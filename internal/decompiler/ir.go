// Package decompiler produces Dart-AOT-aware pseudocode directly from
// disassembled ARM64/x86_64 machine code, without depending on Ghidra.
// Ported from flutterdec's flutterdec-ir + flutterdec-decompiler crates
// (Rust): the architecture is a deliberately minimal IR wrapping raw
// per-instruction text plus a symbolic *string*-expression lifter (not an
// expression tree) and a text-rewriting readability-pass pipeline over the
// emitted pseudocode lines. See knowledge/SESSION_HANDOFF_2026-07-17_
// AOTOPSY_UNIVERSAL_RE_PLATFORM.md and the flutterdec survey this port
// is based on for the full rationale.
package decompiler

// Op classifies one instruction's role in control flow / value flow, this
// is deliberately a small enum mirroring flutterdec-ir's IROp -- most
// instructions are OpOther and get lifted by their raw mnemonic text.
type Op int

const (
	OpOther Op = iota
	OpCall
	OpBranch // conditional; has a Taken and Fallthrough successor
	OpJump   // unconditional direct/indirect jump
	OpReturn
	OpLoadPool
)

// Instr is one lifted instruction. Src is the normalized, lowercased
// "mnemonic operand1, operand2, ..." text for BOTH architectures -- ARM64
// and x86_64 instructions are rendered into the same textual shape so a
// single lifter (lift.go) can handle both, matching flutterdec's own
// string-based (not tree-based) approach.
type Instr struct {
	Addr   uint64
	Op     Op
	Src    string
	Target string // resolved target: "0x<hex>" VA, a register name (indirect), or "" if RET
	// PoolIndex is set for OpLoadPool when the pool slot index is known
	// (ARM64: MOV Xd, [x27/PP, #imm]; x86_64: MOV reg, [r15+imm]). For
	// OpLoadPool, Target holds the destination register name.
	PoolIndex int

	// OpBranch condition classification -- the emitter builds the actual
	// condition expression at walk time (against the live LiftState), so
	// only the raw shape is captured here at lift time:
	//   CondKind "cmp"      -> use the block's last cmp operands + CondOp
	//   CondKind "eqz"/"nez" -> CondReg == 0 / != 0
	//   CondKind "bittest0"/"bittest1" -> ((CondReg >> CondBit) & 1) == 0 / != 0
	CondKind string
	CondOp   string // Dart comparison operator, e.g. "==", "!=", "<", "<=", ">", ">="
	CondReg  string
	CondBit  int
}

// Succ is a control-flow edge out of a Block.
type Succ struct {
	BlockID int
	Cond    string // "" unconditional, "T" taken, "F" fallthrough
}

// Block is one basic block.
type Block struct {
	ID      int
	StartVA uint64
	Instrs  []Instr
	Succs   []Succ
	IsTerm  bool // ends in RET or a branch out of the function
}

// FuncIR is one function's arch-neutral intermediate representation, the
// direct input to the pseudocode emitter (emit.go).
type FuncIR struct {
	Name      string
	EntryVA   uint64
	Blocks    []Block
	blockByVA map[uint64]int
	ArgRegs   []string // arg0..argN register names in calling-convention order
	FrameReg  string   // frame/stack-relative base register name (ARM64: x29; x86_64: rbp)
	ReturnReg string   // register holding the return value (ARM64: x0; x86_64: rax)
	LinkReg   string   // return-address register alias name, if any (ARM64: x30; x86_64: "" -- on the stack)
	PoolReg   string   // object-pool base register (ARM64: x27; x86_64: r15)
	ThreadReg string   // Dart Thread*-holding register (ARM64: x26/THR; x86_64: r14)

	// ArgRegIndices holds the real declared arity, resolved empirically
	// from cross-function call-site aggregation (see
	// internal/disasm.inferCallArgRegMaskLocal and cmd/aotopsy's
	// buildArgCountHints) -- NOT from Function/FunctionType snapshot
	// metadata, which was tried, found unreliable, and abandoned (see
	// ARCHITECTURE.md). Each element is an index into ArgRegs identifying
	// one real argument register, in calling-convention order; nil/empty
	// means unresolved (no confident cross-call-site agreement), in which
	// case callers fall back to displaying the full ArgRegs set unchanged.
	// The set is NOT assumed to start at index 0 -- a verified real sample
	// had a single real argument in ArgRegs[1] with ArgRegs[0] unused.
	ArgRegIndices []int

	// ThreadStubOffsets maps a THR-relative byte displacement to the
	// resolved Dart runtime stub name it holds a cached entry point for
	// (dart-lang/sdk's CACHED_VM_STUBS_ADDRESSES_LIST in thread.h, e.g.
	// write_barrier_entry_point_ or stack_overflow_shared_..._entry_point_).
	// Set by the caller (decompile_native_cmd.go) from a per-Dart-version,
	// per-arch table (internal/disasm.ThreadStubOffsets) BEFORE
	// EmitPseudocode runs -- nil/empty means "not verified for this
	// version/arch", in which case THR-relative loads render as a plain
	// field access (THR.fNN) same as before this feature existed.
	ThreadStubOffsets map[int64]string

	// ParamTypeNames holds real per-parameter type names (e.g. "int",
	// "String"), resolved from FunctionType.parameter_types by the
	// caller (see pipeline.TypeParamResolver) BEFORE EmitPseudocode
	// runs, already adjusted to exclude the implicit receiver.
	//
	// EmitPseudocode only trusts this when its length EXACTLY matches
	// the independently-verified arg count (ArgRegIndices, resolved via
	// cross-function call-site aggregation, a completely separate
	// mechanism) -- never displayed on a count mismatch, falling back to
	// "dynamic argN" instead. This is a deliberate safety gate: this
	// exact FunctionType/signature_ data was tried once before for
	// arity display (see ARCHITECTURE.md's "Real declared arity" note)
	// and reverted after finding it unreliable -- missing for many
	// simple functions (a WeakSerializationReference AOT nulls out when
	// not needed) AND wrong at least once for a real function
	// (StringTools.countVowels decoded NumFixed=0 for its one real
	// parameter). Since ParamTypeNames comes from the SAME FunctionType
	// object, it inherits that same risk -- the count-match check
	// cross-validates it against ArgRegIndices' independently-derived
	// count before trusting it at all, rather than assuming it's
	// authoritative just because it parsed without an error.
	ParamTypeNames []string
}

// BlockByVA resolves a block by its start address.
func (f *FuncIR) BlockByVA(va uint64) (int, bool) {
	id, ok := f.blockByVA[va]
	return id, ok
}

func newFuncIR(name string, entryVA uint64) *FuncIR {
	return &FuncIR{Name: name, EntryVA: entryVA, blockByVA: make(map[uint64]int)}
}

func (f *FuncIR) addBlock(b Block) {
	f.blockByVA[b.StartVA] = len(f.Blocks)
	f.Blocks = append(f.Blocks, b)
}

// SymbolLookup resolves an absolute VA to a symbol name, if known.
type SymbolLookup func(va uint64) (name string, ok bool)

// PoolLookup resolves an object-pool slot index to a display string
// (e.g. a literal value, a selector name, or a class/library hint),
// reusing aotopsy's own already-more-accurate pool resolution
// (internal/pipeline.ResolvePoolDisplay) instead of flutterdec's raw
// "pool[N]" placeholder.
type PoolLookup func(idx int) (display string, ok bool)
