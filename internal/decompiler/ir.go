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

import (
	"sort"
	"strings"
)

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
	Preds   []int // predecessor block IDs (computed by ComputePreds)
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
	// NullReg is the register that permanently caches Object::null(), so
	// every read of it is the literal `null`. ARM64 only (NULL_REG = R22);
	// empty on x86_64, which has no such register and loads null from the
	// object pool instead. See arm64NullReg for the SDK reference and the
	// sample check behind it.
	NullReg string
	// HeapBitsReg is the register holding HEAP_BITS, whose left shift by 32
	// yields heap_base and so marks a compressed-pointer decompression.
	// ARM64 only; x86_64 adds Thread.heap_base instead. See
	// isPointerDecompression.
	HeapBitsReg string

	// PoolIndexOf turns a byte displacement off PoolReg into an object-pool
	// index. The arithmetic differs per architecture -- the ARM64 pool
	// register is untagged and the x86_64 one is tagged, so the same slot
	// sits at a displacement one byte apart -- which is why this is a
	// function supplied by the lifter rather than a constant here. See
	// disasm.ARM64PoolIndex / disasm.X64PoolIndex.
	//
	// Loads through the pool are recognised as OpLoadPool and resolved by
	// the emitter. This field exists for every OTHER instruction that names
	// a pool slot: x86_64 can compare directly against memory, so
	// `cmp eax, [r15+0x3f]` reads a pool entry without ever loading it, and
	// such operands used to render as the literal `pool[?]`. ARM64 has no
	// such shape -- it must load first -- which is why the placeholder was
	// invisible there and showed up only on x64 samples.
	PoolIndexOf func(disp int64) (int, bool)

	// StackReg is the Dart stack pointer -- SPREG in the SDK's terms:
	// `const Register SPREG = R15;` on ARM64 (constants_arm64.h also spells
	// R15 as "SP in Dart code") and `const Register SPREG = RSP;` on x86_64.
	//
	// A displacement off it addresses a STACK SLOT, not a field, so it must
	// not be rendered with field notation. `x15.m16 = framePointer` claimed
	// a field store on the stack pointer, and `rsp._tag` claimed the stack
	// pointer carries an object header.
	StackReg string

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

	// ThreadFieldNames maps a THR-relative byte displacement to the Thread
	// field it names, from the same SDK-derived tables as ThreadStubOffsets
	// (internal/disasm.THRFields) but covering every field rather than only
	// the cached stub entry points.
	//
	// Three of those fields cache VM OBJECTS rather than addresses --
	// object_null, bool_true and bool_false -- so a load of one yields
	// exactly `null`, `true` or `false`. That is how x86_64 materialises
	// them: constants_x64.h has no NULL_REG, so where ARM64 reads R22, x64
	// reads Thread. Rendering them as values is the x64 counterpart of the
	// ARM64 NULL_REG decode.
	//
	// Nil leaves THR accesses as THR.fNN, which is what they were before
	// this existed. They must never be resolved through the Dart class
	// field-name map: Thread is a VM struct, and doing so invented names
	// like THR.radius. See dartFieldResolver.
	ThreadFieldNames map[int64]string

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

	// ExceptionHandlers holds try/catch handler metadata for this function,
	// populated by the caller from cluster.ExceptionHandlerInfo BEFORE
	// EmitPseudocode runs. Each entry describes one handler's PC offset
	// (relative to the function's entry VA), outer try index, and flags.
	// When non-empty, EmitPseudocode wraps the function body in a try/catch
	// block and emits catch clauses at handler entry points.
	ExceptionHandlers []ExceptionHandlerEntry `json:"-"`

	// EnclosingFunction names the function this closure was declared inside,
	// resolved from ClosureData.parent_function. Empty for non-closures.
	// OwnerRefID only reaches the owning class, so without this every anonymous
	// closure in a class is indistinguishable.
	EnclosingFunction string `json:"-"`

	// InlineFrames maps a block's start VA to the inlined-function call stack
	// active there, outermost first, resolved to names by the caller from
	// CodeSourceMap + Code.inlined_id_to_function. Empty/absent means the code
	// belongs to this function itself.
	//
	// This is the consumer for the CodeSourceMap capture: it is what tells a
	// reader that a run of instructions is really a callee the compiler inlined,
	// which is otherwise invisible in the pseudocode.
	InlineFrames map[uint64][]string `json:"-"`

	// TryRegions holds recovered try blocks with their PC extents, populated by
	// the caller from PcDescriptors before EmitPseudocode runs. Unlike
	// ExceptionHandlers (entry points only) these carry ranges, so they are
	// what any real try/catch structuring must be built on.
	TryRegions []TryRegionEntry `json:"-"`

	// TypeParamNames holds this function's declared GENERIC TYPE PARAMETER
	// names in declaration order -- ["T"] for `runUnaryGuarded<T>` -- resolved
	// by the caller from FunctionType.type_parameters -> TypeParameters.names
	// before EmitPseudocode runs. When non-empty, the emitter appends
	// <T1, T2, ...> to the signature.
	//
	// This replaces an earlier GenericTypeArgs field that read the
	// TypeArguments of the parameter_types ARRAY instead: a different object
	// (it describes the array, not the function), and type *arguments* rather
	// than type *parameters*, so it would have emitted invalid Dart had it
	// ever produced output. It never did -- 0 of 300 functions measured.
	// Entries are already rendered ("T", or "T extends NativeFunction"), so the
	// emitter joins them without knowing how bounds are resolved.
	TypeParamNames []string `json:"-"`

	// NamedParamNames holds recovered parameter names positioned by
	// ARGUMENT INDEX, resolved by the caller from
	// FunctionType.named_parameter_names via
	// pipeline.TypeParamResolver.NamedParamNames.
	//
	// Only named optional parameters have recoverable names in an AOT
	// snapshot -- positional ones are dropped by the compiler -- so the
	// slice is the function's full parameter list with "" in every
	// positional slot and names only in the named tail. It is indexed by
	// argument position, NOT by named-parameter position; see
	// NamedParamNames for the SDK reasoning behind that alignment.
	//
	// When non-empty and the length matches the parameter count, the
	// emitter uses these names in the signature instead of generic "argN".
	NamedParamNames []string `json:"-"`

	// FieldNameResolver resolves a (classID, byteOffset) pair to a field name.
	// When non-nil, fieldExpr uses it to emit base.fieldName instead of
	// base.fNN. Set by the caller from pipeline.BuildClassLayouts before
	// EmitPseudocode runs.
	FieldNameResolver func(classID int, byteOffset int64) string `json:"-"`

	// IsAsync is set when the function is detected as async. Detection paths:
	// 1. Direct BL to symbols containing "init_async"/"return_async" (pre-scan)
	// 2. THR stub calls to suspend_state_*_entry_point (emitIndirectCall)
	// 3. SuspendState CID in pool loads (decompile_native_cmd.go)
	// 4. Call targets containing "_SuspendState" + "_await"/"_resume"/"_yield"/"_initAsync"/"_returnAsync"
	// 5. Call targets containing "Future.delayed"/"Future._asyncComplete"/"Future._thenAwait"
	// 6. Post-walk patch if any of the above set IsAsync during walking
	IsAsync bool `json:"-"`

	// IsSyncStar is set when the function is detected as a sync* generator.
	// Detection: call targets containing "InitSyncStar" or "_initSyncStar".
	IsSyncStar bool `json:"-"`

	// IsAsyncStar is set when the function is detected as an async* generator.
	// Detection: call targets containing "YieldAsyncStar" or "_yieldAsyncStar".
	IsAsyncStar bool `json:"-"`

	// SwitchCases holds recovered switch/case dispatch info for indirect
	// branches (br xN from IndirectGotoInstr). Each entry maps a case index
	// to the block ID that handles it. When non-empty, emitJump emits a real
	// `switch (index) { case 0: ... }` instead of a comment.
	// Populated by the caller from jump-table TypedData in the object pool.
	SwitchCases []SwitchCase `json:"-"`

	// LocalTypeHints maps register/local names to inferred Dart type names.
	// Populated by the caller from typetrack results (KnownClass → class name)
	// or from ParamTypeNames. When non-nil, the emitter annotates local
	// variable declarations with their inferred type.
	// Key format: "arg0", "arg1", "local_8", "local_m16", "t1", "x0", etc.
	// Value: Dart type name like "int", "String", "List", "MyClass".
	LocalTypeHints map[string]string `json:"-"`

	// ReceiverClassID is the KnownClass ID of the receiver (arg0/this) for
	// instance methods, resolved from typetrack's FuncOwnerClass. When > 0,
	// FieldNameResolver can use it for per-class field name resolution.
	ReceiverClassID int `json:"-"`

	// ReturnType holds the recovered or inferred return type name (e.g. "String", "int", "bool", "void").
	// When non-empty, the signature emits `<ReturnType> funcName(...)` instead of `dynamic funcName(...)`.
	ReturnType string `json:"-"`

	// ClassNameToID maps a class name to its class ID. It lets the emitter tag a
	// register with a concrete class when a call resolves to that class's
	// allocation stub (`new <Class>`), so subsequent field accesses on the freshly
	// allocated object resolve to real field names. Nil disables the feature.
	ClassNameToID map[string]int `json:"-"`

	// FieldTypeResolver returns the class ID of the declared type of the field at
	// (classID, byteOffset), or 0. It types field-load chains: reading field `a`
	// of a known class yields an object of `a`'s type, so a following `.b`
	// resolves. Nil disables chain typing.
	FieldTypeResolver func(classID int, byteOffset int64) int `json:"-"`
}

// AllocatedClassID returns the class ID a callee name allocates, or 0. A Dart
// AOT allocation stub is named `new <Class>` (isAllocationStubOwner), so a call
// to it yields a fresh instance of <Class>.
func (f *FuncIR) AllocatedClassID(calleeName string) int {
	if f.ClassNameToID == nil {
		return 0
	}
	rest, ok := strings.CutPrefix(calleeName, "new ")
	if !ok {
		return 0
	}
	// The class is the token before any `.` (unnamed vs named constructor) and
	// before any residual args; allocation stubs are just `new <Class>`.
	if i := strings.IndexAny(rest, ". ("); i >= 0 {
		rest = rest[:i]
	}
	return f.ClassNameToID[rest]
}

// SwitchCase is one case in a recovered switch dispatch.
type SwitchCase struct {
	Index   int    // case value (0-based)
	BlockID int    // target block ID in FuncIR.Blocks
}

// TryRegionEntry is one recovered try block: a PC range plus the handler it
// dispatches to.
//
// The range comes from PcDescriptors' try_index (ExceptionHandlers alone gives
// handler entry points but no extents). Both VAs are absolute, converted from
// the Code-relative offsets the snapshot stores.
//
// CAVEAT for anyone rendering these: region granularity is bounded by
// descriptor density. Descriptors exist only at call sites and runtime calls,
// so two nested source-level trys can collapse into one region -- measured on
// compare_sample's nestedTryCatch, which has 2 handlers but yields 1 region.
// Region count is NOT try-block count.
type TryRegionEntry struct {
	StartVA  uint64
	EndVA    uint64 // exclusive
	TryIndex int
	// Handler is the matching ExceptionHandlerEntry, resolved by TryIndex.
	Handler ExceptionHandlerEntry
	// HandlerVA is the absolute address of the handler's entry point.
	HandlerVA uint64
}

// SnapTryRegionsToBlocks widens each try region outward to basic-block
// boundaries and reports how many regions grew.
//
// This is sound, not a heuristic. A basic block is straight-line code with a
// single entry, so control cannot enter it partway: if ANY pc in a block is
// inside try N, every pc in that block is inside try N. Snapping therefore
// cannot over-claim coverage.
//
// It matters because raw PcDescriptor ranges are severe lower bounds --
// descriptors only exist at call sites and runtime calls, so a try whose body
// contains one call yields a range of a single instruction. Snapping recovers
// the enclosing straight-line code, which is what a reader actually wants and
// what any future `try { }` structuring needs.
//
// It does NOT fix the other under-report: two nested trys can still merge when
// descriptors are too sparse to separate them.
func (f *FuncIR) SnapTryRegionsToBlocks() int {
	if len(f.TryRegions) == 0 || len(f.Blocks) == 0 {
		return 0
	}
	// Block extent: [StartVA, last instruction's Addr]. The end is inclusive of
	// the final instruction's address; regions use an exclusive end, so callers
	// get lastAddr+1 at minimum. Instruction width is unknown here (x86_64 is
	// variable length), so the next block's StartVA is used where available.
	type extent struct{ start, end uint64 }
	extents := make([]extent, 0, len(f.Blocks))
	for i := range f.Blocks {
		b := &f.Blocks[i]
		if len(b.Instrs) == 0 {
			continue
		}
		e := b.Instrs[len(b.Instrs)-1].Addr + 1
		extents = append(extents, extent{start: b.StartVA, end: e})
	}
	if len(extents) == 0 {
		return 0
	}
	sort.Slice(extents, func(i, j int) bool { return extents[i].start < extents[j].start })
	// A block's true end is the next block's start when they are contiguous,
	// which recovers the final instruction's width.
	for i := 0; i+1 < len(extents); i++ {
		if extents[i+1].start > extents[i].end {
			extents[i].end = extents[i+1].start
		}
	}

	widened := 0
	for i := range f.TryRegions {
		r := &f.TryRegions[i]
		newStart, newEnd := r.StartVA, r.EndVA
		for _, e := range extents {
			// Overlap test against the region's original extent.
			if e.end <= r.StartVA || e.start >= r.EndVA {
				continue
			}
			if e.start < newStart {
				newStart = e.start
			}
			if e.end > newEnd {
				newEnd = e.end
			}
		}
		if newStart != r.StartVA || newEnd != r.EndVA {
			widened++
			r.StartVA, r.EndVA = newStart, newEnd
		}
	}
	return widened
}

// CatchClause renders the Dart catch binding this handler actually has.
//
// Driven by needs_stacktrace: a source-level `catch (e)` sets it false and
// `catch (e, s)` sets it true. The previous emitter hardcoded `catch (e, st)`
// and so mis-rendered every single-binding catch -- verified against
// ground_truth.dart's tryCatchFinally, which is `catch (e)` and reports
// needs_stacktrace=false.
func (r TryRegionEntry) CatchClause() string {
	if r.Handler.NeedsStacktrace {
		return "catch (e, st)"
	}
	return "catch (e)"
}

// ExceptionHandlerEntry describes one exception handler in a function.
// Populated from cluster.ExceptionHandlerInfo by the pipeline.
type ExceptionHandlerEntry struct {
	PCOffset        int32 `json:"pc_offset"`
	OuterTryIndex   int16 `json:"outer_try_index,omitempty"`
	NeedsStacktrace bool  `json:"needs_stacktrace,omitempty"`
	HasCatchAll     bool  `json:"has_catch_all,omitempty"`
	IsGenerated     bool  `json:"is_generated,omitempty"`
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

// ComputePreds populates Preds for each block from Succs.
// Must be called after all blocks and successors are finalized.
func (f *FuncIR) ComputePreds() {
	for i := range f.Blocks {
		f.Blocks[i].Preds = nil
	}
	for i := range f.Blocks {
		for _, s := range f.Blocks[i].Succs {
			if s.BlockID >= 0 && s.BlockID < len(f.Blocks) {
				f.Blocks[s.BlockID].Preds = append(f.Blocks[s.BlockID].Preds, i)
			}
		}
	}
}

// SymbolLookup resolves an absolute VA to a symbol name, if known.
type SymbolLookup func(va uint64) (name string, ok bool)

// PoolLookup resolves an object-pool slot index to a display string
// (e.g. a literal value, a selector name, or a class/library hint),
// reusing aotopsy's own already-more-accurate pool resolution
// (internal/pipeline.ResolvePoolDisplay) instead of flutterdec's raw
// "pool[N]" placeholder.
type PoolLookup func(idx int) (display string, ok bool)
