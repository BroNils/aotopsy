// Package sdk holds Dart AOT virtual-machine facts verified against the
// dart-lang/sdk source (constants_arm64.h, constants_x64.h, thread.h,
// assembler_*.cc). Every constant, register role, and predicate here is
// ground truth from the SDK, not from inference or convention.
//
// This package exists so that internal/decompiler, internal/disasm,
// internal/typetrack, and internal/signal all share ONE definition of each
// SDK fact. Before this package, the same constants were written down 3–4
// times with different representations (int indices in disasm/typetrack,
// string names in decompiler, magic numbers inline in typetrack handlers),
// and the calling-convention arg-register list in the decompiler was
// explicitly wrong (C ABI x0–x7 / rdi–r9) while typetrack had the
// SDK-verified Dart-specific list.
//
// All constants are verified at the SDK tags noted in each constant's doc
// comment. The SDK layout is stable across the versions aotopsy models
// (Dart 2.10–3.13): register roles have not changed.
package sdk

import "aotopsy/internal/snapshot"

// ArchARM64 is the architecture selector used throughout the package.
const (
	ArchARM64 = true
	ArchX86   = false
)

// ── ARM64 register roles ──────────────────────────────────────────────
//
// Source: runtime/vm/constants_arm64.h @3.12.2 (unchanged 2.10–3.13).
//
// Dart AOT reserves specific ARM64 registers for VM roles. Every analysis
// layer needs to know these: disasm to annotate, typetrack to seed its
// lattice, decompiler to name them in pseudocode, signal to classify THR
// accesses.

const (
	// ARM64 register numbers (0-based, as used by the hardware and the SDK's
	// R0–R30 enum).
	ARM64PP             = 27 // PP   = R27 — object pool pointer
	ARM64THR            = 26 // THR  = R26 — thread pointer
	ARM64DT             = 21 // dispatch table register (X21, used by typetrack)
	ARM64HeapBaseLegacy = 23 // HEAP_BASE = R23 through Dart 2.13 compressed-pointer builds
	ARM64HeapBits       = 28 // HEAP_BITS = R28 (Dart 2.14+: write_barrier_mask<<32 | heap_base>>32; Dart 2.10–2.13: BARRIER_MASK = R28)
	ARM64CodeReg        = 24 // CODE_REG  = R24 — current Code object
	ARM64ArgsDesc       = 4  // ARGS_DESC_REG = R4 — arguments descriptor
	ARM64SPReg          = 15 // SPREG = R15 — Dart stack pointer (NOT hardware CSP)
	ARM64NullReg        = 22 // NULL_REG = R22 — caches Object::null() (ARM64-only)
	ARM64FrameReg       = 29 // FPREG = R29 — frame pointer
	ARM64LinkReg        = 30 // LR    = R30 — link register
	ARM64ReturnReg      = 0  // R0 — return value
)

// ARM64BarrierMask is the alias for R28 in Dart 2.10.0–2.13.0 before HEAP_BITS.
const ARM64BarrierMask = ARM64HeapBits

// ARM64HeapRegisterRoles returns the versioned pinned-register roles used by
// generated ARM64 code. Dart <=2.13 keeps the write-barrier mask in R28;
// compressed-pointer builds at 2.13 additionally keep HEAP_BASE in R23. Dart
// 2.14 replaces both with HEAP_BITS in R28, packing the barrier mask and heap
// base high bits into one register.
func ARM64HeapRegisterRoles(dartVersion string) (heapBitsReg, heapBaseReg, barrierMaskReg string) {
	if dartVersion == "" || !snapshot.VersionAtLeast(dartVersion, "2.10.0") {
		return "", "", ""
	}
	if snapshot.VersionAtLeast(dartVersion, "2.14.0") {
		return ARM64HeapBitsStr, "", ""
	}
	heapBaseReg = ""
	if snapshot.VersionAtLeast(dartVersion, "2.13.0") {
		heapBaseReg = ARM64HeapBaseLegacyStr
	}
	return "", heapBaseReg, ARM64HeapBitsStr
}

// ARM64RegName maps a register number to the lowercase string name the
// decompiler uses in pseudocode (e.g. 27 → "x27").
func ARM64RegName(n int) string {
	if n < 0 || n > 30 {
		return ""
	}
	return xName[n]
}

// X86RegName maps a canonical x86_64 register number to the lowercase
// 64-bit name the decompiler uses in pseudocode (e.g. 0 → "rax").
//
// The numbering is the instruction-encoding order, which is what
// arch/x86.CanonReg produces and what the ABI tables in abi.go are
// written in: RAX=0, RCX=1, RDX=2, RBX=3, RSP=4, RBP=5, RSI=6, RDI=7,
// R8..R15=8..15. This is the counterpart of ARM64RegName; without it the
// x86 half of an ABI table could not be turned back into a name, so the
// tables were only usable on ARM64.
func X86RegName(n int) string {
	if n < 0 || n >= len(x86Name) {
		return ""
	}
	return x86Name[n]
}

var x86Name = [...]string{
	"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
}

// xName is pre-computed to avoid fmt.Sprintf in hot paths.
var xName = [...]string{
	"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
	"x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
	"x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
	"x24", "x25", "x26", "x27", "x28", "x29", "x30",
}

// ARM64 register string names (for the decompiler's string-rewriting model).
const (
	ARM64PoolRegStr        = "x27"
	ARM64ThreadRegStr      = "x26"
	ARM64HeapBaseLegacyStr = "x23"
	ARM64HeapBitsStr       = "x28"
	ARM64CodeRegStr        = "x24"
	ARM64ArgsDescStr       = "x4"
	ARM64StackRegStr       = "x15"
	ARM64NullRegStr        = "x22"
	ARM64FrameRegStr       = "x29"
	ARM64LinkRegStr        = "x30"
	ARM64ReturnRegStr      = "x0"
)

// ── x86_64 register roles ─────────────────────────────────────────────
//
// Source: runtime/vm/constants_x64.h @3.12.2 (unchanged 2.10–3.13).

const (
	// x86_64 canonical register numbers (RAX=0 .. R15=15, matching
	// sdk.X86CanonReg).
	X86PP        = 15 // PP   = R15 — object pool pointer
	X86THR       = 14 // THR  = R14 — thread pointer
	X86CodeReg   = 12 // CODE_REG = R12 — current Code object
	X86ArgsDesc  = 10 // ARGS_DESC_REG = R10 — arguments descriptor
	X86SPReg     = 4  // SPREG = RSP — Dart stack pointer
	X86FrameReg  = 5  // FPREG = RBP — frame pointer
	X86ReturnReg = 0  // RAX — return value
)

// x86_64 register string names (for the decompiler's string-rewriting model).
const (
	X86PoolRegStr   = "r15"
	X86ThreadRegStr = "r14"
	X86CodeRegStr   = "r12"
	X86ArgsDescStr  = "r10"
	X86StackRegStr  = "rsp"
	X86FrameRegStr  = "rbp"
	X86ReturnRegStr = "rax"
)

// ── Symbolic names for register seeding ───────────────────────────────
//
// Every analysis layer that seeds a register state (decompiler's SSA
// fixpoint, typetrack's lattice, disasm's provenance tracker) uses the
// same symbolic names for reserved registers. These are the names the
// decompiler emits in pseudocode; other layers use them for annotation.

const (
	SymTHR         = "THR"
	SymPP          = "PP"
	SymSP          = "SP"
	SymHeapBits    = "HEAP_BITS"
	SymHeapBase    = "HEAP_BASE"
	SymBarrierMask = "BARRIER_MASK"
	SymCode        = "CODE"
	SymArgsDesc    = "argsDesc"
)

// ── Dart register calling convention ──────────────────────────────────
//
// Dart did NOT always pass AOT Dart parameters in registers. The
// DartCallingConvention tables first appear at 3.4.3; <=3.3.0 passes Dart
// parameters on the stack. Treating the register table as timeless caused
// every consumer (decompiler, typetrack, call-edge arity inference and Frida)
// to invent register arguments for old binaries.
//
// Exact source:
//
//	3.3.0 runtime/vm/constants_{arm64,x64}.h: no DartCallingConvention
//	3.4.3 runtime/vm/constants_arm64.h:
//	    kCpuRegistersForArgs = {R1,R2,R3,R5,R6,R7}
//	    kFpuRegistersForArgs = {V0,V1,V2,V3,V4,V5}
//	3.4.3 runtime/vm/constants_x64.h:
//	    kCpuRegistersForArgs = {RDI,RSI,RDX,RBX,R8,R9}
//	    kFpuRegistersForArgs = {XMM1,XMM2,XMM3,XMM4,XMM5,XMM6}
//
// Function::MaxNumberOfParametersInRegisters adds a SECOND, per-function
// gate: generics and several Function::Kind values always use the stack, and
// precompiler-only unboxing metadata can force the stack as well. The latter
// metadata lives in KernelProgramInfo/kernel metadata and is not serialized in
// a full AOT snapshot, so this type describes only the architecture/version
// register layout. Callers must still establish that a particular function
// actually uses it before assigning source parameters to these registers.
const FirstRegisterCallingConventionVersion = "3.4.3"

type RegisterCallingConvention struct {
	GPR       []int
	GPRNames  []string
	FPUName   []string
	FPUReturn string
}

// DartRegisterCallingConvention returns the SDK register layout for versions
// where that calling convention exists. ok=false means Dart parameters are
// stack-passed by construction (<=3.3.0 or an unknown/empty version).
func DartRegisterCallingConvention(dartVersion string, isARM64 bool) (cc RegisterCallingConvention, ok bool) {
	if dartVersion == "" || !snapshot.VersionAtLeast(dartVersion, FirstRegisterCallingConventionVersion) {
		return RegisterCallingConvention{}, false
	}
	if isARM64 {
		return RegisterCallingConvention{
			GPR:       []int{1, 2, 3, 5, 6, 7},
			GPRNames:  []string{"x1", "x2", "x3", "x5", "x6", "x7"},
			FPUName:   []string{"v0", "v1", "v2", "v3", "v4", "v5"},
			FPUReturn: "v0",
		}, true
	}
	return RegisterCallingConvention{
		GPR:       []int{7, 6, 2, 3, 8, 9},
		GPRNames:  []string{"rdi", "rsi", "rdx", "rbx", "r8", "r9"},
		FPUName:   []string{"xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6"},
		FPUReturn: "xmm0",
	}, true
}

// DispatchTableOriginElement is DispatchTable::kOriginElement, the element the
// dispatch-table register points AT rather than the start of the table.
//
//	runtime/vm/dispatch_table.h @3.12.2
//	  #if defined(TARGET_ARCH_X64)
//	    static constexpr intptr_t kOriginElement = 16;    // max negative byte offset / 8
//	  #elif defined(TARGET_ARCH_ARM64)
//	    static constexpr intptr_t kOriginElement = 4096;  // max consecutive sub immediate
//
// It exists so a selector below the origin can still be reached with a
// negative displacement (x86_64) or a `sub` immediate (ARM64), which is why
// recovering a selector from a call site has to add it back.
func DispatchTableOriginElement(isARM64 bool) int {
	if isARM64 {
		return 4096
	}
	return 16
}

// ICDataArgRegIndex is the position of IC_DATA_REG within
// DartCallingConvention::kCpuRegistersForArgs. It is index 3 on BOTH
// architectures:
//
//	constants_arm64.h: IC_DATA_REG = R5;  args = {R1, R2, R3, R5, R6, R7}
//	constants_x64.h:   IC_DATA_REG = RBX; args = {RDI, RSI, RDX, RBX, R8, R9}
//
// At an indirect call this register holds the UnlinkedCall/MegamorphicCache,
// not an argument -- FlowGraphCompiler::EmitInstanceCallAOT loads it there
// immediately before the call on both targets. Since arguments are positional,
// nothing at or above this index can be one either.
//
// This matters because an AOT switchable call passes its arguments on the
// STACK, not in registers: EmitInstanceCallAOT reads the receiver back out of
// the stack (`movq RDX, [RSP + (size-1)*8]` / `LoadFromOffset(R0, SP, ...)`)
// and ends with EmitDropArguments. So the argument REGISTERS at such a site
// hold whatever surrounding code left in them.
//
// The damage was architecture-shaped. The receiver lands in RDX on x86_64 --
// argument index 2 -- and in R0 on ARM64, which is not an argument register at
// all. So on x86_64 two of the six "argument" registers are written by the call
// sequence itself and always look live, and one of them sits early enough that
// truncating from the tail can never reach it. Measured on the same program
// built for both: x86_64 emitted 1.7-1.8x ARM64's placeholder tokens.
const ICDataArgRegIndex = 3

// ── Object layout constants ───────────────────────────────────────────
//
// Source: runtime/vm/raw_object.h, runtime/vm/pointer_tagging.h,
// runtime/vm/compiler/runtime_offsets_extracted.h.

const (
	// HeapObjectTag is the tag bit distinguishing a heap object from a Smi.
	// pointer_tagging.h: kHeapObjectTag = 1. A tagged field displacement is
	// raw_offset + kHeapObjectTag, so every field access subtracts/adds 1
	// to convert between tagged and untagged offsets.
	HeapObjectTag = 1

	// Entry point load displacements: in Dart AOT, field accesses use
	// FieldAddress(base, disp) = Address(base, disp - kHeapObjectTag).
	// With kHeapObjectTag = 1, emitted instruction displacements are (field_offset - 1).
	//
	// Uncompressed mode (Dart 2.10–2.17 & uncompressed 3.x, word_size = 8):
	//   kNormal:               field offset  8 -> displacement 0x7 (7)
	//   kMonomorphic:          field offset 24 -> displacement 0x17 (23)
	//   kUnchecked:            field offset 16 -> displacement 0xf (15)
	//   kMonomorphicUnchecked: field offset 32 -> displacement 0x1f (31)
	//
	CodeEntryPointDispUncompressed            = 0x7
	CodeMonomorphicEntryPointDispUncompressed = 0x17
	CodeUncheckedEntryPointDispUncompressed   = 0xf
	CodeMonomorphicUncheckedDispUncompressed  = 0x1f
)

// ── Pool index layout constants ───────────────────────────────────────
//
// Source: runtime/vm/object.h, AOT_ObjectPool layout.

const (
	// PoolElementsStartOffset is the byte offset of the first element in
	// the AOT object pool from the tagged pool pointer.
	PoolElementsStartOffset = 16
	// PoolElementSize is the size of one pool element in bytes (one word).
	PoolElementSize = 8
)

// ── Class ID bitfield constants ───────────────────────────────────────
//
// Source: runtime/vm/raw_object.h, UntaggedObject class tags.
// The class ID is stored in the object header's tags word as a bitfield.
// Dart 3.x: kClassIdTagPos=12, kClassIdTagSize=20 (64-bit header).
// Dart 2.x: kClassIdTagPos=16, kClassIdTagSize=16 (32-bit header).

const (
	ClassIdTagPosV3  = 12 // kClassIdTagPos for Dart 3.x (64-bit tags)
	ClassIdTagSizeV3 = 20 // kClassIdTagSize for Dart 3.x
	ClassIdTagPosV2  = 16 // kClassIdTagPos for Dart 2.x (32-bit tags)
	ClassIdTagSizeV2 = 16 // kClassIdTagSize for Dart 2.x
)

// ── x86_64 special registers ──────────────────────────────────────────
//
// Source: runtime/vm/constants_x64.h.

const (
	// X86ClassIdReg is RCX (canonical 1), used by the dispatch table
	// null-error ABI and as the class-id register in type checks.
	// NOT an argument register (Dart uses RBX for the 4th arg, not RCX).
	X86ClassIdReg = 1
)

// ── Equality-branch successor convention ──────────────────────────────
//
// Shared between ARM64 (typetrack/intraproc.go's equalitySuccessor, which
// decodes a raw B.cond word) and x86_64 (arch/x86.EqualitySuccessor, which
// switches on an x86asm.Op). The two functions are deliberately NOT merged
// — their inputs are different types. Only the return convention is shared.
//
// Getting this backwards types a register on the wrong edge, which is
// invisible in aggregate and wrong at every individual call site -- the same
// failure mode as an off-by-one pool index.

const (
	// SuccEqual is the taken edge of an equality branch (B.EQ / JE): the
	// values are equal along it.
	SuccEqual = 0
	// SuccNotEqual is the fall-through of an equality branch, and the taken
	// edge of an inequality branch (B.NE / JNE): the values are equal along
	// it.
	SuccNotEqual = 1
	// SuccUnknown means the branch says nothing about equality -- it is not
	// an equality test, or the block does not have exactly two successors.
	SuccUnknown = -1
)

// ── FPU/SIMD calling convention ──────────────────────────────────────
//
// Source: runtime/vm/constants_arm64.h @3.12.2:
//   DartCallingConvention::kFpuRegistersForArgs[] = {V0, V1, V2, V3, V4, V5}
//   kReturnFpuReg = V0
// Source: runtime/vm/constants_x64.h @3.12.2:
//   DartCallingConvention::kFpuRegistersForArgs[] = {XMM1, XMM2, XMM3, XMM4, XMM5, XMM6}
//   kReturnFpuReg = XMM0
//
// Dart passes double/float/SIMD arguments through dedicated FPU registers,
// separate from the GPR argument set. The return value for FP returns uses
// a dedicated FPU return register (V0 on ARM64, XMM0 on x86_64).

// RegisterClass distinguishes GPR from FPU registers for type tracking.
type RegisterClass int

const (
	GPR RegisterClass = iota
	FPU
)
