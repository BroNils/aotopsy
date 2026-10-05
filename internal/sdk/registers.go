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
// Facts that are genuinely architectural invariants stay as constants; facts
// whose meaning changes by SDK release or build configuration are exposed as
// exact-version APIs and fail closed for unsupported versions. In particular,
// heap-register semantics, dispatch CID registers, and Dart register calling
// conventions are not timeless across Dart 2.10–3.13.
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
	ARM64TMP            = 16 // TMP  = R16 — assembler scratch
	ARM64TMP2           = 17 // TMP2 = R17 — assembler scratch / large immediate materialization
	ARM64FrameReg       = 29 // FPREG = R29 — frame pointer
	ARM64LinkReg        = 30 // LR    = R30 — link register
	ARM64ReturnReg      = 0  // R0 — return value
)

// ARM64BarrierMask is the alias for R28 in Dart 2.10.0–2.13.0 before HEAP_BITS.
const ARM64BarrierMask = ARM64HeapBits

// ARM64HeapRegisterRoles returns the version/build-specific pinned-register
// values that are valid at generated-code entry. Dart <=2.13 keeps the
// write-barrier mask in R28. Dart 2.13 additionally loads HEAP_BASE into R23
// only when DART_COMPRESSED_POINTERS is enabled; R23 is reserved on the
// uncompressed build too, but RestorePinnedRegisters does not initialize it and
// consumers must not seed a value there. Dart 2.14+ always initializes HEAP_BITS
// in R28 with the barrier mask in the high half and, on compressed builds, the
// heap-base high bits in the low half.
func ARM64HeapRegisterRoles(dartVersion string, compressedPointers bool) (heapBitsReg, heapBaseReg, barrierMaskReg string) {
	if !isSupportedDartVersion(dartVersion) {
		return "", "", ""
	}
	if snapshot.VersionAtLeast(dartVersion, "2.14.0") {
		return ARM64HeapBitsStr, "", ""
	}
	heapBaseReg = ""
	if dartVersion == "2.13.0" && compressedPointers {
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
// R8..R15=8..15 (SDK @3.12.2 runtime/vm/constants_x64.h:22-41, read; other
// versions not checked). This is the counterpart of ARM64RegName; without it the
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
// DartCallingConvention tables first appear at SDK 3.4.0 (absent through
// 3.3.4); <=3.3.x passes Dart parameters on the stack. Treating the register
// table as timeless caused every consumer (decompiler, typetrack, call-edge
// arity inference and Frida) to invent register arguments for old binaries.
// firstSupportedRegisterCallingConventionVersion is "3.4.3" only because that
// is the first SUPPORTED profile of the 3.4 line (its one snapshot hash maps there);
// it is not the SDK boundary. TestDartCallingConventionMatchesSDK and
// TestDartCallingConventionBoundaryMatchesSDK re-derive both from the SDK.
//
// Exact source (read, not only grepped):
//
//	3.3.4 runtime/vm/constants_{arm64,x64}.h: no DartCallingConvention
//	3.4.0 constants_arm64.h:622, constants_x64.h:677: struct present;
//	      compiler/backend/dart_calling_conventions.cc identical to 3.4.3;
//	      object.cc:104 DEFINE_FLAG(use_register_cc, true)
//	3.4.3 runtime/vm/constants_arm64.h:623 (same lists at 3.12.2:653):
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
const firstSupportedRegisterCallingConventionVersion = "3.4.3"

// RegisterCallingConventionReferenceVersion is an exact supported profile used
// only when a caller needs the architecture's register ordering as a static
// lookup table. It is NOT a boundary predicate; use HasDartRegisterCallingConvention
// for that.
const RegisterCallingConventionReferenceVersion = firstSupportedRegisterCallingConventionVersion

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
	if !isSupportedDartVersion(dartVersion) || !snapshot.VersionAtLeast(dartVersion, firstSupportedRegisterCallingConventionVersion) {
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

// DartCallClobberedGPRs returns the allocatable CPU registers whose values may
// not be carried across an ordinary Dart call. This is deliberately broader
// than DartCallingConvention.GPR: arguments are only a subset of the registers
// the callee may allocate and overwrite.
//
// Exact SDK source @3.12.2:
//
//	runtime/vm/compiler/backend/linearscan.cc: normal calls execute
//	  BlockCpuRegisters(kAllCpuRegistersList, pos, pos + 1)
//	runtime/vm/constants_arm64.h: kDartAvailableCpuRegs is all CPU registers
//	  minus SP/FP/TMP/TMP2/PP/THR/LR/HEAP_BITS/NULL/R18/DT/R31.
//	runtime/vm/constants_x64.h: kDartAvailableCpuRegs is all CPU registers
//	  minus RSP/RBP/TMP(R11)/PP(R15)/THR(R14).
//
// The x64 reserved-register set is stable across the supported releases. ARM64
// has one important exception: Dart 2.13 reserves R23 as HEAP_BASE; in 2.12 it
// is allocatable and in 2.14+ the dedicated heap-base role is replaced by
// HEAP_BITS in R28, making R23 allocatable again. Unknown/future versions fail
// closed instead of inheriting the newest ABI.
func DartCallClobberedGPRs(dartVersion string, isARM64 bool) ([]int, bool) {
	if !isSupportedDartVersion(dartVersion) {
		return nil, false
	}
	if isARM64 {
		regs := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 19, 20}
		if !snapshot.VersionAtLeast(dartVersion, "2.13.0") || snapshot.VersionAtLeast(dartVersion, "2.14.0") {
			regs = append(regs, 23)
		}
		regs = append(regs, 24, 25)
		return regs, true
	}
	// RSP(4), RBP(5), R11(TMP), R14(THR), R15(PP) are reserved.
	return []int{0, 1, 2, 3, 6, 7, 8, 9, 10, 12, 13}, true
}

// HasDartRegisterCallingConvention reports whether this exact supported Dart
// profile has the register calling convention. Unknown/future versions fail
// closed instead of inheriting the newest known ABI.
func HasDartRegisterCallingConvention(dartVersion string) bool {
	_, ok := DartRegisterCallingConvention(dartVersion, ArchARM64)
	return ok
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
func DispatchTableOriginElement(dartVersion string, isARM64 bool) (int, bool) {
	// The SOURCE spelling changes at 2.19.0, not the fact. Dart 2.10-2.18
	// implements DispatchTable::OriginElement() in dispatch_table.cc; 2.19+
	// exposes the same values as DispatchTable::kOriginElement in the header.
	if !isSupportedDartVersion(dartVersion) {
		return 0, false
	}
	if isARM64 {
		return 4096, true
	}
	return 16, true
}

// ICDataArgRegIndex returns the position of IC_DATA_REG within the exact
// version's DartCallingConvention::kCpuRegistersForArgs. It is index 3 on BOTH
// supported architectures once that register calling convention exists:
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
func ICDataArgRegIndex(dartVersion string, isARM64 bool) (int, bool) {
	cc, ok := DartRegisterCallingConvention(dartVersion, isARM64)
	if !ok || len(cc.GPR) <= 3 {
		return 0, false
	}
	want := 3 // RBX on x64.
	if isARM64 {
		want = 5 // R5 on ARM64.
	}
	if cc.GPR[3] != want {
		return 0, false
	}
	return 3, true
}

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
)

// ClosureEntryPointDisp returns the tagged displacement of the cached entry point
// that a Full-AOT ClosureCallInstr loads before calling:
//
//	arm64:  LDR X2, [X0, #disp] ; BLR X2   (R0 = closure)
//	x64:    MOV RCX, [RAX+disp] ; CALL RCX (RAX = closure)
//
// SDK facts, derived from runtime/vm/compiler/runtime_offsets_extracted.h
// (AOT_Closure_entry_point_offset, every supported tag 2.14.0..3.13.0, arm64 and
// x64, compressed and uncompressed) and from il_{arm64,x64}.cc
// ClosureCallInstr::EmitNativeCode (bodies Read at every md5 boundary):
//
//   - before 2.14.0 there is no Closure.entry_point_: the call loads
//     Function.entry_point from a Function in R0/RAX, which has the same
//     displacement as Code.entry_point, so the pair cannot be told apart from
//     other register-entry calls. Reported as unknown (false);
//   - 2.14.0..3.12.2: entry_point_ follows the six pointer fields, 56 uncompressed
//     (tagged 55) and 32 compressed (tagged 31);
//   - 3.13.0+: Closure became variable length and entry_point_ moved directly
//     behind the header: 8 (tagged 7) in every configuration.
//
// TestClosureEntryPointDispMatchesSDK re-derives this table from the SDK.
func ClosureEntryPointDisp(dartVersion string, compressedPointers bool) (int, bool) {
	if !isSupportedDartVersion(dartVersion) || !snapshot.VersionAtLeast(dartVersion, "2.14.0") {
		return 0, false
	}
	switch {
	case snapshot.VersionAtLeast(dartVersion, "3.13.0"):
		return 8 - HeapObjectTag, true
	case compressedPointers:
		return 32 - HeapObjectTag, true
	default:
		return 56 - HeapObjectTag, true
	}
}

// IsCodeEntryPointDisp reports whether off is an instruction displacement for
// one of UntaggedCode's four generated-code entry-point uwords. Every supported
// ARM64/x64 SDK stores these as full target words even with compressed heap
// pointers, in this exact order after the 8-byte object header:
//
//	entry_point_                       offset  8 -> disp 0x07
//	monomorphic_entry_point_           offset 16 -> disp 0x0f
//	unchecked_entry_point_             offset 24 -> disp 0x17
//	monomorphic_unchecked_entry_point_ offset 32 -> disp 0x1f
//
// FieldAddress subtracts kHeapObjectTag (1), hence the odd displacements.
// Keeping the named-field ordering here matters: the old constants had the
// monomorphic and unchecked names swapped even though the set of numbers was
// accidentally still correct.
func IsCodeEntryPointDisp(off int) bool {
	switch off {
	case 0x7, 0xf, 0x17, 0x1f:
		return true
	default:
		return false
	}
}

// ── Pool index layout constants ───────────────────────────────────────
//
// Source: runtime/vm/object.h, AOT_ObjectPool layout.

const (
	// PoolElementsStartOffset is the byte offset of the first element in the
	// 64-bit AOT ObjectPool object layout. Architecture-specific PP tagging is
	// applied by the consumer: ARM64 PP is untagged; x86_64 PP is tagged and
	// FieldAddress subtracts HeapObjectTag.
	PoolElementsStartOffset = 16
	// PoolElementSize is the size of one pool element in bytes (one word).
	PoolElementSize = 8
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
