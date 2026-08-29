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
	ARM64PP        = 27 // PP   = R27 — object pool pointer
	ARM64THR       = 26 // THR  = R26 — thread pointer
	ARM64DT        = 21 // dispatch table register (X21, used by typetrack)
	ARM64HeapBits  = 28 // HEAP_BITS = R28 — write_barrier_mask<<32 | heap_base>>32
	ARM64CodeReg   = 24 // CODE_REG  = R24 — current Code object
	ARM64ArgsDesc  = 4  // ARGS_DESC_REG = R4 — arguments descriptor
	ARM64SPReg     = 15 // SPREG = R15 — Dart stack pointer (NOT hardware CSP)
	ARM64NullReg   = 22 // NULL_REG = R22 — caches Object::null() (ARM64-only)
	ARM64FrameReg  = 29 // FPREG = R29 — frame pointer
	ARM64LinkReg   = 30 // LR    = R30 — link register
	ARM64ReturnReg = 0  // R0 — return value
)

// ARM64RegName maps a register number to the lowercase string name the
// decompiler uses in pseudocode (e.g. 27 → "x27").
func ARM64RegName(n int) string {
	if n < 0 || n > 30 {
		return ""
	}
	return xName[n]
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
	ARM64PoolRegStr   = "x27"
	ARM64ThreadRegStr = "x26"
	ARM64HeapBitsStr  = "x28"
	ARM64CodeRegStr   = "x24"
	ARM64ArgsDescStr  = "x4"
	ARM64StackRegStr  = "x15"
	ARM64NullRegStr   = "x22"
	ARM64FrameRegStr  = "x29"
	ARM64LinkRegStr   = "x30"
	ARM64ReturnRegStr = "x0"
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
	SymTHR      = "THR"
	SymPP       = "PP"
	SymSP       = "SP"
	SymHeapBits = "HEAP_BITS"
	SymCode     = "CODE"
	SymArgsDesc = "argsDesc"
)

// ── Dart calling-convention argument registers ────────────────────────
//
// Source: runtime/vm/constants_arm64.h @3.12.2:
//   DartCallingConvention::kCpuRegistersForArgs[] = {R1, R2, R3, R5, R6, R7}
// Source: runtime/vm/constants_x64.h @3.12.2 and @3.9.2:
//   DartCallingConvention::kCpuRegistersForArgs[] = {RDI, RSI, RDX, RBX, R8, R9}
//
// This is Dart's OWN convention, not the platform C ABI. The decompiler
// previously used x0–x7 / rdi–r9 (C ABI), which includes R0 (kClassIdReg)
// and R4 (ARGS_DESC_REG) — registers that are NOT argument registers in
// Dart's convention. typetrack had the correct list; this makes it shared.
//
// On x86_64 before 3.x, DartCallingConvention does not exist and arguments
// are passed on the stack — see AGENTS-local.md. The list below is still
// the correct set for 3.x; callers that handle 2.x x86_64 must check
// separately.

// DartArgRegisters returns the canonical register indices Dart AOT passes
// arguments in, parameter 0 first.
func DartArgRegisters(isARM64 bool) []int {
	if isARM64 {
		return []int{1, 2, 3, 5, 6, 7}
	}
	// RDI=7, RSI=6, RDX=2, RBX=3, R8=8, R9=9.
	return []int{7, 6, 2, 3, 8, 9}
}

// DartArgRegNames returns the string names of the Dart calling-convention
// argument registers, parameter 0 first — for the decompiler's pseudocode
// display.
func DartArgRegNames(isARM64 bool) []string {
	if isARM64 {
		return []string{"x1", "x2", "x3", "x5", "x6", "x7"}
	}
	return []string{"rdi", "rsi", "rdx", "rbx", "r8", "r9"}
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
	// Compressed mode (Dart 2.18+ / 3.x, compressed_ptr = 4, word_size = 8):
	//   kNormal:               field offset  4 -> displacement 0x3 (3)
	//   kMonomorphic:          field offset 12 -> displacement 0xb (11)
	//   kUnchecked:            field offset  8 -> displacement 0x7 (7)
	//   kMonomorphicUnchecked: field offset 16 -> displacement 0xf (15)

	CodeEntryPointDispUncompressed               = 0x7
	CodeMonomorphicEntryPointDispUncompressed    = 0x17
	CodeUncheckedEntryPointDispUncompressed      = 0xf
	CodeMonomorphicUncheckedDispUncompressed     = 0x1f

	CodeEntryPointDispCompressed                 = 0x3
	CodeMonomorphicEntryPointDispCompressed      = 0xb
	CodeUncheckedEntryPointDispCompressed        = 0x7
	CodeMonomorphicUncheckedDispCompressed       = 0xf

	// Deprecated aliases maintained for compatibility:
	CodeEntryPointDisp            = 0x7
	CodeMonomorphicEntryPointDisp = 0xf
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
