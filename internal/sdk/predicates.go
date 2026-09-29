package sdk

import (
	"strings"

	"aotopsy/internal/snapshot"
)

// ── Write-barrier detection ───────────────────────────────────────────
//
// Source: runtime/vm/compiler/assembler/assembler_arm64.cc @3.9.2,
//   Assembler::StoreBarrier / ArrayStoreBarrier:
//
//	and(scratch, TMP2, Operand(scratch, LSR, kBarrierOverlapShift))
//	tst(scratch, Operand(HEAP_BITS, LSR, 32))
//	b(&done, ZERO)
//
// Source: runtime/vm/compiler/assembler/assembler_x64.cc @3.9.2:
//
//	movb(scratch, FieldAddress(object, tags_offset()))
//	shrl(scratch, Immediate(kBarrierOverlapShift))
//	andl(scratch, Address(THR, write_barrier_mask_offset()))
//	testb(FieldAddress(value, tags_offset()), scratch)
//	j(ZERO, &done)
//
// On Dart 2.10-2.13 ARM64 the mask lives in BARRIER_MASK (R28). Dart 2.14+
// folds that mask together with the compressed-pointer heap base in HEAP_BITS:
// the barrier reads HEAP_BITS >> 32, while pointer decompression reads
// HEAP_BITS << 32. On x86_64 the compiler ANDs against the dedicated
// THR.write_barrier_mask field.
//
// The store the check guards has already been emitted, so eliding the
// branch drops pure GC bookkeeping with no source-level meaning.

// IsWriteBarrierCond reports whether a branch condition string is a Dart
// generational write-barrier check. Used by the decompiler to elide the
// branch, and by signal/disasm to classify it as compiler bookkeeping.
func IsWriteBarrierCond(cond string) bool {
	return containsWriteBarrierMask(cond)
}

// IsWriteBarrierStmt reports whether an emitted statement is the
// write-barrier scratch computation itself (e.g.
// `scratch = obj >> shift & THR.write_barrier_mask`). On x86_64 the scratch
// is materialized into a statement rather than forwarded into the branch
// condition, so the condition-level predicate above never sees it.
func IsWriteBarrierStmt(line string) bool {
	return containsWriteBarrierMask(line)
}

func containsWriteBarrierMask(s string) bool {
	if strings.Contains(s, "write_barrier_mask") || strings.Contains(s, SymBarrierMask) {
		return true
	}
	// HEAP_BITS itself is not barrier-only: `HEAP_BITS << 32` is compressed
	// pointer decompression. Only the SDK's right-shifted high half is the
	// write-barrier mask.
	compact := strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "").Replace(s)
	return strings.Contains(compact, SymHeapBits+">>32")
}

// ── Stack-overflow detection ──────────────────────────────────────────
//
// Source: runtime/vm/compiler/stub_code_compiler_arm64.cc,
//   GenerateEnterFrameSafepointStub / prologue stack check:
//	CompareImmediate(SP, THR.stack_limit)
//
// The prologue compares the Dart stack pointer (SPREG = R15 on ARM64,
// RSP on x86_64) against the THR.stack_limit field. This is a runtime
// safepoint, not source-level logic.

// IsStackOverflowCond reports whether a branch condition string is a Dart
// runtime stack-overflow check: a comparison of the stack pointer against
// THR.stack_limit. Requires BOTH the `stack_limit` token AND a stack-pointer
// token, so an ordinary THR-field compare is never mistaken for the prologue
// guard.
func IsStackOverflowCond(cond string) bool {
	if cond == "" {
		return false
	}
	if !strings.Contains(cond, "stack_limit") {
		return false
	}
	return strings.Contains(cond, "x15") || strings.Contains(cond, "SP") ||
		strings.Contains(cond, "rsp") || strings.Contains(cond, "RSP")
}

// ── Cached VM object values ───────────────────────────────────────────
//
// Source: runtime/vm/thread.h CACHED_VM_OBJECTS_LIST — the Thread fields
// that cache a VM OBJECT rather than an address. Loading one yields the
// object itself. x86_64 reaches null this way because constants_x64.h
// defines no NULL_REG (where ARM64 reads R22, x64 reads Thread.object_null).

// CachedVMObjectValue maps a THR field name to the Dart value it caches,
// reporting ok=false when the field is not a cached VM object.
func CachedVMObjectValue(fieldName string) (value string, ok bool) {
	v, ok := cachedVMObjectValues[fieldName]
	return v, ok
}

var cachedVMObjectValues = map[string]string{
	"object_null": "null",
	"bool_true":   "true",
	"bool_false":  "false",
}

// ── Stack-slot naming ─────────────────────────────────────────────────
//
// A displacement off the Dart stack pointer (SPREG) is a stack slot, not a
// field. The naming convention `stack_pN` / `stack_mN` / `stack_sp` is a
// valid Dart identifier, unlike `[SP+N]` which does not parse.

// StackSlotName renders a stack-pointer-relative offset as a valid Dart
// identifier: `stack_pN` for positive offsets, `stack_mN` for negative,
// `stack_sp` for offset 0.
func StackSlotName(off int64) string {
	if off == 0 {
		return "stack_sp"
	}
	if off < 0 {
		return StackSlotNameMinus(-off)
	}
	return StackSlotNamePlus(off)
}

// StackSlotNamePlus renders a positive stack offset.
func StackSlotNamePlus(off int64) string {
	return "stack_p" + itoa(off)
}

// StackSlotNameMinus renders a negative stack offset (passed as positive).
func StackSlotNameMinus(absOff int64) string {
	return "stack_m" + itoa(absOff)
}

// itoa is a dependency-free int64→string for the hot stack-slot path.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ── Pointer decompression detection ───────────────────────────────────
//
// Source: runtime/vm/compiler/assembler/assembler_arm64.cc:
//   @2.13.0 under DART_COMPRESSED_POINTERS:
//     add(dst, src, Operand(HEAP_BASE))
//   @2.14.0+ under DART_COMPRESSED_POINTERS:
//     add(dst, src, Operand(HEAP_BITS, LSL, 32))
// Source: runtime/vm/compiler/assembler/assembler_x64.cc @3.9.2:
//     addq(dst, Address(THR, heap_base_offset()))
//
// Dart 2.13 ARM64 keeps the full heap base in the dedicated HEAP_BASE (R23).
// Dart 2.14+ ARM64 folds write_barrier_mask<<32 | heap_base>>32 into HEAP_BITS
// (R28), so shifting left by 32 recovers the aligned heap base. On x86_64 the
// compiler adds THR.heap_base directly. All forms are invisible at source level
// and are identity transforms for object type tracking.

// ARM64PointerDecompressionSpec returns the SDK-reserved source register and
// LSL amount used by pointer decompression for an exact Dart version. ok=false
// means that version has no supported ARM64 register decompression form.
func ARM64PointerDecompressionSpec(dartVersion string) (srcReg, lslAmount int, ok bool) {
	if dartVersion == "" {
		return 0, 0, false
	}
	if snapshot.VersionAtLeast(dartVersion, "2.14.0") {
		return ARM64HeapBits, 32, true
	}
	if snapshot.VersionAtLeast(dartVersion, "2.13.0") {
		return ARM64HeapBaseLegacy, 0, true
	}
	return 0, 0, false
}

// IsARM64PointerDecompression reports whether an ADD instruction with the
// given source register and shift matches that version's SDK decompression
// shape. Dart 2.13 is `add Xd, Xn, X23`; Dart 2.14+ is
// `add Xd, Xn, X28, LSL #32`.
func IsARM64PointerDecompression(dartVersion, srcReg, shiftSpec string) bool {
	reg, wantShift, ok := ARM64PointerDecompressionSpec(dartVersion)
	if !ok || strings.ToLower(strings.TrimSpace(srcReg)) != ARM64RegName(reg) {
		return false
	}
	spec := strings.ToLower(strings.TrimSpace(shiftSpec))
	if wantShift == 0 {
		return spec == "" || spec == "lsl #0"
	}
	i := strings.Index(spec, "#")
	return strings.HasPrefix(spec, "lsl") && i >= 0 && strings.TrimSpace(spec[i+1:]) == itoa(int64(wantShift))
}

// IsX86PointerDecompression reports whether an ADD instruction with the
// given memory operand (base register + displacement) is a compressed-pointer
// decompression: `add dst, [THR+heap_base_offset]`.
// thrFieldNames maps a THR byte offset to its field name.
func IsX86PointerDecompression(baseReg string, disp int64, thrFieldNames map[int64]string) bool {
	if thrFieldNames == nil {
		return false
	}
	if strings.ToLower(baseReg) != X86ThreadRegStr {
		return false
	}
	name, ok := thrFieldNames[disp]
	return ok && name == "heap_base"
}

// ── Bool-from-null offsets ────────────────────────────────────────────
//
// Source: runtime/vm/instructions.h / object.h — the canonical bool objects
// are at fixed offsets from the null object:
//
//	kObjectAlignment     = 2 * word_size          // 16 on 64-bit
//	kTrueOffsetFromNull  = kObjectAlignment * 2   // 32
//	kFalseOffsetFromNull = kObjectAlignment * 3   // 48
//
// ARM64 reads `null` from NULL_REG (R22), then `add Xd, X22, #32` yields
// `true` and `add Xd, X22, #48` yields `false`. x86_64 loads null from
// Thread.object_null and does the same arithmetic. Without knowing these
// offsets, the pseudocode reads `null + 32`, which looks like pointer
// arithmetic on null rather than a boolean literal.

const (
	// TrueOffsetFromNull is the byte offset of the canonical true object
	// from the null object on 64-bit builds.
	TrueOffsetFromNull = 32
	// FalseOffsetFromNull is the byte offset of the canonical false object
	// from the null object on 64-bit builds.
	FalseOffsetFromNull = 48
)

// BoolFromNullOffset maps an offset from null to the Dart boolean literal
// it represents, reporting ok=false when the offset is not a bool.
func BoolFromNullOffset(off int64) (value string, ok bool) {
	switch off {
	case TrueOffsetFromNull:
		return "true", true
	case FalseOffsetFromNull:
		return "false", true
	}
	return "", false
}
