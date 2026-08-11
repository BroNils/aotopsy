package disasm

// Object-pool index arithmetic.
//
// A Dart AOT function reaches a pool entry through the object-pool register
// (ARM64: X27, x86_64: R15) at a fixed byte displacement. Turning that
// displacement back into the pool index the snapshot deserializer produced
// requires the SDK's own layout constants -- getting it wrong shifts EVERY
// pool-derived fact (string references, class-id sources, FFI targets,
// decompiler operands) by a constant number of slots, which is invisible in
// aggregate and silently wrong in every individual line.
//
// From dart-lang/sdk (verified at tag 3.9.2):
//
//	runtime/vm/compiler/runtime_offsets_extracted.h, AOT 64-bit blocks:
//	  AOT_ObjectPool_elements_start_offset = 0x10   // 16
//	  AOT_ObjectPool_element_size          = 0x8    // 8
//
//	runtime/vm/compiler/assembler/assembler_arm64.cc:
//	  void Assembler::LoadWordFromPoolIndex(...) {
//	    // PP is _un_tagged on ARM64.
//	    const uint32_t offset = target::ObjectPool::element_offset(index);
//	    ... ldr(dst, Address(pp, offset));            // or add+ldr split
//
//	runtime/vm/compiler/assembler/assembler_x64.cc:
//	  void Assembler::LoadWordFromPoolIndex(Register dst, intptr_t idx) {
//	    // PP is tagged on X64.
//	    movq(dst, FieldAddress(PP, target::ObjectPool::element_offset(idx)));
//
// FieldAddress subtracts kHeapObjectTag (1). Hence:
//
//	ARM64  displacement = 16 + 8*index          (always a multiple of 8)
//	x86_64 displacement = 16 + 8*index - 1      (always ≡ 7 mod 8)
//
// Both were previously computed as plain displacement/8 (ARM64, off by +2)
// and displacement/8 - 2 (x86_64, off by -1). The ARM64 error was visible on
// the ground-truth sample: the string "factorial(6) = " sat at pool index
// 5032 and was reported as loaded by 38 unrelated Flutter framework
// functions, because their real index-5030 loads were labelled 5032.
const (
	poolElementsStartOffset = 16 // AOT_ObjectPool_elements_start_offset
	poolElementSize         = 8  // AOT_ObjectPool_element_size
	heapObjectTag           = 1
)

// ARM64PoolIndex converts a byte displacement off the untagged ARM64 pool
// register (X27) to a pool index. ok is false when the displacement cannot
// name an element (below the first element, or not element-aligned).
func ARM64PoolIndex(byteOffset int) (index int, ok bool) {
	rel := byteOffset - poolElementsStartOffset
	if rel < 0 || rel%poolElementSize != 0 {
		return 0, false
	}
	return rel / poolElementSize, true
}

// X64PoolIndex converts a displacement off the TAGGED x86_64 pool register
// (R15) to a pool index.
func X64PoolIndex(disp int64) (index int, ok bool) {
	rel := disp - (poolElementsStartOffset - heapObjectTag)
	if rel < 0 || rel%poolElementSize != 0 {
		return 0, false
	}
	return int(rel / poolElementSize), true
}
