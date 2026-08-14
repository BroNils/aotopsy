package typetrack

// dartArgRegisters returns the registers Dart AOT passes arguments in, as
// canonical register indices, parameter 0 first.
//
// This is Dart's OWN convention, declared in the SDK, not the platform C ABI:
//
//	constants_arm64.h @3.12.2
//	  DartCallingConvention::kCpuRegistersForArgs[] = {R1, R2, R3, R5, R6, R7}
//	constants_x64.h   @3.12.2 and @3.9.2
//	  DartCallingConvention::kCpuRegistersForArgs[] = {RDI, RSI, RDX, RBX, R8, R9}
//
// One list served both architectures, the ARM64 one, justified by a comment
// calling RDI "the SysV ABI first arg". SysV is the C convention; Dart
// declares its own and only the first register coincides. On x86_64 that
// typed parameter 1 into RDX (should be RSI), parameter 2 into RBX (should be
// RDX) and parameter 3 into RBP -- the frame pointer. Not a missing feature:
// a source of confident wrong types, on registers holding something else.
//
// The struct does not exist on x64 before 3.x. 2.x passed arguments on the
// stack there, which is the documented reason 2.x x86_64 recovers no receiver
// types at all -- see the corpus note in AGENTS-local.md.
func dartArgRegisters(isARM64 bool) []int {
	if isARM64 {
		return []int{1, 2, 3, 5, 6, 7}
	}
	// RDI=7, RSI=6, RDX=2, RBX=3, R8=8, R9=9.
	return []int{7, 6, 2, 3, 8, 9}
}
