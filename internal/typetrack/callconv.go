package typetrack

import "aotopsy/internal/sdk"

// dartArgRegisters returns the registers Dart AOT passes arguments in, as
// canonical register indices, parameter 0 first. Now delegates to
// internal/sdk.DartArgRegisters — the SDK-verified list is shared with the
// decompiler (which previously used the WRONG C-ABI list x0–x7 / rdi–r9).
//
// The struct does not exist on x64 before 3.x. 2.x passed arguments on the
// stack there, which is the documented reason 2.x x86_64 recovers no receiver
// types at all — see the corpus note in AGENTS-local.md.
func dartArgRegisters(isARM64 bool) []int {
	return sdk.DartArgRegisters(isARM64)
}
