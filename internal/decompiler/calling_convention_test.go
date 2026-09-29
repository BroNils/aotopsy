package decompiler

import "aotopsy/internal/sdk"

// Test fixtures that need a modern Dart register ABI use the exact SDK layout
// through the production version-aware API. Keeping these names test-only lets
// old table-driven tests stay compact without resurrecting the removed
// production globals that falsely implied every Dart version/function used
// register arguments.
var (
	arm64TestCC, _ = sdk.DartRegisterCallingConvention("3.12.2", sdk.ArchARM64)
	x86TestCC, _   = sdk.DartRegisterCallingConvention("3.12.2", sdk.ArchX86)
	arm64ArgRegs   = arm64TestCC.GPRNames
	x86ArgRegs     = x86TestCC.GPRNames
)
