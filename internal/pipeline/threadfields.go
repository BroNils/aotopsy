package pipeline

import (
	"aotopsy/internal/disasm"
	"aotopsy/internal/snapshot"
)

// ThreadFieldOffsets adapts disasm's Thread field table (keyed by int) to the
// int64 keys the decompiler's memory-displacement handling uses.
//
// This exists as one shared helper because the decompiler now DEPENDS on the
// table for correctness, not just for readability. Since the vm_tag scoping
// fix, `applyStore` recognises Dart's FFI/native-call bookkeeping by looking
// the displacement up here and checking for the field named "vm_tag" -- so a
// FuncIR built without this table does not merely print `THR.f1904` instead
// of `THR.vm_tag`, it silently stops detecting FFI call targets altogether.
//
// Context.FuncIRFor did exactly that: it set ThreadStubOffsets and not this,
// which left the ffitrace and --from-main paths with a nil table. Only
// cmd/aotopsy's decompile-native path populated it.
func ThreadFieldOffsets(dartVersion string, isARM64 bool, profile *snapshot.VersionProfile) map[int64]string {
	src := disasm.THRFieldsWithProfile(dartVersion, isARM64, profile)
	if len(src) == 0 {
		return nil
	}
	out := make(map[int64]string, len(src))
	for off, name := range src {
		out[int64(off)] = name
	}
	return out
}
