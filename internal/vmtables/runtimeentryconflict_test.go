package vmtables

import (
	"strings"
	"testing"
)

// TestNoRuntimeEntryConflicts fails when a runtime-entry list was merged at
// a base offset that collides with a name the Thread field table already
// carried.
//
// This is not a style check. The runtime-entry block sits outside what the
// SDK's generated header exposes as AOT_Thread_*_offset, so
// TestThreadFieldNamesMatchSDK cannot see it: a wrong base writes wrong
// names into offsets nothing else verifies. The collision is the only
// evidence, and it was a warning on stderr until it caught a bug that had
// already shipped in v1.3.0 -- four new tables inherited their neighbour's
// unshifted offsets for every field the header does not cover.
//
// A conflict means one of two things, both worth failing on:
//   - the base is wrong for this version (the block moved when a field was
//     inserted earlier in the struct), or
//   - the table itself carries a wrong name at that offset.
func TestNoRuntimeEntryConflicts(t *testing.T) {
	if len(runtimeEntryConflicts) == 0 {
		return
	}
	t.Fatalf("mergeRuntimeEntries hit %d conflict(s):\n  %s\n\n"+
		"A conflict means the runtime-entry base offset is wrong for that version, or the\n"+
		"table has a wrong name there. Do not silence it by trimming the entry list: check\n"+
		"the first runtime entry's offset in runtime_offsets_extracted.h for that tag --\n"+
		"the block shifts whenever a field is inserted earlier in Thread.",
		len(runtimeEntryConflicts), strings.Join(runtimeEntryConflicts, "\n  "))
}
