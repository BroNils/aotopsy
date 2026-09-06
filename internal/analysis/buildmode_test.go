package analysis

import "testing"

// TestDetectBuildMode pins the inference rules, because both of them are
// arguments from absence and absence is exactly what a broken parser also
// produces.
func TestDetectBuildMode(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		csm, discarded, codeRanges int
		wantDwarf                  bool
	}{
		{
			// The corpus's obfuscated production sample: no source maps and
			// 91012 of 128999 entries with no Code object.
			name: "obfuscated production build",
			csm:  0, discarded: 91012, codeRanges: 128999,
			wantDwarf: true,
		},
		{
			// The other four samples: thousands of source maps, nothing
			// discarded.
			name: "ordinary release build",
			csm:  6029, discarded: 0, codeRanges: 8175,
			wantDwarf: false,
		},
		{
			// Discarded entries alone are proof: app_snapshot.cc asserts
			// dwarf mode before discarding, so this is dwarf even though
			// source maps survived (retain_code_objects off, split debug
			// info on).
			name: "discarded entries prove dwarf even with source maps",
			csm:  100, discarded: 5, codeRanges: 1000,
			wantDwarf: true,
		},
		{
			// Code present, no source maps: the weaker signal, still dwarf.
			name: "no source maps against a non-empty code population",
			csm:  0, discarded: 0, codeRanges: 8000,
			wantDwarf: true,
		},
		{
			// Nothing parsed at all. Must NOT be reported as dwarf -- that
			// would turn a parse failure into a confident statement about
			// how the binary was built, which is the exact error this
			// detector exists to avoid making in the other direction.
			name: "empty snapshot is not a claim about build flags",
			csm:  0, discarded: 0, codeRanges: 0,
			wantDwarf: false,
		},
	} {
		got := DetectBuildMode(tc.csm, tc.discarded, tc.codeRanges)
		if got.DwarfStackTraces != tc.wantDwarf {
			t.Errorf("%s: DwarfStackTraces = %v, want %v", tc.name, got.DwarfStackTraces, tc.wantDwarf)
		}
		if got.CodeSourceMaps != tc.csm || got.DiscardedCodes != tc.discarded {
			t.Errorf("%s: raw counts not carried through: %+v", tc.name, got)
		}
	}
}
