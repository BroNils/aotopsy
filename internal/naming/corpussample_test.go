package naming

import (
	"testing"

	"aotopsy/internal/samplecorpus"
)

// Sample binaries for the naming tests, resolved from the corpus.
//
// These used to come from AOTOPSY_TEST_SAMPLE_* environment variables and
// skipped when unset, which meant they never ran -- the same silent-skip
// problem the analysis package had.
const (
	sampleARM64Name   = "dart-3.9.2-gt-arm64.so"
	sample312X64Name  = "dart-3.12.2-x64.so"
	sampleDart212Name = "dart-2.12.0-arm64.so"
)

// corpusSample resolves a sample by file name. No samples/ directory at
// all (fresh clone, CI) skips; a corpus that has one but not this sample
// fails. See samplecorpus.Available for why those are different.
func corpusSample(t *testing.T, name string) string {
	t.Helper()
	p := samplecorpus.Path(name)
	if p == "" {
		if !samplecorpus.Available() {
			t.Skipf("no samples/ directory in this checkout; %s cannot be resolved", name)
		}
		t.Fatalf("corpus sample %s is missing from samples/; restore it rather than skipping", name)
	}
	return p
}
