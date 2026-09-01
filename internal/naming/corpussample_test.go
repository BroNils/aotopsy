package naming

import (
	"testing"

	"aotopsy/internal/samplecorpus"
)

// Sample binaries for the naming tests, resolved from the corpus.
//
// These used to come from AOTOPSY_TEST_SAMPLE_* environment variables and
// skipped when unset, which meant they never ran -- the same silent-skip
// problem the analysis package had. A missing sample is a failure now.
const (
	sampleARM64Name   = "dart-3.9.2-gt-arm64.so"
	sample312X64Name  = "dart-3.12.2-x64.so"
	sampleDart212Name = "dart-2.12.0-arm64.so"
)

func corpusSample(t *testing.T, name string) string {
	t.Helper()
	p := samplecorpus.Path(name)
	if p == "" {
		t.Fatalf("corpus sample %s is missing; restore it rather than skipping", name)
	}
	return p
}
