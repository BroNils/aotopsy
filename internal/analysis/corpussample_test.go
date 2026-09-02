package analysis

import (
	"testing"

	"aotopsy/internal/samplecorpus"
)

// Sample binaries for the regression suite, resolved from the corpus.
//
// These used to come from per-test environment variables --
// AOTOPSY_TEST_SAMPLE_ARM64 and four siblings -- and an unset variable
// skipped. Nobody sets five environment variables, so roughly 25 test
// functions across a dozen files had been skipping silently while
// `go test ./internal/...` reported ok. That included the golden gate,
// TestBLRResolutionRate, the pipeline regression suite, and every
// PcDescriptors, instance-field and CHA assertion.
//
// A missing sample is now a failure. The corpus is checked in as
// symlinks and samplecorpus.Path resolves them, so "not set" is not a
// situation that should exist; if a sample really is gone, the fix is to
// restore it, not to let the assertions evaporate.
const (
	// The 3.9.2 ground-truth twin of compare_sample: same app as the
	// stripped dart-3.9.2-arm64.so but built --no-strip, so it carries a
	// .symtab. Tests here assert on recovered names, which is exactly
	// what the unstripped build lets us check.
	//
	// The older extracted_*/ builds of this app contain no
	// AntiInlineTools, no safeDivide and no ground_truth.dart at all;
	// pointing these tests at one of those fails for reasons unrelated to
	// the code. The corpus entry is the merged_native_libs build.
	sampleARM64Name = "dart-3.9.2-gt-arm64.so"

	// The Dart package the above sample's own libraries live under. The
	// test app has been rebuilt under different package names over time
	// (it was compare_sample when these assertions were written), so this
	// sits next to the sample name: change one and the other has to move
	// with it. Hardcoding the old name in each test is how they came to
	// assert against an app that is not in the corpus.
	sampleARM64Package = "sample_dart_392"

	// Dart 2.12 takes a different instructions path entirely (text-offset
	// deltas, no InstructionsTable).
	sampleDart212Name = "dart-2.12.0-arm64.so"

	sample312ARM64Name = "dart-3.12.2-arm64.so"
	sample312X64Name   = "dart-3.12.2-x64.so"

	// A real production app, an order of magnitude larger than the
	// synthetic samples. Only used by tests that stop at the cluster
	// stage -- a full pipeline run on it exhausts this machine.
	sampleLargeName = "dart-3.12.2-realapp-arm64.so"
)

// corpusSample resolves a sample by file name.
//
// Missing samples are treated two different ways on purpose. samples/ is
// gitignored, so a fresh clone and every CI runner has no corpus at all
// and these tests have nothing to assert against -- they skip. But when a
// corpus IS present and this one sample is not in it, the corpus has
// drifted from the registry, and that fails: silently skipping is exactly
// how roughly 25 test functions spent months reporting ok while running
// nothing.
func corpusSample(t *testing.T, name string) string {
	t.Helper()
	p := samplecorpus.Path(name)
	if p == "" {
		if !samplecorpus.Available() {
			t.Skipf("no samples/ directory in this checkout; %s cannot be resolved", name)
		}
		t.Fatalf("corpus sample %s is missing from samples/.\n"+
			"  Restore it rather than skipping: a regression test that cannot find its\n"+
			"  input is not a passing test, and this suite spent months in that state.", name)
	}
	return p
}

func sampleARM64(t *testing.T) string    { return corpusSample(t, sampleARM64Name) }
func sampleDart212(t *testing.T) string  { return corpusSample(t, sampleDart212Name) }
func sample312ARM64(t *testing.T) string { return corpusSample(t, sample312ARM64Name) }
func sample312X64(t *testing.T) string   { return corpusSample(t, sample312X64Name) }
func sampleLarge(t *testing.T) string    { return corpusSample(t, sampleLargeName) }
