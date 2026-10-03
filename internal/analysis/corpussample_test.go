package analysis

import (
	"errors"
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
// A missing sample is now a failure once a local corpus exists. samples/ is a
// local symlink view of the stable ~/dev/aotopsy_samples store, and
// samplecorpus.RequireSample resolves it through the central manifest/registry;
// if a member is gone, the fix is to restore it, not to let assertions evaporate.
const (
	// The canonical stripped 3.9.2 compare_sample. General analysis tests must
	// exercise production conditions; the -gt symbol oracle is reserved for
	// TestSymtabDifferential because pipeline.Run can consult .symtab as a
	// last-resort naming source.
	//
	// The older extracted_*/ builds of this app contain no
	// AntiInlineTools, no safeDivide and no ground_truth.dart at all;
	// pointing these tests at one of those fails for reasons unrelated to
	// the code. The corpus entry is the validated canonical stripped build.
	sampleARM64Name = "dart-3.9.2-arm64.so"

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
	p, err := samplecorpus.RequireSample(name)
	if errors.Is(err, samplecorpus.ErrNoCorpus) {
		t.Skipf("no samples/ directory in this checkout; %s cannot be resolved", name)
	}
	if err != nil {
		t.Fatalf("corpus sample %s cannot be used: %v\n"+
			"  Restore/fix it rather than skipping: a regression test that cannot read its\n"+
			"  input is not a passing test, and this suite spent months in that state.", name, err)
	}
	return p
}

func requireCompleteCorpus(t *testing.T) {
	t.Helper()
	err := samplecorpus.RequireCompleteCorpus()
	if errors.Is(err, samplecorpus.ErrNoCorpus) {
		t.Skip("no samples/ directory in this checkout")
	}
	if err != nil {
		t.Fatalf("sample corpus is incomplete or inconsistent: %v", err)
	}
}

func sampleARM64(t *testing.T) string    { return corpusSample(t, sampleARM64Name) }
func sampleDart212(t *testing.T) string  { return corpusSample(t, sampleDart212Name) }
func sample312ARM64(t *testing.T) string { return corpusSample(t, sample312ARM64Name) }
func sample312X64(t *testing.T) string   { return corpusSample(t, sample312X64Name) }
func sampleLarge(t *testing.T) string    { return corpusSample(t, sampleLargeName) }
