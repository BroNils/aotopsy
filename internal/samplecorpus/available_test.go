package samplecorpus_test

import (
	"os"
	"path/filepath"
	"testing"

	"aotopsy/internal/samplecorpus"
)

// TestAvailableFalseWithoutCorpus pins the contract CI depends on.
//
// .github/workflows/ci.yml states it in a comment -- "Ground-truth sample
// binaries are not redistributable, so the symtab-differential / golden
// gates skip cleanly here" -- and nothing verified it. When the
// sample-driven suite was rebound to the corpus and taught to fail on a
// missing sample, that turned 34 tests red on every CI runner and the
// break was only visible after pushing.
//
// samples/ is gitignored deliberately, so "no corpus" is a permanent,
// legitimate state for a fresh clone. Available() is what separates it
// from "corpus present but incomplete", which must still fail.
func TestAvailableFalseWithoutCorpus(t *testing.T) {
	// t.Chdir restores the working directory and rejects parallel tests,
	// so this cannot leak into the rest of the package.
	t.Chdir(t.TempDir())
	if samplecorpus.Available() {
		t.Fatal("Available() is true in a directory tree with no samples/; " +
			"every sample-driven test would then fail instead of skipping, " +
			"which is what breaks CI")
	}
	if p := samplecorpus.Path(Registry0FileName()); p != "" {
		t.Errorf("Path resolved %q with no corpus present", p)
	}
}

// TestAvailableTrueWithCorpus is the other half: when a samples/
// directory does exist, Available must say so, or the incomplete-corpus
// failure path can never fire and the suite goes back to skipping
// silently -- the state it spent months in.
func TestAvailableTrueWithCorpus(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "samples"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if !samplecorpus.Available() {
		t.Fatal("Available() is false with a samples/ directory present")
	}
	// Present but empty: a specific sample still does not resolve, which
	// is the case callers must treat as a failure rather than a skip.
	if p := samplecorpus.Path(Registry0FileName()); p != "" {
		t.Errorf("Path resolved %q from an empty samples/", p)
	}
}

func Registry0FileName() string {
	if len(samplecorpus.Registry) == 0 {
		return "dart-3.9.2-arm64.so"
	}
	return samplecorpus.Registry[0].FileName()
}
