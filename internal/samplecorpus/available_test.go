package samplecorpus

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCorpusRootAbsentIsDistinctFromMissingSample(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := CorpusRoot(); !errors.Is(err, ErrNoCorpus) {
		t.Fatalf("CorpusRoot error = %v, want ErrNoCorpus", err)
	}
	if _, err := RequireSample(Registry0FileName()); !errors.Is(err, ErrNoCorpus) {
		t.Fatalf("RequireSample error = %v, want ErrNoCorpus", err)
	}
}

func TestRequireCompleteCorpusTreatsPresentEmptyCorpusAsIncomplete(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "samples"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	if err := RequireCompleteCorpus(); err == nil || errors.Is(err, ErrNoCorpus) {
		t.Fatalf("RequireCompleteCorpus error = %v, want present-but-incomplete corpus failure", err)
	}
}

func TestResolveSamplePathUsesNearestCorpusRootOnly(t *testing.T) {
	base := t.TempDir()
	name := Registry0FileName()
	outer := filepath.Join(base, "samples")
	inner := filepath.Join(base, "nested", "samples")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outer, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outer, name), []byte("outer"), 0o644); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(base, "nested", "pkg")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	if _, err := resolveSamplePath(name); !errors.Is(err, ErrSampleMissing) {
		t.Fatalf("resolveSamplePath error = %v, want nearest-root ErrSampleMissing", err)
	}
}

func TestCorpusRootDoesNotFallThroughDanglingNearestRoot(t *testing.T) {
	base := t.TempDir()
	outer := filepath.Join(base, "samples")
	if err := os.Mkdir(outer, 0o755); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(base, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "missing-corpus"), filepath.Join(nested, "samples")); err != nil {
		t.Skipf("symlink unavailable on this filesystem: %v", err)
	}
	work := filepath.Join(nested, "pkg")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	if _, err := CorpusRoot(); err == nil || errors.Is(err, ErrNoCorpus) {
		t.Fatalf("CorpusRoot error = %v, want dangling nearest corpus to be an inconsistency", err)
	}
}

func TestResolveSamplePathRejectsTraversalAndSeparators(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "samples"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	for _, name := range []string{"../escape.so", "a/b.so", `a\b.so`, ".", ".."} {
		if _, err := resolveSamplePath(name); err == nil {
			t.Errorf("resolveSamplePath(%q) unexpectedly succeeded", name)
		}
	}
}

func TestResolveSamplePathRequiresRegularFile(t *testing.T) {
	root := t.TempDir()
	samples := filepath.Join(root, "samples")
	if err := os.Mkdir(samples, 0o755); err != nil {
		t.Fatal(err)
	}
	name := Registry0FileName()
	if err := os.Mkdir(filepath.Join(samples, name), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	if _, err := resolveSamplePath(name); err == nil {
		t.Fatal("directory masquerading as a sample was accepted")
	}
}

func TestResolveSamplePathAcceptsSymlinkToRegularFile(t *testing.T) {
	root := t.TempDir()
	samples := filepath.Join(root, "samples")
	if err := os.Mkdir(samples, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target.so")
	if err := os.WriteFile(target, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	name := Registry0FileName()
	if err := os.Symlink(target, filepath.Join(samples, name)); err != nil {
		t.Skipf("symlink unavailable on this filesystem: %v", err)
	}
	t.Chdir(root)
	p, err := resolveSamplePath(name)
	if err != nil {
		t.Fatalf("resolveSamplePath(symlink): %v", err)
	}
	if filepath.Base(p) != name {
		t.Fatalf("resolved %q, want basename %q", p, name)
	}
}

func Registry0FileName() string {
	if len(Registry) == 0 {
		return "dart-3.9.2-arm64.so"
	}
	return Registry[0].FileName()
}

func TestRequireSampleRejectsUnregisteredNameBeforeFilesystemLookup(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := RequireSample("dart-9.9.9-arm64.so"); !errors.Is(err, ErrSampleUnregistered) {
		t.Fatalf("RequireSample error = %v, want ErrSampleUnregistered", err)
	}
}
