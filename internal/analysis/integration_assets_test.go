package analysis

import (
	"os"
	"path/filepath"
	"testing"
)

// The Ghidra/IDA integration assets were absent from a clean clone for several
// releases: an unanchored `aotopsy_*` line in .gitignore swallowed them, so
// `make install` died on a glob that expanded to nothing (issue #17) and the
// runtime discovery below had nothing to find. These tests hold the whole
// contract -- the files exist in the source tree, discovery finds them in the
// installed layout, and the artifact copies are what callers execute.

// integrationAssets are the paths, relative to the repository root, that both
// `make install` and .goreleaser.yaml must ship. Keep the three lists in sync.
var integrationAssets = []string{
	"ghidra_scripts/aotopsy_prescript.py",
	"ghidra_scripts/aotopsy_apply.py",
	"ghidra_scripts/AARCH64_dart.cspec",
	"ida_scripts/aotopsy_apply.py",
}

// repoRoot walks up from the test's working directory to the directory holding
// go.mod. Tests run in the package directory, so no relative asset path works
// without this.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod above %s", dir)
		}
		dir = parent
	}
}

func TestIntegrationAssetsPresentInSourceTree(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range integrationAssets {
		st, err := os.Stat(filepath.Join(root, rel))
		if err != nil {
			t.Errorf("%s: %v (make install and the release archive both ship this file)", rel, err)
			continue
		}
		if st.Size() == 0 {
			t.Errorf("%s: empty; a placeholder is not an integration script", rel)
		}
	}
}

// setHome points os.UserHomeDir at dir. Both variables are set because
// UserHomeDir reads USERPROFILE on Windows and HOME elsewhere, and the CI
// matrix runs all three platforms.
func setHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

// installLayout builds the directory tree `make install` produces under a
// throwaway HOME and returns that HOME.
func installLayout(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	home := t.TempDir()
	for _, rel := range integrationAssets {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		dst := filepath.Join(home, ".aotopsy", rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dst, err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("write %s: %v", dst, err)
		}
	}
	return home
}

func TestFindScriptPathUsesInstalledLayout(t *testing.T) {
	home := installLayout(t)
	setHome(t, home)

	got, err := FindScriptPath()
	if err != nil {
		t.Fatalf("FindScriptPath: %v", err)
	}
	want := filepath.Join(home, ".aotopsy", "ghidra_scripts")
	if got != want {
		t.Fatalf("FindScriptPath = %s, want %s", got, want)
	}
	for _, name := range []string{"aotopsy_prescript.py", "aotopsy_apply.py"} {
		if _, err := os.Stat(filepath.Join(got, name)); err != nil {
			t.Errorf("%s missing under discovered dir: %v", name, err)
		}
	}
}

// A directory holding only one of the two Ghidra scripts must be rejected:
// half an install is what silently produced a Ghidra run with no preScript.
func TestFindScriptPathRejectsPartialInstall(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".aotopsy", "ghidra_scripts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "aotopsy_apply.py"), []byte("# apply\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	setHome(t, home)

	got, err := FindScriptPath()
	if err == nil {
		t.Fatalf("FindScriptPath accepted a dir without aotopsy_prescript.py: %s", got)
	}
}

func TestFindIDAScriptUsesInstalledLayout(t *testing.T) {
	home := installLayout(t)
	setHome(t, home)

	got, err := FindIDAScript()
	if err != nil {
		t.Fatalf("FindIDAScript: %v", err)
	}
	want := filepath.Join(home, ".aotopsy", "ida_scripts", "aotopsy_apply.py")
	if got != want {
		t.Fatalf("FindIDAScript = %s, want %s", got, want)
	}
}

func TestCopyGhidraArtifactsReturnsSelfContainedDir(t *testing.T) {
	home := installLayout(t)
	setHome(t, home)
	outDir := t.TempDir()

	scriptPath, err := CopyGhidraArtifacts(outDir)
	if err != nil {
		t.Fatalf("CopyGhidraArtifacts: %v", err)
	}

	absOut, err := filepath.Abs(outDir)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	wantDir := filepath.Join(absOut, "ghidra")
	if scriptPath != wantDir {
		t.Fatalf("scriptPath = %s, want %s (Ghidra must run against the copy, not the install)", scriptPath, wantDir)
	}

	root := repoRoot(t)
	for _, name := range []string{"aotopsy_prescript.py", "aotopsy_apply.py"} {
		got, err := os.ReadFile(filepath.Join(scriptPath, name))
		if err != nil {
			t.Errorf("read copied %s: %v", name, err)
			continue
		}
		want, err := os.ReadFile(filepath.Join(root, "ghidra_scripts", name))
		if err != nil {
			t.Fatalf("read source %s: %v", name, err)
		}
		if string(got) != string(want) {
			t.Errorf("copied %s differs from source", name)
		}
	}
}

func TestCopyIDAArtifactsReturnsCopiedScript(t *testing.T) {
	home := installLayout(t)
	setHome(t, home)
	outDir := t.TempDir()

	scriptPath, err := CopyIDAArtifacts(outDir)
	if err != nil {
		t.Fatalf("CopyIDAArtifacts: %v", err)
	}

	absOut, err := filepath.Abs(outDir)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	want := filepath.Join(absOut, "ida", "aotopsy_apply.py")
	if scriptPath != want {
		t.Fatalf("scriptPath = %s, want %s (the executed script must be the copy)", scriptPath, want)
	}

	got, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read copied script: %v", err)
	}
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "ida_scripts", "aotopsy_apply.py"))
	if err != nil {
		t.Fatalf("read source script: %v", err)
	}
	if string(got) != string(src) {
		t.Errorf("copied IDA script differs from source")
	}
}

// Missing assets must surface as an error, not as a silent no-op that leaves
// the caller pointing at an empty artifact directory.
func TestCopyArtifactsFailsWhenAssetsMissing(t *testing.T) {
	setHome(t, t.TempDir())
	// Run from a directory with no ghidra_scripts/ or ida_scripts/ so the
	// relative discovery candidates cannot find the repository's own copies.
	t.Chdir(t.TempDir())
	outDir := t.TempDir()

	if got, err := CopyGhidraArtifacts(outDir); err == nil {
		t.Errorf("CopyGhidraArtifacts succeeded with no assets installed: %s", got)
	}
	if got, err := CopyIDAArtifacts(outDir); err == nil {
		t.Errorf("CopyIDAArtifacts succeeded with no assets installed: %s", got)
	}
}
