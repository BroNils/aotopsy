package output

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPublishFileSetPublishesAndRemovesOneGeneration(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	stale := filepath.Join(dir, "stale.txt")
	for path, data := range map[string]string{a: "old-a", b: "old-b", stale: "old-stale"} {
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := PublishFileSet([]FileArtifact{
		{Path: a, Data: []byte("new-a"), Perm: 0o600},
		{Path: b, Data: []byte("new-b"), Perm: 0o644},
		{Path: stale, Remove: true},
	}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{a: "new-a", b: "new-b"} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v; want %q", path, got, err, want)
		}
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale managed file survived: %v", err)
	}
}

func TestPublishFileSetRejectsDuplicateDestinationBeforeMutation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "artifact")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := PublishFileSet([]FileArtifact{
		{Path: p, Data: []byte("one")},
		{Path: filepath.Join(dir, ".", "artifact"), Data: []byte("two")},
	})
	if err == nil {
		t.Fatal("duplicate canonical destination was accepted")
	}
	b, readErr := os.ReadFile(p)
	if readErr != nil || string(b) != "old" {
		t.Fatalf("duplicate validation mutated old file: %q, %v", b, readErr)
	}
}

func TestPublishFileSetRejectsCaseAliasOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows path comparison is case-insensitive")
	}
	dir := t.TempDir()
	err := PublishFileSet([]FileArtifact{
		{Path: filepath.Join(dir, "Artifact.txt"), Data: []byte("one")},
		{Path: filepath.Join(dir, "artifact.txt"), Data: []byte("two")},
	})
	if err == nil {
		t.Fatal("case-aliased destinations were accepted")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "Artifact.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("duplicate validation published a file: %v", statErr)
	}
}

func TestPublishFileSetRejectsFinalSymlinkWithoutTouchingTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation may require elevated privileges")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("keep-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "managed.txt")
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	err := PublishFileSet([]FileArtifact{{Path: link, Data: []byte("replacement")}})
	if err == nil {
		t.Fatal("final-component symlink was accepted")
	}
	got, readErr := os.ReadFile(victim)
	if readErr != nil || string(got) != "keep-me" {
		t.Fatalf("symlink target changed: %q, %v", got, readErr)
	}
	info, statErr := os.Lstat(link)
	if statErr != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("rejected symlink was changed: mode=%v err=%v", info, statErr)
	}
}
