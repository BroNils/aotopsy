package artifactfs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestWriteAtomicFailurePreservesCurrentArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.txt")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("encode failed")
	err := WriteAtomic(path, 0o600, func(w io.Writer) error {
		if _, err := w.Write([]byte("new-partial")); err != nil {
			return err
		}
		return injected
	})
	if !errors.Is(err, injected) {
		t.Fatalf("WriteAtomic error = %v, want injected failure", err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "old" {
		t.Fatalf("current artifact = %q, %v; want old", b, err)
	}
}

func TestAbortDoesNotDeleteSubstitutedTemp(t *testing.T) {
	dir := t.TempDir()
	a, err := NewAtomicFile(filepath.Join(dir, "artifact"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write([]byte("ours")); err != nil {
		t.Fatal(err)
	}
	tempName := a.tempName
	moved := tempName + ".moved"
	if err := a.root.Rename(tempName, moved); err != nil {
		t.Fatal(err)
	}
	replacement, err := a.root.OpenFile(tempName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.Write([]byte("external")); err != nil {
		t.Fatal(err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.Abort(); err == nil {
		t.Fatal("Abort did not report substituted temp")
	}
	b, err := os.ReadFile(filepath.Join(dir, tempName))
	if err != nil || string(b) != "external" {
		t.Fatalf("substituted temp = %q, %v; cleanup must not remove it", b, err)
	}
}

func TestCommitRejectsSubstitutedTempAndPreservesCurrentArtifact(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "artifact")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := NewAtomicFile(target, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write([]byte("ours")); err != nil {
		t.Fatal(err)
	}
	tempName := a.tempName
	if err := a.root.Rename(tempName, tempName+".moved"); err != nil {
		t.Fatal(err)
	}
	replacement, err := a.root.OpenFile(tempName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.Write([]byte("external")); err != nil {
		t.Fatal(err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.Commit(); err == nil {
		t.Fatal("Commit accepted substituted temp")
	}
	b, err := os.ReadFile(target)
	if err != nil || string(b) != "old" {
		t.Fatalf("current artifact = %q, %v; want old", b, err)
	}
	b, err = os.ReadFile(filepath.Join(dir, tempName))
	if err != nil || string(b) != "external" {
		t.Fatalf("substituted temp = %q, %v; cleanup must not remove it", b, err)
	}
}

func TestCommitDirectorySyncFailureRestoresPreviousArtifact(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "artifact")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := NewAtomicFile(target, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	originalSync := syncDirectory
	defer func() { syncDirectory = originalSync }()
	injected := errors.New("directory fsync failed")
	calls := 0
	syncDirectory = func(root *os.Root) error {
		calls++
		if calls == 2 { // backup is durable; publication metadata sync fails
			return injected
		}
		return originalSync(root)
	}
	if err := a.Commit(); !errors.Is(err, injected) {
		t.Fatalf("Commit error = %v, want injected directory sync failure", err)
	}
	b, err := os.ReadFile(target)
	if err != nil || string(b) != "old" {
		t.Fatalf("failed publication left artifact = %q, %v; want restored old", b, err)
	}
}

func TestWriteAtomicUnderRejectsTraversalAndPortableUnsafeNames(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{
		"../escape", `..\escape`, "a/../escape", "/absolute", "file.txt:stream",
		"NUL", "Owner/CON", "Owner/COM1", "Owner/LPT²", "Owner/trailing.", "Owner/trailing ",
	} {
		if err := WriteAtomicUnder(root, rel, 0o600, func(w io.Writer) error {
			_, err := w.Write([]byte("x"))
			return err
		}); err == nil {
			t.Errorf("WriteAtomicUnder(%q) accepted unsafe name", rel)
		}
	}
}

func TestWriteAtomicUnderRejectsSymlinkAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation may require elevated privileges")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "Owner")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	err := WriteAtomicUnder(root, "Owner/f.txt", 0o600, func(w io.Writer) error {
		_, err := w.Write([]byte("escape"))
		return err
	})
	if err == nil {
		t.Fatal("WriteAtomicUnder followed symlink ancestor")
	}
	if _, err := os.Stat(filepath.Join(outside, "f.txt")); !os.IsNotExist(err) {
		t.Fatalf("outside target was modified: %v", err)
	}
}

func TestWriteAtomicUnderAllowsGroupedArtifact(t *testing.T) {
	root := t.TempDir()
	err := WriteAtomicUnder(root, "Owner/method_1000.txt", 0o640, func(w io.Writer) error {
		_, err := w.Write([]byte("ok"))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "Owner", "method_1000.txt")
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "ok" {
		t.Fatalf("grouped artifact = %q, %v", b, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		// Go's Windows chmod contract uses only owner-write (0200) to toggle
		// the read-only attribute; POSIX group/other bits do not round-trip.
		if info.Mode().Perm()&0o200 == 0 {
			t.Fatalf("grouped artifact unexpectedly read-only on Windows: %v", info.Mode())
		}
	} else if info.Mode().Perm() != 0o640 {
		t.Fatalf("grouped artifact mode = %v, want 0640", info.Mode().Perm())
	}
}

func TestWriteAtomicUnderConcurrentGroupedArtifactsShareDirectory(t *testing.T) {
	root := t.TempDir()
	const writers = 24
	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rel := filepath.ToSlash(filepath.Join("Owner", fmt.Sprintf("method_%02d.txt", i)))
			errs <- WriteAtomicUnder(root, rel, 0o600, func(w io.Writer) error {
				_, err := w.Write([]byte("ok"))
				return err
			})
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent grouped write failed: %v", err)
		}
	}
	for i := 0; i < writers; i++ {
		if _, err := os.Stat(filepath.Join(root, "Owner", fmt.Sprintf("method_%02d.txt", i))); err != nil {
			t.Fatalf("missing concurrent artifact %d: %v", i, err)
		}
	}
}
