package output

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestContainsPathAndSamePath(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "nested", "file.so")
	if err := os.MkdirAll(filepath.Dir(child), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(child, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	contained, err := ContainsPath(root, child)
	if err != nil || !contained {
		t.Fatalf("ContainsPath(root, child) = %v, %v", contained, err)
	}
	sibling := filepath.Join(filepath.Dir(root), filepath.Base(root)+"-sibling", "x")
	contained, err = ContainsPath(root, sibling)
	if err != nil {
		t.Fatal(err)
	}
	if contained {
		t.Fatal("sibling path was classified as contained")
	}
	same, err := SamePath(child, filepath.Join(root, "nested", ".", "file.so"))
	if err != nil || !same {
		t.Fatalf("SamePath canonical = %v, %v", same, err)
	}
}

func TestSamePathRecognizesWindowsCaseAliasBeforeCreation(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows path comparison is case-insensitive")
	}
	dir := t.TempDir()
	a := filepath.Join(dir, "Future", "Artifact.txt")
	b := filepath.Join(dir, "future", "artifact.TXT")
	same, err := SamePath(a, b)
	if err != nil || !same {
		t.Fatalf("SamePath(case aliases) = %v, %v; want true,nil", same, err)
	}
}

func TestSamePathRecognizesHardLinks(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
	same, err := SamePath(a, b)
	if err != nil || !same {
		t.Fatalf("SamePath(hard links) = %v, %v; want true,nil", same, err)
	}
}

func TestContainsPathResolvesSymlinkAliases(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation may require elevated privileges")
	}
	realRoot := t.TempDir()
	parent := t.TempDir()
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(realRoot, alias); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	inside := filepath.Join(realRoot, "libapp.so")
	if err := os.WriteFile(inside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	contained, err := ContainsPath(alias, inside)
	if err != nil || !contained {
		t.Fatalf("symlink alias containment = %v, %v", contained, err)
	}
}

func TestBeginDirTransactionRejectsRegularFileTarget(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "out")
	const original = "do not replace me"
	if err := os.WriteFile(target, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if tx, err := BeginDirTransaction(target); err == nil {
		tx.Abort()
		t.Fatal("regular-file output target was accepted as a directory transaction")
	}
	b, err := os.ReadFile(target)
	if err != nil || string(b) != original {
		t.Fatalf("rejected target changed: %q, %v", b, err)
	}
}

func TestBeginDirTransactionRejectsSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation may require elevated privileges")
	}
	parent := t.TempDir()
	realTarget := filepath.Join(parent, "real")
	if err := os.Mkdir(realTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "out")
	if err := os.Symlink(realTarget, target); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if tx, err := BeginDirTransaction(target); err == nil {
		tx.Abort()
		t.Fatal("symlink output target was accepted as a directory transaction")
	}
	if info, err := os.Lstat(target); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("rejected symlink target changed: mode=%v err=%v", info, err)
	}
}

func TestDirTransactionRefusesTargetThatAppearsBeforeCommit(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "out")
	tx, err := BeginDirTransaction(target)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Abort()
	if err := os.WriteFile(filepath.Join(tx.StageDir(), "fresh.txt"), []byte("fresh"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(target, "sentinel")
	if err := os.WriteFile(sentinel, []byte("external"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err == nil {
		t.Fatal("commit replaced a directory that appeared after BeginDirTransaction")
	}
	b, err := os.ReadFile(sentinel)
	if err != nil || string(b) != "external" {
		t.Fatalf("concurrent target was changed: %q, %v", b, err)
	}
}

func TestDirTransactionCommitReplacesExistingGeneration(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "out")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "old.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	tx, err := BeginDirTransaction(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tx.StageDir(), "new.txt"), []byte("new"), 0o600); err != nil {
		tx.Abort()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		tx.Abort()
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(target, "new.txt")); err != nil || string(b) != "new" {
		t.Fatalf("new generation = %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(target, "old.txt")); !os.IsNotExist(err) {
		t.Fatalf("old generation survived commit: %v", err)
	}
}

func TestDirTransactionCommitSupportsRelativeExistingTarget(t *testing.T) {
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalWD); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	target := filepath.Join("nested", "out")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "old.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	tx, err := BeginDirTransaction(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tx.StageDir(), "new.txt"), []byte("new"), 0o600); err != nil {
		tx.Abort()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		tx.Abort()
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(target, "new.txt")); err != nil || string(b) != "new" {
		t.Fatalf("new generation = %q, %v", b, err)
	}
}

func TestDirTransactionCommitOnWorkingTreeFilesystem(t *testing.T) {
	// Keep this temporary directory on the same filesystem as the package.
	// On WSL DrvFS (/mnt/<drive>), an os.Root opened before rename may keep a
	// stale directory namespace after Root.Rename even though the rename itself
	// succeeded. t.TempDir() normally lives on /tmp and cannot exercise that
	// behavior.
	base, err := os.MkdirTemp(".", ".aotopsy-transaction-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Errorf("remove transaction test directory: %v", err)
		}
	})

	target := filepath.Join(base, "out")
	tx, err := BeginDirTransaction(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tx.StageDir(), "new.txt"), []byte("new"), 0o600); err != nil {
		tx.Abort()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		tx.Abort()
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(target, "new.txt")); err != nil || string(b) != "new" {
		t.Fatalf("new generation = %q, %v", b, err)
	}
}

func TestDirTransactionReplaceExistingOnWorkingTreeFilesystem(t *testing.T) {
	base, err := os.MkdirTemp(".", ".aotopsy-transaction-replace-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Errorf("remove transaction test directory: %v", err)
		}
	})

	target := filepath.Join(base, "out")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "old.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	tx, err := BeginDirTransaction(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tx.StageDir(), "new.txt"), []byte("new"), 0o600); err != nil {
		tx.Abort()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		tx.Abort()
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(target, "new.txt")); err != nil || string(b) != "new" {
		t.Fatalf("new generation = %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(target, "old.txt")); !os.IsNotExist(err) {
		t.Fatalf("old generation survived commit: %v", err)
	}
}

func TestDirTransactionRefusesExistingTargetIdentityChange(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "out")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	tx, err := BeginDirTransaction(target)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Abort()
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(target, "sentinel")
	if err := os.WriteFile(sentinel, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err == nil {
		t.Fatal("commit replaced a different directory at the same pathname")
	}
	b, err := os.ReadFile(sentinel)
	if err != nil || string(b) != "replacement" {
		t.Fatalf("replacement target was changed: %q, %v", b, err)
	}
}

func TestDirTransactionAbortDoesNotRemoveSubstitutedStage(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "out")
	tx, err := BeginDirTransaction(target)
	if err != nil {
		t.Fatal(err)
	}
	stage := tx.StageDir()
	moved := stage + "-moved"
	if err := os.Rename(stage, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(stage, "external")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	tx.Abort()
	if b, err := os.ReadFile(sentinel); err != nil || string(b) != "keep" {
		t.Fatalf("Abort removed substituted staging directory: %q, %v", b, err)
	}
}

func TestRestoreDirectoryBackupRejectsSubstitution(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "out")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	tx, err := BeginDirTransaction(target)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Abort()
	backup := dirBackupPrefix + "test"
	if err := tx.parentRoot.Rename(tx.targetName, backup); err != nil {
		t.Fatal(err)
	}
	tx.backupName = backup
	movedOld := backup + "-old"
	if err := tx.parentRoot.Rename(backup, movedOld); err != nil {
		t.Fatal(err)
	}
	if err := tx.parentRoot.Mkdir(backup, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := tx.restoreDirectoryBackup(); err == nil {
		t.Fatal("restore accepted a substituted backup directory")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("substituted backup was restored to target: %v", err)
	}
	if info, err := tx.parentRoot.Stat(backup); err != nil || !info.IsDir() {
		t.Fatalf("substituted backup was touched: mode=%v err=%v", info, err)
	}
}

func TestRestorePublishedDirectoryDoesNotRemoveSubstitutedTarget(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "out")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	tx, err := BeginDirTransaction(target)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Abort()
	backup := dirBackupPrefix + "test"
	if err := tx.parentRoot.Rename(tx.targetName, backup); err != nil {
		t.Fatal(err)
	}
	tx.backupName = backup
	if err := tx.parentRoot.Rename(tx.stageName, tx.targetName); err != nil {
		t.Fatal(err)
	}
	tx.stageName = ""
	tx.stage = ""
	movedStage := "published-moved"
	if err := tx.parentRoot.Rename(tx.targetName, movedStage); err != nil {
		t.Fatal(err)
	}
	if err := tx.parentRoot.Mkdir(tx.targetName, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(target, "external")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tx.restorePublishedDirectory(); err == nil {
		t.Fatal("restore unexpectedly succeeded after published target substitution")
	}
	if b, err := os.ReadFile(sentinel); err != nil || string(b) != "keep" {
		t.Fatalf("restore removed substituted target: %q, %v", b, err)
	}
}

func TestBeginDirTransactionSupportsLongTargetName(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, strings.Repeat("x", 220))
	tx, err := BeginDirTransaction(target)
	if err != nil {
		t.Fatalf("BeginDirTransaction with valid long target name: %v", err)
	}
	tx.Abort()
}

func TestCloneTreeRejectsSymlinkRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation may require elevated privileges")
	}
	parent := t.TempDir()
	realSource := filepath.Join(parent, "real")
	if err := os.Mkdir(realSource, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realSource, "artifact"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(realSource, alias); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := CloneTree(alias, t.TempDir()); err == nil {
		t.Fatal("CloneTree accepted a symlink root")
	}
}
