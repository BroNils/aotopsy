package output

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"aotopsy/internal/artifactfs"
)

const (
	maxClonedOutputFiles = 250000
	maxClonedOutputBytes = int64(16 << 30)
	tempNameAttempts     = 128
	dirStagePrefix       = ".aotopsy-dir-stage-"
	dirBackupPrefix      = ".aotopsy-dir-previous-"
	generationMarkerData = "aotopsy-output-generation/v1\n"

	// GenerationMarker is written into every directory generation this package
	// publishes. Commit replaces the WHOLE previous directory, so it may only
	// do that to a directory it can prove an earlier aotopsy run produced (or
	// that is empty); otherwise `--out ~/projects/app` would delete the user's
	// files.
	GenerationMarker = ".aotopsy-generation"
)

// syncDirectory is a test seam for directory-transaction durability failures.
// Production always points at artifactfs.SyncRoot.
var syncDirectory = artifactfs.SyncRoot

// DirTransaction publishes a complete artifact generation with one directory
// rename. The target parent is held open for the lifetime of the transaction so
// path replacement cannot make commit operate in a different directory tree.
type DirTransaction struct {
	target        string
	parentPath    string
	targetName    string
	stage         string
	stageName     string
	backupName    string
	parentRoot    *os.Root
	targetRoot    *os.Root
	stageRoot     *os.Root
	targetInfo    os.FileInfo
	stageInfo     os.FileInfo
	targetExisted bool
}

func BeginDirTransaction(target string) (*DirTransaction, error) {
	if strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("output directory is empty")
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("resolve output directory: %w", err)
	}
	absTarget = filepath.Clean(absTarget)
	if base := filepath.Base(absTarget); base == "." || artifactfs.ValidateRelativePath(base) != nil {
		return nil, fmt.Errorf("unsafe output directory name %q", base)
	}
	parentInput := filepath.Dir(absTarget)
	if err := os.MkdirAll(parentInput, 0o755); err != nil {
		return nil, fmt.Errorf("create output parent: %w", err)
	}
	parentPath, err := canonicalPath(parentInput)
	if err != nil {
		return nil, fmt.Errorf("resolve output parent: %w", err)
	}
	parentRoot, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, fmt.Errorf("open output parent: %w", err)
	}

	tx := &DirTransaction{
		target:     filepath.Join(parentPath, filepath.Base(absTarget)),
		parentPath: parentPath,
		targetName: filepath.Base(absTarget),
		parentRoot: parentRoot,
	}
	fail := func(err error) (*DirTransaction, error) {
		tx.closeRoots()
		return nil, err
	}

	targetInfo, targetExisted, err := inspectDirectoryEntry(parentRoot, tx.targetName, tx.target)
	if err != nil {
		return fail(err)
	}
	tx.targetExisted = targetExisted
	if targetExisted {
		tx.targetRoot, err = parentRoot.OpenRoot(tx.targetName)
		if err != nil {
			return fail(fmt.Errorf("pin output directory %q: %w", tx.target, err))
		}
		pinned, err := tx.targetRoot.Stat(".")
		if err != nil {
			return fail(fmt.Errorf("stat pinned output directory %q: %w", tx.target, err))
		}
		if !os.SameFile(targetInfo, pinned) {
			return fail(fmt.Errorf("output directory %q changed while being pinned", tx.target))
		}
		tx.targetInfo = pinned
		if err := requireReplaceableGeneration(tx.targetRoot, tx.target); err != nil {
			return fail(err)
		}
	}

	stageName, err := makeTempDirInRoot(parentRoot, dirStagePrefix)
	if err != nil {
		return fail(fmt.Errorf("create output staging directory: %w", err))
	}
	tx.stageName = stageName
	tx.stage = filepath.Join(parentPath, stageName)
	tx.stageRoot, err = parentRoot.OpenRoot(stageName)
	if err != nil {
		_ = parentRoot.RemoveAll(stageName)
		return fail(fmt.Errorf("pin output staging directory: %w", err))
	}
	tx.stageInfo, err = tx.stageRoot.Stat(".")
	if err != nil {
		_ = parentRoot.RemoveAll(stageName)
		return fail(fmt.Errorf("stat pinned output staging directory: %w", err))
	}
	return tx, nil
}

// requireReplaceableGeneration refuses to let a transaction replace a
// directory that is neither empty nor a previous aotopsy generation.
func requireReplaceableGeneration(root *os.Root, display string) error {
	dir, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open output directory %q: %w", display, err)
	}
	names, err := dir.Readdirnames(1)
	_ = dir.Close()
	if errors.Is(err, io.EOF) || (err == nil && len(names) == 0) {
		return nil // empty: nothing to lose
	}
	if err != nil {
		return fmt.Errorf("read output directory %q: %w", display, err)
	}
	info, err := root.Lstat(GenerationMarker)
	if err == nil && info.Mode().IsRegular() {
		f, openErr := root.Open(GenerationMarker)
		if openErr != nil {
			return fmt.Errorf("open %s in %q: %w", GenerationMarker, display, openErr)
		}
		opened, statErr := f.Stat()
		if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
			_ = f.Close()
			if statErr == nil {
				statErr = fmt.Errorf("marker identity changed")
			}
			return fmt.Errorf("verify %s in %q: %w", GenerationMarker, display, statErr)
		}
		data, readErr := io.ReadAll(io.LimitReader(f, int64(len(generationMarkerData)+1)))
		closeErr := f.Close()
		if readErr != nil {
			return errors.Join(fmt.Errorf("read %s in %q: %w", GenerationMarker, display, readErr), closeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close %s in %q: %w", GenerationMarker, display, closeErr)
		}
		if string(data) == generationMarkerData {
			return nil
		}
		return fmt.Errorf("output directory %q has an invalid %s ownership marker; refusing to replace it", display, GenerationMarker)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s in %q: %w", GenerationMarker, display, err)
	}
	return fmt.Errorf("output directory %q is not empty and was not produced by aotopsy (no %s marker); "+
		"refusing to replace it -- choose a new or empty directory, or delete it yourself", display, GenerationMarker)
}

// stampGeneration writes the ownership marker into the unpublished stage.
func (tx *DirTransaction) stampGeneration() error {
	f, err := tx.stageRoot.OpenFile(GenerationMarker, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("write %s: %w", GenerationMarker, err)
	}
	if _, err := io.WriteString(f, generationMarkerData); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", GenerationMarker, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync %s: %w", GenerationMarker, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", GenerationMarker, err)
	}
	return nil
}

// validateAndSyncGeneration is the durability gate before publication. A
// directory transaction cannot assume every caller used output.WriteAtomic:
// external renderers and legacy callers may have populated StageDir directly.
// Commit therefore rejects links/special files, pins every regular file before
// syncing it, then syncs every directory from leaves to the stage root.
func validateAndSyncGeneration(root *os.Root) error {
	if root == nil {
		return fmt.Errorf("output staging root is nil")
	}
	type dirEntry struct {
		path string
		info os.FileInfo
	}
	dirs := []dirEntry{{path: "."}}
	err := fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == "." {
			return nil
		}
		if err := artifactfs.ValidateRelativePath(filepath.FromSlash(path)); err != nil {
			return fmt.Errorf("staged generation contains non-portable artifact path %s: %w", path, err)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("staged generation contains symlink %s", path)
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat staged artifact %s: %w", path, err)
		}
		if info.IsDir() {
			dirs = append(dirs, dirEntry{path: path, info: info})
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("staged generation contains non-regular artifact %s (%s)", path, info.Mode().Type())
		}
		if err := artifactfs.SyncRegularFile(root, path, info); err != nil {
			return fmt.Errorf("sync staged artifact %s: %w", path, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if dirs[i].path == "." {
			if err := syncDirectory(root); err != nil {
				return fmt.Errorf("sync staged generation root: %w", err)
			}
			continue
		}
		current, err := root.Lstat(dirs[i].path)
		if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(current, dirs[i].info) {
			if err == nil {
				err = fmt.Errorf("directory identity changed")
			}
			return fmt.Errorf("verify staged directory %s: %w", dirs[i].path, err)
		}
		sub, err := root.OpenRoot(dirs[i].path)
		if err != nil {
			return fmt.Errorf("pin staged directory %s: %w", dirs[i].path, err)
		}
		pinned, statErr := sub.Stat(".")
		if statErr != nil || !os.SameFile(current, pinned) {
			_ = sub.Close()
			if statErr == nil {
				statErr = fmt.Errorf("directory identity changed while being pinned")
			}
			return fmt.Errorf("verify pinned staged directory %s: %w", dirs[i].path, statErr)
		}
		syncErr := syncDirectory(sub)
		closeErr := sub.Close()
		if syncErr != nil {
			return errors.Join(fmt.Errorf("sync staged directory %s: %w", dirs[i].path, syncErr), closeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close staged directory %s: %w", dirs[i].path, closeErr)
		}
	}
	return nil
}

func (tx *DirTransaction) StageDir() string {
	if tx == nil {
		return ""
	}
	return tx.stage
}

// RemoveStageFile removes one top-level managed artifact from the unpublished
// generation. The pinned stage root keeps removal independent of pathname
// replacement outside the transaction; directories are deliberately refused.
func (tx *DirTransaction) RemoveStageFile(name string) error {
	if tx == nil || tx.stageRoot == nil || tx.stageName == "" {
		return fmt.Errorf("output transaction is not active")
	}
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, `/\`) || artifactfs.ValidateRelativePath(name) != nil {
		return fmt.Errorf("unsafe staged artifact name %q", name)
	}
	info, err := tx.stageRoot.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat staged artifact %q: %w", name, err)
	}
	if info.IsDir() {
		return fmt.Errorf("staged artifact %q is a directory", name)
	}
	if err := tx.stageRoot.Remove(name); err != nil {
		return fmt.Errorf("remove staged artifact %q: %w", name, err)
	}
	return nil
}

func (tx *DirTransaction) Abort() {
	if tx == nil {
		return
	}
	if tx.stageName != "" && tx.parentRoot != nil {
		// The staging path is visible to callers through StageDir. If another
		// process swaps that pathname, Abort must not recursively delete the
		// replacement. Only remove the directory we pinned at Begin.
		if same, _ := tx.nameMatchesPinnedDirectory(tx.stageName, tx.stageRoot); same {
			_ = tx.parentRoot.RemoveAll(tx.stageName)
		}
	}
	tx.stage = ""
	tx.stageName = ""
	tx.closeRoots()
}

func (tx *DirTransaction) Commit() error {
	if tx == nil || tx.stageName == "" || tx.parentRoot == nil || tx.stageRoot == nil {
		return fmt.Errorf("output transaction is not active")
	}
	if err := tx.stampGeneration(); err != nil {
		return err
	}
	if err := validateAndSyncGeneration(tx.stageRoot); err != nil {
		return fmt.Errorf("validate staged generation: %w", err)
	}

	stageInfo, err := tx.stageRoot.Stat(".")
	if err != nil {
		return fmt.Errorf("stat pinned staging directory: %w", err)
	}
	if tx.stageInfo == nil || !os.SameFile(tx.stageInfo, stageInfo) {
		return fmt.Errorf("output staging directory identity changed during transaction")
	}
	if same, err := tx.nameMatchesInfo(tx.stageName, tx.stageInfo); err != nil {
		return fmt.Errorf("verify staging directory pathname before commit: %w", err)
	} else if !same {
		return fmt.Errorf("output staging directory pathname changed during transaction")
	}
	currentInfo, currentExists, err := inspectDirectoryEntry(tx.parentRoot, tx.targetName, tx.target)
	if err != nil {
		return err
	}
	if tx.targetExisted {
		if !currentExists {
			return fmt.Errorf("output directory %q disappeared during transaction", tx.target)
		}
		pinned, err := tx.targetRoot.Stat(".")
		if err != nil {
			return fmt.Errorf("stat pinned output directory %q: %w", tx.target, err)
		}
		if tx.targetInfo == nil || !os.SameFile(tx.targetInfo, pinned) || !os.SameFile(pinned, currentInfo) {
			return fmt.Errorf("output directory %q changed during transaction", tx.target)
		}
	} else if currentExists {
		return fmt.Errorf("output directory %q appeared during transaction", tx.target)
	}

	if currentExists {
		backupName, err := unusedNameInRoot(tx.parentRoot, dirBackupPrefix)
		if err != nil {
			return fmt.Errorf("reserve previous output name: %w", err)
		}
		if err := tx.parentRoot.Rename(tx.targetName, backupName); err != nil {
			return fmt.Errorf("move previous output aside: %w", err)
		}
		tx.backupName = backupName
		if err := syncDirectory(tx.parentRoot); err != nil {
			return errors.Join(fmt.Errorf("sync previous-output backup: %w", err), tx.restoreDirectoryBackup())
		}
		// On WSL DrvFS, keeping an os.Root open on a directory after moving it
		// can make statat/openat report ENOENT for the directory's new name even
		// though ReadDir already observes the rename. Preserve the inode identity
		// in targetInfo and close the moved handle before verifying the backup.
		closeTargetErr := tx.targetRoot.Close()
		tx.targetRoot = nil
		backupInfo, err := tx.parentRoot.Lstat(backupName)
		if err != nil {
			return errors.Join(fmt.Errorf("stat moved previous output: %w", err), tx.restoreDirectoryBackup())
		}
		if closeTargetErr != nil {
			return errors.Join(fmt.Errorf("close moved previous output: %w", closeTargetErr), tx.restoreDirectoryBackup())
		}
		if tx.targetInfo == nil || !os.SameFile(tx.targetInfo, backupInfo) {
			restoreErr := tx.restoreDirectoryBackup()
			if restoreErr != nil {
				return fmt.Errorf("output directory %q changed during move; restore: %v", tx.target, restoreErr)
			}
			return fmt.Errorf("output directory %q changed during move", tx.target)
		}
	}

	if _, exists, err := inspectDirectoryEntry(tx.parentRoot, tx.targetName, tx.target); err != nil {
		return errors.Join(err, tx.restoreDirectoryBackup())
	} else if exists {
		return errors.Join(fmt.Errorf("output directory %q appeared before publication", tx.target), tx.restoreDirectoryBackup())
	}
	if same, err := tx.nameMatchesInfo(tx.stageName, tx.stageInfo); err != nil {
		return errors.Join(fmt.Errorf("verify staging directory pathname before publication: %w", err), tx.restoreDirectoryBackup())
	} else if !same {
		return errors.Join(fmt.Errorf("output staging directory pathname changed before publication"), tx.restoreDirectoryBackup())
	}
	if err := tx.parentRoot.Rename(tx.stageName, tx.targetName); err != nil {
		return errors.Join(fmt.Errorf("publish output: %w", err), tx.restoreDirectoryBackup())
	}
	tx.stageName = ""
	tx.stage = ""
	// See the DrvFS note above. stageInfo is the pinned identity captured
	// before the rename, so the moved directory handle is no longer needed.
	closeStageErr := tx.stageRoot.Close()
	tx.stageRoot = nil

	published, err := tx.parentRoot.Lstat(tx.targetName)
	if err != nil || !os.SameFile(stageInfo, published) {
		publishErr := err
		if publishErr == nil {
			publishErr = fmt.Errorf("published output identity changed")
		}
		return errors.Join(publishErr, closeStageErr, tx.restorePublishedDirectory())
	}
	if closeStageErr != nil {
		return errors.Join(fmt.Errorf("close published staging directory: %w", closeStageErr), tx.restorePublishedDirectory())
	}
	if err := syncDirectory(tx.parentRoot); err != nil {
		return errors.Join(fmt.Errorf("sync published output directory entry: %w", err), tx.restorePublishedDirectory())
	}

	if tx.backupName != "" {
		same, err := tx.nameMatchesInfo(tx.backupName, tx.targetInfo)
		if err != nil {
			return fmt.Errorf("verify previous output before cleanup: %w", err)
		}
		if !same {
			return fmt.Errorf("output published but previous-generation backup identity changed")
		}
		if err := tx.parentRoot.RemoveAll(tx.backupName); err != nil {
			return fmt.Errorf("output published but remove previous generation %q: %w", filepath.Join(tx.parentPath, tx.backupName), err)
		}
		tx.backupName = ""
		if err := syncDirectory(tx.parentRoot); err != nil {
			return fmt.Errorf("output published but previous-generation cleanup was not synced: %w", err)
		}
	}
	tx.closeRoots()
	return nil
}

func (tx *DirTransaction) restoreDirectoryBackup() error {
	if tx == nil || tx.backupName == "" || tx.parentRoot == nil {
		return nil
	}
	if _, exists, err := inspectDirectoryEntry(tx.parentRoot, tx.targetName, tx.target); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("cannot restore previous output: target %q is occupied", tx.target)
	}
	same, err := tx.nameMatchesInfo(tx.backupName, tx.targetInfo)
	if err != nil {
		return fmt.Errorf("verify previous output backup: %w", err)
	}
	if !same {
		return fmt.Errorf("cannot restore previous output: backup identity changed")
	}
	if err := tx.parentRoot.Rename(tx.backupName, tx.targetName); err != nil {
		return fmt.Errorf("restore previous output: %w", err)
	}
	tx.backupName = ""
	if err := syncDirectory(tx.parentRoot); err != nil {
		return fmt.Errorf("sync restored previous output: %w", err)
	}
	return nil
}

func (tx *DirTransaction) restorePublishedDirectory() error {
	if tx == nil || tx.parentRoot == nil {
		return nil
	}
	var errs []error
	if _, err := tx.parentRoot.Lstat(tx.targetName); errors.Is(err, os.ErrNotExist) {
		// Nothing is currently published under the target name; the previous
		// generation can be restored below.
	} else if err != nil {
		errs = append(errs, fmt.Errorf("stat invalid published output: %w", err))
	} else if same, verifyErr := tx.nameMatchesInfo(tx.targetName, tx.stageInfo); verifyErr != nil {
		errs = append(errs, fmt.Errorf("verify invalid published output: %w", verifyErr))
	} else if !same {
		// A concurrent actor replaced the just-published directory. Deleting by
		// pathname here would destroy somebody else's tree.
		errs = append(errs, fmt.Errorf("invalid published output identity changed; refusing to remove replacement"))
	} else if err := tx.parentRoot.RemoveAll(tx.targetName); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("remove invalid published output: %w", err))
	}
	if err := tx.restoreDirectoryBackup(); err != nil {
		errs = append(errs, err)
	}
	if err := syncDirectory(tx.parentRoot); err != nil {
		errs = append(errs, fmt.Errorf("sync rollback of published output: %w", err))
	}
	return errors.Join(errs...)
}

func (tx *DirTransaction) nameMatchesInfo(name string, expected os.FileInfo) (bool, error) {
	if tx == nil || tx.parentRoot == nil || expected == nil || name == "" {
		return false, nil
	}
	current, err := tx.parentRoot.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.IsDir() {
		return false, nil
	}
	return os.SameFile(current, expected), nil
}

func (tx *DirTransaction) nameMatchesPinnedDirectory(name string, pinned *os.Root) (bool, error) {
	if tx == nil || tx.parentRoot == nil || pinned == nil || name == "" {
		return false, nil
	}
	current, err := tx.parentRoot.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.IsDir() {
		return false, nil
	}
	expected, err := pinned.Stat(".")
	if err != nil {
		return false, err
	}
	return os.SameFile(current, expected), nil
}

func (tx *DirTransaction) closeRoots() {
	if tx == nil {
		return
	}
	if tx.stageRoot != nil {
		_ = tx.stageRoot.Close()
		tx.stageRoot = nil
	}
	if tx.targetRoot != nil {
		_ = tx.targetRoot.Close()
		tx.targetRoot = nil
	}
	if tx.parentRoot != nil {
		_ = tx.parentRoot.Close()
		tx.parentRoot = nil
	}
}

func inspectDirectoryEntry(root *os.Root, name, display string) (os.FileInfo, bool, error) {
	info, err := root.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("stat output directory %q: %w", display, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("output directory %q is a symlink", display)
	}
	if !info.IsDir() {
		return nil, false, fmt.Errorf("output directory %q exists and is not a directory", display)
	}
	return info, true, nil
}

func RebasePath(path, fromDir, toDir string) string {
	if path == "" {
		return ""
	}
	rel, err := filepath.Rel(fromDir, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return path
	}
	return filepath.Join(toDir, rel)
}

func PathsOverlap(a, b string) (bool, error) {
	aAbs, err := canonicalPath(a)
	if err != nil {
		return false, err
	}
	bAbs, err := canonicalPath(b)
	if err != nil {
		return false, err
	}
	if aAbs == bAbs {
		return true, nil
	}
	for _, pair := range [][2]string{{aAbs, bAbs}, {bAbs, aAbs}} {
		rel, err := filepath.Rel(pair[0], pair[1])
		if err != nil {
			return false, err
		}
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true, nil
		}
	}
	return false, nil
}

// ContainsPath reports whether path is the container itself or is below it.
// Existing symlink ancestors are resolved for both operands so a seemingly
// harmless output path cannot alias a source tree through a symlink.
func ContainsPath(container, path string) (bool, error) {
	c, err := canonicalPath(container)
	if err != nil {
		return false, err
	}
	p, err := canonicalPath(path)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(c, p)
	if err != nil {
		return false, err
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))), nil
}

// SamePath compares two filesystem paths after resolving absolute paths and any
// existing symlink ancestors. It is intended for input/output alias checks at
// CLI trust boundaries.
func SamePath(a, b string) (bool, error) {
	ca, err := canonicalPath(a)
	if err != nil {
		return false, err
	}
	cb, err := canonicalPath(b)
	if err != nil {
		return false, err
	}
	if rel, relErr := filepath.Rel(ca, cb); relErr == nil && rel == "." {
		return true, nil
	}
	ai, aErr := os.Stat(ca)
	bi, bErr := os.Stat(cb)
	if aErr == nil && bErr == nil {
		return os.SameFile(ai, bi), nil
	}
	if aErr != nil && !errors.Is(aErr, os.ErrNotExist) {
		return false, aErr
	}
	if bErr != nil && !errors.Is(bErr, os.ErrNotExist) {
		return false, bErr
	}
	return false, nil
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	cur := abs
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			for _, part := range suffix {
				resolved = filepath.Join(resolved, part)
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		// EvalSymlinks also reports ErrNotExist for an existing symlink whose
		// target is missing. Treating that link as an ordinary nonexistent path
		// loses the alias boundary: if its target later appears, a path that was
		// classified as contained can suddenly resolve outside its root.
		if info, lstatErr := os.Lstat(cur); lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("resolve dangling symlink %q: %w", cur, err)
		} else if lstatErr != nil && !errors.Is(lstatErr, os.ErrNotExist) {
			return "", lstatErr
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		suffix = append([]string{filepath.Base(cur)}, suffix...)
		cur = parent
	}
}

// CloneTree copies one complete reusable artifact generation into an
// unpublished staging directory. Both roots are pinned, symlinks and special
// files are rejected, and the byte budget is enforced on bytes actually read
// rather than on mutable directory metadata alone.
func CloneTree(src, dst string) error {
	srcAbs, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	srcInfo, err := os.Lstat(srcAbs)
	if err != nil {
		return err
	}
	if srcInfo.Mode()&os.ModeSymlink != 0 || !srcInfo.IsDir() {
		return fmt.Errorf("artifact tree root is not a regular directory")
	}
	root, err := os.OpenRoot(srcAbs)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	pinned, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(srcInfo, pinned) {
		return fmt.Errorf("artifact tree root changed while being opened")
	}
	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	dstAbs = filepath.Clean(dstAbs)
	overlap, err := PathsOverlap(srcAbs, dstAbs)
	if err != nil {
		return fmt.Errorf("compare clone roots: %w", err)
	}
	if overlap {
		return fmt.Errorf("artifact clone source and destination overlap")
	}
	dstInfo, err := os.Lstat(dstAbs)
	if err != nil {
		return err
	}
	if dstInfo.Mode()&os.ModeSymlink != 0 || !dstInfo.IsDir() {
		return fmt.Errorf("artifact clone destination is not a regular directory")
	}
	dstRoot, err := os.OpenRoot(dstAbs)
	if err != nil {
		return err
	}
	defer func() { _ = dstRoot.Close() }()
	dstPinned, err := dstRoot.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(dstInfo, dstPinned) {
		return fmt.Errorf("artifact clone destination changed while being opened")
	}

	var files int
	var total int64
	return fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == "." {
			return nil
		}
		rel := filepath.FromSlash(path)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("artifact tree contains symlink %s", rel)
		}
		if entry.IsDir() {
			return dstRoot.MkdirAll(rel, 0o755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("artifact tree contains non-regular file %s (%s)", rel, info.Mode().Type())
		}
		files++
		if files > maxClonedOutputFiles {
			return fmt.Errorf("artifact tree exceeds %d-file clone limit", maxClonedOutputFiles)
		}
		if info.Size() < 0 || info.Size() > maxClonedOutputBytes-total {
			return fmt.Errorf("artifact tree exceeds %d-byte clone limit", maxClonedOutputBytes)
		}
		if parent := filepath.Dir(rel); parent != "." {
			if err := dstRoot.MkdirAll(parent, 0o755); err != nil {
				return err
			}
		}

		in, err := root.Open(path)
		if err != nil {
			return err
		}
		openedInfo, statErr := in.Stat()
		if statErr != nil {
			_ = in.Close()
			return statErr
		}
		if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			_ = in.Close()
			return fmt.Errorf("artifact source %s changed while being opened", rel)
		}
		outFile, err := dstRoot.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
		if err != nil {
			_ = in.Close()
			return err
		}
		remaining := maxClonedOutputBytes - total
		written, copyErr := io.Copy(outFile, io.LimitReader(in, remaining+1))
		closeInErr := in.Close()
		syncErr := outFile.Sync()
		closeOutErr := outFile.Close()
		if written > remaining {
			return fmt.Errorf("artifact tree exceeds %d-byte clone limit", maxClonedOutputBytes)
		}
		total += written
		if copyErr != nil {
			return fmt.Errorf("copy %s: %w", rel, copyErr)
		}
		if closeInErr != nil {
			return fmt.Errorf("close source %s: %w", rel, closeInErr)
		}
		if syncErr != nil {
			return fmt.Errorf("sync clone %s: %w", rel, syncErr)
		}
		if closeOutErr != nil {
			return fmt.Errorf("close clone %s: %w", rel, closeOutErr)
		}
		return nil
	})
}

func makeTempDirInRoot(root *os.Root, prefix string) (string, error) {
	for i := 0; i < tempNameAttempts; i++ {
		name, err := randomTempName(prefix)
		if err != nil {
			return "", err
		}
		if err := root.Mkdir(name, 0o700); err == nil {
			return name, nil
		} else if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", fmt.Errorf("could not allocate unique temporary directory")
}

func unusedNameInRoot(root *os.Root, prefix string) (string, error) {
	for i := 0; i < tempNameAttempts; i++ {
		name, err := randomTempName(prefix)
		if err != nil {
			return "", err
		}
		if _, err := root.Lstat(name); errors.Is(err, os.ErrNotExist) {
			return name, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("could not allocate unique temporary name")
}

func randomTempName(prefix string) (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(token[:]), nil
}
