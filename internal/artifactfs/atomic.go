// Package artifactfs contains the filesystem primitives used to publish
// generated artifacts. It deliberately has no dependencies on analysis/domain
// packages so every writer (including jsonutil) can share the same publication
// contract.
package artifactfs

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
)

const (
	tempAttempts = 128
	stagePrefix  = ".aotopsy-file-stage-"
	backupPrefix = ".aotopsy-file-previous-"
)

// syncDirectory is a test seam for durability-failure regression tests. The
// production implementation is SyncRoot; callers outside this package use the
// exported function directly.
var syncDirectory = SyncRoot

// AtomicFile is a streaming same-directory artifact publication. Commit makes
// the completed file visible only after data sync+close succeed. When replacing
// an existing artifact, a hard-link backup is made durable before rename so a
// directory-sync failure can restore the previous generation.
type AtomicFile struct {
	root       *os.Root
	display    string
	finalName  string
	tempName   string
	tempInfo   os.FileInfo
	file       *os.File
	failed     bool
	committed  bool
	rootClosed bool
}

// NewAtomicFile creates a streaming atomic writer for path. This API is for
// trusted destination paths (CLI/output contract paths). Recovered or otherwise
// untrusted path fragments must use NewAtomicFileUnder instead.
func NewAtomicFile(path string, perm os.FileMode) (*AtomicFile, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("artifactfs: empty output path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("artifactfs: resolve %s: %w", path, err)
	}
	abs = filepath.Clean(abs)
	finalName := filepath.Base(abs)
	if err := validatePortableSegment(finalName); err != nil {
		return nil, fmt.Errorf("artifactfs: unsafe output filename %q: %w", finalName, err)
	}
	parent := filepath.Dir(abs)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("artifactfs: mkdir %s: %w", parent, err)
	}
	root, err := openPinnedDirectory(parent)
	if err != nil {
		return nil, fmt.Errorf("artifactfs: open parent %s: %w", parent, err)
	}
	return newAtomicFileInRoot(root, abs, finalName, perm)
}

// NewAtomicFileUnder creates a streaming writer for rel beneath rootPath.
// rootPath is pinned first and every rel directory is opened segment-by-segment
// through os.Root. Symlinks are rejected, and concurrent path replacement is
// detected by inode/file identity, so a recovered name cannot escape or redirect
// publication after a separate preflight check.
func NewAtomicFileUnder(rootPath, rel string, perm os.FileMode) (*AtomicFile, error) {
	localRel, parts, err := portableRelative(rel)
	if err != nil {
		return nil, err
	}
	absRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("artifactfs: resolve artifact root: %w", err)
	}
	absRoot = filepath.Clean(absRoot)
	if err := os.MkdirAll(absRoot, 0o755); err != nil {
		return nil, fmt.Errorf("artifactfs: mkdir artifact root %s: %w", absRoot, err)
	}
	root, err := openPinnedDirectory(absRoot)
	if err != nil {
		return nil, fmt.Errorf("artifactfs: open artifact root %s: %w", absRoot, err)
	}

	// Walk to the final parent while each directory handle is pinned. The final
	// component is a filename and is never followed as a symlink.
	for _, segment := range parts[:len(parts)-1] {
		info, err := root.Lstat(segment)
		if errors.Is(err, os.ErrNotExist) {
			created := false
			if err := root.Mkdir(segment, 0o755); err == nil {
				created = true
			} else if !errors.Is(err, fs.ErrExist) {
				_ = root.Close()
				return nil, fmt.Errorf("artifactfs: mkdir artifact directory %q: %w", segment, err)
			}
			// Another writer may have created the same grouped-artifact directory
			// between Lstat and Mkdir. EEXIST is safe only after the common path
			// below re-stats and proves the object is a real directory. Only the
			// writer that created the directory owns the parent-directory fsync.
			if created {
				if err := syncDirectory(root); err != nil {
					_ = root.Close()
					return nil, fmt.Errorf("artifactfs: sync artifact directory creation %q: %w", segment, err)
				}
			}
			info, err = root.Lstat(segment)
			if err != nil {
				_ = root.Close()
				return nil, fmt.Errorf("artifactfs: stat artifact directory %q after creation race: %w", segment, err)
			}
		}
		if err != nil {
			_ = root.Close()
			return nil, fmt.Errorf("artifactfs: stat artifact directory %q: %w", segment, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			_ = root.Close()
			return nil, fmt.Errorf("artifactfs: artifact path component %q is not a regular directory", segment)
		}
		next, err := root.OpenRoot(segment)
		if err != nil {
			_ = root.Close()
			return nil, fmt.Errorf("artifactfs: pin artifact directory %q: %w", segment, err)
		}
		pinned, err := next.Stat(".")
		if err != nil || !os.SameFile(info, pinned) {
			_ = next.Close()
			_ = root.Close()
			if err == nil {
				err = fmt.Errorf("identity changed")
			}
			return nil, fmt.Errorf("artifactfs: artifact directory %q changed while being pinned: %w", segment, err)
		}
		if err := root.Close(); err != nil {
			_ = next.Close()
			return nil, fmt.Errorf("artifactfs: close parent artifact directory: %w", err)
		}
		root = next
	}

	display := filepath.Join(absRoot, localRel)
	return newAtomicFileInRoot(root, display, parts[len(parts)-1], perm)
}

func newAtomicFileInRoot(root *os.Root, display, finalName string, perm os.FileMode) (*AtomicFile, error) {
	if perm.Perm() != perm {
		_ = root.Close()
		return nil, fmt.Errorf("artifactfs: unsupported file mode %v for %s", perm, display)
	}
	name, f, err := makeTempFile(root, stagePrefix, 0o600)
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("artifactfs: create temp for %s: %w", display, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		_ = root.Remove(name)
		_ = root.Close()
		return nil, fmt.Errorf("artifactfs: stat temp for %s: %w", display, err)
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		_ = root.Remove(name)
		_ = root.Close()
		return nil, fmt.Errorf("artifactfs: chmod temp for %s: %w", display, err)
	}
	return &AtomicFile{root: root, display: display, finalName: finalName, tempName: name, tempInfo: info, file: f}, nil
}

func (a *AtomicFile) Write(p []byte) (int, error) {
	if a == nil || a.file == nil || a.committed {
		return 0, fmt.Errorf("artifactfs: writer is closed")
	}
	if a.failed {
		return 0, fmt.Errorf("artifactfs: writer is failed")
	}
	n, err := a.file.Write(p)
	if err != nil {
		a.failed = true
	}
	return n, err
}

// Abort closes the staged file and removes it only when its identity still
// matches the file created by this writer. A substituted pathname is never
// removed on cleanup.
func (a *AtomicFile) Abort() error {
	if a == nil {
		return nil
	}
	a.failed = true
	var errs []error
	if a.file != nil {
		if err := a.file.Close(); err != nil {
			errs = append(errs, fmt.Errorf("artifactfs: close temp for %s: %w", a.display, err))
		}
		a.file = nil
	}
	if a.root != nil && a.tempName != "" {
		exists, same, err := fileNameHasIdentity(a.root, a.tempName, a.tempInfo)
		if err != nil {
			errs = append(errs, fmt.Errorf("artifactfs: verify temp for %s: %w", a.display, err))
		} else if exists && !same {
			errs = append(errs, fmt.Errorf("artifactfs: refusing to remove changed temp for %s", a.display))
		} else if exists {
			if err := a.root.Remove(a.tempName); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("artifactfs: remove temp for %s: %w", a.display, err))
			} else {
				a.tempName = ""
			}
		}
	}
	if err := a.closeRoot(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Commit publishes the staged bytes. On failure before a durable publication,
// it attempts to restore the exact previous regular file (or absence) before
// returning the error.
func (a *AtomicFile) Commit() error {
	if a == nil || a.root == nil || a.committed {
		return fmt.Errorf("artifactfs: writer is not active")
	}
	if a.failed {
		return errors.Join(fmt.Errorf("artifactfs: writer for %s is failed", a.display), a.Abort())
	}
	if a.file == nil {
		return fmt.Errorf("artifactfs: writer for %s has no open temp file", a.display)
	}
	if err := a.file.Sync(); err != nil {
		a.failed = true
		return errors.Join(fmt.Errorf("artifactfs: sync %s: %w", a.display, err), a.Abort())
	}
	if err := a.file.Close(); err != nil {
		a.file = nil
		a.failed = true
		return errors.Join(fmt.Errorf("artifactfs: close %s: %w", a.display, err), a.Abort())
	}
	a.file = nil
	if exists, same, err := fileNameHasIdentity(a.root, a.tempName, a.tempInfo); err != nil || !exists || !same {
		if err == nil {
			err = fmt.Errorf("temp identity changed")
		}
		a.failed = true
		return errors.Join(fmt.Errorf("artifactfs: verify temp for %s: %w", a.display, err), a.Abort())
	}

	var oldInfo os.FileInfo
	backupName := ""
	if info, err := a.root.Lstat(a.finalName); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			a.failed = true
			return errors.Join(fmt.Errorf("artifactfs: existing destination %s is not a regular non-symlink file", a.display), a.Abort())
		}
		oldInfo = info
		backupName, err = unusedName(a.root, backupPrefix)
		if err != nil {
			a.failed = true
			return errors.Join(fmt.Errorf("artifactfs: reserve backup for %s: %w", a.display, err), a.Abort())
		}
		if err := a.root.Link(a.finalName, backupName); err != nil {
			a.failed = true
			return errors.Join(fmt.Errorf("artifactfs: backup %s: %w", a.display, err), a.Abort())
		}
		if err := syncDirectory(a.root); err != nil {
			_ = removeIfIdentity(a.root, backupName, oldInfo)
			a.failed = true
			return errors.Join(fmt.Errorf("artifactfs: sync backup for %s: %w", a.display, err), a.Abort())
		}
		if current, err := a.root.Lstat(a.finalName); err != nil || !os.SameFile(current, oldInfo) {
			_ = removeIfIdentity(a.root, backupName, oldInfo)
			a.failed = true
			if err == nil {
				err = fmt.Errorf("destination identity changed")
			}
			return errors.Join(fmt.Errorf("artifactfs: destination %s changed before publication: %w", a.display, err), a.Abort())
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		a.failed = true
		return errors.Join(fmt.Errorf("artifactfs: stat destination %s: %w", a.display, err), a.Abort())
	}

	if err := a.root.Rename(a.tempName, a.finalName); err != nil {
		if backupName != "" {
			_ = removeIfIdentity(a.root, backupName, oldInfo)
			_ = syncDirectory(a.root)
		}
		a.failed = true
		return errors.Join(fmt.Errorf("artifactfs: publish %s: %w", a.display, err), a.Abort())
	}
	a.tempName = ""
	published, err := a.root.Lstat(a.finalName)
	if err != nil || !os.SameFile(published, a.tempInfo) {
		if err == nil {
			err = fmt.Errorf("published identity changed")
		}
		return errors.Join(fmt.Errorf("artifactfs: verify published %s: %w", a.display, err), a.rollbackPublished(backupName, oldInfo))
	}
	if err := syncDirectory(a.root); err != nil {
		return errors.Join(fmt.Errorf("artifactfs: sync published %s: %w", a.display, err), a.rollbackPublished(backupName, oldInfo))
	}

	// Publication is now durable. Backup cleanup is also made durable; if this
	// fails the new artifact is still the current complete generation and the
	// hidden backup is never mistaken for it.
	if backupName != "" {
		if err := removeIfIdentity(a.root, backupName, oldInfo); err != nil {
			return errors.Join(fmt.Errorf("artifactfs: cleanup backup for %s: %w", a.display, err), a.closeRoot())
		}
		if err := syncDirectory(a.root); err != nil {
			return errors.Join(fmt.Errorf("artifactfs: sync backup cleanup for %s: %w", a.display, err), a.closeRoot())
		}
	}
	a.committed = true
	return a.closeRoot()
}

func (a *AtomicFile) rollbackPublished(backupName string, oldInfo os.FileInfo) error {
	if a == nil || a.root == nil {
		return nil
	}
	var errs []error
	current, err := a.root.Lstat(a.finalName)
	if err == nil && os.SameFile(current, a.tempInfo) {
		if backupName != "" {
			backup, berr := a.root.Lstat(backupName)
			if berr != nil || oldInfo == nil || !os.SameFile(backup, oldInfo) {
				if berr == nil {
					berr = fmt.Errorf("backup identity changed")
				}
				errs = append(errs, fmt.Errorf("artifactfs: verify rollback backup: %w", berr))
			} else if err := a.root.Rename(backupName, a.finalName); err != nil {
				errs = append(errs, fmt.Errorf("artifactfs: restore previous artifact: %w", err))
				backupName = ""
			} else {
				backupName = ""
			}
		} else if err := a.root.Remove(a.finalName); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("artifactfs: remove failed publication: %w", err))
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("artifactfs: stat failed publication: %w", err))
	} else if err == nil {
		errs = append(errs, fmt.Errorf("artifactfs: published destination was replaced concurrently; refusing rollback removal"))
	}
	if backupName != "" {
		// Publication never restored this link. It is safe to remove only if its
		// identity remains the old artifact.
		if err := removeIfIdentity(a.root, backupName, oldInfo); err != nil {
			errs = append(errs, err)
		}
	}
	if err := syncDirectory(a.root); err != nil {
		errs = append(errs, fmt.Errorf("artifactfs: sync rollback: %w", err))
	}
	a.failed = true
	if err := a.closeRoot(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (a *AtomicFile) closeRoot() error {
	if a == nil || a.root == nil || a.rootClosed {
		return nil
	}
	err := a.root.Close()
	a.rootClosed = true
	a.root = nil
	if err != nil {
		return fmt.Errorf("artifactfs: close destination root for %s: %w", a.display, err)
	}
	return nil
}

// WriteAtomic writes through a streaming AtomicFile.
func WriteAtomic(path string, perm os.FileMode, write func(io.Writer) error) error {
	if write == nil {
		return fmt.Errorf("artifactfs: nil writer for %s", path)
	}
	a, err := NewAtomicFile(path, perm)
	if err != nil {
		return err
	}
	if err := write(a); err != nil {
		return errors.Join(err, a.Abort())
	}
	return a.Commit()
}

// WriteAtomicUnder writes rel beneath rootPath without ever converting rel into
// a trusted absolute pathname before the destination directory is pinned.
func WriteAtomicUnder(rootPath, rel string, perm os.FileMode, write func(io.Writer) error) error {
	if write == nil {
		return fmt.Errorf("artifactfs: nil writer for %s", rel)
	}
	a, err := NewAtomicFileUnder(rootPath, rel, perm)
	if err != nil {
		return err
	}
	if err := write(a); err != nil {
		return errors.Join(err, a.Abort())
	}
	return a.Commit()
}

// ValidateRelativePath applies the portable lexical policy used by
// NewAtomicFileUnder without touching the filesystem. Directory transactions
// use this at their final publication gate as well, so files produced by an
// external renderer cannot smuggle a Unix-only name (for example CON, an ADS
// colon, or a trailing dot) into an otherwise portable generation.
func ValidateRelativePath(rel string) error {
	_, _, err := portableRelative(rel)
	return err
}

func openPinnedDirectory(path string) (*os.Root, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("%s is not a regular non-symlink directory", path)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	pinned, err := root.Stat(".")
	if err != nil || !os.SameFile(info, pinned) {
		_ = root.Close()
		if err == nil {
			err = fmt.Errorf("directory identity changed")
		}
		return nil, err
	}
	return root, nil
}

func portableRelative(rel string) (string, []string, error) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", nil, fmt.Errorf("artifactfs: unsafe relative artifact name %q", rel)
	}
	normalized := strings.ReplaceAll(rel, `\`, "/")
	if strings.HasPrefix(normalized, "/") {
		return "", nil, fmt.Errorf("artifactfs: unsafe relative artifact name %q", rel)
	}
	parts := strings.Split(normalized, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", nil, fmt.Errorf("artifactfs: unsafe relative artifact name %q", rel)
		}
		if err := validatePortableSegment(part); err != nil {
			return "", nil, fmt.Errorf("artifactfs: unsafe relative artifact name %q: %w", rel, err)
		}
	}
	local := filepath.FromSlash(normalized)
	if !filepath.IsLocal(local) {
		return "", nil, fmt.Errorf("artifactfs: unsafe relative artifact name %q", rel)
	}
	return local, parts, nil
}

func validatePortableSegment(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("empty or dot path segment")
	}
	if strings.HasSuffix(name, " ") || strings.HasSuffix(name, ".") {
		return fmt.Errorf("windows-ambiguous trailing space/dot")
	}
	for _, r := range name {
		if r < 0x20 || strings.ContainsRune(`<>:"|?*`, r) {
			return fmt.Errorf("windows-reserved character %q", r)
		}
	}
	base := name
	if i := strings.IndexAny(base, ".:"); i >= 0 {
		base = base[:i]
	}
	base = strings.TrimRight(base, " ")
	upper := strings.ToUpper(base)
	if upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL" || upper == "CONIN$" || upper == "CONOUT$" {
		return fmt.Errorf("windows-reserved device name")
	}
	if len(upper) == 4 && (strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT")) && upper[3] >= '1' && upper[3] <= '9' {
		return fmt.Errorf("windows-reserved device name")
	}
	if strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT") {
		suffix := strings.TrimPrefix(strings.TrimPrefix(upper, "COM"), "LPT")
		if suffix == "¹" || suffix == "²" || suffix == "³" {
			return fmt.Errorf("windows-reserved device name")
		}
	}
	return nil
}

func makeTempFile(root *os.Root, prefix string, perm os.FileMode) (string, *os.File, error) {
	for i := 0; i < tempAttempts; i++ {
		name, err := randomName(prefix)
		if err != nil {
			return "", nil, err
		}
		f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, perm.Perm())
		if err == nil {
			return name, f, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", nil, err
		}
	}
	return "", nil, fmt.Errorf("artifactfs: could not allocate unique temporary file")
}

func unusedName(root *os.Root, prefix string) (string, error) {
	for i := 0; i < tempAttempts; i++ {
		name, err := randomName(prefix)
		if err != nil {
			return "", err
		}
		if _, err := root.Lstat(name); errors.Is(err, os.ErrNotExist) {
			return name, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("artifactfs: could not allocate unique temporary name")
}

func randomName(prefix string) (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(token[:]), nil
}

func fileNameHasIdentity(root *os.Root, name string, want os.FileInfo) (exists, same bool, err error) {
	if root == nil || name == "" || want == nil {
		return false, false, nil
	}
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return true, false, nil
	}
	return true, os.SameFile(info, want), nil
}

func removeIfIdentity(root *os.Root, name string, want os.FileInfo) error {
	exists, same, err := fileNameHasIdentity(root, name, want)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if !same {
		return fmt.Errorf("artifactfs: refusing to remove changed file %s", name)
	}
	return root.Remove(name)
}
