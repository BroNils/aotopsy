package output

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// FileArtifact describes one member of a file-generation transaction. Remove
// means the new generation deliberately omits the file; Data and Perm are
// ignored for removals.
type FileArtifact struct {
	Path   string
	Data   []byte
	Perm   os.FileMode
	Remove bool
}

// PublishFileSet replaces/removes all managed files as one rollback-capable
// generation. Parent directories are pinned with os.Root and the final path
// component is always handled with Lstat/root-relative operations, so a final
// symlink is never followed to some unrelated target.
func PublishFileSet(artifacts []FileArtifact) error {
	if len(artifacts) == 0 {
		return nil
	}
	type state struct {
		artifact  FileArtifact
		root      *os.Root
		parent    string
		finalName string
		display   string
		stageName string
		backup    string
		staged    os.FileInfo
		original  os.FileInfo
		published bool
	}
	states := make([]state, len(artifacts))
	roots := make(map[string]*os.Root)
	seen := make(map[string]int, len(artifacts))
	seenPaths := make([]string, 0, len(artifacts))

	closeRoots := func() {
		for _, root := range roots {
			_ = root.Close()
		}
	}
	defer closeRoots()
	cleanupStages := func() {
		for i := range states {
			s := &states[i]
			if s.root != nil && s.stageName != "" {
				if exists, same, _ := fileNameHasIdentity(s.root, s.stageName, s.staged); exists && same {
					_ = s.root.Remove(s.stageName)
				}
			}
		}
	}
	defer cleanupStages()

	// Validate destinations and stage all new content before touching any
	// existing generation.
	for i, a := range artifacts {
		if a.Path == "" {
			return fmt.Errorf("output: fileset artifact %d has empty path", i)
		}
		abs, err := filepath.Abs(a.Path)
		if err != nil {
			return fmt.Errorf("output: resolve fileset path %s: %w", a.Path, err)
		}
		abs = filepath.Clean(abs)
		parentInput := filepath.Dir(abs)
		if err := os.MkdirAll(parentInput, 0o755); err != nil {
			return fmt.Errorf("output: mkdir for fileset %s: %w", abs, err)
		}
		parent, err := canonicalPath(parentInput)
		if err != nil {
			return fmt.Errorf("output: resolve fileset parent %s: %w", parentInput, err)
		}
		root := roots[parent]
		if root == nil {
			root, err = os.OpenRoot(parent)
			if err != nil {
				return fmt.Errorf("output: open fileset parent %s: %w", parent, err)
			}
			roots[parent] = root
		}
		finalName := filepath.Base(abs)
		display := filepath.Join(parent, finalName)
		if prior, ok := seen[display]; ok {
			return fmt.Errorf("output: duplicate fileset destination %s (entries %d and %d)", display, prior, i)
		}
		if runtime.GOOS == "windows" {
			for prior, priorPath := range seenPaths {
				// filepath.Rel uses EqualFold for Windows path elements. Match that
				// exact comparison instead of lower-casing: Unicode simple-fold pairs
				// such as the two Greek sigma forms do not share one lowercase key.
				if strings.EqualFold(priorPath, display) {
					return fmt.Errorf("output: duplicate fileset destination %s (entries %d and %d)", display, prior, i)
				}
			}
		}
		seen[display] = i
		seenPaths = append(seenPaths, display)
		states[i] = state{artifact: a, root: root, parent: parent, finalName: finalName, display: display}
		if a.Remove {
			continue
		}
		perm := a.Perm
		if perm == 0 {
			perm = 0o644
		}
		stageName, f, err := makeTempFileInRoot(root, ".aotopsy-fileset-stage-", perm)
		if err != nil {
			return fmt.Errorf("output: stage %s: %w", display, err)
		}
		states[i].stageName = stageName
		stagedInfo, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return fmt.Errorf("output: stat staged %s: %w", display, err)
		}
		states[i].staged = stagedInfo
		if err := f.Chmod(perm); err != nil {
			_ = f.Close()
			return fmt.Errorf("output: chmod staged %s: %w", display, err)
		}
		if _, err := f.Write(a.Data); err != nil {
			_ = f.Close()
			return fmt.Errorf("output: write staged %s: %w", display, err)
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return fmt.Errorf("output: sync staged %s: %w", display, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("output: close staged %s: %w", display, err)
		}
	}

	rollback := func() error {
		var errs []error
		for i := len(states) - 1; i >= 0; i-- {
			s := &states[i]
			if s.published {
				exists, same, err := fileNameHasIdentity(s.root, s.finalName, s.staged)
				if err != nil {
					errs = append(errs, fmt.Errorf("verify published %s: %w", s.display, err))
				} else if exists && !same {
					errs = append(errs, fmt.Errorf("published %s was replaced concurrently; refusing to remove replacement", s.display))
				} else if exists {
					if err := s.root.Remove(s.finalName); err != nil && !errors.Is(err, os.ErrNotExist) {
						errs = append(errs, fmt.Errorf("remove published %s: %w", s.display, err))
					}
				}
				s.published = false
			}
			if s.backup != "" {
				exists, same, err := fileNameHasIdentity(s.root, s.backup, s.original)
				if err != nil {
					errs = append(errs, fmt.Errorf("verify backup for %s: %w", s.display, err))
					continue
				}
				if !exists || !same {
					errs = append(errs, fmt.Errorf("backup for %s changed; refusing to restore it", s.display))
					continue
				}
				// A hard link is deliberately used for restore: unlike Rename on
				// Unix it never overwrites a path that appeared concurrently.
				if err := s.root.Link(s.backup, s.finalName); err != nil {
					errs = append(errs, fmt.Errorf("restore %s: %w", s.display, err))
					continue
				}
				exists, same, err = fileNameHasIdentity(s.root, s.finalName, s.original)
				if err != nil || !exists || !same {
					if err == nil {
						err = fmt.Errorf("restored destination identity changed")
					}
					errs = append(errs, fmt.Errorf("verify restored %s: %w", s.display, err))
					continue
				}
				exists, same, err = fileNameHasIdentity(s.root, s.backup, s.original)
				if err != nil || !exists || !same {
					if err == nil {
						err = fmt.Errorf("backup identity changed after restore")
					}
					errs = append(errs, fmt.Errorf("verify restored backup for %s: %w", s.display, err))
					continue
				}
				if err := s.root.Remove(s.backup); err != nil {
					errs = append(errs, fmt.Errorf("remove restored backup for %s: %w", s.display, err))
				} else {
					s.backup = ""
				}
			}
		}
		return errors.Join(errs...)
	}

	// Move every old managed regular file aside before publishing any new
	// member. Lstat keeps the final component opaque; a symlink is rejected.
	for i := range states {
		s := &states[i]
		info, err := s.root.Lstat(s.finalName)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return errors.Join(fmt.Errorf("output: stat existing fileset member %s: %w", s.display, err), rollback())
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.Join(fmt.Errorf("output: existing fileset member %s is not a regular file", s.display), rollback())
		}
		s.original = info
		backup, err := unusedNameInRoot(s.root, ".aotopsy-fileset-backup-")
		if err != nil {
			return errors.Join(fmt.Errorf("output: reserve backup for %s: %w", s.display, err), rollback())
		}
		if err := s.root.Rename(s.finalName, backup); err != nil {
			return errors.Join(fmt.Errorf("output: backup %s: %w", s.display, err), rollback())
		}
		s.backup = backup
		moved, err := s.root.Lstat(backup)
		if err != nil || !os.SameFile(info, moved) {
			moveErr := err
			if moveErr == nil {
				moveErr = fmt.Errorf("identity changed")
			}
			return errors.Join(fmt.Errorf("output: backup %s: %w", s.display, moveErr), rollback())
		}
	}

	for i := range states {
		s := &states[i]
		if s.artifact.Remove {
			continue
		}
		exists, same, err := fileNameHasIdentity(s.root, s.stageName, s.staged)
		if err != nil {
			return errors.Join(fmt.Errorf("output: verify staged %s: %w", s.display, err), rollback())
		}
		if !exists || !same {
			return errors.Join(fmt.Errorf("output: staged %s changed before publication", s.display), rollback())
		}
		// Link is atomic and fails if finalName already exists. This prevents a
		// newly appeared destination from being overwritten by publication.
		if err := s.root.Link(s.stageName, s.finalName); err != nil {
			return errors.Join(fmt.Errorf("output: publish %s: %w", s.display, err), rollback())
		}
		s.published = true
		exists, same, err = fileNameHasIdentity(s.root, s.finalName, s.staged)
		if err != nil || !exists || !same {
			if err == nil {
				err = fmt.Errorf("published identity changed")
			}
			return errors.Join(fmt.Errorf("output: verify published %s: %w", s.display, err), rollback())
		}
		exists, same, err = fileNameHasIdentity(s.root, s.stageName, s.staged)
		if err != nil || !exists || !same {
			if err == nil {
				err = fmt.Errorf("staged identity changed after publication")
			}
			return errors.Join(fmt.Errorf("output: verify staged link for %s: %w", s.display, err), rollback())
		}
		if err := s.root.Remove(s.stageName); err != nil {
			return errors.Join(fmt.Errorf("output: remove staged link for %s: %w", s.display, err), rollback())
		}
		s.stageName = ""
	}

	for i := range states {
		s := &states[i]
		if s.backup == "" {
			continue
		}
		exists, same, err := fileNameHasIdentity(s.root, s.backup, s.original)
		if err != nil {
			return fmt.Errorf("output: verify backup cleanup for %s: %w", s.display, err)
		}
		if !exists || !same {
			return fmt.Errorf("output: generation published but backup identity changed for %s", s.display)
		}
		if err := s.root.Remove(s.backup); err != nil {
			return fmt.Errorf("output: generation published but remove backup for %s: %w", s.display, err)
		}
		s.backup = ""
	}
	return nil
}

func fileNameHasIdentity(root *os.Root, name string, want os.FileInfo) (exists bool, same bool, err error) {
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

func makeTempFileInRoot(root *os.Root, prefix string, perm os.FileMode) (string, *os.File, error) {
	for i := 0; i < tempNameAttempts; i++ {
		name, err := randomTempName(prefix)
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
	return "", nil, fmt.Errorf("could not allocate unique temporary file")
}
