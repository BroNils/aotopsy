//go:build !windows

package artifactfs

import (
	"errors"
	"fmt"
	"os"
)

// SyncRoot flushes directory metadata represented by a pinned os.Root. File
// content is always synced separately before this is called.
func SyncRoot(root *os.Root) error {
	if root == nil {
		return fmt.Errorf("artifactfs: nil directory root")
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	return errors.Join(syncErr, closeErr)
}

// SyncRegularFile pins, verifies, syncs, and closes an existing regular file.
func SyncRegularFile(root *os.Root, name string, want os.FileInfo) error {
	if root == nil || want == nil {
		return fmt.Errorf("artifactfs: missing file identity for %s", name)
	}
	f, err := root.Open(name)
	if err != nil {
		return err
	}
	opened, statErr := f.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(want, opened) {
		_ = f.Close()
		if statErr == nil {
			statErr = fmt.Errorf("file identity changed")
		}
		return statErr
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	return errors.Join(syncErr, closeErr)
}
