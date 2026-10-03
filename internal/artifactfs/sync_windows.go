//go:build windows

package artifactfs

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// SyncRoot flushes the exact directory represented by root.
//
// Go 1.25 opens os.Root directory handles read-only on Windows, while
// File.Sync is FlushFileBuffers and Windows returns ERROR_ACCESS_DENIED for a
// read-only directory handle. Reopen root.Name with GENERIC_WRITE, then verify
// that handle against the already-pinned Root before flushing it. A pathname
// substitution therefore fails identity verification instead of flushing an
// attacker-controlled directory.
func SyncRoot(root *os.Root) error {
	if root == nil {
		return fmt.Errorf("artifactfs: nil directory root")
	}
	pinned, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("artifactfs: stat pinned directory: %w", err)
	}
	path := root.Name()
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("artifactfs: encode directory path %s: %w", path, err)
	}
	h, err := syscall.CreateFile(
		pathp,
		syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return fmt.Errorf("artifactfs: reopen directory %s for flush: %w", path, err)
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		_ = syscall.CloseHandle(h)
		return fmt.Errorf("artifactfs: wrap directory handle for %s", path)
	}
	opened, statErr := f.Stat()
	if statErr != nil || !opened.IsDir() || !os.SameFile(pinned, opened) {
		_ = f.Close()
		if statErr == nil {
			statErr = fmt.Errorf("directory identity changed")
		}
		return fmt.Errorf("artifactfs: verify directory %s before flush: %w", path, statErr)
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	return errors.Join(syncErr, closeErr)
}

// SyncRegularFile uses a write-capable Root-relative handle because Windows'
// FlushFileBuffers rejects read-only handles. Root.OpenFile keeps the path
// resolution confined to the pinned directory tree.
func SyncRegularFile(root *os.Root, name string, want os.FileInfo) error {
	if root == nil || want == nil {
		return fmt.Errorf("artifactfs: missing file identity for %s", name)
	}
	f, err := root.OpenFile(name, os.O_RDWR, 0)
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
