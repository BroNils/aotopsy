//go:build windows

package samplecorpus

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	linuxpath "path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

const (
	errorCantAccessFile        = syscall.Errno(1920)
	fsctlGetReparsePoint       = 0x000900a8
	ioReparseTagLXSymbolicLink = 0xa000001d
	maxReparseDataBufferSize   = 16 * 1024
)

var wslDirCache sync.Map // Linux absolute directory -> Windows UNC directory.

// statCorpusPath follows ordinary Windows symlinks through os.Stat. WSL-created
// symlinks on DrvFs are different: Windows exposes them as
// IO_REPARSE_TAG_LX_SYMLINK and Go deliberately returns ERROR_CANT_ACCESS_FILE
// when Stat tries to follow one. Resolve that one representation explicitly so
// native Windows tests can use the same corpus links as WSL.
func statCorpusPath(path string) (string, fs.FileInfo, error) {
	fi, err := os.Stat(path)
	if err == nil || !errors.Is(err, errorCantAccessFile) {
		return path, fi, err
	}

	target, targetErr := readLXSymbolicLink(path)
	if targetErr != nil {
		return path, nil, err
	}
	resolved, resolveErr := windowsPathForLXTarget(path, target)
	if resolveErr != nil {
		return path, nil, fmt.Errorf("resolve WSL symlink %s: %w", path, resolveErr)
	}
	fi, err = os.Stat(resolved)
	return resolved, fi, err
}

func readLXSymbolicLink(path string) (string, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	h, err := syscall.CreateFile(
		name,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(h)

	var data [maxReparseDataBufferSize]byte
	var n uint32
	if err := syscall.DeviceIoControl(h, fsctlGetReparsePoint, nil, 0, &data[0], uint32(len(data)), &n, nil); err != nil {
		return "", err
	}
	version, target, err := decodeLXReparseData(data[:n])
	if err != nil {
		return "", err
	}
	if target != "" {
		return target, nil
	}

	// Version 1 stored the target in the file data rather than the reparse
	// payload. Keep that older representation readable too.
	if version != 1 {
		return "", fmt.Errorf("LX symbolic-link version %d has no target payload", version)
	}

	buf := make([]byte, 16*1024)
	var read uint32
	if err := syscall.ReadFile(h, buf, &read, nil); err != nil {
		return "", err
	}
	target = string(buf[:read])
	if target == "" {
		return "", fmt.Errorf("empty LX symbolic-link target")
	}
	return target, nil
}

func decodeLXReparseData(data []byte) (uint32, string, error) {
	if len(data) < 12 {
		return 0, "", fmt.Errorf("LX reparse data is only %d bytes", len(data))
	}
	if binary.LittleEndian.Uint32(data[0:4]) != ioReparseTagLXSymbolicLink {
		return 0, "", fmt.Errorf("not an LX symbolic link")
	}
	dataLen := int(binary.LittleEndian.Uint16(data[4:6]))
	if dataLen < 4 || 8+dataLen > len(data) {
		return 0, "", fmt.Errorf("invalid LX reparse data length %d", dataLen)
	}
	version := binary.LittleEndian.Uint32(data[8:12])
	if dataLen == 4 {
		return version, "", nil
	}
	target := string(data[12 : 8+dataLen])
	if target == "" {
		return 0, "", fmt.Errorf("empty LX symbolic-link target")
	}
	return version, target, nil
}

func windowsPathForLXTarget(linkPath, target string) (string, error) {
	if !strings.HasPrefix(target, "/") {
		// Relative DrvFs links resolve relative to the directory containing the
		// link. When both sides are on the mounted Windows filesystem, the
		// equivalent Windows path preserves that relation directly.
		return filepath.Clean(filepath.Join(filepath.Dir(linkPath), filepath.FromSlash(target))), nil
	}

	dir := linuxpath.Dir(target)
	base := linuxpath.Base(target)
	winDir, err := windowsPathForWSLDir(dir)
	if err != nil {
		return "", err
	}
	return filepath.Join(winDir, base), nil
}

func windowsPathForWSLDir(linuxDir string) (string, error) {
	if cached, ok := wslDirCache.Load(linuxDir); ok {
		return cached.(string), nil
	}
	out, err := exec.Command("wsl.exe", "--exec", "wslpath", "-w", linuxDir).Output()
	if err != nil {
		return "", fmt.Errorf("wslpath -w %q: %w", linuxDir, err)
	}
	winDir := strings.TrimSpace(string(out))
	if winDir == "" {
		return "", fmt.Errorf("wslpath -w %q returned an empty path", linuxDir)
	}
	actual, _ := wslDirCache.LoadOrStore(linuxDir, winDir)
	return actual.(string), nil
}
