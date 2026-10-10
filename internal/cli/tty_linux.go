//go:build linux

package cli

import (
	"os"
	"syscall"
	"unsafe"
)

// isTerminalFile asks the kernel whether f is a terminal. It goes through
// SyscallConn rather than f.Fd(): Fd() switches the descriptor to blocking mode
// as a side effect, which would change how an unrelated *os.File behaves just
// because a Logger was constructed around it.
func isTerminalFile(f *os.File) bool {
	if f == nil {
		return false
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	isTTY := false
	if err := rc.Control(func(fd uintptr) {
		var termios syscall.Termios
		_, _, errno := syscall.Syscall6(
			syscall.SYS_IOCTL,
			fd,
			uintptr(syscall.TCGETS),
			uintptr(unsafe.Pointer(&termios)),
			0, 0, 0,
		)
		isTTY = errno == 0
	}); err != nil {
		return false
	}
	return isTTY
}
