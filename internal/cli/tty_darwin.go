//go:build darwin

package cli

import (
	"os"
	"syscall"
	"unsafe"
)

func isTerminalFile(f *os.File) bool {
	if f == nil {
		return false
	}
	var termios syscall.Termios
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TIOCGETA),
		uintptr(unsafe.Pointer(&termios)),
	)
	return errno == 0
}
