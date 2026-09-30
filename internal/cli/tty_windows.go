//go:build windows

package cli

import (
	"os"
	"syscall"
)

const enableVirtualTerminalProcessing = 0x0004

func isTerminalFile(f *os.File) bool {
	if f == nil {
		return false
	}
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(f.Fd()), &mode) == nil && mode&enableVirtualTerminalProcessing != 0
}
