//go:build windows

package cli

import (
	"os"
	"syscall"
)

const enableVirtualTerminalProcessing = 0x0004

// syscall exports GetConsoleMode but not SetConsoleMode.
var procSetConsoleMode = syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleMode")

// isTerminalFile reports whether f is a console that renders ANSI sequences.
//
// A console handle whose output mode lacks ENABLE_VIRTUAL_TERMINAL_PROCESSING
// (legacy conhost, cmd.exe started without Windows Terminal) is asked to turn it
// on, the same thing other CLIs do. If the host refuses, the answer is false and
// output stays plain. A redirected handle (file, pipe, NUL) is not a console, so
// GetConsoleMode fails and the answer is false without touching anything.
//
// The mode change is deliberately left in place: the console belongs to the
// parent shell, which resets the modes it cares about for every command, and a
// process-exit hook to undo it cannot be guaranteed on a crash.
//
// It goes through SyscallConn rather than f.Fd(), which would also switch the
// handle to blocking mode as a side effect.
func isTerminalFile(f *os.File) bool {
	if f == nil {
		return false
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	if err := rc.Control(func(fd uintptr) {
		h := syscall.Handle(fd)
		var mode uint32
		if syscall.GetConsoleMode(h, &mode) != nil {
			return
		}
		if mode&enableVirtualTerminalProcessing != 0 {
			ok = true
			return
		}
		r, _, _ := procSetConsoleMode.Call(uintptr(h), uintptr(mode|enableVirtualTerminalProcessing))
		ok = r != 0
	}); err != nil {
		return false
	}
	return ok
}
