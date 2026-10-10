//go:build !linux && !darwin && !windows

package cli

import "os"

// AOTopsy's CI and release targets are Linux, macOS, and Windows. For an
// unrecognized platform, fail closed rather than treating an arbitrary
// character device as an ANSI-capable terminal.
func isTerminalFile(_ *os.File) bool {
	return false
}
