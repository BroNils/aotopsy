package cli

import (
	"fmt"
	"io"
)

// MakeLogf returns a closure that writes to log only when !quiet.
func MakeLogf(quiet bool, log io.Writer) func(string, ...interface{}) {
	return func(format string, args ...interface{}) {
		if !quiet {
			_, _ = fmt.Fprintf(log, format, args...)
		}
	}
}

// MakeStagef returns a closure that writes a stage header to log only
// when !quiet.
func MakeStagef(quiet bool, log io.Writer) func(string, string, ...interface{}) {
	return func(name string, format string, args ...interface{}) {
		if !quiet {
			detail := fmt.Sprintf(format, args...)
			_, _ = fmt.Fprintf(log, "\n%s%s%s %s\n", Pink, name, Reset, detail)
		}
	}
}
