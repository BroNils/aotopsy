package analysis

import (
	"io"
	"os"
	"strings"
)

// stderr returns os.Stderr as an io.Writer (used by diagnostic output).
func stderr() io.Writer { return os.Stderr }

// trimSpace is strings.TrimSpace.
func trimSpace(s string) string { return strings.TrimSpace(s) }

// splitString splits s on sep.
func splitString(s, sep string) []string { return strings.Split(s, sep) }
