package main

import (
	"os"
	"path/filepath"
	"strings"
)

// defaultOutDir computes the default output directory for a given input file.
// e.g., "libapp.so" → "libapp.aotopsy/" in the same directory.
func defaultOutDir(libPath string) string {
	base := filepath.Base(libPath)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	return filepath.Join(filepath.Dir(libPath), name+".aotopsy")
}

// resolvePositionalLib resolves a positional argument as a path to a file.
// Returns the absolute path if the file exists, or empty string if not.
func resolvePositionalLib(arg string) string {
	if _, err := os.Stat(arg); err == nil {
		abs, _ := filepath.Abs(arg)
		return abs
	}
	return ""
}

// reorderPositionalArg handles the case where a positional file argument
// comes before flags (e.g. "libapp.so --verbose"). Go's flag package stops
// parsing at the first non-flag arg, so we move it to the end.
func reorderPositionalArg(args []string) []string {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return args // already flags-first or empty
	}
	// First arg is non-flag (file path). Move it after all flags.
	reordered := make([]string, 0, len(args))
	reordered = append(reordered, args[1:]...)
	reordered = append(reordered, args[0])
	return reordered
}
