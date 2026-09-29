package main

import (
	"bytes"
	"flag"
	"fmt"
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

// parseInterspersed parses flags even when positional arguments appear before
// or between them. The standard flag package stops at the first positional;
// blindly moving the first token was insufficient for e.g.
//
//	aotopsy --out out libapp.so --max-steps 100
//
// where --max-steps was silently ignored. We use the FlagSet schema so values
// belonging to non-bool flags are never mistaken for positionals.
func parseInterspersed(fs *flag.FlagSet, args []string) error {
	if fs == nil {
		return fmt.Errorf("nil FlagSet")
	}
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			positionals = append(positionals, arg)
			continue
		}

		nameValue := strings.TrimLeft(arg, "-")
		name := nameValue
		hasInlineValue := false
		if eq := strings.IndexByte(nameValue, '='); eq >= 0 {
			name = nameValue[:eq]
			hasInlineValue = true
		}
		f := fs.Lookup(name)
		// Preserve unknown flags for FlagSet.Parse to diagnose.
		flags = append(flags, arg)
		if f == nil || hasInlineValue {
			continue
		}
		isBool := false
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok {
			isBool = bf.IsBoolFlag()
		}
		if isBool {
			continue
		}
		if i+1 >= len(args) {
			// Let FlagSet.Parse return its normal "flag needs an argument" error.
			continue
		}
		i++
		flags = append(flags, args[i])
	}
	return fs.Parse(append(flags, positionals...))
}

// splitLines splits byte data into non-empty trimmed lines.
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	for _, l := range bytes.Split(data, []byte("\n")) {
		l = bytes.TrimSpace(l)
		if len(l) > 0 {
			lines = append(lines, l)
		}
	}
	return lines
}
