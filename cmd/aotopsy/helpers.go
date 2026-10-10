package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type cliUsageError struct {
	err error
}

func (e *cliUsageError) Error() string { return e.err.Error() }
func (e *cliUsageError) Unwrap() error { return e.err }

// parseCLIFlags keeps flag parsing inside the handler error contract. Parse
// errors become usage errors that main maps to exit code 2; help remains the
// standard flag.ErrHelp signal and its generated option list is printed once.
// Capturing FlagSet output prevents malformed flags from being printed twice
// (once by flag and once by main).
func parseCLIFlags(fs *flag.FlagSet, args []string) error {
	if fs == nil {
		return &cliUsageError{err: fmt.Errorf("nil FlagSet")}
	}
	var captured bytes.Buffer
	original := fs.Output()
	fs.SetOutput(&captured)
	err := fs.Parse(args)
	fs.SetOutput(original)
	if err == nil {
		return nil
	}
	if errors.Is(err, flag.ErrHelp) {
		out := original
		if out == nil {
			out = os.Stderr
		}
		_, _ = out.Write(captured.Bytes())
		return flag.ErrHelp
	}
	return &cliUsageError{err: err}
}

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
	info, err := os.Stat(arg)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	abs, err := filepath.Abs(arg)
	if err == nil {
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
	return parseCLIFlags(fs, append(flags, positionals...))
}

// parseNoPositionals parses a flag-only command and rejects stray positional
// tokens before the handler performs any I/O. The standard flag package keeps
// such tokens in FlagSet.Args(), so omitting this check makes typos look like a
// successful command invocation while silently dropping user input.
func parseNoPositionals(fs *flag.FlagSet, args []string) error {
	if err := parseCLIFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%s does not accept positional arguments: %q", fs.Name(), fs.Args())
	}
	return nil
}

func flagWasSet(fs *flag.FlagSet, names ...string) bool {
	if fs == nil {
		return false
	}
	wanted := make(map[string]struct{}, len(names))
	for _, name := range names {
		wanted[name] = struct{}{}
	}
	found := false
	fs.Visit(func(f *flag.Flag) {
		if _, ok := wanted[f.Name]; ok {
			found = true
		}
	})
	return found
}

func requireNonNegativeFlag(name string, value int) error {
	if value < 0 {
		return fmt.Errorf("--%s must be >= 0", name)
	}
	return nil
}

func parseHexAddress(name, raw string) (uint64, error) {
	value := strings.TrimSpace(raw)
	value = strings.TrimPrefix(value, "0x")
	value = strings.TrimPrefix(value, "0X")
	if value == "" {
		return 0, fmt.Errorf("--%s requires a hexadecimal address", name)
	}
	v, err := strconv.ParseUint(value, 16, 64)
	if err != nil || v == 0 {
		return 0, fmt.Errorf("--%s %q is not a valid non-zero hexadecimal address", name, raw)
	}
	return v, nil
}
