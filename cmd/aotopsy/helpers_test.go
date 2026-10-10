package main

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseInterspersedFlagsAfterPositional(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	out := fs.String("out", "", "")
	maxSteps := fs.Int("max-steps", 0, "")
	quiet := fs.Bool("quiet", false, "")
	if err := parseInterspersed(fs, []string{"--out", "dest", "libapp.so", "--max-steps", "123", "--quiet"}); err != nil {
		t.Fatal(err)
	}
	if *out != "dest" || *maxSteps != 123 || !*quiet {
		t.Fatalf("parsed out=%q maxSteps=%d quiet=%v", *out, *maxSteps, *quiet)
	}
	if fs.NArg() != 1 || fs.Arg(0) != "libapp.so" {
		t.Fatalf("positionals = %q, want [libapp.so]", fs.Args())
	}
}

func TestParseInterspersedPreservesFlagValuesThatLookPositional(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	out := fs.String("out", "", "")
	if err := parseInterspersed(fs, []string{"input.so", "--out", "directory-name"}); err != nil {
		t.Fatal(err)
	}
	if *out != "directory-name" || fs.NArg() != 1 || fs.Arg(0) != "input.so" {
		t.Fatalf("out=%q args=%q", *out, fs.Args())
	}
}

func TestParseInterspersedDoubleDashStopsFlagParsing(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	quiet := fs.Bool("quiet", false, "")
	if err := parseInterspersed(fs, []string{"--", "input.so", "--quiet"}); err != nil {
		t.Fatal(err)
	}
	if *quiet || fs.NArg() != 2 || fs.Arg(1) != "--quiet" {
		t.Fatalf("quiet=%v args=%q", *quiet, fs.Args())
	}
}

func TestParseNoPositionalsRejectsSurplusTokens(t *testing.T) {
	fs := flag.NewFlagSet("flag-only", flag.ContinueOnError)
	_ = fs.Bool("quiet", false, "")
	if err := parseNoPositionals(fs, []string{"--quiet", "surplus"}); err == nil {
		t.Fatal("flag-only parser accepted a positional token")
	}
}

func TestParseHexAddressRejectsMalformedOrZero(t *testing.T) {
	for _, raw := range []string{"", "0", "0x0", "not-hex"} {
		if _, err := parseHexAddress("target", raw); err == nil {
			t.Fatalf("parseHexAddress accepted %q", raw)
		}
	}
	if got, err := parseHexAddress("target", "0x1A2b"); err != nil || got != 0x1a2b {
		t.Fatalf("parseHexAddress got 0x%x, %v", got, err)
	}
}

func TestParseCLIFlagsReturnsUsageErrorInsteadOfExiting(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_ = fs.Bool("known", false, "")
	err := parseCLIFlags(fs, []string{"--unknown"})
	var usageErr *cliUsageError
	if !errors.As(err, &usageErr) || !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("parse error = %T %v, want cliUsageError", err, err)
	}
}

func TestParseCLIFlagsPrintsHelpAndReturnsErrHelp(t *testing.T) {
	fs := flag.NewFlagSet("test-help", flag.ContinueOnError)
	_ = fs.Bool("known", false, "known option")
	var out bytes.Buffer
	fs.SetOutput(&out)
	err := parseCLIFlags(fs, []string{"--help"})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help error = %v, want flag.ErrHelp", err)
	}
	if !strings.Contains(out.String(), "known option") {
		t.Fatalf("help output missing registered option: %q", out.String())
	}
}

func TestResolvePositionalLibRejectsDirectories(t *testing.T) {
	if got := resolvePositionalLib(t.TempDir()); got != "" {
		t.Fatalf("directory resolved as positional library: %q", got)
	}
	path := filepath.Join(t.TempDir(), "libapp.so")
	if err := os.WriteFile(path, []byte("placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := resolvePositionalLib(path); got == "" {
		t.Fatal("regular file did not resolve as positional library")
	}
}
