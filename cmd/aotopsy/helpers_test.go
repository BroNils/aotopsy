package main

import (
	"flag"
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
