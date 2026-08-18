// Package samplecorpus is the registry of sample binaries the tests run
// against, and the guard that keeps a sample honest about what it is.
//
// # Why this exists
//
// The fixtures used to be named after the app they came from --
// blutter-lce.so, newandromo.so, evil-patched.so -- with the Dart version
// they were supposed to be recorded only in a comment next to each expected
// count. samples/ is gitignored, so those names pointed at whatever each
// machine happened to have.
//
// They drifted, and nothing noticed. On the machine this package was written
// on, blutter-lce.so (documented as Dart 2.17.6) was a symlink to a Dart
// 3.9.2 binary -- byte-identical to compare_sample_arm64.so -- and
// newandromo.so (documented as 3.1.0) pointed at a 3.11.0 build. Five test
// files were permanently red as a result, so they had stopped being able to
// signal anything at all, and the two versions they were meant to pin had no
// coverage from any test.
//
// # The fix
//
// A sample's name states its Dart version and architecture, and Extract
// reads the binary so callers can check it against its own name (see
// VersionMismatch). A mislabelled fixture now fails immediately, saying
// which version it claims and which it actually is,
// instead of surfacing as a wall of mismatched counts pointing at innocent
// parsing code.
//
// # Coverage
//
// Registry doubles as the corpus inventory. What matters for coverage is not
// the number of versions but the number of FORMAT FAMILIES, since a version
// profile is mostly a restatement of the format its release used --
// see TestCorpusCoverage.
package samplecorpus

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/snapshot"
)

// Extract opens a sample and parses its snapshot headers. It is the one
// operation every caller needs before it can check a sample against its name.
//
// The ELF handle is closed before returning: callers that need the mapped
// data open the file themselves. This exists to answer "what version is
// this file", nothing more.
func Extract(path string) (*snapshot.Info, error) {
	ef, err := elfx.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = ef.Close() }()
	return snapshot.Extract(ef, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
}

// Sample is one binary in the corpus.
type Sample struct {
	// DartVersion is the version snapshot.Extract must report for this
	// file. A file reporting anything else is a mislabelled fixture; see
	// VersionMismatch.
	DartVersion string
	// Arch is "arm64" or "x64", part of the filename only.
	Arch string
	// Note records where the binary came from, for whoever has to
	// reconstruct the corpus on a new machine.
	Note string
}

// FileName is the name this sample must have under samples/.
//
// The version is IN the name deliberately: it is what makes the name
// checkable, and a name that cannot be checked is what rotted last time.
func (s Sample) FileName() string {
	return fmt.Sprintf("dart-%s-%s.so", s.DartVersion, s.Arch)
}

// Registry is every sample the test suite knows about, present or not.
//
// An entry whose file is absent is a documented hole, not an oversight:
// tests needing it skip with a message naming the version (MissingMessage).
// That is deliberately different from the old behaviour, where a missing
// sample was quietly replaced by whatever binary shared its name.
var Registry = []Sample{
	{DartVersion: "2.12.0", Arch: "arm64", Note: "dart212_sample, Flutter 2.x toy app"},
	{DartVersion: "2.17.6", Arch: "arm64", Note: "sample_dart_2.17.6, built with Flutter 3.0.5 to cover TagStyleCidShift1"},
	{DartVersion: "3.1.0", Arch: "arm64", Note: "sample_dart_3.1.0, built with Flutter 3.13.0 (NOT 3.1.0 -- that ships Dart 2.x)"},
	{DartVersion: "3.7.0", Arch: "x64", Note: "gopay_2.14.1 (directory name is the APP version, not Dart's)"},
	{DartVersion: "3.9.2", Arch: "arm64", Note: "compare_sample, the reference toy app"},
	{DartVersion: "3.10.7", Arch: "arm64", Note: "sample_310"},
	{DartVersion: "3.11.0", Arch: "arm64", Note: "sample_311"},
	{DartVersion: "3.12.2", Arch: "arm64", Note: "sample_312"},
	{DartVersion: "3.12.2", Arch: "x64", Note: "sample_312 x86_64"},
	{DartVersion: "3.13.0", Arch: "arm64", Note: "sample_313, built for the unified-snapshot work"},
}

// Get returns the registry entry for a version/arch pair.
func Get(dartVersion, arch string) (Sample, bool) {
	for _, s := range Registry {
		if s.DartVersion == dartVersion && s.Arch == arch {
			return s, true
		}
	}
	return Sample{}, false
}

// Path locates a sample by walking up from the working directory to a
// samples/ directory. It returns "" when the sample is not present, which
// callers turn into a skip.
func Path(fileName string) string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		p := filepath.Join(dir, "samples", fileName)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// MissingMessage is what a test prints when it skips for a missing sample.
func MissingMessage(s Sample) string {
	return fmt.Sprintf("sample %s not present (Dart %s %s: %s) -- "+
		"place or symlink it under samples/", s.FileName(), s.DartVersion, s.Arch, s.Note)
}

// VersionMismatch builds the error text for a sample that is not the version
// its name claims. Kept here so every caller words it the same way, and so the
// remedy is stated where the failure appears.
func VersionMismatch(s Sample, got string) string {
	if got == "" {
		got = "<undetected>"
	}
	return fmt.Sprintf(
		"samples/%s is Dart %s, not %s.\n"+
			"  The filename is the contract: this file must be a Dart %s %s build.\n"+
			"  Point it at the right binary, or remove it so the test skips instead of\n"+
			"  testing the wrong thing. (%s)",
		s.FileName(), got, s.DartVersion, s.DartVersion, s.Arch, s.Note)
}

// Versions returns the registry's Dart versions, deduplicated and sorted.
func Versions() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range Registry {
		if !seen[s.DartVersion] {
			seen[s.DartVersion] = true
			out = append(out, s.DartVersion)
		}
	}
	sort.Slice(out, func(i, j int) bool { return compare(out[i], out[j]) < 0 })
	return out
}

func compare(a, b string) int {
	pa, pb := triple(a), triple(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func triple(s string) [3]int {
	var v [3]int
	for i, part := range strings.SplitN(s, ".", 3) {
		if i >= 3 {
			break
		}
		n := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		v[i] = n
	}
	return v
}
