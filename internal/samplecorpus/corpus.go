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

	// SourceSet names the Dart PROGRAM this binary was compiled from.
	// Samples sharing a non-empty SourceSet were built from byte-identical
	// lib/*.dart by different SDKs, so any difference in what the analyser
	// recovers from them is a version-specific defect rather than a property
	// of the app.
	//
	// That control is what no other gate in this project provides. The golden
	// records compare a version against its own previous output, so a version
	// that has been broken since the day it was added stays green forever --
	// which is exactly what happened to the nine versions whose dispatch table
	// could not be parsed at all. symtabdiff needs a .symtab, which release
	// builds do not have. Comparing a version against its SIBLINGS is the only
	// arrangement that can say "this one recovers sixty times less".
	SourceSet string

	// ProfileIncomplete marks a sample whose Dart version has a VersionProfile
	// that cannot yet parse it. The sample is registered because it exists and
	// is correct; what is not yet correct is this project's profile for that
	// version. Tests skip it with this reason rather than failing forever or,
	// worse, being left unregistered so the gap goes unrecorded.
	ProfileIncomplete string

	// FileSuffix distinguishes samples that share a Dart version and
	// architecture with another entry but were built from a different source
	// set, e.g. "-pre214".
	FileSuffix string
}

// FileName is the name this sample must have under samples/.
//
// The version is IN the name deliberately: it is what makes the name
// checkable, and a name that cannot be checked is what rotted last time.
func (s Sample) FileName() string {
	return fmt.Sprintf("dart-%s%s-%s.so", s.DartVersion, s.FileSuffix, s.Arch)
}

// comparesample is the source set every deliberately-built sample uses: the
// lib/*.dart of ~/dev/compare_sample, copied verbatim into each new project so
// the only variable between those binaries is the Dart SDK that compiled them.
const comparesample = "compare_sample"

// comparesamplePre214 is a SECOND source set, for the Dart versions that
// cannot compile the first one.
//
// signal_ground_truth.dart uses the >>> operator, which does not exist before
// Dart 2.14, and it is the file every metric in the differential is derived
// from. Downlevelling it inside the main set would have quietly changed the
// control that makes the whole comparison meaningful, so the pre-2.14 samples
// get their own set instead: >>> replaced by an _ushr helper that is exactly
// equivalent for 1 <= n <= 63, applied identically to every member.
//
// The set deliberately includes one modern version built from the SAME
// downlevelled source, so its members have a known-good baseline to be
// differential against rather than only each other.
const comparesamplePre214 = "compare_sample_pre214"

// Registry is every sample the test suite knows about, present or not.
//
// An entry whose file is absent is a documented hole, not an oversight:
// tests needing it skip with a message naming the version (MissingMessage).
// That is deliberately different from the old behaviour, where a missing
// sample was quietly replaced by whatever binary shared its name.
var Registry = []Sample{
	{DartVersion: "2.12.0", Arch: "arm64", Note: "dart212_sample, Flutter 2.x toy app"},

	// The pre-2.14 source set; see comparesamplePre214. Names carry the
	// -pre214 suffix so these never collide with the main set's files.
	// Dart 2.10.0 is NOT buildable from this source and is left out on
	// purpose. It predates null safety entirely, so `required`, `?` and `late`
	// are not downlevellable syntax -- rewriting around them would produce a
	// different program, which is exactly what a source set must not contain.
	{DartVersion: "2.13.0", Arch: "arm64", SourceSet: comparesamplePre214, Note: "sample_pre214_2.13.0, Flutter 2.2.0 -- the only TagStyleCidInt32 sample besides 2.12.0", FileSuffix: "-pre214"},
	{DartVersion: "2.13.0", Arch: "x64", SourceSet: comparesamplePre214, Note: "sample_pre214_2.13.0 x86_64", FileSuffix: "-pre214"},
	{DartVersion: "3.5.0", Arch: "arm64", SourceSet: comparesamplePre214, Note: "sample_pre214_3.5.0 -- known-good baseline for the pre-2.14 set", FileSuffix: "-pre214"},
	{DartVersion: "3.5.0", Arch: "x64", SourceSet: comparesamplePre214, Note: "sample_pre214_3.5.0 x86_64", FileSuffix: "-pre214"},
	// 2.14.0-2.16.0 need Java 11 (their Gradle rejects Java 17 class files) and
	// carry ONE source difference: main.dart's two widget constructors are
	// written the pre-2.17 way, because super-parameters do not exist there.
	// ground_truth.dart and signal_ground_truth.dart -- where every metric in
	// the differential comes from -- are byte-identical to the rest of the set.
	{DartVersion: "2.14.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_2.14.0, Flutter 2.5.0 -- first TagStyleCidShift1"},
	{DartVersion: "2.14.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_2.14.0 x86_64"},
	{DartVersion: "2.15.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_2.15.0, Flutter 2.8.0"},
	{DartVersion: "2.15.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_2.15.0 x86_64"},
	{DartVersion: "2.16.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_2.16.0, Flutter 2.10.0 -- last with the 6-field header"},
	{DartVersion: "2.16.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_2.16.0 x86_64"},
	{DartVersion: "2.17.6", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_2.17.6, built with Flutter 3.0.5 to cover TagStyleCidShift1"},
	{DartVersion: "3.1.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.1.0, built with Flutter 3.13.0 (NOT 3.1.0 -- that ships Dart 2.x)"},
	{DartVersion: "2.19.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_2.19.0, Flutter 3.7.0 -- first version with initial_field_table in roots"},
	{DartVersion: "3.3.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.3.0, Flutter 3.19.0 -- last TagStyleCidShift1"},
	{DartVersion: "3.4.3", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.4.3, Flutter 3.22.2 -- first TagStyleObjectHeader, last with the 4-bit type_class_id shift"},
	{DartVersion: "3.5.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.5.0, Flutter 3.24.0 -- first with shared_initial_field_table AND the 3-bit shift"},
	{DartVersion: "2.18.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_2.18.0, Flutter 3.3.1"},
	{DartVersion: "3.7.0", Arch: "x64", Note: "gopay_2.14.1 (directory name is the APP version, not Dart's)"},
	{DartVersion: "3.9.2", Arch: "arm64", SourceSet: comparesample, Note: "compare_sample, the reference toy app"},

	// The x64 half of the same source set. Same program, same Dart version,
	// different architecture -- the control the arch-parity work never had:
	// its headline gap (x86_64 281 vs ARM64 2361 single-callee sites) was
	// measured on one app with no sibling to compare against.
	{DartVersion: "2.17.6", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_2.17.6 x86_64"},
	{DartVersion: "2.18.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_2.18.0 x86_64"},
	{DartVersion: "2.19.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_2.19.0 x86_64"},
	{DartVersion: "3.1.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.1.0 x86_64"},
	{DartVersion: "3.3.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.3.0 x86_64"},
	{DartVersion: "3.4.3", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.4.3 x86_64"},
	{DartVersion: "3.5.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.5.0 x86_64"},
	{DartVersion: "3.10.7", Arch: "arm64", Note: "sample_310"},
	{DartVersion: "3.11.0", Arch: "arm64", Note: "sample_311"},
	{DartVersion: "3.12.2", Arch: "arm64", Note: "sample_312"},
	{DartVersion: "3.12.2", Arch: "x64", Note: "sample_312 x86_64"},
	{DartVersion: "3.13.0", Arch: "arm64", Note: "sample_313, built for the unified-snapshot work"},
}

// SourceSets groups the registry by SourceSet, dropping samples that belong to
// none and sets with fewer than two members -- a set of one has nothing to be
// differential against.
func SourceSets() map[string][]Sample {
	bySet := map[string][]Sample{}
	for _, s := range Registry {
		if s.SourceSet == "" {
			continue
		}
		bySet[s.SourceSet] = append(bySet[s.SourceSet], s)
	}
	for name, members := range bySet {
		if len(members) < 2 {
			delete(bySet, name)
		}
	}
	return bySet
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
