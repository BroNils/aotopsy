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
// A sample's name states its Dart version and architecture, and ValidateSample
// checks both claims against the binary. A mislabelled fixture now fails
// immediately, saying which version or architecture it claims and what the
// binary actually contains,
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
	"debug/elf"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/snapshot"
)

var (
	ErrNoCorpus           = errors.New("samplecorpus: no samples directory in this checkout")
	ErrSampleMissing      = errors.New("samplecorpus: required sample missing")
	ErrSampleUnregistered = errors.New("samplecorpus: sample is not registered")
)

const ExpectedSampleCount = 93

// corpusManifest is intentionally independent from Registry. It is the public
// corpus contract used by completeness gates, so deleting a Registry row cannot
// make a 92-sample run redefine itself as complete.
//
//go:embed corpus_manifest.txt
var corpusManifest string

// corpusSHA256Manifest pins the exact bytes behind every gitignored corpus
// filename. Version/arch validation alone is not enough: two different builds
// from the same Dart release can both satisfy those claims while exercising
// different source or carrying different symbol/debug assistance.
//
//go:embed corpus_sha256.txt
var corpusSHA256Manifest string

// Extract opens a sample and parses its snapshot headers. It is the lightweight
// version-only helper; ValidateSample additionally checks registry identity.
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
	// Arch is "arm64" or "x64" and must match the ELF machine.
	Arch string
	// Note records where the binary came from, for whoever has to
	// reconstruct the corpus on a new machine.
	Note string

	// SourceSet names the Dart PROGRAM family this binary was compiled from.
	// Differential members sharing a SourceSet keep ground_truth.dart and
	// signal_ground_truth.dart byte-identical. The main set deliberately has a
	// syntax-only main.dart lowering on Dart 2.14-2.16 because super-parameters
	// do not exist there; that file is not the source of the differential metrics.
	//
	// That control is what no other gate in this project provides. The golden
	// records compare a version against its own previous output, so a version
	// that has been broken since the day it was added stays green forever --
	// which is exactly what happened to the nine versions whose dispatch table
	// could not be parsed at all. symtabdiff needs a .symtab, which release
	// builds do not have. Comparing a version against its SIBLINGS is the only
	// arrangement that can say "this one recovers sixty times less".
	SourceSet string

	// FileSuffix distinguishes samples that share a Dart version and
	// architecture with another entry but were built from a different source
	// set, e.g. "-pre214".
	FileSuffix string

	// SymbolOracle marks an UNSTRIPPED sample built with
	//
	//	flutter build apk --release --extra-gen-snapshot-options=--no-strip
	//
	// so gen_snapshot leaves a .symtab behind. It exists for exactly one gate,
	// TestSymtabDifferential, which is the only check in this project that
	// compares recovered names against something other than our own previous
	// output.
	//
	// It is a SEPARATE sample rather than a replacement, deliberately. The
	// corpus has to keep representing stripped production binaries, because
	// that is the condition the tool actually runs in -- recovering names
	// without symbols is the whole point. Symbol-oracle samples are excluded
	// from corpus cluster-fact records and from the cross-version differential:
	// their purpose is the ELF symbol-table oracle, not another analysis baseline.
	//
	// When TwinOf is non-empty, the oracle is also a true unstripped twin of the
	// named stripped registry entry. TwinOf is explicit because the 3.10.7 and
	// 3.11.0 symbol oracles come from sample_dart_* while those versions' stripped
	// corpus entries come from sample_310/sample_311; calling those four files
	// twins was false even though they are valid symbol oracles.
	//
	// The true twins' honesty was measured, not assumed. LoadContext -- the path the
	// symtab gate reads names from -- never consults .symtab; only
	// pipeline.Run does, via elfStubName, and only as a last resort for Codes
	// the snapshot could not name at all. Proven on 3.9.2 arm64 by loading a
	// stripped binary and its unstripped twin and diffing the recovered names:
	// 8220 names, ZERO differences. The gate is not validating itself.
	SymbolOracle bool
	TwinOf       string
}

// FileName is the name this sample must have under samples/.
//
// The version is IN the name deliberately: it is what makes the name
// checkable, and a name that cannot be checked is what rotted last time.
func (s Sample) FileName() string {
	return fmt.Sprintf("dart-%s%s-%s.so", s.DartVersion, s.FileSuffix, s.Arch)
}

// comparesample is the main deliberately-built source family. Its two
// metric-bearing files are byte-identical in every differential member. Dart
// 2.14-2.16 only use the syntax-equivalent pre-super-parameter spelling in
// main.dart.
const comparesample = "compare_sample"

// comparesamplePre214 is a SECOND source set, for the Dart versions that
// cannot compile the first one.
//
// signal_ground_truth.dart uses the >>> operator. Dart 2.13 contains the
// implementation but keeps it behind the triple-shift experiment; Dart 2.14
// is the first default-language side used by these samples. Downlevelling it
// inside the main set would have quietly changed the
// control that makes the whole comparison meaningful, so the pre-2.14 samples
// get their own set instead: >>> replaced by an _ushr helper that is exactly
// equivalent for 1 <= n <= 63, applied identically to every member.
//
// The set deliberately includes one modern version built from the SAME
// downlevelled source, so its members have a known-good baseline to be
// differential against rather than only each other.
const comparesamplePre214 = "compare_sample_pre214"

// comparesamplePreNNBD is a THIRD source set, for the versions that predate
// null safety.
//
// Dart 2.10.0 has no `required` keyword at all, so even the pre-2.14 source
// will not compile there. Removing the three uses of it produces valid
// pre-null-safety Dart, and pinning every member's pubspec to language version
// 2.10 makes the whole set compile the same way -- which is what keeps it a
// control rather than three unrelated binaries.
const comparesamplePreNNBD = "compare_sample_prenn"

// Dart 2.10.0 used to be registered here with a ProfileIncomplete note saying
// its roots section could not be read. Both halves of that note were wrong, and
// the way it was wrong is worth keeping.
//
// The note reasoned that since every checkable roots fact was right (roots
// shape, 4-field header, ObjectStoreAOTFieldCount 176) and no FillEnd offset
// within +/-96 bytes parsed, the cause had to be a structural difference in the
// roots layout itself. The roots layout was never the problem. FillEnd was
// short by 392 bytes -- four times further out than the window that was
// searched -- because Instance fill silently read every unboxed field slot as
// one ref instead of two 32-bit reads. At 2.10 the unboxed bitmap lives only in
// the Class cluster, and readFillInstance defaulted it to zero. See
// readFillInstance.
//
// The lesson: a +/-96 byte scan that finds nothing does not mean "not a
// mis-sized fill", it means "not a SMALL mis-sized fill". Widening the search
// and demanding that the whole roots structure replay to exactly the isolate
// snapshot's end found the true offset immediately, and identically on both
// architectures -- which is itself the tell that it was a fixed structural
// miss rather than per-object drift.
// Registry is the complete sample inventory. A checkout with no samples/
// directory may skip corpus-driven tests, but once samples/ exists every
// registry entry is required; a missing member is corpus drift, not a hole.
var Registry = []Sample{
	{DartVersion: "2.12.0", Arch: "arm64", Note: "dart212_sample, Flutter 2.x toy app"},

	// The pre-2.14 source set; see comparesamplePre214. Names carry the
	// -pre214 suffix so these never collide with the main set's files.
	// The pre-null-safety set; see comparesamplePreNNBD. This is where Dart
	// 2.10.0 lives -- it is buildable after all, once the source stops using
	// the `required` keyword.
	{DartVersion: "2.10.0", Arch: "arm64", SourceSet: comparesamplePreNNBD, Note: "sample_prenn_2.10.0, Flutter 1.22.0", FileSuffix: "-prenn"},
	{DartVersion: "2.10.0", Arch: "x64", SourceSet: comparesamplePreNNBD, Note: "sample_prenn_2.10.0 x86_64", FileSuffix: "-prenn"},
	{DartVersion: "2.12.0", Arch: "arm64", SourceSet: comparesamplePreNNBD, Note: "sample_prenn_2.12.0", FileSuffix: "-prenn"},
	{DartVersion: "2.12.0", Arch: "x64", SourceSet: comparesamplePreNNBD, Note: "sample_prenn_2.12.0 x86_64", FileSuffix: "-prenn"},
	{DartVersion: "2.13.0", Arch: "arm64", SourceSet: comparesamplePreNNBD, Note: "sample_prenn_2.13.0", FileSuffix: "-prenn"},
	{DartVersion: "2.13.0", Arch: "x64", SourceSet: comparesamplePreNNBD, Note: "sample_prenn_2.13.0 x86_64", FileSuffix: "-prenn"},
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
	// REAL production apps, not toys. These exercise code shapes -- deep
	// class hierarchies, obfuscated names, third-party packages, XOR/AES
	// helpers -- that the generated sample never produces, which is exactly
	// where name resolution is stressed hardest.
	{DartVersion: "3.7.0", Arch: "x64", Note: "realapp2 (production app, x64)", FileSuffix: "-realapp2"},
	// A real third-party production app, Dart 3.12.2 arm64, 9.5 MB, 23795
	// Codes. Stripped, obfuscated, and shipped alongside native protection
	// libraries, so it is the most adversarial name-resolution target in the
	// corpus. NOT in a SourceSet: its source is unknown and unshared, so it
	// belongs to no differential. Kept deliberately anonymous -- only its
	// format-relevant properties matter here.
	{DartVersion: "3.12.2", Arch: "arm64", Note: "third-party production app, stripped + obfuscated", FileSuffix: "-realapp"},
	{DartVersion: "3.7.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.7.0, Flutter 3.29.1"},
	{DartVersion: "3.7.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.7.0 x86_64"},
	{DartVersion: "3.9.2", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.9.2, Flutter 3.35.5"},
	{DartVersion: "3.9.2", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.9.2 x86_64"},

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
	// sample_310 and sample_311 have their own lib/, NOT compare_sample's, so
	// they stay out of the source set -- checked, not assumed. They still earn
	// their place: corpus cluster facts and architecture coverage.
	{DartVersion: "3.10.7", Arch: "arm64", Note: "sample_310"},
	{DartVersion: "3.10.7", Arch: "x64", Note: "sample_310 x86_64"},
	{DartVersion: "3.11.0", Arch: "arm64", Note: "sample_311"},
	{DartVersion: "3.11.0", Arch: "x64", Note: "sample_311 x86_64"},
	{DartVersion: "3.12.2", Arch: "arm64", Note: "sample_312 stripped_native_libs"},
	{DartVersion: "3.12.2", Arch: "x64", Note: "sample_312 x86_64 stripped_native_libs"},
	// sample_313's lib/ IS byte-identical to compare_sample's, so unlike
	// sample_310/311 this pair can carry its weight in the differential.
	{DartVersion: "3.13.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.13.0, Flutter 3.47.0, stripped_native_libs"},
	{DartVersion: "3.13.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.13.0 x86_64, stripped_native_libs"},

	// The versions whose ObjectStoreAOTFieldCount had only ever been counted
	// from object_store.h, never confirmed against a binary. 2.15.0 is why
	// that distinction matters: its profile looked just as correct, until a
	// real sample showed its snapshot hash was mapped to the wrong version.
	// Flutter release picked from releases_linux.json's dart_sdk_version,
	// not guessed: 3.0.5 -> Flutter 3.10.5, 3.2.5 -> 3.16.8,
	// 3.6.2 -> 3.27.4, 3.8.1 -> 3.32.8.
	{DartVersion: "3.0.5", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.0.5, Flutter 3.10.5"},
	{DartVersion: "3.0.5", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.0.5 x86_64"},
	{DartVersion: "3.2.5", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.2.5, Flutter 3.16.8"},
	{DartVersion: "3.2.5", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.2.5 x86_64"},
	{DartVersion: "3.6.2", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.6.2, Flutter 3.27.4"},
	{DartVersion: "3.6.2", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.6.2 x86_64"},
	{DartVersion: "3.8.1", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.8.1, Flutter 3.32.8"},
	{DartVersion: "3.8.1", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.8.1 x86_64"},

	// Dart 3.12.0 stable. Registered under the 3.12.2 profile because that is
	// what it detects as -- the whole 3.12 line is one format; see the three
	// hashes mapped together in snapshot/version.go. It is kept as its own
	// sample rather than folded into 3.12.2's because it is a different
	// binary from a different Flutter release, and the corpus records are
	// keyed by input sha256.
	{DartVersion: "3.12.2", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.12.0, Flutter 3.44.0 -- Dart 3.12.0 stable, 3.12.2 format, stripped_native_libs", FileSuffix: "-f3440"},
	{DartVersion: "3.12.2", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.12.0 x86_64, Flutter 3.44.0, stripped_native_libs", FileSuffix: "-f3440"},

	// Unstripped symbol oracles -- see Sample.SymbolOracle. Most are true twins
	// of a stripped corpus sample and declare that relation in TwinOf. The
	// 3.10.7/3.11.0 oracles are intentionally standalone: their sample_dart_*
	// source is the compare_sample family, while the stripped 3.10.7/3.11.0
	// corpus entries are sample_310/sample_311 and have different source.
	// All are built with
	// --extra-gen-snapshot-options=--no-strip added.
	//
	// The flag is missing from `flutter build apk --help` on every release
	// before 3.35, which is why it looked unavailable at first. It is present
	// in flutter_tools/lib/src/build_info.dart at 2.5.0 and every release
	// after, merely hidden -- and it works: the 2.14.0 twin carries 7303 FUNC
	// symbols against the analysis sample's zero.
	// 2.10.0 and 2.12.0 have NO twin and cannot get one. Flutter 2.0.0 and
	// earlier reject --extra-gen-snapshot-options on the APK build path
	// outright -- measured both spellings, --no-strip and --no_strip, and the
	// same project builds fine the moment the option is dropped. The option
	// exists in flutter_tools/lib/src/flutter_command.dart at that era but is
	// not plumbed through to the AOT assemble step. Flutter 2.2.0 (Dart 2.13)
	// is where it starts working, so that is the floor for ground truth.
	{DartVersion: "2.13.0", Arch: "arm64", SourceSet: comparesamplePreNNBD, Note: "sample_prenn_2.13.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-2.13.0-prenn-arm64.so"},
	{DartVersion: "2.13.0", Arch: "x64", SourceSet: comparesamplePreNNBD, Note: "sample_prenn_2.13.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-2.13.0-prenn-x64.so"},
	{DartVersion: "2.14.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_2.14.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-2.14.0-arm64.so"},
	{DartVersion: "2.14.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_2.14.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-2.14.0-x64.so"},
	{DartVersion: "2.15.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_2.15.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-2.15.0-arm64.so"},
	{DartVersion: "2.15.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_2.15.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-2.15.0-x64.so"},
	{DartVersion: "2.16.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_2.16.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-2.16.0-arm64.so"},
	{DartVersion: "2.16.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_2.16.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-2.16.0-x64.so"},
	{DartVersion: "2.17.6", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_2.17.6 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-2.17.6-arm64.so"},
	{DartVersion: "2.17.6", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_2.17.6 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-2.17.6-x64.so"},
	{DartVersion: "2.18.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_2.18.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-2.18.0-arm64.so"},
	{DartVersion: "2.18.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_2.18.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-2.18.0-x64.so"},
	{DartVersion: "2.19.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_2.19.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-2.19.0-arm64.so"},
	{DartVersion: "2.19.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_2.19.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-2.19.0-x64.so"},
	{DartVersion: "3.0.5", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.0.5 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.0.5-arm64.so"},
	{DartVersion: "3.0.5", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.0.5 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.0.5-x64.so"},
	{DartVersion: "3.1.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.1.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.1.0-arm64.so"},
	{DartVersion: "3.1.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.1.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.1.0-x64.so"},
	{DartVersion: "3.2.5", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.2.5 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.2.5-arm64.so"},
	{DartVersion: "3.2.5", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.2.5 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.2.5-x64.so"},
	{DartVersion: "3.3.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.3.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.3.0-arm64.so"},
	{DartVersion: "3.3.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.3.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.3.0-x64.so"},
	{DartVersion: "3.4.3", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.4.3 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.4.3-arm64.so"},
	{DartVersion: "3.4.3", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.4.3 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.4.3-x64.so"},
	{DartVersion: "3.5.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.5.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.5.0-arm64.so"},
	{DartVersion: "3.5.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.5.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.5.0-x64.so"},
	{DartVersion: "3.6.2", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.6.2 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.6.2-arm64.so"},
	{DartVersion: "3.6.2", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.6.2 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.6.2-x64.so"},
	{DartVersion: "3.7.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.7.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.7.0-arm64.so"},
	{DartVersion: "3.7.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.7.0 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.7.0-x64.so"},
	{DartVersion: "3.8.1", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.8.1 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.8.1-arm64.so"},
	{DartVersion: "3.8.1", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.8.1 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.8.1-x64.so"},
	{DartVersion: "3.9.2", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.9.2 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.9.2-arm64.so"},
	{DartVersion: "3.9.2", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.9.2 --no-strip", FileSuffix: "-gt", SymbolOracle: true, TwinOf: "dart-3.9.2-x64.so"},
	{DartVersion: "3.10.7", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.10.7 --no-strip; standalone symbol oracle (stripped 3.10.7 is different source)", FileSuffix: "-gt", SymbolOracle: true},
	{DartVersion: "3.10.7", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.10.7 --no-strip; standalone symbol oracle (stripped 3.10.7 is different source)", FileSuffix: "-gt", SymbolOracle: true},
	{DartVersion: "3.11.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.11.0 --no-strip; standalone symbol oracle (stripped 3.11.0 is different source)", FileSuffix: "-gt", SymbolOracle: true},
	{DartVersion: "3.11.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.11.0 --no-strip; standalone symbol oracle (stripped 3.11.0 is different source)", FileSuffix: "-gt", SymbolOracle: true},
}

// DifferentialSourceSets groups analysis samples by SourceSet. Symbol-oracle
// builds are deliberately excluded: even when they share source, their role is
// an ELF-symbol oracle and including them would double-count a source/version.
// Singleton sets are retained so callers cannot silently erase a broken set.
func DifferentialSourceSets() map[string][]Sample {
	bySet := map[string][]Sample{}
	for _, s := range Registry {
		if s.SourceSet == "" || s.SymbolOracle {
			continue
		}
		bySet[s.SourceSet] = append(bySet[s.SourceSet], s)
	}
	return bySet
}

// ExpectedFiles returns the independent corpus manifest in stable order.
func ExpectedFiles() []string {
	lines := strings.Split(strings.TrimSpace(corpusManifest), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func expectedSHA256s() (map[string]string, error) {
	lines := strings.Split(strings.TrimSpace(corpusSHA256Manifest), "\n")
	out := make(map[string]string, len(lines))
	lastName := ""
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("samplecorpus: corpus_sha256.txt row %d has %d fields, want sha256 + filename", i+1, len(fields))
		}
		sum, name := fields[0], fields[1]
		if len(sum) != 64 || sum != strings.ToLower(sum) {
			return nil, fmt.Errorf("samplecorpus: corpus_sha256.txt row %d has malformed sha256 %q", i+1, sum)
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return nil, fmt.Errorf("samplecorpus: corpus_sha256.txt row %d has invalid sha256 %q: %w", i+1, sum, err)
		}
		if err := validateSampleName(name); err != nil {
			return nil, fmt.Errorf("samplecorpus: corpus_sha256.txt row %d: %w", i+1, err)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("samplecorpus: duplicate sha256 manifest entry %q", name)
		}
		if lastName != "" && name <= lastName {
			return nil, fmt.Errorf("samplecorpus: corpus_sha256.txt is not sorted by filename")
		}
		lastName = name
		out[name] = sum
	}
	return out, nil
}

// CorpusRoot returns the nearest samples/ directory walking upward from the
// current working directory. Once a samples/ entry is encountered it is the
// authoritative root: an incomplete nested corpus must never fall through to a
// convenient ancestor corpus.
func CorpusRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("samplecorpus: getwd: %w", err)
	}
	for {
		root := filepath.Join(dir, "samples")
		resolvedRoot, fi, statErr := statCorpusPath(root)
		if statErr == nil {
			if !fi.IsDir() {
				return "", fmt.Errorf("samplecorpus: %s exists but is not a directory", root)
			}
			return resolvedRoot, nil
		}
		if errors.Is(statErr, os.ErrNotExist) {
			// A dangling symlink (including a WSL-created LX symlink on
			// Windows) is still a samples/ entry. Treating it as absent would
			// let an incomplete nested corpus fall through to an ancestor.
			if _, lstatErr := os.Lstat(root); lstatErr == nil {
				return "", fmt.Errorf("samplecorpus: %s exists but its target is unavailable: %w", root, statErr)
			} else if !errors.Is(lstatErr, os.ErrNotExist) {
				return "", fmt.Errorf("samplecorpus: lstat %s: %w", root, lstatErr)
			}
		} else {
			return "", fmt.Errorf("samplecorpus: stat %s: %w", root, statErr)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", ErrNoCorpus
		}
		dir = parent
	}
}

func validateSampleName(fileName string) error {
	if fileName == "" || fileName == "." || fileName == ".." || filepath.IsAbs(fileName) ||
		filepath.Base(fileName) != fileName || strings.ContainsAny(fileName, `/\`) {
		return fmt.Errorf("samplecorpus: unsafe sample name %q", fileName)
	}
	return nil
}

func registeredSample(fileName string) (Sample, bool) {
	for _, s := range Registry {
		if s.FileName() == fileName {
			return s, true
		}
	}
	return Sample{}, false
}

// resolveSamplePath resolves one corpus member from the authoritative nearest
// root without interpreting its bytes. It is intentionally private: production
// test callers must go through RequireSample so a convenient regular file cannot
// bypass registry/version/arch/symbol-role validation.
func resolveSamplePath(fileName string) (string, error) {
	if err := validateSampleName(fileName); err != nil {
		return "", err
	}
	root, err := CorpusRoot()
	if err != nil {
		return "", err
	}
	p := filepath.Join(root, fileName)
	resolved, fi, err := statCorpusPath(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: %s", ErrSampleMissing, fileName)
		}
		return "", fmt.Errorf("samplecorpus: stat %s: %w", p, err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("samplecorpus: %s is not a regular file", p)
	}
	return resolved, nil
}

// RequireSample resolves and validates one REGISTERED corpus member.
// ErrNoCorpus means a fresh checkout may skip the whole corpus gate;
// ErrSampleMissing means a populated corpus is incomplete and must fail;
// ErrSampleUnregistered means the caller attempted to bypass the registry.
func RequireSample(fileName string) (string, error) {
	s, ok := registeredSample(fileName)
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrSampleUnregistered, fileName)
	}
	p, err := resolveSamplePath(fileName)
	if err != nil {
		return "", err
	}
	if _, err := ValidateSample(p, s); err != nil {
		return "", fmt.Errorf("samplecorpus: validate %s: %w", fileName, err)
	}
	return p, nil
}

// ValidateRegistry checks the in-code registry against the independent corpus
// manifest and the snapshot profiles. This is intentionally runnable without
// local sample binaries.
func ValidateRegistry() error {
	expected := ExpectedFiles()
	if len(expected) != ExpectedSampleCount {
		return fmt.Errorf("samplecorpus: manifest has %d entries, want %d", len(expected), ExpectedSampleCount)
	}
	manifestSet := make(map[string]struct{}, len(expected))
	sortedExpected := append([]string(nil), expected...)
	sort.Strings(sortedExpected)
	for i, name := range expected {
		if err := validateSampleName(name); err != nil {
			return fmt.Errorf("samplecorpus: manifest entry %d: %w", i, err)
		}
		if _, dup := manifestSet[name]; dup {
			return fmt.Errorf("samplecorpus: duplicate manifest entry %q", name)
		}
		manifestSet[name] = struct{}{}
		if name != sortedExpected[i] {
			return fmt.Errorf("samplecorpus: corpus_manifest.txt is not sorted")
		}
	}
	hashes, err := expectedSHA256s()
	if err != nil {
		return err
	}
	if len(hashes) != ExpectedSampleCount {
		return fmt.Errorf("samplecorpus: sha256 manifest has %d entries, want %d", len(hashes), ExpectedSampleCount)
	}
	for name := range manifestSet {
		if _, ok := hashes[name]; !ok {
			return fmt.Errorf("samplecorpus: manifest entry %q has no pinned sha256", name)
		}
	}
	for name := range hashes {
		if _, ok := manifestSet[name]; !ok {
			return fmt.Errorf("samplecorpus: sha256 entry %q is absent from corpus manifest", name)
		}
	}

	supported := make(map[string]struct{})
	for _, v := range snapshot.SupportedVersions() {
		supported[v] = struct{}{}
	}
	knownSourceSets := map[string]struct{}{
		comparesample:        {},
		comparesamplePre214:  {},
		comparesamplePreNNBD: {},
	}
	registrySet := make(map[string]struct{}, len(Registry))
	byName := make(map[string]Sample, len(Registry))
	sourceCounts := make(map[string]int)
	type sourceVariant struct {
		set, version, suffix string
	}
	sourceArches := make(map[sourceVariant]map[string]struct{})
	for _, s := range Registry {
		name := s.FileName()
		if _, dup := registrySet[name]; dup {
			return fmt.Errorf("samplecorpus: duplicate Registry filename %q", name)
		}
		registrySet[name] = struct{}{}
		if _, ok := manifestSet[name]; !ok {
			return fmt.Errorf("samplecorpus: Registry entry %q is absent from manifest", name)
		}
		if s.Arch != "arm64" && s.Arch != "x64" {
			return fmt.Errorf("samplecorpus: %s has unsupported architecture %q", name, s.Arch)
		}
		if _, ok := supported[s.DartVersion]; !ok {
			return fmt.Errorf("samplecorpus: %s uses unsupported Dart version %s", name, s.DartVersion)
		}
		if strings.TrimSpace(s.Note) == "" {
			return fmt.Errorf("samplecorpus: %s has no origin/note", name)
		}
		if s.FileSuffix != "" && !strings.HasPrefix(s.FileSuffix, "-") {
			return fmt.Errorf("samplecorpus: %s has malformed file suffix %q", name, s.FileSuffix)
		}
		if s.SourceSet != "" {
			if _, ok := knownSourceSets[s.SourceSet]; !ok {
				return fmt.Errorf("samplecorpus: %s uses unknown source set %q", name, s.SourceSet)
			}
		}
		if s.SymbolOracle {
			if s.FileSuffix != "-gt" {
				return fmt.Errorf("samplecorpus: symbol oracle %s must use the -gt suffix", name)
			}
			if s.SourceSet == "" {
				return fmt.Errorf("samplecorpus: symbol oracle %s must identify its source set", name)
			}
		} else {
			if s.FileSuffix == "-gt" {
				return fmt.Errorf("samplecorpus: %s uses the -gt suffix but is not a symbol oracle", name)
			}
			if s.TwinOf != "" {
				return fmt.Errorf("samplecorpus: non-oracle %s declares TwinOf %q", name, s.TwinOf)
			}
		}
		byName[name] = s
		if s.SourceSet != "" {
			if !s.SymbolOracle {
				sourceCounts[s.SourceSet]++
				key := sourceVariant{set: s.SourceSet, version: s.DartVersion, suffix: s.FileSuffix}
				if sourceArches[key] == nil {
					sourceArches[key] = make(map[string]struct{}, 2)
				}
				sourceArches[key][s.Arch] = struct{}{}
			}
		}
	}
	if len(registrySet) != len(manifestSet) {
		for _, name := range expected {
			if _, ok := registrySet[name]; !ok {
				return fmt.Errorf("samplecorpus: manifest entry %q is absent from Registry", name)
			}
		}
		return fmt.Errorf("samplecorpus: Registry/manifest size mismatch: %d vs %d", len(registrySet), len(manifestSet))
	}
	for name, count := range sourceCounts {
		if count < 2 {
			return fmt.Errorf("samplecorpus: source set %q has only %d member", name, count)
		}
	}
	for key, arches := range sourceArches {
		if _, arm64 := arches["arm64"]; !arm64 {
			return fmt.Errorf("samplecorpus: source set %q Dart %s%s has no arm64 member", key.set, key.version, key.suffix)
		}
		if _, x64 := arches["x64"]; !x64 {
			return fmt.Errorf("samplecorpus: source set %q Dart %s%s has no x64 member", key.set, key.version, key.suffix)
		}
	}
	for _, s := range Registry {
		if !s.SymbolOracle || s.TwinOf == "" {
			continue
		}
		if s.TwinOf == s.FileName() {
			return fmt.Errorf("samplecorpus: symbol oracle %s points TwinOf at itself", s.FileName())
		}
		twin, ok := byName[s.TwinOf]
		if !ok {
			return fmt.Errorf("samplecorpus: symbol oracle %s names missing twin %q", s.FileName(), s.TwinOf)
		}
		if twin.SymbolOracle {
			return fmt.Errorf("samplecorpus: symbol oracle %s points TwinOf at another oracle %s", s.FileName(), s.TwinOf)
		}
		if twin.DartVersion != s.DartVersion || twin.Arch != s.Arch || twin.SourceSet != s.SourceSet {
			return fmt.Errorf("samplecorpus: symbol oracle %s is not source/version/arch-identical to declared twin %s", s.FileName(), s.TwinOf)
		}
	}
	return nil
}

// RequireCompleteCorpus verifies the populated samples/ tree is exactly the
// independent manifest. A fresh checkout returns ErrNoCorpus; a populated but
// partial or extra corpus is an error.
func RequireCompleteCorpus() error {
	if err := ValidateRegistry(); err != nil {
		return err
	}
	root, err := CorpusRoot()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("samplecorpus: read %s: %w", root, err)
	}
	disk := make(map[string]struct{})
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".so") {
			disk[entry.Name()] = struct{}{}
		}
	}
	expected := ExpectedFiles()
	if len(disk) != len(expected) {
		return fmt.Errorf("samplecorpus: samples/ has %d .so entries, want %d", len(disk), len(expected))
	}
	for _, name := range expected {
		if _, ok := disk[name]; !ok {
			return fmt.Errorf("%w: %s", ErrSampleMissing, name)
		}
		if _, err := RequireSample(name); err != nil {
			return err
		}
	}
	for name := range disk {
		found := false
		for _, want := range expected {
			if name == want {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("samplecorpus: unregistered sample %s present in samples/", name)
		}
	}
	return nil
}

// ValidateSample checks exact SHA-256, architecture, snapshot-version and symbol
// role against the independent corpus contract + registry metadata. Callers may
// use the returned snapshot info directly.
func ValidateSample(path string, s Sample) (*snapshot.Info, error) {
	ef, err := elfx.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = ef.Close() }()
	wantMachine := elf.EM_AARCH64
	if s.Arch == "x64" {
		wantMachine = elf.EM_X86_64
	} else if s.Arch != "arm64" {
		return nil, fmt.Errorf("samplecorpus: unsupported architecture %q for %s", s.Arch, s.FileName())
	}
	if ef.Machine() != wantMachine {
		return nil, fmt.Errorf("samplecorpus: %s claims %s but ELF machine is %s", s.FileName(), s.Arch, ef.Machine())
	}
	hashes, err := expectedSHA256s()
	if err != nil {
		return nil, err
	}
	wantHash, ok := hashes[s.FileName()]
	if !ok {
		return nil, fmt.Errorf("samplecorpus: %s has no pinned sha256", s.FileName())
	}
	gotHash, err := ef.SHA256()
	if err != nil {
		return nil, fmt.Errorf("samplecorpus: sha256 %s: %w", s.FileName(), err)
	}
	if gotHash != wantHash {
		return nil, fmt.Errorf("samplecorpus: %s sha256 = %s, want %s; exact corpus binary drifted", s.FileName(), gotHash, wantHash)
	}
	info, err := snapshot.Extract(ef, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
	if err != nil {
		return nil, err
	}
	got := ""
	if info != nil && info.Version != nil {
		got = info.Version.DartVersion
	}
	if got != s.DartVersion {
		return nil, errors.New(VersionMismatch(s, got))
	}
	syms, err := ef.FuncSymbols()
	if err != nil {
		return nil, fmt.Errorf("samplecorpus: inspect .symtab for %s: %w", s.FileName(), err)
	}
	if s.SymbolOracle {
		if len(syms) == 0 {
			return nil, fmt.Errorf("samplecorpus: %s is registered as a symbol oracle but has no defined function symbols", s.FileName())
		}
	} else if len(syms) != 0 {
		return nil, fmt.Errorf("samplecorpus: %s is an analysis sample but carries %d defined .symtab function symbols; use the stripped_native_libs build", s.FileName(), len(syms))
	}
	return info, nil
}

// MissingMessage is what a test prints when the whole corpus is unavailable.
func MissingMessage(s Sample) string {
	return fmt.Sprintf("no samples/ corpus in this checkout; %s cannot be resolved "+
		"(Dart %s %s: %s)", s.FileName(), s.DartVersion, s.Arch, s.Note)
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
			"  Restore or relink the correct binary; a populated corpus must stay complete. (%s)",
		s.FileName(), got, s.DartVersion, s.DartVersion, s.Arch, s.Note)
}

// Versions(), Get(), compare() and triple() lived here and were called by
// nothing -- zero references in the whole repo, verified before removal.
// compare/triple were also a verbatim copy of snapshot's
// compareDartVersions/parseVersionTriple, minus the comment explaining why
// the comparison must be numeric ("2.9.0" sorts after "2.10.0" as a
// string). A second copy of a rule, with the reason for the rule dropped,
// is how the rule gets broken. Use snapshot.SupportedVersions or range
// Registry directly.
