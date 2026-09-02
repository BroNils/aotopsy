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

	// GroundTruth marks an UNSTRIPPED twin: the same program as the analysis
	// sample for this version, built with
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
	// without symbols is the whole point. So these twins are excluded from the
	// corpus cluster-fact records and from the cross-version differential:
	// they would duplicate facts their stripped counterparts already pin, and
	// double the differential's runtime for nothing.
	//
	// Their honesty was measured, not assumed. LoadContext -- the path the
	// symtab gate reads names from -- never consults .symtab; only
	// pipeline.Run does, via elfStubName, and only as a last resort for Codes
	// the snapshot could not name at all. Proven on 3.9.2 arm64 by loading a
	// stripped binary and its unstripped twin and diffing the recovered names:
	// 8220 names, ZERO differences. The gate is not validating itself.
	GroundTruth bool
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
	{DartVersion: "3.12.2", Arch: "arm64", Note: "sample_312"},
	{DartVersion: "3.12.2", Arch: "x64", Note: "sample_312 x86_64"},
	// sample_313's lib/ IS byte-identical to compare_sample's, so unlike
	// sample_310/311 this pair can carry its weight in the differential.
	{DartVersion: "3.13.0", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.13.0, Flutter 3.47.0"},
	{DartVersion: "3.13.0", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.13.0 x86_64"},

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
	{DartVersion: "3.12.2", Arch: "arm64", SourceSet: comparesample, Note: "sample_dart_3.12.0, Flutter 3.44.0 -- Dart 3.12.0 stable, 3.12.2 format", FileSuffix: "-f3440"},
	{DartVersion: "3.12.2", Arch: "x64", SourceSet: comparesample, Note: "sample_dart_3.12.0 x86_64, Flutter 3.44.0", FileSuffix: "-f3440"},

	// Unstripped ground-truth twins -- see Sample.GroundTruth. Built from the
	// SAME project as the version's analysis sample, so the source is
	// identical (including the downlevelled sources of the pre-2.14 and
	// pre-null-safety sets), with
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
	{DartVersion: "2.13.0", Arch: "arm64", Note: "sample_prenn_2.13.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "2.13.0", Arch: "x64", Note: "sample_prenn_2.13.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "2.14.0", Arch: "arm64", Note: "sample_dart_2.14.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "2.14.0", Arch: "x64", Note: "sample_dart_2.14.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "2.15.0", Arch: "arm64", Note: "sample_dart_2.15.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "2.15.0", Arch: "x64", Note: "sample_dart_2.15.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "2.16.0", Arch: "arm64", Note: "sample_dart_2.16.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "2.16.0", Arch: "x64", Note: "sample_dart_2.16.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "2.17.6", Arch: "arm64", Note: "sample_dart_2.17.6 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "2.17.6", Arch: "x64", Note: "sample_dart_2.17.6 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "2.18.0", Arch: "arm64", Note: "sample_dart_2.18.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "2.18.0", Arch: "x64", Note: "sample_dart_2.18.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "2.19.0", Arch: "arm64", Note: "sample_dart_2.19.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "2.19.0", Arch: "x64", Note: "sample_dart_2.19.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.0.5", Arch: "arm64", Note: "sample_dart_3.0.5 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.0.5", Arch: "x64", Note: "sample_dart_3.0.5 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.1.0", Arch: "arm64", Note: "sample_dart_3.1.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.1.0", Arch: "x64", Note: "sample_dart_3.1.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.2.5", Arch: "arm64", Note: "sample_dart_3.2.5 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.2.5", Arch: "x64", Note: "sample_dart_3.2.5 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.3.0", Arch: "arm64", Note: "sample_dart_3.3.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.3.0", Arch: "x64", Note: "sample_dart_3.3.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.4.3", Arch: "arm64", Note: "sample_dart_3.4.3 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.4.3", Arch: "x64", Note: "sample_dart_3.4.3 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.5.0", Arch: "arm64", Note: "sample_dart_3.5.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.5.0", Arch: "x64", Note: "sample_dart_3.5.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.6.2", Arch: "arm64", Note: "sample_dart_3.6.2 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.6.2", Arch: "x64", Note: "sample_dart_3.6.2 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.7.0", Arch: "arm64", Note: "sample_dart_3.7.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.7.0", Arch: "x64", Note: "sample_dart_3.7.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.8.1", Arch: "arm64", Note: "sample_dart_3.8.1 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.8.1", Arch: "x64", Note: "sample_dart_3.8.1 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.9.2", Arch: "arm64", Note: "sample_dart_3.9.2 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.9.2", Arch: "x64", Note: "sample_dart_3.9.2 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.10.7", Arch: "arm64", Note: "sample_dart_3.10.7 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.10.7", Arch: "x64", Note: "sample_dart_3.10.7 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.11.0", Arch: "arm64", Note: "sample_dart_3.11.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
	{DartVersion: "3.11.0", Arch: "x64", Note: "sample_dart_3.11.0 --no-strip", FileSuffix: "-gt", GroundTruth: true},
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

// Versions(), Get(), compare() and triple() lived here and were called by
// nothing -- zero references in the whole repo, verified before removal.
// compare/triple were also a verbatim copy of snapshot's
// compareDartVersions/parseVersionTriple, minus the comment explaining why
// the comparison must be numeric ("2.9.0" sorts after "2.10.0" as a
// string). A second copy of a rule, with the reason for the rule dropped,
// is how the rule gets broken. Use snapshot.SupportedVersions or range
// Registry directly.
