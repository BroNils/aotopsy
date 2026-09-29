package analysis

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aotopsy/internal/elfx"
	"aotopsy/internal/output"
)

// ProvenanceFileName is the artifact recording which binary an output
// directory was produced from.
const ProvenanceFileName = "provenance.json"

// Provenance ties an output directory to the binary it came from.
//
// Nothing recorded this. The signal stage read a "meta.json" from the
// PARENT of the output directory for exactly this information -- one
// reader, zero writers, so the lookup always failed and the HTML report
// fell back to naming the output directory after itself. The SARIF report
// hardcoded "libapp.so", which every Flutter app ships.
//
// Without it, `aotopsy signal --in <dir>` and `--from-dir` cannot say
// which binary they are describing, and neither can anyone reading the
// output later.
type Provenance struct {
	Source             string    `json:"source"`
	SourceName         string    `json:"source_name"`
	SHA256             string    `json:"sha256"`
	Size               int64     `json:"size"`
	Arch               string    `json:"arch"`
	DartVersion        string    `json:"dart_version,omitempty"`
	CompressedPointers bool      `json:"compressed_pointers"`
	Build              BuildMode `json:"build"`
}

// BuildMode records how gen_snapshot was invoked, inferred from the snapshot
// itself rather than from anything the binary declares.
//
// It exists because two of AOTopsy's outputs go empty for a reason that is a
// property of the input, and an empty artifact reads exactly like a parse
// failure. `--split-debug-info` / `--obfuscate` turn on
// FLAG_dwarf_stack_traces_mode, and then:
//
//   - app_snapshot.cc:2911 writes code_source_map_ and inlined_id_to_function_
//     as null, so inline attribution has nothing to attribute; and
//   - with !FLAG_retain_code_objects, Code objects are discarded wholesale, so
//     most InstructionsTable entries have no Code and names must come from
//     Function.code_index instead.
//
// Measured on the corpus: the one obfuscated production sample has 0
// CodeSourceMaps and 91012 of 128999 entries discarded; the other four have
// thousands of CodeSourceMaps and zero discarded.
type BuildMode struct {
	// DwarfStackTraces is true when the snapshot shows the marks of
	// FLAG_dwarf_stack_traces_mode.
	DwarfStackTraces bool `json:"dwarf_stack_traces"`
	// DiscardedCodes is InstructionsTable.FirstEntryWithCode: entries with no
	// Code object. Non-zero PROVES dwarf mode (app_snapshot.cc:2624 asserts
	// it).
	DiscardedCodes int `json:"discarded_codes"`
	// CodeSourceMaps is how many were recovered. Zero alongside a non-empty
	// code population is the other mark of dwarf mode.
	CodeSourceMaps int `json:"code_source_maps"`
}

// DetectBuildMode infers the build mode from what the snapshot contains.
//
// Discarded entries are proof: the serializer asserts
// `kFullAOT && FLAG_dwarf_stack_traces_mode && !FLAG_retain_code_objects`
// before discarding. Zero CodeSourceMaps against a non-empty code population
// is the weaker signal -- it is what dwarf mode does, and there is no other
// way to get code without source maps -- so it is accepted too, and the two
// raw counts are recorded either way so a reader can judge.
func DetectBuildMode(csmCount, discarded, codeRanges int) BuildMode {
	b := BuildMode{DiscardedCodes: discarded, CodeSourceMaps: csmCount}
	b.DwarfStackTraces = discarded > 0 || (csmCount == 0 && codeRanges > 0)
	return b
}

// WriteProvenance captures identity from the same opened file descriptor and
// atomically records it. Returning the immutable value lets later report stages
// identify the analysed bytes without reopening a mutable input path.
func WriteProvenance(outDir, libPath string, source *elfx.File, dartVersion string, isARM64, compressedPtrs bool, build BuildMode) (Provenance, error) {
	if source == nil {
		return Provenance{}, fmt.Errorf("nil provenance source")
	}
	absSource, err := filepath.Abs(libPath)
	if err != nil {
		return Provenance{}, fmt.Errorf("resolve provenance source: %w", err)
	}
	p := Provenance{
		Source:             absSource,
		SourceName:         filepath.Base(libPath),
		Arch:               "x64",
		DartVersion:        dartVersion,
		CompressedPointers: compressedPtrs,
		Build:              build,
	}
	if isARM64 {
		p.Arch = "arm64"
	}
	p.Size = source.FileSize()
	sha, err := source.SHA256()
	if err != nil {
		return Provenance{}, fmt.Errorf("hash provenance source: %w", err)
	}
	p.SHA256 = sha
	if err := output.WriteJSONFile(filepath.Join(outDir, ProvenanceFileName), p); err != nil {
		return Provenance{}, err
	}
	return p, nil
}

// ReadProvenance loads the provenance record from an output directory.
// Missing provenance is a supported legacy state (ok=false); malformed or
// oversized provenance is an error because --from is a trust boundary and an
// anonymous fallback would silently detach reports from their binary identity.
func ReadProvenance(dir string) (p Provenance, ok bool, err error) {
	p, err = readJSONBounded[Provenance](filepath.Join(dir, ProvenanceFileName), maxMetadataArtifactBytes)
	if errors.Is(err, os.ErrNotExist) {
		return Provenance{}, false, nil
	}
	if err != nil {
		return Provenance{}, false, err
	}
	if p.SourceName == "" {
		return Provenance{}, false, fmt.Errorf("%s: missing source_name", ProvenanceFileName)
	}
	return p, true, nil
}

// VerifyProvenanceBinary binds an existing analysis directory to the exact ELF
// bytes a downstream importer/decompiler is about to use. Reusing semantic
// artifacts with a same-architecture but different libapp silently applies
// stale addresses and names, so --from/static consumers must fail closed.
func VerifyProvenanceBinary(dir, libPath string) (Provenance, error) {
	p, ok, err := ReadProvenance(dir)
	if err != nil {
		return Provenance{}, fmt.Errorf("read provenance: %w", err)
	}
	if !ok || len(p.SHA256) != 64 || p.Size <= 0 || p.DartVersion == "" ||
		(p.Arch != "arm64" && p.Arch != "x64") {
		return Provenance{}, fmt.Errorf("analysis directory lacks complete binary provenance")
	}
	ef, err := elfx.Open(libPath)
	if err != nil {
		return Provenance{}, fmt.Errorf("open binary for provenance verification: %w", err)
	}
	defer func() { _ = ef.Close() }()
	arch := "x64"
	if ef.IsARM64() {
		arch = "arm64"
	}
	sha, err := ef.SHA256()
	if err != nil {
		return Provenance{}, fmt.Errorf("hash binary for provenance verification: %w", err)
	}
	if !strings.EqualFold(sha, p.SHA256) || ef.FileSize() != p.Size || arch != p.Arch {
		return Provenance{}, fmt.Errorf("binary does not match analysis provenance (sha256/size/arch mismatch)")
	}
	return p, nil
}
