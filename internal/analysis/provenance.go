package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// ProvenanceFileName is the artifact recording which binary an output
// directory was produced from.
const ProvenanceFileName = "snapshot.json"

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

// WriteProvenance records the analysed binary in outDir.
func WriteProvenance(outDir, libPath, dartVersion string, isARM64, compressedPtrs bool, build BuildMode) error {
	p := Provenance{
		Source:             libPath,
		SourceName:         filepath.Base(libPath),
		Arch:               "x64",
		DartVersion:        dartVersion,
		CompressedPointers: compressedPtrs,
		Build:              build,
	}
	if isARM64 {
		p.Arch = "arm64"
	}
	if fi, err := os.Stat(libPath); err == nil {
		p.Size = fi.Size()
	}
	if f, err := os.Open(libPath); err == nil {
		h := sha256.New()
		if _, err := io.Copy(h, f); err == nil {
			p.SHA256 = hex.EncodeToString(h.Sum(nil))
		}
		_ = f.Close()
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, ProvenanceFileName), append(data, '\n'), 0o644)
}

// ReadProvenance loads the provenance record from an output directory,
// reporting ok=false when there is none -- which is the honest answer for
// a directory produced before this existed, or by a path that never had
// the binary to record.
func ReadProvenance(dir string) (Provenance, bool) {
	data, err := os.ReadFile(filepath.Join(dir, ProvenanceFileName))
	if err != nil {
		return Provenance{}, false
	}
	var p Provenance
	if err := json.Unmarshal(data, &p); err != nil {
		return Provenance{}, false
	}
	return p, p.SourceName != ""
}
