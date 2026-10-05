package strutil

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"aotopsy/internal/jsonutil"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/vmtables"
)

// FlutterMetaFunc is a function entry in flutter_meta.json.
type FlutterMetaFunc struct {
	Addr       string `json:"addr"`
	Name       string `json:"name"`
	Size       int    `json:"size"`
	Owner      string `json:"owner,omitempty"`
	ParamCount int    `json:"param_count,omitempty"`
}

// FlutterMetaTHRField is a THR (thread) struct field.
type FlutterMetaTHRField struct {
	Offset int    `json:"offset"`
	Name   string `json:"name"`
}

// DartMetaJSON is the exact intermediate metadata contract written by the
// analysis pipeline and consumed by RunMetaStage. Keep this separate from
// FlutterMetaJSON: the intermediate file has no optional presentation fields,
// and strict readers must reject schema drift rather than silently accepting a
// zero value from the larger final schema.
type DartMetaJSON struct {
	Architecture       string                `json:"arch"`
	DartVersion        string                `json:"dart_version"`
	CompressedPointers bool                  `json:"compressed_pointers"`
	PointerSize        int                   `json:"pointer_size"`
	THRFields          []FlutterMetaTHRField `json:"thr_fields"`
}

// FlutterMetaJSON is the top-level flutter_meta.json structure.
type FlutterMetaJSON struct {
	Version            string                 `json:"version"`
	Architecture       string                 `json:"arch"`
	DartVersion        string                 `json:"dart_version"`
	BinarySHA256       string                 `json:"binary_sha256"`
	BinarySize         int64                  `json:"binary_size"`
	CompressedPointers bool                   `json:"compressed_pointers"`
	PointerSize        int                    `json:"pointer_size"`
	Functions          []FlutterMetaFunc      `json:"functions,omitempty"`
	Comments           []FlutterMetaComment   `json:"comments,omitempty"`
	FocusFunctions     []string               `json:"focus_functions,omitempty"`
	Classes            []FlutterMetaJSONClass `json:"classes,omitempty"`
	THRFields          []FlutterMetaTHRField  `json:"thr_fields"`
}

// FlutterMetaComment is a comment entry for flutter_meta.json.
type FlutterMetaComment struct {
	Addr string `json:"addr"`
	Text string `json:"text"`
}

// FlutterMetaJSONClass is a class layout entry in flutter_meta.json.
// Aliased from pipeline.DartClassLayout to avoid pipeline import.
type FlutterMetaJSONClass struct {
	ClassName    string             `json:"class_name"`
	ClassID      int32              `json:"class_id"`
	InstanceSize int32              `json:"instance_size"`
	Fields       []FlutterMetaField `json:"fields"`
}

// FlutterMetaField is one field in a FlutterMetaJSONClass.
type FlutterMetaField struct {
	Name        string `json:"name"`
	ByteOffset  int32  `json:"byte_offset"`
	IsReference bool   `json:"is_reference"`
	SlotType    string `json:"slot_type"`
}

// WriteDartMeta writes dart_meta.json from one exact VM target profile. Callers
// do not pass version/compression/pointer-size/THR facts independently: those
// dimensions select each other, and accepting an arbitrary tuple made it
// possible to serialize plausible-but-wrong Thread metadata.
func WriteDartMeta(outDir string, target vmtables.TargetProfile) error {
	meta, err := DartMetaForTarget(target)
	if err != nil {
		return err
	}
	return jsonutil.WriteJSONFile(filepath.Join(outDir, "dart_meta.json"), meta)
}

// DartMetaForTarget derives the intermediate schema from the same exact target
// profile used to select VM offset tables. THRFields is re-derived here instead
// of accepted from the caller so a stale/different table cannot be paired with
// a valid-looking Dart version.
func DartMetaForTarget(target vmtables.TargetProfile) (DartMetaJSON, error) {
	arch, err := validateMetadataTarget(target)
	if err != nil {
		return DartMetaJSON{}, err
	}
	pointerSize := 8
	if target.CompressedPointers {
		// SDK @3.13.0 runtime/vm/globals.h: DART_COMPRESSED_POINTERS makes
		// kCompressedWordSize == kInt32Size. Without it the compressed word is
		// kWordSize; both supported target architectures are 64-bit.
		pointerSize = 4
	}
	return DartMetaJSON{
		Architecture:       arch,
		DartVersion:        target.DartVersion,
		CompressedPointers: target.CompressedPointers,
		PointerSize:        pointerSize,
		THRFields:          sortedTHRFields(vmtables.THRFields(target)),
	}, nil
}

// ValidateDartMeta validates a decoded intermediate artifact against exact
// supported snapshot/VM-table facts and returns the canonical target profile it
// represents. This is a trust boundary: reused/tampered artifacts must not be
// allowed to invent pointer widths or THR offsets that still look reasonable to
// Ghidra/IDA.
func ValidateDartMeta(meta DartMetaJSON) (vmtables.TargetProfile, error) {
	arch, ok := parseMetadataArchitecture(meta.Architecture)
	if !ok {
		return vmtables.TargetProfile{}, fmt.Errorf("dart metadata: unsupported architecture %q", meta.Architecture)
	}
	target := vmtables.TargetProfile{
		DartVersion:        meta.DartVersion,
		Architecture:       arch,
		CompressedPointers: meta.CompressedPointers,
		BuildMode:          snapshot.BuildProduct,
	}
	if _, err := validateMetadataTarget(target); err != nil {
		return vmtables.TargetProfile{}, err
	}
	wantPointerSize := 8
	if target.CompressedPointers {
		wantPointerSize = 4
	}
	if meta.PointerSize != wantPointerSize {
		return vmtables.TargetProfile{}, fmt.Errorf("dart metadata: pointer_size %d disagrees with compressed_pointers=%v (want %d)",
			meta.PointerSize, target.CompressedPointers, wantPointerSize)
	}
	wantFields := sortedTHRFields(vmtables.THRFields(target))
	if len(meta.THRFields) != len(wantFields) {
		return vmtables.TargetProfile{}, fmt.Errorf("dart metadata: THR field count %d disagrees with exact table count %d for %s/%s/compressed=%v",
			len(meta.THRFields), len(wantFields), target.DartVersion, meta.Architecture, target.CompressedPointers)
	}
	for i := range wantFields {
		if meta.THRFields[i] != wantFields[i] {
			return vmtables.TargetProfile{}, fmt.Errorf("dart metadata: THR field %d is %+v, want exact %+v", i, meta.THRFields[i], wantFields[i])
		}
	}
	return target, nil
}

func validateMetadataTarget(target vmtables.TargetProfile) (string, error) {
	arch, ok := metadataArchitectureName(target.Architecture)
	if !ok {
		return "", fmt.Errorf("dart metadata: unsupported architecture %d", target.Architecture)
	}
	if target.BuildMode != snapshot.BuildProduct {
		return "", fmt.Errorf("dart metadata: PRODUCT build profile required, got %d", target.BuildMode)
	}
	p := snapshot.ProfileForVersion(target.DartVersion)
	if p == nil || !p.Supported {
		return "", fmt.Errorf("dart metadata: no exact supported snapshot profile for Dart %q", target.DartVersion)
	}
	if p.CompressionFeatures == snapshot.CompressionFeatureFixedUncompressed && target.CompressedPointers {
		return "", fmt.Errorf("dart metadata: Dart %s cannot use compressed pointers", target.DartVersion)
	}
	p.BuildMode = target.BuildMode
	p.CompressedPointers = target.CompressedPointers
	if !snapshot.IsExactSupportedProfile(p) {
		return "", fmt.Errorf("dart metadata: target profile for Dart %s does not match the exact supported profile", target.DartVersion)
	}
	return arch, nil
}

func metadataArchitectureName(arch vmtables.Architecture) (string, bool) {
	switch arch {
	case vmtables.ArchitectureARM64:
		return "arm64", true
	case vmtables.ArchitectureX64:
		return "x64", true
	default:
		return "", false
	}
}

func parseMetadataArchitecture(arch string) (vmtables.Architecture, bool) {
	switch arch {
	case "arm64":
		return vmtables.ArchitectureARM64, true
	case "x64":
		return vmtables.ArchitectureX64, true
	default:
		return vmtables.ArchitectureUnknown, false
	}
}

func sortedTHRFields(fields map[int]string) []FlutterMetaTHRField {
	out := make([]FlutterMetaTHRField, 0, len(fields))
	for off, name := range fields {
		out = append(out, FlutterMetaTHRField{Offset: off, Name: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	return out
}

// NormalizeHexAddr strips leading zeros: "0x000652e4" → "0x652e4". Malformed
// addresses fail explicitly; returning the input unchanged used to let corrupt
// metadata continue as if it had been normalized.
func NormalizeHexAddr(s string) (string, error) {
	v, err := ParseHexAddr(s)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("0x%x", v), nil
}

// ParseHexAddr parses a 0x-prefixed hexadecimal address. Zero is a legitimate
// address, so parse failure is never represented by the numeric zero value.
func ParseHexAddr(s string) (uint64, error) {
	if len(s) < 3 || !(strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X")) {
		return 0, fmt.Errorf("invalid hex address %q", s)
	}
	v, err := strconv.ParseUint(s[2:], 16, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid hex address %q: %w", s, err)
	}
	return v, nil
}

// AsmCommentRe matches the first producer-owned "  ; " separator. Comments may
// themselves contain "; " (paired THR annotations and string literals), so the
// instruction portion must not greedily consume later semicolons.
var AsmCommentRe = regexp.MustCompile(`^(0x[0-9a-fA-F]+)\s+.*?  ;\s+(.+)$`)

// ExtractAsmComments parses all .txt files below asmDir for instruction-level
// annotations. Disassembly artifacts are grouped under owner directories, so a
// top-level-only scan would silently omit almost every named method.
func ExtractAsmComments(asmDir string) ([]FlutterMetaComment, error) {
	var comments []FlutterMetaComment
	seen := make(map[string]bool)
	err := filepath.WalkDir(asmDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			return nil
		}
		fc, err := extractFileComments(path, seen)
		if err != nil {
			return fmt.Errorf("extract comments from %s: %w", path, err)
		}
		comments = append(comments, fc...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return comments, nil
}

func extractFileComments(path string, seen map[string]bool) ([]FlutterMetaComment, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var comments []FlutterMetaComment
	scanner := bufio.NewScanner(f)
	// Disassembly lines are normally tiny; allow unusually long annotated
	// strings without inheriting Scanner's opaque 64 KiB failure, but still cap
	// attacker-controlled reused artifacts so one line cannot allocate without
	// bound.
	const maxAsmLineBytes = 1 << 20
	scanner.Buffer(make([]byte, 64<<10), maxAsmLineBytes)
	for scanner.Scan() {
		line := scanner.Text()
		m := AsmCommentRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		addr, err := NormalizeHexAddr(m[1])
		if err != nil {
			return nil, fmt.Errorf("normalize asm address %q: %w", m[1], err)
		}
		text := strings.TrimSpace(m[2])

		if strings.HasPrefix(text, "<") && strings.HasSuffix(text, ">") {
			continue
		}

		if seen[addr] {
			continue
		}
		seen[addr] = true

		comments = append(comments, FlutterMetaComment{
			Addr: addr,
			Text: text,
		})
	}

	return comments, scanner.Err()
}

// FileSize returns the size of the file at path, or 0 if stat fails.
func FileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// DisasmIndexEntry is the per-function index record written to index.jsonl.
type DisasmIndexEntry struct {
	Name      string `json:"name"`
	OwnerName string `json:"owner_name,omitempty"`
	RefID     int    `json:"ref_id"`
	OwnerRef  int    `json:"owner_ref,omitempty"`
	PCOffset  uint32 `json:"pc_offset"`
	Size      uint32 `json:"size"`
	File      string `json:"file"`
}
