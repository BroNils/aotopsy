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

// FlutterMetaJSON is the top-level flutter_meta.json structure.
type FlutterMetaJSON struct {
	Version            string                 `json:"version,omitempty"`
	Architecture       string                 `json:"arch,omitempty"`
	DartVersion        string                 `json:"dart_version,omitempty"`
	CompressedPointers bool                   `json:"compressed_pointers"`
	PointerSize        int                    `json:"pointer_size,omitempty"`
	Functions          []FlutterMetaFunc      `json:"functions,omitempty"`
	Comments           []FlutterMetaComment   `json:"comments,omitempty"`
	FocusFunctions     []string               `json:"focus_functions,omitempty"`
	Classes            []FlutterMetaJSONClass `json:"classes,omitempty"`
	THRFields          []FlutterMetaTHRField  `json:"thr_fields,omitempty"`
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

// WriteDartMeta writes dart_meta.json with snapshot metadata.
func WriteDartMeta(outDir, dartVersion, arch string, compressed bool, ptrSize int, thrFields map[int]string) error {
	fields := make([]FlutterMetaTHRField, 0, len(thrFields))
	for off, name := range thrFields {
		fields = append(fields, FlutterMetaTHRField{Offset: off, Name: name})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Offset < fields[j].Offset })

	meta := FlutterMetaJSON{
		Architecture:       arch,
		DartVersion:        dartVersion,
		CompressedPointers: compressed,
		PointerSize:        ptrSize,
		THRFields:          fields,
	}

	return jsonutil.WriteJSONFile(filepath.Join(outDir, "dart_meta.json"), meta)
}

// NormalizeHexAddr strips leading zeros: "0x000652e4" → "0x652e4".
func NormalizeHexAddr(s string) string {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return s
	}
	v, err := strconv.ParseUint(s[2:], 16, 64)
	if err != nil {
		return s
	}
	return fmt.Sprintf("0x%x", v)
}

// ParseHexAddr parses "0x..." hex address strings. Returns 0 on failure.
func ParseHexAddr(s string) uint64 {
	s = strings.TrimPrefix(s, "0x")
	v, _ := strconv.ParseUint(s, 16, 64)
	return v
}

// AsmCommentRe matches annotated asm lines: address + instruction + "; comment"
var AsmCommentRe = regexp.MustCompile(`^(0x[0-9a-fA-F]+)\s+.*;\s+(.+)$`)

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
		addr := NormalizeHexAddr(m[1])
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
