package strutil

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
	Name       string `json:"name"`
	ByteOffset int32  `json:"byte_offset"`
}

// WriteDartMeta writes dart_meta.json with snapshot metadata.
func WriteDartMeta(outDir, dartVersion string, compressed bool, ptrSize int, thrFields map[int]string) error {
	fields := make([]FlutterMetaTHRField, 0, len(thrFields))
	for off, name := range thrFields {
		fields = append(fields, FlutterMetaTHRField{Offset: off, Name: name})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Offset < fields[j].Offset })

	meta := FlutterMetaJSON{
		DartVersion:        dartVersion,
		CompressedPointers: compressed,
		PointerSize:        ptrSize,
		THRFields:          fields,
	}

	f, err := os.Create(filepath.Join(outDir, "dart_meta.json"))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(meta); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
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

// ExtractAsmComments parses all .txt files in asmDir for instruction-level annotations.
func ExtractAsmComments(asmDir string) ([]FlutterMetaComment, error) {
	entries, err := os.ReadDir(asmDir)
	if err != nil {
		return nil, err
	}

	var comments []FlutterMetaComment
	seen := make(map[string]bool)

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		path := filepath.Join(asmDir, entry.Name())
		fc, err := extractFileComments(path, seen)
		if err != nil {
			continue
		}
		comments = append(comments, fc...)
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
