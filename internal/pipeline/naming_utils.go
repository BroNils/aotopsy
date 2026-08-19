package pipeline

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"aotopsy/internal/cli"
	"aotopsy/internal/strutil"
)

func (ci CodeNameInfo) Qualified(pcOffset uint32) string {
	if ci.IsConstructor {
		return QualifiedName("", ci.FuncName, pcOffset)
	}
	return QualifiedName(ci.OwnerName, ci.FuncName, pcOffset)
}

// QualifiedName builds "Owner.FuncName_hexaddr" like blutter.
func QualifiedName(ownerName, funcName string, pcOffset uint32) string {
	suffix := fmt.Sprintf("_%x", pcOffset)
	if funcName == "" {
		return "sub" + suffix
	}
	if ownerName != "" {
		return ownerName + "." + funcName + suffix
	}
	return funcName + suffix
}

// SanitizeFilename makes a string safe for use as a filename.
// Strips non-printable runes and replaces filesystem-unsafe characters.
// SanitizeFilename delegates to the shared strutil.SanitizeFilename.
// Kept for backward compatibility — all callers should eventually use
// strutil.SanitizeFilename directly. (P4-5)
func SanitizeFilename(name string) string {
	return strutil.SanitizeFilename(name)
}

// FuncRelPath returns a relative path like "OwnerClass/funcName_hex" for functions
// with an owner, or "funcName_hex" for ownerless functions.
func FuncRelPath(ownerName, funcName string, pcOffset uint32) string {
	suffix := fmt.Sprintf("_%x", pcOffset)
	var fpart string
	if funcName == "" {
		fpart = "sub" + suffix
	} else {
		fpart = SanitizeFilename(funcName + suffix)
	}
	if ownerName != "" {
		return SanitizeFilename(ownerName) + "/" + fpart
	}
	return fpart
}

// FuncRelPathFromQualified reconstructs the relative path from a qualified name
// and its owner. Used by post-disasm commands (signal, decompile).
func FuncRelPathFromQualified(qualifiedName, owner string) string {
	if owner != "" {
		prefix := owner + "."
		funcPart := qualifiedName
		if strings.HasPrefix(qualifiedName, prefix) {
			funcPart = qualifiedName[len(prefix):]
		}
		return SanitizeFilename(owner) + "/" + SanitizeFilename(funcPart)
	}
	return SanitizeFilename(qualifiedName)
}

// ReadJSONL reads a JSONL file into a slice of T.
func ReadJSONL[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var records []T
	dec := json.NewDecoder(f)
	for dec.More() {
		var rec T
		if err := dec.Decode(&rec); err != nil {
			return records, fmt.Errorf("line %d: %w", len(records)+1, err)
		}
		records = append(records, rec)
	}

	return records, nil
}

// WriteJSONLFile writes a slice of records as JSONL to path. Each record
// is encoded on its own line. Returns the number of records written.
// This is the generic replacement for the 10-case countRecords/encodeAll
// type switch pair that used to live in pipeline.go.
func WriteJSONLFile[T any](path string, records []T) (int, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for i := range records {
		if err := enc.Encode(&records[i]); err != nil {
			return i, fmt.Errorf("encode %s record %d: %w", path, i, err)
		}
	}
	return len(records), nil
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

// DartMetaJSON is the structure written to dart_meta.json.
type DartMetaJSON struct {
	DartVersion        string             `json:"dart_version"`
	CompressedPointers bool               `json:"compressed_pointers"`
	PointerSize        int                `json:"pointer_size"`
	THRFields          []DartMetaTHRField `json:"thr_fields"`
}

// DartMetaTHRField is a THR field entry for dart_meta.json.
type DartMetaTHRField struct {
	Offset int    `json:"offset"`
	Name   string `json:"name"`
}

// WriteDartMeta writes dart_meta.json with snapshot metadata.
func WriteDartMeta(outDir, dartVersion string, compressed bool, ptrSize int, thrFields map[int]string) error {
	fields := make([]DartMetaTHRField, 0, len(thrFields))
	for off, name := range thrFields {
		fields = append(fields, DartMetaTHRField{Offset: off, Name: name})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Offset < fields[j].Offset })

	meta := DartMetaJSON{
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

// fileSize returns the size of the file at path, or 0 if stat fails.
func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// makeLogf returns a closure that writes to log only when !quiet.
// Shared by RunMetaStage and RunSignalStage to avoid duplicating the
// same quiet/log helper pattern in both files.
func makeLogf(quiet bool, log io.Writer) func(string, ...interface{}) {
	return func(format string, args ...interface{}) {
		if !quiet {
			_, _ = fmt.Fprintf(log, format, args...)
		}
	}
}

// makeStagef returns a closure that writes a stage header to log only
// when !quiet. Shared by RunMetaStage and RunSignalStage.
func makeStagef(quiet bool, log io.Writer) func(string, string, ...interface{}) {
	return func(name string, format string, args ...interface{}) {
		if !quiet {
			detail := fmt.Sprintf(format, args...)
			_, _ = fmt.Fprintf(log, "\n%s%s%s %s\n", cli.Pink, name, cli.Reset, detail)
		}
	}
}

// IsInterestingCallee returns true if the callee name represents a real named
// function rather than VM internals, stubs, or dispatch noise.
func IsInterestingCallee(name string) bool {
	if name == "" {
		return false
	}
	switch {
	case len(name) > 4 && name[:4] == "sub_":
		return false
	case len(name) > 2 && name[0] == '0' && name[1] == 'x':
		return false
	case name == "dispatch_table" || name == "object_field":
		return false
	case len(name) > 4 && name[:4] == "THR.":
		return false
	case len(name) > 3 && name[:3] == "PP[":
		return false
	}
	return true
}

// FlutterMetaComment is a comment entry for flutter_meta.json.
type FlutterMetaComment struct {
	Addr string `json:"addr"`
	Text string `json:"text"`
}
