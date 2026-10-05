package analysis

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"aotopsy/internal/disasm"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/output"
)

// ReFlutterDumpEntry represents one entry from reFlutter's dump.dart.
type ReFlutterDumpEntry struct {
	LibraryURL string
	ClassName  string
	ParentName string
	Functions  []ReFlutterFunction
	Fields     []ReFlutterField
}

// ReFlutterFunction is one function from reFlutter's dump.dart.
type ReFlutterFunction struct {
	Name   string
	Offset string
}

// ReFlutterField is one field from reFlutter's dump.dart.
type ReFlutterField struct {
	Type  string
	Name  string
	Value string
}

// ReFlutterImportOptions controls the reFlutter import merge.
type ReFlutterImportOptions struct {
	DumpPath  string // path to reFlutter's dump.dart
	StaticDir string // aotopsy static output directory
	LibPath   string // path to the original libapp.so
	OutDir    string // output directory (default: <static>_reflutter)
}

// ReFlutterImportResult holds the summary of the import.
type ReFlutterImportResult struct {
	Libraries     int
	Functions     int
	ClassesFields int
	EnrichedCount int
	OutputDir     string
}

// RunReFlutterImport parses reFlutter's dump.dart, loads the libapp.so context
// for offset→VA conversion, merges reFlutter names into aotopsy's functions.jsonl,
// and writes the result to outDir.
func RunReFlutterImport(opts ReFlutterImportOptions) (*ReFlutterImportResult, error) {
	if opts.DumpPath == "" || opts.StaticDir == "" {
		return nil, fmt.Errorf("--dump and --static are required")
	}
	if opts.LibPath == "" {
		return nil, fmt.Errorf("--lib is required (offset->VA conversion needs the original libapp.so's codeVA base; see LoadContext)")
	}
	if _, err := VerifyProvenanceBinary(opts.StaticDir, opts.LibPath); err != nil {
		return nil, fmt.Errorf("verify --lib against --static provenance: %w", err)
	}

	// codeVA is NOT persisted in any static output artifact — it's derived fresh
	// from the ELF/snapshot every run (see internal/analysis/context.go).
	ctx, err := LoadContext(opts.LibPath)
	if err != nil {
		return nil, fmt.Errorf("load context for --lib %s: %w", opts.LibPath, err)
	}
	defer func() { _ = ctx.Close() }()
	codeVA := ctx.CodeVA

	// Read dump.dart
	data, err := readFileBounded(opts.DumpPath, maxMetadataArtifactBytes)
	if err != nil {
		return nil, fmt.Errorf("read dump.dart: %v", err)
	}

	// Parse dump.dart
	entries := ParseReFlutterDump(string(data))

	// Determine output directory
	outDir := opts.OutDir
	if outDir == "" {
		outDir = opts.StaticDir + "_reflutter"
	}

	// Read static functions.jsonl. The strict reader needs a concrete record
	// type: a generic map has no derivable schema and is always rejected.
	funcsPath := filepath.Join(opts.StaticDir, "functions.jsonl")
	funcs, err := jsonutil.ReadJSONL[disasm.FuncRecord](funcsPath, jsonutil.StandardLimits)
	if err != nil {
		return nil, fmt.Errorf("read functions: %w", err)
	}
	merge := mergeReFlutterFunctions(funcs, codeVA, entries)
	offsetMap, fieldMap, libraryMap := merge.offsets, merge.fields, merge.libraries
	enrichedCount := merge.enriched

	// Write reFlutter data as separate JSON
	reflutterData := map[string]interface{}{
		"libraries":      libraryMap,
		"offsets":        offsetMap,
		"fields":         fieldMap,
		"entry_count":    len(entries),
		"function_count": len(offsetMap),
	}
	staticAbs, err := filepath.Abs(opts.StaticDir)
	if err != nil {
		return nil, fmt.Errorf("resolve static output: %w", err)
	}
	outAbs, err := filepath.Abs(outDir)
	if err != nil {
		return nil, fmt.Errorf("resolve merged output: %w", err)
	}
	for _, input := range []struct {
		label string
		path  string
	}{
		{"reFlutter dump", opts.DumpPath},
		{"source binary", opts.LibPath},
	} {
		insideOut, err := output.ContainsPath(outAbs, input.path)
		if err != nil {
			return nil, fmt.Errorf("compare merged output/%s paths: %w", input.label, err)
		}
		if insideOut {
			return nil, fmt.Errorf("merged output directory must not contain the %s", input.label)
		}
	}
	if staticAbs != outAbs {
		overlap, err := output.PathsOverlap(staticAbs, outAbs)
		if err != nil {
			return nil, fmt.Errorf("compare static/output paths: %w", err)
		}
		if overlap {
			return nil, fmt.Errorf("static and merged output directories must not contain one another")
		}
	}
	tx, err := output.BeginDirTransaction(outAbs)
	if err != nil {
		return nil, fmt.Errorf("begin reFlutter output transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Abort()
		}
	}()
	stage := tx.StageDir()
	if err := tx.CloneFrom(staticAbs); err != nil {
		return nil, fmt.Errorf("clone static generation: %w", err)
	}
	if err := output.WriteJSONFile(filepath.Join(stage, "reflutter_data.json"), reflutterData); err != nil {
		return nil, fmt.Errorf("write reFlutter data: %w", err)
	}
	if _, err := jsonutil.WriteJSONLFile(filepath.Join(stage, "functions.jsonl"), merge.funcs); err != nil {
		return nil, fmt.Errorf("write merged functions: %w", err)
	}

	// Write report
	report := "reFlutter Import Report\n"
	report += "=======================\n\n"
	report += fmt.Sprintf("Static output: %s\n", opts.StaticDir)
	report += fmt.Sprintf("reFlutter dump: %s\n", opts.DumpPath)
	report += fmt.Sprintf("Merged output: %s\n\n", outDir)
	report += fmt.Sprintf("Libraries parsed: %d\n", len(libraryMap))
	report += fmt.Sprintf("Functions parsed: %d\n", len(offsetMap))
	report += fmt.Sprintf("Classes with fields: %d\n", len(fieldMap))
	report += fmt.Sprintf("Functions enriched: %d\n", enrichedCount)

	reportPath := filepath.Join(stage, "reflutter_import_report.txt")
	if err := output.WriteFileAtomic(reportPath, []byte(report), 0o644); err != nil {
		return nil, fmt.Errorf("write reFlutter import report: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("publish reFlutter generation: %w", err)
	}
	committed = true

	return &ReFlutterImportResult{
		Libraries:     len(libraryMap),
		Functions:     len(offsetMap),
		ClassesFields: len(fieldMap),
		EnrichedCount: enrichedCount,
		OutputDir:     outDir,
	}, nil
}

// reFlutterOffsetEntry is one function from the dump with its owning class.
type reFlutterOffsetEntry struct {
	Name  string `json:"name"`
	Class string `json:"class"`
}

// reFlutterMerge is the result of joining a parsed dump with the static
// function table.
type reFlutterMerge struct {
	funcs     []disasm.FuncRecord
	offsets   map[string]reFlutterOffsetEntry
	fields    map[string][]ReFlutterField
	libraries map[string]string // class -> library URL
	enriched  int
}

// mergeReFlutterFunctions attaches reFlutter names to static functions.
//
// reFlutter's dump.dart offsets are relative to the isolate instructions
// region; a FuncRecord's PC is an absolute ELF VA, so offset = VA - codeVA
// converts between the two. The input slice is not modified.
func mergeReFlutterFunctions(funcs []disasm.FuncRecord, codeVA uint64, entries []ReFlutterDumpEntry) reFlutterMerge {
	m := reFlutterMerge{
		funcs:     make([]disasm.FuncRecord, 0, len(funcs)),
		offsets:   make(map[string]reFlutterOffsetEntry),
		fields:    make(map[string][]ReFlutterField),
		libraries: make(map[string]string),
	}
	for _, e := range entries {
		if e.LibraryURL != "" && e.ClassName != "" {
			m.libraries[e.ClassName] = e.LibraryURL
		}
		for _, fn := range e.Functions {
			if fn.Offset != "" {
				m.offsets[fn.Offset] = reFlutterOffsetEntry{Name: fn.Name, Class: e.ClassName}
			}
		}
		if e.ClassName != "" && len(e.Fields) > 0 {
			m.fields[e.ClassName] = e.Fields
		}
	}

	for _, f := range funcs {
		if va, err := strconv.ParseUint(strings.TrimPrefix(f.PC, "0x"), 16, 64); err == nil && va >= codeVA {
			key := fmt.Sprintf("0x%x", va-codeVA)
			if entry, found := m.offsets[key]; found {
				f.ReflutterName = entry.Name
				if entry.Class != "" {
					f.ReflutterClass = entry.Class
					if lib, ok := m.libraries[entry.Class]; ok {
						f.ReflutterLibrary = lib
					}
				}
				m.enriched++
			}
		}
		m.funcs = append(m.funcs, f)
	}
	return m
}

// ParseReFlutterDump parses reFlutter's dump.dart format.
func ParseReFlutterDump(content string) []ReFlutterDumpEntry {
	var entries []ReFlutterDumpEntry

	// Regex for Library + Class header
	libClassRe := regexp.MustCompile(`Library:'([^']*)'\s+Class:\s+(\S+)\s+extends\s+(\S+)\s+\{`)
	// Regex for function entries
	funcRe := regexp.MustCompile(`function\s+(\S+)\s+offset:\s*(0x[0-9a-fA-F]+);`)
	// Regex for field entries
	fieldRe := regexp.MustCompile(`(\S+)\*\s+(\S+)\s+=\s+(.*?);`)

	lines := strings.Split(content, "\n")
	var current *ReFlutterDumpEntry

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check for Library + Class header
		if m := libClassRe.FindStringSubmatch(line); m != nil {
			if current != nil {
				entries = append(entries, *current)
			}
			current = &ReFlutterDumpEntry{
				LibraryURL: m[1],
				ClassName:  m[2],
				ParentName: m[3],
			}
			continue
		}

		// Check for closing brace
		if line == "}" && current != nil {
			entries = append(entries, *current)
			current = nil
			continue
		}

		if current == nil {
			continue
		}

		// Check for function entry
		if m := funcRe.FindStringSubmatch(line); m != nil {
			current.Functions = append(current.Functions, ReFlutterFunction{
				Name:   m[1],
				Offset: m[2],
			})
			continue
		}

		// Check for field entry
		if m := fieldRe.FindStringSubmatch(line); m != nil {
			current.Fields = append(current.Fields, ReFlutterField{
				Type:  m[1],
				Name:  m[2],
				Value: strings.Trim(m[3], `"`),
			})
		}
	}

	if current != nil {
		entries = append(entries, *current)
	}

	return entries
}
