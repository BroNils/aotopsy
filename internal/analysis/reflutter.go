package analysis

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"aotopsy/internal/frida"
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

	// codeVA is NOT persisted in any static output artifact — it's derived fresh
	// from the ELF/snapshot every run (see internal/analysis/context.go).
	ctx, err := LoadContext(opts.LibPath)
	if err != nil {
		return nil, fmt.Errorf("load context for --lib %s: %w", opts.LibPath, err)
	}
	defer func() { _ = ctx.Close() }()
	codeVA := ctx.CodeVA

	// Read dump.dart
	data, err := os.ReadFile(opts.DumpPath)
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
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir output: %v", err)
	}

	// Build offset → {name, owning class} map from reFlutter dump.
	type offsetEntry struct {
		Name  string `json:"name"`
		Class string `json:"class"`
	}
	offsetMap := make(map[string]offsetEntry)
	fieldMap := make(map[string][]ReFlutterField)
	libraryMap := make(map[string]string) // class → library URL

	for _, e := range entries {
		if e.LibraryURL != "" && e.ClassName != "" {
			libraryMap[e.ClassName] = e.LibraryURL
		}
		for _, fn := range e.Functions {
			if fn.Offset != "" {
				offsetMap[fn.Offset] = offsetEntry{Name: fn.Name, Class: e.ClassName}
			}
		}
		if e.ClassName != "" && len(e.Fields) > 0 {
			fieldMap[e.ClassName] = e.Fields
		}
	}

	// Read static functions.jsonl and merge
	funcsPath := filepath.Join(opts.StaticDir, "functions.jsonl")
	funcsData, err := os.ReadFile(funcsPath)
	if err != nil {
		return nil, fmt.Errorf("read functions: %v", err)
	}

	var mergedFuncs []string
	enrichedCount := 0
	for _, line := range strings.Split(string(funcsData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var f map[string]interface{}
		if json.Unmarshal([]byte(line), &f) == nil {
			if pc, ok := f["pc"].(string); ok {
				// reFlutter's dump.dart offsets are relative to the isolate
				// instructions region; aotopsy's functions.jsonl "pc" is an
				// absolute ELF VA. offset = VA - codeVA converts between the two.
				if va, perr := strconv.ParseUint(strings.TrimPrefix(pc, "0x"), 16, 64); perr == nil && va >= codeVA {
					offset := va - codeVA
					key := fmt.Sprintf("0x%x", offset)
					if entry, found := offsetMap[key]; found {
						f["reflutter_name"] = entry.Name
						if entry.Class != "" {
							f["reflutter_class"] = entry.Class
							if lib, ok := libraryMap[entry.Class]; ok {
								f["reflutter_library"] = lib
							}
						}
						enrichedCount++
					}
				}
			}
			merged, _ := json.Marshal(f)
			mergedFuncs = append(mergedFuncs, string(merged))
		} else {
			mergedFuncs = append(mergedFuncs, line)
		}
	}

	// Write reFlutter data as separate JSON
	reflutterData := map[string]interface{}{
		"libraries":      libraryMap,
		"offsets":        offsetMap,
		"fields":         fieldMap,
		"entry_count":    len(entries),
		"function_count": len(offsetMap),
	}
	reflutterJSON, _ := json.MarshalIndent(reflutterData, "", "  ")
	os.WriteFile(filepath.Join(outDir, "reflutter_data.json"), reflutterJSON, 0644)

	// Copy static files FIRST — copyStaticFiles blanket-copies functions.jsonl
	// from staticDir too, so it must run BEFORE the enriched write below.
	frida.CopyStaticFiles(opts.StaticDir, outDir)

	// Write merged functions (must come after frida.CopyStaticFiles)
	os.WriteFile(filepath.Join(outDir, "functions.jsonl"),
		[]byte(strings.Join(mergedFuncs, "\n")+"\n"), 0644)

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

	reportPath := filepath.Join(outDir, "reflutter_import_report.txt")
	os.WriteFile(reportPath, []byte(report), 0644)

	return &ReFlutterImportResult{
		Libraries:     len(libraryMap),
		Functions:     len(offsetMap),
		ClassesFields: len(fieldMap),
		EnrichedCount: enrichedCount,
		OutputDir:     outDir,
	}, nil
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
