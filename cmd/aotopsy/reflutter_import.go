package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"aotopsy/internal/frida"

	"aotopsy/internal/pipeline"
)

// reFlutterDumpEntry represents one entry from reFlutter's dump.dart
// Format: Library:'url' Class: Name extends Parent { ... }
//
//	function name offset: 0xNNNN;
//	Type* fieldName = value;
type reFlutterDumpEntry struct {
	LibraryURL string
	ClassName  string
	ParentName string
	Functions  []reFlutterFunction
	Fields     []reFlutterField
}

type reFlutterFunction struct {
	Name   string
	Offset string
}

type reFlutterField struct {
	Type  string
	Name  string
	Value string
}

func cmdReflutterImport(args []string) error {
	fs := flag.NewFlagSet("reflutter-import", flag.ExitOnError)
	dumpPath := fs.String("dump", "", "path to reFlutter's dump.dart")
	staticDir := fs.String("static", "", "aotopsy static output directory")
	libPath := fs.String("lib", "", "path to the original libapp.so (needed to convert reFlutter's snapshot-relative offsets to aotopsy's absolute VAs)")
	outDir := fs.String("out", "", "output directory for merged results (default: <static>_reflutter)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dumpPath == "" || *staticDir == "" {
		return fmt.Errorf("--dump and --static are required")
	}
	if *libPath == "" {
		return fmt.Errorf("--lib is required (offset->VA conversion needs the original libapp.so's codeVA base; see LoadContext)")
	}

	// codeVA is NOT persisted in any static output artifact (dart_meta.json,
	// functions.jsonl, ...) -- it's derived fresh from the ELF/snapshot every
	// run (see internal/pipeline/context.go's own comment: "new callers
	// should use LoadContext instead of duplicating the sequence again").
	// This was the actual gap behind M-13: without it, offset->VA conversion
	// had nothing to convert against, so the merge loop below was a no-op.
	ctx, err := pipeline.LoadContext(*libPath)
	if err != nil {
		return fmt.Errorf("load context for --lib %s: %w", *libPath, err)
	}
	defer func() { _ = ctx.Close() }()
	codeVA := ctx.CodeVA

	// Read dump.dart
	data, err := os.ReadFile(*dumpPath)
	if err != nil {
		return fmt.Errorf("read dump.dart: %v", err)
	}

	// Parse dump.dart
	entries := parseReFlutterDump(string(data))

	// Determine output directory
	if *outDir == "" {
		*outDir = *staticDir + "_reflutter"
	}
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return fmt.Errorf("mkdir output: %v", err)
	}

	// Build offset → {name, owning class} map from reFlutter dump. Each
	// function's own reFlutterFunction only carries its Name -- the owning
	// class (needed to look up libraryMap) comes from the enclosing entry,
	// so it must be captured alongside the offset here rather than looked
	// up again later by function name (which isn't a valid libraryMap key).
	type offsetEntry struct {
		Name  string `json:"name"`
		Class string `json:"class"`
	}
	offsetMap := make(map[string]offsetEntry)
	fieldMap := make(map[string][]reFlutterField)
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
	funcsPath := filepath.Join(*staticDir, "functions.jsonl")
	funcsData, err := os.ReadFile(funcsPath)
	if err != nil {
		return fmt.Errorf("read functions: %v", err)
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
				// instructions region (_kDartIsolateSnapshotInstructions);
				// aotopsy's functions.jsonl "pc" is an absolute ELF VA.
				// offset = VA - codeVA converts between the two -- codeVA
				// comes from --lib via pipeline.LoadContext (see above),
				// not from anything already in the static output dir.
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
	os.WriteFile(filepath.Join(*outDir, "reflutter_data.json"), reflutterJSON, 0644)

	// Copy static files FIRST -- copyStaticFiles blanket-copies functions.jsonl
	// from staticDir too, so it must run BEFORE the enriched write below or it
	// clobbers the merge with the pristine original (this was invisible before
	// the M-13 fix, since the "merged" file was always byte-identical to the
	// original anyway; now that enrichment actually changes content, order matters).
	frida.CopyStaticFiles(*staticDir, *outDir)

	// Write merged functions (must come after frida.CopyStaticFiles -- see above)
	os.WriteFile(filepath.Join(*outDir, "functions.jsonl"),
		[]byte(strings.Join(mergedFuncs, "\n")+"\n"), 0644)

	// Write report
	report := fmt.Sprintf("reFlutter Import Report\n")
	report += fmt.Sprintf("=======================\n\n")
	report += fmt.Sprintf("Static output: %s\n", *staticDir)
	report += fmt.Sprintf("reFlutter dump: %s\n", *dumpPath)
	report += fmt.Sprintf("Merged output: %s\n\n", *outDir)
	report += fmt.Sprintf("Libraries parsed: %d\n", len(libraryMap))
	report += fmt.Sprintf("Functions parsed: %d\n", len(offsetMap))
	report += fmt.Sprintf("Classes with fields: %d\n", len(fieldMap))
	report += fmt.Sprintf("Functions enriched: %d\n", enrichedCount)

	reportPath := filepath.Join(*outDir, "reflutter_import_report.txt")
	os.WriteFile(reportPath, []byte(report), 0644)

	fmt.Fprintf(os.Stderr, "reFlutter import complete: %s\n", *outDir)
	fmt.Fprintf(os.Stderr, "  Libraries: %d\n", len(libraryMap))
	fmt.Fprintf(os.Stderr, "  Functions: %d\n", len(offsetMap))
	fmt.Fprintf(os.Stderr, "  Classes with fields: %d\n", len(fieldMap))
	return nil
}

// parseReFlutterDump parses reFlutter's dump.dart format.
// Format example:
//
//	Library:'package:app/file.dart' Class: MyClass extends Object {
//	function methodA offset: 0x1234;
//	function methodB offset: 0x5678;
//	String* fieldName = "value";
//	}
func parseReFlutterDump(content string) []reFlutterDumpEntry {
	var entries []reFlutterDumpEntry

	// Regex for Library + Class header
	libClassRe := regexp.MustCompile(`Library:'([^']*)'\s+Class:\s+(\S+)\s+extends\s+(\S+)\s+\{`)
	// Regex for function entries
	funcRe := regexp.MustCompile(`function\s+(\S+)\s+offset:\s*(0x[0-9a-fA-F]+);`)
	// Regex for field entries
	fieldRe := regexp.MustCompile(`(\S+)\*\s+(\S+)\s+=\s+(.*?);`)

	lines := strings.Split(content, "\n")
	var current *reFlutterDumpEntry

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check for Library + Class header
		if m := libClassRe.FindStringSubmatch(line); m != nil {
			if current != nil {
				entries = append(entries, *current)
			}
			current = &reFlutterDumpEntry{
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
			current.Functions = append(current.Functions, reFlutterFunction{
				Name:   m[1],
				Offset: m[2],
			})
			continue
		}

		// Check for field entry
		if m := fieldRe.FindStringSubmatch(line); m != nil {
			current.Fields = append(current.Fields, reFlutterField{
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
