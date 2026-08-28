package frida

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FridaRuntimeResult is the JSON structure produced by Frida scripts
// that aotopsy frida-import consumes.
type FridaRuntimeResult struct {
	DispatchResolutions []FridaDispatchResolution `json:"dispatch_resolutions"`
	TypeSnapshots       []FridaTypeSnapshot       `json:"type_snapshots"`
	CallGraph           map[string]int            `json:"call_graph"`
	HeapObjects         []FridaHeapObject         `json:"heap_objects"`
}

type FridaDispatchResolution struct {
	BLRAddr    string `json:"blr_addr"`
	FromFunc   string `json:"from_func"`
	TargetVA   string `json:"target_va"`
	TargetName string `json:"target_name,omitempty"`
	ClassID    int    `json:"class_id,omitempty"`
}

type FridaTypeSnapshot struct {
	FuncVA    string         `json:"func_va"`
	Registers map[string]int `json:"registers"`
}

type FridaHeapObject struct {
	Address   string `json:"address"`
	ClassID   int    `json:"class_id"`
	ClassName string `json:"class_name,omitempty"`
}

func CmdFridaImport(args []string) error {
	fs := flag.NewFlagSet("frida-import", flag.ExitOnError)
	fromPath := fs.String("from", "", "path to frida_results.json")
	staticDir := fs.String("static", "", "aotopsy static output directory")
	outDir := fs.String("out", "", "output directory for merged results (default: <static>_merged)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *fromPath == "" || *staticDir == "" {
		return fmt.Errorf("--from and --static are required")
	}

	// Read Frida results
	data, err := os.ReadFile(*fromPath)
	if err != nil {
		return fmt.Errorf("read frida results: %v", err)
	}
	var result FridaRuntimeResult
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parse frida results: %v", err)
	}

	// Determine output directory
	if *outDir == "" {
		*outDir = *staticDir + "_merged"
	}
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return fmt.Errorf("mkdir output: %v", err)
	}

	// Read static call_edges.jsonl
	edgesPath := filepath.Join(*staticDir, "call_edges.jsonl")
	edgesData, err := os.ReadFile(edgesPath)
	if err != nil {
		return fmt.Errorf("read call_edges: %v", err)
	}

	// Build resolution map from Frida results
	resolutionMap := make(map[string]FridaDispatchResolution)
	for _, r := range result.DispatchResolutions {
		resolutionMap[r.BLRAddr] = r
	}

	// Build runtime confirmed functions set from call graph
	runtimeConfirmed := make(map[string]int)
	for name, count := range result.CallGraph {
		runtimeConfirmed[name] = count
	}

	// Merge: update call_edges.jsonl with resolved targets + runtime confirmed flags
	var mergedEdges []string
	resolvedCount := 0
	confirmedCount := 0
	for _, line := range strings.Split(string(edgesData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e map[string]interface{}
		if json.Unmarshal([]byte(line), &e) == nil {
			// Mark runtime confirmed functions
			if fromFunc, ok := e["from_func"].(string); ok {
				if count, found := runtimeConfirmed[fromFunc]; found {
					e["runtime_confirmed"] = true
					e["runtime_call_count"] = count
					confirmedCount++
				}
			}
			// Also check target function
			if target, ok := e["target"].(string); ok {
				if count, found := runtimeConfirmed[target]; found {
					e["runtime_target_confirmed"] = true
					e["runtime_target_count"] = count
				}
			}
			if e["kind"] == "blr" && e["target"] == "" {
				if fromPC, ok := e["from_pc"].(string); ok {
					if r, found := resolutionMap[fromPC]; found {
						e["target"] = r.TargetName
						if r.TargetName == "" {
							e["target"] = r.TargetVA
						}
						e["runtime_resolved"] = true
						if r.ClassID > 0 {
							e["runtime_class_id"] = r.ClassID
						}
						resolvedCount++
					}
				}
			}
			merged, _ := json.Marshal(e)
			mergedEdges = append(mergedEdges, string(merged))
		} else {
			mergedEdges = append(mergedEdges, line)
		}
	}

	// Write merged call_edges.jsonl
	outEdgesPath := filepath.Join(*outDir, "call_edges.jsonl")
	if err := os.WriteFile(outEdgesPath, []byte(strings.Join(mergedEdges, "\n")+"\n"), 0644); err != nil {
		return fmt.Errorf("write merged edges: %v", err)
	}

	// Write resolution report
	report := fmt.Sprintf("Frida Import Report\n")
	report += fmt.Sprintf("===================\n\n")
	report += fmt.Sprintf("Static output: %s\n", *staticDir)
	report += fmt.Sprintf("Frida results: %s\n", *fromPath)
	report += fmt.Sprintf("Merged output: %s\n\n", *outDir)
	report += fmt.Sprintf("Dispatch resolutions from Frida: %d\n", len(result.DispatchResolutions))
	report += fmt.Sprintf("BLR edges resolved by Frida: %d\n", resolvedCount)
	report += fmt.Sprintf("Runtime confirmed functions: %d\n", confirmedCount)
	report += fmt.Sprintf("Type snapshots: %d\n", len(result.TypeSnapshots))
	report += fmt.Sprintf("Heap objects: %d\n", len(result.HeapObjects))
	report += fmt.Sprintf("Call graph entries: %d\n", len(result.CallGraph))

	reportPath := filepath.Join(*outDir, "frida_import_report.txt")
	os.WriteFile(reportPath, []byte(report), 0644)

	// Copy static files to merged directory
	CopyStaticFiles(*staticDir, *outDir)

	fmt.Fprintf(os.Stderr, "Frida import complete: %s\n", *outDir)
	fmt.Fprintf(os.Stderr, "  BLR resolved by Frida: %d\n", resolvedCount)
	fmt.Fprintf(os.Stderr, "  Report: %s\n", reportPath)
	return nil
}

func CopyStaticFiles(srcDir, dstDir string) {
	files := []string{"functions.jsonl", "classes.jsonl", "string_refs.jsonl",
		"dart_meta.json", "dispatch_table.jsonl", "signal_graph.json"}
	for _, f := range files {
		src := filepath.Join(srcDir, f)
		dst := filepath.Join(dstDir, f)
		if data, err := os.ReadFile(src); err == nil {
			os.WriteFile(dst, data, 0644)
		}
	}
}
