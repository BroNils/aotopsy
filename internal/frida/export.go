package frida

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aotopsy/internal/disasm"
	"aotopsy/internal/pipeline"
	"aotopsy/internal/sdk"
	"aotopsy/internal/vmtables"
)

// FridaMetadata is the JSON structure exported for Frida scripts.
// It contains everything a Frida script needs to hook Dart functions,
// probe unresolved BLRs, extract class IDs, and annotate output.
type FridaMetadata struct {
	DartVersion       string                 `json:"dart_version"`
	Architecture      string                 `json:"architecture"`
	CompressedPointers bool                  `json:"compressed_pointers"`
	PointerSize       int                    `json:"pointer_size"`
	ModuleBase        string                 `json:"module_base"`
	THRFields         map[int]string         `json:"thr_fields"`
	THRReg            string                 `json:"thr_reg"`
	PPReg             string                 `json:"pp_reg"`
	DTReg             string                 `json:"dt_reg"`
	HeapBaseReg       string                 `json:"heap_base_reg"`
	HeaderBitOffset   int                    `json:"header_bit_offset"`
	HeaderBitWidth    int                    `json:"header_bit_width"`
	Functions         []FridaFunction        `json:"functions"`
	UnresolvedBLRs    []FridaUnresolvedBLR   `json:"unresolved_blrs"`
	DispatchTable     []FridaDispatchEntry   `json:"dispatch_table"`
	StringRefs        []FridaStringRef       `json:"string_refs"`
	FFICallSites      []FridaFFICallSite     `json:"ffi_call_sites"`
}

type FridaFunction struct {
	VA    string `json:"va"`
	Name  string `json:"name"`
	Owner string `json:"owner"`
	Size  int    `json:"size"`
}

type FridaUnresolvedBLR struct {
	VA        string `json:"va"`
	FromFunc  string `json:"from_func"`
	Reg       string `json:"reg"`
	Via       string `json:"via"`
	SlotHint  int    `json:"slot_hint,omitempty"`
}

type FridaDispatchEntry struct {
	Index  int    `json:"index"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
}

type FridaStringRef struct {
	FromFunc string `json:"from_func"`
	Value    string `json:"value"`
	Kind     string `json:"kind"`
}

type FridaFFICallSite struct {
	FromFunc string `json:"from_func"`
	VA       string `json:"va"`
	Kind     string `json:"kind"`
}

func CmdFridaExport(args []string) error {
	fs := flag.NewFlagSet("frida-export", flag.ExitOnError)
	libPath := fs.String("lib", "", "path to libapp.so")
	fromDir := fs.String("from", "", "reuse existing aotopsy output directory")
	outPath := fs.String("out", "", "output JSON path (default: <from>/frida_metadata.json)")
	genScript := fs.Bool("gen-script", false, "also generate a ready-to-run Frida JS script")
	scriptPath := fs.String("script-out", "", "output path for Frida script (default: <from>/frida_hooks.js)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	dir := *fromDir
	if dir == "" {
		if *libPath == "" {
			return fmt.Errorf("--lib or --from is required")
		}
		// Run full pipeline first
		base := strings.TrimSuffix(filepath.Base(*libPath), ".so")
		dir = base + ".aotopsy"
		opts := pipeline.Opts{
			LibPath:  *libPath,
			OutDir:   dir,
			Quiet:    true,
			Signal:   true,
			SignalK:  2,
			MaxSteps: 100000,
		}
		fmt.Fprintf(os.Stderr, "Running full pipeline...\n")
		result, err := pipeline.Run(opts)
		if err != nil {
			return fmt.Errorf("pipeline failed: %v", err)
		}
		_ = result
	} else {
		if *libPath == "" {
			// Try to find libapp.so from the output directory
			*libPath = filepath.Join(dir, "..", "libapp.so")
			if _, err := os.Stat(*libPath); err != nil {
				return fmt.Errorf("--lib is required when using --from (could not auto-detect)")
			}
		}
	}

	// Load context from output directory
	ctx, err := pipeline.LoadContext(*libPath)
	if err != nil {
		return fmt.Errorf("load context: %v", err)
	}
	// The only LoadContext caller that was not closing its context. Four of
	// the five did; this one held the mapped ELF open until the process
	// exited.
	defer func() { _ = ctx.Close() }()

	// Determine output path
	if *outPath == "" {
		*outPath = filepath.Join(dir, "frida_metadata.json")
	}

	// Build metadata
	meta := BuildFridaMetadata(ctx, dir)

	// Write JSON
	f, err := os.Create(*outPath)
	if err != nil {
		return fmt.Errorf("create output: %v", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(meta); err != nil {
		return fmt.Errorf("encode: %v", err)
	}

	fmt.Fprintf(os.Stderr, "Frida metadata exported: %s\n", *outPath)
	fmt.Fprintf(os.Stderr, "  Functions: %d\n", len(meta.Functions))
	fmt.Fprintf(os.Stderr, "  Unresolved BLRs: %d\n", len(meta.UnresolvedBLRs))
	fmt.Fprintf(os.Stderr, "  Dispatch entries: %d\n", len(meta.DispatchTable))
	fmt.Fprintf(os.Stderr, "  String refs: %d\n", len(meta.StringRefs))
	fmt.Fprintf(os.Stderr, "  FFI call sites: %d\n", len(meta.FFICallSites))

	// Generate Frida script if requested
	if *genScript {
		if *scriptPath == "" {
			*scriptPath = filepath.Join(dir, "frida_hooks.js")
		}
		script := GenerateFridaScriptFromMeta(*outPath)
		if err := os.WriteFile(*scriptPath, []byte(script), 0644); err != nil {
			return fmt.Errorf("write frida script: %v", err)
		}
		fmt.Fprintf(os.Stderr, "  Frida script: %s\n", *scriptPath)
		fmt.Fprintf(os.Stderr, "  Run: frida -H 127.0.0.1:8888 -f com.example.app -l %s\n", *scriptPath)
	}

	return nil
}

func BuildFridaMetadata(ctx *pipeline.Context, dir string) FridaMetadata {
	isARM64 := ctx.IsARM64
	arch := "x64"
	thrReg := sdk.X86ThreadRegStr
	ppReg := sdk.X86PoolRegStr
	dtReg := "rax" // loaded from THR at runtime
	heapBaseReg := "rbp" // not used on x86_64
	if isARM64 {
		arch = "arm64"
		thrReg = sdk.ARM64ThreadRegStr
		ppReg = sdk.ARM64PoolRegStr
		dtReg = "x21"
		heapBaseReg = sdk.ARM64HeapBitsStr
	}

	// Header bit layout
	bitOffset := 12
	bitWidth := 20
	if ctx.Info.Version.PreV32Format {
		bitOffset = 16
		bitWidth = 16
	}

	// Pointer size: 4 for compressed pointers, 8 otherwise.
	pointerSize := 8
	if ctx.Info.Version.CompressedPointers {
		pointerSize = 4
	}

	meta := FridaMetadata{
		DartVersion:        ctx.DartVersion,
		Architecture:       arch,
		CompressedPointers: ctx.Info.Version.CompressedPointers,
		PointerSize:        pointerSize,
		THRFields:          vmtables.THRFieldsWithProfile(ctx.DartVersion, isARM64, ctx.Info.Version),
		THRReg:             thrReg,
		PPReg:              ppReg,
		DTReg:              dtReg,
		HeapBaseReg:        heapBaseReg,
		HeaderBitOffset:    bitOffset,
		HeaderBitWidth:     bitWidth,
	}

	// Functions
	funcsPath := filepath.Join(dir, "functions.jsonl")
	if data, err := os.ReadFile(funcsPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var f struct {
				Name  string `json:"name"`
				PC    string `json:"pc"`
				Size  int    `json:"size"`
				Owner string `json:"owner"`
			}
			if json.Unmarshal([]byte(line), &f) == nil && f.Name != "" {
				meta.Functions = append(meta.Functions, FridaFunction{
					VA:    f.PC,
					Name:  f.Name,
					Owner: f.Owner,
					Size:  f.Size,
				})
			}
		}
	}

	// Unresolved BLRs from call_edges.jsonl
	edgesPath := filepath.Join(dir, "call_edges.jsonl")
	if data, err := os.ReadFile(edgesPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var e struct {
				Kind     string `json:"kind"`
				FromFunc string `json:"from_func"`
				FromPC   string `json:"from_pc"`
				Reg      string `json:"reg"`
				Via      string `json:"via"`
				Target   string `json:"target"`
			}
			if json.Unmarshal([]byte(line), &e) == nil && e.Kind == "blr" && e.Target == "" {
				// Only include dispatch_table and object_field BLRs (not THR calls)
				if e.Via == "dispatch_table" || strings.HasPrefix(e.Via, disasm.ObjectFieldVia) || e.Via == "" {
					meta.UnresolvedBLRs = append(meta.UnresolvedBLRs, FridaUnresolvedBLR{
						VA:       e.FromPC,
						FromFunc: e.FromFunc,
						Reg:      e.Reg,
						Via:      e.Via,
					})
				}
			}
		}
	}

	// Dispatch table
	dtPath := filepath.Join(dir, "dispatch_table.jsonl")
	if data, err := os.ReadFile(dtPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var e struct {
				Index  int    `json:"index"`
				Kind   string `json:"kind"`
				Target string `json:"target"`
			}
			if json.Unmarshal([]byte(line), &e) == nil && e.Kind == "code" && e.Target != "" {
				meta.DispatchTable = append(meta.DispatchTable, FridaDispatchEntry{
					Index:  e.Index,
					Kind:   e.Kind,
					Target: e.Target,
				})
			}
		}
	}

	// String refs
	srPath := filepath.Join(dir, "string_refs.jsonl")
	if data, err := os.ReadFile(srPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var r struct {
				FromFunc string `json:"from_func"`
				Value    string `json:"value"`
				Kind     string `json:"kind"`
			}
			if json.Unmarshal([]byte(line), &r) == nil && r.Value != "" {
				meta.StringRefs = append(meta.StringRefs, FridaStringRef{
					FromFunc: r.FromFunc,
					Value:    r.Value,
					Kind:     r.Kind,
				})
			}
		}
	}

	// FFI call sites (from ffi-trace if available)
	// We'll read from a separate file if it exists
	ffiPath := filepath.Join(dir, "ffi_call_sites.jsonl")
	if data, err := os.ReadFile(ffiPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var f struct {
				FromFunc string `json:"from_func"`
				VA       string `json:"va"`
				Kind     string `json:"kind"`
			}
			if json.Unmarshal([]byte(line), &f) == nil {
				meta.FFICallSites = append(meta.FFICallSites, FridaFFICallSite{
					FromFunc: f.FromFunc,
					VA:       f.VA,
					Kind:     f.Kind,
				})
			}
		}
	}

	return meta
}
