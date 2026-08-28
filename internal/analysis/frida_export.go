package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"aotopsy/internal/disasm"
	"aotopsy/internal/frida"
	"aotopsy/internal/sdk"
	"aotopsy/internal/vmtables"
)

// BuildFridaMetadata builds the Frida metadata JSON from a loaded Context
// and the pipeline output directory.
func BuildFridaMetadata(ctx *AnalysisContext, dir string) frida.FridaMetadata {
	isARM64 := ctx.IsARM64
	arch := "x64"
	thrReg := sdk.X86ThreadRegStr
	ppReg := sdk.X86PoolRegStr
	dtReg := "rax"
	heapBaseReg := "rbp"
	if isARM64 {
		arch = "arm64"
		thrReg = sdk.ARM64ThreadRegStr
		ppReg = sdk.ARM64PoolRegStr
		dtReg = "x21"
		heapBaseReg = sdk.ARM64HeapBitsStr
	}

	bitOffset := 12
	bitWidth := 20
	if ctx.Info.Version.PreV32Format {
		bitOffset = 16
		bitWidth = 16
	}

	pointerSize := 8
	if ctx.Info.Version.CompressedPointers {
		pointerSize = 4
	}

	meta := frida.FridaMetadata{
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
				meta.Functions = append(meta.Functions, frida.FridaFunction{
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
				if e.Via == "dispatch_table" || strings.HasPrefix(e.Via, disasm.ObjectFieldVia) || e.Via == "" {
					meta.UnresolvedBLRs = append(meta.UnresolvedBLRs, frida.FridaUnresolvedBLR{
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
				meta.DispatchTable = append(meta.DispatchTable, frida.FridaDispatchEntry{
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
				meta.StringRefs = append(meta.StringRefs, frida.FridaStringRef{
					FromFunc: r.FromFunc,
					Value:    r.Value,
					Kind:     r.Kind,
				})
			}
		}
	}

	// FFI call sites
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
				meta.FFICallSites = append(meta.FFICallSites, frida.FridaFFICallSite{
					FromFunc: f.FromFunc,
					VA:       f.VA,
					Kind:     f.Kind,
				})
			}
		}
	}

	return meta
}
