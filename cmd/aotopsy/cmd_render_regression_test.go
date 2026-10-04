package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aotopsy/internal/analysis"
	"aotopsy/internal/disasm"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/output"
	"aotopsy/internal/strutil"
)

func TestRenderUsesCanonicalArtifactPathX64AndRemovesStaleCFG(t *testing.T) {
	dir := t.TempDir()
	const funcName = "ShortcutManager.handleKeypress.#action#initializer_1000"
	const artifact = "asm/ShortcutManager/#action#initializer_1000.txt"
	funcs := []disasm.FuncRecord{{PC: "0x1000", PCOffset: 0x1000, RefID: 1, Size: 1, Name: funcName, Owner: "ShortcutManager"}}
	index := []strutil.DisasmIndexEntry{{
		Name: "#action#initializer", OwnerName: "ShortcutManager", RefID: 1,
		PCOffset: 0x1000, Size: 1, File: artifact,
	}}
	if _, err := jsonutil.WriteJSONLFile(filepath.Join(dir, "functions.jsonl"), funcs); err != nil {
		t.Fatal(err)
	}
	if _, err := jsonutil.WriteJSONLFile(filepath.Join(dir, "index.jsonl"), index); err != nil {
		t.Fatal(err)
	}
	if _, err := jsonutil.WriteJSONLFile(filepath.Join(dir, "call_edges.jsonl"), []disasm.CallEdgeRecord{}); err != nil {
		t.Fatal(err)
	}
	prov := analysis.Provenance{Source: filepath.Join(dir, "libapp.so"), SourceName: "libapp.so", SHA256: strings.Repeat("0", 64), Size: 1, Arch: "x64", DartVersion: "3.12.2"}
	if err := output.WriteJSONFile(filepath.Join(dir, analysis.ProvenanceFileName), prov); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(dir, "asm", "ShortcutManager", "#action#initializer_1000.bin")
	if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath, []byte{0xc3}, 0o644); err != nil { // RET
		t.Fatal(err)
	}

	if err := cmdRender([]string{"--in", dir, "--cfg"}); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "render", "cfg", "ShortcutManager", "#action#initializer_1000.dot")
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("canonical nested x64 CFG missing: %v", err)
	}
	wrongDisplayPath := filepath.Join(dir, "render", "cfg", strutil.SanitizeFilename(funcName)+".dot")
	if _, err := os.Stat(wrongDisplayPath); !os.IsNotExist(err) {
		t.Fatalf("render reconstructed CFG path from display name: stat err=%v", err)
	}
	indexHTML, err := os.ReadFile(filepath.Join(dir, "render", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(indexHTML), "[cfg]") {
		t.Fatalf("render linked an SVG CFG even though --no-dot suppressed SVG generation: %s", indexHTML)
	}

	missingAsm := filepath.Join(dir, "missing-asm")
	if err := cmdRender([]string{"--in", dir, "--cfg", "--asm", missingAsm}); err == nil || !strings.Contains(err.Error(), "requires asm directory") {
		t.Fatalf("requested CFG stage silently skipped a missing asm directory: %v", err)
	}
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("failed CFG rerender damaged the previous render generation: %v", err)
	}

	if err := cmdRender([]string{"--in", dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "render", "cfg")); !os.IsNotExist(err) {
		t.Fatalf("stale CFG directory survived render generation without --cfg: %v", err)
	}
}
