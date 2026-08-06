// Package output writes aotopsy analysis results to files.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"aotopsy/internal/disasm"
	"aotopsy/internal/snapshot"
)

// WriteSnapshotJSON writes snapshot metadata to snapshot.json.
func WriteSnapshotJSON(dir string, info *snapshot.Info) error {
	return writeJSON(filepath.Join(dir, "snapshot.json"), info)
}

// SymbolEntry represents a named code address.
type SymbolEntry struct {
	Address uint64 `json:"address"`
	Name    string `json:"name"`
	Size    uint64 `json:"size,omitempty"`
}

// WriteSymbolsJSON writes symbols to symbols.json.
func WriteSymbolsJSON(dir string, symbols []SymbolEntry) error {
	return writeJSON(filepath.Join(dir, "symbols.json"), symbols)
}

// WriteASM writes disassembled instructions to asm/<name>.txt.
// name may contain path separators (e.g., "OwnerClass/func_hex") for directory grouping.
func WriteASM(dir string, name string, insts []disasm.Inst, lookup disasm.SymbolLookup, annotators ...disasm.Annotator) error {
	path := filepath.Join(dir, "asm", name+".txt")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("output: mkdir asm: %w", err)
	}

	text := disasm.Format(insts, lookup, annotators...)
	return os.WriteFile(path, []byte(text), 0644)
}

// WriteASMSingle writes all instructions to a single asm.txt file.
func WriteASMSingle(dir string, insts []disasm.Inst, lookup disasm.SymbolLookup, annotators ...disasm.Annotator) error {
	path := filepath.Join(dir, "asm.txt")
	text := disasm.Format(insts, lookup, annotators...)
	return os.WriteFile(path, []byte(text), 0644)
}

// WriteBin writes raw instruction bytes to asm/<name>.bin for CFG construction.
// name may contain path separators (e.g., "OwnerClass/func_hex") for directory grouping.
func WriteBin(dir string, name string, data []byte) error {
	path := filepath.Join(dir, "asm", name+".bin")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("output: mkdir asm: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("output: create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("output: encode %s: %w", path, err)
	}
	return nil
}
