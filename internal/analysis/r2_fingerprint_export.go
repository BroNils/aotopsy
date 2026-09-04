package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"aotopsy/internal/cluster"
	"aotopsy/internal/naming"
	"aotopsy/internal/strutil"
)

// writeR2Export writes aotopsy.r2 — a radare2 command script with
// recovered function names as flags, so analysts can import them
// via `r2 -i aotopsy.r2 libapp.so`.
//
// Item 18: r2flutter / radare2 integration.
func writeR2Export(outDir string, ranges []cluster.CodeRange, pl *naming.PoolLookups, codeVA, codeOff uint64) error {
	type r2Entry struct {
		va   uint64
		name string
	}
	var entries []r2Entry
	im := NewCodeImage(nil, codeVA, codeOff, pl, nil)
	for _, r := range ranges {
		fs, ok := im.Slice(r)
		if !ok {
			continue
		}
		entries = append(entries, r2Entry{va: fs.VA, name: fs.Name})
	}
	// Sort by VA for deterministic output.
	sort.Slice(entries, func(i, j int) bool { return entries[i].va < entries[j].va })

	path := filepath.Join(outDir, "aotopsy.r2")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	for _, e := range entries {
		// r2 flag: f name @ addr
		// SanitizeR2FlagName returns "" for a name that carries nothing
		// once the separators are stripped, and guarantees the rest is
		// accepted by r2's r_name_check.
		r2Name := strutil.SanitizeR2FlagName(e.name)
		if r2Name == "" {
			continue
		}
		fmt.Fprintf(f, "f %s @ 0x%x\n", r2Name, e.va)
	}
	return nil
}

// writeFunctionFingerprints writes function_fingerprints.jsonl —
// SHA-256 hashes of each function's instruction bytes, for use
// with the cross-sample name transfer dictionary (Item 13/15).
func writeFunctionFingerprints(outDir string, ranges []cluster.CodeRange, pl *naming.PoolLookups, code []byte, codeOff, codeVA uint64) error {
	path := filepath.Join(outDir, "function_fingerprints.jsonl")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	im2 := NewCodeImage(code, codeVA, codeOff, pl, nil)
	for _, r := range ranges {
		fs, ok := im2.Slice(r)
		if !ok {
			continue
		}
		h := sha256.Sum256(fs.Code)
		name := fs.Name
		funcVA := fs.VA
		funcCode := fs.Code
		rec := struct {
			Hash string `json:"hash"`
			VA   string `json:"va"`
			Size int    `json:"size"`
			Name string `json:"name"`
		}{
			Hash: hex.EncodeToString(h[:]),
			VA:   fmt.Sprintf("0x%x", funcVA),
			Size: len(funcCode),
			Name: name,
		}
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}
