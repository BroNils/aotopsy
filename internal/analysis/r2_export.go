package analysis

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"

	"aotopsy/internal/cluster"
	"aotopsy/internal/naming"
	"aotopsy/internal/output"
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
	return output.WriteAtomic(path, 0o644, func(w io.Writer) error {
		for _, e := range entries {
			// r2 flag: f name @ addr
			// SanitizeR2FlagName returns "" for a name that carries no
			// alphanumeric identity and guarantees the rest is accepted by r2's
			// r_name_check without collapsing distinct raw-name/VA identities.
			r2Name := strutil.SanitizeR2FlagName(e.name, e.va)
			if r2Name == "" {
				continue
			}
			if _, err := fmt.Fprintf(w, "f %s @ 0x%x\n", r2Name, e.va); err != nil {
				return fmt.Errorf("write r2 export: %w", err)
			}
		}
		return nil
	})
}
