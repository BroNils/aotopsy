package analysis

import (
	"encoding/binary"
	"strings"
	"testing"

	"aotopsy/internal/decompiler"
	"aotopsy/internal/samplecorpus"
)

// TestSwitchJumpTableRecovery checks the one property that makes switch
// recovery trustworthy: every offset in a recovered jump table lands exactly on
// a block start.
//
// The predecessor of this code did not read the table at all -- it labelled the
// blocks following the indirect jump case 0, 1, 2, ... in address order, so the
// emitted `switch` was a fabrication (see finding 022). A test that only
// asserted "a switch was emitted" would have passed against that. This asserts
// the mapping instead.
//
// Runs over every function, not a prefix: a binary holds only a handful of jump
// tables (2 to 45 across the corpus) and they are not in the first 400
// functions.
func TestSwitchJumpTableRecovery(t *testing.T) {
	samples := []string{
		"dart-3.12.2-x64.so",
		"dart-3.9.2-gt-arm64.so",
		"dart-2.12.0-arm64.so",
	}
	anyRun := false
	for _, name := range samples {
		path := samplecorpus.Path(name)
		if path == "" {
			t.Logf("%s: absent", name)
			continue
		}
		anyRun = true
		t.Run(name, func(t *testing.T) {
			ctx, err := LoadContext(path)
			if err != nil {
				t.Fatalf("LoadContext: %v", err)
			}
			defer func() { _ = ctx.Close() }()

			if len(ctx.Result.Int32Arrays) == 0 {
				t.Fatalf("no Int32Array payloads captured; jump tables cannot be read")
			}

			var withTable, emittedSwitch int
			for _, r := range ctx.Ranges {
				if r.Size == 0 || r.RefID < 0 {
					continue
				}
				fir, err := ctx.FuncIRFor(r)
				if err != nil || fir == nil || len(fir.SwitchCases) == 0 {
					continue
				}
				withTable++

				blockByVA := map[uint64]int{}
				for i := range fir.Blocks {
					blockByVA[fir.Blocks[i].StartVA] = fir.Blocks[i].ID
				}
				// Case i must map to the block at EntryVA + offsets[i], and the
				// indices must be a dense 0..n-1 run -- a renumbered or gapped
				// table would silently mislabel every case after the gap.
				for i, sc := range fir.SwitchCases {
					if sc.Index != i {
						t.Errorf("%s: case %d has Index %d", fir.Name, i, sc.Index)
					}
					found := false
					for _, id := range blockByVA {
						if id == sc.BlockID {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("%s: case %d maps to block %d, which is not a real block",
							fir.Name, i, sc.BlockID)
					}
				}

				// Cross-check against the raw table bytes independently of the
				// wiring code, so a bug in that loop cannot make this pass.
				var table []byte
				for bi := range fir.Blocks {
					for _, ins := range fir.Blocks[bi].Instrs {
						if ins.Op != decompiler.OpLoadPool || ins.PoolIndex < 0 {
							continue
						}
						pe, ok := ctx.Enrichment.PoolByIndex[ins.PoolIndex]
						if !ok {
							continue
						}
						if b, ok := ctx.Result.Int32Arrays[pe.RefID]; ok {
							table = b
						}
					}
				}
				if table == nil {
					t.Errorf("%s: SwitchCases populated but no Int32Array found", fir.Name)
					continue
				}
				if got, want := len(fir.SwitchCases), len(table)/4; got != want {
					t.Errorf("%s: %d cases for a %d-entry table", fir.Name, got, want)
				}
				for i, sc := range fir.SwitchCases {
					if i*4+4 > len(table) {
						break
					}
					off := uint64(binary.LittleEndian.Uint32(table[i*4:]))
					want, ok := blockByVA[fir.EntryVA+off]
					if !ok {
						t.Errorf("%s: case %d offset %#x does not land on a block start",
							fir.Name, i, off)
						continue
					}
					if sc.BlockID != want {
						t.Errorf("%s: case %d -> block %d, table says block %d",
							fir.Name, i, sc.BlockID, want)
					}
				}

				src := decompiler.EmitPseudocode(fir,
					func(va uint64) (string, bool) { s, ok := ctx.SymbolNames[va]; return s, ok && s != "" },
					func(i int) (string, bool) { s, ok := ctx.PoolDisplay[i]; return s, ok }).Source
				if strings.Contains(src, "switch (") {
					emittedSwitch++
				}
			}

			if withTable == 0 {
				t.Fatalf("no function recovered a jump table; every corpus sample has at least two")
			}
			if emittedSwitch == 0 {
				t.Errorf("%d functions recovered a table but none emitted a switch", withTable)
			}
			t.Logf("%d functions with a recovered jump table, %d emitted a switch",
				withTable, emittedSwitch)
		})
	}
	if !anyRun {
		t.Skip("no samples/ directory in this checkout")
	}
}
