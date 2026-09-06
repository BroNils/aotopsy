package analysis

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"aotopsy/internal/decompiler"
	"aotopsy/internal/samplecorpus"
)

// perFunctionSourceCeiling is the largest emitted source one function may
// produce before the sweep calls it a defect.
//
// This is not a style budget. Before the expression-materialization fix,
// SystemHash.hash20 -- two blocks, 896 bytes of machine code -- emitted ~570 MB
// and took the process out of memory. 2 MB is far above anything legitimate
// (the largest honest function in the corpus is two orders below it) and far
// below anything that threatens the host, so it catches a blowup while it is
// still a test failure rather than an OOM.
const perFunctionSourceCeiling = 2 << 20

// TestFullCorpusSweep decompiles EVERY function of EVERY sample.
//
// It exists because of what the 400-function cap hid. Every other decompiler
// check in this project -- the fidelity census, the golden record, the quality
// gates -- looks at a prefix of each binary, and three separate defects lived
// comfortably behind that prefix until a full sweep went looking:
//
//   - fabricated `while (true)` wrappers around straight-line code, from a
//     back-edge test that read block addresses instead of dominance (021)
//   - fabricated `switch` cases, from jump-table "recovery" that never read
//     the jump table (022)
//   - an emitter OOM at 5.9 GB on a two-block function, from unbounded
//     expression forwarding (023)
//
// None of the three is exotic. All three sat in functions numbered past 400.
//
// Opt-in because it is slow (the corpus is 93 binaries and some hold ~38 000
// functions):
//
//	AOTOPSY_SWEEP=1 go test ./internal/analysis/ -run TestFullCorpusSweep -v -timeout 180m
//
// AOTOPSY_SWEEP_SAMPLE=<substring> narrows it to matching samples while
// investigating a specific failure.
func TestFullCorpusSweep(t *testing.T) {
	if os.Getenv("AOTOPSY_SWEEP") == "" {
		t.Skip("set AOTOPSY_SWEEP=1 to sweep every function of every sample")
	}
	filter := os.Getenv("AOTOPSY_SWEEP_SAMPLE")

	type outlier struct {
		sample, fn string
		bytes      int
		blocks     int
	}
	var biggest []outlier
	var totalFns, totalSamples int
	start := time.Now()

	for _, s := range samplecorpus.Registry {
		name := s.FileName()
		if filter != "" && !strings.Contains(name, filter) {
			continue
		}
		path := samplecorpus.Path(name)
		if path == "" {
			continue
		}
		totalSamples++

		t.Run(name, func(t *testing.T) {
			ctx, err := LoadContext(path)
			if err != nil {
				t.Fatalf("LoadContext: %v", err)
			}
			defer func() { _ = ctx.Close() }()

			sym := func(va uint64) (string, bool) {
				n, ok := ctx.SymbolNames[va]
				return n, ok && n != ""
			}
			pool := func(i int) (string, bool) { p, ok := ctx.PoolDisplay[i]; return p, ok }

			var fns, invalid int
			sampleStart := time.Now()
			for _, r := range ctx.Ranges {
				if r.Size == 0 || r.RefID < 0 {
					continue
				}
				fir, err := ctx.FuncIRFor(r)
				if err != nil || fir == nil {
					continue
				}
				fns++

				// A panic here is the failure this sweep is looking for, and a
				// bare panic would abandon the remaining samples. Recover, name
				// the function, and keep going so one bad function does not
				// hide the rest of the corpus.
				var art decompiler.Artifact
				func() {
					defer func() {
						if p := recover(); p != nil {
							t.Errorf("PANIC in %s (blocks=%d size=%d): %v",
								fir.Name, len(fir.Blocks), r.Size, p)
							art = decompiler.Artifact{}
						}
					}()
					art = decompiler.EmitPseudocode(fir, sym, pool)
				}()

				if n := len(art.Source); n > perFunctionSourceCeiling {
					t.Errorf("%s emitted %d bytes from %d blocks / %d code bytes (ceiling %d)",
						fir.Name, n, len(fir.Blocks), r.Size, perFunctionSourceCeiling)
				}
				if probs := decompiler.ValidateSource(art.Source); len(probs) > 0 {
					invalid++
					if invalid <= 5 {
						t.Errorf("%s emitted invalid Dart: %v", fir.Name, probs)
					}
				}

				biggest = append(biggest, outlier{name, fir.Name, len(art.Source), len(fir.Blocks)})
				if len(biggest) > 4096 {
					sort.Slice(biggest, func(i, j int) bool { return biggest[i].bytes > biggest[j].bytes })
					biggest = biggest[:16]
				}
			}
			totalFns += fns
			if invalid > 5 {
				t.Errorf("... and %d more functions emitted invalid Dart", invalid-5)
			}
			t.Logf("%d functions in %s", fns, time.Since(sampleStart).Round(time.Millisecond))
		})
	}

	if totalSamples == 0 {
		t.Skip("no samples/ directory in this checkout")
	}
	sort.Slice(biggest, func(i, j int) bool { return biggest[i].bytes > biggest[j].bytes })
	var b strings.Builder
	for i, o := range biggest {
		if i >= 10 {
			break
		}
		fmt.Fprintf(&b, "\n  %9d bytes  blocks=%-4d %s  [%s]", o.bytes, o.blocks, o.fn, o.sample)
	}
	t.Logf("swept %d functions across %d samples in %s\nlargest emitted:%s",
		totalFns, totalSamples, time.Since(start).Round(time.Second), b.String())
}
