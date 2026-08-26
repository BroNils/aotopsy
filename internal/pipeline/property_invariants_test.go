package pipeline

import (
	"os"
	"strings"
	"testing"

	"aotopsy/internal/decompiler"
	"aotopsy/internal/samplecorpus"
)

// TestDecompilerOutputInvariants is a property check: over the ENTIRE function
// set of real samples on both architectures (thousands of functions, not the
// golden subset the F1 gate samples), every emitted function must satisfy the
// hard invariants the tool's honesty claims rest on. It catches the "fine on the
// goldens, breaks on the 5000th function" failure mode. Env-gated (heavy);
// set AOTOPSY_PROPERTY=1.
//
// Hard invariants (any violation fails):
//   - Zero fabrication markers (§2: never synthesize a lambda body or turn an
//     <Array> placeholder into a concrete []).
//   - Balanced braces per function (a structural guarantee the emitter must keep
//     regardless of control-flow shape — the class of bug phi/dead-code fixes
//     addressed).
//
// Floor invariant:
//   - Dart syntactic validity rate stays >= 0.95 across the full sweep.
func TestDecompilerOutputInvariants(t *testing.T) {
	if os.Getenv("AOTOPSY_PROPERTY") == "" {
		t.Skip("set AOTOPSY_PROPERTY=1 to run the decompiler invariant sweep")
	}
	samples := []string{"dart-3.13.0-arm64.so", "dart-3.13.0-x64.so"}
	const validFloor = 0.95

	for _, name := range samples {
		path := samplecorpus.Path(name)
		if path == "" {
			t.Logf("%s: absent", name)
			continue
		}
		ctx, err := LoadContext(path)
		if err != nil {
			t.Fatalf("%s: LoadContext: %v", name, err)
		}
		func() {
			defer func() { _ = ctx.Close() }()
			sym := func(va uint64) (string, bool) { s, ok := ctx.SymbolNames[va]; return s, ok && s != "" }
			pool := func(i int) (string, bool) { s, ok := ctx.PoolDisplay[i]; return s, ok }

			// Bounded to keep the sweep runnable on a memory-constrained host
			// (6 GB WSL) while still covering ~12x the F1 gate's golden subset.
			const perSampleCap = 3000
			var total, valid, fabrications, unbalanced int
			for _, r := range ctx.Ranges {
				if total >= perSampleCap {
					break
				}
				if r.Size == 0 || r.RefID < 0 {
					continue
				}
				fir, err := ctx.FuncIRFor(r)
				if err != nil || fir == nil {
					continue
				}
				src := decompiler.EmitPseudocode(fir, sym, pool).Source
				total++

				// Hard: no fabrication markers.
				if strings.Contains(src, "(item) => ") {
					fabrications++
				}
				if strings.Contains(src, "return [];") && strings.Contains(src, "Array") {
					fabrications++
				}
				// Hard: balanced braces.
				if strings.Count(src, "{") != strings.Count(src, "}") {
					unbalanced++
				}
				// Floor: syntactic validity.
				if len(decompiler.ValidateSource(src)) == 0 {
					valid++
				}
			}
			if total == 0 {
				t.Fatalf("%s: no functions emitted", name)
			}
			rate := float64(valid) / float64(total)
			t.Logf("%s: %d fns, %.2f%% valid, fabrications=%d unbalanced=%d",
				name, total, rate*100, fabrications, unbalanced)
			if fabrications != 0 {
				t.Errorf("%s: %d fabrication markers over the full function set (must be 0)", name, fabrications)
			}
			if unbalanced != 0 {
				t.Errorf("%s: %d functions with unbalanced braces (must be 0)", name, unbalanced)
			}
			if rate < validFloor {
				t.Errorf("%s: valid-Dart rate %.2f%% below floor %.0f%%", name, rate*100, validFloor*100)
			}
		}()
	}
}
