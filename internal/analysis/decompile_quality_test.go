package analysis

import (
	"strings"
	"testing"

	"aotopsy/internal/decompiler"
	"aotopsy/internal/samplecorpus"
)

// TestDecompileQualityCorpus is the corpus-wide decompiler quality gate that the
// synthetic tests in internal/decompiler could not be (audit F1). It runs the
// real emitter over real functions from real samples, BOTH architectures, and
// enforces two regression invariants:
//
//  1. Dart validity: the fraction of emitted functions that pass ValidateSource
//     stays above a floor. The regex idiom passes can produce invalid Dart on
//     real (multi-arg, placeholder-laden) output; this catches that.
//  2. No fabrication markers: the aggregate output must not contain the specific
//     fabrications the audit removed -- an anonymous closure rewritten to a
//     synthesized `=>` lambda (A3), or an `<Array>` placeholder rewritten to an
//     empty `[]` literal (A1). These are checked as exact-shape signatures so a
//     legitimate lambda or list literal elsewhere does not trip them.
//
// It is bounded (a few samples, capped functions each) to stay within the host's
// memory and time budget, like the symtab gate.
func TestDecompileQualityCorpus(t *testing.T) {
	const perSampleCap = 120
	// One arm64 + one x64 ground-truth sample keeps both backends covered.
	targets := []string{"dart-3.9.2-gt-arm64.so", "dart-3.12.2-x64.so"}

	var totalFns, validFns int
	var fabricatedLambda, fabricatedEmptyList int
	covered := 0

	for _, name := range targets {
		path := samplecorpus.Path(name)
		if path == "" {
			continue
		}
		covered++
		ctx, err := LoadContext(path)
		if err != nil {
			t.Fatalf("%s: LoadContext: %v", name, err)
		}
		func() {
			defer func() { _ = ctx.Close() }()
			symbolLookup := func(va uint64) (string, bool) {
				s, ok := ctx.SymbolNames[va]
				return s, ok && s != ""
			}
			poolLookup := func(idx int) (string, bool) {
				s, ok := ctx.PoolDisplay[idx]
				return s, ok
			}
			emitted := 0
			for _, r := range ctx.Ranges {
				if emitted >= perSampleCap {
					break
				}
				if r.Size == 0 || r.RefID < 0 {
					continue
				}
				fir, err := ctx.FuncIRFor(r)
				if err != nil || fir == nil {
					continue
				}
				art := decompiler.EmitPseudocode(fir, symbolLookup, poolLookup)
				emitted++
				totalFns++
				if len(decompiler.ValidateSource(art.Source)) == 0 {
					validFns++
				}
				src := art.Source
				// A3 fabrication signature: a synthesized lambda sitting where an
				// anonymous closure reference was.
				if strings.Contains(src, "(item) => ") {
					fabricatedLambda++
				}
				// A1 fabrication signature: an `<Array>` placeholder must never be
				// turned into `[]`. If the placeholder is preserved this stays 0.
				if strings.Contains(src, "return [];") && strings.Contains(src, "Array") {
					fabricatedEmptyList++
				}
			}
			t.Logf("%s: emitted=%d", name, emitted)
		}()
	}

	if covered == 0 {
		t.Skip("no target sample present on disk")
	}
	if totalFns == 0 {
		t.Fatal("no functions emitted")
	}

	validRate := float64(validFns) / float64(totalFns)
	t.Logf("decompile quality: %d fns, %.1f%% valid Dart, fabricatedLambda=%d fabricatedEmptyList=%d",
		totalFns, validRate*100, fabricatedLambda, fabricatedEmptyList)

	// Fabrication invariants are hard zero -- these transforms were removed.
	if fabricatedLambda > 0 {
		t.Errorf("A3 regression: %d functions contain a synthesized `(item) =>` lambda", fabricatedLambda)
	}
	if fabricatedEmptyList > 0 {
		t.Errorf("A1 regression: %d functions turned an <Array> placeholder into []", fabricatedEmptyList)
	}

	// Validity floor: a REGRESSION gate. Calibrated just under the measured rate.
	// Raise this whenever the emitter improves; never lower it silently.
	const minValidRate = 0.95
	if validRate < minValidRate {
		t.Errorf("Dart validity %.1f%% < %.1f%% floor", validRate*100, minValidRate*100)
	}
}
