package pipeline

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"aotopsy/internal/decompiler"
	"aotopsy/internal/samplecorpus"
)

// TestDecompileFidelityCensus is a measurement harness (NOT a gate; skipped
// unless AOTOPSY_FIDELITY=1). It runs the emitter over real functions on several
// samples across BOTH architectures and censuses the residual reconstruction
// defects by category, so the SSA/metadata/value-resolution work that follows is
// driven by measured gaps rather than guesswork.
//
//	AOTOPSY_FIDELITY=1 go test ./internal/pipeline/ -run TestDecompileFidelityCensus -v -timeout 60m
func TestDecompileFidelityCensus(t *testing.T) {
	if os.Getenv("AOTOPSY_FIDELITY") == "" {
		t.Skip("set AOTOPSY_FIDELITY=1 to run the fidelity census")
	}
	const perSampleCap = 400
	samples := []string{
		"dart-3.12.2-realapp-arm64.so",
		"dart-3.7.0-gopay-x64.so",
		"dart-3.9.2-gt-arm64.so",
		"dart-3.12.2-x64.so",
	}

	type cat struct {
		name string
		re   *regexp.Regexp
	}
	cats := []cat{
		{"rawReg", regexp.MustCompile(`\b([wx]\d{1,2}|r[a-d]x|rsi|rdi|rbp|r[89]|r1[0-5])\b`)},
		{"rawField", regexp.MustCompile(`\.f\d+\b`)},
		// THR-rooted `.fNN` (e.g. THR.field_table_values.f1760) is NOT an
		// instance-field-name failure; it pollutes rawField. Reported separately
		// so instance-field = rawField - thrField.
		{"thrField", regexp.MustCompile(`THR[\w.]*\.f\d+\b`)},
		{"poolUnresolved", regexp.MustCompile(`\(PP \+ \d+\)|\bpool\[`)},
		{"placeholderVal", regexp.MustCompile(`<[A-Za-z][\w ]*>`)},
		{"unresolvedCall", regexp.MustCompile(`indirectCall|\bsub_[0-9a-f]+|tailCall_|dynamicCall`)},
		{"argDump8", regexp.MustCompile(`arg0\b.*\barg7\b`)},
		{"mixinChain", regexp.MustCompile(` & _?[A-Za-z]`)},
		{"gotoLeak", regexp.MustCompile(`\bgoto \w|block_\d+:;`)},
	}

	for _, name := range samples {
		path := samplecorpus.Path(name)
		if path == "" {
			t.Logf("%s: absent", name)
			continue
		}
		ctx, err := LoadContext(path)
		if err != nil {
			t.Logf("%s: LoadContext: %v", name, err)
			continue
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
			var fns, lines int
			catFnHits := map[string]int{}  // functions containing >=1 hit
			catTokHits := map[string]int{} // total token hits
			var sumStats decompiler.Stats
			for _, r := range ctx.Ranges {
				if fns >= perSampleCap {
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
				fns++
				src := art.Source
				lines += strings.Count(src, "\n")
				sumStats.TotalCalls += art.Stats.TotalCalls
				sumStats.IndirectCalls += art.Stats.IndirectCalls
				sumStats.SemanticDirectCalls += art.Stats.SemanticDirectCalls
				sumStats.PlaceholderIfs += art.Stats.PlaceholderIfs
				sumStats.UnresolvedCF += art.Stats.UnresolvedCF
				sumStats.RawRegisterCalls += art.Stats.RawRegisterCalls
				for _, c := range cats {
					m := c.re.FindAllStringIndex(src, -1)
					if len(m) > 0 {
						catFnHits[c.name]++
						catTokHits[c.name] += len(m)
					}
				}
			}
			t.Logf("=== %s: %d fns, %d lines ===", name, fns, lines)
			names := make([]string, 0, len(cats))
			for _, c := range cats {
				names = append(names, c.name)
			}
			sort.Slice(names, func(i, j int) bool { return catTokHits[names[i]] > catTokHits[names[j]] })
			for _, n := range names {
				pctFn := 0.0
				if fns > 0 {
					pctFn = 100 * float64(catFnHits[n]) / float64(fns)
				}
				t.Logf("  %-16s fns=%d (%.0f%%) tokens=%d", n, catFnHits[n], pctFn, catTokHits[n])
			}
			t.Logf("  Stats: calls=%d indirect=%d semDirect=%d placeholderIf=%d unresolvedCF=%d rawRegCall=%d",
				sumStats.TotalCalls, sumStats.IndirectCalls, sumStats.SemanticDirectCalls,
				sumStats.PlaceholderIfs, sumStats.UnresolvedCF, sumStats.RawRegisterCalls)
		}()
	}
}
