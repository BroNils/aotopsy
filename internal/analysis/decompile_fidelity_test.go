package analysis

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
		"dart-3.7.0-realapp2-x64.so",
		"dart-3.9.2-gt-arm64.so",
		"dart-3.12.2-x64.so",
	}

	type cat struct {
		name string
		re   *regexp.Regexp
	}
	// hexEscapeRe / commentRe strip measurement false-positives before the
	// category regexes run: `\x00` string-escape bytes match the rawReg pattern
	// as "x00" (140k phantom hits on the string-heavy gt-arm64 sample), and
	// register names listed inside generated `//` annotations are not
	// reconstruction defects. Neither is a real residual, so both are removed to
	// keep the census honest.
	hexEscapeRe := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	commentRe := regexp.MustCompile(`//[^\n]*`)
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
			distinctRawReg := 0
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
				// Census measures reconstruction defects in the pseudocode, not
				// in string literals or annotations; strip both first.
				src = commentRe.ReplaceAllString(hexEscapeRe.ReplaceAllString(src, ""), "")
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
				// Distinct rawReg leaks: a giant re-emitted state machine repeats
				// the SAME raw-register line many times, so the raw token count
				// over-states the true number of unresolved values. Counting
				// unique raw-register-bearing lines per function is the honest
				// fidelity figure (a single distinct defect counts once no matter
				// how often the structural walk duplicates its block).
				rr := cats[0].re // rawReg is cats[0]
				uniq := map[string]struct{}{}
				for _, ln := range strings.Split(src, "\n") {
					if rr.MatchString(ln) {
						uniq[strings.TrimSpace(ln)] = struct{}{}
					}
				}
				distinctRawReg += len(uniq)
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
			t.Logf("  rawReg(distinct-lines)=%d  [token count above over-counts re-emitted giants]", distinctRawReg)
		}()
	}
}
