package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"aotopsy/internal/decompiler"
)

// Decompiler fidelity gate (P0 of .tmp/review/MASTER-PLAN.md).
//
// TestDecompileCorpus only proves the emitter does not die and keeps CFG
// coverage. It cannot see a decompiler that is structurally complete and
// semantically wrong -- `a ~/ b` rendered as a runtime-stub call, a string
// literal masked with `& 0xffffffff`, a `<SubtypeTestCache>` argument -- which
// is what the pseudocode actually looks like today.
//
// This test measures two things on the compare_sample ground truth (the
// app's own lib/*.dart, which the binaries were built from):
//
//   - RECALL of facts the source states and the binary must preserve: string
//     literals and calls to other app functions inside each function body.
//   - DEFECT counts: constructs that are never source, so they only go down.
//
// The facts are frozen in testdata/decompile_truth.json (extracted once from
// the sources by AOTOPSY_UPDATE_TRUTH=1) so the test needs the binaries but not
// the Dart project. Floors are measured values; raise recall floors and lower
// defect ceilings when the decompiler improves, never the reverse.

const truthFile = "testdata/decompile_truth.json"

type truthFunc struct {
	Literals []string `json:"literals,omitempty"`
	Callees  []string `json:"callees,omitempty"`
}

type truthSet struct {
	Source string               `json:"source"`
	Funcs  map[string]truthFunc `json:"funcs"`
}

// qualityFloors are the measured floors per sample (see the log line the test
// prints). Recall is a percentage (higher is better); defects are ceilings.
type qualityFloor struct {
	minLiteralRecall float64
	minCalleeRecall  float64
	maxDefects       map[string]int
}

// Measured (59 ground-truth functions each). History:
//
//	baseline (b031828):  arm64 lit 50.0 / x64 lit 45.2, masked_string 140/129, double_mask 6/58,
//	                     orphan 192/111, goto 362/384, local_mN 534/608
//	P4.1 (this file):    string/object literals no longer masked, redundant re-masks dropped,
//	                     x64 R8L..R15L (Go-syntax 32-bit view) aliased to their 64-bit register,
//	                     elided stack-overflow/write-barrier stub blocks no longer listed as orphans.
//
//	P4.2 (stmt_box.go):  BoxInt64 Smi-or-Mint diamonds collapsed after emission
//	                     (goto_block 277/285 -> 249/257, local_mN 534/544 -> 529/540,
//	                     x64 const_masked 29 -> 1). orphan_block is unchanged: orphans come
//	                     from the walk's depth budget, which runs BEFORE this text pass.
//	P4.4 (stmt_interp.go, + pure-goto diamond rule in stmt_box.go): string templates rebuilt from
//	                     the array element stores; `if (c) {L: X} else {goto L}` collapsed when c has
//	                     no call (what the array-store Smi/barrier check leaves behind): goto_block
//	                     249/257 -> 127/133, stack_sp_leak 144/146 -> 141/143, raw_register arm64
//	                     45 -> 41. interpolate_call (new counter) is 127 in these 59 functions
//	                     (call-valued and conditional pieces block the fold); across the first 3000
//	                     functions of the 3.9.2 sample the remaining `_interpolate(` calls went
//	                     253 -> 190 (arm64) and 255 -> 189 (x64), template strings 6/0 -> 54/56.
//
// x64 orphan_block went UP (111 -> 143) although the code shown is strictly more
// correct: with R11L aliased, the barrier/Smi diamonds around `_StringBase._interpolate`
// chains are recognised, the nesting reaches the walker's depth budget sooner and the
// join block is emitted verbatim as an orphan. Collapsing the Mint-box diamond
// (`if ((v>>30)+1 < 2) {..} else {AllocateMint..f7 = v}`) is P4.2 in
// .tmp/review/MASTER-PLAN.md and should bring this ceiling down.
var qualityFloors = map[string]qualityFloor{
	"dart-3.9.2-arm64.so": {
		minLiteralRecall: 50.0, minCalleeRecall: 80.0,
		maxDefects: map[string]int{
			"SubtypeTestCache_arg": 0, "const_masked": 6, "double_mask": 0, "dynamicCall_dispatchTarget": 2,
			"goto_block": 127, "interpolate_call": 127, "local_mN": 528, "masked_string_literal": 2, "orphan_block": 107,
			"raw_register": 41, "runtime_stub_call": 2, "stack_sp_leak": 141,
		},
	},
	"dart-3.9.2-x64.so": {
		minLiteralRecall: 52.3, minCalleeRecall: 80.0,
		maxDefects: map[string]int{
			"SubtypeTestCache_arg": 0, "const_masked": 1, "double_mask": 0, "dynamicCall_dispatchTarget": 0,
			"goto_block": 133, "interpolate_call": 127, "local_mN": 536, "masked_string_literal": 2, "orphan_block": 143,
			"raw_register": 0, "runtime_stub_call": 2, "stack_sp_leak": 143,
		},
	},
}

var defectPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"dynamicCall_dispatchTarget", regexp.MustCompile(`dynamicCall\(dispatchTarget`)},
	{"SubtypeTestCache_arg", regexp.MustCompile(`<SubtypeTestCache>`)},
	{"orphan_block", regexp.MustCompile(`orphan block`)},
	{"goto_block", regexp.MustCompile(`goto block_`)},
	{"local_mN", regexp.MustCompile(`\blocal_m\d+`)},
	{"masked_string_literal", regexp.MustCompile(`"\s*& 0xffffffff`)},
	{"double_mask", regexp.MustCompile(`& 0xffffffff & 0xffffffff`)},
	{"const_masked", regexp.MustCompile(`\((false|true|null|\d+) & 0x[0-9a-f]+\)`)},
	{"runtime_stub_call", regexp.MustCompile(`CallToRuntime\(`)},
	// A string interpolation still shown as the runtime call instead of a template.
	{"interpolate_call", regexp.MustCompile(`_StringBase\._interpolate(?:Single)?\(`)},
	{"stack_sp_leak", regexp.MustCompile(`\bstack_sp\b`)},
	{"raw_register", regexp.MustCompile(`\bx\d{1,2}\b`)},
}

var (
	reDartFnDecl = regexp.MustCompile(`(?m)^[ \t]*(?:static[ \t]+)?(?:[\w<>?,.\[\]]+[ \t]+)+(\w+)[ \t]*\([^;{}]*\)[ \t]*(?:async\*?[ \t]*)?\{`)
	reDartStr    = regexp.MustCompile(`'([^'$\\\n]{3,})'|"([^"$\\\n]{3,})"`)
	reDartCall   = regexp.MustCompile(`\b(\w+)[ \t]*\(`)
	reHashSuffix = regexp.MustCompile(`(?:_[0-9a-f]{3,}|@\d+)+$`)
)

var dartNotFn = map[string]bool{"if": true, "for": true, "while": true, "switch": true, "catch": true, "return": true}

// stripDartComments removes // and /* */ comments (not those inside string
// literals, e.g. the `//` of 'https://...') and @pragma(...) annotation lines,
// so a stray apostrophe in a comment cannot desynchronise the string scan.
func stripDartComments(src string) string {
	var b strings.Builder
	var quote byte
	for i := 0; i < len(src); i++ {
		c := src[i]
		if quote != 0 {
			b.WriteByte(c)
			if c == '\\' && i+1 < len(src) {
				i++
				b.WriteByte(src[i])
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch {
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return b.String()
			}
			i += end + 3
		case c == '\'' || c == '"':
			quote = c
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return rePragma.ReplaceAllString(b.String(), "")
}

var reHasAlnum = regexp.MustCompile(`[A-Za-z0-9]`)

var rePragma = regexp.MustCompile(`(?m)^[ \t]*@pragma\([^\n]*\)[ \t]*$`)

// matchBrace returns the index just past the brace block starting at src[open],
// skipping braces inside simple string literals.
func matchBrace(src string, open int) int {
	depth := 0
	var quote byte
	for i := open; i < len(src); i++ {
		c := src[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(src)
}

// extractTruth derives per-function facts from Dart sources. A name declared
// more than once is dropped: it cannot be matched to one binary function.
func extractTruth(srcs map[string]string) map[string]truthFunc {
	type fn struct{ name, body string }
	var fns []fn
	names := map[string]int{}
	files := make([]string, 0, len(srcs))
	for f := range srcs {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		src := stripDartComments(srcs[f])
		for _, m := range reDartFnDecl.FindAllStringSubmatchIndex(src, -1) {
			name := src[m[2]:m[3]]
			if dartNotFn[name] {
				continue
			}
			open := m[1] - 1
			fns = append(fns, fn{name, src[open:matchBrace(src, open)]})
			names[name]++
		}
	}
	out := map[string]truthFunc{}
	for _, f := range fns {
		if names[f.name] != 1 {
			continue
		}
		lits := map[string]bool{}
		for _, m := range reDartStr.FindAllStringSubmatch(f.body, -1) {
			s := m[1] + m[2]
			// Fragments between interpolations (": ", " (") are not facts.
			if reHasAlnum.MatchString(s) {
				lits[s] = true
			}
		}
		callees := map[string]bool{}
		for _, m := range reDartCall.FindAllStringSubmatch(f.body, -1) {
			if m[1] != f.name && names[m[1]] == 1 && !dartNotFn[m[1]] {
				callees[m[1]] = true
			}
		}
		out[f.name] = truthFunc{Literals: sortedKeys(lits), Callees: sortedKeys(callees)}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func loadOrBuildTruth(t *testing.T) truthSet {
	t.Helper()
	if os.Getenv("AOTOPSY_UPDATE_TRUTH") == "1" {
		home, _ := os.UserHomeDir()
		dir := filepath.Join(home, "dev", "compare_sample", "lib")
		srcs := map[string]string{}
		for _, f := range []string{"ground_truth.dart", "signal_ground_truth.dart", "main.dart"} {
			b, err := os.ReadFile(filepath.Join(dir, f))
			if err != nil {
				t.Fatalf("AOTOPSY_UPDATE_TRUTH=1 needs %s: %v", filepath.Join(dir, f), err)
			}
			srcs[f] = string(b)
		}
		ts := truthSet{Source: "compare_sample/lib/{ground_truth,signal_ground_truth,main}.dart", Funcs: extractTruth(srcs)}
		b, err := json.MarshalIndent(ts, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(truthFile, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s: %d functions", truthFile, len(ts.Funcs))
		return ts
	}
	b, err := os.ReadFile(truthFile)
	if err != nil {
		t.Fatalf("%s missing: regenerate with AOTOPSY_UPDATE_TRUTH=1 (needs ~/dev/compare_sample): %v", truthFile, err)
	}
	var ts truthSet
	if err := json.Unmarshal(b, &ts); err != nil {
		t.Fatal(err)
	}
	return ts
}

// bareFuncName maps a binary function name ("AntiInlineTools.safeDivide_b7a64")
// to the source name ("safeDivide").
func bareFuncName(n string) string {
	if i := strings.LastIndex(n, "."); i >= 0 {
		n = n[i+1:]
	}
	return reHashSuffix.ReplaceAllString(n, "")
}

type qualityResult struct {
	funcs                      int
	litHit, litTotal           int
	calleeHit, calleeTotal     int
	defects                    map[string]int
	missingLits, missingCallee []string
}

func measureQuality(t *testing.T, sampleName string, truth truthSet) qualityResult {
	t.Helper()
	ctx, err := LoadContext(corpusSample(t, sampleName))
	if err != nil {
		t.Fatalf("%s: LoadContext: %v", sampleName, err)
	}
	defer func() { _ = ctx.Close() }()
	sym := func(va uint64) (string, bool) {
		n, ok := ctx.SymbolNames[va]
		return n, ok && n != ""
	}
	poolLk := func(i int) (string, bool) { n, ok := ctx.PoolDisplay[i]; return n, ok }

	res := qualityResult{defects: map[string]int{}}
	seen := map[string]bool{}
	for _, cr := range ctx.Ranges {
		if cr.Size == 0 || cr.RefID < 0 {
			continue
		}
		fir, err := ctx.FuncIRFor(cr)
		if err != nil || fir == nil || len(fir.Blocks) == 0 {
			continue
		}
		name := bareFuncName(fir.Name)
		tf, ok := truth.Funcs[name]
		if !ok || seen[name] {
			continue
		}
		seen[name] = true
		res.funcs++
		src := decompiler.EmitPseudocode(fir, sym, poolLk).Source
		for _, l := range tf.Literals {
			res.litTotal++
			if strings.Contains(src, l) {
				res.litHit++
			} else {
				res.missingLits = append(res.missingLits, name+":"+l)
			}
		}
		for _, c := range tf.Callees {
			res.calleeTotal++
			if strings.Contains(src, c) {
				res.calleeHit++
			} else {
				res.missingCallee = append(res.missingCallee, name+"->"+c)
			}
		}
		for _, d := range defectPatterns {
			res.defects[d.name] += len(d.re.FindAllString(src, -1))
		}
	}
	return res
}

func pct(a, b int) float64 {
	if b == 0 {
		return 100
	}
	return 100 * float64(a) / float64(b)
}

func TestDecompileFidelityGroundTruth(t *testing.T) {
	if testing.Short() {
		t.Skip("decompile fidelity measurement is slow; skipped under -short")
	}
	truth := loadOrBuildTruth(t)
	for _, sampleName := range []string{"dart-3.9.2-arm64.so", "dart-3.9.2-x64.so"} {
		t.Run(sampleName, func(t *testing.T) {
			r := measureQuality(t, sampleName, truth)
			litR, calR := pct(r.litHit, r.litTotal), pct(r.calleeHit, r.calleeTotal)
			keys := make([]string, 0, len(r.defects))
			for k := range r.defects {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var dl []string
			for _, k := range keys {
				dl = append(dl, k+"="+itoa(r.defects[k]))
			}
			t.Logf("%s: %d ground-truth functions; literal recall %d/%d (%.1f%%); callee recall %d/%d (%.1f%%)\n  defects: %s",
				sampleName, r.funcs, r.litHit, r.litTotal, litR, r.calleeHit, r.calleeTotal, calR, strings.Join(dl, " "))
			if os.Getenv("AOTOPSY_QUALITY_VERBOSE") == "1" {
				t.Logf("missing literals: %v", r.missingLits)
				t.Logf("missing callees: %v", r.missingCallee)
			}
			if r.funcs == 0 {
				t.Fatalf("%s: none of the ground-truth functions was found in the binary", sampleName)
			}
			fl, ok := qualityFloors[sampleName]
			if !ok {
				t.Fatalf("%s: no measured floor registered in qualityFloors; copy the numbers logged above", sampleName)
			}
			if litR < fl.minLiteralRecall {
				t.Errorf("literal recall %.1f%% fell below floor %.1f%%", litR, fl.minLiteralRecall)
			}
			if calR < fl.minCalleeRecall {
				t.Errorf("callee recall %.1f%% fell below floor %.1f%%", calR, fl.minCalleeRecall)
			}
			for k, max := range fl.maxDefects {
				if r.defects[k] > max {
					t.Errorf("defect %s = %d exceeds ceiling %d", k, r.defects[k], max)
				}
			}
		})
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
