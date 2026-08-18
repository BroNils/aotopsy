package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"aotopsy/internal/samplecorpus"
)

// Cross-version differential.
//
// Every other gate in this project compares the analyser against ITSELF. The
// golden records compare a version's output to that version's previous output,
// so a version that has been wrong since the day it was added stays green
// forever. That is not hypothetical: ParseDispatchTable could not read the
// roots section on nine supported Dart versions, which silently disabled the
// entire type-inference stage, and no gate noticed because no sample in the
// affected range existed and golden had nothing to compare against anyway.
//
// This one compares a version against its SIBLINGS. The samples in a
// samplecorpus source set were compiled from byte-identical lib/*.dart by
// different SDKs, so the analyser should recover broadly the same facts from
// all of them. Where it does not, the difference is a property of this tool,
// not of the app.
//
// The distinction that makes it usable:
//
//   - a metric that is ZERO on one sibling and substantial on another means a
//     stage produced nothing at all. That is unambiguous and fails.
//   - a metric that merely DIFFERS is expected -- Dart changes what it emits
//     between releases -- so ratios are reported, not enforced.
//
// Running it needs the samples, which are gitignored:
//
//	go test ./internal/pipeline/ -run CrossVersion -v

// knownGap records a metric that is legitimately zero-or-near-zero on some
// versions for a reason that has been MEASURED but not yet explained, so the
// differential reports it loudly instead of failing.
//
// An entry is a debt, not a dismissal: it needs a written reason and it should
// shrink. Nothing gets added here because it is inconvenient -- the roots
// section, Type capture, stub names and Thread offsets were all real bugs this
// harness found, and every one of them was fixed rather than listed.
type knownGap struct {
	metric   string
	versions []string
	reason   string
}

var knownGaps = []knownGap{
	{
		metric: "field_type_declared_hits",
		versions: []string{"2.14.0/arm64", "2.14.0/x64", "2.16.0/arm64", "2.16.0/x64",
			"2.17.6/arm64", "2.17.6/x64", "2.18.0/arm64", "2.18.0/x64",
			"2.19.0/arm64", "2.19.0/x64", "3.1.0/arm64", "3.1.0/x64",
			"3.3.0/arm64", "3.3.0/x64"},
		reason: "Every field metric collapses to 1-3% across the whole <=3.3.0 group, " +
			"not just where it happens to hit exactly zero: field_accessor_xref is " +
			"30-37 against 1708-1792, and field_type_instance_hits 121-341 against " +
			"10434-10914. The cliff sits exactly at the 3.3.0/3.4.3 boundary. " +
			"Measured so far: the field maps themselves are healthy on both sides " +
			"(FieldByOwnerOffset 82-107 classes, 160-219 entries joinable to a " +
			"resolved type), and the hit RATE when FieldValueClass is called is " +
			"actually better on 2.17.6 (6.3%) than on 3.9.2 (4.6%). What is scarce " +
			"is KnownClass receivers: FieldValueClass is called 9860 times on 2.17.6 " +
			"and 307594 on 3.9.2. So the cause is upstream of field handling, in how " +
			"often a receiver register carries a known class, and it is not yet " +
			"explained. Recorded rather than guessed at.",
	},
	{
		metric:   "dispatch_hits",
		versions: []string{"2.14.0/x64", "2.16.0/x64", "2.17.6/x64", "2.18.0/x64"},
		reason: "x86_64 dispatch-table type inference produces nothing at all on Dart " +
			"2.14.0 through 2.18.0, while the SAME source on arm64 gives 192158 hits " +
			"and the dispatch table itself parses fine on both (21000-26000 entries). " +
			"So the table is read and then never used: the x86 handler does not " +
			"recognise the pre-2.19 dispatch-call shape. Found by the architecture " +
			"axis of this differential, which is the only thing that could have: " +
			"comparing x64 against x64 across versions shows a smooth curve, and " +
			"comparing one arch against its own past shows nothing.",
	},
	{
		metric:   "blr_monomorphic",
		versions: []string{"2.14.0/x64", "2.16.0/x64", "2.17.6/x64", "2.18.0/x64"},
		reason: "Downstream of the dispatch_hits gap above: with no dispatch-table " +
			"resolution there is no single-callee site to report. Expected to close " +
			"with it.",
	},
}

func gapAllows(metric, version string) (string, bool) {
	for _, g := range knownGaps {
		if g.metric != metric {
			continue
		}
		for _, v := range g.versions {
			if v == version {
				return g.reason, true
			}
		}
	}
	return "", false
}

// crossVersionMetric is one number compared across siblings.
type crossVersionMetric struct {
	name string
	// get returns the value, or -1 when the sample did not produce it at all.
	get func(m *sampleMetrics) int
	// deadFloor is the value a SIBLING must exceed before a zero here counts
	// as a dead stage. It guards against flagging metrics that are legitimately
	// zero everywhere on a small app.
	deadFloor int
}

// sampleMetrics holds one sample's measured facts.
type sampleMetrics struct {
	version string
	arch    string
	lines   map[string]int
	report  map[string]any
}

func (m *sampleMetrics) line(f string) int {
	if v, ok := m.lines[f]; ok {
		return v
	}
	return -1
}

func (m *sampleMetrics) reportInt(path ...string) int {
	var cur any = m.report
	for _, p := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return -1
		}
		cur, ok = obj[p]
		if !ok {
			// A JSON number omitted by omitempty IS zero, not absent. The
			// report writer uses omitempty on every counter, so a missing key
			// means the counter never incremented -- which is precisely the
			// "stage produced nothing" signal this test is looking for.
			return 0
		}
	}
	f, ok := cur.(float64)
	if !ok {
		return -1
	}
	return int(f)
}

var crossVersionMetrics = []crossVersionMetric{
	{"functions", func(m *sampleMetrics) int { return m.line("functions.jsonl") }, 100},
	{"classes", func(m *sampleMetrics) int { return m.line("classes.jsonl") }, 100},
	{"call_edges", func(m *sampleMetrics) int { return m.line("call_edges.jsonl") }, 100},
	{"string_refs", func(m *sampleMetrics) int { return m.line("string_refs.jsonl") }, 100},
	{"dispatch_table", func(m *sampleMetrics) int { return m.line("dispatch_table.jsonl") }, 100},
	{"field_accessor_xref", func(m *sampleMetrics) int { return m.line("field_accessor_xref.jsonl") }, 100},
	{"string_value_xref", func(m *sampleMetrics) int { return m.line("string_value_xref.jsonl") }, 100},
	{"address_callers_xref", func(m *sampleMetrics) int { return m.line("address_callers_xref.jsonl") }, 100},
	{"pool_immediates", func(m *sampleMetrics) int { return m.line("pool_immediates.jsonl") }, 20},

	{"blr_total", func(m *sampleMetrics) int { return m.reportInt("blr", "total") }, 100},
	{"blr_monomorphic", func(m *sampleMetrics) int { return m.reportInt("blr", "monomorphic") }, 50},
	{"blr_stub", func(m *sampleMetrics) int { return m.reportInt("blr", "stub") }, 5},
	{"pool_hits", func(m *sampleMetrics) int { return m.reportInt("pool_hits") }, 1000},
	{"header_hits", func(m *sampleMetrics) int { return m.reportInt("header_hits") }, 100},
	{"dispatch_hits", func(m *sampleMetrics) int { return m.reportInt("dispatch_hits") }, 50},
	{"field_type_declared_hits", func(m *sampleMetrics) int { return m.reportInt("field_type_declared_hits") }, 100},
	{"field_type_instance_hits", func(m *sampleMetrics) int { return m.reportInt("field_type_instance_hits") }, 100},
	{"field_type_store_hits", func(m *sampleMetrics) int { return m.reportInt("field_type_store_hits") }, 100},
	{"selector_monomorphic_count", func(m *sampleMetrics) int { return m.reportInt("selector_monomorphic_count") }, 20},
	{"func_return_type_count", func(m *sampleMetrics) int { return m.reportInt("func_return_type_count") }, 20},
}

func TestCrossVersionDifferential(t *testing.T) {
	sets := samplecorpus.SourceSets()
	if len(sets) == 0 {
		t.Skip("no source set with two or more members in samplecorpus.Registry")
	}
	names := make([]string, 0, len(sets))
	for n := range sets {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, setName := range names {
		setName := setName
		t.Run(setName, func(t *testing.T) {
			measured := make([]*sampleMetrics, 0, len(sets[setName]))
			for _, s := range sets[setName] {
				path := samplecorpus.Path(s.FileName())
				if path == "" {
					t.Logf("skipping %s: %s", s.FileName(), samplecorpus.MissingMessage(s))
					continue
				}
				if s.ProfileIncomplete != "" {
					t.Logf("skipping %s: %s", s.FileName(), s.ProfileIncomplete)
					continue
				}
				m := measureCrossVersion(t, s, path)
				if m != nil {
					measured = append(measured, m)
				}
			}
			if len(measured) < 2 {
				t.Skipf("source set %q has %d sample(s) present; a differential needs two",
					setName, len(measured))
			}
			// Deterministic AND readable: version first, then architecture.
			// sort.Slice is not stable, so sorting on version alone left the
			// arm64/x64 columns in a different order per version and the table
			// could not be read at all.
			sort.Slice(measured, func(i, j int) bool {
				if measured[i].version != measured[j].version {
					return versionLess(measured[i].version, measured[j].version)
				}
				return measured[i].arch < measured[j].arch
			})
			reportCrossVersion(t, measured)
		})
	}
}

func measureCrossVersion(t *testing.T, s samplecorpus.Sample, path string) *sampleMetrics {
	t.Helper()
	outDir := t.TempDir()
	result, err := Run(Opts{
		LibPath:  path,
		OutDir:   outDir,
		Quiet:    true,
		Signal:   false,
		MaxSteps: 100000,
	})
	if err != nil {
		t.Errorf("%s: pipeline failed: %v", s.FileName(), err)
		return nil
	}
	if result.DartVersion != s.DartVersion {
		t.Errorf("%s", samplecorpus.VersionMismatch(s, result.DartVersion))
		return nil
	}

	m := &sampleMetrics{version: s.DartVersion, arch: s.Arch, lines: map[string]int{}}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("read %s: %v", outDir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(outDir, e.Name()))
		if err != nil {
			continue
		}
		m.lines[e.Name()] = strings.Count(string(data), "\n")
	}
	if data, err := os.ReadFile(filepath.Join(outDir, "typetrack_report.json")); err == nil {
		if err := json.Unmarshal(data, &m.report); err != nil {
			t.Errorf("%s: parse typetrack_report.json: %v", s.FileName(), err)
		}
	} else {
		// Not "no findings" -- the type-inference stage did not complete. That
		// is how the roots-section bug presented on nine Dart versions.
		t.Errorf("%s: no typetrack_report.json; the type-inference stage did not "+
			"finish. Run the pipeline without --quiet to see why.", s.FileName())
	}
	return m
}

func reportCrossVersion(t *testing.T, ms []*sampleMetrics) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "same Dart source, %d SDK versions:\n", len(ms))
	fmt.Fprintf(&b, "  %-28s", "metric")
	for _, m := range ms {
		fmt.Fprintf(&b, "%14s", m.version+"/"+m.arch)
	}
	b.WriteString("\n")

	type deadStage struct {
		metric string
		zeroAt []string
		best   int
		bestAt string
	}
	var dead []deadStage

	for _, met := range crossVersionMetrics {
		vals := make([]int, len(ms))
		best, bestAt := -1, ""
		for i, m := range ms {
			vals[i] = met.get(m)
			if vals[i] > best {
				best, bestAt = vals[i], m.version
			}
		}
		fmt.Fprintf(&b, "  %-28s", met.name)
		for _, v := range vals {
			if v < 0 {
				fmt.Fprintf(&b, "%14s", "-")
			} else {
				fmt.Fprintf(&b, "%14d", v)
			}
		}
		b.WriteString("\n")

		if best < met.deadFloor {
			continue // too small anywhere to call a zero meaningful
		}
		var zeroAt []string
		for i, v := range vals {
			if v == 0 {
				zeroAt = append(zeroAt, ms[i].version+"/"+ms[i].arch)
			}
		}
		if len(zeroAt) > 0 {
			dead = append(dead, deadStage{met.name, zeroAt, best, bestAt})
		}
	}
	t.Log(b.String())

	for _, d := range dead {
		// A gap every listed version shares is a documented debt; one that
		// shows up somewhere else is new and fails.
		allowed := true
		var reason string
		for _, v := range d.zeroAt {
			r, ok := gapAllows(d.metric, v)
			if !ok {
				allowed = false
				break
			}
			reason = r
		}
		if allowed {
			t.Logf("KNOWN GAP: %s is 0 on Dart %s (best sibling: %d on %s).\n  %s",
				d.metric, strings.Join(d.zeroAt, ", "), d.best, d.bestAt, reason)
			continue
		}
		t.Errorf("%s is 0 on Dart %s but %d on Dart %s, from the SAME source.\n"+
			"  A metric that is zero on one sibling and substantial on another is a\n"+
			"  stage that produced nothing, not a difference between Dart releases.\n"+
			"  Verify against dart-lang/sdk at both versions before changing anything:\n"+
			"  the fix is usually a version boundary that the code puts in the wrong\n"+
			"  place, not the feature being genuinely absent.",
			d.metric, strings.Join(d.zeroAt, ", "), d.best, d.bestAt)
	}
}

func versionLess(a, b string) bool {
	pa, pb := versionTriple(a), versionTriple(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func versionTriple(s string) [3]int {
	var v [3]int
	for i, part := range strings.SplitN(s, ".", 3) {
		if i >= 3 {
			break
		}
		n := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		v[i] = n
	}
	return v
}
