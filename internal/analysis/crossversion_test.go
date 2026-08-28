package analysis

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
//   - a metric that DIPS against the versions either side of it, on the same
//     architecture -- under a fifth of their median -- means a stage mostly
//     produced nothing there. That fails. Zero is the extreme case of a dip,
//     not a separate rule.
//   - a metric that merely DIFFERS, or that STEPS from one Dart era to the
//     next, is expected -- Dart changes what it emits between releases -- so
//     ratios are reported, not enforced.
//
// The rule was "exactly zero" until 36 columns made its blind spot obvious:
// blr_monomorphic on 2.16.0/x64 read 15 against same-arch neighbours of 287,
// 294, 133 and 127, and the gate said nothing because 15 is not 0.
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

// Background on the (now-closed) arity/receiver cliff, kept because it explains
// why the recovery in receiver_recovery.go was needed and why 2.14.0 still
// differs.
//
// Before 3.4.3 there is no register calling convention: the receiver arrives
// on the caller's stack at FP + (1 + num_fixed_parameters) * 8, so seeding
// `this` -- and therefore every declared/instance/stored field type reached
// through it -- needs num_fixed_parameters. The SDK removed that number from
// the Function object in two steps:
//
//	2.12.0  UntaggedFunction.packed_fields_ is uint32_t and carries the counts
//	2.13.0  same layout (verified identical in raw_object.h), but the compiler
//	        has begun moving arity onto the new FunctionType
//	2.14.0  packed_fields_ becomes AtomicBitFieldContainer<uint8_t> and carries
//	        no counts at all; arity lives only on FunctionType
//
// and FunctionType is reached through WSR_COMPRESSED_POINTER_FIELD(signature),
// a WeakSerializationReference. app_snapshot.cc is explicit that "No WSRs are
// serialized": when the target is not otherwise reachable it is replaced,
// which deserialises as null. Measured on these samples -- the count of
// Functions whose packed_fields_ still yields an arity, and the share of
// named Codes that end up with FixedParamsWithReceiver:
//
//	2.12.0   7202 of 7573   84%
//	2.13.0   4169 of 7645   51%
//	2.14.0      0 of 7455   14%   (the 14% come from surviving signatures)
//	3.3.0       0 of 7518   12%
//
// On 3.4.3 and later the receiver is in a register and none of this is needed,
// which is exactly where the metrics jump back: field_type_declared_hits goes
// 1782 (3.3.0) -> 13465 (3.4.3) on arm64.
//
// This cliff is now CLOSED by CODE-based receiver-slot recovery
// (typetrack.RecoverReceiverStackSlot*, wired in typetrack_stage.go): when the
// snapshot lacks num_fixed_parameters, the receiver slot is recovered as the
// highest frame-pointer load offset whose loaded register is used as the base of
// an owner-class field access (the second condition rules out static methods, so
// owner field names are never fabricated). Measured on 3.3.0/arm64:
// field_type_declared_hits 1782 -> 12925, matching the 3.4.3 register-convention
// band, and the resolved fields match the 3.4.3 output for the same source. So
// field_type_declared/instance/accessor no longer collapse on 2.15..3.3.0.
//
// Two residual gaps remain, both distinct from the (now-fixed) receiver cliff:
const storeResidualReason = "field_type_store_hits tracks store->load field-type " +
	"propagation, a separate and sparser mechanism than receiver-based field-type " +
	"resolution; the receiver-slot recovery that closed declared/instance hits does " +
	"not feed it, so 3.3.0 store hits stay below the same-source median."

// 2.14.0 is the LAST uncompressed-pointer Dart version (2.15 enabled pointer
// compression). The receiver IS recovered there -- field ACCESSES resolve with
// correct class ids (field_accessor_xref is populated) -- but the field's
// DECLARED TYPE does not resolve: FieldTypes ends up empty because the
// uncompressed era resolves Field.TypeRefID -> Type -> ClassID differently, the
// same family of Type-object boundary bugs already recorded for 2.16-2.19. This
// is a separate, not-yet-root-caused issue in Type resolution, NOT the receiver
// cliff, and it affects only this single version.
const uncompressedTypeResolutionReason = "2.14.0 is the last uncompressed-pointer " +
	"version; its receiver is recovered (field accesses resolve) but the field's " +
	"declared TYPE does not (FieldTypes empty -- uncompressed-era Field.TypeRefID -> " +
	"Type -> ClassID resolution, same family as the 2.16-2.19 Type boundary bugs). " +
	"Separate from the receiver cliff; not yet root-caused."

var knownGaps = []knownGap{
	{metric: "field_type_store_hits", versions: []string{"3.3.0/arm64", "3.3.0/x64", "2.13.0/x64"}, reason: storeResidualReason},
	{metric: "field_type_declared_hits", versions: []string{"2.14.0/arm64", "2.14.0/x64"}, reason: uncompressedTypeResolutionReason},
	{metric: "field_type_instance_hits", versions: []string{"2.14.0/arm64", "2.14.0/x64"}, reason: uncompressedTypeResolutionReason},
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
	// fallback marks a counter that measures LEFTOVERS -- work the primary
	// path did not do. Zero on such a counter means the primary path covered
	// everything, which is the best outcome, not a dead stage. Still shown in
	// the table; never flagged.
	//
	// blr_stub is the case that forced this distinction. Its three increments
	// all sit in the `else` arms after the type tracker's own resolution map
	// misses, so it counts BLR edges rescued by the THR-via and pool-display
	// fallbacks. On the 2.10.0 arm64 sample all 116 THR-via BLR edges already
	// carried a target from the tracker, leaving the fallback nothing to
	// rescue: 335 monomorphic + 0 stub. On 2.12.0, 991 + 14. Reading that 0 as
	// a dead stage inverts its meaning.
	fallback bool
	// confidence marks a counter that goes UP when the resolver guesses and
	// DOWN when it is honest. Such a counter is still checked for ZERO -- that
	// really is a dead stage -- but never for a mere collapse, because a
	// collapse there can be an improvement.
	//
	// blr_monomorphic is the case that forced this, and it forced it twice.
	// §2 of docs/ROADMAP.md records the first: on 3.12.2 arm64 the old
	// resolver claimed 2271 monomorphic sites whose true candidate count is a
	// median of 208 and never 1. The second is 2.16.0/x64, which the collapse
	// rule accused the moment it was added -- 15 against same-arch neighbours
	// of 287, 294, 133, 127. Measured, it is not a defect at all:
	//
	//	          total   mono   poly   stub   unres   resolved
	//	2.15.0    11467    294   2915   7100    1158     89.9%
	//	2.16.0    11256     15   3156   7097     988     91.2%
	//	2.17.6    11379    133   3304   6976     966     91.5%
	//
	// The 279 "missing" monomorphic sites went to polymorphic (+241) and
	// unresolved fell by 170. 2.16.0 resolves MORE than 2.15.0 overall. Its
	// dispatch table parses (20744 entries), its arm64 sibling is healthy
	// (857 monomorphic), the instruction shapes at dispatch sites are
	// identical across all three versions (3564/3566/3779 sites, same
	// base-register distribution), and every type source feeding it is
	// comparable. There was nothing to fix.
	//
	// dispatch_hits carries the flag for the same reason: it counts direct
	// slot resolutions, so it falls when slots legitimately resolve to a
	// scan instead. It stays zero-checked because zero there WAS a real bug
	// -- 0 on x64 for 2.13-2.18 until the 16-bit class-id load was fixed.
	confidence bool
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
	{name: "functions", get: func(m *sampleMetrics) int { return m.line("functions.jsonl") }, deadFloor: 100},
	{name: "classes", get: func(m *sampleMetrics) int { return m.line("classes.jsonl") }, deadFloor: 100},
	{name: "call_edges", get: func(m *sampleMetrics) int { return m.line("call_edges.jsonl") }, deadFloor: 100},
	{name: "string_refs", get: func(m *sampleMetrics) int { return m.line("string_refs.jsonl") }, deadFloor: 100},
	{name: "dispatch_table", get: func(m *sampleMetrics) int { return m.line("dispatch_table.jsonl") }, deadFloor: 100},
	{name: "field_accessor_xref", get: func(m *sampleMetrics) int { return m.line("field_accessor_xref.jsonl") }, deadFloor: 100},
	{name: "string_value_xref", get: func(m *sampleMetrics) int { return m.line("string_value_xref.jsonl") }, deadFloor: 100},
	{name: "address_callers_xref", get: func(m *sampleMetrics) int { return m.line("address_callers_xref.jsonl") }, deadFloor: 100},
	{name: "pool_immediates", get: func(m *sampleMetrics) int { return m.line("pool_immediates.jsonl") }, deadFloor: 20},

	{name: "blr_total", get: func(m *sampleMetrics) int { return m.reportInt("blr", "total") }, deadFloor: 100},
	{name: "blr_monomorphic", get: func(m *sampleMetrics) int { return m.reportInt("blr", "monomorphic") }, deadFloor: 50, confidence: true},
	{name: "blr_stub", get: func(m *sampleMetrics) int { return m.reportInt("blr", "stub") }, deadFloor: 5, fallback: true},
	{name: "pool_hits", get: func(m *sampleMetrics) int { return m.reportInt("pool_hits") }, deadFloor: 1000},
	{name: "header_hits", get: func(m *sampleMetrics) int { return m.reportInt("header_hits") }, deadFloor: 100},
	{name: "dispatch_hits", get: func(m *sampleMetrics) int { return m.reportInt("dispatch_hits") }, deadFloor: 50, confidence: true},
	{name: "field_type_declared_hits", get: func(m *sampleMetrics) int { return m.reportInt("field_type_declared_hits") }, deadFloor: 100},
	{name: "field_type_instance_hits", get: func(m *sampleMetrics) int { return m.reportInt("field_type_instance_hits") }, deadFloor: 100},
	{name: "field_type_store_hits", get: func(m *sampleMetrics) int { return m.reportInt("field_type_store_hits") }, deadFloor: 100},
	{name: "selector_monomorphic_count", get: func(m *sampleMetrics) int { return m.reportInt("selector_monomorphic_count") }, deadFloor: 20},
	{name: "func_return_type_count", get: func(m *sampleMetrics) int { return m.reportInt("func_return_type_count") }, deadFloor: 20},
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

	var collapses []metricCollapse

	for _, met := range crossVersionMetrics {
		vals := make([]int, len(ms))
		for i, m := range ms {
			vals[i] = met.get(m)
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

		if met.fallback {
			continue
		}
		// Judge PER ARCHITECTURE. Several counters differ by one to three
		// orders of magnitude between arm64 and x86_64 by design, not by
		// defect -- blr_stub runs in the thousands on x64 and in the tens on
		// arm64 because the x64 compiler reaches stubs through a call the
		// ARM64 one inlines. Ranking against the best column of EITHER
		// architecture made every such counter look dead on arm64.
		// AGENTS.md records this trap; the gate has to honour it or it
		// manufactures work.
		for _, arch := range archesOf(ms) {
			collapses = append(collapses, collapsesIn(met.name, arch, met.deadFloor, met.confidence, ms, vals)...)
		}
	}
	t.Log(b.String())

	for _, c := range collapses {
		// A gap every listed version shares is a documented debt; one that
		// shows up somewhere else is new and fails.
		allowed := true
		var reason string
		for _, v := range c.at {
			r, ok := gapAllows(c.metric, v)
			if !ok {
				allowed = false
				break
			}
			reason = r
		}
		if allowed {
			t.Logf("KNOWN GAP: %s collapses on Dart %s (%s; %s median %d).\n  %s",
				c.metric, strings.Join(c.at, ", "), c.valueList(), c.arch, c.median, reason)
			continue
		}
		t.Errorf("%s collapses on Dart %s: %s, against a %s median of %d from the SAME source.\n"+
			"  A metric far below its same-architecture siblings is a stage that\n"+
			"  mostly produced nothing, not a difference between Dart releases --\n"+
			"  and zero is only the extreme case of that.\n"+
			"  Verify against dart-lang/sdk at both versions before changing anything:\n"+
			"  the fix is usually a version boundary that the code puts in the wrong\n"+
			"  place, not the feature being genuinely absent.",
			c.metric, strings.Join(c.at, ", "), c.valueList(), c.arch, c.median)
	}
}

// metricCollapse is one metric that fell far below its same-architecture
// siblings on one or more samples.
type metricCollapse struct {
	metric string
	arch   string
	at     []string // "<version>/<arch>" of each collapsed sample
	vals   []int    // their values, parallel to at
	median int      // the same-arch median they are judged against
}

func (c metricCollapse) valueList() string {
	parts := make([]string, len(c.vals))
	for i, v := range c.vals {
		parts[i] = fmt.Sprintf("%s=%d", c.at[i], v)
	}
	return strings.Join(parts, ", ")
}

// collapseRatio is how far below its neighbours a value must fall to be
// accused: v*collapseRatio < neighbourMedian, i.e. under 20%.
//
// The gate used to accuse ONLY exact zeros. That let a real defect through in
// plain sight: with 36 columns, blr_monomorphic on 2.16.0/x64 read 15 while
// its same-architecture neighbours read 287, 294, 133 and 127 -- a ~20x drop
// the gate had no opinion about, because 15 is not 0. Zero is not the only
// shape a dead stage takes; it is just the shape that is easy to test for.
const collapseRatio = 5

// collapseNeighbours is how many same-arch siblings on each side form the
// yardstick.
//
// The yardstick is NEIGHBOURING versions, not the whole row, and that
// distinction is the difference between a usable gate and a noisy one.
// Measured: judging against the whole same-arch median produced five
// accusations, and three were era-shaped rather than defect-shaped --
// pool_immediates sits at 15 on x64 for 2.14, 2.15 AND 2.16 while 3.x sits
// near 123, and field_type_store_hits steps down across six consecutive arm64
// versions. Those are Dart changing what it emits, which this harness
// explicitly does not enforce. A row median dominated by a different era
// accuses every version of the smaller era at once.
//
// A mis-placed version boundary -- the defect this gate exists to find --
// looks nothing like that. It is a LOCAL dip: one version far below the
// versions either side of it, which is exactly what 2.16.0/x64 is.
const collapseNeighbours = 2

// collapsesIn returns the collapsed samples of one architecture for one metric.
func collapsesIn(metric, arch string, deadFloor int, confidence bool, ms []*sampleMetrics, vals []int) []metricCollapse {
	// The same-arch row, in version order, carrying each sample's index.
	type cell struct {
		version string
		val     int
	}
	var row []cell
	for i, m := range ms {
		if m.arch == arch && vals[i] >= 0 {
			row = append(row, cell{m.version, vals[i]})
		}
	}
	if len(row) < 3 {
		// With one or two samples there is no "typical" to be far below; a
		// two-sample row would make each one the other's yardstick.
		return nil
	}
	sort.SliceStable(row, func(a, b int) bool { return versionLess(row[a].version, row[b].version) })

	var c metricCollapse
	c.metric, c.arch = metric, arch
	for i, cur := range row {
		var near []int
		for d := 1; d <= collapseNeighbours; d++ {
			if i-d >= 0 {
				near = append(near, row[i-d].val)
			}
			if i+d < len(row) {
				near = append(near, row[i+d].val)
			}
		}
		if len(near) < 2 {
			continue
		}
		med := medianOf(near)
		if med < deadFloor {
			continue // too small around here for a shortfall to mean anything
		}
		if confidence && cur.val != 0 {
			// See crossVersionMetric.confidence: a dip here can mean the
			// resolver stopped guessing. Only an outright zero is a defect.
			continue
		}
		if cur.val*collapseRatio < med {
			c.at = append(c.at, cur.version+"/"+arch)
			c.vals = append(c.vals, cur.val)
			c.median = med
		}
	}
	if len(c.at) == 0 {
		return nil
	}
	return []metricCollapse{c}
}

// medianOf returns the median of vals, which it sorts a copy of.
func medianOf(vals []int) int {
	s := append([]int(nil), vals...)
	sort.Ints(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// archesOf lists the architectures present, in stable order.
func archesOf(ms []*sampleMetrics) []string {
	seen := make(map[string]bool, 2)
	var out []string
	for _, m := range ms {
		if !seen[m.arch] {
			seen[m.arch] = true
			out = append(out, m.arch)
		}
	}
	sort.Strings(out)
	return out
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
