package render

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"aotopsy/internal/disasm"
	"aotopsy/internal/signal"
)

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

func TestDotIDIsInjectiveForOldEscapeCollision(t *testing.T) {
	a := dotID("a-b")
	b := dotID("a_002db")
	if a == b {
		t.Fatalf("dotID collision: %q and %q both map to %q", "a-b", "a_002db", a)
	}
}

func TestTruncLabelPreservesUTF8(t *testing.T) {
	got := truncLabel("安全なラベル🙂abcdef", 8)
	if !utf8.ValidString(got) {
		t.Fatalf("truncLabel emitted invalid UTF-8: %q", got)
	}
	if utf8.RuneCountInString(got) != 8 {
		t.Fatalf("truncLabel rune count = %d, want 8: %q", utf8.RuneCountInString(got), got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("truncated label lacks ellipsis: %q", got)
	}
}

func TestTopNMapDeterministicTieBreak(t *testing.T) {
	m := map[string]int{"zeta": 7, "alpha": 7, "middle": 3}
	got := topNMap(m, 3)
	if len(got) != 3 || got[0].Name != "alpha" || got[1].Name != "zeta" || got[2].Name != "middle" {
		t.Fatalf("topNMap order = %+v, want count desc/name asc", got)
	}
	if got := topNMap(m, 0); got != nil {
		t.Fatalf("topNMap(..., 0) = %+v, want nil", got)
	}
}

func TestHTMLWritersPropagateShortWrites(t *testing.T) {
	if err := WriteIndexHTML(shortWriter{}, CallgraphStats{}, nil, "title", false, false, false, nil, 0, 0, nil); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteIndexHTML short write error = %v, want io.ErrShortWrite", err)
	}
	g := &signal.SignalGraph{Stats: signal.SignalStats{Categories: map[string]int{}}}
	if err := WriteSignalHTML(shortWriter{}, g, "title", "file", "digest", nil, nil); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteSignalHTML short write error = %v, want io.ErrShortWrite", err)
	}
}

func TestIndexHTMLUsesCanonicalCFGLink(t *testing.T) {
	const name = "ShortcutManager.handleKeypress.#action#initializer_1000"
	links := map[string]string{
		name: "cfg/ShortcutManager/#action#initializer_1000.svg",
	}
	var out bytes.Buffer
	if err := WriteIndexHTML(&out, CallgraphStats{}, nil, "title", false, false, false, []string{name}, 1, 1, links); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	if !strings.Contains(html, `href="cfg/ShortcutManager/%23action%23initializer_1000.svg"`) {
		t.Fatalf("canonical nested CFG link missing:\n%s", html)
	}
	if strings.Contains(html, `ShortcutManager.handleKeypress.#action#initializer_1000.svg`) {
		t.Fatalf("index reconstructed CFG path from display name:\n%s", html)
	}
}

func TestSignalHTMLKeepsArtifactStringsOutOfScriptSource(t *testing.T) {
	payload := `x');document.body.dataset.pwned='1` + "</script><img src=x onerror=alert(1)>"
	g := &signal.SignalGraph{
		Funcs: []signal.SignalFunc{{
			Name:       payload,
			Owner:      "__proto__",
			Role:       "signal",
			Severity:   "high",
			Categories: []string{payload},
			StringRefs: []signal.ClassifiedStringRef{{PC: payload, Value: payload, Categories: []string{payload}}},
		}},
		Stats: signal.SignalStats{SignalFuncs: 1, TotalFuncs: 1, Categories: map[string]int{payload: 1}},
	}
	var out bytes.Buffer
	if err := WriteSignalHTML(&out, g, "title", "file", "digest", map[string]string{payload: payload}, map[string]string{payload: "../asm/safe.txt"}); err != nil {
		t.Fatalf("WriteSignalHTML: %v", err)
	}
	html := out.String()
	if strings.Contains(html, payload) {
		t.Fatalf("attacker-controlled graph data leaked into HTML/JS source context")
	}
	for _, dangerous := range []string{`onclick="revealAndScroll(`, `onclick="scrollAsm(`} {
		if strings.Contains(html, dangerous) {
			t.Fatalf("dynamic inline handler survived hardening: %s", dangerous)
		}
	}
	if !strings.Contains(html, "Object.create(null)") {
		t.Fatal("signal HTML no longer hardens user-keyed dictionaries")
	}
}

func TestCFGDOTPreservesAllPolymorphicTargets(t *testing.T) {
	edges := []disasm.CallEdgeRecord{{
		FromFunc: "Foo.bar", FromPC: "0x1008", Kind: "blr",
		Targets: []string{"Impl.one", "Impl.two"}, Candidates: 2,
	}}
	dot := CFGDOT(twoBlockCFG(), edges, NASA)
	for _, target := range []string{"Impl.one", "Impl.two"} {
		if !strings.Contains(dot, target) || !strings.Contains(dot, "bb1 -> "+dotID(target)) {
			t.Fatalf("polymorphic target %q missing from CFG DOT:\n%s", target, dot)
		}
	}
}

func TestSignalDOTKeepsDeepIndirectPath(t *testing.T) {
	g := &signal.SignalGraph{}
	g.Funcs = append(g.Funcs, signal.SignalFunc{Name: "root"})
	prev := "root"
	for i := 0; i < 12; i++ {
		name := "ctx_" + string(rune('a'+i))
		g.Funcs = append(g.Funcs, signal.SignalFunc{Name: name, Role: "context"})
		kind, via := "bl", ""
		if i == 8 {
			kind, via = "call_indirect", "dispatch_table"
		}
		g.Edges = append(g.Edges, signal.SignalEdge{From: prev, To: name, Kind: kind, Via: via})
		prev = name
	}
	g.Funcs = append(g.Funcs, signal.SignalFunc{Name: "sink", Role: "signal", Severity: "high"})
	g.Edges = append(g.Edges, signal.SignalEdge{From: prev, To: "sink", Kind: "bl"})

	dot := SignalDOT(g, "", NASA)
	for _, name := range []string{"root", "ctx_a", "ctx_l", "sink"} {
		if !strings.Contains(dot, dotID(name)) {
			t.Fatalf("deep-path node %q missing:\n%s", name, dot)
		}
	}
	if !strings.Contains(dot, "style=dashed") || !strings.Contains(dot, "dispatch_table") {
		t.Fatalf("indirect edge semantics missing from deep path:\n%s", dot)
	}
}

func TestSignalCFGDOTMarksIndirectContextPath(t *testing.T) {
	g := &signal.SignalGraph{
		Funcs: []signal.SignalFunc{
			{Name: "signalA", Role: "signal", Severity: "high"},
			{Name: "ctx", Role: "context"},
			{Name: "signalB", Role: "signal", Severity: "medium"},
		},
		Edges: []signal.SignalEdge{
			{From: "signalA", To: "ctx", Kind: "call_indirect", Via: "dispatch_table"},
			{From: "ctx", To: "signalB", Kind: "bl"},
		},
	}
	dot := SignalCFGDOT(g, nil, "", NASA)
	if !strings.Contains(dot, "via indirect/context") || !strings.Contains(dot, "style=dashed") {
		t.Fatalf("transitive indirect path was rendered as a direct call:\n%s", dot)
	}
}

func TestClassgraphAndReachabilityAreDeterministicOnTies(t *testing.T) {
	funcs := []disasm.FuncRecord{
		{Name: "A.one", Owner: "A"}, {Name: "B.one", Owner: "B"},
		{Name: "C.one", Owner: "C"}, {Name: "D.one", Owner: "D"},
	}
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "A.one", Kind: "bl", Target: "B.one"},
		{FromFunc: "C.one", Kind: "bl", Target: "D.one"},
	}
	reachable := map[string]bool{"A.one": true, "B.one": true, "C.one": true, "D.one": true}
	classFirst := ClassgraphDOT(funcs, edges, "", NASA, 0)
	reachFirst := ReachabilityDOT(funcs, edges, reachable, []string{"A.one", "C.one"}, "", NASA)
	for i := 0; i < 25; i++ {
		if got := ClassgraphDOT(funcs, edges, "", NASA, 0); got != classFirst {
			t.Fatalf("ClassgraphDOT changed on repeat %d", i+1)
		}
		if got := ReachabilityDOT(funcs, edges, reachable, []string{"A.one", "C.one"}, "", NASA); got != reachFirst {
			t.Fatalf("ReachabilityDOT changed on repeat %d", i+1)
		}
	}
}

func TestClassgraphPreservesPolymorphicDestinationClasses(t *testing.T) {
	funcs := []disasm.FuncRecord{
		{Name: "Caller.run", Owner: "Caller"},
		{Name: "ImplA.go", Owner: "ImplA"},
		{Name: "ImplB.go", Owner: "ImplB"},
	}
	edges := []disasm.CallEdgeRecord{{
		FromFunc: "Caller.run", Kind: "call_indirect", Via: "dispatch_table",
		Targets: []string{"ImplA.go", "ImplB.go"}, Candidates: 2,
	}}
	dot := ClassgraphDOT(funcs, edges, "", NASA, 0)
	for _, owner := range []string{"ImplA", "ImplB"} {
		if !strings.Contains(dot, dotID(owner)) {
			t.Fatalf("polymorphic destination class %q missing:\n%s", owner, dot)
		}
	}
}

func TestSignalCFGDOTDoesNotInventContextPathForDirectSignalCall(t *testing.T) {
	g := &signal.SignalGraph{
		Funcs: []signal.SignalFunc{
			{Name: "signalA", Role: "signal", Severity: "high"},
			{Name: "signalB", Role: "signal", Severity: "medium"},
		},
		Edges: []signal.SignalEdge{{From: "signalA", To: "signalB", Kind: "bl"}},
	}
	dot := SignalCFGDOT(g, nil, "", NASA)
	if strings.Contains(dot, "via context") {
		t.Fatalf("direct signal edge acquired a synthetic context path:\n%s", dot)
	}
}

func TestSignalHTMLCategoryControlsUseCurrentAttributeAndExactMembership(t *testing.T) {
	g := &signal.SignalGraph{Stats: signal.SignalStats{Categories: map[string]int{"auth": 1, "oauth": 1}}}
	var out bytes.Buffer
	if err := WriteSignalHTML(&out, g, "title", "file", "digest", nil, nil); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	if !strings.Contains(html, `el.dataset.catAction === activeCat`) {
		t.Fatal("category active-state code still reads the removed data-cat attribute")
	}
	if strings.Contains(html, `!cats.includes(activeCat)`) {
		t.Fatal("function category filtering still uses substring matching")
	}
	if !strings.Contains(html, `!categories.includes(activeCat)`) {
		t.Fatal("function category filtering does not use exact category membership")
	}
}

func TestSignalDOTUsesExplicitEntryPointInsideCycle(t *testing.T) {
	g := &signal.SignalGraph{
		Funcs: []signal.SignalFunc{
			{Name: "entry", IsEntryPoint: true},
			{Name: "ctx", Role: "context"},
			{Name: "sink", Role: "signal", Severity: "high"},
		},
		Edges: []signal.SignalEdge{
			{From: "entry", To: "ctx", Kind: "bl"},
			{From: "ctx", To: "entry", Kind: "bl"},
			{From: "ctx", To: "sink", Kind: "bl"},
		},
	}
	dot := SignalDOT(g, "", NASA)
	for _, name := range []string{"entry", "ctx", "sink"} {
		if !strings.Contains(dot, dotID(name)) {
			t.Fatalf("explicit-entry path node %q missing from cyclic graph:\n%s", name, dot)
		}
	}
	for _, line := range strings.Split(dot, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), dotID("entry")+" [") && !strings.Contains(line, NASA.EdgeTHR) {
			t.Fatalf("explicit entry point lost entry styling: %s", line)
		}
	}
}

func TestReachableSetDoesNotTreatViaProvenanceAsFunction(t *testing.T) {
	edges := []disasm.CallEdgeRecord{{
		FromFunc: "entry", Kind: "call_indirect", Via: "dispatch_table",
	}}
	reachable := ReachableSet([]string{"entry"}, edges)
	if reachable["dispatch_table"] {
		t.Fatalf("Via provenance was treated as a reachable function: %+v", reachable)
	}
}

func TestReachabilityDOTPreservesIndirectProvenance(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "entry"}, {Name: "impl"}}
	edges := []disasm.CallEdgeRecord{{
		FromFunc: "entry", Kind: "call_indirect", Via: "dispatch_table", Targets: []string{"impl"}, Candidates: 1,
	}}
	reachable := map[string]bool{"entry": true, "impl": true}
	dot := ReachabilityDOT(funcs, edges, reachable, []string{"entry"}, "", NASA)
	want := dotID("entry") + " -> " + dotID("impl")
	for _, line := range strings.Split(dot, "\n") {
		if strings.Contains(line, want) {
			if !strings.Contains(line, `style="dotted"`) || !strings.Contains(line, NASA.EdgeDispatch) {
				t.Fatalf("indirect dispatch edge lost provenance styling: %s", line)
			}
			return
		}
	}
	t.Fatalf("reachable dispatch edge missing:\n%s", dot)
}

func TestCFGDOTToleratesMalformedBlockBounds(t *testing.T) {
	cfg := disasm.FuncCFG{
		Name: "bad",
		Blocks: []disasm.BasicBlock{
			{ID: 0, Start: -4, End: 1, IsEntry: true},
			{ID: 1, Start: 99, End: 120},
		},
		Insts: []disasm.Inst{{Addr: 0x1000, Text: "ret"}},
	}
	dot := CFGDOT(cfg, nil, NASA)
	if !strings.Contains(dot, "bb0") || !strings.Contains(dot, "bb1") {
		t.Fatalf("malformed CFG bounds dropped block nodes:\n%s", dot)
	}
}

func TestWriteIndexHTMLToleratesZeroTopOwnerCount(t *testing.T) {
	stats := CallgraphStats{TopOwners: []NameCount{{Name: "Owner", Count: 0}}}
	var out bytes.Buffer
	if err := WriteIndexHTML(&out, stats, nil, "title", false, false, false, nil, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
}

func TestComputeStatsIncludesResolvedIndirectCallees(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "caller"}}
	edges := []disasm.CallEdgeRecord{{
		FromFunc: "caller", Kind: "call_indirect", Via: "dispatch_table",
		Targets: []string{"Impl.one", "Impl.two"}, Candidates: 2,
	}}
	stats := ComputeStats(funcs, edges)
	if len(stats.TopCallees) != 2 || stats.TopCallees[0].Count != 1 || stats.TopCallees[1].Count != 1 {
		t.Fatalf("TopCallees omitted resolved indirect targets: %+v", stats.TopCallees)
	}
}

func TestReachableSetDoesNotCountRawAddressTargetsAsFunctions(t *testing.T) {
	edges := []disasm.CallEdgeRecord{{FromFunc: "entry", Kind: "bl", Target: "0x1234"}}
	reachable := ReachableSet([]string{"entry"}, edges)
	if reachable["0x1234"] {
		t.Fatalf("raw call address was counted as a reachable function: %+v", reachable)
	}
	stats := ComputeStats([]disasm.FuncRecord{{Name: "entry"}}, edges)
	if len(stats.TopCallees) != 0 {
		t.Fatalf("raw call address was counted as a top function callee: %+v", stats.TopCallees)
	}
}

func TestClassgraphDoesNotTurnUnknownEndpointsIntoUnownedClass(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "Known.run", Owner: "Known"}}
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "Known.run", Kind: "bl", Target: "0x1234"},
		{FromFunc: "missing.caller", Kind: "bl", Target: "Known.run"},
	}
	dot := ClassgraphDOT(funcs, edges, "", NASA, 0)
	if strings.Contains(dot, dotID("(unowned)")) {
		t.Fatalf("unknown edge endpoint became a synthetic unowned class:\n%s", dot)
	}
}

func TestCFGDOTCallCapCountsUniqueCallees(t *testing.T) {
	insts := make([]disasm.Inst, 11)
	edges := make([]disasm.CallEdgeRecord, 0, 11)
	for i := range insts {
		addr := uint64(0x1000 + i*4)
		insts[i] = disasm.Inst{Addr: addr, Text: "call"}
		target := "Repeated"
		if i == len(insts)-1 {
			target = "UniqueLast"
		}
		edges = append(edges, disasm.CallEdgeRecord{FromFunc: "f", FromPC: fmt.Sprintf("0x%x", addr), Kind: "bl", Target: target})
	}
	cfg := disasm.FuncCFG{Name: "f", Blocks: []disasm.BasicBlock{{ID: 0, Start: 0, End: len(insts)}}, Insts: insts}
	dot := CFGDOT(cfg, edges, NASA)
	if !strings.Contains(dot, "bb0 -> "+dotID("UniqueLast")) {
		t.Fatalf("repeated calls exhausted the unique-callee display cap:\n%s", dot)
	}
}

func TestSignalDOTMoreCountUsesUniqueStrings(t *testing.T) {
	refs := []signal.ClassifiedStringRef{
		{Value: "a"}, {Value: "b"}, {Value: "c"}, {Value: "d"}, {Value: "e"}, {Value: "e"},
	}
	g := &signal.SignalGraph{Funcs: []signal.SignalFunc{{
		Name: "signal", Role: "signal", Severity: "high", IsEntryPoint: true, StringRefs: refs,
	}}}
	dot := SignalDOT(g, "", NASA)
	if strings.Contains(dot, "+1 more") {
		t.Fatalf("duplicate string ref inflated omitted-string count:\n%s", dot)
	}
}

func TestSignalHTMLSerializesEmptyCollectionsAsArrays(t *testing.T) {
	var out bytes.Buffer
	if err := WriteSignalHTML(&out, &signal.SignalGraph{}, "title", "file", "digest", nil, nil); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	const marker = `const _GZ_G = "`
	start := strings.Index(html, marker)
	if start < 0 {
		t.Fatal("embedded signal graph payload missing")
	}
	start += len(marker)
	end := strings.Index(html[start:], `";`)
	if end < 0 {
		t.Fatal("embedded signal graph payload terminator missing")
	}
	compressed, err := base64.StdEncoding.DecodeString(html[start : start+end])
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if err := zr.Close(); err != nil {
		t.Fatal(err)
	}
	var graph map[string]json.RawMessage
	if err := json.Unmarshal(payload, &graph); err != nil {
		t.Fatal(err)
	}
	if string(graph["funcs"]) != "[]" || string(graph["edges"]) != "[]" {
		t.Fatalf("empty graph collections must be arrays for browser iteration: %s", payload)
	}
	var stats map[string]json.RawMessage
	if err := json.Unmarshal(graph["stats"], &stats); err != nil {
		t.Fatal(err)
	}
	if string(stats["categories"]) != "{}" {
		t.Fatalf("empty categories must be an object for Object.entries: %s", graph["stats"])
	}
}

func TestFindEntryPointsIgnoresEdgesFromUnknownCallers(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "target"}}
	edges := []disasm.CallEdgeRecord{{FromFunc: "ghost", Kind: "bl", Target: "target"}}
	got := FindEntryPoints(funcs, edges)
	if len(got) != 1 || got[0] != "target" {
		t.Fatalf("ghost caller suppressed a real entry point: %v", got)
	}
}

func TestRenderIgnoresUnknownCallKinds(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "caller"}, {Name: "callee"}}
	edge := disasm.CallEdgeRecord{FromFunc: "caller", FromPC: "0x1000", Kind: "mystery", Target: "callee"}
	stats := ComputeStats(funcs, []disasm.CallEdgeRecord{edge})
	if stats.TotalEdges != 0 || stats.BLEdges != 0 || stats.BLREdges != 0 {
		t.Fatalf("unknown edge kind affected stats: %+v", stats)
	}
	dot := CallgraphDOT(funcs, []disasm.CallEdgeRecord{edge}, "", NASA, 0)
	if strings.Contains(dot, dotID("caller")+" -> "+dotID("callee")) {
		t.Fatalf("unknown edge kind was rendered as a call:\n%s", dot)
	}
}

func TestCallgraphAndCFGDONotTreatViaAsCallee(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "caller", Owner: "Caller"}, {Name: "dispatch_table", Owner: "Fake"}}
	edge := disasm.CallEdgeRecord{
		FromFunc: "caller", FromPC: "0x1000", Kind: "call_indirect", Via: "dispatch_table",
	}
	callDOT := CallgraphDOT(funcs, []disasm.CallEdgeRecord{edge}, "", NASA, 0)
	if strings.Contains(callDOT, dotID("dispatch_table")) {
		t.Fatalf("callgraph rendered Via provenance as a callee:\n%s", callDOT)
	}
	if !strings.Contains(callDOT, dotID("unresolved_blr")) {
		t.Fatalf("callgraph dropped the unresolved indirect call entirely:\n%s", callDOT)
	}
	classDOT := ClassgraphDOT(funcs, []disasm.CallEdgeRecord{edge}, "", NASA, 0)
	if strings.Contains(classDOT, dotID("Caller")+" -> "+dotID("Fake")) {
		t.Fatalf("classgraph rendered Via provenance as a concrete class edge:\n%s", classDOT)
	}

	cfg := disasm.FuncCFG{
		Name:   "caller",
		Blocks: []disasm.BasicBlock{{ID: 0, Start: 0, End: 1}},
		Insts:  []disasm.Inst{{Addr: 0x1000, Text: "blr x16"}},
	}
	cfgDOT := CFGDOT(cfg, []disasm.CallEdgeRecord{edge}, NASA)
	if strings.Contains(cfgDOT, dotID("dispatch_table")) {
		t.Fatalf("CFG rendered Via provenance as a callee:\n%s", cfgDOT)
	}
}

func TestSignalRenderersIgnoreEdgesToUnknownFunctions(t *testing.T) {
	g := &signal.SignalGraph{
		Funcs: []signal.SignalFunc{
			{Name: "signalA", Role: "signal", Severity: "high", IsEntryPoint: true},
			{Name: "signalB", Role: "signal", Severity: "medium"},
		},
		Edges: []signal.SignalEdge{
			{From: "signalA", To: "ghost", Kind: "bl"},
			{From: "ghost", To: "signalB", Kind: "bl"},
		},
		Stats: signal.SignalStats{TotalEdges: 2},
	}
	if dot := SignalDOT(g, "", NASA); strings.Contains(dot, dotID("ghost")) {
		t.Fatalf("signal DOT rendered an endpoint missing from funcs:\n%s", dot)
	}
	if dot := SignalCFGDOT(g, nil, "", NASA); strings.Contains(dot, "via context") {
		t.Fatalf("signal CFG synthesized a path through an unknown function:\n%s", dot)
	}
	payload := signalGraphHTMLPayload(g)
	if len(payload.Edges) != 0 || payload.Stats.TotalEdges != 0 {
		t.Fatalf("signal HTML payload kept malformed graph edges: %+v", payload.Edges)
	}
}

func TestCFGDOTSkipsUnknownSuccessorsAndUsesSafeNegativeBlockIDs(t *testing.T) {
	cfg := disasm.FuncCFG{
		Name: "malformed",
		Blocks: []disasm.BasicBlock{{
			ID: -1, Start: 0, End: 1, Succs: []disasm.Succ{{BlockID: 99}},
		}},
		Insts: []disasm.Inst{{Addr: 0x1000, Text: "ret"}},
	}
	dot := CFGDOT(cfg, nil, NASA)
	if !strings.Contains(dot, "bb_n1 [") || strings.Contains(dot, "bb-1") {
		t.Fatalf("negative block ID was not rendered as a safe DOT identifier:\n%s", dot)
	}
	if strings.Contains(dot, "-> bb99") {
		t.Fatalf("unknown successor created a phantom Graphviz node:\n%s", dot)
	}
}
