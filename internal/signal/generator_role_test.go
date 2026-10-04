package signal

import (
	"testing"

	"aotopsy/internal/disasm"
)

func TestBuildSignalGraphSeparatesGeneratorAndAsyncTHRStubs(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "syncGen"}, {Name: "asyncFn"}}
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "syncGen", Kind: "blr", Via: "THR.suspend_state_init_sync_star_entry_point"},
		{FromFunc: "asyncFn", Kind: "blr", Via: "THR.suspend_state_await_entry_point"},
	}
	g := BuildSignalGraph("3.12.2", funcs, edges, nil, 0, nil)
	got := make(map[string][]string)
	for _, f := range g.Funcs {
		got[f.Name] = f.Categories
	}
	has := func(cats []string, want string) bool {
		for _, cat := range cats {
			if cat == want {
				return true
			}
		}
		return false
	}
	if !has(got["syncGen"], CatGenerator) || has(got["syncGen"], CatAsync) {
		t.Fatalf("sync* categories = %v, want generator only", got["syncGen"])
	}
	if !has(got["asyncFn"], CatAsync) || has(got["asyncFn"], CatGenerator) {
		t.Fatalf("async categories = %v, want async only", got["asyncFn"])
	}
}

func TestBuildSignalGraphTreatsUnknownTHRAsAnalyzerGap(t *testing.T) {
	funcs := []disasm.FuncRecord{{Name: "caller"}}
	edges := []disasm.CallEdgeRecord{{
		FromFunc: "caller", FromPC: "0x1000", Kind: "blr", Via: "THR.future_sdk_field_entry_point",
	}}
	g := BuildSignalGraph("3.12.2", funcs, edges, nil, 0, nil)
	if g.Stats.SignalFuncs != 0 || g.Stats.UnclassifiedTHRSites != 1 {
		t.Fatalf("unknown THR became target behavior: stats=%+v", g.Stats)
	}
	if len(g.Funcs) != 1 || g.Funcs[0].Role != "" || len(g.Funcs[0].Categories) != 0 {
		t.Fatalf("unknown THR marked caller as signal: %+v", g.Funcs)
	}
}
