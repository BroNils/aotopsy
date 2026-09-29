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
	g := BuildSignalGraph(funcs, edges, nil, 0, nil)
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
	if !has(got["syncGen"], CatGenerator) || has(got["syncGen"], CatAsync) || has(got["syncGen"], CatTHR) {
		t.Fatalf("sync* categories = %v, want generator only", got["syncGen"])
	}
	if !has(got["asyncFn"], CatAsync) || has(got["asyncFn"], CatGenerator) {
		t.Fatalf("async categories = %v, want async only", got["asyncFn"])
	}
}
