package analysis

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/naming"
)

func loopDeps(t *testing.T, dir string, strict bool, failOn int) DecompLoopDeps {
	t.Helper()
	ranges := []cluster.CodeRange{
		{RefID: 1, PCOffset: 0x100, Size: 8},
		{RefID: 2, PCOffset: 0x200, Size: 8},
		{RefID: 3, PCOffset: 0x300, Size: 8},
	}
	im := cluster.CodeImage{CodeVA: 0x1000, CodeOff: 0}
	names := map[uint64]string{}
	byRef := map[int]string{1: "a", 2: "b", 3: "c"}
	for _, r := range ranges {
		va, ok := im.FuncVA(r)
		if !ok {
			t.Fatal("range has no VA")
		}
		names[va] = byRef[r.RefID]
	}
	var buf bytes.Buffer
	return DecompLoopDeps{
		Ranges: ranges, CodeVA: 0x1000, SymbolNames: names,
		Pl: &naming.PoolLookups{},
		DecompileRangeWithIR: func(r cluster.CodeRange) (*decompiler.FuncIR, decompiler.Artifact, error) {
			if r.RefID == failOn {
				return nil, decompiler.Artifact{}, errors.New("boom")
			}
			return nil, decompiler.Artifact{FunctionName: byRef[r.RefID], Source: "ok"}, nil
		},
		W: bufio.NewWriter(&buf), CombinedPath: filepath.Join(dir, "combined.dart"),
		OutDir: dir, Strict: strict, StartTime: time.Now(),
	}
}

func TestDecompileLoopSkipsFailingFunctionAndListsIt(t *testing.T) {
	dir := t.TempDir()
	if err := RunDecompileLoop(loopDeps(t, dir, false, 2)); err != nil {
		t.Fatalf("one failing function aborted the batch: %v", err)
	}
	got, err := jsonutil.ReadJSONL[DecompileFailure](filepath.Join(dir, DecompileFailuresFile), jsonutil.StandardLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "b" || got[0].RefID != 2 || !strings.Contains(got[0].Reason, "boom") {
		t.Fatalf("failure list = %+v", got)
	}
}

func TestDecompileLoopStrictAbortsOnFirstFailure(t *testing.T) {
	if err := RunDecompileLoop(loopDeps(t, t.TempDir(), true, 2)); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("strict mode did not abort with the cause: %v", err)
	}
}

func TestDecompileLoopCleanRunLeavesEmptyFailureList(t *testing.T) {
	dir := t.TempDir()
	// A stale list from an earlier run must not survive a clean one.
	stale := `{"pc":"0x1","ref_id":1,"reason":"old"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, DecompileFailuresFile), []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RunDecompileLoop(loopDeps(t, dir, false, -1)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, DecompileFailuresFile))
	if err != nil || len(b) != 0 {
		t.Fatalf("clean run left %q, %v", b, err)
	}
}
