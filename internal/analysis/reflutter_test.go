package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aotopsy/internal/disasm"
	"aotopsy/internal/jsonutil"
)

func TestMergeReFlutterFunctionsEnrichesByCodeRelativeOffset(t *testing.T) {
	const codeVA = 0x10000
	funcs := []disasm.FuncRecord{
		{PC: "0x10040", PCOffset: 0x40, RefID: 1, Size: 16, Name: "a"},
		{PC: "0x10080", PCOffset: 0x80, RefID: 2, Size: 16, Name: "b"},
		{PC: "0x0f000", RefID: 3, Size: 4, Name: "below_code_va"},
		{PC: "not-hex", RefID: 4, Name: "garbage"},
	}
	entries := ParseReFlutterDump(strings.Join([]string{
		"Library:'package:app/main.dart' Class: Foo extends Object {",
		"  function build offset: 0x40;",
		"}",
	}, "\n"))

	got := mergeReFlutterFunctions(funcs, codeVA, entries)

	if got.enriched != 1 {
		t.Fatalf("enriched = %d, want 1", got.enriched)
	}
	if len(got.funcs) != len(funcs) {
		t.Fatalf("merged %d functions, want %d", len(got.funcs), len(funcs))
	}
	a := got.funcs[0]
	if a.ReflutterName != "build" || a.ReflutterClass != "Foo" || a.ReflutterLibrary != "package:app/main.dart" {
		t.Fatalf("function a not enriched: %+v", a)
	}
	for _, f := range got.funcs[1:] {
		if f.ReflutterName != "" || f.ReflutterClass != "" || f.ReflutterLibrary != "" {
			t.Fatalf("unmatched function %q was enriched: %+v", f.Name, f)
		}
	}
	if funcs[0].ReflutterName != "" {
		t.Fatal("mergeReFlutterFunctions mutated its input")
	}
}

// The merged functions.jsonl must stay loadable by the strict reader every
// later stage uses; a generic-map read (the old code) was rejected outright.
func TestMergedFunctionsRoundTripThroughStrictReader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "functions.jsonl")
	in := []disasm.FuncRecord{
		{PC: "0x10040", RefID: 1, Size: 16, Name: "a", ReflutterName: "build", ReflutterClass: "Foo"},
		{PC: "0x10080", RefID: 2, Size: 16, Name: "b"},
	}
	if _, err := jsonutil.WriteJSONLFile(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := jsonutil.ReadJSONL[disasm.FuncRecord](path, jsonutil.StandardLimits)
	if err != nil {
		t.Fatalf("strict reader rejected merged functions.jsonl: %v", err)
	}
	if len(out) != 2 || out[0].ReflutterName != "build" || out[1].ReflutterName != "" {
		t.Fatalf("round trip lost data: %+v", out)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if strings.Contains(lines[1], "reflutter_") {
		t.Fatalf("unenriched record leaked reflutter keys: %s", lines[1])
	}
}

// An empty static function table must publish a file the strict reader still
// accepts; the old hand-joined writer emitted a lone blank line, which is a
// "blank record" error.
func TestMergedEmptyFunctionsStayReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "functions.jsonl")
	m := mergeReFlutterFunctions(nil, 0, nil)
	if _, err := jsonutil.WriteJSONLFile(path, m.funcs); err != nil {
		t.Fatal(err)
	}
	out, err := jsonutil.ReadJSONL[disasm.FuncRecord](path, jsonutil.StandardLimits)
	if err != nil || len(out) != 0 {
		t.Fatalf("empty merged file = %v, %v; want 0 records, nil", out, err)
	}
}
