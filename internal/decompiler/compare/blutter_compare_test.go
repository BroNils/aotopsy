package compare

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"aotopsy/internal/disasm"
	"aotopsy/internal/jsonutil"
)

func TestCompareBlutterDisagreementSamplesAreDeterministic(t *testing.T) {
	blutterDir := t.TempDir()
	asmDir := filepath.Join(blutterDir, "asm")
	if err := os.Mkdir(asmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var asm string
	var funcs []disasm.FuncRecord
	for i := 0; i < 12; i++ {
		va := fmt.Sprintf("0x%04x", 0x100+i)
		asm += fmt.Sprintf("%s: nop ; blutter_%02d\n", va, i)
		funcs = append(funcs, disasm.FuncRecord{PC: va, Size: 4, Name: fmt.Sprintf("aotopsy_%02d", i)})
	}
	if err := os.WriteFile(filepath.Join(asmDir, "all.txt"), []byte(asm), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blutterDir, "objs.txt"), []byte("class A\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	aotopsyDir := t.TempDir()
	if _, err := jsonutil.WriteJSONLFile(filepath.Join(aotopsyDir, "functions.jsonl"), funcs); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aotopsyDir, "classes.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := CompareBlutter(blutterDir, aotopsyDir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CompareBlutter(blutterDir, aotopsyDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Disagreements) != 10 || len(second.Disagreements) != 10 {
		t.Fatalf("disagreement sample sizes = %d, %d", len(first.Disagreements), len(second.Disagreements))
	}
	for i := range first.Disagreements {
		want := fmt.Sprintf("0x%04x", 0x100+i)
		if first.Disagreements[i].VA != want || second.Disagreements[i].VA != want {
			t.Fatalf("sample %d not stable/sorted: first=%+v second=%+v want=%s", i, first.Disagreements[i], second.Disagreements[i], want)
		}
	}
}

func TestCompareBlutterPropagatesMalformedAotopsyJSON(t *testing.T) {
	blutterDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(blutterDir, "asm"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blutterDir, "objs.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	aotopsyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(aotopsyDir, "functions.jsonl"), []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aotopsyDir, "classes.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CompareBlutter(blutterDir, aotopsyDir); err == nil {
		t.Fatal("malformed functions.jsonl was silently treated as empty coverage")
	}
}
