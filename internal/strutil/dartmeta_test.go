package strutil

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestExtractAsmCommentsWalksOwnerDirectories(t *testing.T) {
	asmDir := t.TempDir()
	nested := filepath.Join(asmDir, "Owner", "method.txt")
	if err := os.MkdirAll(filepath.Dir(nested), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nested, []byte("0x0010  ldr x0, [x1] ; field load\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(asmDir, "top.txt"), []byte("0x0020  ret ; return\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	want := []FlutterMetaComment{
		{Addr: "0x10", Text: "field load"},
		{Addr: "0x20", Text: "return"},
	}
	got, err := ExtractAsmComments(asmDir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtractAsmComments() = %#v, want %#v", got, want)
	}

	again, err := ExtractAsmComments(asmDir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, got) {
		t.Fatalf("ExtractAsmComments() order changed: first=%#v second=%#v", got, again)
	}
}
