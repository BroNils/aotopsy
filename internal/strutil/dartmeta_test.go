package strutil

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"aotopsy/internal/snapshot"
	"aotopsy/internal/vmtables"
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

func TestDartMetaForTargetAndValidationAreExact(t *testing.T) {
	p := snapshot.ProfileForVersion("3.12.2")
	if p == nil {
		t.Fatal("missing 3.12.2 profile")
	}
	p.BuildMode = snapshot.BuildProduct
	p.CompressedPointers = true
	target, ok := vmtables.TargetProfileFromVersion(p, true)
	if !ok {
		t.Fatal("missing exact ARM64 target profile")
	}
	meta, err := DartMetaForTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Architecture != "arm64" || meta.DartVersion != "3.12.2" || !meta.CompressedPointers || meta.PointerSize != 4 {
		t.Fatalf("derived metadata scalar facts = %+v", meta)
	}
	if len(meta.THRFields) == 0 {
		t.Fatal("exact 3.12.2 ARM64 compressed target lost its THR table")
	}
	if got, err := ValidateDartMeta(meta); err != nil || got != target {
		t.Fatalf("ValidateDartMeta = %+v,%v; want %+v,nil", got, err, target)
	}

	badPointer := meta
	badPointer.PointerSize = 8
	if _, err := ValidateDartMeta(badPointer); err == nil {
		t.Fatal("compressed metadata with pointer_size 8 was accepted")
	}
	badTHR := meta
	badTHR.THRFields = append([]FlutterMetaTHRField(nil), meta.THRFields...)
	badTHR.THRFields[0].Name += "_wrong"
	if _, err := ValidateDartMeta(badTHR); err == nil {
		t.Fatal("metadata with a plausible but wrong THR field was accepted")
	}
	unknown := meta
	unknown.DartVersion = "3.99.0"
	if _, err := ValidateDartMeta(unknown); err == nil {
		t.Fatal("unknown Dart version inherited metadata semantics")
	}
}

func TestDartMetaRejectsImpossibleCompressedPointerProfile(t *testing.T) {
	target := vmtables.TargetProfile{
		DartVersion:        "2.10.0",
		Architecture:       vmtables.ArchitectureARM64,
		CompressedPointers: true,
		BuildMode:          snapshot.BuildProduct,
	}
	if _, err := DartMetaForTarget(target); err == nil {
		t.Fatal("Dart 2.10.0 accepted compressed-pointer metadata")
	}
}

func TestHexAddressParsingFailsClosed(t *testing.T) {
	for _, bad := range []string{"", "1234", "0x", "0xzz", "-0x1", "0x10000000000000000"} {
		if _, err := ParseHexAddr(bad); err == nil {
			t.Errorf("ParseHexAddr(%q) accepted malformed input", bad)
		}
		if _, err := NormalizeHexAddr(bad); err == nil {
			t.Errorf("NormalizeHexAddr(%q) accepted malformed input", bad)
		}
	}
	for _, tc := range []struct {
		in   string
		want uint64
	}{
		{"0x0", 0},
		{"0X0010", 0x10},
		{"0xffffffffffffffff", ^uint64(0)},
	} {
		got, err := ParseHexAddr(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("ParseHexAddr(%q) = %#x,%v; want %#x,nil", tc.in, got, err, tc.want)
		}
	}
	if got, err := NormalizeHexAddr("0X0010"); err != nil || got != "0x10" {
		t.Fatalf("NormalizeHexAddr = %q,%v; want 0x10,nil", got, err)
	}
}
