package compare

import (
	"strings"
	"testing"
)

func TestFunctionDictionaryRejectsAmbiguousNamedCollision(t *testing.T) {
	code := []byte{0x90, 0xc3}
	d, err := NewFunctionDictionary("3.12.2", "x64")
	if err != nil {
		t.Fatal(err)
	}
	a := ComputeFingerprint(code, "A.foo", "A")
	b := ComputeFingerprint(code, "B.bar", "B")
	d.Add(a)
	d.Add(b)
	if name, owner, ok := d.Lookup(a.Hash); ok {
		t.Fatalf("ambiguous identical code transferred arbitrary name %q owner %q", name, owner)
	}
	if d.NamedCount() != 0 {
		t.Fatalf("ambiguous entry counted as named seed: %d", d.NamedCount())
	}
	out, err := d.Export()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, a.Hash) {
		t.Fatalf("ambiguous entry was persisted for future name transfer: %q", out)
	}
}

func TestFunctionDictionaryJSONLRoundTripPreservesWhitespaceNames(t *testing.T) {
	d, err := NewFunctionDictionary("3.12.2", "x64")
	if err != nil {
		t.Fatal(err)
	}
	fp := ComputeFingerprint([]byte{0x90, 0xc3}, "<anonymous closure>", "Owner With Space")
	d.Add(fp)

	text, err := d.Export()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, `"name":"<anonymous closure>"`) {
		t.Fatalf("dictionary export lost structured name: %q", text)
	}
	got, err := ImportDictionary(strings.NewReader(text), int64(len(text)))
	if err != nil {
		t.Fatal(err)
	}
	if got.DartVersion() != "3.12.2" || got.Arch() != "x64" {
		t.Fatalf("metadata round-trip = %s/%s", got.DartVersion(), got.Arch())
	}
	name, owner, ok := got.Lookup(fp.Hash)
	if !ok || name != fp.FuncName || owner != fp.Owner {
		t.Fatalf("round-trip = (%q,%q,%v), want (%q,%q,true)", name, owner, ok, fp.FuncName, fp.Owner)
	}
}

func TestImportDictionaryRejectsMalformedOrUnknownFields(t *testing.T) {
	validHash := strings.Repeat("0", 64)
	meta := `{"kind":"metadata","schema":1,"dart_version":"3.12.2","arch":"x64"}` + "\n"
	for _, text := range []string{
		`{"kind":"function","hash":"deadbeef","size":2,"name":"f"}` + "\n",
		meta + `{"kind":"function","hash":"` + validHash + `","size":2,"name":"f","extra":true}` + "\n",
		meta + `{"kind":"function","hash":"` + validHash + `","size":0,"name":"f"}` + "\n",
		`{"kind":"metadata","schema":1,"dart_version":"3.12.2","arch":"mips"}` + "\n",
	} {
		if _, err := ImportDictionary(strings.NewReader(text), int64(len(text))); err == nil {
			t.Fatalf("invalid dictionary accepted: %q", text)
		}
	}
}

func TestFunctionDictionaryRejectsWrongTarget(t *testing.T) {
	d, err := NewFunctionDictionary("3.12.2", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.ValidateTarget("3.12.2", "x64"); err == nil {
		t.Fatal("architecture mismatch accepted")
	}
	if err := d.ValidateTarget("3.13.0", "arm64"); err == nil {
		t.Fatal("version mismatch accepted")
	}
}

func TestImportDictionaryEnforcesTotalBudget(t *testing.T) {
	meta := `{"kind":"metadata","schema":1,"dart_version":"3.12.2","arch":"x64"}` + "\n"
	if _, err := ImportDictionary(strings.NewReader(meta+strings.Repeat(" ", 4096)), int64(len(meta)+16)); err == nil {
		t.Fatal("oversized dictionary accepted")
	}
}
