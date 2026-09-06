package analysis

import (
	"testing"

	"aotopsy/internal/cluster"
	"aotopsy/internal/naming"
)

func TestFuncSlice(t *testing.T) {
	code := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	codeVA := uint64(0x1000)
	codeOff := uint64(0x100)

	pool := &naming.PoolLookups{
		CodeNames: map[int]naming.CodeNameInfo{
			1: {
				FuncName:  "myFunc",
				OwnerName: "MyClass",
			},
		},
	}
	elfSyms := map[uint64]string{
		0x1004: "elf_stub_name",
	}

	im := NewCodeImage(code, codeVA, codeOff, pool, elfSyms)

	// Valid slice with pool lookup
	r1 := cluster.CodeRange{
		PCOffset: 0x100,
		Size:     4,
		RefID:    1,
	}
	fs1, ok := im.Slice(r1)
	if !ok {
		t.Fatalf("expected Slice to succeed for r1")
	}
	if fs1.VA != 0x1000 {
		t.Errorf("expected VA 0x1000, got 0x%x", fs1.VA)
	}
	if len(fs1.Code) != 4 {
		t.Errorf("expected 4 bytes code, got %d", len(fs1.Code))
	}
	if fs1.Owner != "MyClass" {
		t.Errorf("expected Owner 'MyClass', got %q", fs1.Owner)
	}

	// Valid slice with stub (negative RefID) and ELF symbol
	r2 := cluster.CodeRange{
		PCOffset: 0x104,
		Size:     4,
		RefID:    -1,
	}
	fs2, ok := im.Slice(r2)
	if !ok {
		t.Fatalf("expected Slice to succeed for r2")
	}
	if fs2.Name != "elf_stub_name" {
		t.Errorf("expected Name 'elf_stub_name', got %q", fs2.Name)
	}

	// Range with Size 0
	rZero := cluster.CodeRange{PCOffset: 0x100, Size: 0}
	if _, ok := im.Slice(rZero); ok {
		t.Errorf("expected Size 0 to fail")
	}

	// Range out of bounds
	rOOB := cluster.CodeRange{PCOffset: 0x200, Size: 10}
	if _, ok := im.Slice(rOOB); ok {
		t.Errorf("expected out of bounds range to fail")
	}

	// Nil Code image (metadata-only)
	imNil := NewCodeImage(nil, codeVA, codeOff, pool, nil)
	fsNil, ok := imNil.Slice(r1)
	if !ok {
		t.Fatalf("expected Slice on nil code to succeed for metadata")
	}
	if fsNil.VA != 0x1000 {
		t.Errorf("expected VA 0x1000 on nil code, got 0x%x", fsNil.VA)
	}
	if len(fsNil.Code) != 0 {
		t.Errorf("expected empty code slice on nil code, got %d", len(fsNil.Code))
	}

	// Test Each
	ranges := []cluster.CodeRange{r1, r2, rZero}
	seen := 0
	visited := im.Each(ranges, 0, func(fs FuncSlice) bool {
		seen++
		return true
	})
	if visited != 2 || seen != 2 {
		t.Errorf("expected 2 slices visited, got %d (seen %d)", visited, seen)
	}
}
