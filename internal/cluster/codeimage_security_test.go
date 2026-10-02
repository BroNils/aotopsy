package cluster

import (
	"math"
	"testing"
)

func TestCodeImageRejectsVirtualAddressWrap(t *testing.T) {
	im := CodeImage{Code: make([]byte, 16), CodeVA: math.MaxUint64 - 1}
	if va, ok := im.VAAt(4); ok {
		t.Fatalf("VAAt accepted wrapped address %#x", va)
	}

	// Four bytes starting at MaxUint64-3 end exactly at MaxUint64 and are
	// valid; only the first byte after that would wrap.
	r := CodeRange{PCOffset: 0, Size: 4}
	im.CodeVA = math.MaxUint64 - 3
	if got, va, ok := im.SliceExact(r); !ok || va != math.MaxUint64-3 || len(got) != 4 {
		t.Fatalf("boundary range rejected: va=%#x len=%d ok=%v", va, len(got), ok)
	}

	r = CodeRange{PCOffset: 0, Size: 8}
	im.CodeVA = math.MaxUint64 - 3
	if _, _, ok := im.Slice(r); ok {
		t.Fatal("Slice accepted function extent crossing uint64 VA boundary")
	}
	if _, _, ok := im.SliceExact(r); ok {
		t.Fatal("SliceExact accepted function extent crossing uint64 VA boundary")
	}
}
