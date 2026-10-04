package naming

import (
	"testing"

	"aotopsy/internal/dartfmt"
)

func TestBuildVMStubSymbolsRefusesMissingProfileWithoutPanic(t *testing.T) {
	got := BuildVMStubSymbols(nil, dartfmt.Options{})
	if got == nil {
		t.Fatal("BuildVMStubSymbols returned nil map")
	}
	if len(got) != 0 {
		t.Fatalf("BuildVMStubSymbols(nil) returned %d symbols, want none", len(got))
	}
}
