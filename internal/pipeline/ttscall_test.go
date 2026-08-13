package pipeline

import (
	"testing"

	"aotopsy/internal/cluster"
)

func ttsFixture() (*PoolLookups, []cluster.PoolEntry) {
	pl := &PoolLookups{TypeTestingStubNames: map[int]string{
		4242: "TypeTestingStub_RenderBox",
	}}
	pool := []cluster.PoolEntry{
		{Index: 6963, Kind: cluster.PoolTagged, RefID: 4242}, // the Type
		{Index: 75, Kind: cluster.PoolTagged, RefID: 9999},   // a Code, not a Type
		{Index: 12, Kind: cluster.PoolImmediate, Imm: 7},     // not an object at all
	}
	return pl, pool
}

// GenerateIndirectTTSCall loads the subtype-test cache from the pool and then
// calls the entry point stored in the register holding the AbstractType, so a
// call whose register came from a pool slot holding a Type invokes that
// type's testing stub.
func TestTTSCallResolvesAPoolTypeToItsStub(t *testing.T) {
	pl, pool := ttsFixture()
	byIdx := buildTTSCallTargets(pool, pl)

	if got, want := ttsCallTarget("pp[6963] <Type>", byIdx), "TypeTestingStub_RenderBox"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// The annotation is not always carrying a display suffix.
	if got := ttsCallTarget("pp[6963]", byIdx); got != "TypeTestingStub_RenderBox" {
		t.Errorf("bare pool annotation should resolve too, got %q", got)
	}
}

// The displacement cannot disambiguate these calls: Code::entry_point_offset
// and AbstractType::type_test_stub_entry_point_offset are both 8, so both
// shapes appear as `CALL [reg+0x7]`. Only what the register holds decides it,
// which is why a pool slot holding anything but a Type must resolve to
// nothing rather than to a stub name.
func TestTTSCallIgnoresPoolSlotsThatAreNotTypes(t *testing.T) {
	pl, pool := ttsFixture()
	byIdx := buildTTSCallTargets(pool, pl)

	for _, via := range []string{
		"pp[75] <vm:Code>", // a Code entry point -- a real call, but not a TTS
		"pp[12]",           // an immediate
		"pp[9998]",         // a slot that does not exist
		"object_field",     // a runtime type from a field: no static answer
		"THR.write_barrier_entry_point",
		"",
	} {
		if got := ttsCallTarget(via, byIdx); got != "" {
			t.Errorf("via %q resolved to %q; it is not a type-testing stub call", via, got)
		}
	}
}

// With no type-testing stub names available -- the Dart 2.x gate in
// typeteststubs.go -- nothing may resolve.
func TestTTSCallResolvesNothingWithoutStubNames(t *testing.T) {
	_, pool := ttsFixture()
	if got := buildTTSCallTargets(pool, &PoolLookups{}); got != nil {
		t.Errorf("expected no targets without stub names, got %v", got)
	}
	if got := ttsCallTarget("pp[6963] <Type>", nil); got != "" {
		t.Errorf("expected no resolution, got %q", got)
	}
}
