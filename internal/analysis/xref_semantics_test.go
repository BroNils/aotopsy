package analysis

import (
	"path/filepath"
	"reflect"
	"testing"

	"aotopsy/internal/cluster"
	"aotopsy/internal/disasm"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/naming"
	"aotopsy/internal/snapshot"
)

func TestWriteXrefUsesProvidedSelectorCoordinate(t *testing.T) {
	dir := t.TempDir()
	selectorTargets := map[int][]string{5: {"B.foo", "A.foo"}}
	if err := writeXrefJSONL(
		dir,
		&cluster.Result{},
		&naming.PoolLookups{},
		nil,
		nil,
		nil,
		selectorTargets,
		false,
	); err != nil {
		t.Fatal(err)
	}

	recs, err := jsonutil.ReadJSONL[SelectorDispatchXref](filepath.Join(dir, "selector_dispatch_xref.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].SelectorOffset != 5 || !reflect.DeepEqual(recs[0].Targets, []string{"A.foo", "B.foo"}) {
		t.Fatalf("selector xref = %#v, want selector 5 -> sorted targets", recs)
	}
}

func TestWriteXrefFallbackIncludesVMOnlyPoolStrings(t *testing.T) {
	dir := t.TempDir()
	ct := &snapshot.CIDTable{String: 10, OneByteString: 11, TwoByteString: 12}
	cl := &cluster.Result{Pool: []cluster.PoolEntry{{Index: 7, Kind: cluster.PoolTagged, RefID: 41}}}
	pl := &naming.PoolLookups{
		CT:         ct,
		RefCID:     map[int]int{},
		VmRefCID:   map[int]int{41: ct.OneByteString},
		RefToStr:   map[int]string{},
		VmRefToStr: map[int]string{41: "vm-shared-string"},
	}
	if err := writeXrefJSONL(dir, cl, pl, nil, nil, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	recs, err := jsonutil.ReadJSONL[StringValueXref](filepath.Join(dir, "string_value_xref.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].StringValue != "vm-shared-string" || len(recs[0].Functions) != 0 {
		t.Fatalf("VM-only string fallback = %#v, want one empty-reader record", recs)
	}
}

func TestWriteXrefIncludesPolymorphicCandidatesWithoutInventingSingleCallee(t *testing.T) {
	dir := t.TempDir()
	edges := []disasm.CallEdgeRecord{{
		FromFunc:   "Caller",
		FromPC:     "0x100",
		Kind:       "blr",
		Targets:    []string{"A.paint", "B.paint"},
		Candidates: 2,
	}}
	if err := writeXrefJSONL(dir, &cluster.Result{}, &naming.PoolLookups{}, nil, edges, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	recs, err := jsonutil.ReadJSONL[AddressCallersXref](filepath.Join(dir, "address_callers_xref.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		t.Fatal(err)
	}
	want := []AddressCallersXref{
		{Target: "A.paint", Callers: []string{"Caller"}},
		{Target: "B.paint", Callers: []string{"Caller"}},
	}
	if !reflect.DeepEqual(recs, want) {
		t.Fatalf("address caller xref = %#v, want %#v", recs, want)
	}
}
