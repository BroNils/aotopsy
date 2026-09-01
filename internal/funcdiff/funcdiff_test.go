package funcdiff

import (
	"testing"

	"aotopsy/internal/cluster"
	"aotopsy/internal/naming"
	"aotopsy/internal/snapshot"
)

func TestBuildAndDiff(t *testing.T) {
	ct := &snapshot.CIDTable{
		Function: 10,
		Class:    20,
	}

	resA := &cluster.Result{
		Named: []cluster.NamedObject{
			{RefID: 1, CID: 20, NameRefID: 100},
			{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1},
			{RefID: 3, CID: 10, NameRefID: 102, OwnerRefID: 1},
		},
		Codes: []cluster.CodeEntry{
			{OwnerRef: 2, PayloadInfo: 64},
			{OwnerRef: 3, PayloadInfo: 128},
		},
	}
	plA := &naming.PoolLookups{
		RefToStr: map[int]string{
			100: "MyClass",
			101: "funcOne",
			102: "funcTwo",
		},
		RefToNamed: map[int]*cluster.NamedObject{
			1: &resA.Named[0],
			2: &resA.Named[1],
			3: &resA.Named[2],
		},
	}

	funcsA := Build(resA, plA, ct)
	if len(funcsA) != 2 {
		t.Fatalf("Build A got %d funcs, want 2", len(funcsA))
	}

	resB := &cluster.Result{
		Named: []cluster.NamedObject{
			{RefID: 1, CID: 20, NameRefID: 100},
			{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1},
			{RefID: 4, CID: 10, NameRefID: 103, OwnerRefID: 1},
		},
		Codes: []cluster.CodeEntry{
			{OwnerRef: 2, PayloadInfo: 96}, // size changed
			{OwnerRef: 4, PayloadInfo: 32},
		},
	}
	plB := &naming.PoolLookups{
		RefToStr: map[int]string{
			100: "MyClass",
			101: "funcOne",
			103: "funcThree",
		},
		RefToNamed: map[int]*cluster.NamedObject{
			1: &resB.Named[0],
			2: &resB.Named[1],
			4: &resB.Named[2],
		},
	}

	funcsB := Build(resB, plB, ct)
	diff := DiffDescriptors(funcsA, funcsB, 0)

	if len(diff.Added) != 1 || diff.Added[0] != "MyClass::funcThree" {
		t.Errorf("Added = %v, want [MyClass::funcThree]", diff.Added)
	}
	if len(diff.Removed) != 1 || diff.Removed[0] != "MyClass::funcTwo" {
		t.Errorf("Removed = %v, want [MyClass::funcTwo]", diff.Removed)
	}
	if len(diff.Changed) != 1 || diff.Changed[0] != "MyClass::funcOne" {
		t.Errorf("Changed = %v, want [MyClass::funcOne]", diff.Changed)
	}
}
