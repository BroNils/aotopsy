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
	}
	// Two functions at distinct offsets in a synthetic instructions image.
	// PayloadInfo is deliberately NOT used here any more: it is the
	// unchecked-entry offset with a flag in the low bit, not a size.
	rangesA := []cluster.CodeRange{
		{OwnerRef: 2, PCOffset: 0, Size: 8},
		{OwnerRef: 3, PCOffset: 8, Size: 8},
	}
	codeA := []byte{
		1, 1, 1, 1, 1, 1, 1, 1,
		2, 2, 2, 2, 2, 2, 2, 2,
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

	funcsA := Build(resA, plA, ct, rangesA, codeA, 0)
	if len(funcsA) != 2 {
		t.Fatalf("Build A got %d funcs, want 2", len(funcsA))
	}

	resB := &cluster.Result{
		Named: []cluster.NamedObject{
			{RefID: 1, CID: 20, NameRefID: 100},
			{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1},
			{RefID: 4, CID: 10, NameRefID: 103, OwnerRefID: 1},
		},
	}
	// funcOne's body is rewritten to the SAME length. Diffing on size
	// alone would call it unchanged; the instruction hash catches it.
	rangesB := []cluster.CodeRange{
		{OwnerRef: 2, PCOffset: 0, Size: 8},
		{OwnerRef: 4, PCOffset: 8, Size: 8},
	}
	codeB := []byte{
		9, 9, 9, 9, 9, 9, 9, 9,
		3, 3, 3, 3, 3, 3, 3, 3,
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

	funcsB := Build(resB, plB, ct, rangesB, codeB, 0)
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
