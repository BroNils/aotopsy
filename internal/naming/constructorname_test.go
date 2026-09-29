package naming

import (
	"testing"

	"aotopsy/internal/cluster"
	"aotopsy/internal/snapshot"
)

// Dart names a constructor after its class -- `Duration`,
// `_GrowableList.of`, `PlatformDispatcher._` -- so the Function name already
// carries the class and prepending the owner repeats it. The first version of
// this produced `_GrowableList.new _GrowableList.of`.
func TestConstructorNameDoesNotRepeatTheClass(t *testing.T) {
	ci := CodeNameInfo{FuncName: "new _GrowableList.of", OwnerName: "_GrowableList", IsConstructor: true}
	if got, want := ci.Qualified(0x1d8), "new _GrowableList.of_1d8"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// An ordinary method still gets the owner.
	m := CodeNameInfo{FuncName: "compareTo", OwnerName: "Duration"}
	if got, want := m.Qualified(0x80), "Duration.compareTo_80"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// And a nameless Code keeps the placeholder.
	e := CodeNameInfo{}
	if got, want := e.Qualified(0x10), "sub_10"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildClosureParentsConstructorUsesSDKQualification(t *testing.T) {
	ct := &snapshot.CIDTable{Class: 4, Function: 6}
	classObj := &cluster.NamedObject{CID: ct.Class, RefID: 10, NameRefID: 110, OwnerRefID: -1}
	ctor := &cluster.NamedObject{
		CID:        ct.Function,
		RefID:      20,
		NameRefID:  120,
		OwnerRefID: classObj.RefID,
		FuncKind:   cluster.FunctionKindConstructor,
	}
	closure := &cluster.NamedObject{
		CID:        ct.Function,
		RefID:      21,
		NameRefID:  121,
		OwnerRefID: classObj.RefID,
		DataRefID:  30,
		FuncKind:   cluster.FunctionKindClosure,
	}
	res := &cluster.Result{
		Named:       []cluster.NamedObject{*classObj, *ctor, *closure},
		ClosureData: []cluster.ClosureDataInfo{{RefID: 30, ParentFunctionRef: ctor.RefID}},
	}
	pl := &PoolLookups{
		CT: ct,
		RefToStr: map[int]string{
			110: "Future",
			120: "Future.delayed",
			121: "<anonymous closure>",
		},
		RefToNamed: map[int]*cluster.NamedObject{
			classObj.RefID: classObj,
			ctor.RefID:     ctor,
			closure.RefID:  closure,
		},
	}
	got := BuildClosureParents(res, pl)[closure.RefID]
	if want := "new Future.delayed"; got != want {
		t.Fatalf("constructor closure parent = %q, want %q", got, want)
	}
}

func TestBuildClosureParentsRejectsHighVMRefCollision(t *testing.T) {
	ct := &snapshot.CIDTable{Class: 4, Function: 6}
	closure := &cluster.NamedObject{
		CID: ct.Function, RefID: 200, NameRefID: 201, DataRefID: 300,
		FuncKind: cluster.FunctionKindClosure,
	}
	fakeVMParent := &cluster.NamedObject{CID: ct.Function, RefID: 100, NameRefID: 8}
	res := &cluster.Result{
		Named:       []cluster.NamedObject{*closure},
		ClosureData: []cluster.ClosureDataInfo{{RefID: 300, ParentFunctionRef: fakeVMParent.RefID}},
	}
	pl := &PoolLookups{
		CT:           ct,
		BaseObjLimit: 50,
		RefToNamed:   map[int]*cluster.NamedObject{closure.RefID: closure},
		RefToStr:     map[int]string{closure.NameRefID: "<anonymous closure>"},
		VmRefToNamed: map[int]*cluster.NamedObject{fakeVMParent.RefID: fakeVMParent},
		VmRefToStr:   map[int]string{8: "wrongVMParent"},
	}
	if got := BuildClosureParents(res, pl); got != nil {
		t.Fatalf("high ClosureData parent ref crossed into VM namespace: %v", got)
	}
}

func TestBuildDiscardedFunctionSymbolsConstructorDoesNotRepeatOwner(t *testing.T) {
	ct := &snapshot.CIDTable{Class: 4, Function: 6}
	classObj := &cluster.NamedObject{CID: ct.Class, RefID: 10, NameRefID: 110, OwnerRefID: -1}
	ctor := cluster.NamedObject{
		CID:        ct.Function,
		RefID:      20,
		NameRefID:  120,
		OwnerRefID: classObj.RefID,
		CodeIndex:  1,
		FuncKind:   cluster.FunctionKindConstructor,
	}
	method := cluster.NamedObject{
		CID:        ct.Function,
		RefID:      21,
		NameRefID:  121,
		OwnerRefID: classObj.RefID,
		CodeIndex:  2,
		FuncKind:   cluster.FunctionKindRegular,
	}
	pl := &PoolLookups{
		CT: ct,
		RefToStr: map[int]string{
			110: "Widget",
			120: "Widget.named",
			121: "build",
		},
		RefToNamed: map[int]*cluster.NamedObject{classObj.RefID: classObj},
	}
	table := &cluster.InstructionsTable{
		FirstEntryWithCode: 2,
		Entries: []cluster.InstrTableEntry{
			{PCOffset: 0x20},
			{PCOffset: 0x40},
		},
	}
	got := BuildDiscardedFunctionSymbols(
		[]cluster.NamedObject{ctor, method}, ct, table, pl,
		0x1000, 0, true,
	)
	if want := "new Widget.named"; got[0x1020] != want {
		t.Fatalf("discarded constructor = %q, want %q", got[0x1020], want)
	}
	if want := "Widget.build"; got[0x1040] != want {
		t.Fatalf("discarded method = %q, want %q", got[0x1040], want)
	}
}
