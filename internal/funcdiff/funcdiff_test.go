package funcdiff

import (
	"errors"
	"testing"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
	"aotopsy/internal/naming"
	"aotopsy/internal/snapshot"
)

const testLibraryURL = "package:test/test.dart"

// attachTestLibrary makes synthetic Function fixtures model the part of the
// snapshot object graph funcdiff uses for semantic identity: Class -> Library
// -> URL string. Rebuild RefToNamed after appending so every stored pointer
// refers to the current Named slice.
func attachTestLibrary(res *cluster.Result, pl *naming.PoolLookups, ct *snapshot.CIDTable, classRefs ...int) {
	const (
		libraryCID = 900
		libraryRef = 9000
		urlRef     = 9001
	)
	if ct.Library == 0 {
		ct.Library = libraryCID
	}
	for i, classRef := range classRefs {
		if classRef > cluster.RefNull {
			continue
		}
		// Older unit fixtures predated the explicit RefNull sentinel and used
		// ref 1 for an ordinary Class. Real snapshot allocations start after
		// the base-object prefix, so move only that synthetic Class to a valid
		// high ref and repair Function owners before adding library identity.
		validRef := 8000 + i
		for j := range res.Named {
			if res.Named[j].RefID == classRef && res.Named[j].CID == ct.Class {
				res.Named[j].RefID = validRef
			}
			if res.Named[j].OwnerRefID == classRef {
				res.Named[j].OwnerRefID = validRef
			}
		}
		for j := range res.Classes {
			if res.Classes[j].RefID == classRef {
				res.Classes[j].RefID = validRef
			}
		}
		classRefs[i] = validRef
	}
	res.Named = append(res.Named, cluster.NamedObject{RefID: libraryRef, CID: ct.Library, NameRefID: urlRef})
	for _, classRef := range classRefs {
		found := false
		for i := range res.Classes {
			if res.Classes[i].RefID == classRef {
				res.Classes[i].LibraryRefID = libraryRef
				found = true
				break
			}
		}
		if !found {
			res.Classes = append(res.Classes, cluster.ClassInfo{RefID: classRef, LibraryRefID: libraryRef})
		}
	}
	if pl.RefToStr == nil {
		pl.RefToStr = make(map[int]string)
	}
	pl.RefToStr[urlRef] = testLibraryURL
	pl.RefToNamed = make(map[int]*cluster.NamedObject, len(res.Named))
	for i := range res.Named {
		pl.RefToNamed[res.Named[i].RefID] = &res.Named[i]
	}
	pl.CT = ct
}

func TestBuildAndDiff(t *testing.T) {
	ct := &snapshot.CIDTable{
		Function: 10,
		Class:    20,
	}
	profile := &snapshot.VersionProfile{CIDs: ct}

	resA := &cluster.Result{
		Named: []cluster.NamedObject{
			{RefID: 1, CID: 20, NameRefID: 100},
			{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1, FuncKind: cluster.FunctionKindRegular},
			{RefID: 3, CID: 10, NameRefID: 102, OwnerRefID: 1, FuncKind: cluster.FunctionKindRegular},
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
	attachTestLibrary(resA, plA, ct, 1)

	funcsA := Build(resA, plA, profile, nil, rangesA, codeA, 0)
	if len(funcsA) != 2 {
		t.Fatalf("Build A got %d funcs, want 2", len(funcsA))
	}

	resB := &cluster.Result{
		Named: []cluster.NamedObject{
			{RefID: 1, CID: 20, NameRefID: 100},
			{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1, FuncKind: cluster.FunctionKindRegular},
			{RefID: 4, CID: 10, NameRefID: 103, OwnerRefID: 1, FuncKind: cluster.FunctionKindRegular},
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
	attachTestLibrary(resB, plB, ct, 1)

	funcsB := Build(resB, plB, profile, nil, rangesB, codeB, 0)
	diff := DiffDescriptors(funcsA, funcsB, 0)

	wantOne := func(name string) string {
		return testLibraryURL + "::MyClass::" + name + " [kind=regular]"
	}
	if len(diff.Added) != 1 || diff.Added[0] != (DiffEntry{Descriptor: wantOne("funcThree"), Count: 1}) {
		t.Errorf("Added = %v, want funcThree x1", diff.Added)
	}
	if len(diff.Removed) != 1 || diff.Removed[0] != (DiffEntry{Descriptor: wantOne("funcTwo"), Count: 1}) {
		t.Errorf("Removed = %v, want funcTwo x1", diff.Removed)
	}
	if len(diff.Changed) != 1 || diff.Changed[0] != (DiffEntry{Descriptor: wantOne("funcOne"), Count: 1}) {
		t.Errorf("Changed = %v, want funcOne x1", diff.Changed)
	}
}

func TestBuildUsesVMOnlyFunctionNameAndLibraryIdentity(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 10, Class: 20, Library: 30, OneByteString: 40}
	profile := &snapshot.VersionProfile{CIDs: ct}
	res := &cluster.Result{
		Named: []cluster.NamedObject{
			{RefID: 4, CID: 30, NameRefID: 101},
			{RefID: 2, CID: 20, NameRefID: 102},
			{RefID: 3, CID: 10, NameRefID: 103, OwnerRefID: 2, FuncKind: cluster.FunctionKindRegular},
		},
		Classes: []cluster.ClassInfo{{RefID: 2, ClassID: 77, LibraryRefID: 4}},
	}
	pl := &naming.PoolLookups{
		CT:           ct,
		RefToStr:     map[int]string{102: "Owner"},
		VmRefToStr:   map[int]string{101: "package:p/p.dart", 103: "vmOnlyName"},
		VmRefCID:     map[int]int{101: 40, 103: 40},
		RefToNamed:   map[int]*cluster.NamedObject{4: &res.Named[0], 2: &res.Named[1], 3: &res.Named[2]},
		VmRefToNamed: map[int]*cluster.NamedObject{},
		BaseObjLimit: 1000,
	}
	got := Build(res, pl, profile, nil, nil, nil, 0)
	d := FuncDescriptor("package:p/p.dart::Owner::vmOnlyName [kind=regular]")
	if len(got[d]) != 1 || got[d][0].RefID != 3 {
		t.Fatalf("VM-only named Function missing: %#v", got)
	}
}

func TestBuildDoesNotAliasAppRefsIntoVMNamespace(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 10, Class: 20, Library: 30, OneByteString: 40}
	profile := &snapshot.VersionProfile{CIDs: ct}

	t.Run("function name", func(t *testing.T) {
		res := &cluster.Result{Named: []cluster.NamedObject{
			{RefID: 2, CID: 20, NameRefID: 100},
			{RefID: 3, CID: 10, NameRefID: 999, OwnerRefID: 2, FuncKind: cluster.FunctionKindRegular},
		}}
		pl := &naming.PoolLookups{
			CT:           ct,
			RefToStr:     map[int]string{100: "Owner"},
			VmRefToStr:   map[int]string{999: "wrongVmName"},
			VmRefCID:     map[int]int{999: 40},
			BaseObjLimit: 100,
		}
		attachTestLibrary(res, pl, ct, 2)
		if got := Build(res, pl, profile, nil, nil, nil, 0); funcSetCount(got) != 0 {
			t.Fatalf("app-domain NameRef reused unrelated VM string: %#v", got)
		}
	})

	t.Run("owner and library objects", func(t *testing.T) {
		vmClass := cluster.NamedObject{RefID: 999, CID: 20, NameRefID: 997}
		vmLibrary := cluster.NamedObject{RefID: 998, CID: 30, NameRefID: 996}
		res := &cluster.Result{
			Named:   []cluster.NamedObject{{RefID: 3, CID: 10, NameRefID: 101, OwnerRefID: 999, FuncKind: cluster.FunctionKindRegular}},
			Classes: []cluster.ClassInfo{{RefID: 999, LibraryRefID: 998}},
		}
		pl := &naming.PoolLookups{
			CT:           ct,
			RefToStr:     map[int]string{101: "f"},
			RefToNamed:   map[int]*cluster.NamedObject{3: &res.Named[0]},
			VmRefToStr:   map[int]string{997: "WrongOwner", 996: "package:wrong/wrong.dart"},
			VmRefCID:     map[int]int{997: 40, 996: 40},
			VmRefToNamed: map[int]*cluster.NamedObject{999: &vmClass, 998: &vmLibrary},
			BaseObjLimit: 100,
		}
		if got := Build(res, pl, profile, nil, nil, nil, 0); funcSetCount(got) != 0 {
			t.Fatalf("app-domain owner/library refs reused VM objects: %#v", got)
		}
	})
}

func TestBuildRequiresCompleteSemanticIdentity(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 10, Class: 20, Library: 30}
	profile := &snapshot.VersionProfile{CIDs: ct}

	t.Run("library", func(t *testing.T) {
		res := &cluster.Result{
			Named: []cluster.NamedObject{
				{RefID: 2, CID: 20, NameRefID: 100},
				{RefID: 3, CID: 10, NameRefID: 101, OwnerRefID: 2, FuncKind: cluster.FunctionKindRegular},
			},
			Classes: []cluster.ClassInfo{{RefID: 2, LibraryRefID: cluster.RefNull}},
		}
		pl := &naming.PoolLookups{
			CT:         ct,
			RefToStr:   map[int]string{100: "void", 101: "<optimized out>"},
			RefToNamed: map[int]*cluster.NamedObject{2: &res.Named[0], 3: &res.Named[1]},
		}
		if got := Build(res, pl, profile, nil, nil, nil, 0); funcSetCount(got) != 0 {
			t.Fatalf("library-less Function became a stable descriptor: %#v", got)
		}
	})

	t.Run("unknown function kind", func(t *testing.T) {
		res := &cluster.Result{Named: []cluster.NamedObject{
			{RefID: 2, CID: 20, NameRefID: 100},
			{RefID: 3, CID: 10, NameRefID: 101, OwnerRefID: 2, FuncKind: cluster.FunctionKindUnknown},
		}}
		pl := &naming.PoolLookups{CT: ct, RefToStr: map[int]string{100: "Owner", 101: "f"}}
		attachTestLibrary(res, pl, ct, 2)
		if got := Build(res, pl, profile, nil, nil, nil, 0); funcSetCount(got) != 0 {
			t.Fatalf("unknown Function kind became semantic identity: %#v", got)
		}
	})

	t.Run("required closure parent", func(t *testing.T) {
		res := &cluster.Result{
			Named: []cluster.NamedObject{
				{RefID: 2, CID: 20, NameRefID: 100},
				{RefID: 3, CID: 10, NameRefID: 101, OwnerRefID: 2, DataRefID: 50, FuncKind: cluster.FunctionKindClosure},
				{RefID: 4, CID: 10, NameRefID: 999, OwnerRefID: 2, FuncKind: cluster.FunctionKindRegular},
			},
			ClosureData: []cluster.ClosureDataInfo{{RefID: 50, ParentFunctionRef: 4}},
		}
		pl := &naming.PoolLookups{
			CT:           ct,
			RefToStr:     map[int]string{100: "Owner", 101: "<anonymous closure>"},
			VmRefToStr:   map[int]string{999: "wrongParent"},
			BaseObjLimit: 100,
		}
		attachTestLibrary(res, pl, ct, 2)
		if got := Build(res, pl, profile, nil, nil, nil, 0); funcSetCount(got) != 0 {
			t.Fatalf("closure with unresolved required parent lost its qualifier: %#v", got)
		}
	})
}

func TestBuildRecognizesRealTopLevelOwner(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 10, Class: 20}
	profile := &snapshot.VersionProfile{CIDs: ct}
	res := &cluster.Result{Named: []cluster.NamedObject{
		{RefID: 2, CID: 20, NameRefID: 100},
		{RefID: 3, CID: 10, NameRefID: 101, OwnerRefID: 2, FuncKind: cluster.FunctionKindRegular},
	}}
	pl := &naming.PoolLookups{CT: ct, RefToStr: map[int]string{100: "::", 101: "f"}}
	attachTestLibrary(res, pl, ct, 2)
	got := Build(res, pl, profile, nil, nil, nil, 0)
	d := FuncDescriptor(testLibraryURL + "::<top-level>::f [kind=regular]")
	if len(got[d]) != 1 || got[d][0].RefID != 3 {
		t.Fatalf("real top-level owner was not preserved: %#v", got)
	}
}

func TestBuildPreservesDescriptorCollisionsAsMultiset(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 10, Class: 20}
	profile := &snapshot.VersionProfile{CIDs: ct}
	res := &cluster.Result{Named: []cluster.NamedObject{
		{RefID: 1, CID: 20, NameRefID: 100},
		{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1, FuncKind: cluster.FunctionKindClosure},
		{RefID: 3, CID: 10, NameRefID: 101, OwnerRefID: 1, FuncKind: cluster.FunctionKindClosure},
	}}
	pl := &naming.PoolLookups{
		CT:         ct,
		RefToStr:   map[int]string{100: "Owner", 101: "closure"},
		RefToNamed: map[int]*cluster.NamedObject{1: &res.Named[0], 2: &res.Named[1], 3: &res.Named[2]},
	}
	attachTestLibrary(res, pl, ct, 1)
	got := Build(res, pl, profile, nil, nil, nil, 0)
	if funcSetCount(got) != 2 {
		t.Fatalf("Build retained %d Functions, want 2: %#v", funcSetCount(got), got)
	}
	for d, list := range got {
		if len(list) != 2 {
			t.Fatalf("descriptor %q has %d entries, want 2", d, len(list))
		}
	}
}

func TestDiffDescriptorsKeepsDuplicateMismatchesIndeterminate(t *testing.T) {
	d := FuncDescriptor("lib::Owner::f [kind=closure]")
	oldSet := FuncSet{d: {
		{RefID: 50, CodeSize: 4, InstrHash: "same"},
		{RefID: 10, CodeSize: 4, InstrHash: "old"},
	}}
	newSet := FuncSet{d: {
		{RefID: 999, CodeSize: 4, InstrHash: "new"},
		{RefID: 888, CodeSize: 4, InstrHash: "same"},
	}}
	rep := DiffDescriptors(oldSet, newSet, 0)
	if rep.OldCount != 2 || rep.NewCount != 2 || rep.CommonCount != 2 || rep.ChangedTotal != 0 || rep.IndeterminateTotal != 1 {
		t.Fatalf("unexpected multiset report: %+v", rep)
	}
	if len(rep.Indeterminate) != 1 || rep.Indeterminate[0].Descriptor != string(d) || rep.Indeterminate[0].Count != 1 {
		t.Fatalf("Indeterminate = %+v, want %q x1", rep.Indeterminate, d)
	}
	if rep.AddedTotal != 0 || rep.RemovedTotal != 0 {
		t.Fatalf("same multiplicity became added/removed: %+v", rep)
	}
}

func TestBuildPrefersCodeIndexOwnerOverBogusCodeOwnerRef(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 10, Class: 20, Mint: 30}
	profile := &snapshot.VersionProfile{CIDs: ct}
	res := &cluster.Result{
		Named: []cluster.NamedObject{
			{RefID: 1, CID: 20, NameRefID: 100},
			{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1, CodeIndex: 7, FuncKind: cluster.FunctionKindRegular},
			{RefID: 900, CID: 30}, // the bogus raw Code.OwnerRef shape seen in 3.7 x86_64
		},
		Codes: []cluster.CodeEntry{{RefID: 50, OwnerRef: 900, ClusterIndex: 7}},
	}
	pl := &naming.PoolLookups{
		CT:         ct,
		RefToStr:   map[int]string{100: "Owner", 101: "f"},
		RefToNamed: map[int]*cluster.NamedObject{1: &res.Named[0], 2: &res.Named[1], 900: &res.Named[2]},
	}
	attachTestLibrary(res, pl, ct, 1)
	ranges := []cluster.CodeRange{{RefID: 50, OwnerRef: 900, Index: 7, PCOffset: 0, Size: 4}}
	got := Build(res, pl, profile, nil, ranges, []byte{1, 2, 3, 4}, 0)
	d := FuncDescriptor(testLibraryURL + "::Owner::f [kind=regular]")
	if len(got[d]) != 1 || got[d][0].CodeSize != 4 || got[d][0].InstrHash == "" {
		t.Fatalf("reliable CodeIndex owner did not receive code evidence: %#v", got)
	}
}

func TestBuildStripsPrivateLibraryKeysFromDescriptorNames(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 10, Class: 20}
	profile := &snapshot.VersionProfile{CIDs: ct}
	res := &cluster.Result{Named: []cluster.NamedObject{
		{RefID: 1, CID: 20, NameRefID: 100},
		{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1, DataRefID: 50, FuncKind: cluster.FunctionKindClosure},
		{RefID: 3, CID: 10, NameRefID: 102, OwnerRefID: 4, FuncKind: cluster.FunctionKindRegular},
		{RefID: 4, CID: 20, NameRefID: 103},
	}, ClosureData: []cluster.ClosureDataInfo{{RefID: 50, ParentFunctionRef: 3}}}
	pl := &naming.PoolLookups{
		CT:         ct,
		RefToStr:   map[int]string{100: "_Owner@6be832b", 101: "_f@6be832b", 102: "_parent@6be832b", 103: "_Parent@6be832b"},
		RefToNamed: map[int]*cluster.NamedObject{1: &res.Named[0], 2: &res.Named[1], 3: &res.Named[2], 4: &res.Named[3]},
	}
	attachTestLibrary(res, pl, ct, 1, 4)
	got := Build(res, pl, profile, nil, nil, nil, 0)
	d := FuncDescriptor(testLibraryURL + "::_Owner::_f [kind=closure] [parent=_Parent._parent]")
	if len(got[d]) != 1 {
		t.Fatalf("private key remained in descriptor: %#v", got)
	}
}

func TestBuildDoesNotTreatStubRangeIndexAsCodeClusterIndex(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 10, Class: 20}
	profile := &snapshot.VersionProfile{CIDs: ct}
	res := &cluster.Result{
		Named: []cluster.NamedObject{
			{RefID: 1, CID: 20, NameRefID: 100},
			{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1, CodeIndex: 0, FuncKind: cluster.FunctionKindRegular},
		},
		Codes: []cluster.CodeEntry{{RefID: 50, OwnerRef: 2, ClusterIndex: 0}},
	}
	pl := &naming.PoolLookups{
		CT:         ct,
		RefToStr:   map[int]string{100: "Owner", 101: "f"},
		RefToNamed: map[int]*cluster.NamedObject{1: &res.Named[0], 2: &res.Named[1]},
	}
	attachTestLibrary(res, pl, ct, 1)
	// Stub indices start at zero too. With no real Code range present, this
	// must not fabricate code evidence for Function ref 2.
	ranges := []cluster.CodeRange{{RefID: -1, OwnerRef: -1, Index: 0, PCOffset: 0, Size: 4}}
	got := Build(res, pl, profile, nil, ranges, []byte{1, 2, 3, 4}, 0)
	d := FuncDescriptor(testLibraryURL + "::Owner::f [kind=regular]")
	if len(got[d]) != 1 || got[d][0].CodeSize != 0 || got[d][0].InstrHash != "" {
		t.Fatalf("stub range leaked into Function code evidence: %#v", got)
	}
}

func TestDiffDescriptorsDoesNotLetMissingHashConsumeExactMatch(t *testing.T) {
	d := FuncDescriptor("lib::Owner::f [kind=regular]")
	oldSet := FuncSet{d: {
		{RefID: 1, CodeSize: 4},
		{RefID: 2, CodeSize: 4, InstrHash: "A"},
	}}
	newSet := FuncSet{d: {
		{RefID: 3, CodeSize: 4, InstrHash: "A"},
		{RefID: 4, CodeSize: 4, InstrHash: "B"},
	}}
	rep := DiffDescriptors(oldSet, newSet, 0)
	if rep.ChangedTotal != 0 || rep.IndeterminateTotal != 1 || rep.CommonCount != 2 {
		t.Fatalf("mixed evidence misclassified: %+v", rep)
	}
	if len(rep.Indeterminate) != 1 || rep.Indeterminate[0].Count != 1 {
		t.Fatalf("Indeterminate = %+v, want one unknown pair", rep.Indeterminate)
	}
}

func TestDiffDescriptorsMissingHashIsIndeterminateNotUnchanged(t *testing.T) {
	d := FuncDescriptor("lib::Owner::f [kind=regular]")
	rep := DiffDescriptors(
		FuncSet{d: {{RefID: 1, CodeSize: 4, InstrHash: "A"}}},
		FuncSet{d: {{RefID: 2, CodeSize: 4}}}, 0)
	if rep.ChangedTotal != 0 || rep.IndeterminateTotal != 1 || rep.CommonCount != 1 {
		t.Fatalf("missing hash was not marked indeterminate: %+v", rep)
	}
}

func TestDiffDescriptorsDuplicateUnknownsDoNotForceKnownHashesToPair(t *testing.T) {
	d := FuncDescriptor("lib::Owner::f [kind=closure]")
	oldSet := FuncSet{d: {
		{RefID: 1, CodeSize: 4, InstrHash: "B"},
		{RefID: 2, CodeSize: 4},
	}}
	newSet := FuncSet{d: {
		{RefID: 3, CodeSize: 4, InstrHash: "A"},
		{RefID: 4, CodeSize: 4},
	}}
	rep := DiffDescriptors(oldSet, newSet, 0)
	if rep.ChangedTotal != 0 || rep.IndeterminateTotal != 2 || rep.CommonCount != 2 {
		t.Fatalf("ambiguous duplicate identities overclaimed a change: %+v", rep)
	}
}

func TestCrossMachineDiffSuppressesRawByteChangedClassification(t *testing.T) {
	d := FuncDescriptor("lib::Owner::f [kind=regular]")
	rep := diffDescriptors(
		FuncSet{d: {{RefID: 1, CodeSize: 4, InstrHash: "arm"}}},
		FuncSet{d: {{RefID: 2, CodeSize: 8, InstrHash: "x64"}}}, 0, false)
	if rep.CodeComparable || rep.ChangedTotal != 0 || rep.IndeterminateTotal != 1 || rep.CommonCount != 1 {
		t.Fatalf("cross-machine byte evidence was compared: %+v", rep)
	}
}

func TestRequireCompleteVMLegacyAndUnifiedSnapshots(t *testing.T) {
	t.Run("legacy requires VM header and result", func(t *testing.T) {
		sc := &analysis.SnapshotContext{Info: &snapshot.Info{}}
		if err := requireCompleteVM(sc); err == nil {
			t.Fatal("legacy snapshot without VM header was accepted")
		}
		sc.Info.VmHeader = &snapshot.Header{}
		if err := requireCompleteVM(sc); err == nil {
			t.Fatal("legacy snapshot without VM result was accepted")
		}
		sc.VMResult = &cluster.Result{}
		if err := requireCompleteVM(sc); err != nil {
			t.Fatalf("complete legacy VM snapshot rejected: %v", err)
		}
	})

	t.Run("legacy propagates parse error", func(t *testing.T) {
		sc := &analysis.SnapshotContext{
			Info:     &snapshot.Info{VmHeader: &snapshot.Header{}},
			VMResult: &cluster.Result{},
			VMError:  errors.New("bad VM fill"),
		}
		if err := requireCompleteVM(sc); err == nil {
			t.Fatal("legacy VM parse error was ignored")
		}
	})

	t.Run("unified snapshot needs no separate VM result", func(t *testing.T) {
		sc := &analysis.SnapshotContext{Info: &snapshot.Info{UnifiedSnapshot: true}}
		if err := requireCompleteVM(sc); err != nil {
			t.Fatalf("unified snapshot rejected: %v", err)
		}
	})
}
