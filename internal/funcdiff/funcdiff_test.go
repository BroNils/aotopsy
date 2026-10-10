package funcdiff

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
	"aotopsy/internal/naming"
	"aotopsy/internal/snapshot"
)

const testLibraryURL = "package:test/test.dart"

func descriptor(lib, owner, name, kind, enclosing string) FuncDescriptor {
	return FuncDescriptor{LibraryURI: lib, Owner: owner, Name: name, Kind: kind, Enclosing: enclosing}
}

func testDescriptor(owner, name, kind, enclosing string) FuncDescriptor {
	return descriptor(testLibraryURL, owner, name, kind, enclosing)
}

// attachTestLibrary makes synthetic Function fixtures model the part of the
// snapshot object graph funcdiff uses for source-identity-shaped matching: Class -> Library
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
			{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1, CodeIndex: 50, FuncKind: cluster.FunctionKindRegular},
			{RefID: 3, CID: 10, NameRefID: 102, OwnerRefID: 1, CodeIndex: 51, FuncKind: cluster.FunctionKindRegular},
		},
	}
	// Two functions at distinct offsets in a synthetic instructions image.
	// PayloadInfo is deliberately NOT used here any more: it is the
	// unchecked-entry offset with a flag in the low bit, not a size.
	rangesA := []cluster.CodeRange{
		{RefID: 50, OwnerRef: 2, Index: 0, PCOffset: 0, Size: 8},
		{RefID: 51, OwnerRef: 3, Index: 1, PCOffset: 8, Size: 8},
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

	builtA := Build(resA, plA, profile, nil, rangesA, codeA, 0)
	funcsA := builtA.Functions
	if len(funcsA) != 2 || builtA.Stats.ResolvedFunctions != 2 || builtA.Stats.WithInstructionBytes != 2 {
		t.Fatalf("Build A = funcs=%d stats=%+v, want 2 resolved with bytes", len(funcsA), builtA.Stats)
	}

	resB := &cluster.Result{
		Named: []cluster.NamedObject{
			{RefID: 1, CID: 20, NameRefID: 100},
			{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1, CodeIndex: 50, FuncKind: cluster.FunctionKindRegular},
			{RefID: 4, CID: 10, NameRefID: 103, OwnerRefID: 1, CodeIndex: 52, FuncKind: cluster.FunctionKindRegular},
		},
	}
	// funcOne's body is rewritten to the SAME length. Diffing on size
	// alone would call it unchanged; the instruction hash catches it.
	rangesB := []cluster.CodeRange{
		{RefID: 50, OwnerRef: 2, Index: 0, PCOffset: 0, Size: 8},
		{RefID: 52, OwnerRef: 4, Index: 1, PCOffset: 8, Size: 8},
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

	funcsB := Build(resB, plB, profile, nil, rangesB, codeB, 0).Functions
	diff := DiffDescriptors(funcsA, funcsB, 0)

	wantOne := func(name string) FuncDescriptor {
		return testDescriptor("MyClass", name, "regular", "")
	}
	if len(diff.IdentityAdded) != 1 || diff.IdentityAdded[0] != (DiffEntry{Descriptor: wantOne("funcThree"), Count: 1}) {
		t.Errorf("IdentityAdded = %v, want funcThree x1", diff.IdentityAdded)
	}
	if len(diff.IdentityRemoved) != 1 || diff.IdentityRemoved[0] != (DiffEntry{Descriptor: wantOne("funcTwo"), Count: 1}) {
		t.Errorf("IdentityRemoved = %v, want funcTwo x1", diff.IdentityRemoved)
	}
	if len(diff.InstructionBytesDifferent) != 1 || diff.InstructionBytesDifferent[0] != (DiffEntry{Descriptor: wantOne("funcOne"), Count: 1}) {
		t.Errorf("InstructionBytesDifferent = %v, want funcOne x1", diff.InstructionBytesDifferent)
	}
	if diff.InstructionBytesDifferentTotal != 1 || diff.MatchedIdentityTotal != 1 {
		t.Fatalf("byte/identity totals = %+v", diff)
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
	got := Build(res, pl, profile, nil, nil, nil, 0).Functions
	d := descriptor("package:p/p.dart", "Owner", "vmOnlyName", "regular", "")
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
		if got := Build(res, pl, profile, nil, nil, nil, 0); funcSetCount(got.Functions) != 0 {
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
		if got := Build(res, pl, profile, nil, nil, nil, 0); funcSetCount(got.Functions) != 0 {
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
		if got := Build(res, pl, profile, nil, nil, nil, 0); funcSetCount(got.Functions) != 0 {
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
		if got := Build(res, pl, profile, nil, nil, nil, 0); funcSetCount(got.Functions) != 0 || got.Stats.SkippedUnstableKind != 1 {
			t.Fatalf("unknown Function kind became stable descriptor identity: %#v", got)
		}
	})

	t.Run("unmodelled function kind", func(t *testing.T) {
		res := &cluster.Result{Named: []cluster.NamedObject{
			{RefID: 2, CID: 20, NameRefID: 100},
			{RefID: 3, CID: 10, NameRefID: 101, OwnerRefID: 2, FuncKind: cluster.FunctionKindOther},
		}}
		pl := &naming.PoolLookups{CT: ct, RefToStr: map[int]string{100: "Owner", 101: "f"}}
		attachTestLibrary(res, pl, ct, 2)
		got := Build(res, pl, profile, nil, nil, nil, 0)
		if funcSetCount(got.Functions) != 0 || got.Stats.SkippedUnstableKind != 1 {
			t.Fatalf("unmodelled Function kind became stable identity: %+v", got)
		}
	})

	t.Run("illegal owner CID", func(t *testing.T) {
		res := &cluster.Result{Named: []cluster.NamedObject{
			{RefID: 2, CID: ct.Library, NameRefID: 100},
			{RefID: 3, CID: ct.Function, NameRefID: 101, OwnerRefID: 2, FuncKind: cluster.FunctionKindRegular},
		}}
		pl := &naming.PoolLookups{
			CT:         ct,
			RefToStr:   map[int]string{100: "looksLikeOwner", 101: "f"},
			RefToNamed: map[int]*cluster.NamedObject{2: &res.Named[0], 3: &res.Named[1]},
		}
		got := Build(res, pl, profile, nil, nil, nil, 0)
		if funcSetCount(got.Functions) != 0 || got.Stats.SkippedOwner != 1 {
			t.Fatalf("illegal Function owner became identity: %+v", got)
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
		if got := Build(res, pl, profile, nil, nil, nil, 0); funcSetCount(got.Functions) != 0 {
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
	got := Build(res, pl, profile, nil, nil, nil, 0).Functions
	d := testDescriptor("<top-level>", "f", "regular", "")
	if len(got[d]) != 1 || got[d][0].RefID != 3 {
		t.Fatalf("real top-level owner was not preserved: %#v", got)
	}
}

func TestBuildFunctionKindSeparatesConstructorFromRegularName(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 10, Class: 20}
	profile := &snapshot.VersionProfile{CIDs: ct}
	res := &cluster.Result{Named: []cluster.NamedObject{
		{RefID: 2, CID: 20, NameRefID: 100},
		{RefID: 3, CID: 10, NameRefID: 101, OwnerRefID: 2, FuncKind: cluster.FunctionKindRegular},
		{RefID: 4, CID: 10, NameRefID: 101, OwnerRefID: 2, FuncKind: cluster.FunctionKindConstructor},
	}}
	pl := &naming.PoolLookups{CT: ct, RefToStr: map[int]string{100: "Owner", 101: "Owner.named"}}
	attachTestLibrary(res, pl, ct, 2)
	got := Build(res, pl, profile, nil, nil, nil, 0).Functions
	regular := testDescriptor("Owner", "Owner.named", "regular", "")
	ctor := testDescriptor("Owner", "Owner.named", "constructor", "")
	if len(got[regular]) != 1 || len(got[ctor]) != 1 {
		t.Fatalf("constructor and regular function with same name aliased: %#v", got)
	}
}

func TestBuildPreservesDescriptorCollisionsAsMultiset(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 10, Class: 20}
	profile := &snapshot.VersionProfile{CIDs: ct}
	res := &cluster.Result{
		Named: []cluster.NamedObject{
			{RefID: 1, CID: 20, NameRefID: 100},
			{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1, DataRefID: 50, FuncKind: cluster.FunctionKindClosure},
			{RefID: 3, CID: 10, NameRefID: 101, OwnerRefID: 1, DataRefID: 51, FuncKind: cluster.FunctionKindClosure},
			{RefID: 4, CID: 10, NameRefID: 102, OwnerRefID: 1, FuncKind: cluster.FunctionKindRegular},
		},
		ClosureData: []cluster.ClosureDataInfo{
			{RefID: 50, ParentFunctionRef: 4},
			{RefID: 51, ParentFunctionRef: 4},
		},
	}
	pl := &naming.PoolLookups{
		CT:         ct,
		RefToStr:   map[int]string{100: "Owner", 101: "closure", 102: "outer"},
		RefToNamed: map[int]*cluster.NamedObject{1: &res.Named[0], 2: &res.Named[1], 3: &res.Named[2], 4: &res.Named[3]},
	}
	attachTestLibrary(res, pl, ct, 1)
	got := Build(res, pl, profile, nil, nil, nil, 0)
	d := testDescriptor("Owner", "closure", "closure", "Owner.outer")
	if len(got.Functions[d]) != 2 {
		t.Fatalf("collision descriptor has %d Functions, want 2: %#v", len(got.Functions[d]), got.Functions)
	}
	if got.Stats.ResolvedFunctions != 3 || got.Stats.CollisionBuckets != 1 || got.Stats.CollisionFunctions != 2 {
		t.Fatalf("collision stats = %+v, want resolved=3 buckets=1 funcs=2", got.Stats)
	}
}

func TestDiffDescriptorsKeepsDuplicateMismatchesIndeterminate(t *testing.T) {
	d := descriptor("lib", "Owner", "f", "closure", "Owner.outer")
	oldSet := FuncSet{d: {
		{RefID: 50, CodeSize: 4, InstrHash: "same"},
		{RefID: 10, CodeSize: 4, InstrHash: "old"},
	}}
	newSet := FuncSet{d: {
		{RefID: 999, CodeSize: 4, InstrHash: "new"},
		{RefID: 888, CodeSize: 4, InstrHash: "same"},
	}}
	rep := DiffDescriptors(oldSet, newSet, 0)
	if rep.OldIdentity.ResolvedFunctions != 2 || rep.NewIdentity.ResolvedFunctions != 2 || rep.MatchedIdentityTotal != 2 || rep.InstructionBytesDifferentTotal != 0 || rep.InstructionBytesIndeterminateTotal != 1 || rep.InstructionBytesEqualTotal != 1 {
		t.Fatalf("unexpected multiset report: %+v", rep)
	}
	if len(rep.InstructionBytesIndeterminate) != 1 || rep.InstructionBytesIndeterminate[0].Descriptor != d || rep.InstructionBytesIndeterminate[0].Count != 1 {
		t.Fatalf("InstructionBytesIndeterminate = %+v, want %q x1", rep.InstructionBytesIndeterminate, d.String())
	}
	if rep.IdentityAddedTotal != 0 || rep.IdentityRemovedTotal != 0 {
		t.Fatalf("same multiplicity became added/removed: %+v", rep)
	}
}

func TestBuildLegacyCodeRefDoesNotDependOnBogusCodeOwnerRef(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 10, Class: 20, Mint: 30}
	profile := &snapshot.VersionProfile{CIDs: ct}
	res := &cluster.Result{
		Named: []cluster.NamedObject{
			{RefID: 1, CID: 20, NameRefID: 100},
			{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1, CodeIndex: 50, FuncKind: cluster.FunctionKindRegular},
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
	d := testDescriptor("Owner", "f", "regular", "")
	if len(got.Functions[d]) != 1 || got.Functions[d][0].CodeSize != 4 || got.Functions[d][0].InstrHash == "" {
		t.Fatalf("legacy Function Code ref did not receive code evidence: %#v", got)
	}
}

func TestBuildModernSharedCodeGivesEachFunctionByteEvidence(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 10, Class: 20}
	profile := &snapshot.VersionProfile{CIDs: ct, CodeIndexOneBased: true}
	res := &cluster.Result{Named: []cluster.NamedObject{
		{RefID: 1, CID: 20, NameRefID: 100},
		{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1, CodeIndex: 11, FuncKind: cluster.FunctionKindRegular},
		{RefID: 3, CID: 10, NameRefID: 102, OwnerRefID: 1, CodeIndex: 11, FuncKind: cluster.FunctionKindRegular},
	}}
	pl := &naming.PoolLookups{CT: ct, RefToStr: map[int]string{100: "Owner", 101: "f", 102: "g"}}
	attachTestLibrary(res, pl, ct, 1)
	table := &cluster.InstructionsTable{FirstEntryWithCode: 10}
	ranges := []cluster.CodeRange{{RefID: 50, Index: 0, PCOffset: 0, Size: 4}}
	got := Build(res, pl, profile, table, ranges, []byte{1, 2, 3, 4}, 0)
	for _, name := range []string{"f", "g"} {
		d := testDescriptor("Owner", name, "regular", "")
		if len(got.Functions[d]) != 1 || got.Functions[d][0].InstrHash == "" {
			t.Fatalf("shared Code evidence missing for %s: %#v", name, got)
		}
	}
	if got.Stats.WithInstructionBytes != 2 || got.Stats.WithoutInstructionBytes != 0 {
		t.Fatalf("shared Code stats = %+v", got.Stats)
	}
}

func TestSameSourceIdentitySurvivesLegacyToIndexedCodeBoundary(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 10, Class: 20}
	makeBuild := func(profile *snapshot.VersionProfile, functionCodeIndex int, table *cluster.InstructionsTable, codeRef, clusterIndex int) BuildResult {
		res := &cluster.Result{Named: []cluster.NamedObject{
			{RefID: 1, CID: 20, NameRefID: 100},
			{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1, CodeIndex: functionCodeIndex, FuncKind: cluster.FunctionKindRegular},
		}}
		pl := &naming.PoolLookups{CT: ct, RefToStr: map[int]string{100: "Owner", 101: "f"}}
		attachTestLibrary(res, pl, ct, 1)
		ranges := []cluster.CodeRange{{RefID: codeRef, Index: clusterIndex, PCOffset: 0, Size: 4}}
		return Build(res, pl, profile, table, ranges, []byte{1, 2, 3, 4}, 0)
	}

	// <=2.15 stores an absolute Code ref. >=2.16 stores a one-based table slot.
	legacy := makeBuild(&snapshot.VersionProfile{CIDs: ct}, 50, nil, 50, 0)
	modern := makeBuild(&snapshot.VersionProfile{CIDs: ct, CodeIndexOneBased: true}, 11,
		&cluster.InstructionsTable{FirstEntryWithCode: 10}, 60, 0)
	rep := DiffDescriptors(legacy.Functions, modern.Functions, 0)
	if rep.MatchedIdentityTotal != 1 || rep.IdentityAddedTotal != 0 || rep.IdentityRemovedTotal != 0 ||
		rep.InstructionBytesEqualTotal != 1 || rep.InstructionBytesDifferentTotal != 0 || rep.InstructionBytesIndeterminateTotal != 0 {
		t.Fatalf("code-index format boundary created false identity/byte churn: %+v", rep)
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
		RefToStr:   map[int]string{100: "_Owner@709387912", 101: "_f@709387912", 102: "_parent@709387912", 103: "_Parent@709387912"},
		RefToNamed: map[int]*cluster.NamedObject{1: &res.Named[0], 2: &res.Named[1], 3: &res.Named[2], 4: &res.Named[3]},
	}
	attachTestLibrary(res, pl, ct, 1, 4)
	got := Build(res, pl, profile, nil, nil, nil, 0).Functions
	d := testDescriptor("_Owner", "_f", "closure", "_Parent._parent")
	if len(got[d]) != 1 {
		t.Fatalf("private key remained in descriptor: %#v", got)
	}
	if got := stableDescriptorName("name@not_a_vm_private_key.part"); got != "name@not_a_vm_private_key.part" {
		t.Fatalf("non-generated @ text was stripped: %q", got)
	}
}

func TestBuildUsesRecursiveClosureAncestry(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 10, Class: 20}
	profile := &snapshot.VersionProfile{CIDs: ct}
	res := &cluster.Result{
		Named: []cluster.NamedObject{
			{RefID: 1, CID: 20, NameRefID: 100},
			{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1, FuncKind: cluster.FunctionKindRegular},
			{RefID: 3, CID: 10, NameRefID: 102, OwnerRefID: 1, DataRefID: 50, FuncKind: cluster.FunctionKindClosure},
			{RefID: 4, CID: 10, NameRefID: 102, OwnerRefID: 1, DataRefID: 51, FuncKind: cluster.FunctionKindClosure},
		},
		ClosureData: []cluster.ClosureDataInfo{
			{RefID: 50, ParentFunctionRef: 2},
			{RefID: 51, ParentFunctionRef: 3},
		},
	}
	pl := &naming.PoolLookups{CT: ct, RefToStr: map[int]string{100: "Owner", 101: "outer", 102: "<anonymous closure>"}}
	attachTestLibrary(res, pl, ct, 1)
	got := Build(res, pl, profile, nil, nil, nil, 0).Functions
	first := testDescriptor("Owner", "<anonymous closure>", "closure", "Owner.outer")
	nested := testDescriptor("Owner", "<anonymous closure>", "closure", "Owner.outer.<anonymous closure>")
	if len(got[first]) != 1 || len(got[nested]) != 1 {
		t.Fatalf("recursive closure ancestry not preserved: %#v", got)
	}
}

func TestBuildDoesNotTreatStubRangeIndexAsCodeClusterIndex(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 10, Class: 20}
	profile := &snapshot.VersionProfile{CIDs: ct, CodeIndexOneBased: true}
	res := &cluster.Result{
		Named: []cluster.NamedObject{
			{RefID: 1, CID: 20, NameRefID: 100},
			{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1, CodeIndex: 3, FuncKind: cluster.FunctionKindRegular},
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
	table := &cluster.InstructionsTable{FirstEntryWithCode: 5}
	got := Build(res, pl, profile, table, ranges, []byte{1, 2, 3, 4}, 0)
	d := testDescriptor("Owner", "f", "regular", "")
	if len(got.Functions[d]) != 1 || got.Functions[d][0].CodeSize != 0 || got.Functions[d][0].InstrHash != "" {
		t.Fatalf("stub range leaked into Function code evidence: %#v", got)
	}
	if got.Stats.WithoutInstructionBytes != 1 {
		t.Fatalf("discarded/stub evidence was not surfaced as unavailable: %+v", got.Stats)
	}
}

func TestBuildDuplicateRangeIdentityFailsClosedToMissingBytes(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 10, Class: 20}
	profile := &snapshot.VersionProfile{CIDs: ct}
	res := &cluster.Result{Named: []cluster.NamedObject{
		{RefID: 1, CID: 20, NameRefID: 100},
		{RefID: 2, CID: 10, NameRefID: 101, OwnerRefID: 1, CodeIndex: 50, FuncKind: cluster.FunctionKindRegular},
	}}
	pl := &naming.PoolLookups{CT: ct, RefToStr: map[int]string{100: "Owner", 101: "f"}}
	attachTestLibrary(res, pl, ct, 1)
	ranges := []cluster.CodeRange{
		{RefID: 50, Index: 0, PCOffset: 0, Size: 4},
		{RefID: 50, Index: 1, PCOffset: 4, Size: 4},
	}
	got := Build(res, pl, profile, nil, ranges, []byte{1, 2, 3, 4, 5, 6, 7, 8}, 0)
	d := testDescriptor("Owner", "f", "regular", "")
	if len(got.Functions[d]) != 1 || got.Functions[d][0].InstrHash != "" || got.Stats.WithoutInstructionBytes != 1 {
		t.Fatalf("ambiguous duplicate Code ref was resolved last-wins: %+v", got)
	}
}

func TestDiffDescriptorsDoesNotLetMissingHashConsumeExactMatch(t *testing.T) {
	d := descriptor("lib", "Owner", "f", "regular", "")
	oldSet := FuncSet{d: {
		{RefID: 1, CodeSize: 4},
		{RefID: 2, CodeSize: 4, InstrHash: "A"},
	}}
	newSet := FuncSet{d: {
		{RefID: 3, CodeSize: 4, InstrHash: "A"},
		{RefID: 4, CodeSize: 4, InstrHash: "B"},
	}}
	rep := DiffDescriptors(oldSet, newSet, 0)
	if rep.InstructionBytesDifferentTotal != 0 || rep.InstructionBytesIndeterminateTotal != 1 || rep.MatchedIdentityTotal != 2 || rep.InstructionBytesEqualTotal != 1 {
		t.Fatalf("mixed evidence misclassified: %+v", rep)
	}
	if len(rep.InstructionBytesIndeterminate) != 1 || rep.InstructionBytesIndeterminate[0].Count != 1 {
		t.Fatalf("InstructionBytesIndeterminate = %+v, want one unknown pair", rep.InstructionBytesIndeterminate)
	}
}

func TestDiffDescriptorsMissingHashIsIndeterminateNotUnchanged(t *testing.T) {
	d := descriptor("lib", "Owner", "f", "regular", "")
	rep := DiffDescriptors(
		FuncSet{d: {{RefID: 1, CodeSize: 4, InstrHash: "A"}}},
		FuncSet{d: {{RefID: 2, CodeSize: 4}}}, 0)
	if rep.InstructionBytesDifferentTotal != 0 || rep.InstructionBytesIndeterminateTotal != 1 || rep.MatchedIdentityTotal != 1 {
		t.Fatalf("missing hash was not marked indeterminate: %+v", rep)
	}
}

func TestDiffDescriptorsDuplicateUnknownsDoNotForceKnownHashesToPair(t *testing.T) {
	d := descriptor("lib", "Owner", "f", "closure", "Owner.outer")
	oldSet := FuncSet{d: {
		{RefID: 1, CodeSize: 4, InstrHash: "B"},
		{RefID: 2, CodeSize: 4},
	}}
	newSet := FuncSet{d: {
		{RefID: 3, CodeSize: 4, InstrHash: "A"},
		{RefID: 4, CodeSize: 4},
	}}
	rep := DiffDescriptors(oldSet, newSet, 0)
	if rep.InstructionBytesDifferentTotal != 0 || rep.InstructionBytesIndeterminateTotal != 2 || rep.MatchedIdentityTotal != 2 {
		t.Fatalf("ambiguous duplicate identities overclaimed a change: %+v", rep)
	}
}

func TestCrossMachineDiffSuppressesRawByteChangedClassification(t *testing.T) {
	d := descriptor("lib", "Owner", "f", "regular", "")
	rep := diffDescriptors(
		FuncSet{d: {{RefID: 1, CodeSize: 4, InstrHash: "arm"}}},
		FuncSet{d: {{RefID: 2, CodeSize: 8, InstrHash: "x64"}}}, 0, false)
	if rep.InstructionBytesComparable || rep.InstructionBytesDifferentTotal != 0 || rep.InstructionBytesIndeterminateTotal != 1 || rep.MatchedIdentityTotal != 1 {
		t.Fatalf("cross-machine byte evidence was compared: %+v", rep)
	}
}

func TestReportSchemaDoesNotCallRawByteDifferenceSemanticChange(t *testing.T) {
	d := descriptor("lib", "Owner", "f", "regular", "")
	rep := DiffDescriptors(
		FuncSet{d: {{RefID: 1, CodeSize: 4, InstrHash: "old"}}},
		FuncSet{d: {{RefID: 2, CodeSize: 4, InstrHash: "new"}}}, 0)
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"instruction_bytes_different_total":1`) || strings.Contains(s, `"changed`) {
		t.Fatalf("report schema overclaims raw byte drift as semantic change: %s", s)
	}
}

func TestDiffDescriptorsJSONDeterministicAcrossMapInsertionOrder(t *testing.T) {
	a := descriptor("package:a/a.dart", "A", "f", "regular", "")
	b := descriptor("package:b/b.dart", "B", "g", "regular", "")
	old1 := FuncSet{}
	old1[b] = []FuncInfo{{RefID: 20, CodeSize: 4, InstrHash: "same-b"}}
	old1[a] = []FuncInfo{{RefID: 10, CodeSize: 4, InstrHash: "old-a"}}
	new1 := FuncSet{}
	new1[a] = []FuncInfo{{RefID: 99, CodeSize: 4, InstrHash: "new-a"}}
	new1[b] = []FuncInfo{{RefID: 88, CodeSize: 4, InstrHash: "same-b"}}

	old2 := FuncSet{a: append([]FuncInfo(nil), old1[a]...), b: append([]FuncInfo(nil), old1[b]...)}
	new2 := FuncSet{b: append([]FuncInfo(nil), new1[b]...), a: append([]FuncInfo(nil), new1[a]...)}
	j1, err := json.Marshal(DiffDescriptors(old1, new1, 0))
	if err != nil {
		t.Fatal(err)
	}
	j2, err := json.Marshal(DiffDescriptors(old2, new2, 0))
	if err != nil {
		t.Fatal(err)
	}
	if string(j1) != string(j2) {
		t.Fatalf("funcdiff JSON depends on map insertion order:\n%s\n%s", j1, j2)
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
