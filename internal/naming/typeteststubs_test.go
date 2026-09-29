package naming

import (
	"strings"
	"testing"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/snapshot"
)

// loadForNaming is the cluster-only path (ELF -> snapshot -> alloc -> fill),
// with the VM isolate too, because half the naming paths consult it and a nil
// vmResult silently changes what the numbers mean. Measuring this gap with
// vmResult nil is exactly the mistake that produced a first, wrong reading of
// it: 877 Codes looked like "owner resolved, name empty" when the real figure
// with the VM strings present is 0.
func loadForNaming(t *testing.T, libPath string) (*cluster.Result, *cluster.Result, *snapshot.VersionProfile) {
	t.Helper()
	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}
	ef, err := elfx.Open(libPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = ef.Close() }()
	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if info.Version == nil || !info.Version.Supported {
		t.Skipf("unsupported snapshot in %s", libPath)
	}
	data := info.IsolateData.Data
	start, err := snapshot.FindClusterDataStart(data)
	if err != nil {
		t.Fatalf("cluster start: %v", err)
	}
	res, err := cluster.ScanClusters(data, start, info.Version, false, opts)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var size int64
	if info.IsolateHeader != nil {
		size = info.IsolateHeader.TotalSize
	}
	if err := cluster.ReadFill(data, res, info.Version, false, size, dartfmt.Options{}); err != nil {
		t.Fatalf("fill: %v", err)
	}
	var vmRes *cluster.Result
	if vmData := info.VmData.Data; len(vmData) >= 64 && info.VmHeader != nil {
		if vmStart, err := snapshot.FindClusterDataStart(vmData); err == nil {
			if r, err := cluster.ScanClusters(vmData, vmStart, info.Version, true, opts); err == nil {
				_ = cluster.ReadFill(vmData, r, info.Version, true, info.VmHeader.TotalSize, dartfmt.Options{})
				vmRes = r
			}
		}
	}
	if vmRes == nil {
		t.Fatal("no VM snapshot; every name count below would be misleading")
	}
	return res, vmRes, info.Version
}

// A type-testing stub's owner is the Type it tests, not a Function
// (type_testing_stubs.cc `code.set_owner(type)`, verified at tag 3.9.2), so
// it fails both the CodeIndex cross-reference and the RefToNamed lookup and
// used to render as `sub_<pcOffset>`. On the 3.9.2 ARM64 sample that was 324
// of the 409 remaining unnamed Codes.
func TestTypeTestingStubsAreNamed(t *testing.T) {
	for _, name := range []string{sampleARM64Name, sample312X64Name} {
		libPath := corpusSample(t, name)
		t.Run(name, func(t *testing.T) {
			res, vmRes, profile := loadForNaming(t, libPath)
			pl := BuildPoolLookups(res, profile.CIDs, vmRes, profile.CodeIndexOneBased,
				-1, profile.DartVersion)

			var stubs, distinct = 0, map[string]bool{}
			for _, ce := range res.Codes {
				name := pl.CodeNames[ce.RefID].FuncName
				if strings.HasPrefix(name, "TypeTestingStub_") {
					stubs++
					distinct[name] = true
				}
			}
			if stubs < 200 {
				t.Errorf("only %d type-testing stubs named; both 3.x samples have >300", stubs)
			}
			// Collapsing to one class is the specific way this fails --
			// see the 2.12 case below -- so a healthy spread is the check
			// that matters, not the raw count.
			if len(distinct) < stubs/2 {
				t.Errorf("%d stubs but only %d distinct names; the Type->class resolution has collapsed",
					stubs, len(distinct))
			}
			t.Logf("%d type-testing stubs, %d distinct types", stubs, len(distinct))
		})
	}
}

// Type-testing-stub naming on Dart 2.x must not COLLAPSE.
//
// This test used to assert that naming was off below 2.16 entirely, because a
// real 2.12.0 sample resolved 251 of 251 type-owned Codes to a real-looking
// name -- all to the SAME class. 251 confident wrong labels is worse than 251
// honest `sub_` placeholders, and that is still true.
//
// What changed is the cause: Type class ids did not resolve on 2.x at all
// (docs/findings-repo/012), so every Type reported the same one. They resolve
// at parse time now, so the guard is no longer a version but the property it
// was standing in for -- that the names actually discriminate. Pinning the
// property rather than the workaround is what lets the workaround go away.
func TestTypeTestingStubNamingDoesNotCollapseOn2x(t *testing.T) {
	libPath := corpusSample(t, sampleDart212Name)
	res, vmRes, profile := loadForNaming(t, libPath)
	pl := BuildPoolLookups(res, profile.CIDs, vmRes, profile.CodeIndexOneBased,
		-1, profile.DartVersion)

	total := 0
	distinct := map[string]int{}
	for _, ce := range res.Codes {
		n := pl.CodeNames[ce.RefID].FuncName
		if !strings.HasPrefix(n, "TypeTestingStub_") {
			continue
		}
		total++
		distinct[n]++
	}
	if total == 0 {
		t.Fatalf("no type-testing stubs named on %s; naming has regressed to off", profile.DartVersion)
	}
	// Measured at the time of writing: 2187 stubs over 1885 distinct names,
	// most common x8. The floor is deliberately far below that -- this guards
	// against a COLLAPSE, not against normal sharing of a stub between types.
	if ratio := float64(len(distinct)) / float64(total); ratio < 0.5 {
		var worst string
		var worstN int
		for k, v := range distinct {
			if v > worstN {
				worst, worstN = k, v
			}
		}
		t.Errorf("%s: %d stubs collapsed onto %d distinct names (%.2f); most common %q x%d",
			profile.DartVersion, total, len(distinct), ratio, worst, worstN)
	}
}

// buildTypeNames must refuse rather than guess, on the same
// principle as the pool-index arithmetic: a wrong label propagates into every
// call site that references the stub.
func TestTypeTestingStubNamesRefuseWhenUnresolvable(t *testing.T) {
	res := &cluster.Result{
		Types: []cluster.TypeInfo{{RefID: 100, ClassID: 4242}},
	}
	pl := &PoolLookups{RefToNamed: map[int]*cluster.NamedObject{}, RefToStr: map[int]string{}}
	for _, v := range []string{"2.12.0", "2.15.0", "3.3.0"} {
		if got, _ := buildTypeNames(res, pl, nil, v); len(got) != 0 {
			t.Errorf("%s: named an unresolvable class: %v", v, got)
		}
		// The VM spelling is generated from the same inputs and must refuse
		// on the same terms -- a name that scores against the ELF but was
		// invented is the worst of both.
		if got := buildTypeTestingStubSDKNames(res, pl, nil, v); len(got) != 0 {
			t.Errorf("%s: VM-form named an unresolvable class: %v", v, got)
		}
	}
}

func TestExactTypeTestingStubNamesPreserveNestedArgsNullabilityAndTypeParameters(t *testing.T) {
	ct := &snapshot.CIDTable{Class: 4, Library: 11, Type: 46, TypeParameter: 49}
	const (
		cidInt    = 100
		cidString = 101
		cidList   = 102
		cidMap    = 103
		cidBox    = 104
	)
	classDefs := []struct {
		cid     int32
		ref     int
		nameRef int
		name    string
	}{
		{cidInt, 1000, 2000, "int"},
		{cidString, 1001, 2001, "String"},
		{cidList, 1002, 2002, "List"},
		{cidMap, 1003, 2003, "Map"},
		{cidBox, 1004, 2004, "Box"},
	}
	res := &cluster.Result{}
	pl := &PoolLookups{
		CT:           ct,
		RefToStr:     map[int]string{},
		RefToNamed:   map[int]*cluster.NamedObject{},
		VmRefToStr:   map[int]string{},
		VmRefToNamed: map[int]*cluster.NamedObject{},
	}
	for _, d := range classDefs {
		res.Classes = append(res.Classes, cluster.ClassInfo{RefID: d.ref, NameRefID: d.nameRef, ClassID: d.cid, TypeParamsRefID: -1})
		no := &cluster.NamedObject{CID: ct.Class, RefID: d.ref, NameRefID: d.nameRef, OwnerRefID: -1}
		res.Named = append(res.Named, *no)
		pl.RefToNamed[d.ref] = no
		pl.RefToStr[d.nameRef] = d.name
	}

	tp := &cluster.NamedObject{
		CID:                  ct.TypeParameter,
		RefID:                900,
		NameRefID:            -1,
		OwnerRefID:           -1,
		HasTypeParamMetadata: true,
		TypeParamBase:        0,
		TypeParamIndex:       0,
		TypeParamNullability: cluster.TypeNullabilityNullable,
	}
	res.Named = append(res.Named, *tp)
	pl.RefToNamed[tp.RefID] = tp

	res.Types = []cluster.TypeInfo{
		{RefID: 10, ClassID: cidInt, ArgumentsRef: cluster.RefNull, Nullability: cluster.TypeNullabilityNullable},
		{RefID: 11, ClassID: cidString, ArgumentsRef: cluster.RefNull, Nullability: cluster.TypeNullabilityNonNullable},
		{RefID: 12, ClassID: cidList, ArgumentsRef: 500, Nullability: cluster.TypeNullabilityNonNullable},
		{RefID: 13, ClassID: cidMap, ArgumentsRef: 501, Nullability: cluster.TypeNullabilityNullable},
		{RefID: 14, ClassID: cidBox, ArgumentsRef: 502, Nullability: cluster.TypeNullabilityNonNullable},
		{RefID: 15, ClassID: cidList, ArgumentsRef: 999, Nullability: cluster.TypeNullabilityNonNullable},
		{RefID: 16, ClassID: cidMap, ArgumentsRef: 503, Nullability: cluster.TypeNullabilityNonNullable},
		{RefID: 17, ClassID: cidList, ArgumentsRef: 504, Nullability: cluster.TypeNullabilityNonNullable},
	}
	res.TypeArguments = []cluster.TypeArgumentsInfo{
		{RefID: 500, Length: 1, TypeRefs: []int{10}},
		{RefID: 501, Length: 2, TypeRefs: []int{11, 12}},
		{RefID: 502, Length: 1, TypeRefs: []int{tp.RefID}},
		{RefID: 503, Length: 2, TypeRefs: []int{11, 15}},
		{RefID: 504, Length: 2, TypeRefs: []int{10}}, // malformed/truncated vector
	}

	got := buildExactTypeTestingStubNames(res, pl, ct, "3.13.0")
	if want := "TypeTestingStub_Map<String, List<int?>>?"; got[13] != want {
		t.Fatalf("nested nullable TTS = %q, want %q", got[13], want)
	}
	if want := "TypeTestingStub_Box<X0?>"; got[14] != want {
		t.Fatalf("type-parameter TTS = %q, want %q", got[14], want)
	}
	if _, ok := got[15]; ok {
		t.Fatalf("named Type with missing non-null TypeArguments: %q", got[15])
	}
	if _, ok := got[16]; ok {
		t.Fatalf("named parent after nested generic failed: %q", got[16])
	}
	if _, ok := got[17]; ok {
		t.Fatalf("named Type from partial TypeArguments vector: %q", got[17])
	}

	// Generic TypeParameters are often VM-snapshot base objects. The exact
	// renderer may fall back to that namespace only inside the base-object ref
	// prefix, where the two snapshot domains intentionally share numbering.
	delete(pl.RefToNamed, tp.RefID)
	pl.VmRefToNamed[tp.RefID] = tp
	pl.BaseObjLimit = 1000
	if gotVM := buildExactTypeTestingStubNames(res, pl, ct, "3.13.0")[14]; gotVM != "TypeTestingStub_Box<X0?>" {
		t.Fatalf("VM-base TypeParameter fallback = %q", gotVM)
	}

	// Approximate pool display may still be useful, but it must never leak into
	// an indirect-call target when the exact identity is unavailable.
	targets := BuildTTSCallTargets(
		[]cluster.PoolEntry{{Index: 7, Kind: cluster.PoolTagged, RefID: 15}},
		&PoolLookups{TypeNames: map[int]string{15: "List"}, TypeTestingStubNames: got},
	)
	if _, ok := targets[7]; ok {
		t.Fatalf("approximate TypeNames leaked into exact TTS call target: %q", targets[7])
	}
}

func TestTypeTestingStubArgumentSelectionBoundaryAtDart31(t *testing.T) {
	ct := &snapshot.CIDTable{Class: 4, Library: 11, Type: 46, TypeParameter: 49}
	const (
		cidInt    = 100
		cidString = 101
		cidChild  = 102
	)
	coreLib := &cluster.NamedObject{CID: ct.Library, RefID: 7000, NameRefID: 7100, OwnerRefID: -1}
	appLib := &cluster.NamedObject{CID: ct.Library, RefID: 7001, NameRefID: 7101, OwnerRefID: -1}
	intClass := &cluster.NamedObject{CID: ct.Class, RefID: 1000, NameRefID: 2000, OwnerRefID: -1}
	stringClass := &cluster.NamedObject{CID: ct.Class, RefID: 1001, NameRefID: 2001, OwnerRefID: -1}
	childClass := &cluster.NamedObject{CID: ct.Class, RefID: 1002, NameRefID: 2002, OwnerRefID: -1}
	res := &cluster.Result{
		Named: []cluster.NamedObject{*coreLib, *appLib, *intClass, *stringClass, *childClass},
		Classes: []cluster.ClassInfo{
			{RefID: intClass.RefID, NameRefID: intClass.NameRefID, ClassID: cidInt, LibraryRefID: coreLib.RefID, TypeParamsRefID: cluster.RefNull},
			{RefID: stringClass.RefID, NameRefID: stringClass.NameRefID, ClassID: cidString, LibraryRefID: coreLib.RefID, TypeParamsRefID: cluster.RefNull},
			{RefID: childClass.RefID, NameRefID: childClass.NameRefID, ClassID: cidChild, LibraryRefID: appLib.RefID, TypeParamsRefID: 6000},
		},
		Types: []cluster.TypeInfo{
			{RefID: 10, ClassID: cidInt, ArgumentsRef: cluster.RefNull, Nullability: cluster.TypeNullabilityNonNullable},
			{RefID: 11, ClassID: cidString, ArgumentsRef: cluster.RefNull, Nullability: cluster.TypeNullabilityNonNullable},
			{RefID: 12, ClassID: cidChild, ArgumentsRef: 5000, Nullability: cluster.TypeNullabilityNonNullable},
		},
		TypeArguments:  []cluster.TypeArgumentsInfo{{RefID: 5000, Length: 2, TypeRefs: []int{10, 11}}},
		TypeParameters: []cluster.TypeParametersInfo{{RefID: 6000, NamesArrayRef: 6001}},
		Arrays:         []cluster.ArrayInfo{{RefID: 6001, ElementRefIDs: []int{6100}}}, // one own type parameter
	}
	pl := &PoolLookups{
		CT: ct,
		RefToStr: map[int]string{
			2000: "int", 2001: "String", 2002: "Child",
			7100: "dart:core", 7101: "package:test/main.dart",
		},
		RefToNamed: map[int]*cluster.NamedObject{
			coreLib.RefID:     coreLib,
			appLib.RefID:      appLib,
			intClass.RefID:    intClass,
			stringClass.RefID: stringClass,
			childClass.RefID:  childClass,
		},
	}

	oldReadable := buildExactTypeTestingStubNames(res, pl, ct, "3.0.5")[12]
	if want := "TypeTestingStub_Child<String>"; oldReadable != want {
		t.Fatalf("3.0.5 readable = %q, want %q", oldReadable, want)
	}
	newReadable := buildExactTypeTestingStubNames(res, pl, ct, "3.1.0")[12]
	if want := "TypeTestingStub_Child<int, String>"; newReadable != want {
		t.Fatalf("3.1.0 readable = %q, want %q", newReadable, want)
	}

	oldSDK := buildTypeTestingStubSDKNames(res, pl, ct, "3.0.5")[12]
	if want := "TypeTestingStub_package_test_main_dart__Child__dart_core__String"; oldSDK != want {
		t.Fatalf("3.0.5 SDK form = %q, want %q", oldSDK, want)
	}
	newSDK := buildTypeTestingStubSDKNames(res, pl, ct, "3.1.0")[12]
	if want := "TypeTestingStub_package_test_main_dart__Child__dart_core__int__dart_core__String"; newSDK != want {
		t.Fatalf("3.1.0 SDK form = %q, want %q", newSDK, want)
	}
}

func TestTypeParameterTTSNamingBoundaryAtDart214(t *testing.T) {
	tp := &cluster.NamedObject{
		CID:                  49,
		RefID:                900,
		NameRefID:            901,
		HasTypeParamMetadata: true,
		TypeParamBase:        0,
		TypeParamIndex:       0,
		TypeParamNullability: cluster.TypeNullabilityNonNullable,
	}
	pl := &PoolLookups{RefToStr: map[int]string{901: "T"}, BaseObjLimit: 1}

	old := &ttsNameContext{pl: pl, dartVersion: "2.13.0"}
	if got, ok := old.typeParameterTTSName(tp); !ok || got != "T" {
		t.Fatalf("2.13 TypeParameter TTS name = (%q,%v), want source name T", got, ok)
	}
	newer := &ttsNameContext{pl: pl, dartVersion: "2.14.0"}
	if got, ok := newer.typeParameterTTSName(tp); !ok || got != "X0" {
		t.Fatalf("2.14 TypeParameter TTS name = (%q,%v), want canonical X0", got, ok)
	}

	// The real 2.10-2.13 cluster layout stores the source name, but if that
	// ref is unavailable to this package we must refuse rather than fabricate
	// the post-2.14 X/Y spelling.
	withoutOldName := *tp
	withoutOldName.NameRefID = -1
	if got, ok := old.typeParameterTTSName(&withoutOldName); ok || got != "" {
		t.Fatalf("2.13 missing source name produced (%q,%v), want exact-name refusal", got, ok)
	}
	if got, ok := newer.typeParameterTTSName(&withoutOldName); !ok || got != "X0" {
		t.Fatalf("2.14 should not depend on removed source name: (%q,%v)", got, ok)
	}
}

func TestExactTypeTestingStubNamesScrubClassPrivateKeys(t *testing.T) {
	ct := &snapshot.CIDTable{Class: 4, Library: 11, Type: 46}
	lib := &cluster.NamedObject{CID: ct.Library, RefID: 10, NameRefID: 11, OwnerRefID: -1}
	class := &cluster.NamedObject{CID: ct.Class, RefID: 20, NameRefID: 21, OwnerRefID: -1}
	res := &cluster.Result{
		Named: []cluster.NamedObject{*lib, *class},
		Classes: []cluster.ClassInfo{{
			RefID: class.RefID, NameRefID: class.NameRefID, ClassID: 100,
			LibraryRefID: lib.RefID, TypeParamsRefID: cluster.RefNull,
		}},
		Types: []cluster.TypeInfo{{
			RefID: 30, ClassID: 100, ArgumentsRef: cluster.RefNull,
			Nullability: cluster.TypeNullabilityNonNullable,
		}},
	}
	pl := &PoolLookups{
		CT: ct,
		RefToStr: map[int]string{
			lib.NameRefID:   "package:app/main.dart",
			class.NameRefID: "_C@6328321&_E@6328321&_F@6328321",
		},
		RefToNamed:   map[int]*cluster.NamedObject{lib.RefID: lib, class.RefID: class},
		BaseObjLimit: 1,
	}

	readable := buildExactTypeTestingStubNames(res, pl, ct, "3.12.2")[30]
	if want := "TypeTestingStub__C&_E&_F"; readable != want {
		t.Fatalf("readable private class TTS = %q, want %q", readable, want)
	}
	sdk := buildTypeTestingStubSDKNames(res, pl, ct, "3.12.2")[30]
	if want := "TypeTestingStub_package_app_main_dart___C__E__F"; sdk != want {
		t.Fatalf("SDK private class TTS = %q, want %q", sdk, want)
	}
}

func TestExactTypeTestingStubNamesAllowDeepFiniteNestingAndRejectCycles(t *testing.T) {
	ct := &snapshot.CIDTable{Class: 4, Library: 11, Type: 46}
	lib := &cluster.NamedObject{CID: ct.Library, RefID: 10, NameRefID: 11, OwnerRefID: -1}
	intClass := &cluster.NamedObject{CID: ct.Class, RefID: 20, NameRefID: 21, OwnerRefID: -1}
	listClass := &cluster.NamedObject{CID: ct.Class, RefID: 22, NameRefID: 23, OwnerRefID: -1}
	res := &cluster.Result{
		Named: []cluster.NamedObject{*lib, *intClass, *listClass},
		Classes: []cluster.ClassInfo{
			{RefID: intClass.RefID, NameRefID: intClass.NameRefID, ClassID: 100, LibraryRefID: lib.RefID, TypeParamsRefID: cluster.RefNull},
			{RefID: listClass.RefID, NameRefID: listClass.NameRefID, ClassID: 101, LibraryRefID: lib.RefID, TypeParamsRefID: cluster.RefNull},
		},
		Types: []cluster.TypeInfo{{RefID: 1000, ClassID: 100, ArgumentsRef: cluster.RefNull, Nullability: cluster.TypeNullabilityNonNullable}},
	}
	for i := 1; i <= 6; i++ {
		ref := 1000 + i
		argsRef := 2000 + i
		res.Types = append(res.Types, cluster.TypeInfo{RefID: ref, ClassID: 101, ArgumentsRef: argsRef, Nullability: cluster.TypeNullabilityNonNullable})
		res.TypeArguments = append(res.TypeArguments, cluster.TypeArgumentsInfo{RefID: argsRef, Length: 1, TypeRefs: []int{ref - 1}})
	}
	// A malformed self-cycle must fail closed without imposing a depth limit on
	// the valid chain above.
	res.Types = append(res.Types, cluster.TypeInfo{RefID: 3000, ClassID: 101, ArgumentsRef: 3001, Nullability: cluster.TypeNullabilityNonNullable})
	res.TypeArguments = append(res.TypeArguments, cluster.TypeArgumentsInfo{RefID: 3001, Length: 1, TypeRefs: []int{3000}})

	pl := &PoolLookups{
		CT: ct,
		RefToStr: map[int]string{
			lib.NameRefID: "dart:core", intClass.NameRefID: "int", listClass.NameRefID: "List",
		},
		RefToNamed:   map[int]*cluster.NamedObject{lib.RefID: lib, intClass.RefID: intClass, listClass.RefID: listClass},
		BaseObjLimit: 1,
	}

	readable := buildExactTypeTestingStubNames(res, pl, ct, "3.13.0")
	if want := "TypeTestingStub_List<List<List<List<List<List<int>>>>>>"; readable[1006] != want {
		t.Fatalf("deep readable TTS = %q, want %q", readable[1006], want)
	}
	if _, ok := readable[3000]; ok {
		t.Fatalf("cyclic readable metadata was accepted: %q", readable[3000])
	}

	sdk := buildTypeTestingStubSDKNames(res, pl, ct, "3.13.0")
	if sdk[1006] == "" {
		t.Fatal("deep finite SDK-form TTS name was dropped")
	}
	if _, ok := sdk[3000]; ok {
		t.Fatalf("cyclic SDK metadata was accepted: %q", sdk[3000])
	}
}

func TestBuildPoolLookupsDoesNotNameCodeFromApproximateTypeDisplay(t *testing.T) {
	ct := &snapshot.CIDTable{Class: 4, Function: 6, Type: 46, TypeParameter: 49}
	const (
		classRef = 1000
		nameRef  = 2000
		typeRef  = 3000
		codeRef  = 4000
	)
	res := &cluster.Result{
		Strings: []cluster.ParsedString{{RefID: nameRef, Value: "List", IsOneByte: true}},
		Named: []cluster.NamedObject{{
			CID: ct.Class, RefID: classRef, NameRefID: nameRef, OwnerRefID: -1,
		}},
		Classes: []cluster.ClassInfo{{
			RefID: classRef, NameRefID: nameRef, ClassID: 100, TypeParamsRefID: -1,
		}},
		Types: []cluster.TypeInfo{{
			RefID: typeRef, ClassID: 100, ArgumentsRef: 9999, Nullability: cluster.TypeNullabilityNonNullable,
		}},
		Codes: []cluster.CodeEntry{{RefID: codeRef, OwnerRef: typeRef, ClusterIndex: -1}},
	}
	pl := BuildPoolLookups(res, ct, nil, false, -1, "3.13.0")
	if got := pl.TypeNames[typeRef]; got != "List" {
		t.Fatalf("best-effort pool display = %q, want List", got)
	}
	if _, ok := pl.TypeTestingStubNames[typeRef]; ok {
		t.Fatalf("exact TTS map accepted unresolved argument vector: %q", pl.TypeTestingStubNames[typeRef])
	}
	if got, ok := pl.CodeNames[codeRef]; ok {
		t.Fatalf("Code owner was named from approximate Type display: %+v", got)
	}
}
