package pipeline

import (
	"os"
	"testing"

	"aotopsy/internal/cluster"
)

// TestFuncTypeParamNames_Chain verifies generic type parameter reconstruction
// end to end, against real declarations in the Dart SDK source shipped with
// Flutter (dart-sdk/lib):
//
//	async/zone.dart:1327          void runUnaryGuarded<T>(void f(T arg), T arg)
//	internal/list.dart:323        external List<T> makeListFixedLength<T>(...)
//	_internal/vm/lib/ffi_patch.dart:1926
//	                              _get_ffi_native_resolver<T extends NativeFunction>()
//
// The resolution chain under test:
//
//	Function.signature -> FunctionType.type_parameters
//	                   -> TypeParameters.names (Array) -> Strings
func TestFuncTypeParamNames_Chain(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_ARM64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_ARM64 not set")
	}
	res := clusterOnly(t, libPath)

	if len(res.TypeParameters) == 0 {
		t.Fatal("no TypeParameters objects captured; the cluster exists in AOT " +
			"snapshots (395 in compare_sample)")
	}

	// Every FunctionType must have the field captured (>= RefNull), never -1,
	// for a version whose FuncTypeParamTypesIdx is verified. -1 would mean the
	// derived index (FuncTypeParamTypesIdx-2) never fired.
	var withRef, nullRef, notCaptured int
	for _, ft := range res.FuncTypes {
		switch {
		case ft.TypeParamsRefID < 0:
			notCaptured++
		case ft.TypeParamsRefID == cluster.RefNull:
			nullRef++
		default:
			withRef++
		}
	}
	if notCaptured > 0 {
		t.Errorf("%d FunctionTypes have TypeParamsRefID == -1; the derived "+
			"type_parameters index did not fire", notCaptured)
	}
	if withRef == 0 {
		t.Fatal("no FunctionType references a TypeParameters object; a Flutter " +
			"app certainly contains generic functions")
	}
	if nullRef == 0 {
		t.Error("every FunctionType has a non-null type_parameters ref, which is " +
			"implausible -- most functions are not generic. Ref order is likely wrong.")
	}
	t.Logf("FunctionType.type_parameters: %d real, %d null", withRef, nullRef)

	// Resolve the chain the way the decompiler does. StringForRef is required
	// here rather than RefToStr: type parameter names are short shared strings
	// living in the VM snapshot as base objects.
	strByRef := map[int]string{}
	for _, ps := range res.Strings {
		strByRef[ps.RefID] = ps.Value
	}
	tpByRef := map[int]*cluster.TypeParametersInfo{}
	for i := range res.TypeParameters {
		tpByRef[res.TypeParameters[i].RefID] = &res.TypeParameters[i]
	}
	arrByRef := map[int]*cluster.ArrayInfo{}
	for i := range res.Arrays {
		arrByRef[res.Arrays[i].RefID] = &res.Arrays[i]
	}

	// Each generic FunctionType must reach a TypeParameters object and a names
	// Array. Name resolution itself is checked via the full PoolLookups path in
	// the decompiler test; here we assert the object graph is intact.
	var reachedTP, reachedArray int
	for _, ft := range res.FuncTypes {
		if ft.TypeParamsRefID <= cluster.RefNull {
			continue
		}
		tp, ok := tpByRef[ft.TypeParamsRefID]
		if !ok {
			continue
		}
		reachedTP++
		if _, ok := arrByRef[tp.NamesArrayRef]; ok {
			reachedArray++
		}
	}
	if reachedTP != withRef {
		t.Errorf("only %d of %d type_parameters refs resolve to a TypeParameters "+
			"object; ref order or capture is wrong", reachedTP, withRef)
	}
	if reachedArray != reachedTP {
		t.Errorf("only %d of %d TypeParameters resolve a names Array; "+
			"TypeParameters ref 0 may not be `names`", reachedArray, reachedTP)
	}

	// Spot-check a known generic: dart:async's _RootZone.runUnaryGuarded<T>.
	ftByRef := map[int]*cluster.FuncTypeInfo{}
	for i := range res.FuncTypes {
		ftByRef[res.FuncTypes[i].RefID] = &res.FuncTypes[i]
	}
	var found bool
	for i := range res.Named {
		no := &res.Named[i]
		if strByRef[no.NameRefID] != "runUnaryGuarded" {
			continue
		}
		found = true
		ft, ok := ftByRef[no.SignatureRefID]
		if !ok {
			t.Fatalf("runUnaryGuarded (ref %d) signature ref %d is not a FunctionType",
				no.RefID, no.SignatureRefID)
		}
		if ft.TypeParamsRefID <= cluster.RefNull {
			t.Fatalf("runUnaryGuarded's FunctionType has no type_parameters, but the "+
				"source declares runUnaryGuarded<T> (zone.dart:1327). ref=%d",
				ft.TypeParamsRefID)
		}
		tp, ok := tpByRef[ft.TypeParamsRefID]
		if !ok {
			t.Fatalf("no TypeParameters object at ref %d", ft.TypeParamsRefID)
		}
		arr, ok := arrByRef[tp.NamesArrayRef]
		if !ok {
			t.Fatalf("no names Array at ref %d", tp.NamesArrayRef)
		}
		// Exactly one type parameter: <T>.
		if len(arr.ElementRefIDs) != 1 {
			t.Errorf("runUnaryGuarded names Array has %d elements, want 1 (<T>)",
				len(arr.ElementRefIDs))
		}
	}
	if !found {
		t.Skip("runUnaryGuarded not present in this sample")
	}
}

// TestTypeParamRendering pins how a parameter and its bound are rendered.
//
// An unbounded parameter is implicitly bounded by Object, and printing
// "T extends Object?" on every one would be noise, so the resolver reports the
// implicit case as no bound at all. A real bound must survive:
// _get_ffi_native_resolver is declared
// `<T extends NativeFunction>` (dart-sdk/lib/_internal/vm/lib/ffi_patch.dart:1926).
func TestTypeParamRendering(t *testing.T) {
	cases := []struct {
		p    TypeParam
		want string
	}{
		{TypeParam{Name: "T"}, "T"},
		{TypeParam{Name: "T", Bound: "NativeFunction"}, "T extends NativeFunction"},
		{TypeParam{Name: "K", Bound: ""}, "K"},
	}
	for _, c := range cases {
		if got := c.p.String(); got != c.want {
			t.Errorf("%+v -> %q, want %q", c.p, got, c.want)
		}
	}

	if got := FormatTypeParams(nil); got != "" {
		t.Errorf("no params -> %q, want empty", got)
	}
	got := FormatTypeParams([]TypeParam{{Name: "K"}, {Name: "V", Bound: "Comparable"}})
	if want := "<K, V extends Comparable>"; got != want {
		t.Errorf("FormatTypeParams -> %q, want %q", got, want)
	}
}

// TestStringForRefFallsBackToVM pins the VM-snapshot fallback that
// StringForRef adds. Without it, generic type parameter names resolve for only
// a small minority of generic functions, because names like "T"/"K"/"V" are
// shared base objects in the VM isolate snapshot rather than app-isolate
// strings. On compare_sample this was measured at 12 of 84.
func TestStringForRefFallsBackToVM(t *testing.T) {
	pl := &PoolLookups{
		RefToStr:     map[int]string{5000: "AppString"},
		VmRefToStr:   map[int]string{450: "T"},
		VmRefCID:     map[int]int{450: 0},
		BaseObjLimit: 4096,
	}
	if s, ok := pl.StringForRef(5000); !ok || s != "AppString" {
		t.Errorf("isolate lookup: got (%q,%v)", s, ok)
	}
	if s, ok := pl.StringForRef(450); !ok || s != "T" {
		t.Errorf("VM base-object fallback failed: got (%q,%v); generic names live here", s, ok)
	}
	// null and out-of-range must not resolve.
	if _, ok := pl.StringForRef(cluster.RefNull); ok {
		t.Error("RefNull resolved to a string")
	}
	if _, ok := pl.StringForRef(99999); ok {
		t.Error("unknown ref above BaseObjLimit resolved to a string")
	}
}
