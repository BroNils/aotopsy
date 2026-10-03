package naming

import (
	"testing"

	"aotopsy/internal/cluster"
	"aotopsy/internal/snapshot"
)

// TestResolvePoolDisplay_FieldOwnerQualification covers the libapp.so RSA-slice
// pp+0xb050..pp+0xb0c8 collision: three Field NamedObjects share leaf "uHb" but
// have distinct Class owners (Wja, Yja, aka). The pool dump must distinguish
// them by emitting owner.leaf instead of bare leaf.
func TestResolvePoolDisplay_FieldOwnerQualification(t *testing.T) {
	const (
		fieldCID = 200
		classCID = 100
		// Ref IDs for the three Class owners.
		refClassWja = 10
		refClassYja = 11
		refClassAka = 12
		// Ref IDs for the leaf name strings.
		refNameUhb      = 20
		refNameBmb      = 21
		refNameDigest   = 22
		refNameClassWja = 30
		refNameClassYja = 31
		refNameClassAka = 32
		// Ref IDs for the three uHb Field objects and the _bMb field.
		refFieldWjaUhb = 40
		refFieldYjaUhb = 41
		refFieldAkaUhb = 42
		refFieldAkaBmb = 43
		// Field-with-no-owner case.
		refFieldOrphan = 44
		refNameOrphan  = 45
	)

	ct := &snapshot.CIDTable{Field: fieldCID, Class: classCID, OneByteString: 300}

	classWja := &cluster.NamedObject{CID: classCID, RefID: refClassWja, NameRefID: refNameClassWja, OwnerRefID: -1}
	classYja := &cluster.NamedObject{CID: classCID, RefID: refClassYja, NameRefID: refNameClassYja, OwnerRefID: -1}
	classAka := &cluster.NamedObject{CID: classCID, RefID: refClassAka, NameRefID: refNameClassAka, OwnerRefID: -1}

	fieldWjaUhb := &cluster.NamedObject{CID: fieldCID, RefID: refFieldWjaUhb, NameRefID: refNameUhb, OwnerRefID: refClassWja}
	fieldYjaUhb := &cluster.NamedObject{CID: fieldCID, RefID: refFieldYjaUhb, NameRefID: refNameUhb, OwnerRefID: refClassYja}
	fieldAkaUhb := &cluster.NamedObject{CID: fieldCID, RefID: refFieldAkaUhb, NameRefID: refNameUhb, OwnerRefID: refClassAka}
	fieldAkaBmb := &cluster.NamedObject{CID: fieldCID, RefID: refFieldAkaBmb, NameRefID: refNameBmb, OwnerRefID: refClassAka}
	fieldOrphan := &cluster.NamedObject{CID: fieldCID, RefID: refFieldOrphan, NameRefID: refNameOrphan, OwnerRefID: -1}

	l := &PoolLookups{
		RefToStr: map[int]string{
			refNameUhb:      "uHb",
			refNameBmb:      "_bMb@211060559",
			refNameDigest:   "RSA signing with digest ",
			refNameClassWja: "Wja",
			refNameClassYja: "Yja",
			refNameClassAka: "aka",
			refNameOrphan:   "orphanLeaf",
		},
		RefToNamed: map[int]*cluster.NamedObject{
			refClassWja:    classWja,
			refClassYja:    classYja,
			refClassAka:    classAka,
			refFieldWjaUhb: fieldWjaUhb,
			refFieldYjaUhb: fieldYjaUhb,
			refFieldAkaUhb: fieldAkaUhb,
			refFieldAkaBmb: fieldAkaBmb,
			refFieldOrphan: fieldOrphan,
		},
		RefCID:         map[int]int{},
		CodeRefDisplay: map[int]string{},
		VmRefToStr:     map[int]string{},
		VmRefCID:       map[int]int{},
		VmRefToNamed:   map[int]*cluster.NamedObject{},
		CT:             ct,
	}

	// Pool indices match the libapp.so RSA slice byte offsets
	// (0x10 + index*8): 0xb058,0xb060,0xb068,0xb080,0xb088,0xb098 etc.
	// Only the entries we care about for this test are present.
	const (
		idxWjaUhb = (0xb058 - 0x10) / 8 // 5641
		idxYjaUhb = (0xb060 - 0x10) / 8 // 5642
		idxAkaUhb = (0xb068 - 0x10) / 8 // 5643
		idxRSA    = (0xb080 - 0x10) / 8 // 5646
		idxAkaBmb = (0xb088 - 0x10) / 8 // 5647
		idxOrphan = (0xb0c0 - 0x10) / 8 // 5654
	)
	pool := []cluster.PoolEntry{
		{Index: idxWjaUhb, Kind: cluster.PoolTagged, RefID: refFieldWjaUhb},
		{Index: idxYjaUhb, Kind: cluster.PoolTagged, RefID: refFieldYjaUhb},
		{Index: idxAkaUhb, Kind: cluster.PoolTagged, RefID: refFieldAkaUhb},
		{Index: idxRSA, Kind: cluster.PoolTagged, RefID: refNameDigest},
		{Index: idxAkaBmb, Kind: cluster.PoolTagged, RefID: refFieldAkaBmb},
		{Index: idxOrphan, Kind: cluster.PoolTagged, RefID: refFieldOrphan},
	}

	// Sanity: RefToStr resolves "RSA signing with digest " via its own ref,
	// not via NamedObject. ResolvePoolDisplay's string branch handles it.
	// C-1 fix: RefCID must identify the entry as a String CID for it to be
	// quoted as a string (prevents false positive string references from
	// non-string objects sharing a ref ID with a string).
	l.RefToStr[refNameDigest] = "RSA signing with digest "
	l.RefCID[refNameDigest] = ct.OneByteString

	got := ResolvePoolDisplay(pool, l)

	wants := map[int]string{
		idxWjaUhb: "Wja.uHb",
		idxYjaUhb: "Yja.uHb",
		idxAkaUhb: "aka.uHb",
		idxRSA:    `"RSA signing with digest "`,
		idxAkaBmb: "aka._bMb@211060559",
		idxOrphan: "orphanLeaf", // fallback: no owner → leaf-only
	}
	for idx, want := range wants {
		if got[idx] != want {
			t.Errorf("pool[%d]: got %q want %q", idx, got[idx], want)
		}
	}

	// Collision check: the three uHb entries must be distinct.
	if got[idxWjaUhb] == got[idxYjaUhb] {
		t.Errorf("uHb collision not resolved: pp+0xb058 == pp+0xb060 == %q", got[idxWjaUhb])
	}
	if got[idxYjaUhb] == got[idxAkaUhb] {
		t.Errorf("uHb collision not resolved: pp+0xb060 == pp+0xb068 == %q", got[idxYjaUhb])
	}
}

func TestResolvePoolDisplayRejectsVMStringCollisionOnNonStringObject(t *testing.T) {
	ct := &snapshot.CIDTable{Class: 100, OneByteString: 200, TwoByteString: 201, String: 202}
	pl := &PoolLookups{
		VmRefToStr:   map[int]string{7: "looks_callable"},
		VmRefCID:     map[int]int{7: 100},
		VmRefToNamed: map[int]*cluster.NamedObject{},
		RefToStr:     map[int]string{},
		RefToNamed:   map[int]*cluster.NamedObject{},
		RefCID:       map[int]int{},
		CT:           ct,
		BaseObjLimit: 64,
	}
	got := ResolvePoolDisplay([]cluster.PoolEntry{{Index: 1, Kind: cluster.PoolTagged, RefID: 7}}, pl)
	if got[1] == "looks_callable" {
		t.Fatal("non-string VM object collision leaked bare VmRefToStr text")
	}
	if got[1] != "<vm:Class>" {
		t.Fatalf("collision display = %q, want typed placeholder", got[1])
	}
}

func TestResolvePoolDisplayZeroStringCIDDoesNotMatchUnknownCID(t *testing.T) {
	ct := &snapshot.CIDTable{}
	pl := &PoolLookups{
		RefToStr:     map[int]string{9: "not-proven-string"},
		RefCID:       map[int]int{9: 0},
		RefToNamed:   map[int]*cluster.NamedObject{},
		VmRefToStr:   map[int]string{},
		VmRefCID:     map[int]int{},
		VmRefToNamed: map[int]*cluster.NamedObject{},
		CT:           ct,
	}
	got := ResolvePoolDisplay([]cluster.PoolEntry{{Index: 2, Kind: cluster.PoolTagged, RefID: 9}}, pl)
	if got[2] == `"not-proven-string"` {
		t.Fatal("zero-valued CID table falsely classified cid 0 as String")
	}
}

func TestExactTypeNameIsExactOrEmpty(t *testing.T) {
	pl := &PoolLookups{
		SourceTypeNames: map[int]string{
			40: "List<String>",
		},
		BaseObjectNames: []string{
			"null", "sentinel", "<dynamic type>", "<void type>",
		},
		// TypeNames is intentionally looser display metadata. It must never be
		// consulted by ExactTypeName or `List` below would look precise while
		// dropping its serialized type argument.
		TypeNames: map[int]string{41: "List"},
	}
	if got := pl.ExactTypeName(40); got != "List<String>" {
		t.Fatalf("exact Type name = %q, want List<String>", got)
	}
	if got := pl.ExactTypeName(3); got != "dynamic" {
		t.Fatalf("dynamic base-object type = %q", got)
	}
	if got := pl.ExactTypeName(4); got != "void" {
		t.Fatalf("void base-object type = %q", got)
	}
	if got := pl.ExactTypeName(41); got != "" {
		t.Fatalf("best-effort TypeNames leaked into exact signature path: %q", got)
	}
}

func TestIsolateNameAndOwnerDoNotCrossIntoHighVMRefs(t *testing.T) {
	ct := &snapshot.CIDTable{Class: 4, Field: 10, OneByteString: 20}
	vmClass := &cluster.NamedObject{CID: ct.Class, RefID: 100, NameRefID: 8, OwnerRefID: -1}
	appField := &cluster.NamedObject{CID: ct.Field, RefID: 200, NameRefID: 101, OwnerRefID: 100}
	pl := &PoolLookups{
		CT:           ct,
		BaseObjLimit: 50,
		RefToStr:     map[int]string{},
		RefToNamed:   map[int]*cluster.NamedObject{appField.RefID: appField},
		RefCID:       map[int]int{},
		VmRefToStr:   map[int]string{8: "VMBaseClass", 101: "WrongHighName", 100: "WrongHighString"},
		VmRefToNamed: map[int]*cluster.NamedObject{vmClass.RefID: vmClass},
		VmRefCID:     map[int]int{100: ct.OneByteString, 101: ct.OneByteString},
	}

	if got := pl.ResolveIsolateName(appField); got != "" {
		t.Fatalf("high isolate NameRef crossed into VM namespace: %q", got)
	}
	if got := pl.ResolveOwnerName(appField); got != "" {
		t.Fatalf("high isolate OwnerRef crossed into VM namespace: %q", got)
	}
	got := ResolvePoolDisplay([]cluster.PoolEntry{{Index: 1, Kind: cluster.PoolTagged, RefID: 100}}, pl)
	if got[1] != "<ref:100>" {
		t.Fatalf("high pool ref crossed into VM namespace: %q", got[1])
	}

	// Even if the app metadata proves the high ref is a String, a missing app
	// payload must not be filled from the unrelated VM string at the same ref.
	pl.RefCID[101] = ct.OneByteString
	got = ResolvePoolDisplay([]cluster.PoolEntry{{Index: 2, Kind: cluster.PoolTagged, RefID: 101}}, pl)
	if got[2] != "<String>" {
		t.Fatalf("high app String borrowed colliding VM payload: %q", got[2])
	}
}

func TestIsolateOwnerMayUseVMBaseObjectPrefix(t *testing.T) {
	ct := &snapshot.CIDTable{Class: 4, Field: 10, OneByteString: 20}
	vmClass := &cluster.NamedObject{CID: ct.Class, RefID: 20, NameRefID: 8, OwnerRefID: -1}
	appField := &cluster.NamedObject{CID: ct.Field, RefID: 200, NameRefID: 201, OwnerRefID: vmClass.RefID}
	pl := &PoolLookups{
		CT:           ct,
		BaseObjLimit: 50,
		RefToStr:     map[int]string{201: "field"},
		RefToNamed:   map[int]*cluster.NamedObject{appField.RefID: appField},
		VmRefToStr:   map[int]string{8: "VMBaseClass"},
		VmRefToNamed: map[int]*cluster.NamedObject{vmClass.RefID: vmClass},
		VmRefCID:     map[int]int{8: ct.OneByteString},
	}
	if got := pl.ResolveOwnerName(appField); got != "VMBaseClass" {
		t.Fatalf("base-object VM owner fallback = %q, want VMBaseClass", got)
	}
}

// TestResolveCodeOwner_PrefersCodeIndexOverBogusOwnerRef is a regression
// test for the real Dart 3.7.0 x86_64 bug: ~5.4% of functions carry a
// bogus shared Code.OwnerRef that resolves to CID 61 (Mint), never a
// legal Code owner. This reproduces exactly that shape -- OwnerRef
// points at a Mint NamedObject instead of the real Function -- and
// verifies the reliable Function->Code cross-reference is used instead,
// recovering the real owner. In the legacy (<=2.15) encoding the Function
// field is the Code object's absolute snapshot ref ID, not ClusterIndex.
func TestResolveCodeOwner_PrefersCodeIndexOverBogusOwnerRef(t *testing.T) {
	const (
		mintCID    = 61
		funcCID    = 6
		bogusRef   = 900 // the Mint object every buggy Code.OwnerRef points at
		realFnRef  = 901
		codeRef    = 950
		clusterIdx = 5
	)
	ct := &snapshot.CIDTable{Function: funcCID}

	realFn := &cluster.NamedObject{CID: funcCID, RefID: realFnRef, CodeIndex: codeRef}
	bogusMint := &cluster.NamedObject{CID: mintCID, RefID: bogusRef, CodeIndex: -1}

	result := &cluster.Result{
		Named: []cluster.NamedObject{*realFn, *bogusMint},
		Codes: []cluster.CodeEntry{{RefID: codeRef, ClusterIndex: clusterIdx}},
	}
	byCodeIndex := CodeIndexToFunc(result, ct, false, -1)

	refToNamed := map[int]*cluster.NamedObject{
		realFnRef: realFn,
		bogusRef:  bogusMint,
	}

	ce := cluster.CodeEntry{RefID: 1, OwnerRef: bogusRef, ClusterIndex: clusterIdx}
	owner, ok := ResolveCodeOwner(ce, refToNamed, byCodeIndex, ct)
	if !ok {
		t.Fatal("expected ResolveCodeOwner to resolve via CodeIndex cross-reference")
	}
	if owner.RefID != realFnRef {
		t.Errorf("expected real owner ref=%d (via CodeIndex), got ref=%d (the bogus OwnerRef target)", realFnRef, owner.RefID)
	}
}

// TestResolveCodeOwner_FallsBackToOwnerRefWhenNoCodeIndexMatch verifies
// the fallback path: deferred code (ClusterIndex == -1) or any case with
// no CodeIndex match must still resolve via the legacy OwnerRef lookup,
// so this is a strict improvement over the old behavior, never a
// regression.
func TestResolveCodeOwner_FallsBackToOwnerRefWhenNoCodeIndexMatch(t *testing.T) {
	const ownerRef = 55
	ct := &snapshot.CIDTable{Function: 6, Class: 4}
	owner := &cluster.NamedObject{CID: ct.Function, RefID: ownerRef}
	refToNamed := map[int]*cluster.NamedObject{ownerRef: owner}

	ce := cluster.CodeEntry{RefID: 1, OwnerRef: ownerRef, ClusterIndex: -1}
	got, ok := ResolveCodeOwner(ce, refToNamed, map[int]*cluster.NamedObject{}, ct)
	if !ok || got.RefID != ownerRef {
		t.Fatalf("expected fallback to OwnerRef=%d, got %+v ok=%v", ownerRef, got, ok)
	}
}

func TestResolveCodeOwner_FallbackRejectsIllegalOwnerCID(t *testing.T) {
	ct := &snapshot.CIDTable{Class: 4, PatchClass: 5, Function: 6, Field: 10, Type: 46}
	cases := []struct {
		name string
		cid  int
		want bool
	}{
		{"function", ct.Function, true},
		{"class", ct.Class, true},
		{"patch class", ct.PatchClass, false},
		{"field", ct.Field, false},
		{"type", ct.Type, false}, // AbstractType/TTS owners use the Type naming path.
		{"arbitrary", 999, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			owner := &cluster.NamedObject{CID: tc.cid, RefID: 55}
			ce := cluster.CodeEntry{RefID: 1, OwnerRef: owner.RefID, ClusterIndex: -1}
			got, ok := ResolveCodeOwner(ce, map[int]*cluster.NamedObject{owner.RefID: owner}, nil, ct)
			if ok != tc.want {
				t.Fatalf("ResolveCodeOwner cid=%d ok=%v, want %v (owner=%+v)", tc.cid, ok, tc.want, got)
			}
		})
	}

	t.Run("nil CID table refuses fallback", func(t *testing.T) {
		owner := &cluster.NamedObject{CID: 6, RefID: 55}
		if got, ok := ResolveCodeOwner(cluster.CodeEntry{OwnerRef: 55, ClusterIndex: -1}, map[int]*cluster.NamedObject{55: owner}, nil, nil); ok || got != nil {
			t.Fatalf("nil CID table accepted fallback owner: %+v", got)
		}
	})

	t.Run("zero CID table does not classify unknown as legal", func(t *testing.T) {
		owner := &cluster.NamedObject{CID: 0, RefID: 55}
		if got, ok := ResolveCodeOwner(cluster.CodeEntry{OwnerRef: 55, ClusterIndex: -1}, map[int]*cluster.NamedObject{55: owner}, nil, &snapshot.CIDTable{}); ok || got != nil {
			t.Fatalf("zero-valued CID table accepted unknown owner: %+v", got)
		}
	})
}

// TestCodeIndexToFunc_AmbiguousIndexDropped verifies that if more than
// one Function claims the same CodeIndex, that index is left unmapped
// rather than arbitrarily picking one -- ambiguous cases must fall
// through to the OwnerRef-based lookup, not silently guess wrong.
func TestCodeIndexToFunc_AmbiguousIndexDropped(t *testing.T) {
	const funcCID = 6
	ct := &snapshot.CIDTable{Function: funcCID}
	result := &cluster.Result{
		Named: []cluster.NamedObject{
			{CID: funcCID, RefID: 10, CodeIndex: 30},
			{CID: funcCID, RefID: 11, CodeIndex: 30}, // both point at one Code object
		},
		Codes: []cluster.CodeEntry{{RefID: 30, ClusterIndex: 3}},
	}
	m := CodeIndexToFunc(result, ct, false, -1)
	if _, ok := m[3]; ok {
		t.Error("expected ambiguous CodeIndex 3 to be dropped, not mapped to either candidate")
	}
}

func TestCodeIndexToFunc_LegacyUsesAbsoluteCodeRef(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 6}
	result := &cluster.Result{
		Named: []cluster.NamedObject{{CID: 6, RefID: 101, CodeIndex: 700}},
		Codes: []cluster.CodeEntry{{RefID: 700, ClusterIndex: 4}},
	}
	m := CodeIndexToFunc(result, ct, false, -1)
	if got := m[4]; got == nil || got.RefID != 101 {
		t.Fatalf("legacy Code ref 700 -> cluster index 4 = %+v, want Function ref 101", got)
	}
	if _, ok := m[700]; ok {
		t.Fatal("absolute snapshot Code ref leaked into Code-cluster index domain")
	}
}

func TestCodeIndexToFunc_SubtractsFirstEntryWithCode(t *testing.T) {
	const funcCID = 6
	ct := &snapshot.CIDTable{Function: funcCID}
	result := &cluster.Result{Named: []cluster.NamedObject{
		{CID: funcCID, RefID: 101, CodeIndex: 91013}, // slot 91013 -> cluster index 0
		{CID: funcCID, RefID: 102, CodeIndex: 91014}, // slot 91014 -> cluster index 1
	}}
	m := CodeIndexToFunc(result, ct, true, 91012)
	if got := m[0]; got == nil || got.RefID != 101 {
		t.Fatalf("cluster index 0 = %+v, want Function ref 101", got)
	}
	if got := m[1]; got == nil || got.RefID != 102 {
		t.Fatalf("cluster index 1 = %+v, want Function ref 102", got)
	}
	if _, ok := m[91012]; ok {
		t.Fatal("one-based InstructionsTable slot leaked into Code-cluster index map")
	}
}

func TestCodeIndexToFunc_OneBasedWithoutFECDisablesMapping(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 6}
	result := &cluster.Result{Named: []cluster.NamedObject{{CID: 6, RefID: 1, CodeIndex: 42}}}
	if got := CodeIndexToFunc(result, ct, true, -1); len(got) != 0 {
		t.Fatalf("one-based mapping without FEC = %v, want disabled", got)
	}
}

// TestTypeParamResolver_ResolvesRealParameterTypeNames covers the core
// path: a FunctionType whose parameter_types Array elements resolve
// through Result.Types to real Class names (the v3.x-era case, verified
// against real Dart 3.7.0/3.10.7 samples where ~70% of sampled elements
// resolve this way).
func TestTypeParamResolver_ResolvesRealParameterTypeNames(t *testing.T) {
	const (
		arrayRef  = 100
		typeRefA  = 200 // resolves to a named Class (String)
		typeRefB  = 201 // resolves to a predefined CID with no Class record
		stringCID = int32(50)
		intCID    = int32(51)
	)
	ct := &snapshot.CIDTable{Class: 6}
	result := &cluster.Result{
		Arrays: []cluster.ArrayInfo{
			{RefID: arrayRef, ElementRefIDs: []int{typeRefA, typeRefB}},
		},
		Types: []cluster.TypeInfo{
			{RefID: typeRefA, ClassID: stringCID},
			{RefID: typeRefB, ClassID: intCID},
		},
		Classes: []cluster.ClassInfo{
			{RefID: 300, ClassID: stringCID},
		},
	}
	pl := &PoolLookups{
		RefToStr: map[int]string{400: "String"},
		RefToNamed: map[int]*cluster.NamedObject{
			300: {CID: 6, RefID: 300, NameRefID: 400},
		},
		CT: ct,
	}

	r := NewTypeParamResolver(result, pl)
	ft := cluster.FuncTypeInfo{RefID: 1, ParamTypesArrayRefID: arrayRef}
	names := r.ParamTypeNames(ft)
	if len(names) != 2 {
		t.Fatalf("expected 2 param names, got %d: %v", len(names), names)
	}
	if names[0] != "String" {
		t.Errorf("expected names[0]=%q, got %q", "String", names[0])
	}
	// No Class record for intCID -- falls back to a non-empty placeholder,
	// never silently blank.
	if names[1] == "" {
		t.Errorf("expected a non-empty fallback for an unnamed ClassID, got empty string")
	}
}

// TestTypeParamResolver_UnresolvedElementReportsPlaceholder is the
// documented, empirically-confirmed gap: an element ref that isn't in
// Result.Types (e.g. pre-3.x snapshots, where Result.Types is never
// populated at all) must report "?" rather than an empty string or a
// silently-dropped parameter -- callers need to distinguish "resolved
// to nothing meaningful" from "not extracted here."
func TestTypeParamResolver_UnresolvedElementReportsPlaceholder(t *testing.T) {
	const arrayRef = 100
	result := &cluster.Result{
		Arrays: []cluster.ArrayInfo{
			{RefID: arrayRef, ElementRefIDs: []int{999}}, // 999 not in Types
		},
	}
	pl := &PoolLookups{CT: &snapshot.CIDTable{}}

	r := NewTypeParamResolver(result, pl)
	names := r.ParamTypeNames(cluster.FuncTypeInfo{RefID: 1, ParamTypesArrayRefID: arrayRef})
	if len(names) != 1 || names[0] != "?" {
		t.Fatalf("expected [\"?\"], got %v", names)
	}
}

// TestTypeParamResolver_NoParamTypesRefReturnsNil verifies the
// version-gate: a FuncTypeInfo with ParamTypesArrayRefID == -1 (not
// captured for this Dart version, e.g. FuncTypeParamTypesIdx unset)
// returns nil, not a fabricated empty-but-non-nil slice.
func TestTypeParamResolver_NoParamTypesRefReturnsNil(t *testing.T) {
	result := &cluster.Result{}
	pl := &PoolLookups{CT: &snapshot.CIDTable{}}
	r := NewTypeParamResolver(result, pl)
	names := r.ParamTypeNames(cluster.FuncTypeInfo{RefID: 1, ParamTypesArrayRefID: -1})
	if names != nil {
		t.Errorf("expected nil for unversioned/uncaptured parameter_types, got %v", names)
	}
}
