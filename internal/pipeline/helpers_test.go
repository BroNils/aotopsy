package pipeline

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

	ct := &snapshot.CIDTable{Field: fieldCID, Class: classCID}

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

// TestResolveCodeOwner_PrefersCodeIndexOverBogusOwnerRef is a regression
// test for the real Dart 3.7.0 x86_64 bug: ~5.4% of functions carry a
// bogus shared Code.OwnerRef that resolves to CID 61 (Mint), never a
// legal Code owner. This reproduces exactly that shape -- OwnerRef
// points at a Mint NamedObject instead of the real Function -- and
// verifies the reliable Function.CodeIndex==Code.ClusterIndex
// cross-reference is used instead, recovering the real owner.
func TestResolveCodeOwner_PrefersCodeIndexOverBogusOwnerRef(t *testing.T) {
	const (
		mintCID    = 61
		funcCID    = 6
		bogusRef   = 900 // the Mint object every buggy Code.OwnerRef points at
		realFnRef  = 901
		clusterIdx = 5
	)
	ct := &snapshot.CIDTable{Function: funcCID}

	realFn := &cluster.NamedObject{CID: funcCID, RefID: realFnRef, CodeIndex: clusterIdx}
	bogusMint := &cluster.NamedObject{CID: mintCID, RefID: bogusRef, CodeIndex: -1}

	result := &cluster.Result{
		Named: []cluster.NamedObject{*realFn, *bogusMint},
	}
	byCodeIndex := CodeIndexToFunc(result, ct, false)

	refToNamed := map[int]*cluster.NamedObject{
		realFnRef: realFn,
		bogusRef:  bogusMint,
	}

	ce := cluster.CodeEntry{RefID: 1, OwnerRef: bogusRef, ClusterIndex: clusterIdx}
	owner, ok := ResolveCodeOwner(ce, refToNamed, byCodeIndex)
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
	owner := &cluster.NamedObject{CID: 6, RefID: ownerRef}
	refToNamed := map[int]*cluster.NamedObject{ownerRef: owner}

	ce := cluster.CodeEntry{RefID: 1, OwnerRef: ownerRef, ClusterIndex: -1}
	got, ok := ResolveCodeOwner(ce, refToNamed, map[int]*cluster.NamedObject{})
	if !ok || got.RefID != ownerRef {
		t.Fatalf("expected fallback to OwnerRef=%d, got %+v ok=%v", ownerRef, got, ok)
	}
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
			{CID: funcCID, RefID: 1, CodeIndex: 3},
			{CID: funcCID, RefID: 2, CodeIndex: 3}, // collides with ref=1
		},
	}
	m := CodeIndexToFunc(result, ct, false)
	if _, ok := m[3]; ok {
		t.Error("expected ambiguous CodeIndex 3 to be dropped, not mapped to either candidate")
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
