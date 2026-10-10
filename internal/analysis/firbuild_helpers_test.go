package analysis

import (
	"reflect"
	"testing"

	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/naming"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/typetrack"
)

func TestEnrichSignatureUsesSerializedResultTypeNotFunctionName(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 6}
	owners := map[int]*cluster.NamedObject{
		100: {CID: ct.Function, RefID: 100, ResultTypeRefID: 300},
		101: {CID: ct.Function, RefID: 101, ResultTypeRefID: 300, SignatureRefID: 201},
	}
	pl := &naming.PoolLookups{
		CT:         ct,
		RefToNamed: owners,
		SourceTypeNames: map[int]string{
			300: "String",
			301: "int",
		},
	}
	resolver := naming.NewTypeParamResolver(&cluster.Result{}, pl)
	ctx := &AnalysisContext{
		Pool: pl,
		Enrichment: &DecompileEnrichment{
			TypeParams: resolver,
			ParamFuncTypeByRef: map[int]*cluster.FuncTypeInfo{
				201: {RefID: 201, ResultTypeRefID: 301},
			},
		},
	}

	legacy := &decompiler.FuncIR{Name: "clear"}
	ctx.enrichSignatureAndAsync(legacy, cluster.CodeRange{RefID: 1, OwnerRef: 100, Index: -1})
	if legacy.ReturnType != "String" {
		t.Fatalf("direct Function.result_type = %q, want String", legacy.ReturnType)
	}

	modern := &decompiler.FuncIR{Name: "isReady"}
	ctx.enrichSignatureAndAsync(modern, cluster.CodeRange{RefID: 2, OwnerRef: 101, Index: -1})
	if modern.ReturnType != "int" {
		t.Fatalf("FunctionType.result_type = %q, want int", modern.ReturnType)
	}
}

func TestEnrichSignatureUsesSerializedFunctionModifier(t *testing.T) {
	ct := &snapshot.CIDTable{Function: 6}
	owners := map[int]*cluster.NamedObject{
		100: {CID: ct.Function, RefID: 100, HasKindTag: true, FuncModifier: cluster.FunctionModifierAsync},
		101: {CID: ct.Function, RefID: 101, HasKindTag: true, FuncModifier: cluster.FunctionModifierSyncStar},
		102: {CID: ct.Function, RefID: 102, HasKindTag: true, FuncModifier: cluster.FunctionModifierAsyncStar},
		103: {CID: ct.Function, RefID: 103, HasKindTag: true, FuncModifier: cluster.FunctionModifierNone},
	}
	ctx := &AnalysisContext{
		Pool:       &naming.PoolLookups{CT: ct, RefToNamed: owners},
		Enrichment: &DecompileEnrichment{},
	}

	tests := []struct {
		ref                            int
		wantAsync, wantSync, wantAStar bool
	}{
		{100, true, false, false},
		{101, false, true, false},
		{102, true, false, true},
		{103, false, false, false},
	}
	for _, tt := range tests {
		fir := &decompiler.FuncIR{}
		ctx.enrichSignatureAndAsync(fir, cluster.CodeRange{OwnerRef: tt.ref, Index: -1})
		if fir.IsAsync != tt.wantAsync || fir.IsSyncStar != tt.wantSync || fir.IsAsyncStar != tt.wantAStar {
			t.Errorf("modifier owner %d => async=%v sync*=%v async*=%v, want %v/%v/%v",
				tt.ref, fir.IsAsync, fir.IsSyncStar, fir.IsAsyncStar, tt.wantAsync, tt.wantSync, tt.wantAStar)
		}
	}
}

func TestBuildClassLayoutsExcludesCompressedObjectHeader(t *testing.T) {
	result := &cluster.Result{Classes: []cluster.ClassInfo{{
		RefID:        10,
		NameRefID:    11,
		ClassID:      42,
		InstanceSize: 4,
		NextFieldOff: 4,
		TypeArgsOff:  cluster.NoTypeArguments,
	}}}
	pl := &naming.PoolLookups{RefToStr: map[int]string{11: "Widget"}}

	layouts := BuildClassLayouts(result, pl, true)
	if len(layouts) != 1 {
		t.Fatalf("layouts = %d, want 1", len(layouts))
	}
	if len(layouts[0].Fields) != 2 {
		t.Fatalf("compressed fields = %+v, want only offsets 8 and 12", layouts[0].Fields)
	}
	if layouts[0].Fields[0].ByteOffset != 8 || layouts[0].Fields[1].ByteOffset != 12 {
		t.Fatalf("compressed field offsets = %d,%d, want 8,12", layouts[0].Fields[0].ByteOffset, layouts[0].Fields[1].ByteOffset)
	}
}

func TestNamingConsumersUseGuardedVMBaseStrings(t *testing.T) {
	ct := &snapshot.CIDTable{OneByteString: 70}
	pl := &naming.PoolLookups{
		CT:           ct,
		RefToStr:     map[int]string{},
		VmRefToStr:   map[int]string{7: "Widget", 8: "package:app/widget.dart", 99: "WrongHighName"},
		VmRefCID:     map[int]int{7: ct.OneByteString, 8: ct.OneByteString, 99: ct.OneByteString},
		BaseObjLimit: 50,
	}

	result := &cluster.Result{
		Classes: []cluster.ClassInfo{
			{RefID: 10, NameRefID: 7, ClassID: 42, InstanceSize: 4, NextFieldOff: 4, TypeArgsOff: cluster.NoTypeArguments},
			{RefID: 11, NameRefID: 99, ClassID: 43, InstanceSize: 4, NextFieldOff: 4, TypeArgsOff: cluster.NoTypeArguments},
		},
		Scripts: []cluster.ScriptInfo{
			{RefID: 20, URLRef: 8},
			{RefID: 21, URLRef: 99},
		},
	}

	layouts := BuildClassLayouts(result, pl, true)
	if len(layouts) != 1 || layouts[0].ClassName != "Widget" {
		t.Fatalf("class layouts from VM-base names = %+v, want only Widget", layouts)
	}

	scripts := BuildScripts(result, pl)
	if len(scripts) != 2 || scripts[0].URL != "package:app/widget.dart" || scripts[1].URL != "" {
		t.Fatalf("script URL guarded VM fallback = %+v", scripts)
	}
}

func TestBuildFieldTypeByClassOffsetResolvesHostOffsetReference(t *testing.T) {
	result := &cluster.Result{
		Classes: []cluster.ClassInfo{{RefID: 10, ClassID: 42}},
		Types:   []cluster.TypeInfo{{RefID: 20, ClassID: 99}},
		Fields: []cluster.FieldInfo{{
			RefID:      30,
			OwnerRefID: 10,
			TypeRefID:  20,
			HostOffset: 777,
		}},
		MintValues: map[int]int64{777: 3},
	}
	pl := &naming.PoolLookups{}

	compressed := BuildFieldTypeByClassOffset(result, pl, true)
	if got := compressed[42][12]; got != 99 {
		t.Fatalf("compressed field type at byte offset 12 = %d, want 99", got)
	}
	if _, exists := compressed[42][777]; exists {
		t.Fatal("raw HostOffset reference leaked into byte-offset map")
	}

	uncompressed := BuildFieldTypeByClassOffset(result, pl, false)
	if got := uncompressed[42][24]; got != 99 {
		t.Fatalf("uncompressed field type at byte offset 24 = %d, want 99", got)
	}
}

func TestPatchClassOwnedFieldFeedsLayoutsAndTypeChains(t *testing.T) {
	ct := &snapshot.CIDTable{PatchClass: 6}
	result := &cluster.Result{
		Classes: []cluster.ClassInfo{{
			RefID: 10, NameRefID: 11, ClassID: 42, InstanceSize: 4, NextFieldOff: 4,
			TypeArgsOff: cluster.NoTypeArguments,
		}},
		Types: []cluster.TypeInfo{{RefID: 20, ClassID: 99}},
		Fields: []cluster.FieldInfo{{
			RefID: 30, NameRefID: 31, OwnerRefID: 50, TypeRefID: 20, HostOffset: 777,
		}},
		MintValues: map[int]int64{777: 3},
	}
	pl := &naming.PoolLookups{
		CT:       ct,
		RefToStr: map[int]string{11: "Widget", 31: "child"},
		RefToNamed: map[int]*cluster.NamedObject{
			50: {RefID: 50, CID: ct.PatchClass, OwnerRefID: 10},
		},
	}

	layouts := BuildClassLayouts(result, pl, true)
	if len(layouts) != 1 || len(layouts[0].Fields) != 2 {
		t.Fatalf("layouts = %#v, want one 2-slot class", layouts)
	}
	if got := layouts[0].Fields[1]; got.ByteOffset != 12 || got.Name != "child" || got.SlotType != slotInstanceField {
		t.Fatalf("patched field layout = %#v, want child at byte offset 12", got)
	}
	types := BuildFieldTypeByClassOffset(result, pl, true)
	if got := types[42][12]; got != 99 {
		t.Fatalf("patched field type at byte offset 12 = %d, want 99", got)
	}
}

func TestRunTypeInferenceStagePropagatesParseFailure(t *testing.T) {
	opts := &Opts{OutDir: t.TempDir(), Quiet: true}
	profile := &snapshot.VersionProfile{
		DartVersion:              "3.12.2",
		ObjectStoreAOTFieldCount: 1,
		CodeTextOffsetDelta:      true,
		CIDs:                     &snapshot.CIDTable{},
	}
	info := &snapshot.Info{Version: profile, IsolateData: snapshot.Region{Data: nil}}

	_, err := RunTypeInferenceStage(opts, true, &naming.PoolLookups{}, &cluster.Result{}, nil, nil, 0, 0, info, nil, nil, nil)
	if err == nil {
		t.Fatal("type inference parse failure was silently downgraded to success")
	}
}

func TestRunTypeInferenceStageRejectsMissingPrerequisites(t *testing.T) {
	opts := &Opts{OutDir: t.TempDir(), Quiet: true}
	base := snapshot.VersionProfile{
		DartVersion:              "3.12.2",
		ObjectStoreAOTFieldCount: 1,
		CodeTextOffsetDelta:      true,
		CIDs:                     &snapshot.CIDTable{},
	}
	tests := []struct {
		name    string
		profile *snapshot.VersionProfile
		pl      *naming.PoolLookups
	}{
		{"missing pool", &base, nil},
		{"missing cids", &snapshot.VersionProfile{DartVersion: "3.12.2", ObjectStoreAOTFieldCount: 1, CodeTextOffsetDelta: true}, &naming.PoolLookups{}},
		{"unverified object store", &snapshot.VersionProfile{DartVersion: "3.12.2", CodeTextOffsetDelta: true, CIDs: &snapshot.CIDTable{}}, &naming.PoolLookups{}},
		{"missing code locator", &snapshot.VersionProfile{DartVersion: "3.12.2", ObjectStoreAOTFieldCount: 1, CIDs: &snapshot.CIDTable{}}, &naming.PoolLookups{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &snapshot.Info{Version: tt.profile}
			if _, err := RunTypeInferenceStage(opts, true, tt.pl, &cluster.Result{}, nil, nil, 0, 0, info, nil, nil, nil); err == nil {
				t.Fatal("missing type-inference prerequisite was silently accepted")
			}
		})
	}
}

func TestBuildClassNameToIDDropsAmbiguousShortNames(t *testing.T) {
	layouts := []DartClassLayout{
		{ClassName: "State", ClassID: 10},
		{ClassName: "Unique", ClassID: 20},
		{ClassName: "State", ClassID: 30},
	}
	got := BuildClassNameToID(layouts)
	if _, ok := got["State"]; ok {
		t.Fatalf("ambiguous short class name survived lookup: %#v", got)
	}
	if got["Unique"] != 20 {
		t.Fatalf("unique class mapping = %#v, want Unique->20", got)
	}
}

func TestBuildSelectorTargetsUsesSelectorImmediate(t *testing.T) {
	ctx := &typetrack.TypeContext{MethodNameToSelectorImms: map[string][]int{
		"A.foo": {7, 7},
		"B.foo": {7},
		"bar":   {-3},
	}}
	got := buildSelectorTargets(ctx)
	if !reflect.DeepEqual(got[7], []string{"A.foo", "B.foo"}) {
		t.Fatalf("selector 7 targets = %#v", got[7])
	}
	if !reflect.DeepEqual(got[-3], []string{"bar"}) {
		t.Fatalf("selector -3 targets = %#v", got[-3])
	}
}
