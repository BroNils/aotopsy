package naming

import (
	"testing"

	"aotopsy/internal/cluster"
)

func TestFunctionCallConventionDisposition(t *testing.T) {
	nonGeneric := &cluster.FuncTypeInfo{TypeParamsRefID: cluster.RefNull}
	generic := &cluster.FuncTypeInfo{TypeParamsRefID: cluster.RefNull + 1}
	regular := &cluster.NamedObject{HasKindTag: true, FuncKind: cluster.FunctionKindRegular}
	closure := &cluster.NamedObject{HasKindTag: true, FuncKind: cluster.FunctionKindClosure}
	ffi := &cluster.NamedObject{HasKindTag: true, FuncKind: cluster.FunctionKindFfiTrampoline}
	other := &cluster.NamedObject{HasKindTag: true, FuncKind: cluster.FunctionKindOther}
	methodExtractor := &cluster.NamedObject{HasKindTag: true, FuncKind: cluster.FunctionKindMethodExtractor}

	cases := []struct {
		name                   string
		version                string
		owner                  *cluster.NamedObject
		ft                     *cluster.FuncTypeInfo
		wantMay, wantMustStack bool
	}{
		{"pre-343", "3.3.0", regular, nonGeneric, false, true},
		{"modern-regular", "3.4.3", regular, nonGeneric, true, false},
		{"modern-generic", "3.4.3", regular, generic, false, true},
		{"modern-closure", "3.12.2", closure, nonGeneric, false, true},
		{"modern-ffi", "3.12.2", ffi, nonGeneric, false, true},
		{"modern-method-extractor", "3.12.2", methodExtractor, nonGeneric, false, true},
		// Unknown metadata is not positive register proof, but it also cannot
		// rule register CC out. Consumers still require machine-code evidence.
		{"unknown-kind", "3.12.2", other, nonGeneric, true, false},
		{"missing-signature", "3.12.2", regular, nil, true, false},
		{"missing-kind-tag", "3.12.2", &cluster.NamedObject{}, nil, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			may, must := functionCallConventionDisposition(tc.version, tc.owner, tc.ft)
			if may != tc.wantMay || must != tc.wantMustStack {
				t.Fatalf("got may=%v mustStack=%v, want %v/%v", may, must, tc.wantMay, tc.wantMustStack)
			}
		})
	}
}

func TestFunctionReceiverDispositionRequiresConsistentMetadata(t *testing.T) {
	instance := &cluster.NamedObject{HasKindTag: true, IsStatic: false}
	static := &cluster.NamedObject{HasKindTag: true, IsStatic: true}
	implicit := &cluster.FuncTypeInfo{HasImplicit: true}
	nonImplicit := &cluster.FuncTypeInfo{HasImplicit: false}

	tests := []struct {
		name                string
		owner               *cluster.NamedObject
		ft                  *cluster.FuncTypeInfo
		wantKnown, wantRecv bool
	}{
		{"instance-kind-tag", instance, nil, true, true},
		{"static-kind-tag", static, nil, true, false},
		{"signature-only-instance", &cluster.NamedObject{}, implicit, true, true},
		{"signature-only-static", &cluster.NamedObject{}, nonImplicit, true, false},
		{"agree-instance", instance, implicit, true, true},
		{"agree-static", static, nonImplicit, true, false},
		{"conflict-instance-vs-static-signature", instance, nonImplicit, false, false},
		{"conflict-static-vs-instance-signature", static, implicit, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			known, recv := functionReceiverDisposition(tt.owner, tt.ft)
			if known != tt.wantKnown || recv != tt.wantRecv {
				t.Fatalf("got known=%v receiver=%v, want %v/%v", known, recv, tt.wantKnown, tt.wantRecv)
			}
		})
	}
}
