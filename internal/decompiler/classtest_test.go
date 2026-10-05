package decompiler

import "testing"

func TestAnnotateClassIDCondition(t *testing.T) {
	names := map[int]string{116: "_Uint8Array", 119: "_Uint8ArrayView", 94: "_Smi"}
	f := &FuncIR{ClassNameForCID: func(cid int) string { return names[cid] }}
	for _, tc := range []struct{ in, want string }{
		// printed form and raw lifter form of the same unsigned range test
		{"(classId(x1) - 116 & 0xffffffffffffffff) > (3 & 0xffffffffffffffff)",
			"(classId(x1) - 116 & 0xffffffffffffffff) > (3 & 0xffffffffffffffff) /* x1 outside cid 116..119: _Uint8Array.._Uint8ArrayView */"},
		{"((classId(x1) - 116) & 0xffffffff) > ((3) & 0xffffffff)",
			"((classId(x1) - 116) & 0xffffffff) > ((3) & 0xffffffff) /* x1 outside cid 116..119: _Uint8Array.._Uint8ArrayView */"},
		// real 3.9.2 shape: operand is a field expression, triple parens
		{"(((classId((arg0.f75 & 0xffffffff)) - 116)) & 0xffffffffffffffff) > ((3) & 0xffffffffffffffff)",
			"(((classId((arg0.f75 & 0xffffffff)) - 116)) & 0xffffffffffffffff) > ((3) & 0xffffffffffffffff) /* (arg0.f75 & 0xffffffff) outside cid 116..119: _Uint8Array.._Uint8ArrayView */"},
		{"classId((x1.f87 & 0xffffffff)) != 94", "classId((x1.f87 & 0xffffffff)) != 94 /* cid 94 = _Smi */"},
		{"classId(x2) == 94", "classId(x2) == 94 /* cid 94 = _Smi */"},
		{"classId(x2) != 94", "classId(x2) != 94 /* cid 94 = _Smi */"},
		// an end of the range has no known class: unchanged
		{"classId(x2) == 95", "classId(x2) == 95"},
		{"(classId(x1) - 116 & 0xffffffff) > (5 & 0xffffffff)", "(classId(x1) - 116 & 0xffffffff) > (5 & 0xffffffff)"},
		{"x1 == null", "x1 == null"},
	} {
		if got := annotateClassIDCondition(f, tc.in); got != tc.want {
			t.Errorf("annotate(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
	if got := annotateClassIDCondition(&FuncIR{}, "classId(x2) == 94"); got != "classId(x2) == 94" {
		t.Errorf("nil resolver changed the condition: %q", got)
	}
}
