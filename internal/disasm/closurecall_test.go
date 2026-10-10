package disasm

import "testing"

// Encodings are taken from the dart-3.9.2-arm64 sample (compressed pointers):
//
//	LDR  X4, [X27,#656]  ; PP[80]   -> ARGS_DESC_REG load
//	LDUR X2, [X0,#31]               -> Closure.entry_point (32 - kHeapObjectTag)
//	BLR  X2
const (
	rawLDRX4PP656   = 0xF9414B64
	rawLDURX2X0D31  = 0xF841F002
	rawLDURX2X0D55  = 0xF843 << 16 // placeholder replaced below by arm64LDURX2X0
	rawBLRX2        = 0xD63F0040
	rawLDURX2X1D31  = 0xF841F022 // LDUR X2,[X1,#31]: wrong closure register
	rawMOVX9X10Nop  = 0xAA0A03E9 // mov x9, x10: does not define x4
	arm64LDURX2X0   = 0xF8400002 // LDUR X2,[X0,#0]; imm9 patched by ldurX2X0
	closureTestBase = 0x1000
)

func ldurX2X0(imm int) uint32 { return arm64LDURX2X0 | (uint32(imm)&0x1FF)<<12 }

func closureInsts(raws ...uint32) []Inst {
	insts := make([]Inst, len(raws))
	for i, raw := range raws {
		insts[i] = Inst{Addr: closureTestBase + uint64(i)*4, Raw: raw}
	}
	return insts
}

func TestClosureCallAnnotatorLabelsFullAOTClosureCall(t *testing.T) {
	_ = rawLDURX2X0D55
	for _, tc := range []struct {
		name    string
		version string
		comp    bool
		raws    []uint32
		want    bool
	}{
		{"3.9.2 compressed", "3.9.2", true, []uint32{rawLDRX4PP656, rawLDURX2X0D31, rawBLRX2}, true},
		{"3.9.2 uncompressed uses disp 55", "3.9.2", false, []uint32{rawLDRX4PP656, ldurX2X0(55), rawBLRX2}, true},
		{"3.9.2 uncompressed rejects compressed disp", "3.9.2", false, []uint32{rawLDRX4PP656, rawLDURX2X0D31, rawBLRX2}, false},
		{"3.13.0 entry point moved to +8", "3.13.0", true, []uint32{rawLDRX4PP656, ldurX2X0(7), rawBLRX2}, true},
		{"3.13.0 old displacement is the function field", "3.13.0", true, []uint32{rawLDRX4PP656, rawLDURX2X0D31, rawBLRX2}, false},
		{"2.13.0 has no Closure.entry_point_", "2.13.0", false, []uint32{rawLDRX4PP656, ldurX2X0(7), rawBLRX2}, false},
		{"missing ARGS_DESC definition", "3.9.2", true, []uint32{rawMOVX9X10Nop, rawLDURX2X0D31, rawBLRX2}, false},
		{"closure register must be R0", "3.9.2", true, []uint32{rawLDRX4PP656, rawLDURX2X1D31, rawBLRX2}, false},
		{"BLR must follow immediately", "3.9.2", true, []uint32{rawLDRX4PP656, rawLDURX2X0D31, rawMOVX9X10Nop, rawBLRX2}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			insts := closureInsts(tc.raws...)
			ann := ClosureCallAnnotator(insts, ClosureEntryFor(tc.version, tc.comp))
			edges := ExtractCallEdgesCFG("f", insts, nil, []Annotator{ann}, nil)
			var via string
			for _, e := range edges {
				if e.Kind == "blr" {
					via = e.Via
				}
			}
			if got := via == ClosureEntryVia; got != tc.want {
				t.Fatalf("via = %q, closure call recognised = %v, want %v", via, got, tc.want)
			}
		})
	}
}

func TestClosureCallX86(t *testing.T) {
	code := []byte{
		0x4d, 0x8b, 0x57, 0x10, // mov r10, [r15+0x10]   (ARGS_DESC_REG definition)
		0x48, 0x8b, 0x48, 0x37, // mov rcx, [rax+0x37]   (Closure.entry_point, uncompressed)
		0xff, 0xd1, // call rcx
		0xc3,
	}
	res := ScanX86FunctionCFG("3.9.2", ClosureEntryFor("3.9.2", false), code, 0x2000, nil, nil, "f", nil)
	if len(res.Edges) != 1 || res.Edges[0].Via != ClosureEntryVia {
		t.Fatalf("edges = %+v, want one call_indirect via %q", res.Edges, ClosureEntryVia)
	}
	// Compressed build: the same bytes load the function field, not the entry point.
	res = ScanX86FunctionCFG("3.9.2", ClosureEntryFor("3.9.2", true), code, 0x2000, nil, nil, "f", nil)
	if len(res.Edges) != 1 || res.Edges[0].Via == ClosureEntryVia {
		t.Fatalf("compressed config accepted the uncompressed displacement: %+v", res.Edges)
	}
}
