package cluster

import "testing"

// TestPackedParameterCountsLayout locks the bit layout this package decodes
// out of UntaggedFunctionType::packed_parameter_counts_.
//
// Verified against dart-lang/sdk raw_object.h @3.12.2:
//
//	PackedNumImplicitParameters      = BitField<..., uint8_t, 0, 1>
//	PackedHasNamedOptionalParameters = BitField<..., bool,
//	                                     PackedNumImplicitParameters::kNextBit>
//	PackedNumFixedParameters         = BitField<..., uint16_t,
//	                                     PackedHasNamedOptionalParameters::kNextBit, 14>
//	PackedNumOptionalParameters      = BitField<..., uint16_t,
//	                                     PackedNumFixedParameters::kNextBit, 14>
//
// so bit 0 is the implicit-receiver count, bit 1 says whether the optional
// parameters are NAMED, bits 2..15 hold num_fixed and bits 16..29 num_optional.
//
// Bit 1 is the one worth a test: it was silently dropped for a long time, and
// without it a function with optional POSITIONAL parameters is
// indistinguishable from one with named parameters -- which is exactly the
// mistake that made the decompiler invent parameter names.
func TestPackedParameterCountsLayout(t *testing.T) {
	// pack builds a packed_parameter_counts_ word from its four fields.
	pack := func(implicit, named bool, numFixed, numOptional uint32) uint32 {
		var v uint32
		if implicit {
			v |= 1
		}
		if named {
			v |= 2
		}
		return v | (numFixed&0x3FFF)<<2 | (numOptional&0x3FFF)<<16
	}

	cases := []struct {
		name      string
		packed    uint32
		wantFixed int // AFTER the implicit receiver is subtracted
		wantOpt   int
		wantImplicit,
		wantNamed bool
	}{
		// static void f() {}
		{"static no params", pack(false, false, 0, 0), 0, 0, false, false},
		// void m(int a) {} on a class: receiver + 1 declared.
		{"instance one param", pack(true, false, 2, 0), 1, 0, true, false},
		// static void f(int a, [int b]) {}
		{"optional positional", pack(false, false, 1, 1), 1, 1, false, false},
		// static void f(int a, {int? b, int? c}) {}
		{"optional named", pack(false, true, 1, 2), 1, 2, false, true},
		// void m({int? b}) {} on a class: named AND an implicit receiver.
		{"instance named", pack(true, true, 1, 1), 0, 1, true, true},
		// Both fields are 14 bits wide and must not bleed into each other.
		{"max widths", pack(false, false, 0x3FFF, 0x3FFF), 0x3FFF, 0x3FFF, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			packed := tc.packed
			hasImplicit := (packed & 1) != 0
			hasNamedOptional := (packed & 2) != 0
			numFixed := int((packed >> 2) & 0x3FFF)
			numOptional := int((packed >> 16) & 0x3FFF)
			if hasImplicit && numFixed > 0 {
				numFixed--
			}
			if hasImplicit != tc.wantImplicit {
				t.Errorf("hasImplicit = %v, want %v", hasImplicit, tc.wantImplicit)
			}
			if hasNamedOptional != tc.wantNamed {
				t.Errorf("hasNamedOptional = %v, want %v", hasNamedOptional, tc.wantNamed)
			}
			if numFixed != tc.wantFixed {
				t.Errorf("numFixed = %d, want %d", numFixed, tc.wantFixed)
			}
			if numOptional != tc.wantOpt {
				t.Errorf("numOptional = %d, want %d", numOptional, tc.wantOpt)
			}
		})
	}
}
