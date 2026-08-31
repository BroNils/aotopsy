package sdk

import (
	"testing"
)

func TestLookupRecognizedIntrinsic(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantOK   bool
		wantEnum string
	}{
		{
			name:     "BigInt multiply",
			input:    "_BigIntImpl._multiply",
			wantOK:   true,
			wantEnum: "BigInt_multiply",
		},
		{
			name:     "BigInt lsh",
			input:    "_BigIntImpl._lsh",
			wantOK:   true,
			wantEnum: "BigInt_lsh",
		},
		{
			name:     "Utf8 convert",
			input:    "_Utf8Decoder.convert",
			wantOK:   true,
			wantEnum: "Utf8DecoderConvert",
		},
		{
			name:     "Double sin with colon separator",
			input:    "_Double::sin",
			wantOK:   true,
			wantEnum: "DoubleSin",
		},
		{
			name:     "Non-existent method",
			input:    "CustomClass.unknownMethod",
			wantOK:   false,
			wantEnum: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			intr, ok := LookupRecognizedIntrinsic(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("LookupRecognizedIntrinsic(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if ok && intr.EnumName != tt.wantEnum {
				t.Errorf("LookupRecognizedIntrinsic(%q).EnumName = %q, want %q", tt.input, intr.EnumName, tt.wantEnum)
			}
		})
	}
}
