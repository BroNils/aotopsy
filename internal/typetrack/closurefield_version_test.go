package typetrack

import "testing"

func TestClosureFieldOffsetsAcrossLayoutBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		ctx        TypeContext
		function   int
		entryPoint int
	}{
		{
			name:       "2.13 compressed uses ordinary pointer fields and has no cached entry point",
			ctx:        TypeContext{DartVersion: "2.13.0", WordSize: 4, CompressedPointers: true},
			function:   31,
			entryPoint: -1,
		},
		{
			name:       "2.14 compressed uses compact closure pointer fields",
			ctx:        TypeContext{DartVersion: "2.14.0", WordSize: 4, CompressedPointers: true},
			function:   19,
			entryPoint: 31,
		},
		{
			name:       "3.13 compressed variable length closure",
			ctx:        TypeContext{DartVersion: "3.13.0", WordSize: 4, CompressedPointers: true},
			function:   27,
			entryPoint: 7,
		},
		{
			name:       "3.13 uncompressed variable length closure",
			ctx:        TypeContext{DartVersion: "3.13.0", WordSize: 8},
			function:   31,
			entryPoint: 7,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := closureFunctionOffset(&tc.ctx); got != tc.function {
				t.Fatalf("closureFunctionOffset = %d, want %d", got, tc.function)
			}
			if got := closureEntryPointOffset(&tc.ctx); got != tc.entryPoint {
				t.Fatalf("closureEntryPointOffset = %d, want %d", got, tc.entryPoint)
			}
		})
	}
}
