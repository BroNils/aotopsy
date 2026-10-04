package vmtables

import (
	"testing"

	"aotopsy/internal/snapshot"
)

func TestDart392CachedConstantFieldsPresentOnBothArchitectures(t *testing.T) {
	for _, arch := range []Architecture{ArchitectureARM64, ArchitectureX64} {
		name := "arm64"
		if arch == ArchitectureX64 {
			name = "x64"
		}
		t.Run(name, func(t *testing.T) {
			fields := THRFields(TargetProfile{
				DartVersion: "3.9.2", Architecture: arch,
				CompressedPointers: true, BuildMode: snapshot.BuildProduct,
			})
			for off, want := range map[int]string{
				0x90:  "empty_array",
				0x98:  "empty_type_arguments",
				0xa0:  "dynamic_type",
				0x2b8: "double_nan_address",
			} {
				if got := fields[off]; got != want {
					t.Fatalf("THR[%#x] = %q, want %q", off, got, want)
				}
			}
		})
	}
}

func TestDeferredMarkingStackBlockIsCanonicalSDKDerivedField(t *testing.T) {
	for _, tc := range []struct {
		version string
		arch    Architecture
		off     int
	}{
		{"3.2.5", ArchitectureARM64, 0x718},
		{"3.12.2", ArchitectureX64, 0x678},
	} {
		fields := THRFields(TargetProfile{
			DartVersion: tc.version, Architecture: tc.arch,
			CompressedPointers: true, BuildMode: snapshot.BuildProduct,
		})
		if got := fields[tc.off]; got != "deferred_marking_stack_block" {
			t.Fatalf("%s/%v THR[%#x] = %q, want deferred_marking_stack_block", tc.version, tc.arch, tc.off, got)
		}
	}
}
