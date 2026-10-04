package vmtables

import (
	"testing"

	"aotopsy/internal/snapshot"
)

func TestTargetProfileFromVersionRequiresExactProfile(t *testing.T) {
	p := snapshot.ProfileForVersion("3.12.2")
	if p == nil {
		t.Fatal("missing exact 3.12.2 profile")
	}
	p.BuildMode = snapshot.BuildProduct
	p.CompressedPointers = true
	if _, ok := TargetProfileFromVersion(p, false); !ok {
		t.Fatal("canonical per-binary profile was rejected")
	}

	mutated := *p
	mutated.ImageHeaderSize++
	if _, ok := TargetProfileFromVersion(&mutated, false); ok {
		t.Fatal("profile with mutated static image layout was accepted")
	}

	future := *p
	future.DartVersion = "3.12.99"
	if _, ok := TargetProfileFromVersion(&future, false); ok {
		t.Fatal("future version carrying copied profile facts was accepted")
	}
}

func TestTargetProfileRejectsUnregisteredVersion(t *testing.T) {
	target := TargetProfile{
		DartVersion:        "3.12.0-dev",
		Architecture:       ArchitectureX64,
		CompressedPointers: true,
		BuildMode:          snapshot.BuildProduct,
	}
	if fields := THRFields(target); fields != nil {
		t.Fatal("unregistered Dart version selected a THR table")
	}
	if stubs := ThreadStubOffsets(target); stubs != nil {
		t.Fatal("unregistered Dart version selected Thread cached stubs")
	}
}
