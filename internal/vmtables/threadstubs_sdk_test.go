package vmtables

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
	"aotopsy/internal/snapshot"
)

func TestThreadStubOffsetsMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	out, err := runStubOffsetCheck()
	t.Logf("extract_thr -check-stub-offsets output:\n%s", out)
	if err != nil {
		t.Fatalf("ThreadStubOffsets disagrees with the Dart SDK: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "verified") {
		t.Fatalf("stub-offset drift gate did not prove any target:\n%s", out)
	}
}

func target(version string, arch Architecture, compressed bool) TargetProfile {
	return TargetProfile{
		DartVersion:        version,
		Architecture:       arch,
		CompressedPointers: compressed,
		BuildMode:          snapshot.BuildProduct,
	}
}

func TestThreadStubOffsetsAreProfileAware(t *testing.T) {
	compressed := ThreadStubOffsets(target("3.12.2", ArchitectureX64, true))
	uncompressed := ThreadStubOffsets(target("3.12.2", ArchitectureX64, false))
	if compressed == nil || uncompressed == nil {
		t.Fatalf("3.12.2 x64 tables missing: compressed=%v uncompressed=%v", compressed != nil, uncompressed != nil)
	}
	if compressed[0x200] != "WriteBarrier" {
		t.Fatalf("compressed 3.12.2 x64 WriteBarrier=%q at 0x200", compressed[0x200])
	}
	if uncompressed[0x1f8] != "WriteBarrier" {
		t.Fatalf("uncompressed 3.12.2 x64 WriteBarrier=%q at 0x1f8", uncompressed[0x1f8])
	}
	if uncompressed[0x200] != "ArrayWriteBarrier" {
		t.Fatalf("uncompressed 3.12.2 x64 offset 0x200=%q, want ArrayWriteBarrier", uncompressed[0x200])
	}
}

func TestThreadStubOffsetsRefuseUnsupportedProfile(t *testing.T) {
	for _, p := range []TargetProfile{
		target("3.14.0", ArchitectureARM64, true),
		{DartVersion: "3.12.2", Architecture: ArchitectureUnknown, CompressedPointers: true},
		{DartVersion: "3.12.2", Architecture: ArchitectureX64, CompressedPointers: true, BuildMode: snapshot.BuildRelease},
	} {
		if got := ThreadStubOffsets(p); got != nil {
			t.Fatalf("ThreadStubOffsets(%+v) returned %d entries, want nil", p, len(got))
		}
	}
}

func TestThreadStubTablesAreInjective(t *testing.T) {
	profiles := []TargetProfile{
		target("2.10.0", ArchitectureARM64, false), target("2.12.0", ArchitectureX64, false),
		target("2.18.0", ArchitectureARM64, true), target("3.9.2", ArchitectureX64, true),
		target("3.9.2", ArchitectureX64, false), target("3.12.2", ArchitectureX64, true),
		target("3.12.2", ArchitectureX64, false), target("3.13.0", ArchitectureARM64, true),
	}
	for _, p := range profiles {
		tbl := ThreadStubOffsets(p)
		if len(tbl) == 0 {
			t.Fatalf("%+v: no stub offsets", p)
		}
		seen := map[string]int64{}
		for off, name := range tbl {
			if prev, dup := seen[name]; dup {
				t.Errorf("%+v: stub %q appears at both 0x%x and 0x%x", p, name, prev, off)
			}
			seen[name] = off
		}
	}
}

func runStubOffsetCheck() ([]byte, error) {
	cmd := exec.Command("go", "run", "tools/extract_thr.go", "-check-stub-offsets")
	cmd.Dir = ".."
	if wd, err := os.Getwd(); err == nil {
		cmd.Dir = strings.TrimSuffix(filepath.ToSlash(wd), "/internal/vmtables")
	}
	return cmd.CombinedOutput()
}
