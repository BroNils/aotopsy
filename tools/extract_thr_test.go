package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"aotopsy/internal/snapshot"
	"aotopsy/internal/vmtables"
)

func TestEveryCommittedTHRTableHasTarget(t *testing.T) {
	root := filepath.Clean("..")
	files := []string{
		filepath.Join(root, "internal", "vmtables", "thrfields.go"),
		filepath.Join(root, "internal", "vmtables", "thrfieldsx86.go"),
	}
	committed, err := parseCommittedTables(files)
	if err != nil {
		t.Fatal(err)
	}

	covered := make(map[string]bool, len(allTargets))
	for _, target := range allTargets {
		covered[mapName(target.tag, target.arch, target.compressed, target.product)] = true
	}

	for name := range committed {
		if !covered[name] {
			t.Errorf("committed THR table %s has no matching extraction target", name)
		}
	}
}

func TestEverySupportedVersionHasProductTHRTargets(t *testing.T) {
	supported := map[string]bool{}
	for _, version := range snapshot.SupportedVersions() {
		supported[version] = true
		seen := map[vmtables.Architecture]bool{}
		for _, target := range allTargets {
			if target.tag != version || !target.product {
				continue
			}
			profile := vmTargetProfile(target)
			if len(vmtables.THRFields(profile)) != 0 {
				seen[profile.Architecture] = true
			}
		}
		for _, arch := range []vmtables.Architecture{vmtables.ArchitectureARM64, vmtables.ArchitectureX64} {
			if !seen[arch] {
				t.Errorf("supported Dart %s has no committed PRODUCT THR target for architecture %v", version, arch)
			}
		}
	}
	for _, target := range allTargets {
		if !supported[target.tag] {
			t.Errorf("allTargets contains unsupported Dart version %s", target.tag)
		}
	}
}

func TestDart2176ARM64NonCompressedUsesExactCommittedName(t *testing.T) {
	const want = "thrV2176_nocompress"
	if got := mapName("2.17.6", "arm64", false, true); got != want {
		t.Fatalf("mapName(2.17.6 arm64 uncompressed product) = %q, want %q", got, want)
	}
}

func TestObjectStoreFieldsUsesSharedSDKFetcherExactLocalTag(t *testing.T) {
	repo := t.TempDir()
	t.Setenv("AOTOPSY_DART_SDK_REPO", repo)
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", t.TempDir())
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	const tag = "9.9.9"
	sdkPath := filepath.Join(repo, "runtime", "vm", "object_store.h")
	if err := os.MkdirAll(filepath.Dir(sdkPath), 0o755); err != nil {
		t.Fatal(err)
	}
	const src = `#define OBJECT_STORE_FIELD_LIST(R_, RW) \
  RW(Object, object_class) \
  RW(Code, slow_tts_stub)

class ObjectStore {
#define DECLARE_OBJECT_STORE_FIELD(type, name) type name##_
  OBJECT_STORE_FIELD_LIST(DECLARE_OBJECT_STORE_FIELD, DECLARE_OBJECT_STORE_FIELD)

  ObjectPtr* from() { return reinterpret_cast<ObjectPtr*>(&object_class_); }
  ObjectPtr* to_snapshot(Snapshot::Kind kind) {
    switch (kind) {
      case kFullAOT:
        return reinterpret_cast<ObjectPtr*>(&slow_tts_stub_);
    }
  }
};
`
	if err := os.WriteFile(sdkPath, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git unavailable")
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "sdk-test@example.invalid"},
		{"config", "user.name", "SDK Test"},
		{"add", "runtime/vm/object_store.h"},
		{"commit", "-q", "-m", "fixture"},
		{"tag", tag},
	} {
		cmd := exec.Command(git, append([]string{"-C", repo}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	got, desc, err := objectStoreFields(tag)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"object_class", "slow_tts_stub"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("objectStoreFields() = %v, want %v", got, want)
	}
	if desc != "from=object_class to=slow_tts_stub" {
		t.Fatalf("objectStoreFields() description = %q", desc)
	}
}

func TestClassIdTagCheckFailsWhenNoSDKVersionCanBeVerified(t *testing.T) {
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", t.TempDir())
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	t.Setenv("AOTOPSY_DART_SDK_REPO", t.TempDir())

	if bad := runCheckClassIdTag(); bad == 0 {
		t.Fatal("ClassIdTag drift gate passed after verifying zero SDK versions")
	}
}
