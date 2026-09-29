package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
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

func TestDart2176ARM64NonCompressedUsesExactCommittedName(t *testing.T) {
	const want = "thrV2176_nocompress"
	if got := mapName("2.17.6", "arm64", false, true); got != want {
		t.Fatalf("mapName(2.17.6 arm64 uncompressed product) = %q, want %q", got, want)
	}
}

func TestObjectStoreFieldsUsesSharedSDKFetcherCache(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", cacheDir)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	const tag = "9.9.9"
	cachePath := filepath.Join(cacheDir, tag, "runtime", "vm", "object_store.h")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	const src = `#define OBJECT_STORE_FIELD_LIST(V) \
  RW(Object, object_class) \
  RW(Code, slow_tts_stub)

class ObjectStore {
#define DECLARE_OBJECT_STORE_FIELD(type, name) type name##_
  OBJECT_STORE_FIELD_LIST(DECLARE_OBJECT_STORE_FIELD)

  ObjectPtr* from() { return reinterpret_cast<ObjectPtr*>(&object_class_); }
  ObjectPtr* to_snapshot(Snapshot::Kind kind) {
    switch (kind) {
      case kFullAOT:
        return reinterpret_cast<ObjectPtr*>(&slow_tts_stub_);
    }
  }
};
`
	if err := os.WriteFile(cachePath, []byte(src), 0o600); err != nil {
		t.Fatal(err)
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
