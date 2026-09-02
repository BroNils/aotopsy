package sdktest

import (
	"os"
	"path/filepath"
	"testing"
)

// GHFileAtTag must refuse a floating ref. Reading main gives the future,
// not the version a table was derived from, and the resulting "no drift"
// is meaningless.
func TestGHFileAtTagRefusesFloatingRef(t *testing.T) {
	for _, ref := range []string{"", "main", "master"} {
		if _, err := GHFileAtTag("runtime/vm/thread.h", ref); err == nil {
			t.Errorf("GHFileAtTag(..., %q) succeeded, want refusal", ref)
		}
	}
}

// A cached file must be served without invoking gh at all, which is what
// makes a full gate sweep survive the API rate limit.
func TestGHFileAtTagUsesDiskCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", dir)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	t.Setenv("PATH", "") // no gh reachable: a fetch would fail loudly

	const path, tag, body = "runtime/vm/thread.h", "9.9.9", "cached contents\n"
	full := filepath.Join(dir, tag, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	memMu.Lock()
	memCache = map[string]string{}
	memMu.Unlock()

	got, err := GHFileAtTag(path, tag)
	if err != nil {
		t.Fatalf("cached read: %v", err)
	}
	if got != body {
		t.Errorf("got %q, want %q", got, body)
	}
}

func TestGHFileAtTagOfflineMissFails(t *testing.T) {
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", t.TempDir())
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	memMu.Lock()
	memCache = map[string]string{}
	memMu.Unlock()
	if _, err := GHFileAtTag("runtime/vm/nothing_here.h", "9.9.9"); err == nil {
		t.Error("offline cache miss must fail; a silent empty result reads as no drift")
	}
}
