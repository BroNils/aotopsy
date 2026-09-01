package sdktest

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The macro expander is the piece every SDK gate now depends on, and its
// failure mode is silent truncation -- a short list reads as a narrower
// mask or a shifted table, not as an error. These cases are the shapes
// that actually appear in the SDK headers.

const sampleHeader = `
// A leading comment mentioning V(NotAnEntry).
#define PROBE_POINT_STUBS_LIST(V)                                              \
  V(AllocationProbePoint)                                                      \
  V(ReturnProbePoint)

/* A block comment with V(AlsoNotAnEntry) in it. */
#define VM_TYPE_TESTING_STUB_CODE_LIST(V)                                      \
  V(DefaultTypeTest)

#define VM_STUB_CODE_LIST(V)                                                   \
  V(GetCStackPointer)                                                          \
  PROBE_POINT_STUBS_LIST(V)                                                    \
  V(JumpToFrame)                                                               \
  VM_TYPE_TESTING_STUB_CODE_LIST(V)

#define CACHED_VM_OBJECTS_LIST(V)                                              \
  V(ObjectPtr, object_null_, Object::null())                                   \
  V(BoolPtr, bool_true_, Object::bool_true().ptr())
`

func TestExpandMacroNested(t *testing.T) {
	macros := ParseMacros(sampleHeader)
	got, err := ExpandMacro(macros, "VM_STUB_CODE_LIST")
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	want := []string{
		"GetCStackPointer",
		"AllocationProbePoint", "ReturnProbePoint",
		"JumpToFrame",
		"DefaultTypeTest",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("nested expansion\n got %q\nwant %q", got, want)
	}
}

func TestExpandMacroIgnoresComments(t *testing.T) {
	macros := ParseMacros(sampleHeader)
	got, err := ExpandMacro(macros, "PROBE_POINT_STUBS_LIST")
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	want := []string{"AllocationProbePoint", "ReturnProbePoint"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	// A V(...) inside a line or block comment must not become an entry.
	for _, n := range got {
		if n == "NotAnEntry" || n == "AlsoNotAnEntry" {
			t.Errorf("comment contents leaked into the list: %q", n)
		}
	}
}

func TestExpandMacroMultiArg(t *testing.T) {
	macros := ParseMacros(sampleHeader)
	rows, err := ExpandMacroRaw(macros, "CACHED_VM_OBJECTS_LIST")
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2: %q", len(rows), rows)
	}
	if !reflect.DeepEqual(rows[0], []string{"ObjectPtr", "object_null_", "Object::null()"}) {
		t.Errorf("row 0 = %q", rows[0])
	}
	// A single-argument read of a multi-argument list must yield the type,
	// not silently drop the row.
	names, err := ExpandMacroColumn(macros, "CACHED_VM_OBJECTS_LIST", 1)
	if err != nil {
		t.Fatalf("column: %v", err)
	}
	if !reflect.DeepEqual(names, []string{"object_null_", "bool_true_"}) {
		t.Errorf("column 1 = %q", names)
	}
}

func TestExpandMacroUnknown(t *testing.T) {
	if _, err := ExpandMacro(ParseMacros(sampleHeader), "NO_SUCH_LIST"); err == nil {
		t.Error("expanding an unknown macro must fail, not return an empty list")
	}
}

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
