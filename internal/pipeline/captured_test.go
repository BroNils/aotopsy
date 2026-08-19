package pipeline

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression coverage for the fill-phase capture layer (Instance, Context,
// TypeArguments, ExceptionHandlers, ICData, Script, LoadingUnit,
// KernelProgramInfo, ClosureData) and for the JSONL artifacts built from it.
//
// Gated on AOTOPSY_TEST_SAMPLE_ARM64 (a Dart 3.9.2 ARM64 libapp.so), same as
// the other integration tests; skips when unset.

// sharedCaptureOutDir caches the pipeline output from a single Run() call
// so that multiple TestCaptured_* tests don't each re-run the full pipeline
// (each Run() takes ~90s on the 3.9.2 ARM64 sample, and running 5 of them
// serially exceeds the test timeout).
var sharedCaptureOutDir string
var sharedCaptureErr error

func runCaptureFixture(t *testing.T) string {
	t.Helper()
	// Delegate to the package-wide shared pipeline fixture.
	return sharedPipelineOutDir(t)
}

func readJSONL(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		return nil // absent file == zero records, which is a valid assertion target
	}
	defer func() { _ = f.Close() }()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("%s: bad JSON line: %v", filepath.Base(path), err)
		}
		out = append(out, m)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("%s: %v", filepath.Base(path), err)
	}
	return out
}

// TestCaptured_AbsentInAOT pins the fact that ICData, Context and
// KernelProgramInfo never appear in an AOT snapshot, so their files are never
// written. Analysis features must not be built on them -- an earlier revision
// wired BLR call resolution to ICData and it resolved exactly zero call sites.
func TestCaptured_AbsentInAOT(t *testing.T) {
	outDir := runCaptureFixture(t)
	for _, name := range []string{"icdata.jsonl", "contexts.jsonl", "kpi.jsonl"} {
		if recs := readJSONL(t, filepath.Join(outDir, name)); len(recs) != 0 {
			t.Errorf("%s: got %d records, want 0 (not serialized in AOT). If this "+
				"ever fires legitimately, the capture code is unverified against a "+
				"real binary -- validate the ref order before trusting it.", name, len(recs))
		}
	}
}

// TestCaptured_Scripts checks Script capture against ground truth: URLs must be
// real Dart URIs, and the app's own library must be present. Guards the
// assumption that Script's ref 0 is url_ (ReadFromTo order).
func TestCaptured_Scripts(t *testing.T) {
	outDir := runCaptureFixture(t)
	recs := readJSONL(t, filepath.Join(outDir, "scripts.jsonl"))
	if len(recs) < 100 {
		t.Fatalf("scripts.jsonl: got %d records, want >=100", len(recs))
	}
	var withURL, appOwn int
	for _, r := range recs {
		url, _ := r["url"].(string)
		if url == "" {
			continue
		}
		withURL++
		if !strings.Contains(url, ":") {
			t.Errorf("script url %q has no scheme -- ref 0 may not be url_", url)
		}
		if strings.HasPrefix(url, "package:compare_sample/") {
			appOwn++
		}
	}
	// A handful of dart:* patch scripts legitimately carry no url; the vast
	// majority must resolve.
	if ratio := float64(withURL) / float64(len(recs)); ratio < 0.9 {
		t.Errorf("only %.0f%% of scripts resolved a URL (%d/%d), want >=90%%",
			ratio*100, withURL, len(recs))
	}
	if appOwn == 0 {
		t.Error("no package:compare_sample/ script found; expected the app's own library")
	}
}

// TestCaptured_ExceptionHandlers sanity-checks handler decoding. outer_try_index
// is read as a tagged 32-bit value and narrowed to int16, so -1 (the "no outer
// try" sentinel) round-tripping correctly is the signal that the width and the
// packed_fields>>1 length decode are both right.
func TestCaptured_ExceptionHandlers(t *testing.T) {
	outDir := runCaptureFixture(t)
	recs := readJSONL(t, filepath.Join(outDir, "exception_handlers.jsonl"))
	if len(recs) == 0 {
		t.Fatal("exception_handlers.jsonl is empty; AOT snapshots do contain " +
			"ExceptionHandlers clusters")
	}
	var handlers, sawNegOuter int
	for _, r := range recs {
		hs, _ := r["handlers"].([]any)
		for _, h := range hs {
			hm, _ := h.(map[string]any)
			handlers++
			pc, _ := hm["pc_offset"].(float64)
			if pc < 0 {
				t.Errorf("negative pc_offset %v", pc)
			}
			if pc > 1<<24 {
				t.Errorf("implausible pc_offset 0x%x -- stream likely misaligned", int64(pc))
			}
			if ot, ok := hm["outer_try_index"].(float64); ok && ot == -1 {
				sawNegOuter++
			}
		}
	}
	if handlers == 0 {
		t.Fatal("no handler entries decoded")
	}
	if sawNegOuter == 0 {
		t.Error("no handler with outer_try_index=-1; the int16 narrowing of the " +
			"tagged read is probably wrong")
	}
}

// TestCaptured_LoadingUnitID guards the bug where the loading-unit id scalar
// was read and then discarded with `_ = v`, making every record report 0.
// The root loading unit has id 1.
func TestCaptured_LoadingUnitID(t *testing.T) {
	outDir := runCaptureFixture(t)
	recs := readJSONL(t, filepath.Join(outDir, "loading_units.jsonl"))
	if len(recs) == 0 {
		t.Skip("no loading units in this sample")
	}
	for _, r := range recs {
		// unit_id is omitempty, so a dropped id shows up as a missing key.
		if _, ok := r["unit_id"]; !ok {
			t.Errorf("loading unit %v has no unit_id: the id scalar is being discarded", r["ref_id"])
		}
	}
}

// TestCaptured_ClosureData checks ClosureData ref order for AOT, where
// context_scope_ is skipped and the refs are parent_function then closure.
func TestCaptured_ClosureData(t *testing.T) {
	outDir := runCaptureFixture(t)
	recs := readJSONL(t, filepath.Join(outDir, "closure_data.jsonl"))
	if len(recs) == 0 {
		t.Fatal("closure_data.jsonl is empty; ClosureData IS serialized in AOT")
	}
	var withParent int
	for _, r := range recs {
		if p, ok := r["parent_function_ref"].(float64); ok && p > 1 {
			withParent++
		}
	}
	if withParent == 0 {
		t.Error("no ClosureData resolved a parent_function_ref; ref 0 may not be " +
			"parent_function (context_scope_ must be skipped for kFullAOT)")
	}
}

// TestCaptured_TypeArguments checks that TypeArguments lengths agree with the
// number of captured type refs -- the cheapest signal that the fill stream is
// aligned through this cluster.
func TestCaptured_TypeArguments(t *testing.T) {
	outDir := runCaptureFixture(t)
	recs := readJSONL(t, filepath.Join(outDir, "type_arguments.jsonl"))
	if len(recs) == 0 {
		t.Fatal("type_arguments.jsonl is empty")
	}
	for _, r := range recs {
		length, _ := r["length"].(float64)
		refs, _ := r["type_refs"].([]any)
		if int(length) != len(refs) {
			t.Fatalf("TypeArguments %v: length=%v but %d type_refs -- misaligned fill",
				r["ref_id"], length, len(refs))
		}
	}
}
