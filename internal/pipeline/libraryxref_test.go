package pipeline

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLibraryFunctionsXref verifies the library -> functions xref against the
// actual Dart source of compare_sample, which declares:
//
//	main.dart:         CompareApp, MathTools, StringTools, AntiInlineTools,
//	                   Processor, AddProcessor, MulProcessor, CompareHomePage,
//	                   _CompareHomePageState                        (9 classes)
//	ground_truth.dart: Shape, Circle, Square, Triangle, ConfigData  (5 classes)
//
// IMPORTANT — pick the right binary. compare_sample/build contains FIVE
// libapp.so files with five different hashes, and the two under
// build/app/outputs/flutter-apk/extracted_*/ are built from an OLDER revision
// of lib/*.dart: they contain no AntiInlineTools, no safeDivide and no
// ground_truth.dart at all. Point AOTOPSY_TEST_SAMPLE_ARM64 at
// build/app/intermediates/merged_native_libs/... (or jniLibs/...) instead, or
// this test will fail for a reason that has nothing to do with the code.
func TestLibraryFunctionsXref(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_ARM64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_ARM64 not set")
	}
	outDir := t.TempDir()
	if _, err := Run(Opts{LibPath: libPath, OutDir: outDir, Quiet: true, MaxSteps: 100000}); err != nil {
		t.Fatalf("pipeline failed: %v", err)
	}
	recs := readJSONL(t, filepath.Join(outDir, "library_functions.jsonl"))
	if len(recs) < 50 {
		t.Fatalf("library_functions.jsonl: %d records, want >=50 (a Flutter app "+
			"bundles hundreds of libraries)", len(recs))
	}

	byURL := map[string]map[string]any{}
	var framework, app int
	for _, r := range recs {
		url, _ := r["url"].(string)
		byURL[url] = r
		if fw, _ := r["is_framework"].(bool); fw {
			framework++
		} else if url != "" {
			app++
		}
	}
	if framework == 0 {
		t.Error("no library flagged is_framework; dart:* and package:flutter* must be")
	}
	if app == 0 {
		t.Error("every library flagged as framework; app/third-party code must not be")
	}

	main, ok := byURL["package:compare_sample/main.dart"]
	if !ok {
		t.Fatalf("package:compare_sample/main.dart missing. If this sample's "+
			"libapp.so is the stale extracted_* one, see this test's doc comment. "+
			"Sample: %s", libPath)
	}
	// Class count must match the source exactly: the AOT compiler drops unused
	// classes, but every class here is reachable from _runAll.
	if cc, _ := main["class_count"].(float64); int(cc) != 9 {
		t.Errorf("main.dart class_count = %v, want 9 (source declares 9)", cc)
	}

	classes := map[string]bool{}
	if cs, ok := main["classes"].([]any); ok {
		for _, c := range cs {
			s, _ := c.(string)
			classes[s] = true
		}
	}
	for _, want := range []string{"CompareApp", "MathTools", "StringTools",
		"AntiInlineTools", "Processor", "AddProcessor", "MulProcessor", "CompareHomePage"} {
		if !classes[want] {
			t.Errorf("main.dart is missing class %q", want)
		}
	}

	funcs := map[string]bool{}
	if fs, ok := main["functions"].([]any); ok {
		for _, f := range fs {
			s, _ := f.(string)
			funcs[s] = true
		}
	}
	// Owner-qualified names, and specifically ones that survive inlining.
	// AntiInlineTools.safeDivide survives because its try/catch blocks
	// inlining -- the same reason it is a useful try/catch fixture.
	for _, want := range []string{
		"MathTools.factorial", "MathTools.isPrime", "MathTools.fibonacci",
		"StringTools.reverseString", "StringTools.countVowels",
		"AntiInlineTools.safeDivide", "AntiInlineTools.processItems",
		"AddProcessor.process", "MulProcessor.process",
		"CompareApp.build", "CompareHomePage.createState",
	} {
		if !funcs[want] {
			t.Errorf("main.dart is missing function %q", want)
		}
	}
	// MathTools.classify and AntiInlineTools.dayName are deliberately NOT
	// asserted: main.dart carries no @pragma('vm:never-inline'), and both are
	// small pure functions returning constants, so the AOT compiler inlines
	// them and no Function object survives. Asserting their presence would
	// encode a compiler decision we do not control.

	if gt, ok := byURL["package:compare_sample/ground_truth.dart"]; ok {
		if cc, _ := gt["class_count"].(float64); int(cc) != 5 {
			t.Errorf("ground_truth.dart class_count = %v, want 5", cc)
		}
	} else {
		t.Error("package:compare_sample/ground_truth.dart missing (stale binary?)")
	}
}

// TestLibraryResolverPatchClassHop checks that library resolution hops through a
// PatchClass owner. Dart wraps patched/mixin-applied classes in a PatchClass
// (CID 6), and a Function's owner frequently points at that wrapper rather than
// the real Class; without the hop, every such function loses its library.
func TestLibraryResolverPatchClassHop(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_ARM64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_ARM64 not set")
	}
	outDir := t.TempDir()
	if _, err := Run(Opts{LibPath: libPath, OutDir: outDir, Quiet: true, MaxSteps: 100000}); err != nil {
		t.Fatalf("pipeline failed: %v", err)
	}
	recs := readJSONL(t, filepath.Join(outDir, "library_functions.jsonl"))

	var total, unresolved int
	for _, r := range recs {
		fc, _ := r["func_count"].(float64)
		total += int(fc)
		if url, _ := r["url"].(string); url == "" {
			unresolved = int(fc)
		}
	}
	if total == 0 {
		t.Fatal("no functions grouped at all")
	}
	// dart:core and friends are patched libraries, so a broken PatchClass hop
	// shows up as a large unresolved bucket. Allow some slack for genuinely
	// owner-less functions (top-level closures in unusual positions).
	if ratio := float64(unresolved) / float64(total); ratio > 0.35 {
		t.Errorf("%.0f%% of functions (%d/%d) have no library; PatchClass hop or "+
			"Library.url resolution is likely broken", ratio*100, unresolved, total)
	}
	t.Logf("grouped %d functions across %d libraries, %d unresolved", total, len(recs), unresolved)
}
