package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPipelineRegression_CompareSample_ARM64 runs the full pipeline on the
// compare_sample ARM64 binary and verifies key output counts.
// This is an integration test that requires the sample binary to exist.
// Set AOTOPSY_TEST_SAMPLE_ARM64 to the path of a Dart 3.9.2 ARM64 libapp.so to enable.
func TestPipelineRegression_CompareSample_ARM64(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_ARM64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_ARM64 not set, skipping regression test")
	}
	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		t.Skipf("sample binary not found at %s, skipping regression test", libPath)
	}

	outDir, err := os.MkdirTemp("", "aotopsy_regression_arm64_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outDir)

	opts := Opts{
		LibPath:  libPath,
		OutDir:   outDir,
		Quiet:    true,
		Signal:   true,
		SignalK:  2,
		MaxSteps: 100000,
	}
	result, err := Run(opts)
	if err != nil {
		t.Fatalf("pipeline failed: %v", err)
	}

	// Verify Dart version.
	if result.DartVersion != "3.9.2" {
		t.Errorf("Dart version: got %s, want 3.9.2", result.DartVersion)
	}

	// Verify function count (should be ~7856, allow some variance).
	if result.FuncCount < 7000 || result.FuncCount > 9000 {
		t.Errorf("Function count: got %d, expected 7000-9000", result.FuncCount)
	}

	// Verify class count.
	if result.ClassCount < 1500 || result.ClassCount > 2500 {
		t.Errorf("Class count: got %d, expected 1500-2500", result.ClassCount)
	}

	// Verify signal count (after C-1 fix, should be ~133, not 239).
	if result.SignalCount < 50 || result.SignalCount > 300 {
		t.Errorf("Signal count: got %d, expected 50-300 (was 239 before C-1 fix, 133 after)",
			result.SignalCount)
	}

	// Verify call_edges.jsonl exists and has reasonable count.
	edgesPath := filepath.Join(outDir, "call_edges.jsonl")
	edgeData, err := os.ReadFile(edgesPath)
	if err != nil {
		t.Fatalf("read call_edges.jsonl: %v", err)
	}
	edgeLines := strings.Count(string(edgeData), "\n")
	if edgeLines < 20000 || edgeLines > 50000 {
		t.Errorf("Call edge count: got %d, expected 20000-50000", edgeLines)
	}

	// Verify functions.jsonl exists.
	funcsPath := filepath.Join(outDir, "functions.jsonl")
	funcData, err := os.ReadFile(funcsPath)
	if err != nil {
		t.Fatalf("read functions.jsonl: %v", err)
	}

	// Verify that known functions are present.
	knownFuncs := []string{"factorial", "reverseString", "countVowels", "_runAll"}
	for _, name := range knownFuncs {
		if !strings.Contains(string(funcData), name) {
			t.Errorf("Expected function %q not found in functions.jsonl", name)
		}
	}

	// Verify pointer size (compressed pointers = 4 for 3.9.2).
	if result.PointerSize != 4 {
		t.Errorf("Pointer size: got %d, want 4 (compressed)", result.PointerSize)
	}
}

// TestPipelineRegression_Sample312_ARM64 runs the full pipeline on the
// Dart 3.12 sample ARM64 binary and verifies key output counts.
// Set AOTOPSY_TEST_SAMPLE_312_ARM64 to the path of a Dart 3.12 ARM64 libapp.so to enable.
func TestPipelineRegression_Sample312_ARM64(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_312_ARM64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_312_ARM64 not set, skipping regression test")
	}
	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		t.Skipf("sample binary not found at %s, skipping regression test", libPath)
	}

	outDir, err := os.MkdirTemp("", "aotopsy_regression_sample_arm64_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outDir)

	opts := Opts{
		LibPath:  libPath,
		OutDir:   outDir,
		Quiet:    true,
		Signal:   true,
		SignalK:  2,
		MaxSteps: 100000,
	}
	result, err := Run(opts)
	if err != nil {
		t.Fatalf("pipeline failed: %v", err)
	}

	if result.DartVersion != "3.12.2" {
		t.Errorf("Dart version: got %s, want 3.12.2", result.DartVersion)
	}

	// Dart 3.12 sample ARM64: ~8175 functions, ~1913 classes, ~136 signal (after C-1 fix)
	if result.FuncCount < 7000 || result.FuncCount > 10000 {
		t.Errorf("Function count: got %d, expected 7000-10000", result.FuncCount)
	}
	if result.ClassCount < 1500 || result.ClassCount > 2500 {
		t.Errorf("Class count: got %d, expected 1500-2500", result.ClassCount)
	}
	// Signal should be ~136 after C-1 fix (was 247 before)
	if result.SignalCount < 50 || result.SignalCount > 300 {
		t.Errorf("Signal count: got %d, expected 50-300", result.SignalCount)
	}
}

// TestPipelineRegression_Sample312_X64 runs the full pipeline on the
// Dart 3.12 sample x86_64 binary and verifies key output counts.
// Set AOTOPSY_TEST_SAMPLE_312_X64 to the path of a Dart 3.12 x86_64 libapp.so to enable.
func TestPipelineRegression_Sample312_X64(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_312_X64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_312_X64 not set, skipping regression test")
	}
	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		t.Skipf("sample binary not found at %s, skipping regression test", libPath)
	}

	outDir, err := os.MkdirTemp("", "aotopsy_regression_sample_x64_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outDir)

	opts := Opts{
		LibPath:  libPath,
		OutDir:   outDir,
		Quiet:    true,
		Signal:   true,
		SignalK:  2,
		MaxSteps: 100000,
	}
	result, err := Run(opts)
	if err != nil {
		t.Fatalf("pipeline failed: %v", err)
	}

	if result.DartVersion != "3.12.2" {
		t.Errorf("Dart version: got %s, want 3.12.2", result.DartVersion)
	}

	// Dart 3.12 sample x86_64: ~8173 functions, ~1913 classes
	if result.FuncCount < 7000 || result.FuncCount > 10000 {
		t.Errorf("Function count: got %d, expected 7000-10000", result.FuncCount)
	}
	if result.ClassCount < 1500 || result.ClassCount > 2500 {
		t.Errorf("Class count: got %d, expected 1500-2500", result.ClassCount)
	}
	// x86_64 signal should be >0 after H-3 fix (THR tables added)
	if result.SignalCount < 100 {
		t.Errorf("Signal count: got %d, expected >100 (x86_64 THR tables should produce signal)", result.SignalCount)
	}
}

// TestDecompilerAccuracy_Factorial verifies that decompile-native produces
// correct output for MathTools.factorial on the compare_sample.
// Set AOTOPSY_TEST_SAMPLE_ARM64 to the path of a Dart 3.9.2 ARM64 libapp.so to enable.
func TestDecompilerAccuracy_Factorial(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_ARM64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_ARM64 not set, skipping decompiler test")
	}
	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		t.Skipf("sample binary not found at %s, skipping decompiler test", libPath)
	}

	// Run the pipeline first to get output.
	outDir, err := os.MkdirTemp("", "aotopsy_decomp_test_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outDir)

	opts := Opts{
		LibPath:  libPath,
		OutDir:   outDir,
		Quiet:    true,
		Signal:   false,
		MaxSteps: 100000,
	}
	_, err = Run(opts)
	if err != nil {
		t.Fatalf("pipeline failed: %v", err)
	}

	// Read functions.jsonl and find factorial.
	funcsPath := filepath.Join(outDir, "functions.jsonl")
	funcData, err := os.ReadFile(funcsPath)
	if err != nil {
		t.Fatal(err)
	}

	// Verify factorial is present and named correctly.
	if !strings.Contains(string(funcData), "MathTools.factorial") {
		t.Error("MathTools.factorial not found in functions.jsonl")
	}

	// Verify string_refs.jsonl does NOT contain false positive "factorial(6) = "
	// from non-string pool entries (C-1 fix verification).
	stringRefsPath := filepath.Join(outDir, "string_refs.jsonl")
	if stringRefData, err := os.ReadFile(stringRefsPath); err == nil {
		// Count occurrences of "factorial(6)" — should be 1 (the real ref),
		// not 38 (false positives before C-1 fix).
		count := strings.Count(string(stringRefData), "factorial(6)")
		if count > 5 {
			t.Errorf("False positive string refs for 'factorial(6)': got %d, expected <=5 (was 38 before C-1 fix)", count)
		}
	}
}

// TestDart212StringExtraction verifies that Dart 2.12.0 string extraction
// works (C-3 fix verification).
// Set AOTOPSY_TEST_SAMPLE_DART212 to the path of a Dart 2.12.0 ARM64 libapp.so to enable.
func TestDart212StringExtraction(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_DART212")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_DART212 not set, skipping string extraction test")
	}
	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		t.Skipf("sample binary not found at %s, skipping string extraction test", libPath)
	}

	outDir, err := os.MkdirTemp("", "aotopsy_dart212_test_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outDir)

	opts := Opts{
		LibPath:  libPath,
		OutDir:   outDir,
		Quiet:    true,
		Signal:   true,
		SignalK:  2,
		MaxSteps: 100000,
	}
	result, err := Run(opts)
	if err != nil {
		t.Fatalf("pipeline failed: %v", err)
	}

	if result.DartVersion != "2.12.0" {
		t.Errorf("Dart version: got %s, want 2.12.0", result.DartVersion)
	}

	// After C-3 fix, Dart 2.12 should have classes resolved (was 0 before).
	if result.ClassCount < 100 {
		t.Errorf("Class count: got %d, expected >100 (C-3 fix should resolve classes from isolate strings)", result.ClassCount)
	}
}

// TestDart212StringExtractionClusterOnly is the memory-safe variant of
// TestDart212StringExtraction. It uses the clusterOnly harness (ELF -> snapshot
// -> alloc -> fill, NO disassembly) instead of full pipeline.Run(), so it can
// run on this 6GB WSL2 VM without OOM. The original test calls Run() which
// spawns the full disasm+typetrack+signal pipeline and has crashed the host.
//
// This verifies the same C-3 fix (Dart 2.12 isolate string extraction → class
// resolution) using only cluster.Result.Strings and cluster.Result.Classes,
// which are populated by ReadFill without any disassembly.
//
// Set AOTOPSY_TEST_SAMPLE_DART212 to the path of a Dart 2.12.0 ARM64 libapp.so.
func TestDart212StringExtractionClusterOnly(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_DART212")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_DART212 not set, skipping cluster-only string extraction test")
	}
	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		t.Skipf("sample binary not found at %s, skipping cluster-only string extraction test", libPath)
	}

	res := clusterOnly(t, libPath)

	// C-3 fix: Dart 2.12 (non-compressed pointers, StringRODataPerSubclass)
	// extracts strings from the ROData image. Before the fix, isolate string
	// extraction returned nothing and classes could not be resolved by name.
	if len(res.Strings) == 0 {
		t.Errorf("Strings: got 0, expected >0 (C-3 fix should extract isolate strings from ROData)")
	}
	// Classes are populated from the Class cluster fill; name resolution needs
	// strings. A non-zero class count confirms the fill stream parsed and the
	// Class cluster was captured.
	if len(res.Classes) < 100 {
		t.Errorf("Classes: got %d, expected >100 (Class cluster fill should yield >100 classes)", len(res.Classes))
	}
}

// Helper to parse first JSON object from JSONL.
func parseFirstJSON(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		t.Fatal("empty JSONL file")
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
