package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cli"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/naming"
	"aotopsy/internal/output"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/thraudit"
)

func TestFridaExportNoLongerAcceptsCrossGenerationDestinations(t *testing.T) {
	for _, args := range [][]string{
		{"--out", filepath.Join(t.TempDir(), "metadata.json")},
		{"--script-out", filepath.Join(t.TempDir(), "hooks.js")},
	} {
		if err := cmdFridaExport(args); err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
			t.Fatalf("retired cross-generation destination flag %q was not rejected: %v", args[0], err)
		}
	}
}

// Every command that takes exactly one libapp.so must reject a second
// positional instead of silently analysing only the first and dropping the
// rest; ghidra already did, ida/run/meta/signal used `< 1`.
func TestSingleLibraryCommandsRejectSurplusPositionals(t *testing.T) {
	cmds := map[string]func([]string) error{
		"run":    cmdRun,
		"meta":   cmdMeta,
		"signal": cmdSignalPipeline,
		"ida":    cmdIDA,
		"ghidra": cmdGhidra,
	}
	for name, fn := range cmds {
		t.Run(name, func(t *testing.T) {
			err := fn([]string{"libapp.so", "surplus.so"})
			if err == nil || !strings.Contains(err.Error(), "usage:") {
				t.Fatalf("surplus positional was not rejected with a usage error: %v", err)
			}
		})
	}
}

func TestFridaExportRejectsSurplusPositionalsBeforeIO(t *testing.T) {
	if err := cmdFridaExport([]string{"surplus"}); err == nil {
		t.Fatal("frida-export accepted surplus positional arguments")
	}
}

func TestBatchFridaOutputCannotCollideWithManagedGenerationArtifacts(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "decompile")
	for _, name := range []string{"combined.dart", analysis.DecompileFailuresFile, output.GenerationMarker} {
		err := validateBatchFridaOutput(outDir, filepath.Join(outDir, name))
		if err == nil || !strings.Contains(err.Error(), "managed batch artifact") {
			t.Fatalf("reserved batch artifact %q was accepted: %v", name, err)
		}
	}
	if err := validateBatchFridaOutput(outDir, outDir); err == nil {
		t.Fatal("output directory itself was accepted as a Frida script path")
	}
	if err := validateBatchFridaOutput(outDir, filepath.Join(filepath.Dir(outDir), "outside.js")); err == nil {
		t.Fatal("cross-generation Frida script path was accepted")
	}
	if err := validateBatchFridaOutput(outDir, filepath.Join(outDir, "hooks", "batch.js")); err != nil {
		t.Fatalf("ordinary in-generation Frida script path was rejected: %v", err)
	}
}

func TestDebugDumpFailurePreservesPreviousGeneration(t *testing.T) {
	root := t.TempDir()
	lib := filepath.Join(root, "broken-libapp.so")
	if err := os.WriteFile(lib, []byte("not-an-elf"), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "dump")
	prior, err := output.BeginDirTransaction(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := output.WriteArtifactFile(prior.StageDir(), "sentinel.txt", []byte("previous generation"), 0o600); err != nil {
		prior.Abort()
		t.Fatal(err)
	}
	if err := prior.Commit(); err != nil {
		prior.Abort()
		t.Fatal(err)
	}

	if err := cmdDump([]string{"--lib", lib, "--out", outDir}); err == nil {
		t.Fatal("invalid ELF unexpectedly produced a dump generation")
	}
	got, err := os.ReadFile(filepath.Join(outDir, "sentinel.txt"))
	if err != nil || string(got) != "previous generation" {
		t.Fatalf("failed dump changed previous generation: %q, %v", got, err)
	}
}

func TestTHRClusterPublishesOneFreshGeneration(t *testing.T) {
	root := t.TempDir()
	inPath := filepath.Join(root, "thr_loads.jsonl")
	record := thraudit.THRAuditRecord{
		Sample:      "sample.so",
		DartVersion: "3.12.2",
		Arch:        thraudit.ArchARM64,
		PC:          "0x1000",
		Insn:        "LDR X16, [X26,#0x100]",
		THROffset:   "0x100",
		Width:       8,
		FuncName:    "f",
		Context:     []string{"> 0x1000: LDR X16, [X26,#0x100]"},
	}
	if _, err := jsonutil.WriteJSONLFile(inPath, []thraudit.THRAuditRecord{record}); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "cluster")
	prior, err := output.BeginDirTransaction(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := output.WriteArtifactFile(prior.StageDir(), "stale.txt", []byte("old"), 0o600); err != nil {
		prior.Abort()
		t.Fatal(err)
	}
	if err := prior.Commit(); err != nil {
		prior.Abort()
		t.Fatal(err)
	}

	if err := cmdTHRCluster([]string{"--in", inPath, "--out", outDir}); err != nil {
		t.Fatalf("cmdTHRCluster: %v", err)
	}
	for _, name := range []string{"bands.json", "bands.md", output.GenerationMarker} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("fresh generation missing %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, "stale.txt")); !os.IsNotExist(err) {
		t.Fatalf("stale THR-cluster artifact survived replacement: %v", err)
	}
}

func TestFindLibappBatchReportsArchiveErrorsAndReplacesGeneration(t *testing.T) {
	inDir := t.TempDir()
	for _, name := range []string{"bad.zip", "bad.apk"} {
		if err := os.WriteFile(filepath.Join(inDir, name), []byte("not a zip"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outDir := filepath.Join(t.TempDir(), "out")
	// Build the prior directory through the real transaction contract so its
	// ownership marker cannot be forged by a test-only sentinel.
	prior, err := output.BeginDirTransaction(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := output.WriteArtifactFile(prior.StageDir(), "stale.json", []byte("stale"), 0o600); err != nil {
		prior.Abort()
		t.Fatal(err)
	}
	if err := prior.Commit(); err != nil {
		prior.Abort()
		t.Fatal(err)
	}
	stale := filepath.Join(outDir, "stale.json")

	err = cmdFindLibappBatch([]string{"--dir", inDir, "--out", outDir})
	if err == nil {
		t.Fatal("corrupt archive was silently accepted by batch command")
	}
	report, readErr := os.ReadFile(filepath.Join(outDir, "no_libapp_report.md"))
	if readErr != nil {
		t.Fatalf("error report was not published: %v", readErr)
	}
	if !strings.Contains(string(report), "| bad.zip | ERROR |") {
		t.Fatalf("batch report omitted corrupt archive: %s", report)
	}
	if !strings.Contains(string(report), "| bad.apk | ERROR |") {
		t.Fatalf("batch report omitted corrupt APK: %s", report)
	}
	if _, statErr := os.Stat(stale); !os.IsNotExist(statErr) {
		t.Fatalf("stale prior-generation artifact survived batch replacement: %v", statErr)
	}
}

// --out pointing at a directory that holds someone else's files must fail
// without deleting them: a directory generation is replaced wholesale.
func TestFindLibappBatchRefusesToReplaceForeignDirectory(t *testing.T) {
	inDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(inDir, "bad.zip"), []byte("not a zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "my-project")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	precious := filepath.Join(outDir, "main.go")
	if err := os.WriteFile(precious, []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := cmdFindLibappBatch([]string{"--dir", inDir, "--out", outDir})
	if err == nil || !strings.Contains(err.Error(), output.GenerationMarker) {
		t.Fatalf("foreign directory was not refused with the marker explanation: %v", err)
	}
	if b, readErr := os.ReadFile(precious); readErr != nil || string(b) != "package main" {
		t.Fatalf("user file was destroyed by --out: %q, %v", b, readErr)
	}
}

func TestFindLibappBatchRejectsOutputContainingInputDirectory(t *testing.T) {
	root := t.TempDir()
	inDir := filepath.Join(root, "archives")
	if err := os.MkdirAll(inDir, 0o755); err != nil {
		t.Fatal(err)
	}
	err := cmdFindLibappBatch([]string{"--dir", inDir, "--out", root})
	if err == nil || !strings.Contains(err.Error(), "must not contain the input archive directory") {
		t.Fatalf("destructive input/output overlap was not rejected: %v", err)
	}
}

func TestArchiveInputBaseAcceptsZipAndAPK(t *testing.T) {
	for _, tc := range []struct {
		name string
		base string
		ok   bool
	}{
		{"sample.zip", "sample", true},
		{"sample.APK", "sample", true},
		{"sample.so", "", false},
	} {
		base, ok := archiveInputBase(tc.name)
		if base != tc.base || ok != tc.ok {
			t.Fatalf("archiveInputBase(%q)=(%q,%v), want (%q,%v)", tc.name, base, ok, tc.base, tc.ok)
		}
	}
}

func TestInventoryRejectsOutputAliasingInputArchive(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "sample.zip")
	const original = "archive-must-survive"
	if err := os.WriteFile(archive, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdInventory([]string{"--dir", dir, "--out", archive}); err == nil {
		t.Fatal("inventory accepted output aliasing a consumed archive")
	}
	got, err := os.ReadFile(archive)
	if err != nil || string(got) != original {
		t.Fatalf("rejected inventory output changed input archive: %q, %v", got, err)
	}
}

func TestInventoryReportsCleanAbsenceSeparatelyFromCorruptArchive(t *testing.T) {
	dir := t.TempDir()
	emptyPath := filepath.Join(dir, "empty.zip")
	f, err := os.Create(emptyPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	if err := zw.Close(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.zip"), []byte("not a zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "inventory.jsonl")
	err = cmdInventory([]string{"--dir", dir, "--out", out})
	if err == nil || !strings.Contains(err.Error(), "1 archive error") {
		t.Fatalf("inventory error = %v, want exactly one corrupt-archive error", err)
	}
	data, readErr := os.ReadFile(out)
	if readErr != nil {
		t.Fatal(readErr)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("inventory rows = %d, want 2: %s", len(lines), data)
	}
	byID := map[string]string{}
	for _, line := range lines {
		if strings.Contains(line, `"sample_id":"empty"`) {
			byID["empty"] = line
		}
		if strings.Contains(line, `"sample_id":"broken"`) {
			byID["broken"] = line
		}
	}
	if strings.Contains(byID["empty"], `"error"`) || !strings.Contains(byID["empty"], `"declared_libapp":false`) {
		t.Fatalf("clean no-libapp row misclassified: %s", byID["empty"])
	}
	if !strings.Contains(byID["broken"], `"error":"open zip:`) {
		t.Fatalf("corrupt archive row lost its error: %s", byID["broken"])
	}
}

func TestSignalSummaryOnlyAdvertisesPublishedArtifactsAndSupportedDecompiler(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "signal.html"), []byte("html"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	writeSignalSummary(&out, &analysis.SignalResult{SignalCount: 1}, dir, "/tmp/libapp.so", "x64")
	got := out.String()
	for _, forbidden := range []string{"signal.svg", "signal_cfg.dot", "aotopsy ghidra", "aotopsy ida"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("x64 summary advertised unavailable %q: %s", forbidden, got)
		}
	}
	if !strings.Contains(got, "signal.html") || !strings.Contains(got, "decompile-native") {
		t.Fatalf("x64 summary omitted published/supported next step: %s", got)
	}

	for _, name := range []string{"signal.svg", "signal_cfg.dot"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("artifact"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out.Reset()
	writeSignalSummary(&out, &analysis.SignalResult{SignalCount: 1}, dir, "/tmp/libapp.so", "arm64")
	got = out.String()
	for _, required := range []string{"signal.html", "signal.svg", "signal_cfg.dot", "aotopsy ghidra", "aotopsy ida"} {
		if !strings.Contains(got, required) {
			t.Fatalf("arm64 summary omitted available %q: %s", required, got)
		}
	}
}

func TestRunSummaryDoesNotRecommendARM64OnlyToolsForX64(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "signal.html"), []byte("html"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	writeSummary(&out, &analysis.Result{OutDir: dir, LibPath: "/tmp/libapp.so", Arch: "x64"})
	got := out.String()
	if strings.Contains(got, "aotopsy ghidra") || strings.Contains(got, "aotopsy ida") {
		t.Fatalf("x64 run summary advertised ARM64-only tool: %s", got)
	}
	if !strings.Contains(got, "decompile-native") {
		t.Fatalf("x64 run summary omitted supported native decompiler: %s", got)
	}
}

func TestSummaryUsesDestinationWriterModeAndSanitizesDynamicText(t *testing.T) {
	// A generic non-terminal destination decides its own color capability and
	// must receive plain text even if dynamic values contain terminal controls.
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")

	var out bytes.Buffer
	writeSummary(&out, &analysis.Result{
		OutDir:      "unsafe\nFORGED\x1b[2J",
		LibPath:     "lib\tapp.so\x1b]0;title\a",
		Arch:        "x64",
		DartVersion: "3.12.2\u202eabc",
	})
	got := out.String()
	if strings.Contains(got, "\x1b[") || strings.Contains(got, "\x1b]") {
		t.Fatalf("non-terminal summary received ANSI/control sequence: %q", got)
	}
	if strings.Contains(got, "\nFORGED") || strings.Contains(got, "\u202e") {
		t.Fatalf("summary allowed dynamic text to spoof terminal layout: %q", got)
	}
}

func TestDotDiagnosticsAreSanitizedBeforeTerminalOutput(t *testing.T) {
	var out bytes.Buffer
	logger := cli.NewLogger(&out, false)
	warnDotFailure(logger,
		"CFG\u202eforged",
		errors.New("failed\nFORGED"),
		"\x1b[2Jstderr\nMORE\u202e",
		"")
	got := out.String()
	if strings.Count(got, "\n") != 1 || strings.Contains(got, "\x1b[") || strings.ContainsRune(got, '\u202e') || strings.Contains(got, "\nFORGED") {
		t.Fatalf("Graphviz diagnostic escaped terminal sanitizer: %q", got)
	}
	if !strings.Contains(got, "CFGforged") || !strings.Contains(got, "failed FORGED") || !strings.Contains(got, "stderr MORE") {
		t.Fatalf("Graphviz diagnostic lost printable content: %q", got)
	}
}

func TestDoctorRejectsUnresolvedSnapshotVersion(t *testing.T) {
	if _, err := doctorVersionProfile(&snapshot.Info{}); err == nil {
		t.Fatal("doctor accepted snapshot without a resolved Dart version/profile")
	}
	p := &snapshot.VersionProfile{DartVersion: "3.9.2", Supported: true}
	got, err := doctorVersionProfile(&snapshot.Info{Version: p})
	if err != nil || got != p {
		t.Fatalf("doctor rejected resolved version: got=%v err=%v", got, err)
	}
}

func TestObjectPoolByteOffsetUsesArchitectureTagging(t *testing.T) {
	if got := objectPoolByteOffset(0, true); got != 16 {
		t.Fatalf("ARM64 pool[0] offset=%d, want 16", got)
	}
	if got := objectPoolByteOffset(0, false); got != 15 {
		t.Fatalf("x64 pool[0] offset=%d, want 15", got)
	}
	if got := objectPoolByteOffset(3, false); got != 39 {
		t.Fatalf("x64 pool[3] offset=%d, want 39", got)
	}
}

func TestProvenPoolStringRefRejectsNumericVMCollision(t *testing.T) {
	ct := &snapshot.CIDTable{Class: 100, OneByteString: 200, TwoByteString: 201, String: 202}
	pl := &naming.PoolLookups{
		CT:           ct,
		BaseObjLimit: 64,
		RefCID:       map[int]int{},
		VmRefCID:     map[int]int{7: 100, 8: 200},
	}
	if provenPoolStringRef(pl, 7) {
		t.Fatal("non-string VM base object was accepted as string solely by numeric RefID")
	}
	if !provenPoolStringRef(pl, 8) {
		t.Fatal("CID-proven VM string was rejected")
	}
	pl.RefCID[8] = 100
	if provenPoolStringRef(pl, 8) {
		t.Fatal("app-isolate non-string CID did not override colliding VM string RefID")
	}
}

func TestSDKCheckFindsSourceTreeOutsideRepoCWD(t *testing.T) {
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	}()
	root, err := sdkCheckSourceRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "tools", "extract_thr.go")); err != nil {
		t.Fatalf("resolved root lacks SDK tool: %s: %v", root, err)
	}
}

func TestExportDartRejectsOutputContainingSourceBeforeELFParse(t *testing.T) {
	outDir := t.TempDir()
	lib := filepath.Join(outDir, "libapp.so")
	const original = "must survive"
	if err := os.WriteFile(lib, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdExportDart([]string{"--lib", lib, "--out", outDir}); err == nil {
		t.Fatal("export-dart accepted an output directory containing its source binary")
	}
	b, err := os.ReadFile(lib)
	if err != nil || string(b) != original {
		t.Fatalf("source changed after rejected export destination: %q, %v", b, err)
	}
}

func TestDebugSnapshotSelectorsRejectUnknownValueBeforeIO(t *testing.T) {
	for name, fn := range map[string]func([]string) error{
		"clusters": cmdClusters,
		"strings":  cmdStrings,
	} {
		t.Run(name, func(t *testing.T) {
			err := fn([]string{"--lib", filepath.Join(t.TempDir(), "missing.so"), "--which", "typo"})
			if err == nil || !strings.Contains(err.Error(), "--which") || !strings.Contains(err.Error(), "typo") {
				t.Fatalf("invalid selector was not rejected before I/O: %v", err)
			}
		})
	}
}
