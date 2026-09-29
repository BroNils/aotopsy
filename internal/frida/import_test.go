package frida

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"aotopsy/internal/cli"
	"aotopsy/internal/disasm"
	"aotopsy/internal/evidence"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/output"
)

func writeStaticImportFixture(t *testing.T, dir string, edges []disasm.CallEdgeRecord, funcs []disasm.FuncRecord) FridaBinding {
	t.Helper()
	if _, err := jsonutil.WriteJSONLFile(filepath.Join(dir, "call_edges.jsonl"), edges); err != nil {
		t.Fatal(err)
	}
	if _, err := jsonutil.WriteJSONLFile(filepath.Join(dir, "functions.jsonl"), funcs); err != nil {
		t.Fatal(err)
	}
	p := staticProvenance{
		Source:      filepath.Join(dir, "libapp.so"),
		SourceName:  "libapp.so",
		SHA256:      testSourceSHA256,
		Size:        1234,
		Arch:        "x64",
		DartVersion: "3.12.2",
		Build:       json.RawMessage(`{}`),
	}
	if err := output.WriteJSONFile(filepath.Join(dir, "provenance.json"), p); err != nil {
		t.Fatal(err)
	}
	artifacts := make([]ArtifactDigest, 0, len(generationArtifactNames))
	for i, name := range generationArtifactNames {
		path := filepath.Join(dir, name)
		b, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) && i >= 3 {
				artifacts = append(artifacts, DigestArtifact(name, nil, false))
				continue
			}
			t.Fatal(err)
		}
		artifacts = append(artifacts, DigestArtifact(name, b, true))
	}
	allFunctions := make([]FridaFunction, 0, len(funcs))
	for _, f := range funcs {
		allFunctions = append(allFunctions, FridaFunction{VA: f.PC, Name: f.Name, Owner: f.Owner, Size: f.Size})
	}
	allProbes := make([]FridaUnresolvedBLR, 0, len(edges))
	for _, e := range edges {
		probe, ok := RuntimeProbeForEdge(e)
		if !ok {
			continue
		}
		if probe.Via == "dispatch_table" {
			probe.ClassIDReg = DispatchClassIDRegister(p.Arch, p.DartVersion)
		}
		allProbes = append(allProbes, probe)
	}
	binding := FridaBinding{
		SchemaVersion:   BindingSchemaVersion,
		MetadataSchema:  MetadataSchemaVersion,
		AnalyzerVersion: cli.Version,
		AnalyzerCommit:  cli.Commit,
		SourceSHA256:    p.SHA256,
		SourceSize:      p.Size,
		ModuleName:      p.SourceName,
		DartVersion:     p.DartVersion,
		Architecture:    p.Arch,
		RuntimeIdentity: []RuntimeRegionDigest{{
			Kind: "executable", Offset: "0x0", Size: 4,
			SHA256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		}},
		Artifacts:          artifacts,
		InstalledFunctions: installedFunctions(allFunctions),
		InstalledBLRs:      installedBLRs(allProbes),
	}
	generationID, err := ComputeGenerationID(binding)
	if err != nil {
		t.Fatal(err)
	}
	binding.GenerationID = generationID
	if err := output.WriteJSONFile(filepath.Join(dir, BindingFileName), binding); err != nil {
		t.Fatal(err)
	}
	return binding
}

func writeRuntimeLog(t *testing.T, binding FridaBinding, events []runtimeEvent) string {
	t.Helper()
	var log strings.Builder
	log.WriteString("Frida banner/noise before events\n")
	for _, ev := range events {
		if ev.SchemaVersion == 0 {
			ev.SchemaVersion = MetadataSchemaVersion
		}
		if ev.GenerationID == "" {
			ev.GenerationID = binding.GenerationID
		}
		if ev.SourceSHA256 == "" {
			ev.SourceSHA256 = binding.SourceSHA256
		}
		if ev.SourceSize == 0 {
			ev.SourceSize = binding.SourceSize
		}
		if ev.Architecture == "" {
			ev.Architecture = binding.Architecture
		}
		b, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		log.WriteString("[device]-> ")
		log.WriteString(runtimeEventPrefix)
		log.Write(b)
		log.WriteByte('\n')
	}
	p := filepath.Join(t.TempDir(), "frida.log")
	if err := os.WriteFile(p, []byte(log.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFridaImportEventLogMergesOmittedTargetsAndPolymorphism(t *testing.T) {
	staticDir := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "merged")
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "F", FromPC: "0x100", Kind: "blr", Reg: "X16", Via: "dispatch_table"},
		{FromFunc: "G", FromPC: "0x200", Kind: "call_indirect", Reg: "RAX"},
		{FromFunc: "H", FromPC: "0x300", Kind: "bl", Target: "Known"},
	}
	staticEvidence := []evidence.Evidence{{
		PC: "0x100", Function: "F", Kind: "call", Confidence: evidence.ConfUnknown,
		Result: map[string]any{"resolved": false},
	}}
	if _, err := jsonutil.WriteJSONLFile(filepath.Join(staticDir, "evidence.jsonl"), staticEvidence); err != nil {
		t.Fatal(err)
	}
	binding := writeStaticImportFixture(t, staticDir, edges, []disasm.FuncRecord{
		{PC: "0x10", Size: 4, Name: "F"},
		{PC: "0x20", Size: 4, Name: "G"},
		{PC: "0x30", Size: 4, Name: "H"},
		{PC: "0x40", Size: 4, Name: "Known"},
		{PC: "0xaaa", Size: 4, Name: "A"},
		{PC: "0xbbb", Size: 4, Name: "B"},
	})

	events := []runtimeEvent{
		{Type: "function_enter", Name: "F", FunctionVA: "0x10"},
		{Type: "function_enter", Name: "F", FunctionVA: "0x10"},
		{Type: "function_enter", Name: "H", FunctionVA: "0x30"},
		{Type: "function_enter", Name: "Known", FunctionVA: "0x40"},
		{SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "dispatch", BLRAddr: "0x100", FromFunc: "F", TargetName: "A", TargetVA: "0xaaa", TargetModule: "libapp.so", ClassID: 10},
		{SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "dispatch", BLRAddr: "0x100", FromFunc: "F", TargetName: "B", TargetVA: "0xbbb", TargetModule: "libapp.so", ClassID: 11},
		{SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "dispatch", BLRAddr: "0x100", FromFunc: "F", TargetName: "A", TargetVA: "0xaaa", TargetModule: "libapp.so", ClassID: 10},
		{SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "dispatch", BLRAddr: "0x200", FromFunc: "G", TargetVA: "libother.so+0x44", TargetModule: "libother.so", ClassID: -1},
	}
	logPath := writeRuntimeLog(t, binding, events)

	if err := CmdFridaImport([]string{"--in", logPath, "--static", staticDir, "--out", outDir}); err != nil {
		t.Fatalf("CmdFridaImport: %v", err)
	}
	got, err := readStaticCallEdges(filepath.Join(outDir, "call_edges.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("merged edges = %d, want 3", len(got))
	}
	first := got[0]
	if first.Target != "" || !reflect.DeepEqual(first.Targets, []string{"A", "B"}) || first.Candidates != 2 {
		t.Fatalf("polymorphic target merge = %+v", first)
	}
	if !first.RuntimeResolved || !reflect.DeepEqual(first.RuntimeTargets, []string{"A", "B"}) ||
		!reflect.DeepEqual(first.RuntimeClassIDs, []int{10, 11}) || first.RuntimeObservations != 3 {
		t.Fatalf("runtime aggregate = %+v", first)
	}
	if !first.RuntimeConfirmed || first.RuntimeCallCount != 3 {
		t.Fatalf("runtime source count = %+v", first)
	}
	second := got[1]
	if second.Target != "libother.so+0x44" || !second.RuntimeResolved {
		t.Fatalf("x86 call_indirect merge = %+v", second)
	}
	if got[2].Target != "Known" || got[2].RuntimeResolved || got[2].RuntimeConfirmed || got[2].RuntimeTargetConfirmed {
		t.Fatalf("function entry incorrectly confirmed an unobserved direct callsite: %+v", got[2])
	}

	mergedEvidence, err := jsonutil.ReadJSONL[evidence.Evidence](filepath.Join(outDir, "evidence.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(mergedEvidence) != 1 || mergedEvidence[0].Confidence != evidence.ConfRuntimeConfirmed {
		t.Fatalf("runtime evidence was not merged: %+v", mergedEvidence)
	}
	runtimeTargets, ok := mergedEvidence[0].Result["runtime_targets"].([]any)
	if !ok || len(runtimeTargets) != 2 || runtimeTargets[0] != "A" || runtimeTargets[1] != "B" {
		t.Fatalf("merged runtime targets = %#v", mergedEvidence[0].Result["runtime_targets"])
	}

	coverageBytes, err := os.ReadFile(filepath.Join(outDir, "runtime_coverage.json"))
	if err != nil {
		t.Fatal(err)
	}
	var coverage evidence.CoverageReport
	if err := json.Unmarshal(coverageBytes, &coverage); err != nil {
		t.Fatal(err)
	}
	if coverage.RuntimeConfirmed != 1 || coverage.BothConflict != 0 {
		t.Fatalf("runtime coverage = %+v", coverage)
	}
	prov, err := readStaticProvenance(filepath.Join(outDir, "provenance.json"))
	if err != nil || prov.SHA256 != testSourceSHA256 {
		t.Fatalf("merged generation lost provenance: %+v, %v", prov, err)
	}
	if _, err := os.Stat(filepath.Join(outDir, BindingFileName)); !os.IsNotExist(err) {
		t.Fatalf("merged output retained stale Frida generation binding, stat err=%v", err)
	}
}

func TestRuntimeEventLogRejectsWrongOrMalformedWireFormat(t *testing.T) {
	binding := FridaBinding{
		GenerationID: strings.Repeat("c", 64), SourceSHA256: testSourceSHA256,
		SourceSize: 1234, Architecture: "x64",
	}
	p := filepath.Join(t.TempDir(), "bad.log")
	if err := os.WriteFile(p, []byte("{\"dispatch_resolutions\":[]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRuntimeEventLog(p, binding); err == nil {
		t.Fatal("legacy/disconnected aggregate JSON was accepted without any AOTOPSY_EVENT records")
	}
	raw := runtimeEventPrefix + `{"schema_version":2,"generation_id":"` + binding.GenerationID + `","source_sha256":"` + testSourceSHA256 + `","source_size":1234,"architecture":"x64","type":"dispatch","unexpected":1}` + "\n"
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRuntimeEventLog(p, binding); err == nil {
		t.Fatal("unknown runtime-event field was silently accepted")
	}
}

func TestFridaImportRejectsRuntimeIdentityAndSitePoisoning(t *testing.T) {
	staticDir := t.TempDir()
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "F", FromPC: "0x100", Kind: "blr", Reg: "X16", Via: "dispatch_table"},
		{FromFunc: "G", FromPC: "0x200", Kind: "call_indirect", Reg: "RAX"},
	}
	binding := writeStaticImportFixture(t, staticDir, edges, []disasm.FuncRecord{
		{PC: "0x10", Size: 4, Name: "F"},
		{PC: "0x20", Size: 4, Name: "G"},
	})

	tests := []struct {
		name string
		ev   runtimeEvent
	}{
		{
			name: "wrong source",
			ev: runtimeEvent{SchemaVersion: MetadataSchemaVersion, SourceSHA256: strings.Repeat("b", 64), Type: "dispatch",
				BLRAddr: "0x100", FromFunc: "F", TargetName: "Target", ClassID: 10},
		},
		{
			name: "unknown site",
			ev: runtimeEvent{SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "dispatch",
				BLRAddr: "0x999", FromFunc: "F", TargetName: "Target", ClassID: 10},
		},
		{
			name: "wrong function",
			ev: runtimeEvent{SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "dispatch",
				BLRAddr: "0x100", FromFunc: "G", TargetName: "Target", ClassID: 10},
		},
		{
			name: "class id on non dispatch",
			ev: runtimeEvent{SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "dispatch",
				BLRAddr: "0x200", FromFunc: "G", TargetName: "Target", ClassID: 77},
		},
		{
			name: "unknown function enter",
			ev: runtimeEvent{SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "function_enter",
				Name: "NotInStaticGeneration", FunctionVA: "0x10"},
		},
		{
			name: "wrong generation",
			ev: runtimeEvent{GenerationID: strings.Repeat("d", 64), Type: "dispatch",
				BLRAddr: "0x100", FromFunc: "F", TargetVA: "0x10", TargetModule: "libapp.so"},
		},
		{
			name: "wrong runtime size",
			ev: runtimeEvent{SourceSize: 9999, Type: "dispatch",
				BLRAddr: "0x100", FromFunc: "F", TargetVA: "0x10", TargetModule: "libapp.so"},
		},
		{
			name: "wrong runtime architecture",
			ev: runtimeEvent{Architecture: "arm64", Type: "dispatch",
				BLRAddr: "0x100", FromFunc: "F", TargetVA: "0x10", TargetModule: "libapp.so"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logPath := writeRuntimeLog(t, binding, []runtimeEvent{tt.ev})
			outDir := filepath.Join(t.TempDir(), "merged")
			if err := CmdFridaImport([]string{"--in", logPath, "--static", staticDir, "--out", outDir}); err == nil {
				t.Fatal("poisoned runtime evidence was accepted")
			}
			if _, err := os.Stat(outDir); !os.IsNotExist(err) {
				t.Fatalf("failed import published output directory, stat err=%v", err)
			}
		})
	}
}

func TestFridaImportRejectsUnexportedSitesAndTargetIdentityPoisoning(t *testing.T) {
	staticDir := t.TempDir()
	edges := []disasm.CallEdgeRecord{
		{FromFunc: "F", FromPC: "0x100", Kind: "blr", Reg: "X16", Via: "dispatch_table"},
		{FromFunc: "Resolved", FromPC: "0x200", Kind: "blr", Reg: "X17", Target: "Known"},
		{FromFunc: "Unsupported", FromPC: "0x300", Kind: "blr", Reg: "X18", Via: "future_recipe"},
	}
	binding := writeStaticImportFixture(t, staticDir, edges, []disasm.FuncRecord{
		{PC: "0x10", Size: 4, Name: "F"},
		{PC: "0x20", Size: 4, Name: "Resolved"},
		{PC: "0x30", Size: 4, Name: "Unsupported"},
		{PC: "0x400", Size: 4, Name: "Known"},
	})

	tests := []struct {
		name string
		ev   runtimeEvent
	}{
		{
			name: "resolved static edge was never exported",
			ev: runtimeEvent{SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "dispatch",
				BLRAddr: "0x200", FromFunc: "Resolved", TargetVA: "0x400", TargetName: "Known", TargetModule: "libapp.so"},
		},
		{
			name: "unsupported provenance was never exported",
			ev: runtimeEvent{SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "dispatch",
				BLRAddr: "0x300", FromFunc: "Unsupported", TargetVA: "0x400", TargetName: "Known", TargetModule: "libapp.so"},
		},
		{
			name: "own module name does not match target pc",
			ev: runtimeEvent{SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "dispatch",
				BLRAddr: "0x100", FromFunc: "F", TargetVA: "0x10", TargetName: "Known", TargetModule: "libapp.so", ClassID: 7},
		},
		{
			name: "unknown own module name",
			ev: runtimeEvent{SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "dispatch",
				BLRAddr: "0x100", FromFunc: "F", TargetVA: "0x400", TargetName: "Spoofed", TargetModule: "libapp.so", ClassID: 7},
		},
		{
			name: "external module target does not match module",
			ev: runtimeEvent{SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "dispatch",
				BLRAddr: "0x100", FromFunc: "F", TargetVA: "other.so+0x44", TargetModule: "evil.so", ClassID: 7},
		},
		{
			name: "ownerless absolute runtime target",
			ev: runtimeEvent{SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "dispatch",
				BLRAddr: "0x100", FromFunc: "F", TargetVA: "0x7fff12345678", ClassID: -1},
		},
		{
			name: "invalid negative class id",
			ev: runtimeEvent{SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "dispatch",
				BLRAddr: "0x100", FromFunc: "F", TargetVA: "0x400", TargetModule: "libapp.so", ClassID: -2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logPath := writeRuntimeLog(t, binding, []runtimeEvent{tt.ev})
			outDir := filepath.Join(t.TempDir(), "merged")
			if err := CmdFridaImport([]string{"--in", logPath, "--static", staticDir, "--out", outDir}); err == nil {
				t.Fatal("poisoned or non-exportable runtime site was accepted")
			}
		})
	}
}

func TestFridaImportRejectsEligibleButUninstalledSites(t *testing.T) {
	t.Run("probe beyond cap", func(t *testing.T) {
		staticDir := t.TempDir()
		edges := make([]disasm.CallEdgeRecord, 0, maxInstalledBLRs+1)
		for i := 0; i < maxInstalledBLRs+1; i++ {
			edges = append(edges, disasm.CallEdgeRecord{
				FromFunc: "F", FromPC: fmt.Sprintf("0x%x", 0x1000+i), Kind: "call_indirect", Reg: "RAX",
			})
		}
		binding := writeStaticImportFixture(t, staticDir, edges, []disasm.FuncRecord{{PC: "0x10", Size: 4, Name: "F"}})
		uninstalled := edges[maxInstalledBLRs].FromPC
		logPath := writeRuntimeLog(t, binding, []runtimeEvent{{
			Type: "dispatch", BLRAddr: uninstalled, FromFunc: "F",
			TargetVA: "libother.so+0x44", TargetModule: "libother.so", ClassID: -1,
		}})
		outDir := filepath.Join(t.TempDir(), "merged")
		if err := CmdFridaImport([]string{"--in", logPath, "--static", staticDir, "--out", outDir}); err == nil {
			t.Fatal("runtime event for an eligible but uninstalled probe was accepted")
		}
	})

	t.Run("function beyond cap", func(t *testing.T) {
		staticDir := t.TempDir()
		funcs := make([]disasm.FuncRecord, 0, maxInstalledFunctions+1)
		for i := 0; i < maxInstalledFunctions+1; i++ {
			funcs = append(funcs, disasm.FuncRecord{PC: fmt.Sprintf("0x%x", 0x2000+i), Size: 4, Name: fmt.Sprintf("F%d", i)})
		}
		binding := writeStaticImportFixture(t, staticDir, nil, funcs)
		uninstalled := funcs[maxInstalledFunctions]
		logPath := writeRuntimeLog(t, binding, []runtimeEvent{{
			Type: "function_enter", Name: uninstalled.Name, FunctionVA: uninstalled.PC,
		}})
		outDir := filepath.Join(t.TempDir(), "merged")
		if err := CmdFridaImport([]string{"--in", logPath, "--static", staticDir, "--out", outDir}); err == nil {
			t.Fatal("runtime event for an eligible but uninstalled function hook was accepted")
		}
	})
}

func TestFridaImportRejectsStaticGenerationDrift(t *testing.T) {
	staticDir := t.TempDir()
	edges := []disasm.CallEdgeRecord{{FromFunc: "F", FromPC: "0x100", Kind: "call_indirect", Reg: "RAX"}}
	binding := writeStaticImportFixture(t, staticDir, edges, []disasm.FuncRecord{{PC: "0x10", Size: 4, Name: "F"}})
	logPath := writeRuntimeLog(t, binding, []runtimeEvent{{
		Type: "dispatch", BLRAddr: "0x100", FromFunc: "F",
		TargetVA: "libother.so+0x44", TargetModule: "libother.so", ClassID: -1,
	}})

	edges = append(edges, disasm.CallEdgeRecord{FromFunc: "F", FromPC: "0x200", Kind: "call_indirect", Reg: "RAX"})
	if _, err := jsonutil.WriteJSONLFile(filepath.Join(staticDir, "call_edges.jsonl"), edges); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "merged")
	if err := CmdFridaImport([]string{"--in", logPath, "--static", staticDir, "--out", outDir}); err == nil {
		t.Fatal("mixed static generation was accepted after a bound artifact changed")
	}
	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Fatalf("failed mixed-generation import published output, stat err=%v", err)
	}
}

func TestFridaImportRejectsInputInsideOutputWithoutDeletingIt(t *testing.T) {
	staticDir := t.TempDir()
	binding := writeStaticImportFixture(t, staticDir,
		[]disasm.CallEdgeRecord{{FromFunc: "F", FromPC: "0x100", Kind: "call_indirect", Reg: "RAX"}},
		[]disasm.FuncRecord{{PC: "0x10", Size: 4, Name: "F"}},
	)
	sourceLog := writeRuntimeLog(t, binding, []runtimeEvent{{
		Type: "dispatch", BLRAddr: "0x100", FromFunc: "F",
		TargetVA: "libother.so+0x44", TargetModule: "libother.so", ClassID: -1,
	}})
	logBytes, err := os.ReadFile(sourceLog)
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "merged")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	inPath := filepath.Join(outDir, "runtime.log")
	if err := os.WriteFile(inPath, logBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CmdFridaImport([]string{"--in", inPath, "--static", staticDir, "--out", outDir}); err == nil {
		t.Fatal("runtime log inside replacement output directory was accepted")
	}
	got, err := os.ReadFile(inPath)
	if err != nil {
		t.Fatalf("rejected alias destroyed runtime log: %v", err)
	}
	if !reflect.DeepEqual(got, logBytes) {
		t.Fatal("rejected alias changed runtime log")
	}
}

func TestFridaImportCanonicalizesOwnModuleTargetFromStaticIdentity(t *testing.T) {
	staticDir := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "merged")
	binding := writeStaticImportFixture(t, staticDir,
		[]disasm.CallEdgeRecord{{FromFunc: "F", FromPC: "0x100", Kind: "blr", Reg: "X16", Via: "dispatch_table"}},
		[]disasm.FuncRecord{{PC: "0x10", Size: 4, Name: "F"}, {PC: "0x400", Size: 4, Name: "Known"}},
	)
	logPath := writeRuntimeLog(t, binding, []runtimeEvent{{
		SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "dispatch",
		BLRAddr: "0x100", FromFunc: "F", TargetVA: "0x0400", TargetModule: "libapp.so", ClassID: 7,
	}})
	if err := CmdFridaImport([]string{"--in", logPath, "--static", staticDir, "--out", outDir}); err != nil {
		t.Fatal(err)
	}
	edges, err := readStaticCallEdges(filepath.Join(outDir, "call_edges.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 || edges[0].Target != "Known" || !reflect.DeepEqual(edges[0].RuntimeTargets, []string{"Known"}) {
		t.Fatalf("own-module runtime target was not canonicalized from static identity: %+v", edges)
	}
}

func TestFridaImportFailurePreservesPreviousGeneration(t *testing.T) {
	staticDir := t.TempDir()
	// Deliberately malformed but generation-bound evidence forces failure only
	// after the complete static tree has been cloned into the unpublished stage.
	if err := os.WriteFile(filepath.Join(staticDir, "evidence.jsonl"), []byte("not-json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	binding := writeStaticImportFixture(t, staticDir,
		[]disasm.CallEdgeRecord{{FromFunc: "F", FromPC: "0x100", Kind: "blr", Reg: "X16", Via: "dispatch_table"}},
		[]disasm.FuncRecord{{PC: "0x10", Size: 4, Name: "F"}},
	)
	outDir := filepath.Join(t.TempDir(), "merged")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(outDir, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("previous generation"), 0o644); err != nil {
		t.Fatal(err)
	}
	logPath := writeRuntimeLog(t, binding, []runtimeEvent{{
		SchemaVersion: MetadataSchemaVersion, SourceSHA256: testSourceSHA256, Type: "dispatch",
		BLRAddr: "0x100", FromFunc: "F", TargetName: "Target", ClassID: 10,
	}})
	if err := CmdFridaImport([]string{"--in", logPath, "--static", staticDir, "--out", outDir}); err == nil {
		t.Fatal("expected malformed evidence to fail import")
	}
	b, err := os.ReadFile(sentinel)
	if err != nil || string(b) != "previous generation" {
		t.Fatalf("failed import damaged prior generation: %q, %v", b, err)
	}
}

func TestRuntimeEventLogHonorsTotalByteBudget(t *testing.T) {
	p := filepath.Join(t.TempDir(), "oversized.log")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxRuntimeLogBytes + 1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	binding := FridaBinding{GenerationID: strings.Repeat("c", 64), SourceSHA256: testSourceSHA256, SourceSize: 1234, Architecture: "x64"}
	if _, err := readRuntimeEventLog(p, binding); err == nil {
		t.Fatal("runtime log byte budget was not enforced")
	}
}

func TestReadStaticCallEdgesRejectsSchemaDrift(t *testing.T) {
	p := filepath.Join(t.TempDir(), "call_edges.jsonl")
	body := `{"from_func":"F","from_pc":"0x100","kind":"blr","stale":true}` + "\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readStaticCallEdges(p); err == nil {
		t.Fatal("unknown static call-edge field was accepted")
	}
}
