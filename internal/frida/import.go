package frida

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"aotopsy/internal/cli"
	"aotopsy/internal/disasm"
	"aotopsy/internal/evidence"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/output"
)

const runtimeEventPrefix = "AOTOPSY_EVENT "

const (
	maxRuntimeLogBytes  = int64(64 << 20)
	maxRuntimeEvents    = 500_000
	maxRuntimeEventLine = 1 << 20
	maxProvenanceBytes  = int64(1 << 20)
)

// runtimeEvent is the one and only export→run→import wire record. Generated
// scripts print one tagged JSON object per runtime observation; redirect Frida's
// stdout to a file and pass that file to frida-import. Ordinary Frida/console
// chatter is deliberately ignored.
type runtimeEvent struct {
	SchemaVersion int    `json:"schema_version"`
	GenerationID  string `json:"generation_id"`
	SourceSHA256  string `json:"source_sha256"`
	SourceSize    int64  `json:"source_size"`
	Architecture  string `json:"architecture"`
	Type          string `json:"type"`
	Name          string `json:"name,omitempty"`
	FunctionVA    string `json:"function_va,omitempty"`
	CallAddr      string `json:"call_addr,omitempty"`
	FromFunc      string `json:"from_func,omitempty"`
	TargetVA      string `json:"target_va,omitempty"`
	TargetName    string `json:"target_name,omitempty"`
	TargetModule  string `json:"target_module,omitempty"`
	ClassID       int    `json:"class_id,omitempty"`
}

type staticProvenance struct {
	Source             string          `json:"source"`
	SourceName         string          `json:"source_name"`
	SHA256             string          `json:"sha256"`
	Size               int64           `json:"size"`
	Arch               string          `json:"arch"`
	DartVersion        string          `json:"dart_version"`
	CompressedPointers bool            `json:"compressed_pointers"`
	Build              json.RawMessage `json:"build"`
}

type staticRuntimeSite struct {
	fromFunc   string
	via        string
	classIDReg string
}

type staticGeneration struct {
	provenance staticProvenance
	edges      []disasm.CallEdgeRecord
	functions  []disasm.FuncRecord
	binding    FridaBinding
}

type resolutionAggregate struct {
	targets      map[string]int
	classIDs     map[int]struct{}
	function     string
	observations int
}

// ImportOptions identifies one static generation and the runtime observations
// that should be merged into it. CLI parsing belongs in cmd/aotopsy; this
// package owns only the import/validation business logic.
type ImportOptions struct {
	InPath    string
	StaticDir string
	OutDir    string
}

func Import(opts ImportOptions) error {
	if opts.InPath == "" || opts.StaticDir == "" {
		return fmt.Errorf("runtime log and static directory are required")
	}
	if opts.OutDir == "" {
		opts.OutDir = opts.StaticDir + "_merged"
	}

	staticAbs, err := filepath.Abs(opts.StaticDir)
	if err != nil {
		return fmt.Errorf("frida-import: resolve static dir: %w", err)
	}
	outAbs, err := filepath.Abs(opts.OutDir)
	if err != nil {
		return fmt.Errorf("frida-import: resolve output dir: %w", err)
	}
	inAbs, err := filepath.Abs(opts.InPath)
	if err != nil {
		return fmt.Errorf("frida-import: resolve runtime log: %w", err)
	}
	if staticAbs != outAbs {
		overlap, err := output.PathsOverlap(staticAbs, outAbs)
		if err != nil {
			return fmt.Errorf("frida-import: compare static/output paths: %w", err)
		}
		if overlap {
			return fmt.Errorf("frida-import: --static and --out must not contain one another")
		}
	}
	insideOut, err := output.ContainsPath(outAbs, inAbs)
	if err != nil {
		return fmt.Errorf("frida-import: compare runtime-log/output paths: %w", err)
	}
	if insideOut {
		return fmt.Errorf("frida-import: --in must not be inside --out because publishing the merged generation would replace the input log")
	}

	generation, err := readStaticGeneration(staticAbs)
	if err != nil {
		return err
	}
	prov := generation.provenance
	edges := generation.edges
	funcs := generation.functions
	events, err := readRuntimeEventLog(inAbs, generation.binding)
	if err != nil {
		return err
	}

	knownFunctions := make(map[string]struct{}, len(funcs))
	knownFunctionPCs := make(map[string]string, len(funcs))
	for _, f := range funcs {
		knownFunctions[f.Name] = struct{}{}
		pc, err := canonicalRuntimeHex(f.PC)
		if err != nil {
			return fmt.Errorf("frida-import: static function %q has invalid pc %q: %w", f.Name, f.PC, err)
		}
		if old, exists := knownFunctionPCs[pc]; exists && old != f.Name {
			return fmt.Errorf("frida-import: conflicting static functions at %s: %q and %q", pc, old, f.Name)
		}
		knownFunctionPCs[pc] = f.Name
	}
	installedFunctions := make(map[string]string, len(generation.binding.InstalledFunctions))
	for _, f := range generation.binding.InstalledFunctions {
		pc, err := canonicalRuntimeHex(f.VA)
		if err != nil {
			return fmt.Errorf("frida-import: installed function %q has invalid pc %q: %w", f.Name, f.VA, err)
		}
		if old, exists := installedFunctions[pc]; exists && old != f.Name {
			return fmt.Errorf("frida-import: conflicting installed functions at %s: %q and %q", pc, old, f.Name)
		}
		installedFunctions[pc] = f.Name
	}
	sites := make(map[string]staticRuntimeSite, len(generation.binding.InstalledCallProbes))
	for _, p := range generation.binding.InstalledCallProbes {
		pc, err := canonicalRuntimeHex(p.VA)
		if err != nil {
			return fmt.Errorf("frida-import: installed probe has invalid pc %q: %w", p.VA, err)
		}
		site := staticRuntimeSite{fromFunc: p.FromFunc, via: p.Via, classIDReg: p.ClassIDReg}
		if old, exists := sites[pc]; exists && old != site {
			return fmt.Errorf("frida-import: conflicting installed runtime sites at %s", pc)
		}
		sites[pc] = site
	}

	resolutions := make(map[string]*resolutionAggregate)
	runtimeCalls := make(map[string]int)
	for _, ev := range events {
		switch ev.Type {
		case "function_enter":
			if ev.Name == "" || ev.FunctionVA == "" {
				return fmt.Errorf("frida-import: function_enter event missing name/function_va")
			}
			pc, err := canonicalRuntimeHex(ev.FunctionVA)
			if err != nil {
				return fmt.Errorf("frida-import: function_enter has invalid function_va %q: %w", ev.FunctionVA, err)
			}
			installedName, ok := installedFunctions[pc]
			if !ok || installedName != ev.Name {
				return fmt.Errorf("frida-import: function_enter %s/%q was not in the exact installed hook set", pc, ev.Name)
			}
			runtimeCalls[ev.Name]++
		case "dispatch":
			if ev.CallAddr == "" {
				return fmt.Errorf("frida-import: dispatch event missing call_addr")
			}
			pc, err := canonicalRuntimeHex(ev.CallAddr)
			if err != nil {
				return fmt.Errorf("frida-import: dispatch event has invalid call_addr %q: %w", ev.CallAddr, err)
			}
			site, ok := sites[pc]
			if !ok {
				return fmt.Errorf("frida-import: dispatch event references site %s that was not in the exact installed probe set", pc)
			}
			if ev.FromFunc == "" || ev.FromFunc != site.fromFunc {
				return fmt.Errorf("frida-import: dispatch site %s function %q does not match static %q", ev.CallAddr, ev.FromFunc, site.fromFunc)
			}
			if ev.ClassID < -1 || int64(ev.ClassID) > 1<<31-1 {
				return fmt.Errorf("frida-import: site %s supplied impossible class id %d", pc, ev.ClassID)
			}
			if ev.ClassID > 0 && (site.via != "dispatch_table" || site.classIDReg == "") {
				return fmt.Errorf("frida-import: site %s supplied class id %d without a generation-approved CID register", pc, ev.ClassID)
			}
			target, err := validateRuntimeTarget(ev, prov, knownFunctions, knownFunctionPCs)
			if err != nil {
				return fmt.Errorf("frida-import: dispatch site %s target: %w", ev.CallAddr, err)
			}
			a := resolutions[pc]
			if a == nil {
				a = &resolutionAggregate{targets: map[string]int{}, classIDs: map[int]struct{}{}, function: site.fromFunc}
				resolutions[pc] = a
			}
			a.targets[target]++
			if ev.ClassID > 0 {
				a.classIDs[ev.ClassID] = struct{}{}
			}
			a.observations++
		default:
			return fmt.Errorf("frida-import: unsupported event type %q", ev.Type)
		}
	}

	observedEdges := 0
	agreeingEdges := 0
	conflictingEdges := 0
	indeterminateEdges := 0
	observedOnlyEdges := 0
	for i := range edges {
		e := &edges[i]
		if e.Kind != "blr" && e.Kind != "call_indirect" {
			continue
		}
		pc, err := canonicalRuntimeHex(e.FromPC)
		if err != nil {
			return fmt.Errorf("frida-import: static indirect edge has invalid from_pc %q: %w", e.FromPC, err)
		}
		a := resolutions[pc]
		if a == nil {
			continue
		}
		rt := runtimeEvidenceFromAggregate(generation.binding, a)
		rt.Agreement = runtimeAgreementForEdge(*e, rt)
		e.Runtime = &rt
		observedEdges++
		switch rt.Agreement {
		case disasm.RuntimeAgrees:
			agreeingEdges++
		case disasm.RuntimeConflicts:
			conflictingEdges++
		case disasm.RuntimeIndeterminate:
			indeterminateEdges++
		case disasm.RuntimeObservedOnly:
			observedOnlyEdges++
		}
	}

	tx, err := output.BeginDirTransaction(outAbs)
	if err != nil {
		return fmt.Errorf("frida-import: begin output transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Abort()
		}
	}()
	stage := tx.StageDir()
	if err := tx.CloneFrom(staticAbs); err != nil {
		return fmt.Errorf("frida-import: clone static generation: %w", err)
	}
	stagedGeneration, err := readStaticGeneration(stage)
	if err != nil {
		return fmt.Errorf("frida-import: validate cloned static generation: %w", err)
	}
	if stagedGeneration.binding.GenerationID != generation.binding.GenerationID {
		return fmt.Errorf("frida-import: static generation changed while it was being cloned")
	}
	for _, name := range []string{
		BindingFileName,
		"frida_metadata.json",
		"frida_hooks.js",
		"runtime_coverage.json",
		"frida_import_report.txt",
	} {
		if err := os.Remove(filepath.Join(stage, name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("frida-import: remove stale Frida export artifact %s: %w", name, err)
		}
	}
	if _, err := jsonutil.WriteJSONLFile(filepath.Join(stage, "call_edges.jsonl"), edges); err != nil {
		return fmt.Errorf("frida-import: write merged edges: %w", err)
	}
	runtimeObservations := flattenRuntimeObservations(generation.binding, resolutions)
	coverage, evidenceMerged, err := mergeRuntimeEvidence(stage, stage, generation.binding.DartVersion, runtimeObservations)
	if err != nil {
		return err
	}

	report := fmt.Sprintf(
		"Frida Import Report\n===================\n\nStatic output: %s\nFrida event log: %s\nMerged output: %s\nGeneration ID: %s\nSource SHA-256: %s\n\nRuntime events: %d\nFunction entries observed: %d\nDispatch sites observed: %d\nIndirect edges observed: %d\nStatic/runtime agreement: %d\nStatic/runtime conflict: %d\nStatic/runtime indeterminate: %d\nRuntime observed with no static target: %d\nEvidence merged: %t\nEvidence coverage: static_only=%d runtime_only=%d match=%d conflict=%d indeterminate=%d static_unresolved_observed=%d invalid_runtime=%d\n",
		opts.StaticDir, opts.InPath, opts.OutDir, generation.binding.GenerationID, generation.binding.SourceSHA256,
		len(events), totalRuntimeCalls(runtimeCalls), len(resolutions), observedEdges, agreeingEdges, conflictingEdges, indeterminateEdges, observedOnlyEdges,
		evidenceMerged, coverage.StaticOnly, coverage.RuntimeOnly, coverage.BothMatch, coverage.BothConflict, coverage.BothIndeterminate, coverage.StaticUnresolvedObserved, coverage.InvalidRuntime,
	)
	if err := output.WriteFileAtomic(filepath.Join(stage, "frida_import_report.txt"), []byte(report), 0o644); err != nil {
		return fmt.Errorf("frida-import: write report: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("frida-import: publish merged generation: %w", err)
	}
	committed = true

	logger := cli.NewLogger(os.Stderr, false)
	logger.Printf("Frida import complete: %s\n", opts.OutDir)
	logger.Printf("  indirect edges observed: %d\n", observedEdges)
	return nil
}

func runtimeEvidenceFromAggregate(binding FridaBinding, aggregate *resolutionAggregate) disasm.RuntimeEvidence {
	targetNames := sortedTargetKeys(aggregate.targets)
	targets := make([]disasm.RuntimeTargetObservation, 0, len(targetNames))
	for _, target := range targetNames {
		targets = append(targets, disasm.RuntimeTargetObservation{Target: target, Count: aggregate.targets[target]})
	}
	return disasm.RuntimeEvidence{
		Source:       "frida",
		GenerationID: strings.ToLower(binding.GenerationID),
		SourceSHA256: strings.ToLower(binding.SourceSHA256),
		SourceSize:   binding.SourceSize,
		ModuleName:   binding.ModuleName,
		DartVersion:  binding.DartVersion,
		Architecture: binding.Architecture,
		Agreement:    disasm.RuntimeObservedOnly,
		Targets:      targets,
		ClassIDs:     sortedIntKeys(aggregate.classIDs),
		Observations: aggregate.observations,
	}
}

func runtimeAgreementForEdge(edge disasm.CallEdgeRecord, runtime disasm.RuntimeEvidence) disasm.RuntimeAgreement {
	if edge.Target != "" {
		for _, observed := range runtime.Targets {
			if observed.Target != edge.Target {
				return disasm.RuntimeConflicts
			}
		}
		return disasm.RuntimeAgrees
	}
	if len(edge.Targets) == 0 {
		return disasm.RuntimeObservedOnly
	}
	allowed := make(map[string]struct{}, len(edge.Targets))
	for _, target := range edge.Targets {
		allowed[target] = struct{}{}
	}
	for _, observed := range runtime.Targets {
		if _, ok := allowed[observed.Target]; ok {
			continue
		}
		if edge.Candidates > 0 && edge.Candidates == len(edge.Targets) {
			return disasm.RuntimeConflicts
		}
		return disasm.RuntimeIndeterminate
	}
	return disasm.RuntimeAgrees
}

func flattenRuntimeObservations(binding FridaBinding, aggregates map[string]*resolutionAggregate) []evidence.RuntimeObservation {
	pcs := make([]string, 0, len(aggregates))
	for pc := range aggregates {
		pcs = append(pcs, pc)
	}
	sort.Strings(pcs)
	var out []evidence.RuntimeObservation
	for _, pc := range pcs {
		a := aggregates[pc]
		if a == nil {
			continue
		}
		out = append(out, evidence.RuntimeObservation{
			PC:       pc,
			Function: a.function,
			Runtime:  runtimeEvidenceFromAggregate(binding, a),
		})
	}
	return out
}

func mergeRuntimeEvidence(staticDir, outDir, dartVersion string, runtime []evidence.RuntimeObservation) (evidence.CoverageReport, bool, error) {
	staticPath := filepath.Join(staticDir, "evidence.jsonl")
	hasStatic := true
	if _, err := os.Stat(staticPath); err != nil {
		if os.IsNotExist(err) {
			hasStatic = false
		} else {
			return evidence.CoverageReport{}, false, fmt.Errorf("frida-import: stat evidence.jsonl: %w", err)
		}
	}
	var records []evidence.Evidence
	if hasStatic {
		var err error
		records, err = jsonutil.ReadJSONL[evidence.Evidence](staticPath, jsonutil.StandardLimits)
		if err != nil {
			return evidence.CoverageReport{}, false, fmt.Errorf("frida-import: read evidence.jsonl: %w", err)
		}
	}
	c := evidence.NewCollectorFromRecords(dartVersion, records)
	if err := c.ValidateStatic(); err != nil {
		return evidence.CoverageReport{}, false, fmt.Errorf("frida-import: validate static evidence.jsonl: %w", err)
	}
	if err := c.MergeRuntime(runtime); err != nil {
		return evidence.CoverageReport{}, false, fmt.Errorf("frida-import: merge runtime evidence: %w", err)
	}
	coverage := c.Coverage(runtime)
	if !hasStatic && len(runtime) == 0 {
		return coverage, false, nil
	}
	if err := c.WriteJSONL(filepath.Join(outDir, "evidence.jsonl")); err != nil {
		return evidence.CoverageReport{}, false, fmt.Errorf("frida-import: write enriched evidence.jsonl: %w", err)
	}
	if err := output.WriteJSONFile(filepath.Join(outDir, "runtime_coverage.json"), coverage); err != nil {
		return evidence.CoverageReport{}, false, fmt.Errorf("frida-import: write runtime coverage: %w", err)
	}
	return coverage, true, nil
}

func readRuntimeEventLog(path string, binding FridaBinding) ([]runtimeEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("frida-import: open runtime log: %w", err)
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil {
		return nil, fmt.Errorf("frida-import: stat runtime log: %w", err)
	} else if st.Size() > maxRuntimeLogBytes {
		return nil, fmt.Errorf("frida-import: runtime log is %d bytes, exceeds %d-byte limit", st.Size(), maxRuntimeLogBytes)
	}

	s := bufio.NewScanner(f)
	// Events are intentionally tiny. A generous 1 MiB ceiling prevents an
	// attacker-controlled log line from forcing Scanner to grow without bound.
	s.Buffer(make([]byte, 64<<10), maxRuntimeEventLine+1)
	var events []runtimeEvent
	lineNo := 0
	var consumed int64
	for s.Scan() {
		lineNo++
		line := s.Text()
		consumed += int64(len(line)) + 1
		if consumed > maxRuntimeLogBytes {
			return nil, fmt.Errorf("frida-import: runtime log exceeds %d-byte limit", maxRuntimeLogBytes)
		}
		idx := strings.Index(line, runtimeEventPrefix)
		if idx < 0 {
			continue
		}
		raw := strings.TrimSpace(line[idx+len(runtimeEventPrefix):])
		ev, err := jsonutil.DecodeStrictObject[runtimeEvent]([]byte(raw))
		if err != nil {
			return nil, fmt.Errorf("frida-import: event line %d: %w", lineNo, err)
		}
		if ev.SchemaVersion != MetadataSchemaVersion {
			return nil, fmt.Errorf("frida-import: event line %d schema %d, want %d", lineNo, ev.SchemaVersion, MetadataSchemaVersion)
		}
		if !strings.EqualFold(ev.GenerationID, binding.GenerationID) {
			return nil, fmt.Errorf("frida-import: event line %d generation id does not match exported hook generation", lineNo)
		}
		if !strings.EqualFold(ev.SourceSHA256, binding.SourceSHA256) {
			return nil, fmt.Errorf("frida-import: event line %d source sha256 does not match static provenance", lineNo)
		}
		if ev.SourceSize != binding.SourceSize {
			return nil, fmt.Errorf("frida-import: event line %d source size does not match static provenance", lineNo)
		}
		if ev.Architecture != binding.Architecture {
			return nil, fmt.Errorf("frida-import: event line %d architecture does not match static provenance", lineNo)
		}
		events = append(events, ev)
		if len(events) > maxRuntimeEvents {
			return nil, fmt.Errorf("frida-import: runtime event limit %d exceeded", maxRuntimeEvents)
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("frida-import: read runtime log: %w", err)
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("frida-import: no %q records found in %s", strings.TrimSpace(runtimeEventPrefix), path)
	}
	return events, nil
}

func readStaticGeneration(dir string) (staticGeneration, error) {
	var out staticGeneration
	bindingBytes, present, err := readPinnedStaticFile(filepath.Join(dir, BindingFileName), 8<<20, true)
	if err != nil {
		return out, fmt.Errorf("frida-import: read %s: %w", BindingFileName, err)
	}
	if !present {
		return out, fmt.Errorf("frida-import: missing %s; run frida-export for this static generation first", BindingFileName)
	}
	binding, err := jsonutil.DecodeStrictObject[FridaBinding](bindingBytes)
	if err != nil {
		return out, fmt.Errorf("frida-import: decode %s: %w", BindingFileName, err)
	}
	if err := ValidateBinding(binding); err != nil {
		return out, fmt.Errorf("frida-import: %w", err)
	}
	if binding.AnalyzerVersion != cli.Version || binding.AnalyzerCommit != cli.Commit {
		return out, fmt.Errorf("frida-import: binding analyzer identity %s/%s does not match this aotopsy %s/%s", binding.AnalyzerVersion, binding.AnalyzerCommit, cli.Version, cli.Commit)
	}

	blobs := make(map[string][]byte, len(binding.Artifacts))
	for i, name := range GenerationArtifactNames() {
		expected := binding.Artifacts[i]
		b, gotPresent, err := readPinnedStaticFile(filepath.Join(dir, name), jsonutil.StandardLimits.MaxBytes, expected.Present)
		if err != nil {
			return out, fmt.Errorf("frida-import: read bound artifact %s: %w", name, err)
		}
		actual := DigestArtifact(name, b, gotPresent)
		if actual != expected {
			return out, fmt.Errorf("frida-import: static artifact %s does not match the Frida generation binding", name)
		}
		if gotPresent {
			blobs[name] = b
		}
	}

	prov, err := jsonutil.DecodeStrictObject[staticProvenance](blobs["provenance.json"])
	if err != nil {
		return out, fmt.Errorf("frida-import: decode provenance: %w", err)
	}
	if err := validateStaticProvenance(&prov); err != nil {
		return out, err
	}
	if !strings.EqualFold(prov.SHA256, binding.SourceSHA256) || prov.Size != binding.SourceSize || prov.SourceName != binding.ModuleName || prov.Arch != binding.Architecture || prov.DartVersion != binding.DartVersion {
		return out, fmt.Errorf("frida-import: provenance identity does not match Frida generation binding")
	}

	funcs, err := jsonutil.DecodeJSONL[disasm.FuncRecord](blobs["functions.jsonl"], jsonutil.StandardLimits)
	if err != nil {
		return out, fmt.Errorf("frida-import: decode functions.jsonl: %w", err)
	}
	if err := validateStaticFunctions(funcs); err != nil {
		return out, err
	}
	edges, err := jsonutil.DecodeJSONL[disasm.CallEdgeRecord](blobs["call_edges.jsonl"], jsonutil.StandardLimits)
	if err != nil {
		return out, fmt.Errorf("frida-import: decode call_edges.jsonl: %w", err)
	}
	if err := ValidateStaticCallEdges(edges); err != nil {
		return out, fmt.Errorf("frida-import: invalid static call_edges.jsonl: %w", err)
	}
	if evidenceBytes, ok := blobs["evidence.jsonl"]; ok {
		records, err := jsonutil.DecodeJSONL[evidence.Evidence](evidenceBytes, jsonutil.StandardLimits)
		if err != nil {
			return out, fmt.Errorf("frida-import: decode evidence.jsonl: %w", err)
		}
		if err := evidence.NewCollectorFromRecords(binding.DartVersion, records).ValidateStatic(); err != nil {
			return out, fmt.Errorf("frida-import: invalid static evidence.jsonl: %w", err)
		}
	}

	allFunctions := make([]FridaFunction, 0, len(funcs))
	for _, f := range funcs {
		allFunctions = append(allFunctions, FridaFunction{VA: f.PC, Name: f.Name, Owner: f.Owner, Size: f.Size})
	}
	allProbes := make([]FridaCallProbe, 0)
	for _, e := range edges {
		p, ok := RuntimeProbeForEdge(e)
		if !ok {
			continue
		}
		if p.Via == "dispatch_table" {
			p.ClassIDReg = DispatchClassIDRegister(binding.Architecture, binding.DartVersion, p.IndexReg)
		}
		allProbes = append(allProbes, p)
	}
	if !sameInstalledFunctions(binding.InstalledFunctions, installedFunctions(allFunctions)) {
		return out, fmt.Errorf("frida-import: installed function subset does not match bound functions.jsonl")
	}
	if !sameInstalledCallProbes(binding.InstalledCallProbes, installedCallProbes(allProbes)) {
		return out, fmt.Errorf("frida-import: installed probe subset does not match bound call_edges.jsonl")
	}

	out.provenance = prov
	out.edges = edges
	out.functions = funcs
	out.binding = binding
	return out, nil
}

func readPinnedStaticFile(path string, limit int64, required bool) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) && !required {
			return nil, false, nil
		}
		return nil, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s is not a regular non-symlink file", path)
	}
	if info.Size() > limit {
		return nil, false, fmt.Errorf("%s is %d bytes, exceeds limit %d", path, info.Size(), limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if !os.SameFile(info, opened) {
		return nil, false, fmt.Errorf("%s changed while being opened", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) > limit {
		return nil, false, fmt.Errorf("%s exceeds byte limit %d", path, limit)
	}
	return b, true, nil
}

func readCallEdgesStrict(path string) ([]disasm.CallEdgeRecord, error) {
	out, err := jsonutil.ReadJSONL[disasm.CallEdgeRecord](path, jsonutil.StandardLimits)
	if err != nil {
		return nil, fmt.Errorf("frida-import: read call_edges.jsonl: %w", err)
	}
	return out, nil
}

func validateStaticFunctions(out []disasm.FuncRecord) error {
	for i, f := range out {
		if f.PC == "" || f.Name == "" || f.Size < 0 {
			return fmt.Errorf("frida-import: functions line %d missing/invalid required field", i+1)
		}
	}
	return nil
}

func readStaticProvenance(path string) (staticProvenance, error) {
	p, err := jsonutil.ReadJSONFile[staticProvenance](path, maxProvenanceBytes)
	if err != nil {
		return staticProvenance{}, fmt.Errorf("frida-import: read provenance: %w", err)
	}
	if err := validateStaticProvenance(&p); err != nil {
		return staticProvenance{}, err
	}
	return p, nil
}

func validateStaticProvenance(p *staticProvenance) error {
	if p == nil {
		return fmt.Errorf("frida-import: missing provenance")
	}
	if p.SourceName == "" || p.Size <= 0 || (p.Arch != "arm64" && p.Arch != "x64") || p.DartVersion == "" || len(p.SHA256) != 64 {
		return fmt.Errorf("frida-import: incomplete/invalid provenance identity")
	}
	if _, err := hex.DecodeString(p.SHA256); err != nil {
		return fmt.Errorf("frida-import: invalid provenance sha256: %w", err)
	}
	p.SHA256 = strings.ToLower(p.SHA256)
	return nil
}

func validateRuntimeTarget(ev runtimeEvent, prov staticProvenance, knownFunctions map[string]struct{}, knownFunctionPCs map[string]string) (string, error) {
	if ev.TargetVA == "" {
		return "", fmt.Errorf("missing target_va")
	}
	if ev.TargetModule == prov.SourceName {
		pc, err := canonicalRuntimeHex(ev.TargetVA)
		if err != nil {
			return "", fmt.Errorf("own-module target_va %q: %w", ev.TargetVA, err)
		}
		staticName, knownPC := knownFunctionPCs[pc]
		if ev.TargetName != "" {
			if _, ok := knownFunctions[ev.TargetName]; !ok {
				return "", fmt.Errorf("unknown own-module target name %q", ev.TargetName)
			}
			if !knownPC || staticName != ev.TargetName {
				return "", fmt.Errorf("target name %q does not match static function at %s", ev.TargetName, pc)
			}
			return ev.TargetName, nil
		}
		if knownPC {
			return staticName, nil
		}
		return pc, nil
	}

	if ev.TargetModule == "" {
		return "", fmt.Errorf("target has no owning module; absolute runtime addresses cannot be merged into module-relative static evidence")
	}

	if strings.ContainsAny(ev.TargetModule, "/\\\r\n\x00") {
		return "", fmt.Errorf("invalid external module name %q", ev.TargetModule)
	}
	if ev.TargetName != "" {
		return "", fmt.Errorf("external module %q supplied unsupported target_name %q", ev.TargetModule, ev.TargetName)
	}
	prefix := ev.TargetModule + "+"
	if !strings.HasPrefix(ev.TargetVA, prefix) {
		return "", fmt.Errorf("external target_va %q does not match module %q", ev.TargetVA, ev.TargetModule)
	}
	off, err := canonicalRuntimeHex(strings.TrimPrefix(ev.TargetVA, prefix))
	if err != nil {
		return "", fmt.Errorf("external target_va %q: %w", ev.TargetVA, err)
	}
	return ev.TargetModule + "+" + off, nil
}

func canonicalRuntimeHex(s string) (string, error) {
	if len(s) < 3 || !strings.HasPrefix(s, "0x") {
		return "", fmt.Errorf("expected 0x-prefixed hexadecimal value")
	}
	v, err := strconv.ParseUint(s[2:], 16, 64)
	if err != nil {
		return "", fmt.Errorf("invalid hexadecimal value: %w", err)
	}
	return fmt.Sprintf("0x%x", v), nil
}

func sortedTargetKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedIntKeys(m map[int]struct{}) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func totalRuntimeCalls(calls map[string]int) int {
	total := 0
	for _, n := range calls {
		total += n
	}
	return total
}
