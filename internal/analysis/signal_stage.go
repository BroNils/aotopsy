package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aotopsy/internal/cli"
	"aotopsy/internal/disasm"
	"aotopsy/internal/evidence"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/output"
	"aotopsy/internal/render"
	"aotopsy/internal/signal"
	"aotopsy/internal/strutil"
)

// SignalResult holds summary stats from the signal stage.
type SignalResult struct {
	SignalCount         int
	ContextCount        int
	StaticRelationCount int
	// Findings are returned so the pipeline can fold them into the single
	// evidence collector. The stage writes its own evidence.jsonl only on
	// the standalone path, where nothing downstream will.
	Findings []output.SignalFinding
}

// RunSignalStage runs signal analysis using artifacts from inDir and writes all
// generated artifacts to outDir. Keeping those roles separate is required for
// `run --from SRC --out DST`: regenerating analysis must never mutate SRC.
// writeEvidence marks the terminal/standalone path: it emits evidence.jsonl and
// the signal-only SARIF itself. The full pipeline passes false because it folds
// type evidence and later detector families into richer final artifacts.
func RunSignalStage(inDir, outDir string, k int, noAsm bool, quiet bool, log io.Writer, writeEvidence bool) (*SignalResult, error) {
	if log == nil {
		log = os.Stderr
	}
	if outDir == "" {
		outDir = inDir
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir signal output: %w", err)
	}
	// These artifacts are conditional (no-asm, no connected content, missing
	// Graphviz). Remove the previous generation up front so a successful rerun
	// cannot advertise stale optional output.
	for _, name := range []string{"signal_cfg.dot", "signal_cfg.svg", "signal.svg"} {
		if err := os.Remove(filepath.Join(outDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("remove stale %s: %w", name, err)
		}
	}
	logger := cli.NewLogger(log, quiet)
	logf := logger.Printf
	stagef := logger.Stage
	warnf := logger.Warn

	// provenance.json is what the pipeline leaves behind describing the
	// binary this directory came from: its name, hash, and architecture.
	// Read once here; three separate call sites used to re-read it.
	prov, hasProv, err := ReadProvenance(inDir)
	if err != nil {
		return nil, fmt.Errorf("read provenance: %w", err)
	}

	// Read functions.jsonl.
	funcs, err := jsonutil.ReadJSONL[disasm.FuncRecord](filepath.Join(inDir, "functions.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		return nil, fmt.Errorf("read functions.jsonl: %w", err)
	}
	index, err := jsonutil.ReadJSONL[strutil.DisasmIndexEntry](filepath.Join(inDir, "index.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		return nil, fmt.Errorf("read index.jsonl: %w", err)
	}
	artifactFiles, err := DisasmArtifactFiles(funcs, index)
	if err != nil {
		return nil, err
	}

	// Read call_edges.jsonl.
	edges, err := jsonutil.ReadJSONL[disasm.CallEdgeRecord](filepath.Join(inDir, "call_edges.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		return nil, fmt.Errorf("read call_edges.jsonl: %w", err)
	}

	// Read string_refs.jsonl.
	stringRefs, err := jsonutil.ReadJSONL[disasm.StringRefRecord](filepath.Join(inDir, "string_refs.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		return nil, fmt.Errorf("read string_refs.jsonl: %w", err)
	}

	// Signal expansion: crypto ID, MethodChannel, plugins, deobfuscation, network endpoints.
	// Convert disasm.StringRefRecord to signal.StringRefRecord for the signal package.
	sigStringRefs := make([]signal.StringRefRecord, len(stringRefs))
	for i, sr := range stringRefs {
		sigStringRefs[i] = signal.StringRefRecord{
			Func:    sr.Func,
			PC:      sr.PC,
			Kind:    sr.Kind,
			PoolIdx: sr.PoolIdx,
			Value:   sr.Value,
		}
	}
	if err := signal.WriteSignalExpansionJSONL(outDir, sigStringRefs); err != nil {
		return nil, fmt.Errorf("signal expansion: %w", err)
	}

	// Compute structural source-component roots of the resolved static graph.
	// These are candidates for traversal roots, not language-level entry points.
	rootList := render.FindRootCandidates(funcs, edges)
	rootSet := make(map[string]bool, len(rootList))
	for _, root := range rootList {
		rootSet[root] = true
	}

	// Build signal graph.
	dartVersion := ""
	if hasProv {
		dartVersion = prov.DartVersion
	}
	g := signal.BuildSignalGraph(dartVersion, funcs, edges, stringRefs, k, rootSet)
	stagef("signal", "%s%d%s signal + %s%d%s context, %s%d%s call sites / %s%d%s static relations",
		cli.Gold, g.Stats.SignalFuncs, cli.Reset,
		cli.Gold, g.Stats.ContextFuncs, cli.Reset,
		cli.Gold, g.Stats.CallSites, cli.Reset,
		cli.Gold, g.Stats.StaticRelations, cli.Reset)
	if g.Stats.IncompletePolymorphicSites > 0 || g.Stats.UnknownCandidateCountSites > 0 || g.Stats.UnresolvedIndirectSites > 0 || g.Stats.RuntimeObservedSites > 0 || g.Stats.UnclassifiedTHRSites > 0 {
		logf("  %sgraph completeness:%s %d incomplete polymorphic, %d unknown candidate-count, %d unresolved indirect, %d runtime-observed, %d unclassified THR site(s)\n",
			cli.Muted, cli.Reset, g.Stats.IncompletePolymorphicSites, g.Stats.UnknownCandidateCountSites, g.Stats.UnresolvedIndirectSites, g.Stats.RuntimeObservedSites, g.Stats.UnclassifiedTHRSites)
	}
	categories := make([]string, 0, len(g.Stats.Categories))
	for cat := range g.Stats.Categories {
		categories = append(categories, cat)
	}
	sort.Strings(categories)
	for _, cat := range categories {
		count := g.Stats.Categories[cat]
		logf("  %s%s:%s %d\n", cli.Muted, cat, cli.Reset, count)
	}

	// Load asm snippets.
	const contextAsmLines = 30
	asmSnippets := make(map[string]string)
	asmLinks := make(map[string]string)
	if !noAsm {
		for _, sf := range g.Funcs {
			if sf.Role == "" {
				continue
			}
			relPath, ok := artifactFiles[sf.Name]
			if !ok {
				return nil, fmt.Errorf("signal: no disassembly artifact for %q", sf.Name)
			}
			path := filepath.Join(inDir, relPath)
			data, err := readFileBounded(path, maxAsmArtifactBytes)
			if err != nil {
				return nil, fmt.Errorf("read asm snippet %s: %w", path, err)
			}
			s := strings.TrimRight(string(data), "\n")
			if sf.Role == "context" {
				lines := strings.SplitN(s, "\n", contextAsmLines+1)
				if len(lines) > contextAsmLines {
					s = strings.Join(lines[:contextAsmLines], "\n") + "\n[... truncated]"
				}
			}
			asmSnippets[sf.Name] = s
			insideOut, err := output.ContainsPath(outDir, path)
			if err != nil {
				return nil, fmt.Errorf("compare signal report/asm paths for %s: %w", sf.Name, err)
			}
			if insideOut {
				if rel, err := filepath.Rel(outDir, path); err == nil {
					asmLinks[sf.Name] = filepath.ToSlash(rel)
				}
			}
		}
		logf("  %sasm snippets:%s %d\n", cli.Muted, cli.Reset, len(asmSnippets))
	}

	// Write signal_graph.json.
	outPath := filepath.Join(outDir, "signal.html")
	jsonPath := filepath.Join(outDir, "signal_graph.json")
	if err := output.WriteAtomic(jsonPath, 0o644, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(g)
	}); err != nil {
		return nil, fmt.Errorf("write signal_graph.json: %w", err)
	}
	logf("  %s->%s %s%s%s (%d bytes)\n", cli.Muted, cli.Reset, cli.Blue, jsonPath, cli.Reset, strutil.FileSize(jsonPath))

	// Write signal.html.
	title := "aotopsy"
	digest := filepath.Base(filepath.Dir(inDir))
	filename := inDir
	// This used to read a dead meta.json path. provenance.json is now the
	// single immutable identity record shared by HTML/SARIF/report stages.
	if hasProv {
		filename = prov.SourceName
		if prov.SHA256 != "" {
			digest = prov.SHA256
		}
	}
	if err := output.WriteAtomic(outPath, 0o644, func(w io.Writer) error {
		return render.WriteSignalHTML(w, g, title, filename, digest, asmSnippets, asmLinks)
	}); err != nil {
		return nil, fmt.Errorf("write signal.html: %w", err)
	}
	logf("  %s->%s %s%s%s (%d bytes)\n", cli.Muted, cli.Reset, cli.Blue, outPath, cli.Reset, strutil.FileSize(outPath))

	// Write signal.dot.
	dotPath := filepath.Join(outDir, "signal.dot")
	dotContent := render.SignalDOT(g, title, render.NASA)
	if err := output.WriteFileAtomic(dotPath, []byte(dotContent), 0o644); err != nil {
		return nil, fmt.Errorf("write signal.dot: %w", err)
	}
	logf("  %s->%s %s%s%s (%d bytes)\n", cli.Muted, cli.Reset, cli.Blue, dotPath, cli.Reset, strutil.FileSize(dotPath))

	// Write SARIF report.
	var findings []output.SignalFinding
	for _, sf := range g.Funcs {
		representedCategories := make(map[string]bool)
		// String-based findings
		for _, ref := range sf.StringRefs {
			for _, cat := range ref.Categories {
				representedCategories[cat] = true
				findings = append(findings, output.SignalFinding{
					Category:           cat,
					StringValue:        ref.Value,
					Function:           sf.Name,
					PC:                 ref.PC,
					AddressKind:        "instruction",
					RuleID:             "signal.category." + cat,
					ProducerConfidence: ref.Confidence,
					FingerprintParts: []string{
						"category-string", cat, sf.Name, ref.Value,
					},
				})
			}
		}
		// Structural categories (async/generator runtime stubs) may coexist with
		// lexical findings in the same function. Emit every category not already
		// represented by a string witness instead of dropping it wholesale when a
		// function happens to reference any string.
		for _, cat := range sf.Categories {
			if representedCategories[cat] {
				continue
			}
			findings = append(findings, output.SignalFinding{
				Category:           cat,
				StringValue:        "",
				Function:           sf.Name,
				PC:                 sf.PC,
				AddressKind:        "function",
				RuleID:             "signal.category." + cat,
				ProducerConfidence: "high",
				FingerprintParts: []string{
					"category-function", cat, sf.Name,
				},
			})
		}
	}
	// Binary-level obfuscation measure. Reported once for the whole binary
	// rather than per string: see signal.ObfuscationRatio for why a single
	// short name is not evidence of anything.
	{
		values := make([]string, 0, len(stringRefs))
		for _, sr := range stringRefs {
			values = append(values, sr.Value)
		}
		ratio, considered, samples := signal.ObfuscationRatio(values)
		if considered >= 50 && ratio >= signal.ObfuscationThreshold {
			logf("  %sobfuscated identifiers:%s %.0f%% of %d name-like strings (e.g. %s)\n",
				cli.Muted, cli.Reset, ratio*100, considered, strings.Join(samples, ", "))
			findings = append(findings, output.SignalFinding{
				Category:           signal.CatObfuscation,
				StringValue:        fmt.Sprintf("%.0f%% of %d identifier-like strings look obfuscated", ratio*100, considered),
				RuleID:             "signal.obfuscation.ratio",
				ProducerConfidence: "medium",
				FingerprintParts: []string{
					"obfuscation-ratio",
				},
			})
		}
	}

	// Write evidence.jsonl only when nothing downstream will.
	//
	// The full pipeline writes it again at step 9 with the type-inference
	// resolutions and these findings folded in, so writing here too meant
	// producing a strictly poorer file and then overwriting it. That was
	// invisible while both wrote the same call-edge-only content; it stops
	// being invisible the moment either side gains a source.
	if writeEvidence {
		// The standalone/from-artifacts path can recompute graph-based detectors
		// from the current functions/calls/string refs, but it cannot recompute
		// binary-only entropy/crypto or cluster-backed channel/native artifacts.
		// Remove those stale outputs and regenerate every detector it can prove
		// from this generation before publishing SARIF/evidence.
		if err := removeSignalDetectorArtifacts(outDir); err != nil {
			return nil, err
		}
		for _, name := range []string{"platform_channels.jsonl", "native_capabilities.jsonl", "deobfuscate_map.jsonl"} {
			if err := os.Remove(filepath.Join(outDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("remove stale %s: %w", name, err)
			}
		}
		if err := signal.WriteSourceSinkFindings(outDir, funcs, stringRefs, edges); err != nil {
			return nil, fmt.Errorf("source/sink proximity: %w", err)
		}
		if err := signal.WriteYaraFindings(outDir, stringRefs); err != nil {
			return nil, fmt.Errorf("yara: %w", err)
		}
		if err := signal.WriteBehavioralFindings(outDir, funcs, edges); err != nil {
			return nil, fmt.Errorf("behavioral: %w", err)
		}
		extended, err := collectExtendedSARIF(outDir, nil)
		if err != nil {
			return nil, err
		}
		findings = append(findings, extended...)

		identity := output.ArtifactIdentity{}
		if hasProv {
			identity = output.ArtifactIdentity{URI: prov.SourceName, Size: prov.Size, SHA256: prov.SHA256}
		}
		// Always replace the report, even with zero findings. Otherwise a clean
		// rerun leaves yesterday's findings looking current.
		if err := output.WriteSARIF(outDir, findings, cli.Version, identity); err != nil {
			return nil, fmt.Errorf("write sarif: %w", err)
		}
		sarifPath := filepath.Join(outDir, "aotopsy.sarif")
		logf("  %s->%s %s%s%s (%d bytes, %d findings)\n", cli.Muted, cli.Reset, cli.Blue, sarifPath, cli.Reset, strutil.FileSize(sarifPath), len(findings))

		evidencePath := filepath.Join(outDir, "evidence.jsonl")
		dartVersion := ""
		if hasProv {
			dartVersion = prov.DartVersion
		}
		evCollector := evidence.NewCollector(dartVersion)
		evCollector.FromCallEdges(edges)
		evCollector.FromSignalFindings(findings)
		if err := evCollector.WriteJSONL(evidencePath); err != nil {
			return nil, fmt.Errorf("write evidence: %w", err)
		}
		logf("  %s->%s %s%s%s (%d bytes)\n", cli.Muted, cli.Reset, cli.Blue, evidencePath, cli.Reset, strutil.FileSize(evidencePath))
	}

	// Build connected signal CFG only when the producer recorded the binary
	// architecture. Legacy artifact directories can legitimately predate
	// provenance.json; guessing their decoder from instruction bytes is unsound
	// (short x86 functions can decode as plausible ARM64 words and vice versa).
	// The main signal graph/report remains reusable, while this optional
	// architecture-dependent artifact is omitted until provenance is available.
	if !noAsm && hasProv {
		content, err := BuildSignalContent(g, inDir, funcs, edges, artifactFiles, prov.Arch)
		if err != nil {
			return nil, err
		}
		if len(content) > 0 {
			cfgTitle := "signal CFG"
			if title != "" {
				cfgTitle = title + " signal CFG"
			}
			cfgDOT := render.SignalCFGDOT(g, content, cfgTitle, render.NASA)
			cfgPath := filepath.Join(outDir, "signal_cfg.dot")
			if err := output.WriteFileAtomic(cfgPath, []byte(cfgDOT), 0o644); err != nil {
				return nil, fmt.Errorf("write signal_cfg.dot: %w", err)
			}
			logf("  %s->%s %s%s%s (%d functions, %d bytes)\n",
				cli.Muted, cli.Reset, cli.Blue, cfgPath, cli.Reset, len(content), strutil.FileSize(cfgPath))
		}
	} else if !noAsm && !hasProv && g.Stats.SignalFuncs > 0 {
		warnf("legacy analysis has no provenance architecture; skipping connected signal CFG")
	}

	// Render SVG via dot if available.
	// Large DOT files (>1 MB) are skipped. dot's hierarchical layout is O(n^2)
	// and hangs on graphs with thousands of nodes. Use sfdp for large graphs.
	const dotTimeout = 120 * time.Second
	const largeDOTThreshold = 1 << 20 // 1 MB
	dotBin, err := exec.LookPath("dot")
	if err != nil {
		warnf("dot not found; install Graphviz for SVG (for example: brew install graphviz)")
	} else {
		dotFiles := []string{dotPath}
		cfgDotPath := filepath.Join(outDir, "signal_cfg.dot")
		if _, statErr := os.Stat(cfgDotPath); statErr == nil {
			dotFiles = append(dotFiles, cfgDotPath)
		}
		for _, df := range dotFiles {
			svgPath := strings.TrimSuffix(df, ".dot") + ".svg"
			dfSize := strutil.FileSize(df)
			if dfSize > largeDOTThreshold {
				warnf("skipping SVG for %s (%d KB), too large for dot",
					filepath.Base(df), dfSize/1024)
				logf("    render manually: %ssfdp -Tsvg -o %s %s%s\n",
					cli.Muted, filepath.Base(svgPath), filepath.Base(df), cli.Reset)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), dotTimeout)
			cmd := exec.CommandContext(ctx, dotBin, "-Tsvg", "-o", svgPath, df)
			out := cli.NewDiagnosticBuffer(cli.DefaultDiagnosticCaptureLimit)
			cmd.Stdout = out
			cmd.Stderr = out
			err := cmd.Run()
			cancel()
			if ctx.Err() == context.DeadlineExceeded {
				warnf("dot timed out after %v for %s", dotTimeout, filepath.Base(df))
				logf("    render manually: %ssfdp -Tsvg -o %s %s%s\n",
					cli.Muted, filepath.Base(svgPath), filepath.Base(df), cli.Reset)
			} else if err != nil {
				warnf("dot render failed for %s: %v: %s", filepath.Base(df), err, out.String())
			} else {
				logf("  %s->%s %s%s%s (%d bytes)\n", cli.Muted, cli.Reset, cli.Blue, svgPath, cli.Reset, strutil.FileSize(svgPath))
			}
		}
	}

	return &SignalResult{
		SignalCount:         g.Stats.SignalFuncs,
		ContextCount:        g.Stats.ContextFuncs,
		StaticRelationCount: g.Stats.StaticRelations,
		Findings:            findings,
	}, nil
}

// BuildSignalContent re-disassembles signal functions from bin files and extracts
// interesting calls and string refs for each function.
// arch is the provenance architecture ("arm64" or "x64"); it selects the
// decoder outright. This used to be guessed: decode every function as
// ARM64, and if not one instruction address lined up with a known call
// edge, assume x86_64 and redo it. That guess silently misfires on any
// function with no call edges at all, and it cost a full wasted ARM64
// decode of every x86_64 function. The pipeline knows the architecture,
// so it passes it.
func BuildSignalContent(
	g *signal.SignalGraph,
	inDir string,
	funcs []disasm.FuncRecord,
	edgeRecords []disasm.CallEdgeRecord,
	artifactFiles map[string]string,
	arch string,
) (map[string]*render.SignalFuncContent, error) {
	hasSignal := false
	for _, sf := range g.Funcs {
		if sf.Role == "signal" {
			hasSignal = true
			break
		}
	}
	if !hasSignal {
		return map[string]*render.SignalFuncContent{}, nil
	}
	if arch != "arm64" && arch != "x64" {
		return nil, fmt.Errorf("signal CFG: unsupported or unknown provenance architecture %q", arch)
	}
	edgesByFunc := make(map[string]map[uint64][]disasm.CallEdgeRecord)
	for _, er := range edgeRecords {
		pc, err := strutil.ParseHexAddr(er.FromPC)
		if err != nil {
			return nil, fmt.Errorf("signal CFG: malformed call-edge PC %q for %q: %w", er.FromPC, er.FromFunc, err)
		}
		byPC := edgesByFunc[er.FromFunc]
		if byPC == nil {
			byPC = make(map[uint64][]disasm.CallEdgeRecord)
			edgesByFunc[er.FromFunc] = byPC
		}
		byPC[pc] = append(byPC[pc], er)
	}

	funcByName := make(map[string]disasm.FuncRecord, len(funcs))
	for _, f := range funcs {
		funcByName[f.Name] = f
	}

	result := make(map[string]*render.SignalFuncContent)

	for _, sf := range g.Funcs {
		if sf.Role != "signal" {
			continue
		}
		fr, ok := funcByName[sf.Name]
		if !ok {
			continue
		}

		txtRel, ok := artifactFiles[sf.Name]
		if !ok {
			return nil, fmt.Errorf("signal CFG: no disassembly artifact for %q", sf.Name)
		}
		data, err := ReadFunctionBin(filepath.Join(inDir, "asm"), txtRel, fr.Size)
		if err != nil {
			return nil, fmt.Errorf("read function bytes for %s: %w", sf.Name, err)
		}
		if len(data) < 4 {
			return nil, fmt.Errorf("function bytes for %s are truncated: %d bytes", sf.Name, len(data))
		}

		baseAddr, err := strutil.ParseHexAddr(fr.PC)
		if err != nil {
			return nil, fmt.Errorf("signal CFG: malformed function PC %q for %q: %w", fr.PC, fr.Name, err)
		}

		edgeByPC := edgesByFunc[sf.Name]

		var instAddrs []uint64
		if arch == "x64" {
			for _, inst := range disasm.DecodeX86Simple(data, baseAddr) {
				instAddrs = append(instAddrs, inst.VA)
			}
		} else {
			for _, inst := range disasm.Disassemble(data, disasm.Options{BaseAddr: baseAddr}) {
				instAddrs = append(instAddrs, inst.Addr)
			}
		}
		if len(instAddrs) == 0 {
			continue
		}

		calls := staticSignalCalls(edgeByPC, instAddrs)

		seenStrs := make(map[string]bool)
		var strs []render.ClassifiedString
		for _, sr := range sf.StringRefs {
			if seenStrs[sr.Value] {
				continue
			}
			seenStrs[sr.Value] = true
			cat := ""
			if len(sr.Categories) > 0 {
				cat = sr.Categories[0]
			}
			strs = append(strs, render.ClassifiedString{Value: sr.Value, Category: cat, Confidence: sr.Confidence})
		}

		if len(calls) > 0 || len(strs) > 0 {
			result[sf.Name] = &render.SignalFuncContent{
				Calls:   calls,
				Strings: strs,
			}
		}
	}

	return result, nil
}

func staticSignalCalls(edgeByPC map[uint64][]disasm.CallEdgeRecord, instAddrs []uint64) []string {
	seen := make(map[string]bool)
	var calls []string
	for _, addr := range instAddrs {
		for _, e := range edgeByPC[addr] {
			// Static semantic targets only. Runtime observations remain a separate
			// evidence axis and must not be promoted into this call list.
			for _, callee := range e.ResolvedTargets() {
				if signal.IsInterestingCallee(callee) && !seen[callee] {
					seen[callee] = true
					calls = append(calls, callee)
				}
			}
		}
	}
	sort.Strings(calls)
	return calls
}
