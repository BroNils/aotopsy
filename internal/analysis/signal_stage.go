package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"aotopsy/internal/cli"
	"aotopsy/internal/disasm"
	"aotopsy/internal/evidence"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/naming"
	"aotopsy/internal/output"
	"aotopsy/internal/render"
	"aotopsy/internal/signal"
	"aotopsy/internal/strutil"
)

// SignalResult holds summary stats from the signal stage.
type SignalResult struct {
	SignalCount  int
	ContextCount int
	EdgeCount    int
	// Findings are returned so the pipeline can fold them into the single
	// evidence collector. The stage writes its own evidence.jsonl only on
	// the standalone path, where nothing downstream will.
	Findings []output.SignalFinding
}

// RunSignalStage runs the signal analysis on existing disasm output.
// writeEvidence tells the stage to emit evidence.jsonl itself. The full
// pipeline passes false and writes a richer one at step 9; the standalone
// `aotopsy signal` and --from-dir paths pass true, because nothing else
// will.
// libPath is the analysed binary, used to name and hash the SARIF
// artifact. The standalone entry points pass "" -- they are handed an
// output directory and genuinely do not know which binary produced it,
// and no artifact records it. WriteSARIF degrades to a placeholder name
// rather than inventing one.
func RunSignalStage(inDir string, k int, noAsm bool, quiet bool, log io.Writer, writeEvidence bool, libPath string) (*SignalResult, error) {
	if log == nil {
		log = os.Stderr
	}
	logf := cli.MakeLogf(quiet, log)
	stagef := cli.MakeStagef(quiet, log)

	// snapshot.json is what the pipeline leaves behind describing the
	// binary this directory came from: its name, hash, and architecture.
	// Read once here; three separate call sites used to re-read it.
	prov, hasProv := ReadProvenance(inDir)

	// Read functions.jsonl.
	funcs, err := jsonutil.ReadJSONL[disasm.FuncRecord](filepath.Join(inDir, "functions.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("read functions.jsonl: %w", err)
	}

	// Read call_edges.jsonl.
	edges, err := jsonutil.ReadJSONL[disasm.CallEdgeRecord](filepath.Join(inDir, "call_edges.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("read call_edges.jsonl: %w", err)
	}

	// Read string_refs.jsonl.
	stringRefs, err := jsonutil.ReadJSONL[disasm.StringRefRecord](filepath.Join(inDir, "string_refs.jsonl"))
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
	if err := signal.WriteSignalExpansionJSONL(inDir, sigStringRefs); err != nil {
		logf("  signal expansion: %v\n", err)
	}

	// Compute entry points.
	entryList := render.FindEntryPoints(funcs, edges)
	entrySet := make(map[string]bool, len(entryList))
	for _, ep := range entryList {
		entrySet[ep] = true
	}

	// Build signal graph.
	g := signal.BuildSignalGraph(funcs, edges, stringRefs, k, entrySet)
	stagef("signal", "%s%d%s signal + %s%d%s context, %s%d%s edges",
		cli.Gold, g.Stats.SignalFuncs, cli.Reset,
		cli.Gold, g.Stats.ContextFuncs, cli.Reset,
		cli.Gold, g.Stats.TotalEdges, cli.Reset)
	for cat, count := range g.Stats.Categories {
		logf("  %s%s:%s %d\n", cli.Muted, cat, cli.Reset, count)
	}

	// Load asm snippets.
	const contextAsmLines = 30
	asmSnippets := make(map[string]string)
	if !noAsm {
		asmDir := filepath.Join(inDir, "asm")
		for _, sf := range g.Funcs {
			if sf.Role == "" {
				continue
			}
			relPath := naming.FuncRelPathFromQualified(sf.Name, sf.Owner)
			path := filepath.Join(asmDir, relPath+".txt")
			data, err := os.ReadFile(path)
			if err != nil {
				flatPath := filepath.Join(asmDir, strutil.SanitizeFilename(sf.Name)+".txt")
				data, err = os.ReadFile(flatPath)
				if err != nil {
					continue
				}
			}
			s := strings.TrimRight(string(data), "\n")
			if sf.Role == "context" {
				lines := strings.SplitN(s, "\n", contextAsmLines+1)
				if len(lines) > contextAsmLines {
					s = strings.Join(lines[:contextAsmLines], "\n") + "\n[... truncated]"
				}
			}
			asmSnippets[sf.Name] = s
		}
		logf("  %sasm snippets:%s %d\n", cli.Muted, cli.Reset, len(asmSnippets))
	}

	// Write signal_graph.json.
	outPath := filepath.Join(inDir, "signal.html")
	jsonPath := filepath.Join(inDir, "signal_graph.json")
	jsonFile, err := os.Create(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("create signal_graph.json: %w", err)
	}
	enc := json.NewEncoder(jsonFile)
	enc.SetIndent("", "  ")
	if err := enc.Encode(g); err != nil {
		_ = jsonFile.Close()
		return nil, fmt.Errorf("write signal_graph.json: %w", err)
	}
	_ = jsonFile.Close()
	logf("  %s->%s %s%s%s (%d bytes)\n", cli.Muted, cli.Reset, cli.Blue, jsonPath, cli.Reset, strutil.FileSize(jsonPath))

	// Write signal.html.
	htmlFile, err := os.Create(outPath)
	if err != nil {
		return nil, fmt.Errorf("create signal.html: %w", err)
	}
	title := "aotopsy"
	digest := filepath.Base(filepath.Dir(inDir))
	filename := inDir
	// This read a "meta.json" from the PARENT of the output directory.
	// Nothing ever wrote that file -- one reader, zero writers -- so the
	// lookup always failed and the report named itself after its own
	// output directory. The pipeline writes snapshot.json now.
	if hasProv {
		filename = prov.SourceName
		if prov.SHA256 != "" {
			digest = prov.SHA256
		}
	}
	render.WriteSignalHTML(htmlFile, g, title, filename, digest, asmSnippets)
	if err := htmlFile.Close(); err != nil {
		return nil, fmt.Errorf("close signal.html: %w", err)
	}
	logf("  %s->%s %s%s%s (%d bytes)\n", cli.Muted, cli.Reset, cli.Blue, outPath, cli.Reset, strutil.FileSize(outPath))

	// Write signal.dot.
	dotPath := filepath.Join(inDir, "signal.dot")
	dotContent := render.SignalDOT(g, title, render.NASA)
	if err := os.WriteFile(dotPath, []byte(dotContent), 0644); err != nil {
		return nil, fmt.Errorf("write signal.dot: %w", err)
	}
	logf("  %s->%s %s%s%s (%d bytes)\n", cli.Muted, cli.Reset, cli.Blue, dotPath, cli.Reset, strutil.FileSize(dotPath))

	// Write SARIF report.
	var findings []output.SignalFinding
	for _, sf := range g.Funcs {
		// String-based findings
		for _, ref := range sf.StringRefs {
			for _, cat := range ref.Categories {
				findings = append(findings, output.SignalFinding{
					Category:    cat,
					StringValue: ref.Value,
					Function:    sf.Name,
					PC:          ref.PC,
				})
			}
		}
		// Category-based findings (e.g. THR calls) without string refs
		if len(sf.StringRefs) == 0 && len(sf.Categories) > 0 {
			for _, cat := range sf.Categories {
				findings = append(findings, output.SignalFinding{
					Category:    cat,
					StringValue: "",
					Function:    sf.Name,
					PC:          sf.PC,
				})
			}
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
				Category:    signal.CatObfuscation,
				StringValue: fmt.Sprintf("%.0f%% of %d identifier-like strings look obfuscated", ratio*100, considered),
			})
		}
	}

	if len(findings) > 0 {
		// The standalone entry points hand us no binary path; recover it
		// from the provenance record the pipeline left behind, so a
		// `aotopsy signal --in <dir>` report still names the file it is
		// about.
		sarifLib := libPath
		if sarifLib == "" && hasProv {
			sarifLib = prov.Source
		}
		if err := output.WriteSARIF(inDir, findings, "1.0.0", sarifLib); err != nil {
			logf("  %swarning: sarif: %v%s\n", cli.Gold, err, cli.Reset)
		} else {
			sarifPath := filepath.Join(inDir, "aotopsy.sarif")
			logf("  %s->%s %s%s%s (%d bytes, %d findings)\n", cli.Muted, cli.Reset, cli.Blue, sarifPath, cli.Reset, strutil.FileSize(sarifPath), len(findings))
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
		evidencePath := filepath.Join(inDir, "evidence.jsonl")
		evCollector := evidence.NewCollector()
		evCollector.FromCallEdges(edges)
		evCollector.FromSignalFindings(findings)
		if err := evCollector.WriteJSONL(evidencePath); err != nil {
			logf("  %swarning: evidence: %v%s\n", cli.Gold, err, cli.Reset)
		} else {
			logf("  %s->%s %s%s%s (%d bytes)\n", cli.Muted, cli.Reset, cli.Blue, evidencePath, cli.Reset, strutil.FileSize(evidencePath))
		}
	}

	// Build connected signal CFG.
	if !noAsm {
		content := BuildSignalContent(g, inDir, funcs, edges, prov.Arch)
		if len(content) > 0 {
			cfgTitle := "signal CFG"
			if title != "" {
				cfgTitle = title + " signal CFG"
			}
			cfgDOT := render.SignalCFGDOT(g, content, cfgTitle, render.NASA)
			cfgPath := filepath.Join(inDir, "signal_cfg.dot")
			if err := os.WriteFile(cfgPath, []byte(cfgDOT), 0644); err != nil {
				return nil, fmt.Errorf("write signal_cfg.dot: %w", err)
			}
			logf("  %s->%s %s%s%s (%d functions, %d bytes)\n",
				cli.Muted, cli.Reset, cli.Blue, cfgPath, cli.Reset, len(content), strutil.FileSize(cfgPath))
		}
	}

	// Render SVG via dot if available.
	// Large DOT files (>1 MB) are skipped. dot's hierarchical layout is O(n^2)
	// and hangs on graphs with thousands of nodes. Use sfdp for large graphs.
	const dotTimeout = 120 * time.Second
	const largeDOTThreshold = 1 << 20 // 1 MB
	dotBin, err := exec.LookPath("dot")
	if err != nil {
		logf("  %s!%s dot not found, install Graphviz for SVG: %sbrew install graphviz%s\n",
			cli.Red, cli.Reset, cli.Gold, cli.Reset)
	} else {
		dotFiles := []string{dotPath}
		cfgDotPath := filepath.Join(inDir, "signal_cfg.dot")
		if _, statErr := os.Stat(cfgDotPath); statErr == nil {
			dotFiles = append(dotFiles, cfgDotPath)
		}
		for _, df := range dotFiles {
			svgPath := strings.TrimSuffix(df, ".dot") + ".svg"
			dfSize := strutil.FileSize(df)
			if dfSize > largeDOTThreshold {
				logf("  %s!%s skipping SVG for %s (%d KB), too large for dot\n",
					cli.Red, cli.Reset, filepath.Base(df), dfSize/1024)
				logf("    render manually: %ssfdp -Tsvg -o %s %s%s\n",
					cli.Muted, filepath.Base(svgPath), filepath.Base(df), cli.Reset)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), dotTimeout)
			cmd := exec.CommandContext(ctx, dotBin, "-Tsvg", "-o", svgPath, df)
			out, err := cmd.CombinedOutput()
			cancel()
			if ctx.Err() == context.DeadlineExceeded {
				logf("  %s!%s dot timed out after %v for %s\n",
					cli.Red, cli.Reset, dotTimeout, filepath.Base(df))
				logf("    render manually: %ssfdp -Tsvg -o %s %s%s\n",
					cli.Muted, filepath.Base(svgPath), filepath.Base(df), cli.Reset)
			} else if err != nil {
				logf("  %s!%s dot render failed for %s: %v\n%s\n", cli.Red, cli.Reset, filepath.Base(df), err, out)
			} else {
				logf("  %s->%s %s%s%s (%d bytes)\n", cli.Muted, cli.Reset, cli.Blue, svgPath, cli.Reset, strutil.FileSize(svgPath))
			}
		}
	}

	return &SignalResult{
		SignalCount:  g.Stats.SignalFuncs,
		ContextCount: g.Stats.ContextFuncs,
		EdgeCount:    g.Stats.TotalEdges,
		Findings:     findings,
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
	arch string,
) map[string]*render.SignalFuncContent {
	edgesByFunc := make(map[string][]disasm.CallEdge)
	for _, er := range edgeRecords {
		pc := strutil.ParseHexAddr(er.FromPC)
		ce := disasm.CallEdge{
			FromPC:     pc,
			Kind:       er.Kind,
			TargetName: er.Target,
			TargetPC:   strutil.ParseHexAddr(er.Target),
			Via:        er.Via,
		}
		edgesByFunc[er.FromFunc] = append(edgesByFunc[er.FromFunc], ce)
	}

	funcByName := make(map[string]disasm.FuncRecord, len(funcs))
	for _, f := range funcs {
		funcByName[f.Name] = f
	}

	asmDir := filepath.Join(inDir, "asm")
	result := make(map[string]*render.SignalFuncContent)

	for _, sf := range g.Funcs {
		if sf.Role != "signal" {
			continue
		}
		fr, ok := funcByName[sf.Name]
		if !ok {
			continue
		}

		relPath := naming.FuncRelPathFromQualified(sf.Name, sf.Owner)
		binPath := filepath.Join(asmDir, relPath+".bin")
		data, err := os.ReadFile(binPath)
		if err != nil {
			binPath = filepath.Join(asmDir, strutil.SanitizeFilename(sf.Name)+".bin")
			data, err = os.ReadFile(binPath)
		}
		if err != nil || len(data) < 4 {
			continue
		}

		baseAddr := strutil.ParseHexAddr(fr.PC)
		if baseAddr == 0 {
			continue
		}

		funcEdges := edgesByFunc[sf.Name]
		edgeByPC := make(map[uint64]disasm.CallEdge, len(funcEdges))
		for _, e := range funcEdges {
			edgeByPC[e.FromPC] = e
		}

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

		seenCalls := make(map[string]bool)
		var calls []string
		for _, addr := range instAddrs {
			if e, ok := edgeByPC[addr]; ok {
				callee := e.TargetName
				if callee == "" {
					callee = e.Via
				}
				if signal.IsInterestingCallee(callee) && !seenCalls[callee] {
					seenCalls[callee] = true
					calls = append(calls, callee)
				}
			}
		}

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
			strs = append(strs, render.ClassifiedString{Value: sr.Value, Category: cat})
		}

		if len(calls) > 0 || len(strs) > 0 {
			result[sf.Name] = &render.SignalFuncContent{
				Calls:   calls,
				Strings: strs,
			}
		}
	}

	return result
}
