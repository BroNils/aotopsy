package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cli"
	"aotopsy/internal/disasm"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/output"
	"aotopsy/internal/render"
	"aotopsy/internal/strutil"
)

// cmdGraph implements "aotopsy _debug graph" for extracting named object graphs.
func cmdGraph(args []string) error {
	fs := flag.NewFlagSet("graph", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	which := fs.String("which", "isolate", "which snapshot: vm, isolate, or both")
	outDir := fs.String("out", "", "output directory for JSONL files")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *libapp == "" {
		return fmt.Errorf("--lib is required")
	}
	if *outDir == "" {
		return fmt.Errorf("--out is required")
	}

	return analysis.RunGraph(*libapp, *outDir, *which, *maxSteps)
}

// cmdRender implements "aotopsy _debug render" for rendering DOT and HTML from JSONL output.
func cmdRender(args []string) error {
	fs := flag.NewFlagSet("render", flag.ExitOnError)
	inDir := fs.String("in", "", "input directory (disasm output)")
	maxNodes := fs.Int("max-nodes", 0, "max function nodes in callgraph (0 = all)")
	title := fs.String("title", "", "title for callgraph and HTML (auto-detected from dir name)")
	noDot := fs.Bool("no-dot", true, "skip SVG generation (dot not required)")
	cfgFlag := fs.Bool("cfg", false, "generate per-function CFGs for reachable functions")
	asmDir := fs.String("asm", "", "directory with per-function .bin files (defaults to <in>/asm)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inDir == "" {
		return fmt.Errorf("--in is required")
	}

	if *title == "" {
		*title = "aotopsy"
	}
	if *asmDir == "" {
		*asmDir = filepath.Join(*inDir, "asm")
	}
	logger := cli.NewLogger(os.Stderr, false)

	// Read functions.jsonl.
	funcs, err := jsonutil.ReadJSONL[disasm.FuncRecord](filepath.Join(*inDir, "functions.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		return fmt.Errorf("read functions.jsonl: %w", err)
	}
	logger.Printf("read %d functions\n", len(funcs))
	index, err := jsonutil.ReadJSONL[strutil.DisasmIndexEntry](filepath.Join(*inDir, "index.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		return fmt.Errorf("read index.jsonl: %w", err)
	}
	artifactFiles, err := analysis.DisasmArtifactFiles(funcs, index)
	if err != nil {
		return err
	}

	// Read call_edges.jsonl.
	edges, err := jsonutil.ReadJSONL[disasm.CallEdgeRecord](filepath.Join(*inDir, "call_edges.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		return fmt.Errorf("read call_edges.jsonl: %w", err)
	}
	logger.Printf("read %d call edges\n", len(edges))

	// Read unresolved_thr.jsonl (optional).
	unresTHRPath := filepath.Join(*inDir, "unresolved_thr.jsonl")
	var unresTHR []disasm.UnresolvedTHRRecord
	if _, err := os.Stat(unresTHRPath); err == nil {
		unresTHR, err = jsonutil.ReadJSONL[disasm.UnresolvedTHRRecord](unresTHRPath, jsonutil.StandardLimits)
		if err != nil {
			return fmt.Errorf("read unresolved_thr.jsonl: %w", err)
		}
		logger.Printf("read %d unresolved THR records\n", len(unresTHR))
	}

	finalRenderDir := filepath.Join(*inDir, "render")
	tx, err := output.BeginDirTransaction(finalRenderDir)
	if err != nil {
		return fmt.Errorf("begin render generation: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Abort()
		}
	}()
	renderDir := tx.StageDir()

	// Compute stats.
	stats := render.ComputeStats(funcs, edges)

	// Compute reachability.
	rootCandidates := render.FindRootCandidates(funcs, edges)
	reach := render.ReachableSet(funcs, rootCandidates, edges)
	logger.Printf("static root candidates: %d, known functions in structural closure: %d / %d\n",
		len(rootCandidates), len(reach.Functions), stats.TotalFunctions)
	if reach.IncompletePolymorphicSites > 0 || reach.UnknownCandidateCountSites > 0 || reach.UnresolvedIndirectSites > 0 {
		logger.Printf("  reachability lower-bound gaps: %d incomplete polymorphic, %d unknown candidate-count, %d unresolved indirect site(s)\n",
			reach.IncompletePolymorphicSites, reach.UnknownCandidateCountSites, reach.UnresolvedIndirectSites)
	}

	// Generate reachability DOT.
	reachDOT := render.ReachabilityDOT(funcs, edges, reach, rootCandidates,
		*title+" (static structural closure)", render.NASA)
	reachDotPath := filepath.Join(renderDir, "reachable.dot")
	if err := output.WriteArtifactFile(renderDir, "reachable.dot", []byte(reachDOT), 0o644); err != nil {
		return fmt.Errorf("write reachable.dot: %w", err)
	}
	logger.Printf("wrote %s (%d bytes)\n", reachDotPath, len(reachDOT))

	// Generate callgraph DOT.
	dot := render.CallgraphDOT(funcs, edges, *title, render.NASA, *maxNodes)
	dotPath := filepath.Join(renderDir, "callgraph.dot")
	if err := output.WriteArtifactFile(renderDir, "callgraph.dot", []byte(dot), 0o644); err != nil {
		return fmt.Errorf("write callgraph.dot: %w", err)
	}
	logger.Printf("wrote %s (%d bytes)\n", dotPath, len(dot))

	// Generate classgraph DOT.
	classDOT := render.ClassgraphDOT(funcs, edges, *title+" (class level)", render.NASA, *maxNodes)
	classDotPath := filepath.Join(renderDir, "classgraph.dot")
	if err := output.WriteArtifactFile(renderDir, "classgraph.dot", []byte(classDOT), 0o644); err != nil {
		return fmt.Errorf("write classgraph.dot: %w", err)
	}
	logger.Printf("wrote %s (%d bytes)\n", classDotPath, len(classDOT))

	// Generate SVGs via graphviz dot.
	hasCallgraphSVG := false
	hasClassgraphSVG := false
	hasReachableSVG := false
	if !*noDot {
		svgPath := filepath.Join(renderDir, "callgraph.svg")
		stderr, err := runDot(dotPath, svgPath, "svg")
		if err != nil {
			warnDotFailure(logger, "callgraph SVG", err, stderr, " (use --no-dot to skip)")
		} else {
			warnDotOutput(logger, "callgraph SVG", stderr)
			hasCallgraphSVG = true
			fi, _ := os.Stat(svgPath)
			logger.Printf("wrote %s (%d bytes)\n", svgPath, fi.Size())
		}

		classSvgPath := filepath.Join(renderDir, "classgraph.svg")
		stderr, err = runDot(classDotPath, classSvgPath, "svg")
		if err != nil {
			warnDotFailure(logger, "classgraph SVG", err, stderr, "")
		} else {
			warnDotOutput(logger, "classgraph SVG", stderr)
			hasClassgraphSVG = true
			fi, _ := os.Stat(classSvgPath)
			logger.Printf("wrote %s (%d bytes)\n", classSvgPath, fi.Size())
		}

		reachSvgPath := filepath.Join(renderDir, "reachable.svg")
		stderr, err = runDot(reachDotPath, reachSvgPath, "svg")
		if err != nil {
			warnDotFailure(logger, "reachable SVG", err, stderr, "")
		} else {
			warnDotOutput(logger, "reachable SVG", stderr)
			hasReachableSVG = true
			fi, _ := os.Stat(reachSvgPath)
			logger.Printf("wrote %s (%d bytes)\n", reachSvgPath, fi.Size())
		}
	}

	// Generate per-function CFGs if --cfg and asm directory exists.
	var cfgFuncs int
	cfgLinks := make(map[string]string)
	if *cfgFlag {
		prov, ok, err := analysis.ReadProvenance(*inDir)
		if err != nil {
			return fmt.Errorf("read provenance for CFG architecture: %w", err)
		}
		if !ok || (prov.Arch != "arm64" && prov.Arch != "x64") {
			return fmt.Errorf("--cfg requires provenance.json with arch arm64 or x64")
		}
		if _, err := os.Stat(*asmDir); err != nil {
			logger.Warn("--cfg requires asm directory at %s", *asmDir)
		} else {
			cfgDir := filepath.Join(renderDir, "cfg")
			if err := os.MkdirAll(cfgDir, 0o755); err != nil {
				return fmt.Errorf("mkdir cfg: %w", err)
			}
			cfgFuncs, cfgLinks, err = generateCFGs(logger, funcs, edges, reach.Functions, artifactFiles, *asmDir, cfgDir, prov.Arch, !*noDot)
			if err != nil {
				return fmt.Errorf("generate CFGs: %w", err)
			}
			logger.Printf("generated %d CFGs in %s\n", cfgFuncs, cfgDir)
		}
	}

	// Generate index.html.
	htmlPath := filepath.Join(renderDir, "index.html")
	if err := output.WriteAtomic(htmlPath, 0o644, func(w io.Writer) error {
		return render.WriteIndexHTML(w, stats, unresTHR, *title,
			hasCallgraphSVG, hasClassgraphSVG, hasReachableSVG,
			rootCandidates, reach, cfgFuncs, cfgLinks)
	}); err != nil {
		return fmt.Errorf("write index.html: %w", err)
	}
	fi, _ := os.Stat(htmlPath)
	logger.Printf("wrote %s (%d bytes)\n", htmlPath, fi.Size())
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("publish render generation: %w", err)
	}
	committed = true

	return nil
}

func generateCFGs(logger *cli.Logger, funcs []disasm.FuncRecord, edges []disasm.CallEdgeRecord, reachable map[string]bool, artifactFiles map[string]string, asmDir, cfgDir, arch string, genSVG bool) (int, map[string]string, error) {
	// Call edges bucketed by caller, so each CFG can be drawn with the
	// callees of that function rather than of the whole binary.
	edgesByFunc := make(map[string][]disasm.CallEdgeRecord, len(funcs))
	for _, e := range edges {
		edgesByFunc[e.FromFunc] = append(edgesByFunc[e.FromFunc], e)
	}
	count := 0
	cfgLinks := make(map[string]string)
	for _, f := range funcs {
		if !reachable[f.Name] {
			continue
		}
		if strings.HasPrefix(f.Name, "sub_") {
			continue
		}

		txtRel, ok := artifactFiles[f.Name]
		if !ok {
			return count, cfgLinks, fmt.Errorf("no canonical disassembly artifact for %q", f.Name)
		}
		data, err := analysis.ReadFunctionBin(asmDir, txtRel, f.Size)
		if err != nil {
			return count, cfgLinks, fmt.Errorf("read function bytes for %s: %w", f.Name, err)
		}
		if len(data) == 0 {
			continue
		}

		pc, err := strconv.ParseUint(strings.TrimPrefix(f.PC, "0x"), 16, 64)
		if err != nil {
			return count, cfgLinks, fmt.Errorf("parse function pc %q for %s: %w", f.PC, f.Name, err)
		}

		var cfg disasm.FuncCFG
		switch arch {
		case "arm64":
			if len(data)%4 != 0 {
				return count, cfgLinks, fmt.Errorf("ARM64 function %s has non-word byte length %d", f.Name, len(data))
			}
			insts := decodeRawInsts(data, pc)
			cfg = disasm.BuildCFG(f.Name, insts)
		case "x64":
			cfg = disasm.BuildX86CFG(f.Name, data, pc)
		default:
			return count, cfgLinks, fmt.Errorf("unsupported CFG architecture %q", arch)
		}
		if len(cfg.Blocks) == 0 {
			continue
		}

		dot := render.CFGDOT(cfg, edgesByFunc[f.Name], render.NASA)
		underAsm, err := filepath.Rel("asm", txtRel)
		if err != nil || underAsm == "." || underAsm == ".." || strings.HasPrefix(underAsm, ".."+string(filepath.Separator)) {
			return count, cfgLinks, fmt.Errorf("canonical artifact %q escapes asm root", txtRel)
		}
		dotRel := strings.TrimSuffix(underAsm, filepath.Ext(underAsm)) + ".dot"
		dotPath := filepath.Join(cfgDir, dotRel)
		if err := output.WriteArtifactFile(cfgDir, filepath.ToSlash(dotRel), []byte(dot), 0o644); err != nil {
			return count, cfgLinks, fmt.Errorf("write %s: %w", dotPath, err)
		}

		if genSVG {
			svgPath := strings.TrimSuffix(dotPath, filepath.Ext(dotPath)) + ".svg"
			stderr, err := runDot(dotPath, svgPath, "svg")
			if err != nil {
				warnDotFailure(logger, "CFG SVG for "+f.Name, err, stderr, "")
			} else {
				warnDotOutput(logger, "CFG SVG for "+f.Name, stderr)
				svgRel := strings.TrimSuffix(dotRel, filepath.Ext(dotRel)) + ".svg"
				cfgLinks[f.Name] = filepath.ToSlash(filepath.Join("cfg", svgRel))
			}
		}
		count++
	}
	return count, cfgLinks, nil
}

func decodeRawInsts(data []byte, baseAddr uint64) []disasm.Inst {
	n := len(data) / 4
	insts := make([]disasm.Inst, 0, n)
	for i := 0; i < n; i++ {
		raw := binary.LittleEndian.Uint32(data[i*4:])
		addr := baseAddr + uint64(i*4)
		inst := disasm.Inst{
			Addr: addr,
			Raw:  raw,
			Size: 4,
			Text: fmt.Sprintf(".word 0x%08x", raw),
		}
		text := disasm.DisasmOne(raw)
		if text != "" {
			inst.Text = text
		}
		insts = append(insts, inst)
	}
	return insts
}

func runDot(dotPath, outPath, format string) (string, error) {
	cmd := exec.Command("dot", "-T"+format, "-o", outPath, dotPath)
	stderr := cli.NewDiagnosticBuffer(cli.DefaultDiagnosticCaptureLimit)
	cmd.Stderr = stderr
	err := cmd.Run()
	return stderr.String(), err
}

func warnDotFailure(logger *cli.Logger, label string, err error, stderr, suffix string) {
	if stderr == "" {
		logger.Warn("%s failed: %v%s", label, err, suffix)
		return
	}
	logger.Warn("%s failed: %v: %s%s", label, err, stderr, suffix)
}

func warnDotOutput(logger *cli.Logger, label, stderr string) {
	if stderr != "" {
		logger.Warn("%s: %s", label, stderr)
	}
}
