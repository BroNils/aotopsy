package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"aotopsy/internal/analysis"
	"aotopsy/internal/disasm"
	"aotopsy/internal/jsonutil"
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

	// Read functions.jsonl.
	funcs, err := jsonutil.ReadJSONL[disasm.FuncRecord](filepath.Join(*inDir, "functions.jsonl"))
	if err != nil {
		return fmt.Errorf("read functions.jsonl: %w", err)
	}
	fmt.Fprintf(os.Stderr, "read %d functions\n", len(funcs))

	// Read call_edges.jsonl.
	edges, err := jsonutil.ReadJSONL[disasm.CallEdgeRecord](filepath.Join(*inDir, "call_edges.jsonl"))
	if err != nil {
		return fmt.Errorf("read call_edges.jsonl: %w", err)
	}
	fmt.Fprintf(os.Stderr, "read %d call edges\n", len(edges))

	// Read unresolved_thr.jsonl (optional).
	unresTHRPath := filepath.Join(*inDir, "unresolved_thr.jsonl")
	var unresTHR []disasm.UnresolvedTHRRecord
	if _, err := os.Stat(unresTHRPath); err == nil {
		unresTHR, err = jsonutil.ReadJSONL[disasm.UnresolvedTHRRecord](unresTHRPath)
		if err != nil {
			return fmt.Errorf("read unresolved_thr.jsonl: %w", err)
		}
		fmt.Fprintf(os.Stderr, "read %d unresolved THR records\n", len(unresTHR))
	}

	// Create render output directory.
	renderDir := filepath.Join(*inDir, "render")
	if err := os.MkdirAll(renderDir, 0o755); err != nil {
		return fmt.Errorf("mkdir render: %w", err)
	}

	// Compute stats.
	stats := render.ComputeStats(funcs, edges)

	// Compute reachability.
	entryPoints := render.FindEntryPoints(funcs, edges)
	reachable := render.ReachableSet(entryPoints, edges)
	fmt.Fprintf(os.Stderr, "entry points: %d, reachable functions: %d / %d\n",
		len(entryPoints), len(reachable), len(funcs))

	// Generate reachability DOT.
	reachDOT := render.ReachabilityDOT(funcs, edges, reachable, entryPoints,
		*title+" (reachable)", render.NASA)
	reachDotPath := filepath.Join(renderDir, "reachable.dot")
	if err := os.WriteFile(reachDotPath, []byte(reachDOT), 0o644); err != nil {
		return fmt.Errorf("write reachable.dot: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", reachDotPath, len(reachDOT))

	// Generate callgraph DOT.
	dot := render.CallgraphDOT(funcs, edges, *title, render.NASA, *maxNodes)
	dotPath := filepath.Join(renderDir, "callgraph.dot")
	if err := os.WriteFile(dotPath, []byte(dot), 0o644); err != nil {
		return fmt.Errorf("write callgraph.dot: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", dotPath, len(dot))

	// Generate classgraph DOT.
	classDOT := render.ClassgraphDOT(funcs, edges, *title+" (class level)", render.NASA, *maxNodes)
	classDotPath := filepath.Join(renderDir, "classgraph.dot")
	if err := os.WriteFile(classDotPath, []byte(classDOT), 0o644); err != nil {
		return fmt.Errorf("write classgraph.dot: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", classDotPath, len(classDOT))

	// Generate SVGs via graphviz dot.
	hasCallgraphSVG := false
	hasClassgraphSVG := false
	hasReachableSVG := false
	if !*noDot {
		svgPath := filepath.Join(renderDir, "callgraph.svg")
		if err := runDot(dotPath, svgPath, "svg"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: callgraph SVG failed: %v (use --no-dot to skip)\n", err)
		} else {
			hasCallgraphSVG = true
			fi, _ := os.Stat(svgPath)
			fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", svgPath, fi.Size())
		}

		classSvgPath := filepath.Join(renderDir, "classgraph.svg")
		if err := runDot(classDotPath, classSvgPath, "svg"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: classgraph SVG failed: %v\n", err)
		} else {
			hasClassgraphSVG = true
			fi, _ := os.Stat(classSvgPath)
			fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", classSvgPath, fi.Size())
		}

		reachSvgPath := filepath.Join(renderDir, "reachable.svg")
		if err := runDot(reachDotPath, reachSvgPath, "svg"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: reachable SVG failed: %v\n", err)
		} else {
			hasReachableSVG = true
			fi, _ := os.Stat(reachSvgPath)
			fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", reachSvgPath, fi.Size())
		}
	}

	// Generate per-function CFGs if --cfg and asm directory exists.
	var cfgFuncs int
	if *cfgFlag {
		if _, err := os.Stat(*asmDir); err != nil {
			fmt.Fprintf(os.Stderr, "warning: --cfg requires asm directory at %s\n", *asmDir)
		} else {
			cfgDir := filepath.Join(renderDir, "cfg")
			if err := os.MkdirAll(cfgDir, 0o755); err != nil {
				return fmt.Errorf("mkdir cfg: %w", err)
			}
			cfgFuncs, err = generateCFGs(funcs, reachable, *asmDir, cfgDir, !*noDot)
			if err != nil {
				return fmt.Errorf("generate CFGs: %w", err)
			}
			fmt.Fprintf(os.Stderr, "generated %d CFGs in %s\n", cfgFuncs, cfgDir)
		}
	}

	// Generate index.html.
	htmlPath := filepath.Join(renderDir, "index.html")
	htmlFile, err := os.Create(htmlPath)
	if err != nil {
		return fmt.Errorf("create index.html: %w", err)
	}
	render.WriteIndexHTML(htmlFile, stats, unresTHR, *title,
		hasCallgraphSVG, hasClassgraphSVG, hasReachableSVG,
		entryPoints, len(reachable), cfgFuncs)
	if err := htmlFile.Close(); err != nil {
		return fmt.Errorf("close index.html: %w", err)
	}
	fi, _ := os.Stat(htmlPath)
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", htmlPath, fi.Size())

	return nil
}

func generateCFGs(funcs []disasm.FuncRecord, reachable map[string]bool, asmDir, cfgDir string, genSVG bool) (int, error) {
	count := 0
	for _, f := range funcs {
		if !reachable[f.Name] {
			continue
		}
		if strings.HasPrefix(f.Name, "sub_") {
			continue
		}

		safeName := strutil.SanitizeFilename(f.Name)
		binPath := filepath.Join(asmDir, safeName+".bin")
		data, err := os.ReadFile(binPath)
		if err != nil {
			continue
		}
		if len(data) < 4 {
			continue
		}

		pc, err := strconv.ParseUint(strings.TrimPrefix(f.PC, "0x"), 16, 64)
		if err != nil {
			continue
		}

		insts := decodeRawInsts(data, pc)
		if len(insts) == 0 {
			continue
		}

		cfg := disasm.BuildCFG(f.Name, insts)
		if len(cfg.Blocks) == 0 {
			continue
		}

		dot := render.CFGDOT(cfg, render.NASA)
		dotPath := filepath.Join(cfgDir, safeName+".dot")
		if err := os.WriteFile(dotPath, []byte(dot), 0o644); err != nil {
			return count, fmt.Errorf("write %s: %w", dotPath, err)
		}

		if genSVG {
			svgPath := filepath.Join(cfgDir, safeName+".svg")
			if err := runDot(dotPath, svgPath, "svg"); err != nil {
				fmt.Fprintf(os.Stderr, "  warning: CFG SVG failed for %s: %v\n", f.Name, err)
			}
		}
		count++
	}
	return count, nil
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

func runDot(dotPath, outPath, format string) error {
	cmd := exec.Command("dot", "-T"+format, "-o", outPath, dotPath)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
