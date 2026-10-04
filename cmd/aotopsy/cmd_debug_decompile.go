package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cli"
	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/frida"
	"aotopsy/internal/output"
)

// cmdDecompileNative implements "aotopsy _debug decompile-native" for Dart-AOT-aware pseudocode generation.
func cmdDecompileNative(args []string) error {
	fs := flag.NewFlagSet("decompile-native", flag.ContinueOnError)
	libapp := fs.String("lib", "", "path to libapp.so (ARM64 or x86_64)")
	funcVAStr := fs.String("func", "", "hex VA of any address inside the target function")
	all := fs.Bool("all", false, "decompile every function, writing one combined.dart file under --out")
	fromMain := fs.Bool("from-main", false, "decompile the app's own code reachable from its main() entry point")
	genFrida := fs.Bool("gen-frida", false, "also emit a ready-to-run Frida script")
	genFridaOut := fs.String("gen-frida-out", "", "output path for the generated Frida script")
	genFridaStalker := fs.Bool("gen-frida-stalker", false, "add Stalker call tracing to the --gen-frida script")
	genFridaStalkerMin := fs.Int("gen-frida-stalker-min", 10, "with --gen-frida-stalker, suppress call targets seen fewer than this many times")
	findSubstr := fs.String("find", "", "list VA + resolved name for every function whose name contains this substring")
	outDir := fs.String("out", "", "output directory for --all mode")
	maxFuncs := fs.Int("max", 500, "max functions to emit in --all mode (0 = unlimited)")
	skipFuncs := fs.Int("skip", 0, "skip this many matching functions before starting to emit")
	maxStepsFlag := fs.Int("max-steps", 0, "override the per-function emitter step budget")
	filterSubstr := fs.String("filter", "", "modifier for --all ONLY: restricts --all to functions whose name contains this substring")
	strict := fs.Bool("strict", false, "abort on the first function that cannot be decompiled (default: skip it and list it in "+analysis.DecompileFailuresFile+")")
	if err := parseNoPositionals(fs, args); err != nil {
		return err
	}
	for name, value := range map[string]int{
		"max":                   *maxFuncs,
		"skip":                  *skipFuncs,
		"max-steps":             *maxStepsFlag,
		"gen-frida-stalker-min": *genFridaStalkerMin,
	} {
		if err := requireNonNegativeFlag(name, value); err != nil {
			return err
		}
	}
	if *libapp == "" {
		return fmt.Errorf("--lib is required")
	}
	actions := 0
	if *funcVAStr != "" {
		actions++
	}
	if *findSubstr != "" {
		actions++
	}
	if *all {
		actions++
	}
	if *fromMain {
		actions++
	}
	if actions != 1 {
		return fmt.Errorf("exactly one of --func <hex VA>, --find <substring>, --all, or --from-main is required")
	}
	if *filterSubstr != "" && !*all {
		return fmt.Errorf("--filter only applies to --all (did you mean --all --filter %q?)", *filterSubstr)
	}
	if *skipFuncs != 0 && !*all {
		return fmt.Errorf("--skip only applies to --all")
	}
	if flagWasSet(fs, "max") && !*all && !*fromMain {
		return fmt.Errorf("--max only applies to --all/--from-main")
	}
	if *outDir != "" && !*all && !*fromMain {
		return fmt.Errorf("--out only applies to --all/--from-main")
	}
	if *strict && !*all && !*fromMain {
		return fmt.Errorf("--strict only applies to --all/--from-main")
	}
	if *findSubstr != "" && *genFrida {
		return fmt.Errorf("--gen-frida cannot be used with --find because --find only lists matches")
	}
	if !*genFrida && (*genFridaOut != "" || *genFridaStalker || flagWasSet(fs, "gen-frida-stalker-min")) {
		return fmt.Errorf("--gen-frida-out/--gen-frida-stalker options require --gen-frida")
	}
	decompiler.SetMaxStepsPerEmitter(*maxStepsFlag)

	deps, err := analysis.BuildDecompileNativeDeps(*libapp)
	if err != nil {
		return err
	}
	defer func() { _ = deps.Ctx.Close() }()

	if *findSubstr != "" {
		hits := analysis.FindFunctionsByName(deps.SymbolNames, deps.SymbolSizes, *findSubstr)
		cli.Errf("%d match(es) for %q among %d functions\n", hits, *findSubstr, len(deps.SymbolNames))
		return nil
	}

	if !*all && !*fromMain {
		targetVA, err := parseHexAddress("func", *funcVAStr)
		if err != nil {
			return err
		}
		found := cluster.FindRangeContainingVA(deps.Ctx.Ranges, deps.Ctx.CodeVA, deps.Ctx.CodeOff, targetVA)
		if found == nil {
			return fmt.Errorf("no CodeRange contains VA 0x%x", targetVA)
		}
		fir, art, err := deps.DecompileRangeWithIR(*found)
		if err != nil {
			return err
		}
		fmt.Println(art.Source)
		statsData, _ := json.MarshalIndent(art.Stats, "", "  ")
		cli.Errf("stats: %s\n", statsData)
		if *genFrida {
			if err := analysis.EmitSingleFuncFrida(*libapp, deps.IsARM64, fir, art, targetVA, *genFridaOut,
				frida.FridaOptions{Stalker: *genFridaStalker, StalkerMinCalls: *genFridaStalkerMin}); err != nil {
				return err
			}
		}
		return nil
	}

	if *outDir == "" {
		return fmt.Errorf("--out is required with --all/--from-main")
	}
	containsSource, err := output.ContainsPath(*outDir, *libapp)
	if err != nil {
		return fmt.Errorf("compare decompile output/source paths: %w", err)
	}
	if containsSource {
		return fmt.Errorf("decompile output directory must not contain the source binary")
	}
	if *genFrida && *genFridaOut != "" {
		if err := validateBatchFridaOutput(*outDir, *genFridaOut); err != nil {
			return err
		}
	}
	tx, err := output.BeginDirTransaction(*outDir)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			tx.Abort()
		}
	}()
	stageDir := tx.StageDir()
	combinedPath := filepath.Join(stageDir, "combined.dart")
	stagedFridaOut := ""
	if *genFridaOut != "" {
		stagedFridaOut = output.RebasePath(*genFridaOut, *outDir, stageDir)
		insideStage, err := output.ContainsPath(stageDir, stagedFridaOut)
		if err != nil || !insideStage {
			return fmt.Errorf("rebase batch Frida output into staging generation")
		}
	}

	const gcEveryN = 250
	startTime := time.Now()
	debugTrace := os.Getenv("AOTOPSY_DEBUG_TRACE") != ""

	runBatch := func(w *bufio.Writer) error {
		if *fromMain {
			return analysis.RunFromMain(analysis.FromMainDeps{
				Ranges:                    deps.Ctx.Ranges,
				CodeOff:                   deps.Ctx.CodeOff,
				CodeVA:                    deps.Ctx.CodeVA,
				SymbolNames:               deps.SymbolNames,
				BuildFuncIR:               deps.BuildFuncIR,
				CallTargetsOf:             decompiler.CallTargetsOf,
				LibraryURLForCodeRef:      deps.LibraryURLForCodeRef,
				LibraryURLForClassRef:     deps.LibraryURLForClassRef,
				IsFrameworkLibraryURL:     deps.IsFrameworkLibraryURL,
				FunctionsByOwnerClassRef:  deps.FunctionsByOwnerClassRef,
				ClassRefTouchedByPoolLoad: deps.ClassRefTouchedByPoolLoad,
				SymbolLookup:              deps.SymbolLookup,
				PoolLookup:                deps.PoolLookup,
				MaxFuncs:                  *maxFuncs,
				W:                         w,
				CombinedPath:              combinedPath,
				DebugTrace:                debugTrace,
				GcEveryN:                  gcEveryN,
				StartTime:                 startTime,
				IsARM64:                   deps.IsARM64,
				GenFrida:                  *genFrida,
				GenFridaOut:               stagedFridaOut,
				FridaOpts:                 frida.FridaOptions{Stalker: *genFridaStalker, StalkerMinCalls: *genFridaStalkerMin},
				LibPath:                   *libapp,
				OutDir:                    stageDir,
				Strict:                    *strict,
			})
		}

		return analysis.RunDecompileLoop(analysis.DecompLoopDeps{
			Ranges:               deps.Ctx.Ranges,
			CodeOff:              deps.Ctx.CodeOff,
			CodeVA:               deps.Ctx.CodeVA,
			SymbolNames:          deps.SymbolNames,
			FilterSubstr:         *filterSubstr,
			SkipFuncs:            *skipFuncs,
			MaxFuncs:             *maxFuncs,
			DebugTrace:           debugTrace,
			DecompileRangeWithIR: deps.DecompileRangeWithIR,
			W:                    w,
			CombinedPath:         combinedPath,
			GcEveryN:             gcEveryN,
			StartTime:            startTime,
			Pl:                   deps.Ctx.Pool,
			GenFrida:             *genFrida,
			GenFridaOut:          stagedFridaOut,
			OutDir:               stageDir,
			Libapp:               *libapp,
			IsARM64:              deps.IsARM64,
			GenFridaStalker:      *genFridaStalker,
			GenFridaStalkerMin:   *genFridaStalkerMin,
			Strict:               *strict,
		})
	}
	if err := output.WriteAtomic(combinedPath, 0o644, func(dst io.Writer) error {
		w := bufio.NewWriterSize(dst, 256*1024)
		if err := runBatch(w); err != nil {
			return err
		}
		return w.Flush()
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func validateBatchFridaOutput(outDir, fridaOut string) error {
	inside, err := output.ContainsPath(outDir, fridaOut)
	if err != nil {
		return fmt.Errorf("compare batch Frida/output paths: %w", err)
	}
	if !inside {
		return fmt.Errorf("--gen-frida-out must be inside --out in batch mode so the generation can publish atomically")
	}
	sameRoot, err := output.SamePath(outDir, fridaOut)
	if err != nil {
		return fmt.Errorf("compare batch Frida/output directory: %w", err)
	}
	if sameRoot {
		return fmt.Errorf("--gen-frida-out must name a file inside --out, not the output directory itself")
	}
	for _, managed := range []string{"combined.dart", analysis.DecompileFailuresFile, output.GenerationMarker} {
		reserved := filepath.Join(outDir, managed)
		same, err := output.SamePath(fridaOut, reserved)
		if err != nil {
			return fmt.Errorf("compare batch Frida output with managed artifact %s: %w", managed, err)
		}
		if same {
			return fmt.Errorf("--gen-frida-out must not replace managed batch artifact %s", managed)
		}
	}
	return nil
}
