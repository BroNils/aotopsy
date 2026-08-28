package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/frida"
)

func cmdDecompileNative(args []string) error {
	fs := flag.NewFlagSet("decompile-native", flag.ExitOnError)
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	decompiler.SetMaxStepsPerEmitter(*maxStepsFlag)
	if *libapp == "" {
		return fmt.Errorf("--lib is required")
	}
	if *funcVAStr == "" && !*all && !*fromMain && *findSubstr == "" {
		return fmt.Errorf("--func <hex VA>, --find <substring>, --all, or --from-main is required")
	}
	if *all && *fromMain {
		return fmt.Errorf("--all and --from-main are mutually exclusive -- pick one traversal mode")
	}
	if *filterSubstr != "" && !*all {
		return fmt.Errorf("--filter only applies to --all (did you mean --all --filter %q?)", *filterSubstr)
	}

	deps, err := analysis.BuildDecompileNativeDeps(*libapp)
	if err != nil {
		return err
	}
	defer func() { _ = deps.Ctx.Close() }()

	if *findSubstr != "" {
		hits := analysis.FindFunctionsByName(deps.SymbolNames, deps.SymbolSizes, *findSubstr)
		fmt.Fprintf(os.Stderr, "%d match(es) for %q among %d functions\n", hits, *findSubstr, len(deps.SymbolNames))
		return nil
	}

	if !*all && !*fromMain {
		var targetVA uint64
		_, scanErr := fmt.Sscanf(*funcVAStr, "0x%x", &targetVA)
		if scanErr != nil || targetVA == 0 {
			if _, err := fmt.Sscanf(*funcVAStr, "%x", &targetVA); err != nil || targetVA == 0 {
				return fmt.Errorf("--func %q: not a valid hex address", *funcVAStr)
			}
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
		fmt.Fprintf(os.Stderr, "stats: %s\n", statsData)
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
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", *outDir, err)
	}

	runtime.GOMAXPROCS(2)
	debug.SetMemoryLimit(1536 << 20)

	combinedPath := filepath.Join(*outDir, "combined.dart")
	outFile, err := os.Create(combinedPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", combinedPath, err)
	}
	defer func() { _ = outFile.Close() }()
	w := bufio.NewWriterSize(outFile, 256*1024)

	const gcEveryN = 250
	startTime := time.Now()
	debugTrace := os.Getenv("AOTOPSY_DEBUG_TRACE") != ""

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
			GenFridaOut:               *genFridaOut,
			FridaOpts:                 frida.FridaOptions{Stalker: *genFridaStalker, StalkerMinCalls: *genFridaStalkerMin},
			LibPath:                   *libapp,
			OutDir:                    *outDir,
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
		GenFridaOut:          *genFridaOut,
		OutDir:               *outDir,
		Libapp:               *libapp,
		IsARM64:              deps.IsARM64,
		GenFridaStalker:      *genFridaStalker,
		GenFridaStalkerMin:   *genFridaStalkerMin,
	})
}

// suppress unused import warning
var _ = strings.Split
