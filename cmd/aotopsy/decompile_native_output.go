package main

import (
	"encoding/json"
	"fmt"
	"os"

	"aotopsy/internal/decompiler"
	"aotopsy/internal/frida"
)

// aggregateStats folds one function's per-artifact Stats into the
// running aggregate. Extracted from the inline fold that was
// duplicated between --all's loop (decompile_native_loop.go) and
// --from-main's loop (decompile_native_from_main.go) -- the two
// copies had already drifted once (three fields were missing from
// --all's fold, reporting 0 for try_blocks / catch_handlers /
// non_last_branch no matter what the per-function artifacts said),
// so centralizing the fold prevents a third copy from drifting too.
func aggregateStats(agg *decompiler.Stats, s decompiler.Stats) {
	agg.TotalCalls += s.TotalCalls
	agg.IndirectCalls += s.IndirectCalls
	agg.SemanticDirectCalls += s.SemanticDirectCalls
	agg.SemanticIndirectCalls += s.SemanticIndirectCalls
	agg.PlaceholderIfs += s.PlaceholderIfs
	agg.UnresolvedCF += s.UnresolvedCF
	agg.RawRegisterCalls += s.RawRegisterCalls
	agg.NonLastBranch += s.NonLastBranch
	agg.TryBlocks += s.TryBlocks
	agg.CatchHandlers += s.CatchHandlers
}

// emitSingleFuncFrida generates and writes a Frida script for the
// single-function (--func) mode. If genFridaOut is empty the script
// is printed to stdout after the pseudocode; otherwise it is written
// to the named file.
func emitSingleFuncFrida(libPath string, isARM64 bool, fir *decompiler.FuncIR, art decompiler.Artifact, targetVA uint64, genFridaOut string, opts frida.FridaOptions) error {
	hook := frida.FridaHook{VA: targetVA, Name: art.FunctionName, ArgRegs: frida.RealArgRegs(fir)}
	probes := frida.CollectIndirectCallProbes(fir)
	script := frida.GenerateFridaScriptWithOptions(libPath, isARM64, []frida.FridaHook{hook}, probes, opts)
	if genFridaOut == "" {
		fmt.Println("\n// --- Frida script (--gen-frida) ---")
		fmt.Println(script)
	} else if err := os.WriteFile(genFridaOut, []byte(script), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", genFridaOut, err)
	} else {
		fmt.Fprintf(os.Stderr, "Frida script written to %s\n", genFridaOut)
	}
	return nil
}

// finalizeFridaOutput writes the Frida script at the end of a batch
// (--all / --from-main) run, logging how many indirect-call probes
// were dropped past the cap if any.
func finalizeFridaOutput(genFridaOut, outDir, libPath string, isARM64 bool, hooks []frida.FridaHook, probes []frida.FridaProbe, probesDropped int, opts frida.FridaOptions) error {
	if probesDropped > 0 {
		fmt.Fprintf(os.Stderr, "--gen-frida: %d indirect-call probe(s) dropped past the %d cap (maxFridaProbes) -- rerun with --filter/--func on a narrower target to see the rest\n", probesDropped, frida.MaxFridaProbes)
	}
	return frida.WriteFridaScript(genFridaOut, outDir, libPath, isARM64, hooks, probes, opts)
}

// printAggregateStats marshals and prints the aggregate stats to stderr.
func printAggregateStats(agg decompiler.Stats) {
	statsData, _ := json.MarshalIndent(agg, "", "  ")
	fmt.Fprintf(os.Stderr, "aggregate stats: %s\n", statsData)
}
