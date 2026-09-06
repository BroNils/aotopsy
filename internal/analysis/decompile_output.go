package analysis

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"

	"aotopsy/internal/decompiler"
	"aotopsy/internal/frida"
)

// AggregateStats folds one function's per-artifact Stats into the
// running aggregate.
//
// Every field of decompiler.Stats is an int counter, so this sums them all
// by reflection rather than by a hand-written list. The list version had
// silently dropped OrphanBlocks and the stack-map counter: a new field
// reported zero forever and looked like "the feature does nothing" instead
// of "nobody added a line here". Reflection makes forgetting impossible;
// the guard below turns a future non-int field into a loud test failure
// rather than a silently ignored one.
func AggregateStats(agg *decompiler.Stats, s decompiler.Stats) {
	dst := reflect.ValueOf(agg).Elem()
	src := reflect.ValueOf(s)
	for i := 0; i < src.NumField(); i++ {
		f := src.Field(i)
		if f.Kind() != reflect.Int {
			panic("AggregateStats: decompiler.Stats." + src.Type().Field(i).Name +
				" is not an int; teach this function how to fold it")
		}
		dst.Field(i).SetInt(dst.Field(i).Int() + f.Int())
	}
}

// EmitSingleFuncFrida generates and writes a Frida script for the
// single-function (--func) mode.
func EmitSingleFuncFrida(libPath string, isARM64 bool, fir *decompiler.FuncIR, art decompiler.Artifact, targetVA uint64, genFridaOut string, opts frida.FridaOptions) error {
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

// FinalizeFridaOutput writes the Frida script at the end of a batch
// (--all / --from-main) run.
func FinalizeFridaOutput(genFridaOut, outDir, libPath string, isARM64 bool, hooks []frida.FridaHook, probes []frida.FridaProbe, probesDropped int, opts frida.FridaOptions) error {
	if probesDropped > 0 {
		fmt.Fprintf(os.Stderr, "--gen-frida: %d indirect-call probe(s) dropped past the %d cap (maxFridaProbes) -- rerun with --filter/--func on a narrower target to see the rest\n", probesDropped, frida.MaxFridaProbes)
	}
	return frida.WriteFridaScript(genFridaOut, outDir, libPath, isARM64, hooks, probes, opts)
}

// PrintAggregateStats marshals and prints the aggregate stats to stderr.
func PrintAggregateStats(agg decompiler.Stats) {
	statsData, _ := json.MarshalIndent(agg, "", "  ")
	fmt.Fprintf(os.Stderr, "aggregate stats: %s\n", statsData)
}
