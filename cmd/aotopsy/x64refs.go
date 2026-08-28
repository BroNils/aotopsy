package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/frida"
)

func cmdX64Refs(args []string) error {
	fs := flag.NewFlagSet("x64refs", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so (x86_64)")
	find := fs.String("find", "", "substring to search for in resolved pool-entry display strings (case-sensitive); empty = dump all pool refs found")
	maxHits := fs.Int("max", 200, "stop after this many matches (0 = unlimited)")
	disasmFuncVA := fs.String("disasm-func", "", "hex VA (e.g. 0x25a7ac4) of any address inside a function; dumps the full disassembly of that function with pool annotations")
	callersOfVA := fs.String("callers-of", "", "hex VA of a function's ENTRY point; scans the whole binary for CALL rel32 instructions targeting it and prints the caller function + address")
	indirectCalls := fs.Bool("indirect-calls", false, "scan the whole binary for CALL sites with a Reg/Mem operand (never a Rel) -- classifies GDT (dispatch-table) calls and pool-sourced indirect calls, both invisible to --callers-of's direct-call-only scan")
	indirectInFunc := fs.String("indirect-calls-in", "", "hex VA of any address inside a function; restrict --indirect-calls to just that one function")
	cidName := fs.Int("cid-name", -1, "resolve a class id (decimal, e.g. from a live GDT-call RCX capture) to its Dart class name via the snapshot's class cluster")
	disasmByCodeIndex := fs.Int("disasm-by-code-index", -1, "Function.CodeIndex (from refinfo --siblings-of-owner) to disassemble -- resolves to a CodeRange by its cluster Index and dumps like --disasm-func")
	hashScan := fs.Bool("hash-scan", false, "scan every function for XOR/ROL/ROR/ADD/AND/OR/NOT/SHL/SHR instruction density (a 'hash-shaped' loop) -- a heuristic for locating a hand-rolled or compiled hash/HMAC round; empirically, most positional hits turn out to be object/Map/dispatch plumbing rather than actual crypto, so treat matches as candidates to inspect, not confirmed hits")
	hashScanMinOps := fs.Int("hash-scan-min-ops", 8, "minimum hash-op count for a function to be reported by --hash-scan")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *libapp == "" {
		return fmt.Errorf("--lib is required")
	}

	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}

	sc, err := analysis.LoadSnapshot(*libapp, opts)
	if err != nil {
		return err
	}
	defer func() { _ = sc.Close() }()

	info := sc.Info
	result := sc.Result
	ranges := sc.Ranges
	code := sc.Code
	codeOff := sc.CodeOff
	codeVA := sc.CodeVA
	pl := sc.Pool
	poolDisplay := sc.PoolDisplay

	fmt.Fprintf(os.Stderr, "Dart SDK version: %s\n", info.Version.DartVersion)
	fmt.Fprintf(os.Stderr, "ranges: %d, pool: %d entries (%d resolved)\n", len(ranges), len(result.Pool), len(poolDisplay))

	if *disasmFuncVA != "" {
		var targetVA uint64
		_, _ = fmt.Sscanf(*disasmFuncVA, "0x%x", &targetVA)
		if targetVA == 0 {
			_, _ = fmt.Sscanf(*disasmFuncVA, "%x", &targetVA)
		}
		return analysis.DumpFuncDisasm(targetVA, ranges, code, codeOff, codeVA, pl, poolDisplay)
	}

	if *callersOfVA != "" {
		var targetVA uint64
		_, _ = fmt.Sscanf(*callersOfVA, "0x%x", &targetVA)
		if targetVA == 0 {
			_, _ = fmt.Sscanf(*callersOfVA, "%x", &targetVA)
		}
		return analysis.FindCallersOf(targetVA, ranges, code, codeOff, codeVA, pl, *maxHits)
	}

	if *disasmByCodeIndex >= 0 {
		targetIdx := *disasmByCodeIndex
		if info.Version.CodeIndexOneBased {
			targetIdx = *disasmByCodeIndex - 1
		}
		for _, r := range ranges {
			if r.Index == targetIdx {
				var funcName string
				if r.RefID >= 0 {
					funcName = analysis.QualifiedCodeNameLocal(r.RefID, pl, r.PCOffset)
				} else {
					funcName = fmt.Sprintf("stub_%x", r.PCOffset)
				}
				funcStart := uint64(r.PCOffset) - codeOff
				funcVA := codeVA + funcStart
				fmt.Fprintf(os.Stderr, "resolved code index %d -> %s @ 0x%x\n", *disasmByCodeIndex, funcName, funcVA)
				return analysis.DumpFuncDisasm(funcVA, ranges, code, codeOff, codeVA, pl, poolDisplay)
			}
		}
		return fmt.Errorf("no CodeRange with Index==%d", targetIdx)
	}

	if *cidName >= 0 {
		found := false
		for _, ci := range result.Classes {
			if int(ci.ClassID) == *cidName {
				name := "<unnamed>"
				if s, ok := pl.RefToStr[ci.NameRefID]; ok {
					name = s
				}
				fmt.Printf("cid=%d -> %q (instanceSize=%d, nameRefID=%d)\n", *cidName, name, ci.InstanceSize, ci.NameRefID)
				found = true
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "cid=%d not found in class cluster (%d classes total) -- may be a predefined/VM cid, not an app class\n", *cidName, len(result.Classes))
		}
		return nil
	}

	if *hashScan {
		return analysis.ScanHashShapedFunctions(ranges, code, codeOff, codeVA, pl, *hashScanMinOps)
	}

	if *indirectCalls || *indirectInFunc != "" {
		scanRanges := ranges
		if *indirectInFunc != "" {
			var targetVA uint64
			_, _ = fmt.Sscanf(*indirectInFunc, "0x%x", &targetVA)
			if targetVA == 0 {
				_, _ = fmt.Sscanf(*indirectInFunc, "%x", &targetVA)
			}
			scanRanges = nil
			found := cluster.FindRangeContainingVA(ranges, codeVA, codeOff, targetVA)
			if found != nil {
				scanRanges = append(scanRanges, *found)
			}
			if scanRanges == nil {
				return fmt.Errorf("no range contains VA 0x%x", targetVA)
			}
		}
		calls, err := frida.ScanIndirectCalls(scanRanges, code, codeOff, codeVA, pl, poolDisplay, *maxHits)
		if err != nil {
			return err
		}
		for _, c := range calls {
			fmt.Printf("%s @ 0x%x  [%s]  %s  ; %s\n", c.FuncName, c.Addr, c.Kind, c.Text, c.Detail)
		}
		fmt.Fprintf(os.Stderr, "total indirect call sites: %d\n", len(calls))
		return nil
	}

	return analysis.ScanPoolRefs(ranges, code, codeOff, codeVA, pl, poolDisplay, *find, *maxHits)
}

// suppress unused import warning
var _ = strings.Split
