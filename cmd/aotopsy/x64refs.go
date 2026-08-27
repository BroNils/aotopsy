package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/arch/x86/x86asm"

	"aotopsy/internal/arch"
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/disasm"
	"aotopsy/internal/pipeline"
)

// cmdX64Refs disassembles every function in an x86_64 libapp.so (using
// golang.org/x/arch/x86/x86asm, already a project dependency for a
// different reason) and reports which functions reference a given
// object-pool entry (by resolved display string, e.g. a header/field name
// string literal) via a
// [r15+disp] memory operand -- r15 is the Dart AOT x64 ABI's fixed
// object-pool-pointer register (confirmed against
// third_party_tools/blutter/blutter/src/Disassembler_x64.h: PP = R15,
// THR = R14).
//
// Why this exists: blutter's own x64 CodeAnalyzer/pool-annotation
// coverage is narrow (confirmed empirically: only 255/13309 functions in
// a full disasm run ever got a "[pp+0x...]" comment on ANY instruction),
// so searching its asm output for a given pool string is unreliable --
// absence of a match there does not mean absence in the real binary.
// aotopsy's own snapshot/cluster parsing already works cleanly on
// x86_64 (elfx.Open relaxed to accept EM_X86_64 -- see internal/elfx),
// so this reuses that same metadata layer (ranges, pool display map) and
// only adds a minimal, purpose-built x86_64 decode loop instead of
// depending on blutter's incomplete analyzer at all.
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

	sc, err := pipeline.LoadSnapshot(*libapp, opts)
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
		return dumpFuncDisasm(targetVA, ranges, code, codeOff, codeVA, pl, poolDisplay)
	}

	if *callersOfVA != "" {
		var targetVA uint64
		_, _ = fmt.Sscanf(*callersOfVA, "0x%x", &targetVA)
		if targetVA == 0 {
			_, _ = fmt.Sscanf(*callersOfVA, "%x", &targetVA)
		}
		return findCallersOf(targetVA, ranges, code, codeOff, codeVA, pl, *maxHits)
	}

	if *disasmByCodeIndex >= 0 {
		// Function.CodeIndex is 1-based for Dart >=2.16 (0=LazyCompile stub),
		// 0-based for <=2.15. CodeRange.Index is always 0-based (Code.ClusterIndex).
		// Convert the user-provided CodeIndex to 0-based for comparison.
		targetIdx := *disasmByCodeIndex
		if info.Version.CodeIndexOneBased {
			targetIdx = *disasmByCodeIndex - 1
		}
		for _, r := range ranges {
			if r.Index == targetIdx {
				var funcName string
				if r.RefID >= 0 {
					funcName = qualifiedCodeNameLocal(r.RefID, pl, r.PCOffset)
				} else {
					funcName = fmt.Sprintf("stub_%x", r.PCOffset)
				}
				funcStart := uint64(r.PCOffset) - codeOff
				funcVA := codeVA + funcStart
				fmt.Fprintf(os.Stderr, "resolved code index %d -> %s @ 0x%x\n", *disasmByCodeIndex, funcName, funcVA)
				return dumpFuncDisasm(funcVA, ranges, code, codeOff, codeVA, pl, poolDisplay)
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
		return scanHashShapedFunctions(ranges, code, codeOff, codeVA, pl, *hashScanMinOps)
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
			found := findRangeContainingVA(ranges, codeVA, codeOff, targetVA)
			if found != nil {
				scanRanges = append(scanRanges, *found)
			}
			if scanRanges == nil {
				return fmt.Errorf("no range contains VA 0x%x", targetVA)
			}
		}
		calls, err := scanIndirectCalls(scanRanges, code, codeOff, codeVA, pl, poolDisplay, *maxHits)
		if err != nil {
			return err
		}
		for _, c := range calls {
			fmt.Printf("%s @ 0x%x  [%s]  %s  ; %s\n", c.FuncName, c.Addr, c.Kind, c.Text, c.Detail)
		}
		fmt.Fprintf(os.Stderr, "total indirect call sites: %d\n", len(calls))
		return nil
	}

	hits := 0
	for _, r := range ranges {
		if r.Size == 0 {
			continue
		}
		funcStart := uint64(r.PCOffset) - codeOff
		funcEnd := funcStart + uint64(r.Size)
		if funcEnd > uint64(len(code)) {
			funcEnd = uint64(len(code))
		}
		if funcStart >= funcEnd {
			continue
		}
		funcCode := code[funcStart:funcEnd]
		funcVA := codeVA + funcStart

		var funcName string
		if r.RefID >= 0 {
			funcName = qualifiedCodeNameLocal(r.RefID, pl, r.PCOffset)
		} else {
			funcName = fmt.Sprintf("stub_%x", r.PCOffset)
		}

		capped := false
		arch.WalkX86(funcCode, funcVA, func(d arch.X86Decoded) bool {
			if !d.Bad {
				for _, arg := range d.Inst.Args {
					mem, ok := arg.(x86asm.Mem)
					if !ok || mem.Base != x86asm.R15 {
						continue
					}
					poolIdx, _ := disasm.X64PoolIndex(mem.Disp)
					display, resolved := poolDisplay[poolIdx]
					if !resolved {
						continue
					}
					if *find != "" && !strings.Contains(display, *find) {
						continue
					}
					fmt.Printf("%s @ 0x%x  pp_idx=%d  codeRef=%d  funcStartVA=0x%x  %q\n", funcName, d.VA, poolIdx, r.RefID, funcVA, display)
					hits++
				}
			}
			if *maxHits > 0 && hits >= *maxHits {
				fmt.Fprintf(os.Stderr, "stopping at --max=%d hits\n", *maxHits)
				capped = true
				return false
			}
			return true
		})
		if capped {
			return nil
		}
	}
	fmt.Fprintf(os.Stderr, "total hits: %d\n", hits)
	return nil
}

// dumpFuncDisasm finds the range containing targetVA and prints a full
// disassembly with [r15+disp]/[r14+disp] pool/thread annotations and
// CALL target resolution -- built specifically to find what a Dart
// function does immediately after loading a given pool string (e.g. the
// dispatch call right after a header/field-name string is loaded as a
// Map/getter key), the natural next step once blind register/memory
// dumping alone hits its limit.
func dumpFuncDisasm(targetVA uint64, ranges []cluster.CodeRange, code []byte, codeOff, codeVA uint64, pl *poolLookups, poolDisplay map[int]string) error {
	r := findRangeContainingVA(ranges, codeVA, codeOff, targetVA)
	if r == nil {
		return fmt.Errorf("no range contains VA 0x%x", targetVA)
	}
	funcStart := uint64(r.PCOffset) - codeOff
	funcEnd := funcStart + uint64(r.Size)
	if funcEnd > uint64(len(code)) {
		funcEnd = uint64(len(code))
	}
	funcVA := codeVA + funcStart
	var funcName string
	if r.RefID >= 0 {
		funcName = qualifiedCodeNameLocal(r.RefID, pl, r.PCOffset)
	} else {
		funcName = fmt.Sprintf("stub_%x", r.PCOffset)
	}
	fmt.Fprintf(os.Stderr, "found %s @ 0x%x, size=%d, target=0x%x\n", funcName, funcVA, r.Size, targetVA)

	funcCode := code[funcStart:funcEnd]
	arch.WalkX86(funcCode, funcVA, func(d arch.X86Decoded) bool {
		if d.Bad {
			fmt.Printf("0x%x: <decode error>\n", d.VA)
			return true
		}
		text := d.Inst.String()
		annotation := ""
		for _, arg := range d.Inst.Args {
			if mem, ok := arg.(x86asm.Mem); ok {
				if mem.Base == x86asm.R15 {
					poolIdx, _ := disasm.X64PoolIndex(mem.Disp)
					if disp, ok := poolDisplay[poolIdx]; ok {
						annotation = "  ; [pp+idx=" + fmt.Sprint(poolIdx) + "] " + disp
					} else {
						annotation = fmt.Sprintf("  ; [pp+idx=%d]", poolIdx)
					}
				} else if mem.Base == x86asm.R14 {
					annotation = fmt.Sprintf("  ; [THR+0x%x]", mem.Disp)
				}
			}
		}
		// Resolve JMP/Jcc/CALL rel targets to absolute VA -- added to
		// disambiguate whether a given address is reachable via normal
		// control flow or only via a jump/deopt-landing-pad from elsewhere.
		if target, ok := arch.X86RelTarget(d.Inst, d.VA, d.Len); ok {
			annotation += fmt.Sprintf("  ; -> 0x%x", target)
		}
		marker := "  "
		if d.VA == targetVA {
			marker = "->"
		}
		fmt.Printf("%s 0x%x: %s%s\n", marker, d.VA, text, annotation)
		return true
	})
	return nil
}

// findCallersOf scans every function in the binary for CALL rel32
// instructions targeting targetVA's entry point, printing the caller
// function + call-site address for each. Same per-range disassembly
// loop as the pool-string search (cmdX64Refs's main body) -- proven
// cheap (a couple of seconds for a whole binary) by reusing the
// identical iteration structure, just checking `inst.Op == x86asm.CALL`
// with a `x86asm.Rel` arg instead of a `x86asm.Mem` pool-offset arg.
// Built to trace one hop further up the call chain once a function's
// own callers (not callees) are needed -- e.g. finding what calls a
// serializer function, to locate where one of its arguments gets
// constructed.
func findCallersOf(targetVA uint64, ranges []cluster.CodeRange, code []byte, codeOff, codeVA uint64, pl *poolLookups, maxHits int) error {
	hits := 0
	for _, r := range ranges {
		if r.Size == 0 {
			continue
		}
		funcStart := uint64(r.PCOffset) - codeOff
		funcEnd := funcStart + uint64(r.Size)
		if funcEnd > uint64(len(code)) {
			funcEnd = uint64(len(code))
		}
		if funcStart >= funcEnd {
			continue
		}
		funcCode := code[funcStart:funcEnd]
		funcVA := codeVA + funcStart

		var funcName string
		if r.RefID >= 0 {
			funcName = qualifiedCodeNameLocal(r.RefID, pl, r.PCOffset)
		} else {
			funcName = fmt.Sprintf("stub_%x", r.PCOffset)
		}

		capped := false
		arch.WalkX86(funcCode, funcVA, func(d arch.X86Decoded) bool {
			if !d.Bad && d.Inst.Op == x86asm.CALL {
				if target, ok := arch.X86RelTarget(d.Inst, d.VA, d.Len); ok && target == targetVA {
					fmt.Printf("%s @ 0x%x  calls target\n", funcName, d.VA)
					hits++
				}
			}
			if maxHits > 0 && hits >= maxHits {
				fmt.Fprintf(os.Stderr, "stopping at --max=%d hits\n", maxHits)
				capped = true
				return false
			}
			return true
		})
		if capped {
			return nil
		}
	}
	fmt.Fprintf(os.Stderr, "total callers of 0x%x: %d\n", targetVA, hits)
	return nil
}

// hashShapedOp reports whether op is one of the bitwise/arithmetic
// instructions a hand-rolled or compiled SHA-256/HMAC round is built from
// (Ch/Maj/sigma = XOR+AND+OR+NOT+ROR chains; the compression loop's word
// addition is unsigned ADD, not Dart's normal boxed-Smi add path). This
// same instruction-density signature is what actually locates hand-rolled
// crypto in plain native (non-Dart) code too -- searching for this shape
// directly is generally more productive than following object/Map/
// dispatch call chains hoping to land on it by accident.
func hashShapedOp(op x86asm.Op) bool {
	switch op {
	case x86asm.XOR, x86asm.ROL, x86asm.ROR, x86asm.ADD, x86asm.ADC,
		x86asm.AND, x86asm.OR, x86asm.NOT, x86asm.SHL, x86asm.SHR,
		x86asm.PXOR, x86asm.XORPD, x86asm.XORPS:
		return true
	default:
		return false
	}
}

type hashScanResult struct {
	funcName  string
	funcVA    uint64
	size      uint32
	hashOps   int
	rotateOps int
	total     int
}

// scanHashShapedFunctions walks every function in the binary and counts
// hash/bitwise-shaped instructions vs. total instructions, ranking
// candidates by raw hash-op count (a real SHA-256 compression round has
// dozens of XOR/ROR/AND/ADD per 64-byte block, run in a loop -- structurally
// unlike anything found in this investigation so far, which has all been
// Dart object/Map/dispatch plumbing with near-zero raw bitwise arithmetic).
func scanHashShapedFunctions(ranges []cluster.CodeRange, code []byte, codeOff, codeVA uint64, pl *poolLookups, minOps int) error {
	var results []hashScanResult
	for _, r := range ranges {
		if r.Size == 0 {
			continue
		}
		funcStart := uint64(r.PCOffset) - codeOff
		funcEnd := funcStart + uint64(r.Size)
		if funcEnd > uint64(len(code)) {
			funcEnd = uint64(len(code))
		}
		if funcStart >= funcEnd {
			continue
		}
		funcCode := code[funcStart:funcEnd]
		funcVA := codeVA + funcStart

		hashOps := 0
		rotateOps := 0
		total := 0
		arch.WalkX86(funcCode, funcVA, func(d arch.X86Decoded) bool {
			if d.Bad {
				return true
			}
			total++
			if hashShapedOp(d.Inst.Op) {
				hashOps++
			}
			if d.Inst.Op == x86asm.ROL || d.Inst.Op == x86asm.ROR {
				rotateOps++
			}
			return true
		})
		if hashOps < minOps {
			continue
		}
		var funcName string
		if r.RefID >= 0 {
			funcName = qualifiedCodeNameLocal(r.RefID, pl, r.PCOffset)
		} else {
			funcName = fmt.Sprintf("stub_%x", r.PCOffset)
		}
		results = append(results, hashScanResult{funcName, funcVA, r.Size, hashOps, rotateOps, total})
	}

	// ROL/ROR are near-exclusively used for hash/crypto/bit-rotation code --
	// unlike XOR/AND/SHR, which are also pervasive in ordinary Dart AOT
	// Smi-tag-check/masking idioms (confirmed by inspecting the top
	// XOR/AND/SHR-ranked hit this scan found: a 20KB media-recorder error-
	// handling function with a single incidental "XOR EAX,EAX" zero-init,
	// not a hash loop at all). Rank by rotate-op count first as the more
	// selective signal, falling back to raw hashOps for functions with zero
	// rotates (still shown, just deprioritized).
	sort.Slice(results, func(i, j int) bool {
		if results[i].rotateOps != results[j].rotateOps {
			return results[i].rotateOps > results[j].rotateOps
		}
		return results[i].hashOps > results[j].hashOps
	})

	for _, res := range results {
		density := float64(res.hashOps) / float64(res.total)
		fmt.Printf("%s @ 0x%x  size=%d  hashOps=%d  rotateOps=%d  totalInstrs=%d  density=%.2f\n",
			res.funcName, res.funcVA, res.size, res.hashOps, res.rotateOps, res.total, density)
	}
	fmt.Fprintf(os.Stderr, "total functions with >= %d hash-shaped ops: %d\n", minOps, len(results))
	return nil
}

// qualifiedCodeNameLocal mirrors pipeline.QualifiedCodeName without importing
// the pipeline package's disasm-stage machinery (this command is intentionally
// standalone -- see file header). Uses ci.Qualified() so constructor names
// are handled correctly (no owner prefix duplication).
func qualifiedCodeNameLocal(refID int, pl *poolLookups, pcOffset uint32) string {
	ci := pl.CodeNames[refID]
	return ci.Qualified(pcOffset)
}
