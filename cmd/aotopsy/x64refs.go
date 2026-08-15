package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/arch/x86/x86asm"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/disasm"
	"aotopsy/internal/elfx"
	"aotopsy/internal/pipeline"
	"aotopsy/internal/snapshot"
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

	ef, err := elfx.Open(*libapp)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = ef.Close() }()

	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Dart SDK version: %s\n", info.Version.DartVersion)

	data := info.IsolateData.Data
	clusterStart, err := cluster.FindClusterDataStart(data)
	if err != nil {
		return fmt.Errorf("cluster start: %w", err)
	}
	result, err := cluster.ScanClusters(data, clusterStart, info.Version, false, opts)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	if err := cluster.ReadFill(data, result, info.Version, false, info.IsolateHeader.TotalSize); err != nil {
		return fmt.Errorf("fill: %w", err)
	}

	table, err := cluster.ParseInstructionsTable(data, &result.Header, info.Version, info.IsolateHeader)
	var ranges []cluster.CodeRange
	if err != nil && result.Header.InstructionTableDataOffset == 0 && info.Version.CodeTextOffsetDelta {
		ranges = cluster.ResolveCodeRangesFromTextOffset(result.Codes)
	} else if err != nil {
		return fmt.Errorf("instrtable: %w", err)
	} else {
		codeRanges, err := cluster.ResolveCodeRanges(result.Codes, table)
		if err != nil {
			return fmt.Errorf("code ranges: %w", err)
		}
		stubRanges := cluster.ResolveStubRanges(table)
		ranges = cluster.MergeRanges(stubRanges, codeRanges)
	}

	code, codeOff, payloadLen, err := snapshot.CodeRegion(info.IsolateInstructions.Data)
	if err != nil {
		return fmt.Errorf("code region: %w", err)
	}
	codeEndOffset := uint32(codeOff) + uint32(payloadLen)
	cluster.SetLastRangeSize(ranges, codeEndOffset)
	codeVA := info.IsolateInstructions.VA + codeOff

	// Parse the VM-isolate snapshot region for base-object resolution --
	// same fix applied to decompile_native_cmd.go/pipeline.LoadContext
	// this session; this command had the identical nil-vmResult gap.
	// Mirrors objects.go/refinfo.go's already-proven pattern.
	var vmResult *cluster.Result
	if vmData := info.VmData.Data; len(vmData) >= 64 && info.VmHeader != nil {
		if vmStart, err := cluster.FindClusterDataStart(vmData); err == nil {
			if vmRes, err := cluster.ScanClusters(vmData, vmStart, info.Version, true, opts); err == nil {
				_ = cluster.ReadFill(vmData, vmRes, info.Version, true, info.VmHeader.TotalSize)
				vmResult = vmRes
			}
		}
	}

	pl := pipeline.BuildPoolLookups(result, info.Version.CIDs, vmResult, info.Version.CodeIndexOneBased, info.Version.DartVersion, info.Version.TypeClassIdIsRef)
	poolDisplay := pipeline.ResolvePoolDisplay(result.Pool, pl)

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
			for _, r := range ranges {
				if r.Size == 0 {
					continue
				}
				funcStart := uint64(r.PCOffset) - codeOff
				funcVA := codeVA + funcStart
				if targetVA >= funcVA && targetVA < funcVA+uint64(r.Size) {
					scanRanges = append(scanRanges, r)
					break
				}
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

		for off := 0; off < len(funcCode); {
			inst, err := x86asm.Decode(funcCode[off:], 64)
			length := inst.Len
			if err != nil || length <= 0 {
				length = 1 // resync one byte at a time on decode failure
			}
			if err == nil {
				for _, arg := range inst.Args {
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
					addr := funcVA + uint64(off)
					fmt.Printf("%s @ 0x%x  pp_idx=%d  codeRef=%d  funcStartVA=0x%x  %q\n", funcName, addr, poolIdx, r.RefID, funcVA, display)
					hits++
				}
			}
			off += length
			if *maxHits > 0 && hits >= *maxHits {
				fmt.Fprintf(os.Stderr, "stopping at --max=%d hits\n", *maxHits)
				return nil
			}
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
	for _, r := range ranges {
		if r.Size == 0 {
			continue
		}
		funcStart := uint64(r.PCOffset) - codeOff
		funcEnd := funcStart + uint64(r.Size)
		if funcEnd > uint64(len(code)) {
			funcEnd = uint64(len(code))
		}
		funcVA := codeVA + funcStart
		if targetVA < funcVA || targetVA >= funcVA+uint64(r.Size) {
			continue
		}
		var funcName string
		if r.RefID >= 0 {
			funcName = qualifiedCodeNameLocal(r.RefID, pl, r.PCOffset)
		} else {
			funcName = fmt.Sprintf("stub_%x", r.PCOffset)
		}
		fmt.Fprintf(os.Stderr, "found %s @ 0x%x, size=%d, target=0x%x\n", funcName, funcVA, r.Size, targetVA)

		funcCode := code[funcStart:funcEnd]
		for off := 0; off < len(funcCode); {
			addr := funcVA + uint64(off)
			inst, err := x86asm.Decode(funcCode[off:], 64)
			length := inst.Len
			if err != nil || length <= 0 {
				fmt.Printf("0x%x: <decode error: %v>\n", addr, err)
				length = 1
				off += length
				continue
			}
			text := inst.String()
			annotation := ""
			for _, arg := range inst.Args {
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
				if rel, ok := arg.(x86asm.Rel); ok {
					// Resolve JMP/Jcc/CALL rel targets to absolute VA --
					// added to disambiguate whether a given address is
					// reachable via normal control flow or only via a
					// jump/deopt-landing-pad from elsewhere (useful for
					// telling which of two candidate write sites in a
					// function is on the normal path vs. a rare
					// deopt/exception continuation).
					target := addr + uint64(length) + uint64(int64(rel))
					annotation += fmt.Sprintf("  ; -> 0x%x", target)
				}
			}
			marker := "  "
			if addr == targetVA {
				marker = "->"
			}
			fmt.Printf("%s 0x%x: %s%s\n", marker, addr, text, annotation)
			off += length
		}
		return nil
	}
	return fmt.Errorf("no range contains VA 0x%x", targetVA)
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

		for off := 0; off < len(funcCode); {
			addr := funcVA + uint64(off)
			inst, err := x86asm.Decode(funcCode[off:], 64)
			length := inst.Len
			if err != nil || length <= 0 {
				length = 1
				off += length
				continue
			}
			if inst.Op == x86asm.CALL {
				for _, arg := range inst.Args {
					if rel, ok := arg.(x86asm.Rel); ok {
						target := addr + uint64(length) + uint64(int64(rel))
						if target == targetVA {
							fmt.Printf("%s @ 0x%x  calls target\n", funcName, addr)
							hits++
						}
					}
				}
			}
			off += length
			if maxHits > 0 && hits >= maxHits {
				fmt.Fprintf(os.Stderr, "stopping at --max=%d hits\n", maxHits)
				return nil
			}
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
		for off := 0; off < len(funcCode); {
			inst, err := x86asm.Decode(funcCode[off:], 64)
			length := inst.Len
			if err != nil || length <= 0 {
				length = 1
				off += length
				continue
			}
			total++
			if hashShapedOp(inst.Op) {
				hashOps++
			}
			if inst.Op == x86asm.ROL || inst.Op == x86asm.ROR {
				rotateOps++
			}
			off += length
		}
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
