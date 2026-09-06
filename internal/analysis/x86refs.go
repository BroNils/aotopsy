package analysis

import (
	"aotopsy/internal/arch/x86"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/arch/x86/x86asm"

	"aotopsy/internal/cluster"
	"aotopsy/internal/disasm"
	"aotopsy/internal/naming"
)

// DumpFuncDisasm finds the range containing targetVA and prints a full
// disassembly with [r15+disp]/[r14+disp] pool/thread annotations and
// CALL target resolution.
func DumpFuncDisasm(targetVA uint64, ranges []cluster.CodeRange, code []byte, codeOff, codeVA uint64, pl *naming.PoolLookups, poolDisplay map[int]string) error {
	r := cluster.FindRangeContainingVA(ranges, codeVA, codeOff, targetVA)
	if r == nil {
		return fmt.Errorf("no range contains VA 0x%x", targetVA)
	}
	im := NewCodeImage(code, codeVA, codeOff, pl, nil)
	fs, ok := im.Slice(*r)
	if !ok {
		return fmt.Errorf("range for VA 0x%x is empty or out of bounds", targetVA)
	}
	funcName := fs.Name
	funcVA := fs.VA
	funcCode := fs.Code
	fmt.Fprintf(os.Stderr, "found %s @ 0x%x, size=%d, target=0x%x\n", funcName, funcVA, r.Size, targetVA)
	x86.Walk(funcCode, funcVA, func(d x86.Decoded) bool {
		if d.Bad {
			fmt.Printf("0x%x: <decode error>\n", d.VA)
			return true
		}
		text := x86.InstText(d.Inst)
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
		if target, ok := x86.RelTarget(d.Inst, d.VA, d.Len); ok {
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

// FindCallersOf scans every function in the binary for CALL rel32
// instructions targeting targetVA's entry point.
func FindCallersOf(targetVA uint64, ranges []cluster.CodeRange, code []byte, codeOff, codeVA uint64, pl *naming.PoolLookups, maxHits int) error {
	hits := 0
	im := NewCodeImage(code, codeVA, codeOff, pl, nil)
	for _, r := range ranges {
		fs, ok := im.Slice(r)
		if !ok {
			continue
		}
		funcCode := fs.Code
		funcVA := fs.VA
		funcName := fs.Name

		capped := false
		x86.Walk(funcCode, funcVA, func(d x86.Decoded) bool {
			if !d.Bad && d.Inst.Op == x86asm.CALL {
				if target, ok := x86.RelTarget(d.Inst, d.VA, d.Len); ok && target == targetVA {
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

// HashShapedOp reports whether op is one of the bitwise/arithmetic
// instructions a hand-rolled or compiled SHA-256/HMAC round is built from.
func HashShapedOp(op x86asm.Op) bool {
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

// ScanHashShapedFunctions walks every function and counts hash/bitwise-shaped
// instructions vs. total instructions, ranking candidates by raw hash-op count.
func ScanHashShapedFunctions(ranges []cluster.CodeRange, code []byte, codeOff, codeVA uint64, pl *naming.PoolLookups, minOps int) error {
	var results []hashScanResult
	im := NewCodeImage(code, codeVA, codeOff, pl, nil)
	for _, r := range ranges {
		fs, ok := im.Slice(r)
		if !ok {
			continue
		}
		funcCode := fs.Code
		funcVA := fs.VA

		hashOps := 0
		rotateOps := 0
		total := 0
		x86.Walk(funcCode, funcVA, func(d x86.Decoded) bool {
			if d.Bad {
				return true
			}
			total++
			if HashShapedOp(d.Inst.Op) {
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
		funcName := fs.Name
		results = append(results, hashScanResult{funcName, funcVA, r.Size, hashOps, rotateOps, total})
	}

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

// QualifiedCodeNameLocal mirrors pipeline.QualifiedCodeName without importing
// the pipeline package's disasm-stage machinery. Uses ci.Qualified() so
// constructor names are handled correctly.
func QualifiedCodeNameLocal(refID int, pl *naming.PoolLookups, pcOffset uint32) string {
	ci := pl.CodeNames[refID]
	return ci.Qualified(pcOffset)
}

// ScanPoolRefs walks every function's code for [r15+disp] pool loads and
// prints matches containing findSubstr (or all if empty), capped at maxHits.
func ScanPoolRefs(ranges []cluster.CodeRange, code []byte, codeOff, codeVA uint64, pl *naming.PoolLookups, poolDisplay map[int]string, findSubstr string, maxHits int) error {
	hits := 0
	im := NewCodeImage(code, codeVA, codeOff, pl, nil)
	for _, r := range ranges {
		fs, ok := im.Slice(r)
		if !ok {
			continue
		}
		funcCode := fs.Code
		funcVA := fs.VA
		funcName := fs.Name

		capped := false
		x86.Walk(funcCode, funcVA, func(d x86.Decoded) bool {
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
					if findSubstr != "" && !strings.Contains(display, findSubstr) {
						continue
					}
					fmt.Printf("%s @ 0x%x  pp_idx=%d  codeRef=%d  funcStartVA=0x%x  %q\n", funcName, d.VA, poolIdx, r.RefID, funcVA, display)
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
	fmt.Fprintf(os.Stderr, "total hits: %d\n", hits)
	return nil
}
