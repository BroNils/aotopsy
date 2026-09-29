// Package strxref finds which Dart functions reference a given object-pool
// slot -- i.e. cross-references a string (or any pool-resolvable value) back
// to every machine-code instruction that actually reads or otherwise addresses
// that slot.
package strxref

import (
	"fmt"
	"math"
	"strings"

	"aotopsy/internal/analysis"
	arm64arch "aotopsy/internal/arch/arm64"
	x86arch "aotopsy/internal/arch/x86"
	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"

	"golang.org/x/arch/x86/x86asm"
)

const (
	// DefaultMaxScan is deliberately high enough to cover the largest real
	// corpus/app measured during this audit (129k functions), while still making
	// a corrupt/malicious range table finite by default. Callers that truly want
	// an unbounded function count must opt in explicitly.
	DefaultMaxScan = 250_000
	// DefaultMaxRefs bounds retained output independently of scan cost. A single
	// synthetic function can contain tens of thousands of references, so a
	// function-count cap alone is not an output/memory bound.
	DefaultMaxRefs = 100_000
)

// Reference is one machine-code instruction that references one target pool
// index. Pair loads can therefore contribute two References at the same
// InstrAddr, one for each adjacent pool slot.
type Reference struct {
	FuncName  string `json:"func_name"`
	FuncVA    uint64 `json:"func_va"`
	InstrAddr uint64 `json:"instr_addr"`
	PoolIndex int    `json:"pool_index"`
}

// Options bounds FindPoolReferences' cost.
type Options struct {
	// MaxScan caps eligible functions attempted. 0 uses DefaultMaxScan. The cap
	// is counted before decoding, so malformed functions cannot bypass it by
	// repeatedly failing construction/decoding.
	MaxScan int
	// AllowUnbounded disables the function-count cap. It does not disable the
	// retained-reference cap; set MaxRefs explicitly if a larger result is
	// required.
	AllowUnbounded bool
	// MaxRefs caps retained Reference records. 0 uses DefaultMaxRefs.
	MaxRefs int
	// Filter restricts scanning to functions whose resolved name contains this
	// substring.
	Filter string
}

// Result makes partial work explicit. Callers must not present a capped result
// as complete: ScanLimitReached / ReferenceLimitReached identify the exact
// reason scanning stopped.
type Result struct {
	References            []Reference
	Attempted             int
	Scanned               int
	ScanLimitReached      bool
	ReferenceLimitReached bool
}

type refKey struct {
	pc  uint64
	idx int
}

// FindPoolReferences scans the raw function bytes for PP-relative references.
// It intentionally does not build FuncIR: FuncIRFor now builds lazy enrichment
// maps and is no longer the cheap, bounded primitive the original strxref
// implementation assumed. Reading the machine-code operands directly is both
// cheaper and more complete: x64 CompareObject, for example, emits CMP against
// [PP+disp] rather than a MOV/OpLoadPool.
func FindPoolReferences(ctx *analysis.AnalysisContext, poolIndices []int, opts Options) (Result, error) {
	var result Result
	if ctx == nil {
		return result, fmt.Errorf("strxref: nil analysis context")
	}
	if opts.MaxScan < 0 {
		return result, fmt.Errorf("strxref: MaxScan must be >= 0")
	}
	if opts.MaxRefs < 0 {
		return result, fmt.Errorf("strxref: MaxRefs must be >= 0")
	}
	if len(poolIndices) == 0 {
		return result, nil
	}

	target := make(map[int]struct{}, len(poolIndices))
	for _, idx := range poolIndices {
		if idx >= 0 {
			target[idx] = struct{}{}
		}
	}
	if len(target) == 0 {
		return result, nil
	}

	maxScan := opts.MaxScan
	if maxScan == 0 && !opts.AllowUnbounded {
		maxScan = DefaultMaxScan
	}
	maxRefs := opts.MaxRefs
	if maxRefs == 0 {
		maxRefs = DefaultMaxRefs
	}

	seen := make(map[refKey]struct{})
	emit := func(funcName string, funcVA, pc uint64, idx int) bool {
		if _, wanted := target[idx]; !wanted {
			return true
		}
		key := refKey{pc: pc, idx: idx}
		if _, dup := seen[key]; dup {
			return true
		}
		if len(result.References) >= maxRefs {
			result.ReferenceLimitReached = true
			return false
		}
		seen[key] = struct{}{}
		result.References = append(result.References, Reference{
			FuncName:  funcName,
			FuncVA:    funcVA,
			InstrAddr: pc,
			PoolIndex: idx,
		})
		return true
	}

	image := ctx.Image()
	for _, r := range ctx.Ranges {
		if r.Size == 0 || r.RefID < 0 {
			continue
		}
		fs, ok := image.SliceExact(r)
		if !ok {
			return result, fmt.Errorf("strxref: invalid function range ref=%d pc_off=0x%x size=%d", r.RefID, r.PCOffset, r.Size)
		}
		name := ctx.SymbolNames[fs.VA]
		if name == "" {
			name = fs.Name
		}
		if opts.Filter != "" && !strings.Contains(name, opts.Filter) {
			continue
		}
		if !opts.AllowUnbounded && maxScan > 0 && result.Attempted >= maxScan {
			result.ScanLimitReached = true
			break
		}
		result.Attempted++

		var err error
		if ctx.IsARM64 {
			err = scanARM64(fs.Code, fs.VA, func(pc uint64, idx int) bool {
				return emit(name, fs.VA, pc, idx)
			})
		} else {
			err = scanX64(fs.Code, fs.VA, func(pc uint64, idx int) bool {
				return emit(name, fs.VA, pc, idx)
			})
		}
		if err != nil {
			return result, fmt.Errorf("strxref: scan %s @ 0x%x: %w", name, fs.VA, err)
		}
		result.Scanned++
		if result.ReferenceLimitReached {
			break
		}
	}
	return result, nil
}

// scanX64 records every statically-addressable memory operand based directly
// on PP. This includes MOV loads, CALL/JMP through pool slots, and importantly
// direct comparisons such as Dart's CompareObject `cmp reg, [PP+disp]`.
func scanX64(code []byte, baseVA uint64, emit func(pc uint64, idx int) bool) error {
	var decodeErr error
	x86arch.Walk(code, baseVA, func(d x86arch.Decoded) bool {
		if d.Bad {
			decodeErr = fmt.Errorf("invalid x86 instruction byte at 0x%x", d.VA)
			return false
		}
		for _, arg := range d.Inst.Args {
			mem, ok := arg.(x86asm.Mem)
			if !ok || x86arch.CanonReg(mem.Base) != sdk.X86PP || x86arch.CanonReg(mem.Index) >= 0 {
				continue
			}
			idx, ok := disasm.X64PoolIndex(mem.Disp)
			if ok && !emit(d.VA, idx) {
				return false
			}
		}
		return true
	})
	return decodeErr
}

// scanARM64 tracks the PP-relative base forms emitted by Dart's
// LoadWordFromPoolIndex / LoadDoubleWordFromPoolIndex. Direct LDR/LDP reads are
// recognized as well as the common `add tmp, PP, #hi; ldr/ldp [...,#lo]`
// forms. Unknown instruction words are errors, not transparent provenance.
func scanARM64(code []byte, baseVA uint64, emit func(pc uint64, idx int) bool) error {
	if len(code)%4 != 0 {
		return fmt.Errorf("truncated ARM64 function: %d bytes", len(code))
	}
	insts := disasm.Disassemble(code, disasm.Options{BaseAddr: baseVA, MaxSteps: len(code) / 4})
	if len(insts) != len(code)/4 {
		return fmt.Errorf("ARM64 decode stopped early: decoded=%d words=%d", len(insts), len(code)/4)
	}

	// Register -> byte offset relative to the untagged object-pool base.
	ppOffset := map[int]int64{sdk.ARM64PP: 0}
	for _, inst := range insts {
		if inst.Bad {
			return fmt.Errorf("invalid ARM64 instruction word at 0x%x", inst.Addr)
		}

		if base, off, ok := arm64arch.LDR64UnsignedOffset(inst.Raw); ok {
			if hi, tracked := ppOffset[base]; tracked {
				if idx, ok := poolIndex64(hi, int64(off)); ok && !emit(inst.Addr, idx) {
					return nil
				}
			}
		} else if base, off, _, ok := arm64arch.LDR32UnsignedOffset(inst.Raw); ok {
			if hi, tracked := ppOffset[base]; tracked {
				if idx, ok := poolIndex64(hi, int64(off)); ok && !emit(inst.Addr, idx) {
					return nil
				}
			}
		} else if base, _, off, ok := arm64arch.LDUR64(inst.Raw); ok {
			if hi, tracked := ppOffset[base]; tracked {
				if idx, ok := poolIndex64(hi, int64(off)); ok && !emit(inst.Addr, idx) {
					return nil
				}
			}
		} else if base, _, off, ok := arm64arch.LDUR32(inst.Raw); ok {
			if hi, tracked := ppOffset[base]; tracked {
				if idx, ok := poolIndex64(hi, int64(off)); ok && !emit(inst.Addr, idx) {
					return nil
				}
			}
		} else if base, _, _, off, ok := arm64arch.LDP64UnsignedOffset(inst.Raw); ok {
			if hi, tracked := ppOffset[base]; tracked {
				if idx, ok := poolIndex64(hi, int64(off)); ok {
					if !emit(inst.Addr, idx) || !emit(inst.Addr, idx+1) {
						return nil
					}
				}
			}
		}

		if rd, rn, imm, ok := arm64arch.ADD64Immediate(inst.Raw); ok {
			if base, tracked := ppOffset[rn]; tracked {
				next := base + int64(imm)
				if next >= base { // immediates are non-negative; reject signed wrap.
					ppOffset[rd] = next
				} else {
					delete(ppOffset, rd)
				}
			} else {
				delete(ppOffset, rd)
			}
			continue
		}

		for _, rd := range arm64arch.DstRegsOfInst(inst.Raw) {
			delete(ppOffset, rd)
		}
	}
	return nil
}

func poolIndex64(base, off int64) (int, bool) {
	if (off > 0 && base > math.MaxInt64-off) || (off < 0 && base < math.MinInt64-off) {
		return 0, false
	}
	total := base + off
	if total < 0 || int64(int(total)) != total {
		return 0, false
	}
	return disasm.ARM64PoolIndex(int(total))
}
