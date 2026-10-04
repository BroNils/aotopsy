// Package strxref finds which Dart functions reference a given object-pool
// slot -- i.e. cross-references a string (or any pool-resolvable value) back
// to every machine-code instruction that actually reads or otherwise addresses
// that slot.
package strxref

import (
	"fmt"
	"strings"

	"aotopsy/internal/analysis"
	x86arch "aotopsy/internal/arch/x86"
	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"

	"golang.org/x/arch/x86/x86asm"
)

const (
	// DefaultMaxScan keeps a corrupt/malicious range table finite by default.
	// Callers that truly want an unbounded function count must opt in explicitly.
	DefaultMaxScan = 250_000
	// DefaultMaxRefs bounds retained output independently of scan cost. A single
	// synthetic function can contain tens of thousands of references, so a
	// function-count cap alone is not an output/memory bound.
	DefaultMaxRefs = 100_000
)

// Reference is one machine-code instruction that references one target pool
// index. Pair loads and 16-byte SIMD loads can therefore contribute two
// References at the same InstrAddr, one for each adjacent pool slot.
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
	References []Reference
	// Attempted counts eligible functions whose machine code scan was started.
	// A decode failure or reference-cap stop therefore increments Attempted.
	Attempted int
	// Scanned counts eligible functions whose complete declared byte range was
	// decoded and exhausted. A function stopped by MaxRefs is attempted but not
	// scanned completely.
	Scanned int

	ScanLimitReached      bool
	ReferenceLimitReached bool
}

// Complete reports whether the scan exhausted every eligible function and
// retained every matching reference. Decode/range failures are returned as an
// error instead of being represented as a successful-but-incomplete Result.
func (r Result) Complete() bool {
	return !r.ScanLimitReached && !r.ReferenceLimitReached
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

	// A reference is a physical machine-code fact: one instruction addresses one
	// pool slot. Duplicate target indices or duplicate/overlapping CodeRange rows
	// must not duplicate that physical xref merely because it was encountered
	// through two logical records.
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
		// With no name filter every structurally eligible range would be scanned,
		// so enforce MaxScan before even slicing the next function. Otherwise a
		// corrupt out-of-range record beyond the requested cap could turn a bounded
		// partial result into an unrelated range error.
		if opts.Filter == "" && !opts.AllowUnbounded && maxScan > 0 && result.Attempted >= maxScan {
			result.ScanLimitReached = true
			break
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

		var (
			scanComplete bool
			err          error
		)
		if ctx.IsARM64 {
			scanComplete, err = scanARM64(fs.Code, fs.VA, func(pc uint64, idx int) bool {
				return emit(name, fs.VA, pc, idx)
			})
		} else {
			scanComplete, err = scanX64(fs.Code, fs.VA, func(pc uint64, idx int) bool {
				return emit(name, fs.VA, pc, idx)
			})
		}
		if err != nil {
			return result, fmt.Errorf("strxref: scan %s @ 0x%x: %w", name, fs.VA, err)
		}
		if scanComplete {
			result.Scanned++
		}
		if result.ReferenceLimitReached {
			break
		}
	}
	return result, nil
}

// scanX64 records every statically-addressable memory operand based directly
// on PP. This includes MOV loads/stores, CALL/JMP through pool slots, direct
// comparisons such as Dart's CompareObject `cmp reg, [PP+disp]`, and wide SIMD
// operands. A memory operand wider than one 8-byte pool entry emits one xref per
// touched slot (notably LoadQImmediate's 16-byte MOVUPS).
// It returns complete=false only when the caller deliberately stops emission
// (currently the retained-reference cap). Bad decoding is an error: resuming at
// the next byte would lose instruction-boundary proof and can invent xrefs.
func scanX64(code []byte, baseVA uint64, emit func(pc uint64, idx int) bool) (complete bool, err error) {
	complete = true
	var decodeErr error
	x86arch.Walk(code, baseVA, func(d x86arch.Decoded) bool {
		if d.Bad {
			decodeErr = fmt.Errorf("invalid x86 instruction byte at 0x%x", d.VA)
			return false
		}
		for _, arg := range d.Inst.Args {
			mem, ok := arg.(x86asm.Mem)
			if !ok {
				continue
			}
			disp, static := x86arch.StaticBaseDisp(mem, sdk.X86PP)
			if !static {
				continue
			}
			idx, ok := disasm.X64PoolIndex(disp)
			if !ok {
				continue
			}
			slots := 1
			if d.Inst.MemBytes > sdk.PoolElementSize {
				slots = (d.Inst.MemBytes + sdk.PoolElementSize - 1) / sdk.PoolElementSize
			}
			maxInt := int(^uint(0) >> 1)
			for slot := 0; slot < slots; slot++ {
				if idx > maxInt-slot || !emit(d.VA, idx+slot) {
					complete = false
					return false
				}
			}
		}
		return true
	})
	if decodeErr != nil {
		return false, decodeErr
	}
	return complete, nil
}

// scanARM64 delegates pool-address provenance to disasm.ExtractARM64PoolAccesses,
// the canonical implementation also used by call-edge/dataflow analysis. That
// extractor models the exact SDK LoadWordFromPoolIndex, StoreWordToPoolIndex,
// LoadDoubleWordFromPoolIndex, and FP/SIMD LoadS/D/QImmediate lowerings in the
// supported releases, including wide Q loads spanning two pool entries and all
// positive-offset materialization forms used by PrepareLargeOffset. Keeping this
// package's old second provenance engine caused both missed large-pool refs and
// false facts across control-flow joins.
func scanARM64(code []byte, baseVA uint64, emit func(pc uint64, idx int) bool) (complete bool, err error) {
	if len(code)%4 != 0 {
		return false, fmt.Errorf("truncated ARM64 function: %d bytes", len(code))
	}
	insts := disasm.Disassemble(code, disasm.Options{BaseAddr: baseVA, MaxSteps: len(code) / 4})
	if len(insts) != len(code)/4 {
		return false, fmt.Errorf("ARM64 decode stopped early: decoded=%d words=%d", len(insts), len(code)/4)
	}
	for _, inst := range insts {
		if inst.Bad {
			return false, fmt.Errorf("invalid ARM64 instruction word at 0x%x", inst.Addr)
		}
	}

	for _, access := range disasm.ExtractARM64PoolAccesses(insts, nil) {
		if !emit(access.PC, access.PoolIndex) {
			return false, nil
		}
	}
	return true, nil
}
