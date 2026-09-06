package disasm

import (
	"strconv"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/sdk"
)

// ExtractCallEdgesCFG is ExtractCallEdges's CFG-wide replacement: instead
// of a fixed W-instruction lookback window (which loses provenance across
// any branch further than W instructions back -- including the common
// case of a PP/THR load in one block and its use a few blocks later),
// this computes register provenance as a real forward dataflow problem
// over the function's control flow graph, so provenance survives for as
// long as it's actually live along every path reaching the use site --
// unbounded by instruction count, bounded instead by real reachability.
//
// The analysis is a classic "available value" (reaching-definitions-style)
// problem with a per-register lattice of three states:
//   - top ("no info yet" -- not yet computed by the fixed-point iteration)
//   - a known annotation (e.g. "PP[42] Widget.build")
//   - bottom ("conflicting" -- different values reach here from different
//     paths, so the provenance can't be trusted and is treated as unknown,
//     same as the old window's "expired" state)
//
// Meet = intersection: two equal knowns stay known, anything else collapses
// toward bottom. This is monotonic (values only ever get less precise
// across iterations), so the worklist below is guaranteed to terminate.
func ExtractCallEdgesCFG(name string, insts []Inst, symbols SymbolLookup, annotators []Annotator) []CallEdge {
	if len(insts) == 0 {
		return nil
	}
	cfg := BuildCFG(name, insts)
	if len(cfg.Blocks) == 0 {
		return nil
	}

	// Precompute each block's local effect: which registers it touches
	// (defines or kills) and what they end up as, replaying the block's
	// own instructions from a blank slate. This is independent of the
	// block's entry state -- Define/Kill in this package are always
	// absolute overwrites, never "modify based on old value" -- so a
	// register untouched by the block simply passes its entry value
	// through unchanged, and a touched register ends up at the same
	// final value regardless of what reached the block's start.
	effects := make([]provBlockEffect, len(cfg.Blocks))
	for bi, blk := range cfg.Blocks {
		var regs noWindowRegs
		var touched [31]bool
		for i := blk.Start; i < blk.End && i < len(insts); i++ {
			touchInstrEffect(insts[i], &regs, annotators, &touched)
		}
		eff := provBlockEffect{
			touched: touched[:],
			final:   make([]lvalue, 31),
		}
		for r := 0; r < 31; r++ {
			if touched[r] {
				if v := regs[r]; v != "" {
					eff.final[r] = lvalue{kind: lvKnown, note: v}
				} else {
					eff.final[r] = lvalue{kind: lvBottom}
				}
			}
		}
		effects[bi] = eff
	}

	entryState := runProvFixpoint(len(cfg.Blocks), 31, func(b int) []Succ {
		return cfg.Blocks[b].Succs
	}, effects)

	// Final pass: walk every block once more, seeded with its converged
	// entry state, to actually classify BL/BLR/dispatch-table sites and
	// emit CallEdge records -- the same per-instruction classification
	// ExtractCallEdges uses, just seeded from real CFG-derived provenance
	// instead of a sliding window.
	var edges []CallEdge
	for bi, blk := range cfg.Blocks {
		var regs noWindowRegs
		for r := 0; r < 31; r++ {
			if entryState[bi][r].kind == lvKnown {
				regs[r] = entryState[bi][r].note
			}
		}
		for i := blk.Start; i < blk.End && i < len(insts); i++ {
			inst := insts[i]
			if target, ok := arm64.BL(inst.Raw, inst.Addr); ok {
				argMask := inferCallArgRegMaskLocal(insts, i)
				e := CallEdge{FromPC: inst.Addr, Kind: "bl", TargetPC: target, ArgCountHint: popcount8(argMask), ArgRegMask: argMask}
				if symbols != nil {
					if n, found := symbols(target); found {
						e.TargetName = n
					}
				}
				edges = append(edges, e)
				continue
			}
			if rn, ok := arm64.BLR(inst.Raw); ok {
				var via string
				if rn >= 0 && rn <= 30 {
					via = regs[rn]
				}
				edges = append(edges, CallEdge{
					FromPC: inst.Addr, Kind: "blr",
					Reg: regName(rn), Via: via,
				})
				continue
			}
			var touched [31]bool
			touchInstrEffect(inst, &regs, annotators, &touched)
		}
	}

	return edges
}

// noWindowRegs is a plain last-write-wins register->annotation map, with
// no time-based expiry -- unlike RegTracker, correctness here comes from
// following real CFG edges, not from aging out old definitions.
type noWindowRegs [31]string

type lvKind uint8

const (
	lvTop    lvKind = iota // no information yet (fixed-point not yet reached this block)
	lvKnown                // a single, path-consistent annotation
	lvBottom               // conflicting across paths, or no provenance at all
)

type lvalue struct {
	kind lvKind
	note string
}

func meetLvalue(a, b lvalue) lvalue {
	if a.kind == lvTop {
		return b
	}
	if b.kind == lvTop {
		return a
	}
	if a.kind == lvBottom || b.kind == lvBottom {
		return lvalue{kind: lvBottom}
	}
	if a.note == b.note {
		return a
	}
	return lvalue{kind: lvBottom}
}

// touchInstrEffect applies one instruction's register-definition effect
// (if any) to regs, mirroring ExtractCallEdges's per-instruction logic
// exactly (dispatch-table loads, object-field LDUR, annotator-detected
// PP/THR loads, and killing any other load/data-processing destination)
// -- but without emitting CallEdge records, since BL/BLR sites are
// classified separately by the two passes above (the local-effect
// precompute pass never needs them; the final emission pass classifies
// them inline before falling through to this function).
func touchInstrEffect(inst Inst, regs *noWindowRegs, annotators []Annotator, touched *[31]bool) {
	if _, ok := arm64.BL(inst.Raw, inst.Addr); ok {
		killReg(regs, touched, sdk.ARM64LinkReg)
		return
	}
	if _, ok := arm64.BLR(inst.Raw); ok {
		killReg(regs, touched, sdk.ARM64LinkReg)
		return
	}
	if base, _, dstR, ok := arm64.LDRRegExtended(inst.Raw); ok && base == regDT {
		defineReg(regs, touched, dstR, "dispatch_table")
		return
	}
	if base, dstR, off, ok := arm64.LDUR64(inst.Raw); ok {
		// A Code entry-point load inherits its base's provenance: the entry
		// point OF Code X is X. See IsCodeEntryPointDisp.
		//
		// When the base is unknown HERE the result is the same anonymous
		// object_field it always was, so nothing gets worse. During the
		// block-local precompute `regs` starts blank, which means this only
		// fires when the pool load and the entry-point load sit in the same
		// block -- and measured on the corpus they are one or two
		// instructions apart, so that covers essentially all of them.
		if IsCodeEntryPointDisp(off) && base >= 0 && base < len(regs) && regs[base] != "" {
			defineReg(regs, touched, dstR, regs[base])
			return
		}
		defineReg(regs, touched, dstR, ObjectFieldViaAt(off))
		return
	}
	var annotation string
	for _, ann := range annotators {
		if s := ann(inst); s != "" {
			annotation = s
			break
		}
	}
	dsts := arm64.DstRegsOfInst(inst.Raw)
	if annotation != "" && len(dsts) > 0 {
		for _, rd := range dsts {
			defineReg(regs, touched, rd, annotation)
		}
		return
	}
	for _, rd := range dsts {
		killReg(regs, touched, rd)
	}
}

func defineReg(regs *noWindowRegs, touched *[31]bool, rd int, note string) {
	if rd < 0 || rd > 30 {
		return
	}
	regs[rd] = note
	touched[rd] = true
}

func killReg(regs *noWindowRegs, touched *[31]bool, rd int) {
	if rd < 0 || rd > 30 {
		return
	}
	regs[rd] = ""
	touched[rd] = true
}

func regName(rn int) string {
	return "X" + strconv.Itoa(rn)
}
