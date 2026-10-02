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
func ExtractCallEdgesCFG(name string, insts []Inst, symbols SymbolLookup, annotators []Annotator, poolDisplay map[int]string) []CallEdge {
	if len(insts) == 0 {
		return nil
	}
	cfg := BuildCFG(name, insts)
	if len(cfg.Blocks) == 0 {
		return nil
	}
	poolNotes := arm64PoolNotesByPC(ExtractARM64PoolLoads(insts, poolDisplay))

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
		for r := range regs {
			regs[r] = provInputNote(r)
		}
		var touched [31]bool
		for i := blk.Start; i < blk.End && i < len(insts); i++ {
			touchInstrEffect(insts[i], &regs, annotators, poolNotes, &touched)
		}
		eff := provBlockEffect{
			touched:  touched[:],
			final:    make([]lvalue, 31),
			copyFrom: make([]int, 31),
		}
		for r := range eff.copyFrom {
			eff.copyFrom[r] = -1
		}
		for r := 0; r < 31; r++ {
			if touched[r] {
				if src, ok := provInputReg(regs[r]); ok {
					eff.copyFrom[r] = src
					continue
				}
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
			if arm64.IsBLEncoding(inst.Raw) {
				target, targetValid := arm64.BL(inst.Raw, inst.Addr)
				argMask := inferCallArgRegMaskLocal(insts, i, blk.Start)
				e := CallEdge{FromPC: inst.Addr, Kind: "bl", TargetPC: target, TargetValid: targetValid, ArgCountHint: popcount8(argMask), ArgRegMask: argMask}
				if targetValid && symbols != nil {
					if n, found := symbols(target); found {
						e.TargetName = n
					}
				}
				edges = append(edges, e)
				// Ordinary Dart calls are full register-allocation barriers: the SDK's
				// linear-scan allocator blocks every CPU register at a non-callee-safe
				// call. No tracked temporary provenance is therefore valid after BL.
				var callTouched [31]bool
				killAllRegs(&regs, &callTouched)
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
				var callTouched [31]bool
				killAllRegs(&regs, &callTouched)
				continue
			}
			var touched [31]bool
			touchInstrEffect(inst, &regs, annotators, poolNotes, &touched)
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
// exactly (dispatch-table loads, object-field LDR/LDUR, annotator-detected
// PP/THR loads, and killing any other load/data-processing destination)
// -- but without emitting CallEdge records, since BL/BLR sites are
// classified separately by the two passes above (the local-effect
// precompute pass never needs them; the final emission pass classifies
// them inline before falling through to this function).
func touchInstrEffect(inst Inst, regs *noWindowRegs, annotators []Annotator, poolNotes map[uint64]map[int]string, touched *[31]bool) {
	if IsARM64SemanticBarrier(inst) {
		killAllRegs(regs, touched)
		return
	}
	if arm64.IsBLEncoding(inst.Raw) {
		killAllRegs(regs, touched)
		return
	}
	if _, ok := arm64.BLR(inst.Raw); ok {
		killAllRegs(regs, touched)
		return
	}
	if rd, rm, ok := arm64.MOVOrr(inst.Raw); ok {
		if rm >= 0 && rm < len(regs) && regs[rm] != "" {
			defineReg(regs, touched, rd, regs[rm])
		} else {
			killReg(regs, touched, rd)
		}
		return
	}
	if notes := poolNotes[inst.Addr]; len(notes) > 0 {
		// A scalar load has one destination/note; LDP has two distinct pool
		// slots and therefore two distinct notes. Kill any destination that the
		// structured pool-load census did not prove rather than applying one
		// inline string annotation to every written register.
		for _, rd := range arm64.DstRegsOfInst(inst.Raw) {
			if note, ok := notes[rd]; ok && note != "" {
				defineReg(regs, touched, rd, note)
			} else {
				killReg(regs, touched, rd)
			}
		}
		return
	}
	if base, _, dstR, ok := arm64.LDRRegExtended(inst.Raw); ok && base == regDT {
		defineReg(regs, touched, dstR, "dispatch_table")
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
	if mem, ok := arm64.Load64Immediate(inst.Raw); ok && mem.Mode == arm64.AddressOffset {
		base, dstR, off := mem.BaseReg, mem.Reg, mem.ByteOffset
		// Fixed-role registers do not name heap object fields. PP/THR facts are
		// handled above by structured pool notes / annotators; SP/FP are stack
		// slots; DT is dispatch storage. If none of those paths recognized this
		// load, unknown is safer than inventing object_field provenance.
		switch base {
		case sdk.ARM64SPReg, sdk.ARM64FrameReg, sdk.ARM64PP, sdk.ARM64THR, sdk.ARM64DT:
			killReg(regs, touched, dstR)
			return
		}
		// A Code entry-point load inherits its base's provenance: the entry
		// point OF Code X is X. See IsCodeEntryPointDisp.
		if IsCodeEntryPointDisp(off) && base >= 0 && base < len(regs) && regs[base] != "" {
			defineReg(regs, touched, dstR, regs[base])
			return
		}
		// A displacement alone does not prove that an arbitrary register holds
		// a heap object. Only retain generic object-field provenance when the
		// base itself already has path-consistent provenance. This keeps a load
		// after a CFG join from turning an unknown/bypassed temporary into a
		// fabricated heap-field fact.
		if base < 0 || base >= len(regs) || regs[base] == "" {
			killReg(regs, touched, dstR)
			return
		}
		defineReg(regs, touched, dstR, ObjectFieldViaAt(off))
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

func killAllRegs(regs *noWindowRegs, touched *[31]bool) {
	for r := range regs {
		killReg(regs, touched, r)
	}
}

func regName(rn int) string {
	return "X" + strconv.Itoa(rn)
}
