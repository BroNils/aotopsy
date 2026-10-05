package typetrack

import (
	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/cluster"
	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
)

// BlrResolution is one indirect call site the analysis said something about.
//
// A site is one of three things, and they are NOT the same claim:
//
//   - monomorphic: exactly one callee is known. TargetName holds it,
//     TargetNames is empty, Polymorphic is false.
//   - polymorphic: the receiver class is unknown but the selector is, so the
//     callee is one of N implementations of that selector. TargetNames holds
//     up to maxPolymorphicNames of them, Candidates the true count, and
//     TargetName is EMPTY -- there is no single callee to name.
//   - unresolved: Resolved is false.
//
// TargetName used to carry a " | "-joined string for the polymorphic case.
// Consumers treat it as a callee name: render.ReachableSet added it to the
// call graph, so a 43-way virtual call became one graph node literally named
// "detach | get:first | paint | ...".
type BlrResolution struct {
	PC          uint64   // instruction address
	Reg         int      // BLR register number (0-30)
	SlotIndex   int      // dispatch table slot (if resolved)
	TargetName  string   // the single resolved callee, monomorphic sites only
	TargetNames []string // candidate callees, polymorphic sites only (capped)
	Resolved    bool     // true if we said anything about this site

	// Polymorphic marks a site whose callee is one of TargetNames.
	// Candidates is how many distinct names the scan found, which can exceed
	// len(TargetNames) -- see maxPolymorphicNames.
	Polymorphic bool
	Candidates  int

	// Confidence classifies how the resolution was derived. An indirect call is
	// never exact: even a direct dispatch-slot lookup depends on receiver and
	// dispatch state inferred outside the CALL/BLR instruction itself.
	Confidence ResolutionConfidence `json:"confidence"`
	// Derivation records the independent mechanism that produced the claim.
	// Confidence alone is insufficient provenance: both a real GDT call and an
	// UnlinkedCall selector lookup can be static_inferred/polymorphic, but only
	// the former is justified by FlowGraphCompiler::EmitDispatchTableCall.
	Derivation ResolutionDerivation `json:"derivation"`
}

// ResolutionConfidence is the closed vocabulary emitted by typetrack for an
// indirect call. It is intentionally separate from evidence.Confidence to keep
// the dependency direction acyclic while preventing arbitrary strings from
// becoming new certainty tiers.
type ResolutionConfidence string

const (
	ResolutionStaticInferred ResolutionConfidence = "static_inferred"
	ResolutionPolymorphic    ResolutionConfidence = "polymorphic"
	ResolutionStub           ResolutionConfidence = "stub"
	ResolutionUnknown        ResolutionConfidence = "unknown"
)

func (c ResolutionConfidence) Valid() bool {
	switch c {
	case ResolutionStaticInferred, ResolutionPolymorphic, ResolutionStub, ResolutionUnknown:
		return true
	}
	return false
}

// ResolutionDerivation is the closed provenance vocabulary for indirect-call
// resolution. It deliberately does not encode certainty; that is Confidence's
// job. Keeping the two axes separate prevents a shared confidence tier from
// acquiring an SDK reference that belongs to a different lowering mechanism.
type ResolutionDerivation string

const (
	DerivationUnknown       ResolutionDerivation = "unknown"
	DerivationDispatchTable ResolutionDerivation = "dispatch_table"
	DerivationUnlinkedCall  ResolutionDerivation = "unlinked_call"
	DerivationStub          ResolutionDerivation = "stub"
)

func (d ResolutionDerivation) Valid() bool {
	switch d {
	case DerivationUnknown, DerivationDispatchTable, DerivationUnlinkedCall, DerivationStub:
		return true
	}
	return false
}

// maxPolymorphicNames bounds how many callee names a polymorphic resolution
// lists. A selector-offset scan across every class in the dispatch table can
// match hundreds of implementations; listing them all produced a single
// multi-kilobyte field in call_edges.jsonl.
const maxPolymorphicNames = 8

// cappedCandidates returns at most maxPolymorphicNames names.
func cappedCandidates(targets []string) []string {
	if len(targets) <= maxPolymorphicNames {
		return targets
	}
	return targets[:maxPolymorphicNames]
}

// selectorCandidates returns the distinct callee names reachable through a
// dispatch-table call whose class ID is unknown but whose selector immediate
// is known.
//
// The SDK emits (flow_graph_compiler_arm64.cc, EmitDispatchTableCall):
//
//	const intptr_t offset = selector_offset - DispatchTable origin;
//	2.10/2.12: add the offset to cid_reg in place and index with cid_reg
//	2.13+:     add the offset into LR and index with LR
//
// so the runtime index off DISPATCH_TABLE_REG is `cid + imm`, where imm is the
// signed immediate passed here. DispatchBySlot is keyed by that same
// register-relative index (absolute entry.Index - kOriginElement), therefore:
//
//	cid = key - imm = (entry.Index - kOriginElement) - imm
//
// The earlier formula, `entry.Index - imm + kOriginElement`, had the origin
// term on the wrong side and was off by 2*kOriginElement (8192 on ARM64), so
// every implied class ID -- and thus the old observational RTA filter built
// on it -- was wrong. Candidate enumeration now uses the structural class
// universe instead.
func (ctx *TypeContext) selectorCandidates(imm int) []string {
	// Cache by selector immediate. DispatchBySlot and its code-name map are
	// immutable during typetrack, so this cache is independent of the observed
	// allocation/instance population.
	if cached, ok := ctx.SelectorCache[imm]; ok {
		return cached
	}
	// Monomorphic fast path: if the complete structurally represented dispatch
	// table has exactly one unique implementation for this selector, return it.
	if name, ok := ctx.SelectorMonomorphic[imm]; ok {
		result := []string{name}
		ctx.SelectorCache[imm] = result
		return result
	}
	// SuperClass is built from every isolate + VM ClassInfo, so its keys are a
	// structural runtime-CID universe. Enumerating those CIDs and looking up
	// `cid+imm` is strictly safer than iterating every populated dispatch slot
	// and treating `slot-imm` as a hypothetical CID. Slots that the SDK's
	// row-displacement packing placed there for OTHER selectors are rejected by
	// selectorRowCandidates (owner/leaf row identity). The result is sorted, so
	// the same binary yields the same call_edges.jsonl on every run.
	targets := ctx.selectorRowCandidates(imm)
	// Cache the result for future lookups with the same imm.
	ctx.SelectorCache[imm] = targets
	// If exactly one unique name, record as monomorphic for future
	// fast-path lookups.
	if len(targets) == 1 {
		ctx.SelectorMonomorphic[imm] = targets[0]
	}
	return targets
}

// applySelectorCandidates fills res from a selector-offset scan: one name
// means a real (monomorphic) resolution, more means a candidate set.
func applySelectorCandidates(res *BlrResolution, targets []string) {
	if len(targets) == 0 {
		return
	}
	res.Candidates = len(targets)
	res.Resolved = true
	res.SlotIndex = -1
	if len(targets) == 1 {
		res.TargetName = targets[0]
		return
	}
	res.Polymorphic = true
	res.TargetNames = cappedCandidates(targets)
}

// IntraResult holds the result of intra-procedural analysis for one function.
type IntraResult struct {
	// EntryTypes[i] = type lattice for register i at function entry.
	EntryTypes [31]TypeLattice

	// ExitTypes[i] = type lattice for register i at function exit.
	ExitTypes [31]TypeLattice

	// Resolved BLR call sites in this function.
	BLRResolutions []BlrResolution

	// ParamTypes[i] = inferred type for parameter i (register Xi at entry).
	// Index 0 = X0 (receiver for instance methods).
	ParamTypes [31]TypeLattice

	// BLCallSiteTypes maps call-instruction PC → register state immediately before
	// the Dart-call clobber set is invalidated. This is call-site evidence, not
	// function-exit state, and is keyed by PC because several calls can target the
	// same callee with different argument facts.
	BLCallSiteTypes map[uint64][31]TypeLattice

	// FieldAccesses lists every instance-field read/write this function
	// performs through a receiver whose class was resolved. It is what makes
	// a real field cross-reference possible: (class, offset) -> the functions
	// that touch it.
	FieldAccesses []FieldAccess
}

// FieldAccess is one instance-field read or write with a known receiver class.
type FieldAccess struct {
	ClassID    int    // receiver's class ID
	ByteOffset int32  // raw instruction displacement (tagged-pointer relative)
	IsStore    bool   // true for a write, false for a read
	PC         uint64 // instruction address
}

// clearFieldAccessAtPC removes evidence produced by an earlier worklist visit.
// A block can be processed multiple times before its entry state reaches the
// fixed point; evidence must describe the latest/final visit, not the first.
func clearFieldAccessAtPC(result *IntraResult, pc uint64) {
	if result == nil {
		return
	}
	for i := range result.FieldAccesses {
		if result.FieldAccesses[i].PC == pc {
			result.FieldAccesses = append(result.FieldAccesses[:i], result.FieldAccesses[i+1:]...)
			return
		}
	}
}

// recordFieldAccess records one access, replacing any evidence from an earlier
// worklist visit to the same instruction.
func recordFieldAccess(result *IntraResult, ctx *TypeContext, receiverCID int, byteOffset int32, isStore bool, pc uint64) {
	if result == nil || ctx == nil || receiverCID < 0 {
		return
	}
	ownerCID, _, ok := ctx.DeclaredFieldOwner(receiverCID, byteOffset)
	if !ok {
		return
	}
	for i := range result.FieldAccesses {
		if result.FieldAccesses[i].PC == pc {
			result.FieldAccesses[i] = FieldAccess{ClassID: ownerCID, ByteOffset: byteOffset, IsStore: isStore, PC: pc}
			return
		}
	}
	result.FieldAccesses = append(result.FieldAccesses, FieldAccess{
		ClassID:    ownerCID,
		ByteOffset: byteOffset,
		IsStore:    isStore,
		PC:         pc,
	})
}

func arm64WritesRegister(raw uint32, reg int) bool {
	for _, dst := range arm64.DstRegsOfInst(raw) {
		if dst == reg {
			return true
		}
	}
	return false
}

// AnalyzeFunction runs intra-procedural type dataflow on one function.
// It uses a forward CFG worklist algorithm:
//  1. Build basic blocks from the instruction list.
//  2. Initialize entry types (from inter-procedural propagation or Top).
//  3. For each block, transfer function: decode each instruction and
//     update register type state.
//  4. Meet block exit → successor entry, repeat until fixed point.
//  5. On BLR instructions, attempt to resolve the dispatch target.
//
// entryTypes provides the initial types for parameters (from interproc).
// Pass all-Top if no inter-procedural info is available yet.
// entryStack seeds the first block's stack-slot types. It is how the receiver
// is supplied on the Dart versions that pass arguments on the stack; nil
// everywhere else. See TypeContext.FuncReceiverStackSlot.
func AnalyzeFunction(
	insts []disasm.Inst,
	ctx *TypeContext,
	entryTypes [31]TypeLattice,
	entryStack map[int]TypeLattice,
) *IntraResult {
	result := &IntraResult{
		EntryTypes: entryTypes,
	}

	// Skip analysis for very large functions (>50K instructions) to prevent
	// timeout. These are typically init:xxx functions with megabytes of
	// initialization code that don't have dispatch calls.
	const maxInstsForAnalysis = 50000
	if len(insts) > maxInstsForAnalysis {
		return result
	}

	// Pre-scan: find dispatch table call patterns and record selector offsets.
	// The index computation is versioned by the exact SDK:
	//
	// 2.13+: ADD/SUB X30, X0, #imm → LDR X30, [X21, X30, LSL #3] → BLR X30
	//   SDK: AddImmediate(LR, cid_reg, offset), with cid_reg fixed to R0
	//
	// 2.10/2.12: ADD/SUB Xn, Xn, #imm → LDR X30, [X21, Xn, LSL #3] → BLR X30
	//   SDK: AddImmediate(cid_reg, cid_reg, offset), with caller-selected cid_reg
	//
	// The imm gives the selector offset (in slot units, relative to kOriginElement).
	_, dispatchSupported := sdk.DispatchTableOriginElement(ctx.DartVersion, sdk.ArchARM64)
	_, fixedDispatchCID := sdk.DispatchTableClassIDReg(ctx.DartVersion, sdk.ArchARM64)
	legacyDispatch := dispatchSupported && !fixedDispatchCID
	for i := 0; i < len(insts)-2; i++ {
		if insts[i].Bad {
			continue
		}
		raw := insts[i].Raw
		var selectorOffset int
		var slotReg int // register used as dispatch table index
		var found bool

		if rd, rn, imm, ok := arm64.ADD64Immediate(raw); ok && sdk.IsARM64DispatchTableIndexComputation(ctx.DartVersion, rd, rn) {
			selectorOffset = imm
			slotReg = rd
			found = true
		} else if rd, rn, imm, ok := arm64.SUB64Immediate(raw); ok && sdk.IsARM64DispatchTableIndexComputation(ctx.DartVersion, rd, rn) {
			selectorOffset = -imm
			slotReg = rd
			found = true
		}
		// Modern zero-offset form: MOV X30, X0. The SDK emits this
		// instead of an ADD when `selector_offset - kOriginElement == 0`, so
		// the immediate is ZERO and the runtime index is the class ID itself.
		//
		// (This previously recorded kOriginElement as the "selector offset",
		// mixing two different quantities in the same map: every other
		// pattern stores the raw ADD/SUB immediate. The consumer subtracts
		// that immediate from the slot key, so the mismatch shifted every
		// implied class ID by kOriginElement.)
		// Pattern: MOV X30, X0 → ... → LDR X30, [X21, X30, LSL #3] → BLR X30
		if !found {
			if rd, rm, ok := arm64.MOVOrr(raw); ok && fixedDispatchCID && sdk.IsARM64DispatchTableIndexComputation(ctx.DartVersion, rd, rm) {
				for j := i + 1; j < len(insts)-1 && j <= i+4; j++ {
					if insts[j].Bad || insts[j+1].Bad {
						break
					}
					ldrRaw := insts[j].Raw
					if base, rm2, rt, ok := arm64.LDRRegExtended(ldrRaw); ok && base == sdk.ARM64DT && rt == sdk.ARM64LinkReg && rm2 == rd {
						if blrReg, ok := arm64.BLR(insts[j+1].Raw); ok && blrReg == sdk.ARM64LinkReg {
							selectorOffset = 0
							slotReg = rd
							found = true
							ctx.SelectorOffsets[insts[j+1].Addr] = selectorOffset
							break
						}
					}
					// This look-ahead is allowed to bridge instructions only while
					// the exact index register value is still live on the same
					// straight-line path. A redefinition or control-flow boundary
					// invalidates the structural proof.
					if arm64RecoveryBarrier(ldrRaw, insts[j].Addr) || arm64WritesRegister(ldrRaw, rd) {
						break
					}
				}
			}
		}
		if !found {
			continue
		}
		// Check next instruction: LDR X30, [X21, XslotReg, LSL #3]
		if i+1 < len(insts) && !insts[i+1].Bad {
			ldrRaw := insts[i+1].Raw
			if base, rm, rt, ok := arm64.LDRRegExtended(ldrRaw); ok && base == sdk.ARM64DT && rt == sdk.ARM64LinkReg && rm == slotReg {
				// Check instruction after: BLR X30
				if i+2 < len(insts) && !insts[i+2].Bad {
					if blrReg, ok := arm64.BLR(insts[i+2].Raw); ok && blrReg == sdk.ARM64LinkReg {
						ctx.SelectorOffsets[insts[i+2].Addr] = selectorOffset
					}
				}
			}
		}
	}

	// Large-immediate form, every supported SDK: LoadImmediate(TMP2, imm) →
	// ADD Xd, Xm, TMP2 → LDR X30, [X21, Xd, LSL #3] → BLR X30.
	// AddImmediate(dest, rn, imm) falls back to LoadImmediate(TMP2, imm) +
	// register-register ADD whenever imm is neither a 12-bit immediate nor
	// imm12<<12 (SDK @3.12.2 assembler_arm64.cc AddImmediate, assembler_arm64.h
	// CanHold; same shape @2.12.0), and EmitDispatchTableCall emits
	// AddImmediate(LR, cid_reg, offset). This pattern is NOT caught by the
	// ADD/SUB #imm scan above. The destination/source registers are validated by
	// the same per-SDK predicate as the immediate form.
	for i := 0; dispatchSupported && i < len(insts)-3; i++ {
		if insts[i].Bad || insts[i+1].Bad || insts[i+2].Bad || insts[i+3].Bad {
			continue
		}
		// AddImmediate uses TMP2 exactly when the selector offset does not fit
		// ADD/SUB immediate. Accept only the single-MOVZ LoadImmediate form;
		// multi-instruction MOVK/ORR materializations are left unresolved until
		// replayed exactly rather than guessed from an arbitrary constant reg.
		movReg, movImm, movOK := arm64.MOVZ64(insts[i].Raw)
		if !movOK || movReg != sdk.ARM64TMP2 {
			continue
		}
		// Next: ADD Xd, Xm, Xn (register-register, rm == movReg)
		if i+1 >= len(insts) {
			continue
		}
		addRd, addRn, addRm, addShift, addAmount, addOK := arm64.ADD64Register(insts[i+1].Raw)
		if !addOK || addShift != arm64.ShiftLSL || addAmount != 0 || addRm != sdk.ARM64TMP2 ||
			!sdk.IsARM64DispatchTableIndexComputation(ctx.DartVersion, addRd, addRn) {
			continue
		}
		// Next: LDR X30, [X21, Xd, LSL #3]
		if i+2 >= len(insts) {
			continue
		}
		base, rm, rt, ldrOK := arm64.LDRRegExtended(insts[i+2].Raw)
		if !ldrOK || base != sdk.ARM64DT || rt != sdk.ARM64LinkReg || rm != addRd {
			continue
		}
		// Next: BLR X30
		if i+3 >= len(insts) {
			continue
		}
		if blrReg, ok := arm64.BLR(insts[i+3].Raw); ok && blrReg == sdk.ARM64LinkReg {
			ctx.SelectorOffsets[insts[i+3].Addr] = movImm
		}
	}

	// Dart 2.10/2.12 zero-offset form: LDURH Wn, [Xm,#1] → ... →
	// LDR X30, [X21, Xp, LSL #3] → BLR X30.
	// When selector_offset == kOriginElement, the ADD/SUB is a no-op (offset=0)
	// and the compiler omits it entirely. The class ID from LDURH goes directly
	// into the dispatch table LDR without any arithmetic. selectorOffset = 0.
	// There may be intervening instructions (PP loads, STP pushes, MOV) between
	// the LDURH and the LDR. The MOV bridges the register: LDURH writes Wn,
	// MOV Xp, Xn copies it, LDR uses Xp.
	halfWordDisp, hasHalfWordCID := ctx.HalfWordClassIDDisp()
	for i := 0; legacyDispatch && hasHalfWordCID && i < len(insts)-2; i++ {
		if insts[i].Bad {
			continue
		}
		// Look for LDURH Wn, [Xm,#1] (class ID extraction, 2.x style)
		_, ldurhRt, ldurhImm9, ldurhOK := arm64.LDURH(insts[i].Raw)
		if !ldurhOK || int64(ldurhImm9) != halfWordDisp || ldurhRt >= 31 {
			continue
		}
		// Track which register holds the class ID. LDURH writes to ldurhRt,
		// but a MOV Xp, Xn may bridge it to a different register before the LDR.
		classIdReg := ldurhRt
		// Scan forward up to 5 instructions for MOV bridge then LDR.
		for j := i + 1; j < len(insts)-1 && j <= i+5; j++ {
			if insts[j].Bad || insts[j+1].Bad {
				break
			}
			jraw := insts[j].Raw
			// Check for MOV Xp, Xn (ORR Xd, XZR, Xm) that bridges the class ID.
			if movRd, movRm, movOK := arm64.MOVOrr(jraw); movOK && movRd < 31 {
				if movRm == classIdReg {
					classIdReg = movRd
					continue
				}
			}
			// Check for LDR X30, [X21, XclassIdReg, LSL #3]
			base, rm, rt, ldrOK := arm64.LDRRegExtended(jraw)
			if !ldrOK || base != sdk.ARM64DT || rt != sdk.ARM64LinkReg || rm != classIdReg {
				if arm64RecoveryBarrier(jraw, insts[j].Addr) || arm64WritesRegister(jraw, classIdReg) {
					break
				}
				continue
			}
			// Next: BLR X30
			if j+1 < len(insts) {
				if blrReg, ok := arm64.BLR(insts[j+1].Raw); ok && blrReg == sdk.ARM64LinkReg {
					ctx.SelectorOffsets[insts[j+1].Addr] = 0
				}
			}
			break
		}
	}

	// Build basic blocks.
	blocks := buildBlocks(insts)
	if len(blocks) == 0 {
		return result
	}

	// Per-block entry/exit type state.
	blockEntry := make([][31]TypeLattice, len(blocks))
	blockExit := make([][31]TypeLattice, len(blocks))
	blockVisited := make([]bool, len(blocks))

	// PHASE A: Per-block stack types (replaces function-wide stackTypes).
	// Each block has its own stackTypes map, propagated via block exit/entry.
	// This prevents cross-block pollution where Block B (after BL kills R1)
	// overwrites an object-class fact saved by Block A with Top.
	blockStackEntry := make([]map[int]TypeLattice, len(blocks))
	blockStackExit := make([]map[int]TypeLattice, len(blocks))
	blockShadowEntry := make([]shadowSPState, len(blocks))
	blockShadowSet := make([]bool, len(blocks))
	for i := range blockStackEntry {
		blockStackEntry[i] = make(map[int]TypeLattice)
		blockStackExit[i] = make(map[int]TypeLattice)
	}
	blockShadowSet[0] = true // function entry relation is unknown until frame setup

	// Initialize first block's entry with parameter types.
	blockEntry[0] = entryTypes
	blockVisited[0] = true
	for off, t := range entryStack {
		blockStackEntry[0][off] = t
	}

	// LCA helper for meetType.
	lca := func(a, b int) int { return LCA(a, b, ctx.SuperClass) }

	// Worklist: forward dataflow.
	worklist := make([]int, 0, len(blocks))
	worklist = append(worklist, 0)
	inWorklist := make(map[int]bool, len(blocks))
	inWorklist[0] = true

	for len(worklist) > 0 {
		idx := worklist[0]
		worklist = worklist[1:]
		inWorklist[idx] = false

		// Transfer function: walk instructions in this block.
		state := blockEntry[idx]
		blk := blocks[idx]
		// PHASE A: use per-block stack types (copy from entry, modify during transfer).
		stackTypes := make(map[int]TypeLattice, len(blockStackEntry[idx]))
		for k, v := range blockStackEntry[idx] {
			stackTypes[k] = v
		}
		shadowSP := blockShadowEntry[idx]

		var prevRaw uint32
		// Type narrowing: track CMP/SUBS that compare a class ID with an
		// immediate. Which SUCCESSOR that licenses depends on the branch --
		// see equalitySuccessor.
		var cmpReg int  // register being compared
		var cmpImm int  // immediate being compared against
		var hasCmp bool // whether we saw a CMP/SUBS in this block
		for _, inst := range blk.insts {
			if inst.Bad {
				hasCmp = false
				transferInstruction(&state, inst, 0, ctx, result, lca, stackTypes, &shadowSP)
				prevRaw = 0
				continue
			}
			// Detect CMP/SUBS Wd, Wn, #imm (CMP is SUBS WZR, Wn, #imm).
			//
			// Deliberately 32-bit only. Extending this to the 64-bit form
			// was tried and measured: narrow_hits went 5872 -> 68313 on
			// dart-3.9.2-arm64, an 11x increase, with resolved_blr moving
			// by exactly 0 -- and dart-2.12.0-arm64 lost one monomorphic
			// call to polymorphic. A class id is extracted into a W
			// register, so a CMP on an X register is almost always
			// comparing a tagged value or a Smi, and narrowing the
			// register to an exact class identity on that edge is simply wrong.
			// 62000 extra narrowings that buy no resolution are 62000
			// chances to be confidently wrong.
			if _, rn, imm, ok := arm64.SUBS32Immediate(inst.Raw); ok {
				cmpReg = rn
				cmpImm = imm
				hasCmp = true
			} else if hasCmp && !arm64PreservesCompareFlags(inst.Raw, inst.Addr) {
				// A later flag-writing/unknown instruction invalidates the CMP.
				// Previously CMP; <flag clobber>; B.EQ still narrowed the edge
				// using stale NZCV state.
				hasCmp = false
			}
			transferInstruction(&state, inst, prevRaw, ctx, result, lca, stackTypes, &shadowSP)
			prevRaw = inst.Raw
		}

		oldExit := blockExit[idx]
		blockExit[idx] = state
		// PHASE A: save per-block stack exit state.
		blockStackExit[idx] = stackTypes

		// Propagate to successors (meet).
		//
		// eqSucc is the successor index on which the compared register
		// definitely EQUALS cmpImm, or -1 when the terminating branch
		// licenses no such conclusion. Only that successor may be narrowed.
		eqSucc := -1
		if hasCmp && cmpReg < 31 && len(blk.insts) > 0 {
			eqSucc = equalitySuccessor(blk.insts[len(blk.insts)-1].Raw, len(blk.successors))
		}
		if eqSucc >= 0 {
			branchPC := blk.insts[len(blk.insts)-1].Addr
			if isClassID(state[cmpReg].Kind) {
				ctx.recordNarrowMetric(branchPC, narrowMetricHit)
			} else {
				ctx.recordNarrowMetric(branchPC, narrowMetricNoType)
			}
		}
		for succIdx, succ := range blk.successors {
			var newEntry [31]TypeLattice

			if succIdx == eqSucc {
				// The compared register is proven to contain a class-id scalar.
				// On this edge the comparison succeeded, so it is exactly cmpImm.
				narrowed := state
				if isClassID(state[cmpReg].Kind) {
					narrowed[cmpReg] = ExactClassID(cmpImm)
				}
				if !blockVisited[succ] {
					newEntry = narrowed
				} else {
					for r := 0; r < 31; r++ {
						newEntry[r] = joinType(blockEntry[succ][r], narrowed[r], lca)
					}
				}
			} else {
				// Every other edge, including the "not equal" one: the
				// lattice cannot express "not N", so nothing is learned.
				if !blockVisited[succ] {
					newEntry = state
				} else {
					for r := 0; r < 31; r++ {
						newEntry[r] = joinType(blockEntry[succ][r], state[r], lca)
					}
				}
			}

			firstVisit := !blockVisited[succ]
			changed := firstVisit || !typesEqual(newEntry, blockEntry[succ])
			newStackEntry, stackChanged := mergeStackFacts(blockStackEntry[succ], stackTypes, firstVisit, lca)
			if stackChanged {
				blockStackEntry[succ] = newStackEntry
				changed = true
			}

			// Shadow-SP is a separate lattice. It must propagate even when the
			// ordinary stack-fact map is empty; the old code accidentally nested
			// this merge inside the stack-key loop.
			if !blockShadowSet[succ] {
				blockShadowEntry[succ] = shadowSP
				blockShadowSet[succ] = true
				changed = true
			} else {
				mergedShadow := meetShadowSP(blockShadowEntry[succ], shadowSP)
				if !mergedShadow.Equal(blockShadowEntry[succ]) {
					blockShadowEntry[succ] = mergedShadow
					changed = true
				}
			}

			if changed {
				blockEntry[succ] = newEntry
				blockVisited[succ] = true
				if !inWorklist[succ] {
					worklist = append(worklist, succ)
					inWorklist[succ] = true
				}
			}
		}

		// Check if exit changed (for convergence).
		_ = oldExit // we rely on successor entry changes to drive the worklist
	}

	// Collect exit types from the last block(s).
	for i := range blocks {
		if len(blocks[i].successors) == 0 {
			// Exit block.
			for r := 0; r < 31; r++ {
				result.ExitTypes[r] = joinType(result.ExitTypes[r], blockExit[i][r], lca)
			}
		}
	}

	// Record parameter types from entry.
	result.ParamTypes = entryTypes

	return result
}

// typesEqual checks if two [31]TypeLattice arrays are identical.
func typesEqual(a, b [31]TypeLattice) bool {
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

// mergeStackFacts is a must-analysis join for sparse stack facts. Absence means
// reachable-but-unknown, so after the first predecessor a key survives only if
// every predecessor carries a compatible fact for that slot.
func mergeStackFacts(old, incoming map[int]TypeLattice, first bool, lca func(int, int) int) (map[int]TypeLattice, bool) {
	if first {
		out := make(map[int]TypeLattice, len(incoming))
		for k, v := range incoming {
			if v.Kind != LatticeTop && v.Kind != LatticeBottom {
				out[k] = v
			}
		}
		return out, true
	}
	out := make(map[int]TypeLattice, len(old))
	changed := false
	for k, oldV := range old {
		inV, ok := incoming[k]
		if !ok {
			changed = true
			continue
		}
		joined := joinType(oldV, inV, lca)
		if joined.Kind == LatticeTop || joined.Kind == LatticeBottom {
			changed = true
			continue
		}
		out[k] = joined
		if !joined.Equal(oldV) {
			changed = true
		}
	}
	if len(out) != len(old) {
		changed = true
	}
	return out, changed
}

// arm64PreservesCompareFlags is deliberately conservative. Narrowing is an
// assertion of exact class identity, so when we cannot prove an instruction
// leaves NZCV untouched we drop the comparison evidence rather than guess.
func arm64PreservesCompareFlags(raw uint32, pc uint64) bool {
	if raw == 0xD503201F { // NOP
		return true
	}
	if _, _, ok := arm64.MOVOrr(raw); ok {
		return true
	}
	if _, _, _, ok := arm64.ADD64Immediate(raw); ok {
		return true
	}
	if _, _, _, _, _, ok := arm64.ADD64Register(raw); ok {
		return true
	}
	if _, _, _, _, ok := arm64.UBFX(raw); ok {
		return true
	}
	if _, _, ok := arm64.LDR64UnsignedOffset(raw); ok {
		return true
	}
	if _, _, _, ok := arm64.LDR32UnsignedOffset(raw); ok {
		return true
	}
	if _, _, _, ok := arm64.LDUR64(raw); ok {
		return true
	}
	if _, _, _, ok := arm64.LDUR32(raw); ok {
		return true
	}
	if _, _, _, ok := arm64.LDURH(raw); ok {
		return true
	}
	if _, _, _, _, ok := arm64.LDP64UnsignedOffset(raw); ok {
		return true
	}
	if _, _, _, ok := arm64.STR64UnsignedOffset(raw); ok {
		return true
	}
	if _, _, _, ok := arm64.STR32UnsignedOffset(raw); ok {
		return true
	}
	if _, _, _, ok := arm64.STUR64(raw); ok {
		return true
	}
	if _, _, _, ok := arm64.STUR32(raw); ok {
		return true
	}
	if arm64.IsRet(raw) {
		return true
	}
	if arm64.IsBLEncoding(raw) {
		return true
	}
	if _, ok := arm64.BLR(raw); ok {
		return true
	}
	if _, ok := arm64.IsBR(raw); ok {
		return true
	}
	if arm64.IsBEncoding(raw) {
		return true
	}
	if arm64.IsConditionalBranchEncoding(raw) {
		return true
	}
	_, _, kind, ok := arm64.BCond(raw, pc)
	return ok && kind == arm64.BCondAlways
}

// basicBlock is a straight-line sequence of instructions with successors.
type basicBlock struct {
	startAddr  uint64
	insts      []disasm.Inst
	successors []int // block indices
}

// equalitySuccessor reports which successor edge of a block ending in `last`
// proves that a preceding `CMP reg, #imm` compared EQUAL, or -1 when no edge
// does. numSuccs is the block's successor count.
//
// Successors are built target-first, fall-through-second (see buildBlocks),
// so index 0 is the taken edge and index 1 the not-taken one -- but only when
// both were resolvable, hence the numSuccs == 2 requirement. With one
// successor the single entry may be either, and guessing is how this went
// wrong before.
//
// This check did not exist. Narrowing was applied to successor 0 after ANY
// conditional branch, which is right for B.EQ and wrong for everything else:
// after B.NE, reaching the target proves the register is NOT the immediate,
// and after B.LS/B.CS/B.HI/B.GE/B.LT/B.GT the test is a range, not an
// equality.
//
// Measured on the 3.x ARM64 sample, the cost of that was small: narrowings
// actually applied went 4148 -> 3983, so 165 (4%) had no grounds, and no
// output changed at all -- call_edges.jsonl is byte-identical either way.
// The disassembly-level distribution of CMP-then-branch is much worse than
// that (1408 B.EQ against 1207 B.NE and ~1900 range branches), but most of
// those compare ordinary integers, where the register is Top and no
// narrowing fires whatever the branch says. Rate over the WRONG population.
//
// B.NE is not merely excluded, it is inverted usefully: reaching its
// FALL-THROUGH proves equality, so that edge is narrowed instead.
//
// Known remaining limit: this does not verify that the CMP is what set the
// flags the branch reads. Another flag-setting instruction between the two
// would invalidate it. That is a smaller and separate hazard from the branch
// condition, which is what the measurement above sized.
func equalitySuccessor(last uint32, numSuccs int) int {
	if numSuccs != 2 {
		return sdk.SuccUnknown
	}
	// Only B.cond reads the flags a CMP set. CBZ/CBNZ and TBZ/TBNZ test a
	// register or a single bit directly, so a preceding CMP says nothing
	// about which way they go.
	_, cond, kind, ok := arm64.BCond(last, 0)
	if !ok || kind != arm64.BCondConditional {
		return sdk.SuccUnknown
	}
	// Same successor convention as x86.EqualitySuccessor. The two
	// functions are deliberately NOT merged -- one decodes a raw 32-bit
	// B.cond word, the other switches on an x86asm.Op, and a single
	// function taking both would be a union of unrelated inputs. Only the
	// convention is shared, because that is the part that can be got
	// backwards without anything failing loudly.
	switch cond {
	case 0: // EQ: the taken edge is the equal one.
		return sdk.SuccEqual
	case 1: // NE: the taken edge proves inequality; the fall-through proves equality.
		return sdk.SuccNotEqual
	}
	return sdk.SuccUnknown
}

// buildBlocks constructs basic blocks from an instruction list.
//
// NOT merged with buildBlocksX86 despite sharing the same algorithm
// (leader detection → partition → successor edges). The two differ in:
//   - Instruction type: disasm.Inst (fixed 4-byte, .Raw uint32) vs
//     X86DecodedInst (variable-length, .Inst x86asm.Inst)
//   - Branch classification: ARM64 raw-encoding pattern matching
//     (isBL/isBLR/isB/isCondBranch) vs x86 opcode switch
//     (x86asm.RET/JMP/IsX86CondJump)
//   - Partition approach: incremental (iterate, check leader map) vs
//     sorted-index (sort leader indices, slice between them)
//
// A generic version would need type parameters for instruction + block
// types plus a branch-classifier callback — more abstraction overhead
// than the ~30 lines of shared partition logic it would save.
func buildBlocks(insts []disasm.Inst) []basicBlock {
	if len(insts) == 0 {
		return nil
	}

	// Identify block leaders: first instruction + any branch target.
	leaders := make(map[uint64]bool)
	leaders[insts[0].Addr] = true

	for i, inst := range insts {
		if disasm.IsARM64SemanticBarrier(inst) {
			if i+1 < len(insts) {
				leaders[insts[i+1].Addr] = true
			}
			continue
		}
		if arm64.IsRet(inst.Raw) {
			if i+1 < len(insts) {
				leaders[insts[i+1].Addr] = true
			}
			continue
		}
		// Check for BL (branch with link) — creates a new block after it even
		// when target arithmetic overflows at a malformed high virtual address.
		if arm64.IsBLEncoding(inst.Raw) {
			if i+1 < len(insts) {
				leaders[insts[i+1].Addr] = true
			}
		}
		// Check for BLR — same.
		if _, ok := arm64.BLR(inst.Raw); ok {
			if i+1 < len(insts) {
				leaders[insts[i+1].Addr] = true
			}
		}
		// Check for B (unconditional branch) — target is a leader, next inst is a leader.
		if arm64.IsBEncoding(inst.Raw) {
			if target, ok := arm64.B(inst.Raw, inst.Addr); ok {
				leaders[target] = true
			}
			if i+1 < len(insts) {
				leaders[insts[i+1].Addr] = true
			}
		}
		// Check for B.cond / CBZ / CBNZ / TBZ / TBNZ — both targets are leaders.
		if arm64.IsConditionalBranchEncoding(inst.Raw) {
			if targets, ok := isCondBranch(inst.Raw, inst.Addr); ok {
				for _, t := range targets {
					leaders[t] = true
				}
			}
			if i+1 < len(insts) {
				leaders[insts[i+1].Addr] = true
			}
		} else if _, kind, ok := arm64.BCondClass(inst.Raw); ok && kind == arm64.BCondAlways {
			// Historical B.AL — unconditional despite B.cond encoding.
			// isCondBranch returns false for it; treat it as
			// unconditional branch. The following instruction must still start
			// a new (unreachable) block so the branch remains the terminator of
			// this block, exactly like ordinary B above.
			if target, _, _, targetOK := arm64.BCond(inst.Raw, inst.Addr); targetOK {
				leaders[target] = true
			}
			if i+1 < len(insts) {
				leaders[insts[i+1].Addr] = true
			}
		}
	}

	// Build blocks from leaders.
	addrToBlock := make(map[uint64]int)
	var blocks []basicBlock

	curBlock := basicBlock{startAddr: insts[0].Addr}
	for i, inst := range insts {
		if i > 0 && leaders[inst.Addr] {
			// Close current block.
			blocks = append(blocks, curBlock)
			addrToBlock[curBlock.startAddr] = len(blocks) - 1
			curBlock = basicBlock{startAddr: inst.Addr}
		}
		curBlock.insts = append(curBlock.insts, inst)
	}
	if len(curBlock.insts) > 0 {
		blocks = append(blocks, curBlock)
		addrToBlock[curBlock.startAddr] = len(blocks) - 1
	}

	// Build successor edges.
	for i := range blocks {
		blk := &blocks[i]
		lastInst := blk.insts[len(blk.insts)-1]
		if disasm.IsARM64SemanticBarrier(lastInst) {
			// Unknown instruction semantics and architectural traps are hard
			// control-flow barriers. Never flow facts into following bytes.
			continue
		}
		if arm64.IsRet(lastInst.Raw) {
			continue
		}

		// Find the index of lastInst in the global insts list.
		// H-1 fix: was O(n) linear search for globalLastIdx.
		// ARM64 instructions are always 4 bytes (disasm.go:16) and contiguous,
		// so fallthrough addr = lastInst.Addr + uint64(lastInst.Size).
		fallThroughAddr, hasFallThroughAddr := arm64.PCRelativeTarget(lastInst.Addr, int64(lastInst.Size))

		// Branch targets.
		if arm64.IsBEncoding(lastInst.Raw) {
			if target, ok := arm64.B(lastInst.Raw, lastInst.Addr); ok {
				if bi, ok2 := addrToBlock[target]; ok2 {
					blk.successors = append(blk.successors, bi)
				}
			}
			continue // unconditional branch — no fall-through
		}
		if arm64.IsConditionalBranchEncoding(lastInst.Raw) {
			if targets, ok := isCondBranch(lastInst.Raw, lastInst.Addr); ok {
				for _, t := range targets {
					if bi, ok2 := addrToBlock[t]; ok2 {
						blk.successors = append(blk.successors, bi)
					}
				}
			}
			// Fall-through (if not the last instruction overall).
			if hasFallThroughAddr {
				if bi, ok2 := addrToBlock[fallThroughAddr]; ok2 {
					blk.successors = append(blk.successors, bi)
				}
			}
			continue
		} else if _, kind, ok := arm64.BCondClass(lastInst.Raw); ok && kind == arm64.BCondAlways {
			// Historical B.AL — unconditional, no fall-through.
			if target, _, _, targetOK := arm64.BCond(lastInst.Raw, lastInst.Addr); targetOK {
				if bi, ok2 := addrToBlock[target]; ok2 {
					blk.successors = append(blk.successors, bi)
				}
			}
			continue
		}
		// BL/BLR: fall-through to next block.
		if arm64.IsBLEncoding(lastInst.Raw) {
			if hasFallThroughAddr {
				if bi, ok2 := addrToBlock[fallThroughAddr]; ok2 {
					blk.successors = append(blk.successors, bi)
				}
			}
			continue
		}
		if _, ok := arm64.BLR(lastInst.Raw); ok {
			if hasFallThroughAddr {
				if bi, ok2 := addrToBlock[fallThroughAddr]; ok2 {
					blk.successors = append(blk.successors, bi)
				}
			}
			continue
		}
		// Default: fall-through.
		if hasFallThroughAddr {
			if bi, ok2 := addrToBlock[fallThroughAddr]; ok2 {
				blk.successors = append(blk.successors, bi)
			}
		}
	}

	return blocks
}

// transferInstruction updates the register type state based on one instruction.
// On BLR instructions, it attempts to resolve the dispatch target.
// stackTypes tracks stack slot types for frame pointer (X29) loads/stores.
// prevRaw is the raw encoding of the previous instruction (0 if none),
// used to detect header-load → UBFX patterns for class ID extraction.
func transferInstruction(
	state *[31]TypeLattice,
	inst disasm.Inst,
	prevRaw uint32,
	ctx *TypeContext,
	result *IntraResult,
	lca func(int, int) int,
	stackTypes map[int]TypeLattice,
	shadowSP *shadowSPState,
) {
	clearFieldAccessAtPC(result, inst.Addr)
	if disasm.IsARM64SemanticBarrier(inst) {
		for i := range state {
			state[i] = Top()
		}
		for k := range stackTypes {
			delete(stackTypes, k)
		}
		if shadowSP != nil {
			*shadowSP = shadowSPState{}
		}
		return
	}

	observeShadowFrameUpdate(inst.Raw, shadowSP)

	tc := transferCtx{
		state:      state,
		inst:       inst,
		prevRaw:    prevRaw,
		ctx:        ctx,
		result:     result,
		lca:        lca,
		stackTypes: stackTypes,
		shadowSP:   shadowSP,
	}

	// The ArgumentsDescriptor-relative receiver load is checked first: it is
	// a plain `LDR Xr, [Xt, #disp]` that handleFieldLoad would otherwise
	// treat as a field read off an untyped base, and the prepass has already
	// proved -- via the owner-field-base gate -- that this exact PC produces
	// `this`. See TypeContext.ReceiverLoadAtPC.
	if handleArgsDescReceiver(&tc) {
		return
	}
	// Handlers run in the same order as the original if-chain.
	// Stack stores don't kill source registers, so they return false to
	// let subsequent handlers run (except STR [X29] which returns true).
	if handleStackStore(&tc) {
		return
	}
	if handleStackLoad(&tc) {
		return
	}
	if handleTHRLoad(&tc) {
		return
	}
	if handlePPLoad(&tc) {
		return
	}
	if handleDispatchTableLoad(&tc) {
		return
	}
	if handleDispatchArith(&tc) {
		return
	}
	if handleFieldLoad(&tc) {
		return
	}
	if handleUBFX(&tc) {
		return
	}
	if handleMOV(&tc) {
		return
	}
	if handleBLR(&tc) {
		return
	}
	if handleBL(&tc) {
		return
	}

	// 9. Default: if this instruction defines a register, kill its type.
	for _, rd := range arm64.DstRegsOfInst(inst.Raw) {
		if rd >= 0 && rd < 31 {
			state[rd] = Top()
		}
	}
}

// recordBLRResolution makes call-site evidence fixed-point stable. Worklist
// revisits replace the prior state for the same machine instruction instead of
// accumulating intermediate guesses.
func recordBLRResolution(result *IntraResult, res BlrResolution) {
	if result == nil {
		return
	}
	res = canonicalBLRResolution(res)
	for i := range result.BLRResolutions {
		if result.BLRResolutions[i].PC == res.PC {
			result.BLRResolutions[i] = res
			return
		}
	}
	result.BLRResolutions = append(result.BLRResolutions, res)
}

// canonicalBLRResolution fails contradictory producer state closed. A
// polymorphic candidate set is never a single callee, and an unresolved site
// must not retain a stale target from an earlier fixed-point visit.
func canonicalBLRResolution(res BlrResolution) BlrResolution {
	failClosed := func() BlrResolution {
		res.TargetName = ""
		res.TargetNames = nil
		res.Resolved = false
		res.Polymorphic = false
		res.Candidates = 0
		res.Confidence = ResolutionUnknown
		res.Derivation = DerivationUnknown
		return res
	}

	if !res.Derivation.Valid() {
		return failClosed()
	}
	if !res.Resolved {
		res.TargetName = ""
		res.TargetNames = nil
		res.Polymorphic = false
		res.Candidates = 0
		res.Confidence = ResolutionUnknown
		return res
	}
	if res.Polymorphic {
		if res.TargetName != "" || len(res.TargetNames) < 2 || res.Candidates < len(res.TargetNames) {
			return failClosed()
		}
		if res.Derivation != DerivationDispatchTable && res.Derivation != DerivationUnlinkedCall {
			return failClosed()
		}
		res.Confidence = ResolutionPolymorphic
		return res
	}
	if res.TargetName == "" || len(res.TargetNames) != 0 {
		return failClosed()
	}
	if res.Confidence != ResolutionStaticInferred && res.Confidence != ResolutionStub {
		return failClosed()
	}
	if res.Confidence == ResolutionStub && res.Derivation != DerivationStub {
		return failClosed()
	}
	if res.Confidence == ResolutionStaticInferred && res.Derivation != DerivationDispatchTable && res.Derivation != DerivationUnlinkedCall {
		return failClosed()
	}
	return res
}

// resolveBLR resolves only evidence produced by the exact generated dispatch
// shapes: either a proven concrete table slot, or a proven selector immediate
// whose CID remains unknown. It never scans neighboring slots to manufacture a
// selector or converts an object-class fact into a code pointer.
func resolveBLR(
	state *[31]TypeLattice,
	rn int,
	inst disasm.Inst,
	ctx *TypeContext,
	result *IntraResult,
) {
	res := BlrResolution{
		PC:         inst.Addr,
		Reg:        rn,
		Confidence: ResolutionUnknown,
		Derivation: DerivationUnknown,
	}

	t := state[rn]
	switch t.Kind {
	case LatticeKnownDispatchIndex:
		if t.SelectorOnly {
			ctx.recordBLRMetric(inst.Addr, blrMetricKnownDispatchSelector)
		} else {
			ctx.recordBLRMetric(inst.Addr, blrMetricKnownDispatch)
		}
	case LatticeExactClass, LatticeClassBound:
		ctx.recordBLRMetric(inst.Addr, blrMetricObject)
	case LatticeKnownStub:
		ctx.recordBLRMetric(inst.Addr, blrMetricStub)
	case LatticeTop:
		ctx.recordBLRMetric(inst.Addr, blrMetricTop)
	case LatticeBottom:
		ctx.recordBLRMetric(inst.Addr, blrMetricUnreachable)
	default:
		ctx.recordBLRMetric(inst.Addr, blrMetricOther)
	}
	switch t.Kind {
	case LatticeKnownStub:
		if appendKnownStubResolution(t, inst.Addr, rn, ctx, result) {
			return
		}
	case LatticeKnownDispatchIndex:
		// P1.2: class unknown, selector immediate known -- scan the dispatch
		// table at that selector across all classes.
		if t.SelectorOnly {
			res.Derivation = DerivationDispatchTable
			res.SlotIndex = -1
			imm := t.SelectorImm
			// The pre-scan's per-BLR record is authoritative when present:
			// it saw the actual ADD/SUB + LDR + BLR triple.
			if fromPreScan, ok := ctx.SelectorOffsets[inst.Addr]; ok {
				imm = fromPreScan
			}
			applySelectorCandidates(&res, ctx.selectorCandidates(imm))
			if res.Polymorphic {
				res.Confidence = ResolutionPolymorphic
			} else if res.Resolved {
				res.Confidence = ResolutionStaticInferred
			}
			if res.Resolved {
				ctx.hitMetric(metricDispatch, inst.Addr, &ctx.DispatchHits)
			}
			recordBLRResolution(result, res)
			return
		}

		// Direct slot lookup.
		res.Derivation = DerivationDispatchTable
		res.SlotIndex = t.DispatchIndex

		if name, ok := ctx.ResolveDispatchTarget(t.DispatchIndex); ok {
			res.TargetName = name
			res.Resolved = true
			res.Confidence = ResolutionStaticInferred
		} else {
			// A DispatchCode slot may still have an exact semantic name through
			// the code-index map even when ResolveDispatchTarget returned false.
			if entry, ok2 := ctx.DispatchBySlot[t.DispatchIndex]; ok2 && entry.Kind == cluster.DispatchCode {
				if name, ok3 := ctx.DispatchCodeIndexToName[entry.ClusterIndex]; ok3 && name != "" {
					res.TargetName = name
					res.Resolved = true
					res.Confidence = ResolutionStaticInferred
				}
			}
			if res.Resolved {
				ctx.hitMetric(metricDispatch, inst.Addr, &ctx.DispatchHits)
			}
		}
	case LatticeExactClass, LatticeClassBound:
		// An object value in the BLR target register is not a dispatch entry.
		// Do not turn an object-type fact into a code pointer by scanning table
		// slots. Exact dispatch evidence must have been produced by the table load.
	case LatticeTop, LatticeBottom, LatticeUnknownClassID, LatticeExactClassID:
		// No usable type for the call register -- fall back to the selector
		// immediate the pre-scan recorded for this exact BLR.
		//
		// The pre-scan is independent structural evidence from the exact generated
		// ADD/SUB + DISPATCH_TABLE_REG load + BLR shape, so it can still provide
		// selector-only candidates when a value fact was lost at a conservative
		// control-flow merge.
		if selectorImm, ok := ctx.SelectorOffsets[inst.Addr]; ok {
			res.Derivation = DerivationDispatchTable
			// Scan every class's slot at this selector immediate; see
			// selectorCandidates for the index arithmetic and its SDK source.
			applySelectorCandidates(&res, ctx.selectorCandidates(selectorImm))
			if res.Polymorphic {
				res.Confidence = ResolutionPolymorphic
			} else if res.Resolved {
				res.Confidence = ResolutionStaticInferred
			}
			if res.Resolved {
				ctx.hitMetric(metricDispatch, inst.Addr, &ctx.DispatchHits)
			}
		}
	}

	recordBLRResolution(result, res)
}

// --- ARM64 instruction decoders ---

// isBL detects BL (branch with link). Returns target address.
