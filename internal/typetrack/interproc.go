package typetrack

import (
	"aotopsy/internal/arch/x86"
	"sort"
	"strings"

	"aotopsy/internal/disasm"
	"aotopsy/internal/sdk"
)

// sortedKeysInsts, sortedKeysX86 and sortedEdgeKeys return map keys in a
// stable order so that analysis passes that mutate the shared TypeContext
// produce identical results on every run.
// entryStackFor builds the first-block stack seed for a function, or nil when
// this Dart version passes the receiver in a register.
func entryStackFor(ctx *TypeContext, name string) map[int]TypeLattice {
	ownerCID, ok := ctx.FuncOwnerClass[name]
	if !ok || ownerCID < 0 {
		return nil
	}
	slot, ok := ctx.FuncReceiverStackSlot[name]
	if !ok {
		return nil
	}
	return map[int]TypeLattice{slot: KnownClass(ownerCID)}
}

func sortedKeys[M ~map[string]V, V any](m M) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isHexSuffix checks if s is a hex address suffix (e.g., "1c4", "1b7e54").
func isHexSuffix(s string) bool {
	if len(s) == 0 || len(s) > 8 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// FuncAnalysis holds the analysis result for one function, keyed by name.
type FuncAnalysis struct {
	Intra *IntraResult
	Name  string
}

// InterResult holds the results of inter-procedural type propagation.
type InterResult struct {
	// Functions[name] = analysis for that function.
	Functions map[string]*FuncAnalysis

	// AllResolvedBLR is the total count of resolved BLR call sites across
	// all functions.
	AllResolvedBLR int

	// TotalBLR is the total count of BLR call sites across all functions.
	TotalBLR int
}

// FuncInstsARM64 holds ARM64 function instructions for RunInterprocedural.
type FuncInstsARM64 map[string][]disasm.Inst

// FuncInstsX86 holds x86_64 function instructions for RunInterprocedural.
type FuncInstsX86 map[string][]x86.Decoded

// RunInterprocedural runs the inter-procedural fixed-point algorithm:
//  1. For each function, run intra-procedural analysis with current
//     parameter type estimates (initially all Top).
//  2. For each BL call edge, propagate the caller's argument types
//     to the callee's parameter types (meet).
//  3. Repeat until no parameter types change (fixed point) or max
//     iterations reached.
//
// Fase 7 PART A: also propagates callee return types (ExitTypes[0]) back
// to callers via ctx.CalleeExitTypes, enabling type chains across calls.
//
// funcInstsARM64 or funcInstsX86 maps function name → instruction list.
// blEdges maps caller name → list of (callee name, argument types at call site).
// blTargetToName maps BL target address → callee function name (for call-return
// tracking). maxIterations caps the number of rounds (default 3).
// isARM64 selects the architecture-specific analysis path.
func RunInterprocedural(
	ctx *TypeContext,
	funcInstsARM64 FuncInstsARM64,
	funcInstsX86 FuncInstsX86,
	blEdges map[string][]BLEdge,
	maxIterations int,
	isARM64 bool,
	blTargetToName map[uint64]string,
) *InterResult {
	if maxIterations <= 0 {
		maxIterations = 3
	}

	var funcCount int

	// TARGET 1: MethodNameToRefIDs is built in BuildTypeContext and stored
	// in ctx. It maps method name (e.g., "adoptChild") → []Function refIDs.
	// Used by setEntryFromParamTypes to look up FuncParamTypes.

	// The SDK register table is only a layout, not proof that an individual
	// Function uses it. It first exists at 3.4.3; even then generic and several
	// Function kinds are stack-only, and unboxing metadata can force additional
	// functions to the stack. Build a per-callee evidence map from independent
	// direct-call setup masks and only propagate those proven positions.
	cc, hasRegisterCC := sdk.DartRegisterCallingConvention(ctx.DartVersion, isARM64)
	argRegOrder := cc.GPR
	regArgsByFunc := make(map[string][]int)
	if hasRegisterCC {
		masksByFunc := make(map[string][]uint8)
		for _, caller := range sortedKeys(blEdges) {
			for _, edge := range blEdges[caller] {
				if edge.ArgMask != 0 && ctx.FuncMayUseRegisterCC[edge.Callee] {
					masksByFunc[edge.Callee] = append(masksByFunc[edge.Callee], edge.ArgMask)
				}
			}
		}
		for name, masks := range masksByFunc {
			if idx, ok := disasm.ResolveArgRegIndices(masks); ok {
				valid := true
				for _, pos := range idx {
					if pos < 0 || pos >= len(argRegOrder) {
						valid = false
						break
					}
				}
				if valid {
					regArgsByFunc[name] = idx
				}
			}
		}
	}

	if isARM64 {
		funcCount = len(funcInstsARM64)
	} else {
		funcCount = len(funcInstsX86)
	}

	result := &InterResult{
		Functions: make(map[string]*FuncAnalysis, funcCount),
	}

	receiverReg := -1
	if len(argRegOrder) > 0 {
		receiverReg = argRegOrder[0]
	}
	hasRegPosition := func(name string, pos int) bool {
		if pos == 0 && ctx.FuncReceiverInRegister[name] {
			return true
		}
		for _, p := range regArgsByFunc[name] {
			if p == pos {
				return true
			}
		}
		return false
	}

	// Initialize function analyses with entry types.
	// M-6 fix: only iterate the map for the active architecture.
	// TARGET 1: Set entry types for ALL parameter registers from
	// FuncParamTypes (resolved from FunctionType parameter_types Array).
	// This enables dispatch resolution when receiver is a non-this parameter
	// (e.g., adoptChild(child) dispatches on child, not on this).

	// Helper: set entry types from FuncParamTypes for a given function name.
	// Function names in funcInstsARM64 have format "Owner.method_hexaddr"
	// but CodeRefToName has "Owner.method" (without hex suffix).
	// Strip the last "_hex" suffix to match.
	// Q10 fix: try qualified "Owner.method" name first (more precise),
	// then fall back to bare method name (broader match).
	setEntryFromParamTypes := func(name string, entry *[31]TypeLattice) {
		positions := regArgsByFunc[name]
		if len(positions) == 0 {
			return
		}
		// Function name format: "Owner.method_hexaddr" or "method_hexaddr"
		// Strip hex suffix to get "Owner.method"
		lookupName := name
		if idx := strings.LastIndex(name, "_"); idx > 0 {
			suffix := name[idx+1:]
			if isHexSuffix(suffix) {
				lookupName = name[:idx]
			}
		}
		// Q10: Try qualified name first (e.g., "MyClass.adoptChild")
		refIDs, ok := ctx.MethodNameToRefIDs[lookupName]
		if !ok || len(refIDs) == 0 {
			// Fall back to bare method name (e.g., "adoptChild")
			methodName := lookupName
			if dotIdx := strings.LastIndex(lookupName, "."); dotIdx >= 0 {
				methodName = lookupName[dotIdx+1:]
			}
			refIDs, ok = ctx.MethodNameToRefIDs[methodName]
			if !ok || len(refIDs) == 0 {
				return
			}
		}
		// Try each refID — use first one that has param types
		var paramTypes []int
		var refID int
		for _, rid := range refIDs {
			if pt, ok2 := ctx.FuncParamTypes[rid]; ok2 && len(pt) > 0 {
				paramTypes = pt
				refID = rid
				break
			}
		}
		if paramTypes == nil {
			return
		}
		// For instance methods, parameter 0 is 'this' (receiver in R1).
		// Parameters 1..N map to argRegOrder[1..N] = {R2, R3, R5, R6, R7}.
		// For static methods, parameters 0..N map to argRegOrder[0..N].
		// CRITICAL FIX: param i maps to argRegOrder[i], NOT argRegOrder[i-startIdx].
		// Dart AOT calling convention: param 0 (this) → R1, param 1 → R2, param 2 → R3, etc.
		// For instance methods, we skip param 0 (this, already set from FuncOwnerClass),
		// but param 1 still maps to argRegOrder[1]=R2, not argRegOrder[0]=R1.
		isInstance := ctx.FuncIsInstance[refID]
		startIdx := 0
		if isInstance {
			startIdx = 1 // Skip 'this' — already set from FuncOwnerClass
		}
		allowed := make(map[int]bool, len(positions))
		for _, pos := range positions {
			allowed[pos] = true
		}
		for i := startIdx; i < len(paramTypes) && i < len(argRegOrder); i++ {
			if !allowed[i] {
				continue
			}
			cid := paramTypes[i]
			if cid >= 0 {
				regIdx := argRegOrder[i]
				if regIdx < 31 && entry[regIdx].Kind == LatticeTop {
					entry[regIdx] = KnownClass(cid)
				}
			}
		}
	}

	// Analyse functions in a deterministic order. AnalyzeFunction mutates the
	// shared TypeContext (field-store types, instantiated classes, selector
	// offsets), so what function A records is visible to function B: iterating
	// the map directly made the resolved-BLR set differ between runs of the
	// same binary.
	if isARM64 {
		for _, name := range sortedKeys(funcInstsARM64) {
			insts := funcInstsARM64[name]
			var entry [31]TypeLattice
			for i := range entry {
				entry[i] = Top()
			}
			var entryStack map[int]TypeLattice
			if ownerCID, ok := ctx.FuncOwnerClass[name]; ok && ownerCID >= 0 {
				if receiverReg >= 0 && hasRegPosition(name, 0) {
					entry[receiverReg] = KnownClass(ownerCID)
				}
				// Pre-3.4.3 the receiver arrives on the stack and the
				// prologue immediately overwrites the register, so the
				// register seed alone is dead on arrival.
				if slot, ok2 := ctx.FuncReceiverStackSlot[name]; ok2 {
					entryStack = map[int]TypeLattice{slot: KnownClass(ownerCID)}
				}
			}
			// TARGET 1: Also set entry types for non-receiver parameters.
			setEntryFromParamTypes(name, &entry)
			intra := AnalyzeFunction(insts, ctx, entry, entryStack)
			result.Functions[name] = &FuncAnalysis{Intra: intra, Name: name}
		}
	} else {
		for _, name := range sortedKeys(funcInstsX86) {
			insts := funcInstsX86[name]
			var entry [31]TypeLattice
			for i := range entry {
				entry[i] = Top()
			}
			if ownerCID, ok := ctx.FuncOwnerClass[name]; ok && ownerCID >= 0 && receiverReg >= 0 && hasRegPosition(name, 0) {
				entry[receiverReg] = KnownClass(ownerCID)
			}
			// TARGET 1: Also set entry types for non-receiver parameters.
			setEntryFromParamTypes(name, &entry)
			intra := AnalyzeFunctionX86(insts, ctx, entry, entryStackFor(ctx, name))
			result.Functions[name] = &FuncAnalysis{Intra: intra, Name: name}
		}
	}

	// Seed CalleeExitTypes from declared return types (FuncReturnType).
	seedHits := 0
	for target, name := range blTargetToName {
		lookupName := name
		if idx := strings.LastIndex(name, "_"); idx > 0 {
			suffix := name[idx+1:]
			if isHexSuffix(suffix) {
				lookupName = name[:idx]
			}
		}
		refIDs, ok := ctx.MethodNameToRefIDs[lookupName]
		if !ok || len(refIDs) == 0 {
			methodName := lookupName
			if dotIdx := strings.LastIndex(lookupName, "."); dotIdx >= 0 {
				methodName = lookupName[dotIdx+1:]
			}
			refIDs, ok = ctx.MethodNameToRefIDs[methodName]
		}
		if ok {
			for _, rid := range refIDs {
				if cid, ok2 := ctx.FuncReturnType[rid]; ok2 && cid >= 0 {
					ctx.CalleeExitTypes[target] = KnownClass(cid)
					seedHits++
					break
				}
			}
		}
	}
	ctx.FuncReturnTypeSeeds = seedHits

	// Initial CalleeExitTypes population after the first analysis pass,
	// so the first fixed-point iteration's handleBL can see return types.
	// Don't overwrite FuncReturnType seeds with Top — the declared return
	// type is more precise than "we don't know from analysis alone".
	needReanalysis := false
	for target, name := range blTargetToName {
		if fa, ok := result.Functions[name]; ok && fa.Intra != nil {
			if fa.Intra.ExitTypes[0].Kind != LatticeTop {
				if old, ok := ctx.CalleeExitTypes[target]; !ok || !old.Equal(fa.Intra.ExitTypes[0]) {
					ctx.CalleeExitTypes[target] = fa.Intra.ExitTypes[0]
					needReanalysis = true
				}
			}
			if old, ok := ctx.CalleeAllExitTypes[target]; !ok || !latticeArrayEqual(old, fa.Intra.ExitTypes) {
				ctx.CalleeAllExitTypes[target] = fa.Intra.ExitTypes
				needReanalysis = true
			}
		}
	}

	// LCA helper.
	lca := func(a, b int) int { return LCA(a, b, ctx.SuperClass) }

	// Fixed-point iteration. Parameter estimates are recomputed from the
	// current call-site states each round, but convergence is measured against
	// the PREVIOUS round. Comparing against a fresh all-Top map makes every
	// non-Top argument look changed forever and forces maxIterations runs.
	prevParamTypes := make(map[string][31]TypeLattice)
	for iter := 0; iter < maxIterations; iter++ {
		calleeParamTypes := make(map[string][31]TypeLattice)

		for _, caller := range sortedKeys(blEdges) {
			edges := blEdges[caller]
			callerAnalysis, ok := result.Functions[caller]
			if !ok {
				continue
			}

			for _, edge := range edges {
				// CRITICAL FIX: use BLCallSiteTypes (register state at BL call site,
				// BEFORE BL kills R0-R7) instead of ExitTypes (state at function exit).
				// ExitTypes is Top for R0-R7 because BL kills them and exit blocks
				// don't restore. BLCallSiteTypes captures ACTUAL parameter types.
				var argTypes [31]TypeLattice
				if callerAnalysis.Intra.BLCallSiteTypes != nil {
					if cs, ok := callerAnalysis.Intra.BLCallSiteTypes[edge.CallPC]; ok {
						argTypes = cs
					} else {
						argTypes = callerAnalysis.Intra.ExitTypes
					}
				} else {
					argTypes = callerAnalysis.Intra.ExitTypes
				}

				positions := regArgsByFunc[edge.Callee]
				if len(positions) == 0 {
					continue
				}
				current := calleeParamTypes[edge.Callee]
				for _, pos := range positions {
					r := argRegOrder[pos]
					newType := meetType(current[r], argTypes[r], lca)
					if !newType.Equal(current[r]) {
						calleeParamTypes[edge.Callee] = updateReg(calleeParamTypes[edge.Callee], r, newType)
					}
				}
			}
		}

		changed := !paramTypeMapsEqual(prevParamTypes, calleeParamTypes)
		if !changed && !needReanalysis {
			break
		}
		prevParamTypes = cloneParamTypeMap(calleeParamTypes)
		needReanalysis = false

		// Re-run intra-procedural analysis with updated parameter types.
		// M-6 fix: only iterate the map for the active architecture.
		//
		// Sorted, for the same reason as the initial pass above:
		// AnalyzeFunction writes into the shared TypeContext, so the order
		// functions are re-analysed in changes what later ones see. Sorting
		// only the first pass left this one random, and call_edges.jsonl
		// still differed between runs of the same binary.
		if isARM64 {
			for _, name := range sortedKeys(funcInstsARM64) {
				insts := funcInstsARM64[name]
				entry := calleeParamTypes[name]
				if allTop(entry) {
					for i := range entry {
						entry[i] = Top()
					}
				}
				if receiverReg >= 0 && hasRegPosition(name, 0) && entry[receiverReg].Kind == LatticeTop {
					if ownerCID, ok := ctx.FuncOwnerClass[name]; ok && ownerCID >= 0 {
						entry[receiverReg] = KnownClass(ownerCID)
					}
				}
				// TARGET 1: Also update non-receiver params from FuncParamTypes.
				setEntryFromParamTypes(name, &entry)
				intra := AnalyzeFunction(insts, ctx, entry, entryStackFor(ctx, name))
				result.Functions[name].Intra = intra
			}
		} else {
			for _, name := range sortedKeys(funcInstsX86) {
				insts := funcInstsX86[name]
				entry := calleeParamTypes[name]
				if allTop(entry) {
					for i := range entry {
						entry[i] = Top()
					}
				}
				if receiverReg >= 0 && hasRegPosition(name, 0) && entry[receiverReg].Kind == LatticeTop {
					if ownerCID, ok := ctx.FuncOwnerClass[name]; ok && ownerCID >= 0 {
						entry[receiverReg] = KnownClass(ownerCID)
					}
				}
				// TARGET 1: Also update non-receiver params from FuncParamTypes.
				setEntryFromParamTypes(name, &entry)
				intra := AnalyzeFunctionX86(insts, ctx, entry, entryStackFor(ctx, name))
				result.Functions[name].Intra = intra
			}
		}

		// Update CalleeExitTypes after each re-analysis pass, so the
		// NEXT iteration's handleBL can see callee return types.
		// Don't overwrite FuncReturnType seeds with Top — the declared
		// return type is more precise than "analysis found nothing".
		for target, name := range blTargetToName {
			if fa, ok := result.Functions[name]; ok && fa.Intra != nil {
				if fa.Intra.ExitTypes[0].Kind != LatticeTop {
					if old, ok := ctx.CalleeExitTypes[target]; !ok || !old.Equal(fa.Intra.ExitTypes[0]) {
						ctx.CalleeExitTypes[target] = fa.Intra.ExitTypes[0]
						needReanalysis = true
					}
				}
				if old, ok := ctx.CalleeAllExitTypes[target]; !ok || !latticeArrayEqual(old, fa.Intra.ExitTypes) {
					ctx.CalleeAllExitTypes[target] = fa.Intra.ExitTypes
					needReanalysis = true
				}
			}
		}
		// Invalidate selector cache: new allocation sites may have been
		// discovered during this iteration's re-analysis, changing the
		// RTA-filtered candidate set. The cache will be rebuilt lazily
		// on the next iteration's selectorCandidates calls.
		ctx.InvalidateSelectorCache()
	}

	// Count resolved BLR.
	for _, fa := range result.Functions {
		result.TotalBLR += len(fa.Intra.BLRResolutions)
		for _, res := range fa.Intra.BLRResolutions {
			if res.Resolved {
				result.AllResolvedBLR++
			}
		}
	}

	return result
}

func paramTypeMapsEqual(a, b map[string][31]TypeLattice) bool {
	if len(a) != len(b) {
		return false
	}
	for name, av := range a {
		bv, ok := b[name]
		if !ok || !typesEqual(av, bv) {
			return false
		}
	}
	return true
}

func cloneParamTypeMap(src map[string][31]TypeLattice) map[string][31]TypeLattice {
	dst := make(map[string][31]TypeLattice, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// BLEdge represents a direct BL call edge for inter-procedural propagation.
type BLEdge struct {
	Callee string
	CallPC uint64 // address of the BL instruction
	// ArgMask is the direct call site's observed register-setup mask in SDK
	// convention-position order. It is evidence, not a declaration: consumers
	// aggregate multiple independent call sites before trusting it.
	ArgMask uint8
}

// updateReg returns a copy of types with register r set to newType.
func updateReg(types [31]TypeLattice, r int, newType TypeLattice) [31]TypeLattice {
	types[r] = newType
	return types
}

func latticeArrayEqual(a, b [31]TypeLattice) bool {
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}
