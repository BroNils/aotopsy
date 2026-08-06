package typetrack

import (
	"strings"

	"aotopsy/internal/disasm"
)

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
type FuncInstsX86 map[string][]X86DecodedInst

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

	// Dart AOT calling convention (ARM64):
	// kCpuRegistersForArgs = {R1, R2, R3, R5, R6, R7}
	// R0 = kClassIdReg, R4 = ARGS_DESC_REG
	// Parameter i maps to argRegOrder[i]:
	argRegOrder := []int{1, 2, 3, 5, 6, 7}

	if isARM64 {
		funcCount = len(funcInstsARM64)
	} else {
		funcCount = len(funcInstsX86)
	}

	result := &InterResult{
		Functions: make(map[string]*FuncAnalysis, funcCount),
	}

	// Receiver register: ARM64 = X1 (1), x86_64 = RDI (7).
	// Fase 7 PHASE 1 fix: Dart AOT calling convention uses R1 for receiver
	// ('this'), NOT R0. R0 is kClassIdReg (used for dispatch table calls).
	// Verified against dart-lang/sdk constants_arm64.h at 3.9.2:
	//   DartCallingConvention::kCpuRegistersForArgs[] = {R1, R2, R3, R5, R6, R7}
	// R0 = kClassIdReg, R4 = ARGS_DESC_REG, R5 = IC_DATA_REG.
	receiverReg := 1 // ARM64: X1
	if !isARM64 {
		receiverReg = x86RegRDI // x86_64: RDI (SysV ABI first arg)
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
		for i := startIdx; i < len(paramTypes) && i < len(argRegOrder); i++ {
			cid := paramTypes[i]
			if cid >= 0 {
				regIdx := argRegOrder[i]
				if regIdx < 31 && entry[regIdx].Kind == LatticeTop {
					entry[regIdx] = KnownClass(cid)
				}
			}
		}
	}

	if isARM64 {
		for name, insts := range funcInstsARM64 {
			var entry [31]TypeLattice
			for i := range entry {
				entry[i] = Top()
			}
			if ownerCID, ok := ctx.FuncOwnerClass[name]; ok && ownerCID >= 0 {
				entry[receiverReg] = KnownClass(ownerCID)
			}
			// TARGET 1: Also set entry types for non-receiver parameters.
			setEntryFromParamTypes(name, &entry)
			intra := AnalyzeFunction(insts, ctx, entry)
			result.Functions[name] = &FuncAnalysis{Intra: intra, Name: name}
		}
	} else {
		for name, insts := range funcInstsX86 {
			var entry [31]TypeLattice
			for i := range entry {
				entry[i] = Top()
			}
			if ownerCID, ok := ctx.FuncOwnerClass[name]; ok && ownerCID >= 0 {
				entry[receiverReg] = KnownClass(ownerCID)
			}
			// TARGET 1: Also set entry types for non-receiver parameters.
			setEntryFromParamTypes(name, &entry)
			intra := AnalyzeFunctionX86(insts, ctx, entry)
			result.Functions[name] = &FuncAnalysis{Intra: intra, Name: name}
		}
	}

	// LCA helper.
	lca := func(a, b int) int { return LCA(a, b, ctx.SuperClass) }

	// Fixed-point iteration.
	for iter := 0; iter < maxIterations; iter++ {
		changed := false

		calleeParamTypes := make(map[string][31]TypeLattice)

		for caller, edges := range blEdges {
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

				current := calleeParamTypes[edge.Callee]
				for r := 0; r < 31; r++ {
					newType := meetType(current[r], argTypes[r], lca)
					if !newType.Equal(current[r]) {
						calleeParamTypes[edge.Callee] = updateReg(calleeParamTypes[edge.Callee], r, newType)
						changed = true
					}
				}
			}
		}

		if !changed {
			break
		}

		// Re-run intra-procedural analysis with updated parameter types.
		// M-6 fix: only iterate the map for the active architecture.
		if isARM64 {
			for name, insts := range funcInstsARM64 {
				entry := calleeParamTypes[name]
				if allTop(entry) {
					for i := range entry {
						entry[i] = Top()
					}
				}
				if entry[receiverReg].Kind == LatticeTop {
					if ownerCID, ok := ctx.FuncOwnerClass[name]; ok && ownerCID >= 0 {
						entry[receiverReg] = KnownClass(ownerCID)
					}
				}
			// TARGET 1: Also update non-receiver params from FuncParamTypes.
			setEntryFromParamTypes(name, &entry)
				intra := AnalyzeFunction(insts, ctx, entry)
				result.Functions[name].Intra = intra
			}
		} else {
			for name, insts := range funcInstsX86 {
				entry := calleeParamTypes[name]
				if allTop(entry) {
					for i := range entry {
						entry[i] = Top()
					}
				}
				if entry[receiverReg].Kind == LatticeTop {
					if ownerCID, ok := ctx.FuncOwnerClass[name]; ok && ownerCID >= 0 {
						entry[receiverReg] = KnownClass(ownerCID)
					}
				}
			// TARGET 1: Also update non-receiver params from FuncParamTypes.
			setEntryFromParamTypes(name, &entry)
				intra := AnalyzeFunctionX86(insts, ctx, entry)
				result.Functions[name].Intra = intra
			}
		}
	}

	// Fase 7 PART A: populate CalleeExitTypes for call-return tracking.
	// Map BL target address → callee's ExitTypes[0] (return value type).
	// Also store full ExitTypes array for full register type propagation.
	for target, name := range blTargetToName {
		if fa, ok := result.Functions[name]; ok && fa.Intra != nil {
			ctx.CalleeExitTypes[target] = fa.Intra.ExitTypes[0]
			ctx.CalleeAllExitTypes[target] = fa.Intra.ExitTypes
		}
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

// BLEdge represents a direct BL call edge for inter-procedural propagation.
type BLEdge struct {
	Callee string
	CallPC uint64 // address of the BL instruction
}

// updateReg returns a copy of types with register r set to newType.
func updateReg(types [31]TypeLattice, r int, newType TypeLattice) [31]TypeLattice {
	types[r] = newType
	return types
}
