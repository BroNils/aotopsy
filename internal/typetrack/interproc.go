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
	return map[int]TypeLattice{slot: ClassBound(ownerCID)}
}

func stripFunctionAddressSuffix(name string) string {
	if idx := strings.LastIndex(name, "_"); idx > 0 {
		if suffix := name[idx+1:]; isHexSuffix(suffix) {
			return name[:idx]
		}
	}
	return name
}

// functionRefIDs prefers the semantic qualified identity. Bare selector names
// are only a fallback and can denote many unrelated Functions; every consumer
// therefore requires all returned candidates to agree before using metadata as
// an inference fact.
func functionRefIDs(ctx *TypeContext, name string) []int {
	lookup := stripFunctionAddressSuffix(name)
	if refs := ctx.MethodNameToRefIDs[lookup]; len(refs) > 0 {
		return refs
	}
	if dot := strings.LastIndex(lookup, "."); dot >= 0 {
		return ctx.MethodNameToRefIDs[lookup[dot+1:]]
	}
	return nil
}

func consensusParamSignature(ctx *TypeContext, refs []int) ([]int, bool, bool) {
	if len(refs) == 0 {
		return nil, false, false
	}
	var want []int
	var wantInstance bool
	for i, rid := range refs {
		pt, ok := ctx.FuncParamTypes[rid]
		if !ok || len(pt) == 0 {
			return nil, false, false
		}
		instance := ctx.FuncIsInstance[rid]
		if i == 0 {
			want = append([]int(nil), pt...)
			wantInstance = instance
			continue
		}
		if instance != wantInstance || len(pt) != len(want) {
			return nil, false, false
		}
		for j := range pt {
			if pt[j] != want[j] {
				return nil, false, false
			}
		}
	}
	return want, wantInstance, true
}

func consensusReturnClass(ctx *TypeContext, refs []int) (int, bool) {
	if len(refs) == 0 {
		return 0, false
	}
	want := -1
	for _, rid := range refs {
		cid, ok := ctx.FuncReturnType[rid]
		if !ok || cid < 0 {
			return 0, false
		}
		if want < 0 {
			want = cid
		} else if cid != want {
			return 0, false
		}
	}
	return want, want >= 0
}

func normalizeReachableEntry(entry *[31]TypeLattice) {
	for i := range entry {
		if entry[i].Kind == LatticeBottom {
			entry[i] = Top()
		}
	}
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

	// Fixed-point telemetry. When Converged is false, Functions contains the
	// conservative fallback analyses rather than the last partial propagation
	// round.
	Iterations int
	Converged  bool
}

// FuncInstsARM64 holds ARM64 function instructions for RunInterprocedural.
type FuncInstsARM64 map[string][]disasm.Inst

// FuncInstsX86 holds x86_64 function instructions for RunInterprocedural.
type FuncInstsX86 map[string][]x86.Decoded

// RunInterprocedural runs the inter-procedural fixed-point algorithm:
//  1. For each function, run intra-procedural analysis with current
//     parameter type estimates (initially all Top).
//  2. For each BL call edge with independently recovered setup evidence,
//     propagate the caller's argument types to the callee's parameters.
//  3. Repeat until no parameter types change (fixed point) or max
//     iterations reached.
//
// Fase 7 PART A: also propagates callee return types (ExitTypes[0]) back
// to callers via ctx.CalleeExitTypes, enabling type chains across calls.
//
// funcInstsARM64 or funcInstsX86 maps function name → instruction list.
// blEdges maps caller name → list of (callee name, argument types at call site).
// blTargetToName maps BL target address → callee function name (for call-return
// tracking). maxIterations is a caller-supplied safety budget; exhaustion is
// fail-closed through the conservative fallback below rather than published as
// a partial fixed point.
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
	// Direct BL/CALL sites are not a closed-world caller census. Code referenced
	// by the dispatch table or by a pool Code/Closure may also be entered through
	// indirect runtime paths that never contribute a BLEdge. Exact runtime facts
	// observed at the direct sites therefore cannot remain Exact at such a
	// callee's entry.
	externallyEnterable := make(map[string]bool)
	markExternallyEnterable := func(name string) {
		if name == "" {
			return
		}
		externallyEnterable[name] = true
		externallyEnterable[stripFunctionAddressSuffix(name)] = true
	}
	for _, name := range ctx.DispatchCodeIndexToName {
		markExternallyEnterable(name)
	}
	for _, name := range ctx.PoolCodeNames {
		markExternallyEnterable(name)
	}
	for _, name := range ctx.PoolClosureFunctionNames {
		markExternallyEnterable(name)
	}
	isExternallyEnterable := func(name string) bool {
		return externallyEnterable[name] || externallyEnterable[stripFunctionAddressSuffix(name)] ||
			sdk.LooksLikeVMStubName(stripFunctionAddressSuffix(name))
	}
	regArgsByFunc := make(map[string][]int)
	if hasRegisterCC {
		masksByFunc := make(map[string][]uint8)
		for _, caller := range sortedKeys(blEdges) {
			for _, edge := range blEdges[caller] {
				if ctx.FuncMayUseRegisterCC[edge.Callee] {
					// Zero is real negative evidence from an observed direct call
					// site: none of the convention registers was set in that site's
					// local setup window. Dropping zero masks would let two positive
					// sites manufacture consensus while a third observed site
					// contradicts it. ResolveArgRegIndices intentionally intersects
					// every observed site, including zero.
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
		paramTypes, isInstance, ok := consensusParamSignature(ctx, functionRefIDs(ctx, name))
		if !ok {
			return
		}
		// For instance methods, parameter 0 is 'this' (receiver in R1).
		// Parameters 1..N map to argRegOrder[1..N] = {R2, R3, R5, R6, R7}.
		// For static methods, parameters 0..N map to argRegOrder[0..N].
		// CRITICAL FIX: param i maps to argRegOrder[i], NOT argRegOrder[i-startIdx].
		// Dart AOT calling convention: param 0 (this) → R1, param 1 → R2, param 2 → R3, etc.
		// For instance methods, we skip param 0 (this, already set from FuncOwnerClass),
		// but param 1 still maps to argRegOrder[1]=R2, not argRegOrder[0]=R1.
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
					entry[regIdx] = ClassBound(cid)
				}
			}
		}
	}

	// Analyse functions in a deterministic order. AnalyzeFunction mutates the
	// shared TypeContext (telemetry, selector offsets, and resolution caches), so
	// what function A records is visible to function B: iterating
	// the map directly made the resolved-BLR set differ between runs of the
	// same binary.
	if isARM64 {
		for _, name := range sortedKeys(funcInstsARM64) {
			insts := funcInstsARM64[name]
			var entry [31]TypeLattice
			for i := range entry {
				entry[i] = Top()
			}
			if ownerCID, ok := ctx.FuncOwnerClass[name]; ok && ownerCID >= 0 {
				if receiverReg >= 0 && hasRegPosition(name, 0) {
					entry[receiverReg] = ClassBound(ownerCID)
				}
			}
			// TARGET 1: Also set entry types for non-receiver parameters.
			setEntryFromParamTypes(name, &entry)
			// Pre-3.4.3 the receiver arrives on the stack and the prologue
			// immediately overwrites the register, so the register seed alone is
			// dead on arrival; the stack seed also carries the declared type of
			// every stack-passed parameter.
			intra := AnalyzeFunction(insts, ctx, entry, entryStackSeed(ctx, name))
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
				entry[receiverReg] = ClassBound(ownerCID)
			}
			// TARGET 1: Also set entry types for non-receiver parameters.
			setEntryFromParamTypes(name, &entry)
			intra := AnalyzeFunctionX86(insts, ctx, entry, entryStackSeed(ctx, name))
			result.Functions[name] = &FuncAnalysis{Intra: intra, Name: name}
		}
	}

	// Seed CalleeExitTypes from declared return types (FuncReturnType).
	seedHits := 0
	for target, name := range blTargetToName {
		if cid, ok := consensusReturnClass(ctx, functionRefIDs(ctx, name)); ok {
			ctx.CalleeExitTypes[target] = ClassBound(cid)
			seedHits++
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
			if fa.Intra.ExitTypes[0].Kind != LatticeTop && fa.Intra.ExitTypes[0].Kind != LatticeBottom {
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
	converged := false
	iterations := 0
	for iter := 0; iter < maxIterations; iter++ {
		iterations = iter + 1
		calleeParamTypes := make(map[string][31]TypeLattice)

		for _, caller := range sortedKeys(blEdges) {
			edges := blEdges[caller]
			callerAnalysis, ok := result.Functions[caller]
			if !ok {
				continue
			}

			for _, edge := range edges {
				// Use BLCallSiteTypes (register state immediately before the call)
				// instead of ExitTypes (state at function exit). Ordinary Dart calls
				// clobber the SDK-defined allocatable set, which is broader than just
				// argument registers, so exit state is not call-site evidence.
				if callerAnalysis.Intra.BLCallSiteTypes == nil {
					continue
				}
				argTypes, ok := callerAnalysis.Intra.BLCallSiteTypes[edge.CallPC]
				if !ok {
					// Function-exit state is not call-site evidence. Falling back to
					// it can assign a value created after the call to a callee argument.
					continue
				}

				positions := regArgsByFunc[edge.Callee]
				if len(positions) == 0 {
					continue
				}
				current := calleeParamTypes[edge.Callee]
				for _, pos := range positions {
					r := argRegOrder[pos]
					incoming := argTypes[r]
					if isExternallyEnterable(edge.Callee) {
						incoming = openWorldEntryFact(incoming)
					}
					newType := joinType(current[r], incoming, lca)
					if !newType.Equal(current[r]) {
						calleeParamTypes[edge.Callee] = updateReg(calleeParamTypes[edge.Callee], r, newType)
					}
				}
			}
		}

		changed := !paramTypeMapsEqual(prevParamTypes, calleeParamTypes)
		if !changed && !needReanalysis {
			converged = true
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
				normalizeReachableEntry(&entry)
				if receiverReg >= 0 && hasRegPosition(name, 0) && entry[receiverReg].Kind == LatticeTop {
					if ownerCID, ok := ctx.FuncOwnerClass[name]; ok && ownerCID >= 0 {
						entry[receiverReg] = ClassBound(ownerCID)
					}
				}
				// TARGET 1: Also update non-receiver params from FuncParamTypes.
				setEntryFromParamTypes(name, &entry)
				intra := AnalyzeFunction(insts, ctx, entry, entryStackSeed(ctx, name))
				result.Functions[name].Intra = intra
			}
		} else {
			for _, name := range sortedKeys(funcInstsX86) {
				insts := funcInstsX86[name]
				entry := calleeParamTypes[name]
				normalizeReachableEntry(&entry)
				if receiverReg >= 0 && hasRegPosition(name, 0) && entry[receiverReg].Kind == LatticeTop {
					if ownerCID, ok := ctx.FuncOwnerClass[name]; ok && ownerCID >= 0 {
						entry[receiverReg] = ClassBound(ownerCID)
					}
				}
				// TARGET 1: Also update non-receiver params from FuncParamTypes.
				setEntryFromParamTypes(name, &entry)
				intra := AnalyzeFunctionX86(insts, ctx, entry, entryStackSeed(ctx, name))
				result.Functions[name].Intra = intra
			}
		}

		// Update CalleeExitTypes after each re-analysis pass, so the
		// NEXT iteration's handleBL can see callee return types.
		// Don't overwrite FuncReturnType seeds with Top — the declared
		// return type is more precise than "analysis found nothing".
		for target, name := range blTargetToName {
			if fa, ok := result.Functions[name]; ok && fa.Intra != nil {
				if fa.Intra.ExitTypes[0].Kind != LatticeTop && fa.Intra.ExitTypes[0].Kind != LatticeBottom {
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
		// Selector candidates depend only on immutable dispatch-table evidence;
		// partial observed-instantiation data is deliberately not a filter.
	}

	result.Iterations = iterations
	result.Converged = converged
	ctx.InterIterations = iterations
	ctx.InterConverged = converged

	if !converged {
		// Hitting the resource budget is not proof of a fixed point. The final
		// partial round can still be too precise when a deeper caller has not yet
		// contributed a conflicting type. Discard interprocedural facts and run
		// one conservative pass from independently justified receiver/register
		// evidence plus declared static bounds.
		ctx.CalleeExitTypes = make(map[uint64]TypeLattice)
		ctx.CalleeAllExitTypes = make(map[uint64][31]TypeLattice)
		for target, name := range blTargetToName {
			if cid, ok := consensusReturnClass(ctx, functionRefIDs(ctx, name)); ok {
				ctx.CalleeExitTypes[target] = ClassBound(cid)
			}
		}

		if isARM64 {
			for _, name := range sortedKeys(funcInstsARM64) {
				var entry [31]TypeLattice
				for i := range entry {
					entry[i] = Top()
				}
				if receiverReg >= 0 && hasRegPosition(name, 0) {
					if ownerCID, ok := ctx.FuncOwnerClass[name]; ok && ownerCID >= 0 {
						entry[receiverReg] = ClassBound(ownerCID)
					}
				}
				setEntryFromParamTypes(name, &entry)
				intra := AnalyzeFunction(funcInstsARM64[name], ctx, entry, entryStackSeed(ctx, name))
				result.Functions[name] = &FuncAnalysis{Intra: intra, Name: name}
			}
		} else {
			for _, name := range sortedKeys(funcInstsX86) {
				var entry [31]TypeLattice
				for i := range entry {
					entry[i] = Top()
				}
				if receiverReg >= 0 && hasRegPosition(name, 0) {
					if ownerCID, ok := ctx.FuncOwnerClass[name]; ok && ownerCID >= 0 {
						entry[receiverReg] = ClassBound(ownerCID)
					}
				}
				setEntryFromParamTypes(name, &entry)
				intra := AnalyzeFunctionX86(funcInstsX86[name], ctx, entry, entryStackSeed(ctx, name))
				result.Functions[name] = &FuncAnalysis{Intra: intra, Name: name}
			}
		}

		// Publish exits from the conservative pass for downstream consumers, but
		// do not feed them back into another interprocedural propagation round.
		for target, name := range blTargetToName {
			if fa, ok := result.Functions[name]; ok && fa.Intra != nil {
				ctx.CalleeAllExitTypes[target] = fa.Intra.ExitTypes
				if ret := fa.Intra.ExitTypes[0]; ret.Kind != LatticeTop && ret.Kind != LatticeBottom {
					ctx.CalleeExitTypes[target] = ret
				}
			}
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

// openWorldEntryFact removes exactness that is justified only by the observed
// direct callers. A ClassBound remains valid for additional subclass/indirect
// callers; other value-specific lattice facts have no equivalent open-world
// guarantee and become Top.
func openWorldEntryFact(v TypeLattice) TypeLattice {
	switch v.Kind {
	case LatticeBottom, LatticeTop:
		return v
	case LatticeExactClass:
		return ClassBound(v.ClassID)
	case LatticeClassBound:
		return v
	default:
		return Top()
	}
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

// StackParam is one stack-passed parameter with a declared class (see
// TypeContext.FuncStackParams).
type StackParam struct {
	Slot  int // FP-relative byte offset
	Class int // class id of the declared parameter type
}

// DeclaredParamClasses returns the declared class of every parameter of the
// function (index 0 = the receiver of an instance method), -1 where the
// declared type has no class (dynamic, a type parameter, a function type). ok is
// false when the metadata of the candidate Functions disagrees or is missing.
func (ctx *TypeContext) DeclaredParamClasses(name string) ([]int, bool) {
	classes, _, ok := consensusParamSignature(ctx, functionRefIDs(ctx, name))
	return classes, ok
}

// entryStackSeed builds the first-block stack seed of a function: the receiver
// slot (owner class) and every stack parameter with a declared class. A slot
// holds an upper bound, so the owner class wins for the receiver.
func entryStackSeed(ctx *TypeContext, name string) map[int]TypeLattice {
	seed := entryStackFor(ctx, name)
	for _, p := range ctx.FuncStackParams[name] {
		if _, taken := seed[p.Slot]; taken || p.Class < 0 {
			continue
		}
		if seed == nil {
			seed = make(map[int]TypeLattice)
		}
		seed[p.Slot] = ClassBound(p.Class)
	}
	return seed
}
