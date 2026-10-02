// Package ffitrace statically traces Dart AOT code for dart:ffi usage:
// which functions call out to a native library, and (where the
// arguments are literal strings, not computed at runtime) which
// library path and symbol name a DynamicLibrary.open/lookup call
// resolves to. Pure static analysis -- no CPU emulation, no live
// device, no Unicorn/cgo dependency. See docs/plan-phase1-dart-aot-
// emulation-harness.md's Komponen H.
package ffitrace

import (
	"fmt"
	"strconv"
	"strings"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/naming"
	"aotopsy/internal/sdk"
	"aotopsy/internal/snapshot"
)

// Finding is one FFI-relevant observation: either a resolved (or attempted)
// DynamicLibrary.open/lookup call site, or a Dart-to-native FFI call wrapper.
type Finding struct {
	CallerFunc string `json:"caller_func"`
	CallerVA   uint64 `json:"caller_va"`
	CallSitePC uint64 `json:"call_site_pc,omitempty"`
	Kind       string `json:"kind"`
	CalleeName string `json:"callee_name,omitempty"`
	LiteralArg string `json:"literal_arg,omitempty"`
	Resolved   bool   `json:"resolved"`
}

// Result makes bounded-scan completeness explicit. A non-empty Findings slice
// with ScanLimitReached=true is a valid prefix, not a complete FFI inventory.
type Result struct {
	Findings         []Finding
	Attempted        int
	Scanned          int
	ScanLimitReached bool
}

// Options bounds Trace's cost. A real Flutter app's libapp.so bundles
// the entire framework -- thousands to tens of thousands of functions,
// per this project's own README -- and running EITHER detector over
// ALL of them unbounded is architecturally the same operation
// `decompile-native --all` without --max already does, which this
// project's own README/WORKFLOW.md/ARCHITECTURE.md document as needing
// ~64GB of RAM and having crashed the whole host (not just the
// process) TWICE on a 5.8GB-RAM machine.
//
// CONFIRMED DIRECTLY during this package's own development: an older Trace
// implementation that also ran EmitPseudocode as a vm_tag direction fallback
// reached 5.4GB RSS + 1.7GB swap on an 8149-function sample. That fallback has
// been removed because the SDK proves vm_tag transitions are direction-neutral
// (callback NativeReturn uses them too), but FuncIR construction is still
// bounded here rather than assuming an unbounded real-app scan is cheap.
type Options struct {
	// MaxScan caps how many functions Trace processes with EITHER
	// detector. 0 means use the package default (500, matching
	// decompile-native --all's own default --max). Ignored if
	// AllowUnbounded is true.
	MaxScan int
	// AllowUnbounded opts into scanning every function, same as
	// decompile-native --all with --max 0 -- the caller is asserting
	// they understand the RAM/host-crash risk documented above
	// (measured directly at 5.4GB RSS + 1.7GB swap on an 8149-function
	// SAMPLE app) and have sized the host accordingly. Do not set this
	// against a real production app's libapp.so on a memory-
	// constrained host.
	AllowUnbounded bool
	// Filter restricts scanning to functions whose resolved name
	// contains this substring, mirroring decompile-native --all
	// --filter. Empty means no restriction. Prefer this over
	// AllowUnbounded when a specific neighborhood is already known.
	Filter string
}

// Trace runs two detectors per function, both gated by the same scan
// bound (see Options):
//
//  1. findDynamicLibraryCalls: resolved direct calls to exactly the
//     DynamicLibrary open/lookup APIs, with a string accepted only when local
//     call-site dataflow proves an object-pool literal reaches an outgoing
//     stack/register argument. Constant-specialized DynamicLibrary.open
//     wrappers are followed one level, because current AOT moves the literal
//     into that wrapper rather than leaving it at the caller.
//  2. Dart-to-native call wrappers. Up through Dart 3.2, kFfiTrampoline is
//     accepted only when its FfiTrampolineData says callback_target == null;
//     callbacks use the same Function::Kind and must not be mislabeled. Dart
//     3.3+ lowers outbound calls to compiler-generated #ffiClosureN closures,
//     while kFfiTrampoline is callback-only. Thread::vm_tag transitions are
//     deliberately NOT used as a direction fallback: callback NativeReturn and
//     outbound FFI calls both execute TransitionGeneratedToNative.
//
// Applies the same hardening decompile-native --all uses for the same
// underlying cost profile: GOMAXPROCS cap, a hard memory-limit
// backstop, and periodic GC.
//
// Returns findings plus explicit scan-completeness state.
func Trace(ctx *analysis.AnalysisContext, opts Options) (Result, error) {
	var result Result
	if ctx == nil {
		return result, fmt.Errorf("ffi trace: nil analysis context")
	}
	byCodeIndex := ffiOwnerIndex(ctx)
	ffiData := ffiTrampolineIndex(ctx)
	scanOpts := analysis.ScanOptions{
		MaxScan:        opts.MaxScan,
		AllowUnbounded: opts.AllowUnbounded,
		Filter:         opts.Filter,
		GcEveryN:       100,
	}

	scanResult, err := ctx.ScanFuncs(scanOpts, func(r cluster.CodeRange, fir *decompiler.FuncIR, funcVA uint64) {
		result.Findings = append(result.Findings, findDynamicLibraryCalls(ctx, fir, funcVA)...)

		if classifyFfiRange(ctx, r, fir.Name, byCodeIndex, ffiData) == cluster.FfiDirectionOutbound {
			result.Findings = append(result.Findings, Finding{
				CallerFunc: fir.Name,
				CallerVA:   funcVA,
				Kind:       "native_call_site",
			})
		}
	})
	result.Attempted = scanResult.Attempted
	result.Scanned = scanResult.Scanned
	result.ScanLimitReached = scanResult.ScanLimitReached
	if err != nil {
		return result, fmt.Errorf("scan functions: %w", err)
	}
	return result, nil
}

func ffiOwnerIndex(ctx *analysis.AnalysisContext) map[int]*cluster.NamedObject {
	if ctx == nil || ctx.Result == nil || ctx.Info == nil || ctx.Info.Version == nil || ctx.Pool == nil {
		return nil
	}
	firstEntryWithCode := -1
	if ctx.InstrTable != nil {
		firstEntryWithCode = int(ctx.InstrTable.FirstEntryWithCode)
	}
	return naming.CodeIndexToFunc(ctx.Result, ctx.Info.Version.CIDs, ctx.Info.Version.CodeIndexOneBased, firstEntryWithCode)
}

func ffiTrampolineIndex(ctx *analysis.AnalysisContext) map[int]cluster.FfiTrampolineInfo {
	if ctx == nil || ctx.Result == nil {
		return nil
	}
	out := make(map[int]cluster.FfiTrampolineInfo, len(ctx.Result.FfiTrampolines))
	for _, info := range ctx.Result.FfiTrampolines {
		out[info.RefID] = info
	}
	return out
}

// classifyFfiRange classifies function-level FFI wrappers without conflating
// outbound Dart->native calls with native->Dart callbacks. A direction is
// returned only from Function/FfiTrampolineData metadata whose semantics are
// verified for the exact supported SDK range; ambiguous structural transition
// markers are never promoted to an outbound claim.
//
// The SDK changed representation at Dart 3.3:
//   - older SDKs use kFfiTrampoline for both directions; FfiTrampolineData's
//     callback_target is null only for outbound calls;
//   - 3.3+ uses kFfiTrampoline only for callbacks. @Native functions are marked
//     by Function::is_ffi_native() == is_native() && is_external(), while the
//     Pointer.asFunction use-site transform synthesizes an ordinary closure
//     named #ffiClosureN and tags it vm:ffi:call-closure.
//
// Full AOT snapshots serialize Function.kind_tag_, so HasKindTag plus the
// native/external flags is direct metadata for @Native on 3.3+. We do not have
// the vm:ffi:call-closure pragma object itself, so the compiler-generated
// closure name remains the serialized discriminator for Pointer.asFunction.
// Unknown/missing metadata is an honest false negative rather than a callback
// false positive.
func classifyFfiRange(ctx *analysis.AnalysisContext, r cluster.CodeRange, funcName string, byCodeIndex map[int]*cluster.NamedObject, ffiData map[int]cluster.FfiTrampolineInfo) cluster.FfiDirection {
	if ctx == nil || ctx.Pool == nil {
		return cluster.FfiDirectionUnknown
	}
	owner, ok := naming.ResolveCodeOwner(
		cluster.CodeEntry{RefID: r.RefID, OwnerRef: r.OwnerRef, ClusterIndex: r.Index},
		ctx.Pool.RefToNamed,
		byCodeIndex,
		ctx.Pool.CT,
	)
	if !ok || owner == nil {
		return cluster.FfiDirectionUnknown
	}
	if owner.FuncKind == cluster.FunctionKindFfiTrampoline {
		if usesModernFfiLowering(ctx.DartVersion) {
			return cluster.FfiDirectionCallback
		}
		info, ok := ffiData[owner.DataRefID]
		if !ok {
			return cluster.FfiDirectionUnknown
		}
		return cluster.ClassifyFfiTrampolineDirection(ctx.DartVersion, info)
	}
	if usesModernFfiLowering(ctx.DartVersion) && owner.HasKindTag && owner.IsNative && owner.IsExternal {
		return cluster.FfiDirectionOutbound
	}
	if usesModernFfiLowering(ctx.DartVersion) && owner.FuncKind == cluster.FunctionKindClosure && looksLikeGeneratedFfiCallClosure(funcName) {
		return cluster.FfiDirectionOutbound
	}
	return cluster.FfiDirectionUnknown
}

// usesModernFfiLowering is deliberately limited to repository-supported exact
// versions. The is_ffi_native predicate and #ffiClosure lowering both appear at
// Dart 3.3.0. Unknown/future versions stay unclassified until their SDK source
// and snapshot layout have been verified and a profile exists here.
func usesModernFfiLowering(version string) bool {
	return snapshot.ProfileForVersion(version) != nil && snapshot.VersionAtLeast(version, "3.3.0")
}

// findDynamicLibraryCalls scans one function's blocks for direct calls
// resolving to a dart:ffi DynamicLibrary open/lookup method. Literal
// resolution is deliberately block-local, but it follows real outgoing
// call-site dataflow rather than FuncIR.ArgRegs. ArgRegs describes this
// *caller's incoming* calling convention and is not evidence about a callee's
// arguments. Stack stores are therefore tracked for every supported SDK, and
// the register calling convention is considered only in versions where it
// exists. Cached-field/cross-block values remain unresolved rather than being
// guessed.
func findDynamicLibraryCalls(ctx *analysis.AnalysisContext, fir *decompiler.FuncIR, funcVA uint64) []Finding {
	var out []Finding
	callArgRegs := make(map[string]bool)
	if cc, ok := sdk.DartRegisterCallingConvention(ctx.DartVersion, ctx.IsARM64); ok {
		for _, reg := range cc.GPRNames {
			callArgRegs[strings.ToLower(reg)] = true
		}
	}
	for _, blk := range fir.Blocks {
		literalByReg := make(map[string]string)
		literalByStackSlot := make(map[string]string)
		for _, ins := range blk.Instrs {
			if ins.Op == decompiler.OpLoadPool {
				invalidateDefinedRegs(literalByReg, ins.DefRegs)
				reg := strings.ToLower(ins.Target)
				if s, ok := decodedPoolString(ctx.PoolDisplay[ins.PoolIndex]); ok {
					literalByReg[reg] = s
				} else {
					delete(literalByReg, reg)
				}
				continue
			}
			if ins.Op != decompiler.OpCall || ins.Target == "" {
				trackLiteralFlow(fir, ins, literalByReg, literalByStackSlot, ctx.IsARM64)
				continue
			}
			literalArg, haveLiteral := uniqueCallLiteral(literalByReg, literalByStackSlot, callArgRegs)
			if !strings.HasPrefix(ins.Target, "0x") {
				// Pre-resolved callee name (not a hex VA). If it already
				// looks like an ffi DynamicLibrary.open / lookupFunction
				// call site, record it directly without needing a symbol
				// lookup -- the decompiler resolved the target name already.
				if looksLikeFfiOpenOrLookup(ins.Target) {
					f := Finding{
						CallerFunc: fir.Name,
						CallerVA:   funcVA,
						CallSitePC: ins.Addr,
						Kind:       "dynamic_library_call",
						CalleeName: ins.Target,
					}
					if haveLiteral {
						f.LiteralArg = literalArg
						f.Resolved = true
					}
					out = append(out, f)
				}
				clear(literalByReg)
				clear(literalByStackSlot)
				continue // indirect call (register target) -- not a directly-resolved callee name
			}
			va, err := strconv.ParseUint(strings.TrimPrefix(ins.Target, "0x"), 16, 64)
			if err != nil {
				clear(literalByReg)
				clear(literalByStackSlot)
				continue
			}
			name, ok := ctx.SymbolNames[va]
			if !ok || !(looksLikeFfiOpenOrLookup(name) || isPrivateFfiOpenTarget(ctx, va, name)) {
				clear(literalByReg)
				clear(literalByStackSlot)
				continue
			}
			if !haveLiteral && looksLikeDynamicLibraryOpen(name) {
				literalArg, haveLiteral = literalPassedInsideCallee(ctx, va)
			}
			f := Finding{
				CallerFunc: fir.Name,
				CallerVA:   funcVA,
				CallSitePC: ins.Addr,
				Kind:       "dynamic_library_call",
				CalleeName: name,
			}
			if haveLiteral {
				f.LiteralArg = literalArg
				f.Resolved = true
			}
			out = append(out, f)
			clear(literalByReg)
			clear(literalByStackSlot)
		}
	}
	return out
}

func looksLikeFfiOpenOrLookup(name string) bool {
	lower := normalizedRecoveredName(name)
	for _, method := range []string{
		"dynamiclibrary.open",
		"dynamiclibrary.lookup",
		"dynamiclibrary.lookupfunction",
		"dynamiclibraryextension.lookupfunction",
	} {
		if containsQualifiedMethod(lower, method) {
			return true
		}
	}
	return false
}

func looksLikeDynamicLibraryOpen(name string) bool {
	return containsQualifiedMethod(normalizedRecoveredName(name), "dynamiclibrary.open")
}

// isPrivateFfiOpenTarget covers dart:ffi's private `_open` patch helper, used
// by DynamicLibrary.open across the supported range (SDK @2.10.0 and @3.13.0
// sdk/lib/_internal/vm/lib/ffi_dynamic_library_patch.dart: both factory bodies
// call `_open`). `_open` is too generic to trust by name alone, so require the
// resolved function owner to belong to the dart:ffi library as well.
func isPrivateFfiOpenTarget(ctx *analysis.AnalysisContext, va uint64, name string) bool {
	if !looksLikePrivateFfiOpenName(name) || ctx == nil || ctx.Result == nil || ctx.Pool == nil || ctx.Info == nil || ctx.Info.Version == nil {
		return false
	}
	var target cluster.CodeRange
	found := false
	for _, r := range ctx.Ranges {
		fs, ok := ctx.Slice(r)
		if ok && fs.VA == va {
			target, found = r, true
			break
		}
	}
	if !found {
		return false
	}
	owner, ok := naming.ResolveCodeOwner(
		cluster.CodeEntry{RefID: target.RefID, OwnerRef: target.OwnerRef, ClusterIndex: target.Index},
		ctx.Pool.RefToNamed,
		ffiOwnerIndex(ctx),
		ctx.Pool.CT,
	)
	if !ok || owner == nil {
		return false
	}
	resolver := analysis.NewLibraryResolver(ctx.Result, ctx.Pool)
	classRef := resolver.EffectiveClassRef(owner.OwnerRefID)
	return resolver.LibraryURLForClassRef(classRef) == "dart:ffi"
}

func looksLikePrivateFfiOpenName(name string) bool {
	name = normalizedRecoveredName(name)
	if name == "_open" || strings.HasSuffix(name, "::_open") || strings.HasSuffix(name, "._open") {
		return true
	}
	i := strings.LastIndex(name, "_open@")
	if i < 0 {
		return false
	}
	tail := name[i+len("_open@"):]
	if tail == "" {
		return false
	}
	for j := 0; j < len(tail); j++ {
		if tail[j] < '0' || tail[j] > '9' {
			return false
		}
	}
	return true
}

func containsQualifiedMethod(s, method string) bool {
	for start := 0; ; {
		i := strings.Index(s[start:], method)
		if i < 0 {
			return false
		}
		i += start
		beforeOK := i == 0 || !isIdentifierByte(s[i-1])
		end := i + len(method)
		afterOK := end == len(s) || !isIdentifierByte(s[end])
		if beforeOK && afterOK {
			return true
		}
		start = i + 1
	}
}

func isIdentifierByte(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
}

func decodedPoolString(display string) (string, bool) {
	if len(display) < 2 || display[0] != '"' {
		return "", false
	}
	s, err := strconv.Unquote(display)
	if err != nil {
		return "", false
	}
	return s, true
}

func normalizedRecoveredName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	// naming.QualifiedName appends _<pcOffset in hex> to every recovered
	// function. Match semantic names before that local disambiguator; otherwise
	// `DynamicLibrary.lookup_3dd24` is rejected because '_' is an identifier byte.
	if i := strings.LastIndexByte(lower, '_'); i >= 0 && i+1 < len(lower) && allHex(lower[i+1:]) {
		return lower[:i]
	}
	return lower
}

func allHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}

func looksLikeGeneratedFfiCallClosure(name string) bool {
	name = normalizedRecoveredName(name)
	for _, prefix := range []string{"#fficlosure", ".#fficlosure"} {
		i := strings.LastIndex(name, prefix)
		if i < 0 {
			continue
		}
		tail := name[i+len(prefix):]
		if tail == "" {
			continue
		}
		allDigits := true
		for j := 0; j < len(tail); j++ {
			if tail[j] < '0' || tail[j] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return true
		}
	}
	return false
}

func invalidateDefinedRegs(values map[string]string, regs []string) {
	for _, reg := range regs {
		delete(values, strings.ToLower(reg))
	}
}

func trackLiteralFlow(fir *decompiler.FuncIR, ins decompiler.Instr, literalByReg, literalByStackSlot map[string]string, isARM64 bool) {
	// Capture source facts before invalidating the destination: `mov x1, x2`
	// may overwrite x1 with a literal that currently lives in x2.
	copyDst, copySrc, isCopy := simpleRegisterCopy(ins.Src)
	copyLiteral, copyHasLiteral := literalByReg[copySrc]
	stackSlot, stackSrc, isStackStore := stackStoreSource(ins.Src, fir.StackReg, isARM64)
	stackLiteral, stackHasLiteral := literalByReg[stackSrc]
	pushSrc, isPush := pushedRegister(ins.Src)
	pushLiteral, pushHasLiteral := literalByReg[pushSrc]

	invalidateDefinedRegs(literalByReg, ins.DefRegs)
	if isCopy {
		if copyHasLiteral {
			literalByReg[copyDst] = copyLiteral
		} else {
			delete(literalByReg, copyDst)
		}
	}
	if isStackStore {
		if stackHasLiteral {
			literalByStackSlot[stackSlot] = stackLiteral
		} else {
			delete(literalByStackSlot, stackSlot)
		}
	}
	if isPush && pushHasLiteral {
		// Dart 2.x x86_64 passes arguments with PUSH rather than stores to
		// pre-reserved [rsp+N] slots. Each push is a distinct outgoing slot;
		// keying by instruction address preserves multiple string arguments and
		// lets uniqueCallLiteral reject ambiguity instead of taking the nearest.
		literalByStackSlot["push@"+strconv.FormatUint(ins.Addr, 16)] = pushLiteral
	}
}

func pushedRegister(src string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(src))
	if !strings.HasPrefix(s, "push ") {
		return "", false
	}
	reg := strings.TrimSpace(strings.TrimPrefix(s, "push "))
	return reg, isPlainRegister(reg)
}

func simpleRegisterCopy(src string) (dst, source string, ok bool) {
	s := strings.ToLower(strings.TrimSpace(src))
	if !strings.HasPrefix(s, "mov ") {
		return "", "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(s, "mov "))
	comma := strings.IndexByte(rest, ',')
	if comma < 0 {
		return "", "", false
	}
	dst = strings.TrimSpace(rest[:comma])
	source = strings.TrimSpace(rest[comma+1:])
	if !isPlainRegister(dst) || !isPlainRegister(source) {
		return "", "", false
	}
	return dst, source, true
}

func isPlainRegister(s string) bool {
	if s == "" || strings.ContainsAny(s, "[]+ -#") {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9') {
			return false
		}
	}
	return true
}

func stackStoreSource(src, stackReg string, isARM64 bool) (slot, sourceReg string, ok bool) {
	s := strings.ToLower(strings.TrimSpace(src))
	stackReg = strings.ToLower(strings.TrimSpace(stackReg))
	if stackReg == "" {
		return "", "", false
	}
	if isARM64 {
		if !(strings.HasPrefix(s, "str ") || strings.HasPrefix(s, "stur ")) {
			return "", "", false
		}
		rest := strings.TrimSpace(s[strings.IndexByte(s, ' ')+1:])
		comma := strings.IndexByte(rest, ',')
		if comma < 0 {
			return "", "", false
		}
		sourceReg = strings.TrimSpace(rest[:comma])
		slot = strings.TrimSpace(rest[comma+1:])
		if !memoryUsesBase(slot, stackReg) {
			return "", "", false
		}
		return slot, sourceReg, true
	}

	if !strings.HasPrefix(s, "mov ") {
		return "", "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(s, "mov "))
	comma := strings.LastIndexByte(rest, ',')
	if comma < 0 {
		return "", "", false
	}
	slot = strings.TrimSpace(rest[:comma])
	sourceReg = strings.TrimSpace(rest[comma+1:])
	if !memoryUsesBase(slot, stackReg) {
		return "", "", false
	}
	return slot, sourceReg, true
}

func memoryUsesBase(mem, base string) bool {
	mem = strings.ReplaceAll(strings.ToLower(mem), " ", "")
	base = strings.ToLower(base)
	return strings.HasPrefix(mem, "["+base+"]") || strings.HasPrefix(mem, "["+base+",") || strings.HasPrefix(mem, "["+base+"+") || strings.HasPrefix(mem, "["+base+"-")
}

func uniqueCallLiteral(regValues, stackValues map[string]string, callArgRegs map[string]bool) (string, bool) {
	values := make(map[string]bool)
	for _, value := range stackValues {
		values[value] = true
	}
	for reg, value := range regValues {
		if callArgRegs[reg] {
			values[value] = true
		}
	}
	if len(values) != 1 {
		return "", false
	}
	for value := range values {
		return value, true
	}
	return "", false
}

func literalPassedInsideCallee(ctx *analysis.AnalysisContext, va uint64) (string, bool) {
	if ctx == nil {
		return "", false
	}
	var target cluster.CodeRange
	found := false
	for _, r := range ctx.Ranges {
		fs, ok := ctx.Slice(r)
		if ok && fs.VA == va {
			target, found = r, true
			break
		}
	}
	if !found {
		return "", false
	}
	fir, err := ctx.FuncIRFor(target)
	if err != nil || fir == nil {
		return "", false
	}
	return literalPassedToOpenHelper(ctx, fir)
}

// literalPassedToOpenHelper follows only the SDK DynamicLibrary.open -> _open
// edge. Accepting a literal passed to an arbitrary call inside the wrapper can
// mislabel an unrelated logging/error string as the library path when the real
// _open argument is computed at runtime.
func literalPassedToOpenHelper(ctx *analysis.AnalysisContext, fir *decompiler.FuncIR) (string, bool) {
	callArgRegs := make(map[string]bool)
	if cc, ok := sdk.DartRegisterCallingConvention(ctx.DartVersion, ctx.IsARM64); ok {
		for _, reg := range cc.GPRNames {
			callArgRegs[strings.ToLower(reg)] = true
		}
	}
	values := make(map[string]bool)
	for _, blk := range fir.Blocks {
		literalByReg := make(map[string]string)
		literalByStackSlot := make(map[string]string)
		for _, ins := range blk.Instrs {
			if ins.Op == decompiler.OpLoadPool {
				invalidateDefinedRegs(literalByReg, ins.DefRegs)
				if s, ok := decodedPoolString(ctx.PoolDisplay[ins.PoolIndex]); ok {
					literalByReg[strings.ToLower(ins.Target)] = s
				}
				continue
			}
			if ins.Op != decompiler.OpCall || ins.Target == "" {
				trackLiteralFlow(fir, ins, literalByReg, literalByStackSlot, ctx.IsARM64)
				continue
			}
			if isDynamicLibraryOpenHelperCall(ctx, ins.Target) {
				if value, ok := uniqueCallLiteral(literalByReg, literalByStackSlot, callArgRegs); ok {
					values[value] = true
				}
			}
			clear(literalByReg)
			clear(literalByStackSlot)
		}
	}
	if len(values) != 1 {
		return "", false
	}
	for value := range values {
		return value, true
	}
	return "", false
}

func isDynamicLibraryOpenHelperCall(ctx *analysis.AnalysisContext, target string) bool {
	if target == "" {
		return false
	}
	if !strings.HasPrefix(target, "0x") {
		return looksLikePrivateFfiOpenName(target)
	}
	va, err := strconv.ParseUint(strings.TrimPrefix(target, "0x"), 16, 64)
	if err != nil || ctx == nil {
		return false
	}
	name, ok := ctx.SymbolNames[va]
	if !ok || !looksLikePrivateFfiOpenName(name) {
		return false
	}
	return isPrivateFfiOpenTarget(ctx, va, name)
}
