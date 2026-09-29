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

// Options bounds Trace's cost. A real Flutter app's libapp.so bundles
// the entire framework -- thousands to tens of thousands of functions,
// per this project's own README -- and running EITHER detector over
// ALL of them unbounded is architecturally the same operation
// `decompile-native --all` without --max already does, which this
// project's own README/WORKFLOW.md/ARCHITECTURE.md document as needing
// ~64GB of RAM and having crashed the whole host (not just the
// process) TWICE on a 5.8GB-RAM machine.
//
// CONFIRMED DIRECTLY during this package's own development (not just
// inherited caution): running Trace with AllowUnbounded against a
// SMALL sample app (3MB libapp.so, 8149 functions -- far smaller than
// a real production app) drove resident set size to 5.4GB on a
// 5.8GB-RAM machine, pushed 1.7GB into swap, evicted nearly all page
// cache, and still hadn't finished after 90 seconds. An earlier
// assumption that FuncIR construction alone (without EmitPseudocode)
// was "cheap enough to run unbounded" was WRONG and is not repeated
// here -- BOTH detectors are gated by the same scan bound below.
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
//     while kFfiTrampoline is callback-only. The decompiler vm_tag marker is
//     kept as an independent legacy structural fallback.
//
// Applies the same hardening decompile-native --all uses for the same
// underlying cost profile: GOMAXPROCS cap, a hard memory-limit
// backstop, and periodic GC.
//
// Returns the findings plus how many functions were actually
// processed -- callers (and this package's own regression tests) can
// use the scanned count to verify bounding actually took effect,
// rather than only inferring it indirectly from findings.
func Trace(ctx *analysis.AnalysisContext, opts Options) ([]Finding, int, error) {
	if ctx == nil {
		return nil, 0, fmt.Errorf("ffi trace: nil analysis context")
	}
	var findings []Finding
	byCodeIndex := ffiOwnerIndex(ctx)
	ffiData := ffiTrampolineIndex(ctx)
	scanOpts := analysis.ScanOptions{
		MaxScan:        opts.MaxScan,
		AllowUnbounded: opts.AllowUnbounded,
		Filter:         opts.Filter,
		GcEveryN:       100,
	}

	scanned, err := ctx.ScanFuncs(scanOpts, func(r cluster.CodeRange, fir *decompiler.FuncIR, funcVA uint64) {
		findings = append(findings, findDynamicLibraryCalls(ctx, fir, funcVA)...)

		// Metadata is the primary signal. It distinguishes old outbound
		// kFfiTrampoline functions from callbacks, and modern FFI call closures
		// from modern callback-only kFfiTrampoline functions.
		nativeCall := isOutboundFfiRange(ctx, r, fir.Name, byCodeIndex, ffiData)
		if !nativeCall {
			art := decompiler.EmitPseudocode(fir, ctx.SymbolLookup, ctx.PoolLookup)
			nativeCall = strings.Contains(art.Source, decompiler.FFICallMarker)
		}
		if nativeCall {
			findings = append(findings, Finding{
				CallerFunc: fir.Name,
				CallerVA:   funcVA,
				Kind:       "native_call_site",
			})
		}
	})
	if err != nil {
		return findings, scanned, fmt.Errorf("scan functions: %w", err)
	}
	return findings, scanned, nil
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

// isOutboundFfiRange classifies function-level outbound FFI wrappers without
// conflating them with native-to-Dart callbacks.
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
func isOutboundFfiRange(ctx *analysis.AnalysisContext, r cluster.CodeRange, funcName string, byCodeIndex map[int]*cluster.NamedObject, ffiData map[int]cluster.FfiTrampolineInfo) bool {
	if ctx == nil || ctx.Pool == nil {
		return false
	}
	owner, ok := naming.ResolveCodeOwner(
		cluster.CodeEntry{RefID: r.RefID, OwnerRef: r.OwnerRef, ClusterIndex: r.Index},
		ctx.Pool.RefToNamed,
		byCodeIndex,
		ctx.Pool.CT,
	)
	if !ok || owner == nil {
		return false
	}
	if owner.FuncKind == cluster.FunctionKindFfiTrampoline {
		// Starting in 3.3, kFfiTrampoline is callback-only. Treat it as a
		// callback even if malformed metadata has a null callback_target; using
		// the old null-target rule here would turn corrupted modern callback
		// metadata into a confident outbound finding.
		if usesModernFfiLowering(ctx.DartVersion) {
			return false
		}
		info, ok := ffiData[owner.DataRefID]
		return ok && info.CallbackTargetRef == cluster.RefNull
	}
	if usesModernFfiLowering(ctx.DartVersion) && owner.HasKindTag && owner.IsNative && owner.IsExternal {
		return true
	}
	return owner.FuncKind == cluster.FunctionKindClosure && looksLikeGeneratedFfiCallClosure(funcName)
}

// usesModernFfiLowering is deliberately limited to the verified Dart 3.x
// boundary. The is_ffi_native predicate and #ffiClosure lowering both appear at
// 3.3. Unknown future major versions stay unclassified until their SDK layout
// is verified; in production HasKindTag is also false for unsupported profiles.
func usesModernFfiLowering(version string) bool {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil || major != 3 {
		return false
	}
	minor, err := strconv.Atoi(parts[1])
	return err == nil && minor >= 3
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
			if !ok || !(looksLikeFfiOpenOrLookup(name) || isLegacyFfiOpenTarget(ctx, va, name)) {
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

// isLegacyFfiOpenTarget covers the pre-3.3 lowering where a
// DynamicLibrary.open use site can call dart:ffi's private `_open` patch helper
// directly. `_open` is too generic to trust by name alone, so require the
// resolved function owner to belong to the dart:ffi library as well.
func isLegacyFfiOpenTarget(ctx *analysis.AnalysisContext, va uint64, name string) bool {
	if !looksLikeLegacyFfiOpenName(name) || ctx == nil || ctx.Result == nil || ctx.Pool == nil || ctx.Info == nil || ctx.Info.Version == nil {
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

func looksLikeLegacyFfiOpenName(name string) bool {
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
		return looksLikeLegacyFfiOpenName(target)
	}
	va, err := strconv.ParseUint(strings.TrimPrefix(target, "0x"), 16, 64)
	if err != nil || ctx == nil {
		return false
	}
	name, ok := ctx.SymbolNames[va]
	if !ok || !looksLikeLegacyFfiOpenName(name) {
		return false
	}
	return isLegacyFfiOpenTarget(ctx, va, name)
}
