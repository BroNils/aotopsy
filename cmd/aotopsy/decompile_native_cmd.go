package main

import (
	"bufio"
	"debug/elf"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/disasm"
	"aotopsy/internal/elfx"
	"aotopsy/internal/pipeline"
	"aotopsy/internal/snapshot"
)

// cmdDecompileNative implements "aotopsy _debug decompile-native --lib
// <path> --func <hex VA>": Dart-AOT-aware pseudocode generation, ported
// from flutterdec's flutterdec-decompiler crate, with NO dependency on
// Ghidra (unlike aotopsy's existing top-level "decompile" command,
// which is purely a Ghidra-headless orchestration wrapper). Works for
// both ARM64 and x86_64 builds -- flutterdec itself is ARM64-only.
func cmdDecompileNative(args []string) error {
	fs := flag.NewFlagSet("decompile-native", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so (ARM64 or x86_64)")
	funcVAStr := fs.String("func", "", "hex VA of any address inside the target function")
	all := fs.Bool("all", false, "decompile every function, writing one combined.dart file under --out -- EXPENSIVE (a real Flutter app's libapp.so bundles the whole framework, easily thousands of functions), prefer --find first and consider --filter. A full-binary sweep against a real ~130k-function app has been observed needing roughly 64GB of RAM to complete without crashing the whole host -- confirmed the hard way: two separate whole-VM crashes/reboots on a 5.8GB-RAM machine from --all runs during this project's development (once with --max unbounded, once with --max set to the FULL matched-function count, which is exactly as expensive as --max 0). If you don't have that much RAM, use --find + --func on specific addresses, or --all with a SMALL bounded --max (a few dozen, not thousands) -- never rely on --all's own budget/heartbeat/GC hardening alone to keep memory in check on a constrained host.")
	fromMain := fs.Bool("from-main", false, "decompile the app's own code reachable from its main() entry point, transitively following direct call sites (plus a class-touch expansion for canonicalized const instances seen via the object pool), writing one combined.dart file under --out -- unlike --all+--filter, this needs NO class/package name known in advance: reachability is determined by walking the call graph from main(), and any function whose owning Dart library resolves to dart:* or package:flutter* is skipped (not decompiled, not descended into) rather than matched by name. CONFIRMED LIMITATION: virtual/polymorphic dispatch (Widget.build(), State.initState(), UI callbacks) is invisible to a direct-call-graph walk, same as any other static call-graph tool -- class-touch expansion recovers some of these cases but is a documented over-approximation, not a proof of reachability. See ARCHITECTURE.md for the full analysis, including cases where an entry function's own argument is supplied by the Dart VM's isolate-startup machinery rather than any disassemblable instruction -- use --gen-frida to confirm reachability/argument values dynamically when static analysis alone hits this wall. Use --filter for a name-based sweep when you already know a class name.")
	genFrida := fs.Bool("gen-frida", false, "also emit a ready-to-run Frida script (see https://frida.re/docs/javascript-api/) hooking every function this invocation decompiles, dumping argument registers (only the REAL declared arity when confidently resolved, see the arity-inference note in ARCHITECTURE.md -- falls back to the full raw register set otherwise) + return value at runtime, PLUS a second set of probes at every still-unresolved indirect-call site (dynamicCall(indirectTarget_xN, ...) in the pseudocode) that reads the actual runtime call target and logs its module-relative offset -- the natural next step when static analysis alone can't resolve something (virtual dispatch, VM-supplied arguments, etc.). Probes are capped (maxFridaProbes in frida_gen.go) and skip memory-operand dispatch-table call shapes (not a single register to read) -- narrow with --filter/--func if you hit the cap.")
	genFridaOut := fs.String("gen-frida-out", "", "output path for the generated Frida script (default: <out>/hooks.js in --all/--from-main mode, or stdout after the pseudocode in --func mode)")
	findSubstr := fs.String("find", "", "list VA + resolved name for every function whose name contains this substring, WITHOUT decompiling any of them -- cheap, safe way to locate a target address before using --func")
	outDir := fs.String("out", "", "output directory for --all mode -- writes ONE combined.dart file inside it (not one file per function; avoids thousands of small file-create syscalls, which correlated with real host crashes during this tool's own testing)")
	maxFuncs := fs.Int("max", 500, "max functions to emit in --all mode (0 = unlimited -- can be very slow/memory-heavy on a real app with tens of thousands of functions; prefer a bounded value)")
	skipFuncs := fs.Int("skip", 0, "skip this many matching functions before starting to emit -- combine with --max to process the whole binary in separate SHARDS (separate process invocations), each covering one slice, then concatenate the resulting combined.dart files. This is the recommended way to decompile a full real-world app: it bounds each individual run's resource/time footprint and lets one bad shard be re-run alone instead of restarting the whole batch")
	filterSubstr := fs.String("filter", "", "modifier for --all ONLY (not its own mode, and not accepted with --from-main): restricts --all to functions whose name contains this substring (e.g. your own app's class name) -- a real Flutter build's libapp.so bundles the ENTIRE framework (widgets/rendering/Material/dart:core/etc), so an unfiltered --all against even a tiny app can mean thousands of framework functions that were never the actual target. Requires knowing a name substring in advance -- if you don't (a real RE scenario against an unfamiliar binary), use --from-main instead, which classifies by owning-library URL (dart:*/package:flutter*) instead of by name.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *libapp == "" {
		return fmt.Errorf("--lib is required")
	}
	if *funcVAStr == "" && !*all && !*fromMain && *findSubstr == "" {
		return fmt.Errorf("--func <hex VA>, --find <substring>, --all, or --from-main is required")
	}
	if *all && *fromMain {
		return fmt.Errorf("--all and --from-main are mutually exclusive -- pick one traversal mode")
	}
	if *filterSubstr != "" && !*all {
		return fmt.Errorf("--filter only applies to --all (it is a name-based restriction on --all's full-binary sweep, not a standalone mode); did you mean --all --filter %q, or --from-main for a name-free reachability walk?", *filterSubstr)
	}

	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}

	ef, err := elfx.Open(*libapp)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = ef.Close() }()
	isARM64 := ef.ELF.Machine == elf.EM_AARCH64

	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Dart SDK version: %s, arch: %s\n", info.Version.DartVersion, ef.ELF.Machine)

	data := info.IsolateData.Data
	clusterStart, err := cluster.FindClusterDataStart(data)
	if err != nil {
		return fmt.Errorf("cluster start: %w", err)
	}
	result, err := cluster.ScanClusters(data, clusterStart, info.Version, false, opts)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	if err := cluster.ReadFill(data, result, info.Version, false, info.IsolateHeader.TotalSize); err != nil {
		return fmt.Errorf("fill: %w", err)
	}

	table, err := cluster.ParseInstructionsTable(data, &result.Header, info.Version, info.IsolateHeader)
	var ranges []cluster.CodeRange
	switch {
	case err != nil && result.Header.InstructionTableDataOffset == 0 && info.Version.CodeTextOffsetDelta:
		ranges = cluster.ResolveCodeRangesFromTextOffset(result.Codes)
	case err != nil:
		return fmt.Errorf("instrtable: %w", err)
	default:
		codeRanges, err := cluster.ResolveCodeRanges(result.Codes, table)
		if err != nil {
			return fmt.Errorf("code ranges: %w", err)
		}
		stubRanges := cluster.ResolveStubRanges(table)
		ranges = cluster.MergeRanges(stubRanges, codeRanges)
	}

	code, codeOff, payloadLen, err := snapshot.CodeRegion(info.IsolateInstructions.Data)
	if err != nil {
		return fmt.Errorf("code region: %w", err)
	}
	codeEndOffset := uint32(codeOff) + uint32(payloadLen) //nolint:gosec // codeOff/payloadLen are offsets within one already-loaded snapshot payload, always well under 2^32
	cluster.SetLastRangeSize(ranges, codeEndOffset)
	codeVA := info.IsolateInstructions.VA + codeOff

	// Parse the VM-isolate snapshot region for base-object resolution
	// (strings/names/CIDs shared across every app using this Dart SDK
	// build). Without this, pool entries referencing VM-isolate objects
	// showed as opaque "<vm:NNN>" placeholders instead of their real
	// content -- a real, previously-unnoticed gap (this command passed
	// nil here since it was written), even though objects.go already
	// does this correctly (its own "vm snapshot: N clusters, N strings"
	// stderr line, ~99% pool resolution on a real app). Mirrors
	// objects.go's exact proven pattern.
	var vmResult *cluster.Result
	if vmData := info.VmData.Data; len(vmData) >= 64 && info.VmHeader != nil {
		if vmStart, err := cluster.FindClusterDataStart(vmData); err == nil {
			if vmRes, err := cluster.ScanClusters(vmData, vmStart, info.Version, true, opts); err == nil {
				_ = cluster.ReadFill(vmData, vmRes, info.Version, true, info.VmHeader.TotalSize)
				vmResult = vmRes
			}
		}
	}

	pl := buildPoolLookups(result, info.Version.CIDs, vmResult, info.Version.CodeIndexOneBased)
	poolDisplay := resolvePoolDisplay(result.Pool, pl)

	// Build class layouts for field-name resolution in the decompiler.
	// When fir.FieldNameResolver is set, fieldExpr emits base.fieldName
	// instead of base.fNN.
	//
	// The lifter does not know the receiver's class ID at fieldExpr time
	// (that would require integrating typetrack's KnownClass into the
	// lifter). Instead, we build a global offset→name map: if a byte
	// offset maps to the same field name across ALL classes that have a
	// field at that offset, it is unambiguous and can be used. If
	// different classes have different names at the same offset, it is
	// ambiguous and we skip it (return "" → fallback to fNN).
	classLayouts := pipeline.BuildClassLayouts(result, pl, info.Version.CompressedPointers)
	type fieldVote struct {
		name    string
		conflict bool
	}
	globalFieldNames := map[int32]*fieldVote{} // byteOffset → name (unanimous only)
	for _, cl := range classLayouts {
		for _, f := range cl.Fields {
			v, exists := globalFieldNames[f.ByteOffset]
			if !exists {
				globalFieldNames[f.ByteOffset] = &fieldVote{name: f.Name}
				continue
			}
			if v.name != f.Name {
				v.conflict = true
			}
		}
	}
	fieldNameResolver := func(classID int, byteOffset int64) string {
		// classID is ignored — we use the global unanimous map.
		// When typetrack integration is added, this can be upgraded to
		// use the per-class map for higher precision.
		if v, ok := globalFieldNames[int32(byteOffset)]; ok && !v.conflict {
			return v.name
		}
		return ""
	}

	// Build exception handler map: Code.RefID → []ExceptionHandlerEntry.
	// Code.ExceptionHandlersRef points to an ExceptionHandlers object in
	// result.ExceptionHandlers. We map that ref to the handler entries
	// so the decompiler can emit try/catch structure.
	excHandlersByRef := make(map[int][]cluster.ExceptionHandlerEntry)
	for i := range result.ExceptionHandlers {
		eh := &result.ExceptionHandlers[i]
		excHandlersByRef[eh.RefID] = eh.Handlers
	}
	codeRefToExcHandlers := make(map[int][]cluster.ExceptionHandlerEntry)
	for _, ce := range result.Codes {
		if ce.ExceptionHandlersRef >= 0 {
			if handlers, ok := excHandlersByRef[ce.ExceptionHandlersRef]; ok {
				codeRefToExcHandlers[ce.RefID] = handlers
			}
		}
	}

	// Code.RefID -> decoded PcDescriptors. Their try_index is the only source
	// for try-block EXTENTS; ExceptionHandlers above gives entry points only.
	pcDescByRef := make(map[int][]cluster.PcDescriptorEntry, len(result.PcDescriptors))
	for i := range result.PcDescriptors {
		pcDescByRef[result.PcDescriptors[i].RefID] = result.PcDescriptors[i].Entries
	}
	codeRefToPcDesc := make(map[int][]cluster.PcDescriptorEntry)
	for _, ce := range result.Codes {
		if ce.PcDescriptorsRef >= 0 {
			if entries, ok := pcDescByRef[ce.PcDescriptorsRef]; ok {
				codeRefToPcDesc[ce.RefID] = entries
			}
		}
	}

	// Code.RefID -> decoded CodeSourceMap, and -> the inlined_id_to_function
	// name table its PushFunction indices point into. Together these turn
	// "this pc is in inline frame 3" into "this pc is inside Foo.bar".
	csmByRef := make(map[int]*cluster.CodeSourceMapInfo, len(result.CodeSourceMaps))
	for i := range result.CodeSourceMaps {
		csmByRef[result.CodeSourceMaps[i].RefID] = &result.CodeSourceMaps[i]
	}
	arrayByRef := make(map[int]*cluster.ArrayInfo, len(result.Arrays))
	for i := range result.Arrays {
		arrayByRef[result.Arrays[i].RefID] = &result.Arrays[i]
	}
	codeRefToCSM := make(map[int]*cluster.CodeSourceMapInfo)
	codeRefToInlinedNames := make(map[int][]string)
	for _, ce := range result.Codes {
		if ce.CodeSourceMapRef >= 0 {
			if csm, ok := csmByRef[ce.CodeSourceMapRef]; ok {
				codeRefToCSM[ce.RefID] = csm
			}
		}
		if ce.InlinedFuncsRef < 0 {
			continue
		}
		arr, ok := arrayByRef[ce.InlinedFuncsRef]
		if !ok {
			continue
		}
		names := make([]string, len(arr.ElementRefIDs))
		for i, fnRef := range arr.ElementRefIDs {
			if no, ok := pl.RefToNamed[fnRef]; ok {
				owner := pl.ResolveOwnerName(no)
				name := pl.ResolveName(no)
				if name == "" {
					name = pl.ResolveVMName(no)
				}
				switch {
				case owner != "" && name != "":
					names[i] = owner + "." + name
				case name != "":
					names[i] = name
				}
			}
		}
		codeRefToInlinedNames[ce.RefID] = names
	}

	// The typeInfoByRef / typeArgsByRef / resolveTypeName / resolveTypeArgs
	// helpers that used to be built here are gone along with
	// decompiler.FuncIR.GenericTypeArgs -- see that field's removal note.
	// resolveTypeName also linear-scanned result.Classes on every call, which
	// would have been O(types x classes) had it ever produced output.

	// vmStubNames: VA->real-name map for the VM isolate's own stub Code
	// objects (StackOverflowSharedWithoutFPURegs, etc.), parsed from a
	// SEPARATE snapshot region (info.VmData) than the app's own isolate
	// data. Best-effort: empty (not nil) if this Dart version hasn't been
	// verified yet, or the region can't be parsed -- see
	// pipeline.BuildVMStubSymbols's doc comment and ARCHITECTURE.md's
	// "Stub naming" section.
	vmStubNames := buildVMStubSymbols(info, opts)

	// Build a whole-binary VA->name symbol table once, so cross-function
	// call targets resolve to real names instead of sub_<hex>.
	symbolNames := make(map[uint64]string, len(ranges))
	symbolSizes := make(map[uint64]uint32, len(ranges))
	for _, r := range ranges {
		if r.Size == 0 {
			continue
		}
		funcStart := uint64(r.PCOffset) - codeOff
		funcVA := codeVA + funcStart
		symbolSizes[funcVA] = r.Size
		if r.RefID >= 0 {
			symbolNames[funcVA] = qualifiedCodeNameLocal(r.RefID, pl, r.PCOffset)
		} else {
			symbolNames[funcVA] = fmt.Sprintf("stub_%x", r.PCOffset)
		}
	}
	// vmStubNames' entries live in an entirely different address range
	// (info.VmInstructions, not info.IsolateInstructions/codeVA above) --
	// merge them in directly rather than looking them up by an isolate
	// funcVA that will never match a VM-region address. A direct call
	// (BL/CALL) targeting a VM stub's real address resolves through this
	// same map.
	for va, name := range vmStubNames {
		symbolNames[va] = name
	}
	// discardedFuncNames: names Instructions whose owning Code object was
	// discarded by Dart AOT's release-build space optimization (the SAME
	// population ResolveStubRanges labels "stubs" above, RefID==-1 --
	// confirmed NOT a small fixed stub set but ordinary Dart functions,
	// via Function.CodeIndex, the exact scheme dart-lang/sdk's own
	// Deserializer::GetCodeAndEntryPointByIndex uses for runtime stack-
	// trace symbolication. See pipeline.BuildDiscardedFunctionSymbols's
	// doc comment and ARCHITECTURE.md's "Discarded-Code function naming"
	// section for the full derivation.
	discardedFuncNames := buildDiscardedFunctionSymbols(result.Named, info.Version.CIDs, table, pl, codeVA, codeOff, info.Version.CodeIndexOneBased)
	for va, name := range discardedFuncNames {
		symbolNames[va] = name
	}
	// Shared-stub detection (ARM64 only, see disasm.DetectSharedStubCall's
	// doc comment): a Code object whose OwnerRef doesn't resolve to any
	// NamedObject at all has no Dart Function behind it -- Dart AOT's
	// precompiler synthesizes these to share a common "call one THR-cached
	// runtime entry point" sequence across call sites. Confirmed on a real
	// sample: previously showed as opaque sub_<hex> despite being a
	// perfectly resolvable Code object (RefID >= 0), just with an
	// unresolvable owner.
	// H-3 fix: get THR fields for x86_64 call edge annotation.
	thrFields := disasm.THRFieldsWithProfile(info.Version.DartVersion, isARM64, info.Version)

	if isARM64 {
		if threadStubOffsets := disasm.ThreadStubOffsets(info.Version.DartVersion, isARM64); len(threadStubOffsets) > 0 {
			ownerByCodeRef := make(map[int]int, len(result.Codes))
			for _, ce := range result.Codes {
				ownerByCodeRef[ce.RefID] = ce.OwnerRef
			}
			for _, r := range ranges {
				if r.RefID < 0 || r.Size == 0 {
					continue
				}
				ownerRef, ok := ownerByCodeRef[r.RefID]
				if !ok {
					continue
				}
				if _, hasOwner := pl.RefToNamed[ownerRef]; hasOwner {
					continue // real Function/Class owner -- not a candidate
				}
				fStart := uint64(r.PCOffset) - codeOff
				fEnd := fStart + uint64(r.Size)
				if fEnd > uint64(len(code)) {
					continue
				}
				fVA := codeVA + fStart
				insts := disasm.Disassemble(code[fStart:fEnd], disasm.Options{BaseAddr: fVA})
				if name, ok := disasm.DetectSharedStubCall(insts, threadStubOffsets); ok {
					symbolNames[fVA] = "SharedStub_" + name
				}
			}
		}
	}
	symbolLookup := func(va uint64) (string, bool) {
		name, ok := symbolNames[va]
		return name, ok
	}
	poolLookup := func(idx int) (string, bool) {
		s, ok := poolDisplay[idx]
		if !ok {
			return "", false
		}
		return fmt.Sprintf("%q", s), true
	}

	// argRegMasks is a lazily-computed, whole-binary aggregation of every
	// direct-call site's ArgRegMask (internal/disasm's
	// inferCallArgRegMaskLocal for ARM64, inferX86CallArgRegMaskLocal for
	// x86_64), keyed by callee VA -- built once, only if a decompile
	// actually needs it, and reused across every function this invocation
	// processes (relevant for --all/--from-main touching thousands of
	// functions). Both architectures use the SAME downstream resolver
	// (resolveArgRegIndices) and the SAME bit-position convention: bit i =
	// the i'th calling-convention argument register (ArgRegs[i] in
	// internal/decompiler's arm64.go/x86.go), even though the two arches'
	// underlying register-index schemes differ (ARM64's X0-X7 are
	// contiguous; x86_64's RDI/RSI/RDX/RCX/R8/R9 are not -- see x86.go's
	// x86ArgRegBitPos for the remapping).
	var argRegMasks map[uint64][]uint8
	buildArgRegMasks := func() map[uint64][]uint8 {
		if argRegMasks != nil {
			return argRegMasks
		}
		argRegMasks = make(map[uint64][]uint8)
		for _, r := range ranges {
			if r.Size == 0 {
				continue
			}
			fStart := uint64(r.PCOffset) - codeOff
			fEnd := fStart + uint64(r.Size)
			if fEnd > uint64(len(code)) {
				fEnd = uint64(len(code))
			}
			if fStart >= fEnd {
				continue
			}
			fVA := codeVA + fStart
			if isARM64 {
				insts := disasm.Disassemble(code[fStart:fEnd], disasm.Options{BaseAddr: fVA})
				if len(insts) == 0 {
					continue
				}
				for _, e := range disasm.ExtractCallEdgesCFG(symbolNames[fVA], insts, symbolLookup, nil) {
					if e.Kind == "bl" && e.ArgRegMask != 0 {
						argRegMasks[e.TargetPC] = append(argRegMasks[e.TargetPC], e.ArgRegMask)
					}
				}
				continue
			}
			scan := disasm.ScanX86FunctionCFG(code[fStart:fEnd], fVA, symbolLookup, poolDisplay, symbolNames[fVA], thrFields)
			for _, e := range scan.Edges {
				if e.Kind == "call" && e.ArgRegMask != 0 {
					argRegMasks[e.TargetPC] = append(argRegMasks[e.TargetPC], e.ArgRegMask)
				}
			}
		}
		return argRegMasks
	}

	// Real per-parameter type names (pipeline.TypeParamResolver), for a
	// function's pseudocode signature -- see FuncIR.ParamTypeNames' doc
	// comment for the count-match safety gate EmitPseudocode applies
	// before trusting any of this.
	paramTypeByCodeIndex := pipeline.CodeIndexToFunc(result, info.Version.CIDs, info.Version.CodeIndexOneBased)
	paramFuncTypeByRef := make(map[int]*cluster.FuncTypeInfo, len(result.FuncTypes))
	for i := range result.FuncTypes {
		paramFuncTypeByRef[result.FuncTypes[i].RefID] = &result.FuncTypes[i]
	}
	typeParams := pipeline.NewTypeParamResolver(result, pl)
	// poolEntryByIndex looks up a pool entry by its PP index.
	poolByIndex := make(map[int]cluster.PoolEntry, len(result.Pool))
	for _, pe := range result.Pool {
		poolByIndex[pe.Index] = pe
	}
	poolEntryByIndex := func(idx int) (cluster.PoolEntry, bool) {
		pe, ok := poolByIndex[idx]
		return pe, ok
	}
	paramTypeNamesFor := func(r cluster.CodeRange) []string {
		if r.RefID < 0 {
			return nil
		}
		ce := cluster.CodeEntry{RefID: r.RefID, OwnerRef: r.OwnerRef, ClusterIndex: r.Index}
		owner, ok := pipeline.ResolveCodeOwner(ce, pl.RefToNamed, paramTypeByCodeIndex)
		if !ok || owner.SignatureRefID <= 0 {
			return nil
		}
		ft, ok := paramFuncTypeByRef[owner.SignatureRefID]
		if !ok {
			return nil
		}
		names := typeParams.ParamTypeNames(*ft)
		if ft.HasImplicit && len(names) > 0 {
			names = names[1:] // drop the implicit receiver's own type
		}
		return names
	}

	// Generic type PARAMETER names (the `<T>` in `runUnaryGuarded<T>`), a
	// different thing from the parameter TYPES resolved just above. Source:
	// FunctionType.type_parameters -> TypeParameters.names.
	funcTypeGenerics := pipeline.BuildFuncTypeParamNames(result, pl)
	// Closure -> declaring function, from ClosureData.parent_function.
	closureParents := pipeline.BuildClosureParents(result, pl)
	genericParamNamesFor := func(r cluster.CodeRange) []string {
		if funcTypeGenerics == nil || r.RefID < 0 {
			return nil
		}
		ce := cluster.CodeEntry{RefID: r.RefID, OwnerRef: r.OwnerRef, ClusterIndex: r.Index}
		owner, ok := pipeline.ResolveCodeOwner(ce, pl.RefToNamed, paramTypeByCodeIndex)
		if !ok || owner.SignatureRefID <= 0 {
			return nil
		}
		params := funcTypeGenerics[owner.SignatureRefID]
		if len(params) == 0 {
			return nil
		}
		// Render here so the decompiler stays unaware of how bounds resolve:
		// "T" or "T extends NativeFunction".
		out := make([]string, len(params))
		for i, p := range params {
			out[i] = p.String()
		}
		return out
	}

	buildFuncIR := func(r cluster.CodeRange) (*decompiler.FuncIR, error) {
		funcStart := uint64(r.PCOffset) - codeOff
		funcEnd := funcStart + uint64(r.Size)
		if funcEnd > uint64(len(code)) {
			funcEnd = uint64(len(code))
		}
		if funcStart >= funcEnd {
			return nil, fmt.Errorf("empty function range")
		}
		funcCode := code[funcStart:funcEnd]
		funcVA := codeVA + funcStart
		name := symbolNames[funcVA]

		var fir *decompiler.FuncIR
		if isARM64 {
			insts := disasm.Disassemble(funcCode, disasm.Options{BaseAddr: funcVA})
			fir = decompiler.BuildARM64IR(name, insts)
		} else {
			xinsts := decompiler.DecodeX86Range(funcCode, funcVA)
			fir = decompiler.BuildX86IR(name, xinsts)
		}
		if masks, ok := buildArgRegMasks()[funcVA]; ok {
			if regIdx, confident := resolveArgRegIndices(masks); confident {
				fir.ArgRegIndices = regIdx
			}
		}
		fir.ThreadStubOffsets = disasm.ThreadStubOffsets(info.Version.DartVersion, isARM64)
		fir.ParamTypeNames = paramTypeNamesFor(r)
		fir.TypeParamNames = genericParamNamesFor(r)
		fir.FieldNameResolver = fieldNameResolver
		if len(closureParents) > 0 && r.RefID >= 0 {
			ce := cluster.CodeEntry{RefID: r.RefID, OwnerRef: r.OwnerRef, ClusterIndex: r.Index}
			if owner, ok := pipeline.ResolveCodeOwner(ce, pl.RefToNamed, paramTypeByCodeIndex); ok {
				parent := closureParents[owner.RefID]
				// Drop same-name parents. A tear-off's ClosureData points at a
				// DIFFERENT Function object that shares the method's name, so a
				// ref-level self-check (done in BuildClosureParents) does not
				// catch it: 49 of 99 annotations were "closure declared in: X"
				// on X itself. Comparing names removes those without losing any
				// genuinely nested closure.
				if parent != "" && parent != fir.Name &&
					!strings.HasPrefix(fir.Name, parent+"_") {
					fir.EnclosingFunction = parent
				}
			}
		}
		// Wire exception handlers from cluster capture → decompiler FuncIR.
		if handlers, ok := codeRefToExcHandlers[r.RefID]; ok {
			fir.ExceptionHandlers = make([]decompiler.ExceptionHandlerEntry, len(handlers))
			for i, h := range handlers {
				fir.ExceptionHandlers[i] = decompiler.ExceptionHandlerEntry{
					PCOffset:        h.PCOffset,
					OuterTryIndex:   h.OuterTryIndex,
					NeedsStacktrace: h.NeedsStacktrace,
					HasCatchAll:     h.HasCatchAll,
					IsGenerated:     h.IsGenerated,
				}
			}

			// Recover try EXTENTS from PcDescriptors and pair each with its
			// handler. endPC is the function's size: the last descriptor has no
			// successor to delimit it, so without this the final region would
			// be dropped.
			if entries, ok := codeRefToPcDesc[r.RefID]; ok && len(entries) > 0 {
				regions := cluster.BuildTryRegions(entries, r.Size)
				// Recover enclosing trys that left no descriptor of their own:
				// a pc inside try N is inside handler[N].outer_try_index too.
				regions = cluster.ExpandOuterTryRegions(regions, handlers)
				for _, reg := range regions {
					if reg.TryIndex < 0 || reg.TryIndex >= len(fir.ExceptionHandlers) {
						// try_index must index this Code's own handler table;
						// anything else means a mismatched Code/handler pair
						// rather than a usable region.
						continue
					}
					h := fir.ExceptionHandlers[reg.TryIndex]
					fir.TryRegions = append(fir.TryRegions, decompiler.TryRegionEntry{
						StartVA:   funcStart + codeVA + uint64(reg.StartPC),
						EndVA:     funcStart + codeVA + uint64(reg.EndPC),
						TryIndex:  reg.TryIndex,
						Handler:   h,
						HandlerVA: funcStart + codeVA + uint64(h.PCOffset),
					})
				}
				// Widen to basic-block boundaries. Sound because a block has a
				// single entry, so a block containing any in-try pc is entirely
				// in-try. Raw descriptor ranges are otherwise single-instruction
				// lower bounds.
				fir.SnapTryRegionsToBlocks()
			}
		}

		// Inlined-frame annotation: for each block, ask the CodeSourceMap which
		// inline stack is active at its start VA and resolve the indices to
		// function names. Blocks belonging to the function itself get nothing.
		if csm, ok := codeRefToCSM[r.RefID]; ok && len(fir.Blocks) > 0 {
			names := codeRefToInlinedNames[r.RefID]
			for bi := range fir.Blocks {
				blockVA := fir.Blocks[bi].StartVA
				// CSM pc offsets are relative to the Code payload start, the
				// same base funcStart is measured from.
				pcOff := uint32(blockVA - codeVA)
				stack, _, ok := csm.InlineStackAt(pcOff)
				if !ok || len(stack) == 0 {
					continue
				}
				var frames []string
				for _, id := range stack {
					if int(id) < len(names) && names[id] != "" {
						frames = append(frames, names[id])
					}
				}
				if len(frames) == 0 {
					continue
				}
				if fir.InlineFrames == nil {
					fir.InlineFrames = make(map[uint64][]string)
				}
				fir.InlineFrames[blockVA] = frames
			}
		}
		// P6: Switch/case recovery — detect IndirectGoto pattern (br xN).
		// Dart AOT uses IndirectGotoInstr for switches with >=16 cases.
		// The codegen (il_arm64.cc) loads a TypedData (int32 offsets) from
		// the pool, reads offset[index], adds base address (ADR), and br.
		// The PP load may use 2-level addressing (ADD xN, x27, #hi + LDR xN, [xN, #lo])
		// which the lifter doesn't recognize as OpLoadPool. So instead of
		// relying on OpLoadPool, we detect br xN directly and map the
		// following blocks (which are the case targets — each is a MOV+RET
		// or a block of case body code) as switch cases.
		if isARM64 && len(fir.Blocks) > 0 {
			for bi := range fir.Blocks {
				for _, ins := range fir.Blocks[bi].Instrs {
					if ins.Op != decompiler.OpJump || strings.HasPrefix(ins.Target, "0x") || ins.Target == "" {
						continue
					}
					// Found br xN — this is a jump-table dispatch.
					// Map ALL following blocks as case targets. Each case
					// starts at a block boundary after the br block. We
					// collect blocks until we run out or hit 64 cases.
					// Cases can have complex bodies (if/else, calls) —
					// don't filter by block size or terminator type.
					var cases []decompiler.SwitchCase
					for ci := bi + 1; ci < len(fir.Blocks) && len(cases) < 64; ci++ {
						cases = append(cases, decompiler.SwitchCase{
							Index:   len(cases),
							BlockID: fir.Blocks[ci].ID,
						})
					}
					if len(cases) >= 2 {
						fir.SwitchCases = cases
					}
					break
				}
			}
		}

		// P7: Async/await detection via SuspendState CID in pool loads.
		// Async functions allocate a SuspendState object (CID=78) early.
		if !fir.IsAsync && info.Version.CIDs.SuspendState != 0 {
			for bi := range fir.Blocks {
				for _, ins := range fir.Blocks[bi].Instrs {
					if ins.Op != decompiler.OpLoadPool || ins.PoolIndex < 0 {
						continue
					}
					if pe, ok := poolEntryByIndex(ins.PoolIndex); ok {
						if cid, ok2 := pl.RefCID[pe.RefID]; ok2 && cid == info.Version.CIDs.SuspendState {
							fir.IsAsync = true
							break
						}
					}
				}
				if fir.IsAsync {
					break
				}
			}
		}

		return fir, nil
	}

	// decompileRangeWithIR returns both the pseudocode Artifact and the
	// intermediate FuncIR -- --gen-frida needs the FuncIR to build
	// real-arity-aware hooks and indirect-call-site probes (see
	// frida_gen.go) without disassembling the same range twice.
	decompileRangeWithIR := func(r cluster.CodeRange) (*decompiler.FuncIR, decompiler.Artifact, error) {
		fir, err := buildFuncIR(r)
		if err != nil {
			return nil, decompiler.Artifact{}, err
		}
		return fir, decompiler.EmitPseudocode(fir, symbolLookup, poolLookup), nil
	}

	// callTargetsOf extracts every resolved direct-call target VA from a
	// FuncIR's blocks -- used by --from-main's reachability walk to
	// discover callees without re-running EmitPseudocode's full
	// text-emission pipeline just to find call sites.
	callTargetsOf := func(fir *decompiler.FuncIR) []uint64 {
		var out []uint64
		for _, blk := range fir.Blocks {
			for _, ins := range blk.Instrs {
				if ins.Op != decompiler.OpCall || ins.Target == "" {
					continue
				}
				if va, err := strconv.ParseUint(strings.TrimPrefix(ins.Target, "0x"), 16, 64); err == nil {
					out = append(out, va)
				}
			}
		}
		return out
	}

	// --- --from-main support: classify each function's owning library as
	// framework/SDK (dart:*, package:flutter*) vs. application code, so a
	// reachability walk from main() can decompile only the app's own code
	// without needing to know any class/package name in advance (unlike
	// --filter, which needs a name substring known up front). Resolution
	// chain: CodeRange.RefID (Code ref) -> Code.owner (Function ref) ->
	// Function.OwnerRefID (Class or PatchClass ref; PatchClass hops one
	// more level to wrapped_class, mirroring internal/funcdiff's owner
	// resolution) -> ClassInfo.LibraryRefID -> Library.url string.
	ct := info.Version.CIDs
	classByRef := make(map[int]cluster.ClassInfo, len(result.Classes))
	for _, ci := range result.Classes {
		classByRef[ci.RefID] = ci
	}
	// Resolved via pipeline.ResolveCodeOwner rather than trusting
	// ce.OwnerRef directly -- Code.OwnerRef is confirmed unreliable on
	// some real snapshots (Dart 3.7.0 x86_64: ~5.4% of functions get a
	// bogus shared owner resolving to CID 61/Mint), which would
	// misclassify those functions' library (framework vs. app) here.
	byCodeIndex := pipeline.CodeIndexToFunc(result, ct, info.Version.CodeIndexOneBased)
	codeOwnerFunc := make(map[int]int, len(result.Codes))
	for _, ce := range result.Codes {
		if owner, ok := pipeline.ResolveCodeOwner(ce, pl.RefToNamed, byCodeIndex); ok {
			codeOwnerFunc[ce.RefID] = owner.RefID
		}
	}
	// effectiveOwnerClassRef resolves a Function NamedObject's real owner
	// Class ref, hopping one level through PatchClass when present
	// (mirrors internal/funcdiff's resolveEffectiveOwnerName, but returns
	// the ref itself rather than a resolved name string).
	effectiveOwnerClassRef := func(funcObj *cluster.NamedObject) int {
		effectiveClass := funcObj.OwnerRefID
		if owner, ok := pl.RefToNamed[effectiveClass]; ok && owner.CID == ct.PatchClass {
			effectiveClass = owner.OwnerRefID
		}
		return effectiveClass
	}
	libraryURLForClassRef := func(classRef int) string {
		classInfo, ok := classByRef[classRef]
		if !ok || classInfo.LibraryRefID < 0 {
			return ""
		}
		libObj, ok := pl.RefToNamed[classInfo.LibraryRefID]
		if !ok {
			return ""
		}
		if url := pl.ResolveName(libObj); url != "" {
			return url
		}
		return pl.ResolveVMName(libObj)
	}
	libraryURLForCodeRef := func(codeRef int) string {
		funcRef, ok := codeOwnerFunc[codeRef]
		if !ok {
			return ""
		}
		funcObj, ok := pl.RefToNamed[funcRef]
		if !ok {
			return ""
		}
		return libraryURLForClassRef(effectiveOwnerClassRef(funcObj))
	}
	isFrameworkLibraryURL := func(url string) bool {
		return strings.HasPrefix(url, "dart:") || strings.HasPrefix(url, "package:flutter")
	}

	// --- Class-touch expansion support: a virtual/polymorphic call (e.g.
	// Flutter's Element/State dispatch calling Widget.build()/State.
	// initState()) is invisible to callTargetsOf's direct-call scan --
	// confirmed empirically this session testing --from-main against a
	// real compiled app, where main()'s reachable set from a plain
	// `runApp(const MyApp())` was just 2 functions, never reaching
	// MyApp's own build()/State methods at all. Verified against
	// dart-lang/sdk source (runtime/vm/app_snapshot.cc's
	// InstanceSerializationCluster, constructed per concrete `cid`, and
	// runtime/vm/class_table.h's ClassTable::At(cid)) that every Instance
	// object's cluster CID *is* its concrete class's ClassInfo.ClassID --
	// so when a reachable function's object pool holds a canonicalized
	// instance of an app-code class (e.g. the const MyApp() the
	// trampoline passes to runApp), that class's ClassID is directly
	// recoverable from the pool ref's cluster CID, with no dispatch
	// needed. Once a class is "touched" this way, ALL of its own methods
	// (build/initState/etc., whatever we can't reach by direct call) are
	// added to the BFS queue too -- a deliberate, documented
	// over-approximation (like class-hierarchy-analysis in other static
	// call-graph tools), not a precise proof of runtime reachability.
	classIDToClassRef := make(map[int32]int, len(result.Classes))
	for _, ci := range result.Classes {
		classIDToClassRef[ci.ClassID] = ci.RefID
	}
	functionsByOwnerClassRef := make(map[int][]uint64, len(result.Classes))
	for _, r := range ranges {
		if r.Size == 0 || r.RefID < 0 {
			continue
		}
		funcRef, ok := codeOwnerFunc[r.RefID]
		if !ok {
			continue
		}
		funcObj, ok := pl.RefToNamed[funcRef]
		if !ok {
			continue
		}
		classRef := effectiveOwnerClassRef(funcObj)
		funcStart := uint64(r.PCOffset) - codeOff
		funcVA := codeVA + funcStart
		functionsByOwnerClassRef[classRef] = append(functionsByOwnerClassRef[classRef], funcVA)
	}
	// classRefTouchedByPoolLoad resolves an OpLoadPool instruction's pool
	// index to the concrete class ref of whatever object it loads (if the
	// pool entry is a tagged ref to an Instance/canonicalized const), or
	// -1 if it doesn't resolve to a known app-code class.
	classRefTouchedByPoolLoad := func(poolIndex int) int {
		if poolIndex < 0 {
			return -1
		}
		pe, ok := poolByIndex[poolIndex]
		if !ok || pe.Kind != cluster.PoolTagged {
			return -1
		}
		cid, ok := pl.RefCID[pe.RefID]
		if !ok {
			return -1
		}
		classRef, ok := classIDToClassRef[int32(cid)] //nolint:gosec // cid is a Dart class ID, always well within int32 range
		if !ok {
			return -1
		}
		return classRef
	}

	if *findSubstr != "" {
		// Pure name lookup -- no disassembly, no CFG walk, no emitter.
		// Safe to run against a full real-world app (tens of thousands
		// of functions) without the cost/risk of --all's actual
		// decompilation of every one of them.
		hits := 0
		for va, name := range symbolNames {
			if strings.Contains(name, *findSubstr) {
				fmt.Printf("0x%x  size=%d  %s\n", va, symbolSizes[va], name)
				hits++
			}
		}
		fmt.Fprintf(os.Stderr, "%d match(es) for %q among %d functions\n", hits, *findSubstr, len(symbolNames))
		return nil
	}

	if !*all && !*fromMain {
		if *funcVAStr == "" {
			return fmt.Errorf("--func is required (hex VA of an address inside the target function)")
		}
		var targetVA uint64
		_, scanErr := fmt.Sscanf(*funcVAStr, "0x%x", &targetVA)
		if scanErr != nil || targetVA == 0 {
			if _, err := fmt.Sscanf(*funcVAStr, "%x", &targetVA); err != nil || targetVA == 0 {
				return fmt.Errorf("--func %q: not a valid hex address", *funcVAStr)
			}
		}
		// Prefer the TIGHTEST containing range, and among equally-tight
		// candidates prefer a real Code entry (RefID >= 0) over a bare
		// stub -- CodeRange sets from ResolveCodeRanges/ResolveStubRanges
		// can overlap (e.g. a stub range spanning several real Code
		// ranges), and picking merely the FIRST containing range (this
		// command's original behavior) sometimes resolved to the wrong,
		// much larger enclosing range instead of the actual function
		// starting exactly at --func's address -- found by testing this
		// exact command against real libapp.so files with known-good
		// function addresses.
		var found *cluster.CodeRange
		for i, r := range ranges {
			if r.Size == 0 {
				continue
			}
			funcStart := uint64(r.PCOffset) - codeOff
			funcVA := codeVA + funcStart
			if targetVA < funcVA || targetVA >= funcVA+uint64(r.Size) {
				continue
			}
			if found == nil || r.Size < found.Size || (r.Size == found.Size && r.RefID >= 0 && found.RefID < 0) {
				found = &ranges[i]
			}
		}
		if found == nil {
			return fmt.Errorf("no CodeRange contains VA 0x%x", targetVA)
		}
		fir, art, err := decompileRangeWithIR(*found)
		if err != nil {
			return err
		}
		fmt.Println(art.Source)
		statsData, _ := json.MarshalIndent(art.Stats, "", "  ")
		fmt.Fprintf(os.Stderr, "stats: %s\n", statsData)
		if *genFrida {
			hook := fridaHook{VA: targetVA, Name: art.FunctionName, ArgRegs: realArgRegs(fir)}
			probes := collectIndirectCallProbes(fir)
			script := generateFridaScript(*libapp, isARM64, []fridaHook{hook}, probes)
			if *genFridaOut == "" {
				fmt.Println("\n// --- Frida script (--gen-frida) ---")
				fmt.Println(script)
			} else if err := os.WriteFile(*genFridaOut, []byte(script), 0o600); err != nil {
				return fmt.Errorf("write %s: %w", *genFridaOut, err)
			} else {
				fmt.Fprintf(os.Stderr, "Frida script written to %s\n", *genFridaOut)
			}
		}
		return nil
	}

	if *outDir == "" {
		return fmt.Errorf("--out is required with --all/--from-main")
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", *outDir, err)
	}

	// Hardening for --all against a real, repeated incident this session:
	// running --all --max N (even a few thousand) against a full real
	// Flutter app build crashed the WHOLE HOST (not a Go panic, not an
	// OOM this process's own heap stats ever showed -- MemStats stayed
	// at a flat few MiB every single time it crashed) more than once,
	// always after a few thousand functions and only a few seconds of
	// wall-clock time. Since heap never grew, this pointed away from a
	// memory bug in this process and toward a much simpler suspect: this
	// loop used to call os.WriteFile once per function, i.e. thousands
	// of small separate file-create syscalls onto a WSL2-mounted
	// filesystem in a short burst -- a known stressor for WSL2/Windows
	// Defender real-time-scanning interaction. Fixed by writing every
	// function's pseudocode into ONE buffered, append-only combined
	// file instead (bufio.Writer, explicit periodic Flush -- NOT one
	// os.Create per function). This removes the suspected root cause
	// entirely, independent of whether the exact mechanism was ever
	// fully confirmed. The other hardening below is kept as defense in
	// depth regardless:
	//   1. GOMAXPROCS capped -- this command is single-threaded logic;
	//      capping avoids the Go GC's default NumCPU-scaled worker pool
	//      contending for memory/scheduler time on a resource-constrained
	//      VM (WSL2 here, but this is a real risk on any small host).
	//   2. Explicit periodic GC + debug.FreeOSMemory() -- actively
	//      returns freed heap pages to the OS at regular intervals.
	//   3. A per-function recover() -- if decompiling one function
	//      panics for any reason (a bug we haven't found yet), that
	//      function is skipped and counted, not fatal to the batch.
	//   4. Progress heartbeat, flushed to disk periodically -- so a long
	//      run is visibly alive AND partial progress survives even if
	//      the process is later killed for an unrelated reason.
	runtime.GOMAXPROCS(2)
	debug.SetMemoryLimit(1536 << 20)

	combinedPath := filepath.Join(*outDir, "combined.dart")
	outFile, err := os.Create(combinedPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", combinedPath, err)
	}
	defer func() { _ = outFile.Close() }()
	w := bufio.NewWriterSize(outFile, 256*1024)

	emitted := 0
	skipped := 0
	var agg decompiler.Stats
	var fridaHooks []fridaHook
	var fridaProbes []fridaProbe
	fridaProbesDropped := 0
	const gcEveryN = 250
	startTime := time.Now()
	// Temporary diagnostic: print+flush every attempted function's VA
	// immediately BEFORE decompiling it, so if the process is killed
	// externally (not a Go panic, not a memory blowup -- both already
	// ruled out this session), the very last flushed line names the
	// exact function that was in progress at the moment of death.
	debugTrace := os.Getenv("AOTOPSY_DEBUG_TRACE") != ""

	if *fromMain {
		return runFromMain(fromMainDeps{
			ranges:                    ranges,
			codeOff:                   codeOff,
			codeVA:                    codeVA,
			symbolNames:               symbolNames,
			buildFuncIR:               buildFuncIR,
			callTargetsOf:             callTargetsOf,
			libraryURLForCodeRef:      libraryURLForCodeRef,
			libraryURLForClassRef:     libraryURLForClassRef,
			isFrameworkLibraryURL:     isFrameworkLibraryURL,
			functionsByOwnerClassRef:  functionsByOwnerClassRef,
			classRefTouchedByPoolLoad: classRefTouchedByPoolLoad,
			symbolLookup:              symbolLookup,
			poolLookup:                poolLookup,
			maxFuncs:                  *maxFuncs,
			w:                         w,
			combinedPath:              combinedPath,
			debugTrace:                debugTrace,
			gcEveryN:                  gcEveryN,
			startTime:                 startTime,
			isARM64:                   isARM64,
			genFrida:                  *genFrida,
			genFridaOut:               *genFridaOut,
			libPath:                   *libapp,
			outDir:                    *outDir,
		})
	}

	// rangeMatchesFilter applies --filter (if set) on top of the base
	// Size!=0/RefID>=0 eligibility check, so a filtered run's --skip/--max
	// counts and "N total matching functions" figure are ALL computed
	// against the SAME (filtered) set -- default (no --filter) still
	// covers the full framework, unchanged; --filter is purely additive.
	rangeMatchesFilter := func(r cluster.CodeRange) bool {
		if r.Size == 0 || r.RefID < 0 {
			return false
		}
		if *filterSubstr == "" {
			return true
		}
		funcStart := uint64(r.PCOffset) - codeOff
		funcVA := codeVA + funcStart
		return strings.Contains(symbolNames[funcVA], *filterSubstr)
	}

	totalMatching := 0
	for _, r := range ranges {
		if rangeMatchesFilter(r) {
			totalMatching++
		}
	}
	if *skipFuncs >= totalMatching {
		fmt.Fprintf(os.Stderr, "--skip %d >= %d total matching functions -- nothing to do, this shard is past the end\n", *skipFuncs, totalMatching)
		return nil
	}

	matched := 0
	// P3: Class method reconstruction — sort matched ranges by owner name
	// so methods of the same class are contiguous, then emit real
	// `class Owner { ... }` syntax. This avoids invalid Dart (multiple
	// class declarations for the same class).
	type ownerRange struct {
		r     cluster.CodeRange
		owner string
	}
	var matchedRanges []ownerRange
	for _, r := range ranges {
		if !rangeMatchesFilter(r) {
			continue
		}
		owner := ""
		if r.RefID >= 0 {
			if ci, ok := pl.CodeNames[r.RefID]; ok && ci.OwnerName != "" {
				owner = ci.OwnerName
			}
		}
		matchedRanges = append(matchedRanges, ownerRange{r: r, owner: owner})
	}
	sort.SliceStable(matchedRanges, func(i, j int) bool {
		return matchedRanges[i].owner < matchedRanges[j].owner
	})

	type classBuffer struct {
		owner     string
		artifacts []decompiler.Artifact
	}
	var curClass *classBuffer
	flushClass := func() {
		if curClass == nil || len(curClass.artifacts) == 0 {
			curClass = nil
			return
		}
		_, _ = fmt.Fprintf(w, "class %s {\n", curClass.owner)
		for _, art := range curClass.artifacts {
			body := strings.ReplaceAll(art.Source, "\n", "\n  ")
			_, _ = fmt.Fprintf(w, "  // === %s ===\n  %s\n\n", art.FunctionName, body)
		}
		_, _ = fmt.Fprintf(w, "}\n\n")
		curClass = nil
	}
	for _, mr := range matchedRanges {
		r := mr.r
		matched++
		if matched <= *skipFuncs {
			continue // this shard's --skip window hasn't started yet
		}
		if *maxFuncs > 0 && emitted >= *maxFuncs {
			break
		}

		if debugTrace {
			funcStart := uint64(r.PCOffset) - codeOff
			funcVA := codeVA + funcStart
			fmt.Fprintf(os.Stderr, "trace: about to decompile 0x%x size=%d %s\n", funcVA, r.Size, symbolNames[funcVA])
		}

		func() {
			defer func() {
				if rec := recover(); rec != nil {
					skipped++
					fmt.Fprintf(os.Stderr, "warning: recovered panic decompiling range (PCOffset=0x%x): %v\n", r.PCOffset, rec)
				}
			}()

			fir, art, err := decompileRangeWithIR(r)
			if err != nil {
				skipped++
				return
			}
			// P3: Class method reconstruction — buffer per class, emit
			// real `class Owner { ... }` when owner changes.
			ownerName := mr.owner
			if ownerName != "" {
				// Function belongs to a class — buffer it.
				if curClass == nil || curClass.owner != ownerName {
					flushClass()
					curClass = &classBuffer{owner: ownerName}
				}
				curClass.artifacts = append(curClass.artifacts, art)
			} else {
				// Standalone function (stub, top-level) — flush any open
				// class, then emit directly.
				flushClass()
				_, _ = fmt.Fprintf(w, "// === %s (PCOffset=0x%x) ===\n%s\n\n", art.FunctionName, r.PCOffset, art.Source)
			}
			agg.TotalCalls += art.Stats.TotalCalls
			agg.IndirectCalls += art.Stats.IndirectCalls
			agg.SemanticDirectCalls += art.Stats.SemanticDirectCalls
			agg.SemanticIndirectCalls += art.Stats.SemanticIndirectCalls
			agg.PlaceholderIfs += art.Stats.PlaceholderIfs
			agg.UnresolvedCF += art.Stats.UnresolvedCF
			agg.RawRegisterCalls += art.Stats.RawRegisterCalls
			// These three were missing from the fold, so the aggregate JSON
			// reported 0 for them no matter what the per-function artifacts
			// said. Observed: "try_blocks": 0 on a run that emitted 10.
			agg.NonLastBranch += art.Stats.NonLastBranch
			agg.TryBlocks += art.Stats.TryBlocks
			agg.CatchHandlers += art.Stats.CatchHandlers
			emitted++
			if *genFrida {
				funcStart := uint64(r.PCOffset) - codeOff
				fridaHooks = append(fridaHooks, fridaHook{VA: codeVA + funcStart, Name: art.FunctionName, ArgRegs: realArgRegs(fir)})
				for _, p := range collectIndirectCallProbes(fir) {
					if len(fridaProbes) >= maxFridaProbes {
						fridaProbesDropped++
						continue
					}
					fridaProbes = append(fridaProbes, p)
				}
			}
		}()

		if emitted > 0 && emitted%gcEveryN == 0 {
			if err := w.Flush(); err != nil {
				return fmt.Errorf("flush %s: %w", combinedPath, err)
			}
			runtime.GC()
			debug.FreeOSMemory()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			fmt.Fprintf(os.Stderr, "progress: %d emitted, %d skipped, heap=%dMiB, elapsed=%s\n",
				emitted, skipped, m.HeapAlloc/1024/1024, time.Since(startTime).Round(time.Second))
		}
	}
	// P3: flush last class buffer.
	flushClass()
	if err := w.Flush(); err != nil {
		return fmt.Errorf("final flush %s: %w", combinedPath, err)
	}
	fmt.Fprintf(os.Stderr, "emitted %d functions (skipped %d) to %s in %s -- shard covered matched-index [%d, %d) of %d total matching functions in this binary\n",
		emitted, skipped, combinedPath, time.Since(startTime).Round(time.Second), *skipFuncs, *skipFuncs+emitted+skipped, totalMatching)
	statsData, _ := json.MarshalIndent(agg, "", "  ")
	fmt.Fprintf(os.Stderr, "aggregate stats: %s\n", statsData)
	if *genFrida {
		if fridaProbesDropped > 0 {
			fmt.Fprintf(os.Stderr, "--gen-frida: %d indirect-call probe(s) dropped past the %d cap (maxFridaProbes) -- rerun with --filter/--func on a narrower target to see the rest\n", fridaProbesDropped, maxFridaProbes)
		}
		if err := writeFridaScript(*genFridaOut, *outDir, *libapp, isARM64, fridaHooks, fridaProbes); err != nil {
			return err
		}
	}
	return nil
}

// resolveArgRegIndices decides a confident real arity from a callee's
// aggregated per-call-site ArgRegMask values (internal/disasm's
// inferCallArgRegMaskLocal), one mask per direct call site targeting it.
//
// Uses the BITWISE-AND INTERSECTION across every call site, not majority
// vote and not exact-equality. Verified necessary on a real sample:
// MathTools.factorial(int n) (1 real parameter, in X1) has two call sites
// -- self-recursion (mask 0b11, X0+X1: X0 there is the recursive call
// preserving `n` across the call for the LATER `n * factorial(n-1)`
// multiplication, not an argument) and the call from _runAll (mask 0b10,
// X1 only). Exact-equality rejected both (0b11 != 0b10) even though the
// real signal (X1) was consistent; the intersection (0b11 & 0b10 = 0b10)
// correctly recovers X1-only. A register that is genuinely required is
// set at EVERY call site with no exceptions; one that only sometimes
// appears is call-site-specific noise (a preserved-across-call value, an
// unrelated field store reusing the register, etc.) and must be dropped,
// not trusted.
//
// An empty intersection (no bit survives) means unresolved -- callers
// fall back to the full ArgRegs display.
//
// Requires at least 2 independent call sites. A single call site has
// nothing to intersect against, so its mask (however clean-looking) is
// unvalidated -- verified as a real risk on the same test binary:
// _CompareHomePageState._runAll has exactly one call site (from
// initState) on both architectures, and trusting that one site alone gave
// a DIFFERENT arg count on ARM64 (2) than on x86_64 (1) for the SAME Dart
// function -- real arity cannot differ by target architecture, so at
// least one of those single-sample answers was wrong. Two or more call
// sites are required before the intersection is trusted at all.
func resolveArgRegIndices(masks []uint8) ([]int, bool) {
	if len(masks) < 2 {
		return nil, false
	}
	core := masks[0]
	for _, m := range masks[1:] {
		core &= m
	}
	var idx []int
	for i := 0; i < 8; i++ { // L-4: 8 covers both ARM64 (X0-X7) and x86_64 (6 regs, bits 6-7 always 0)
		if core&(1<<uint(i)) != 0 {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return nil, false
	}
	return idx, true
}
