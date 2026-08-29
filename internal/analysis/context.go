package analysis

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/disasm"
	"aotopsy/internal/elfx"
	"aotopsy/internal/naming"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/vmtables"
)

// Context bundles everything a per-function tool (FFI-target tracing,
// CPU emulation, or any other future single-function analysis) needs
// from the existing static pipeline, built once per libapp.so and
// reused across however many functions get analyzed in one run.
//
// This factors out the ELF→snapshot→cluster→pool-lookup setup sequence
// (elfx.Open -> snapshot.Extract -> cluster.ScanClusters/ReadFill ->
// ParseInstructionsTable -> ResolveCodeRanges -> BuildPoolLookups) into a
// reusable, exported entry point. cmd/aotopsy/decompile_native_cmd.go (and
// the decompiler engine in internal/analysis) now calls
// LoadContext instead of duplicating the sequence; new callers should do
// the same.
type AnalysisContext struct {
	EF     *elfx.File
	Info   *snapshot.Info
	Result *cluster.Result
	Ranges []cluster.CodeRange

	// InstrTable is the parsed InstructionsTable, needed to convert a
	// dispatch-table entry's code_index into a ClusterIndex (see
	// cluster.ParseDispatchTable). Nil when ParseInstructionsTable
	// failed and Ranges was built via the pre-v2.16 text-offset
	// fallback instead (see LoadContext).
	InstrTable *cluster.InstructionsTable

	Pool *naming.PoolLookups

	// PoolDisplay maps object-pool index -> human-readable display string
	// (quoted for literal strings, e.g. `"libbatteryOpt.so"`), mirroring
	// decompile_native_cmd.go's poolDisplay.
	PoolDisplay map[int]string

	// Code is the raw instructions-image byte slice; CodeVA is the
	// virtual address of Code[0]; CodeOff is the byte offset of
	// Code[0] within the isolate instructions region (subtract this
	// from a CodeRange.PCOffset to get an index into Code).
	Code    []byte
	CodeVA  uint64
	CodeOff uint64

	// SymbolNames/SymbolSizes map a function's start VA to its
	// resolved display name / byte size, covering every CodeRange
	// (Dart functions, discarded-code functions, VM/isolate stubs).
	SymbolNames map[uint64]string
	SymbolSizes map[uint64]uint32

	IsARM64     bool
	DartVersion string

	// Enrichment holds lazy-built decompile maps. Nil until ensureDecompileMaps.
	Enrichment      *DecompileEnrichment
	enrichmentBuilt bool
}

// DecompileEnrichment holds the lazy-built per-binary maps that turn a bare
// FuncIR into a fully-resolved one: field names by (class, offset), each Code's
// receiver class, closure parents, exception-handler / PcDescriptor tables,
// parameter types, generic type parameters, named-parameter names, async
// detection, and arg-reg masks. Built once on demand by ensureDecompileMaps.
type DecompileEnrichment struct {
	FieldNameResolver      func(classID int, byteOffset int64) string
	ReceiverClassByCode    map[int]int
	ClosureParentByFunc    map[int]string
	ExcHandlersByCode      map[int][]cluster.ExceptionHandlerEntry
	PcDescByCode           map[int][]cluster.PcDescriptorEntry
	ParamTypeByCodeIndex   map[int]*cluster.NamedObject
	ClassNameToID          map[string]int
	FieldTypeByClassOffset map[int]map[int64]int
	ParamFuncTypeByRef     map[int]*cluster.FuncTypeInfo
	TypeParams             *naming.TypeParamResolver
	FuncTypeGenerics       map[int][]naming.TypeParam
	PoolByIndex            map[int]cluster.PoolEntry
	ArgRegMasks            map[uint64][]uint8
	AccessorFieldNames     map[int]map[int64]string
}

// LoadContext opens libPath and runs the full static-analysis setup
// pipeline once. Callers must call Close() when done (closes the
// underlying ELF file).
func LoadContext(libPath string) (ctx *AnalysisContext, err error) {
	sc, err := LoadSnapshot(libPath, dartfmtOptionsDefault())
	if err != nil {
		return nil, err
	}

	symbolNames := make(map[uint64]string, len(sc.Ranges))
	symbolSizes := make(map[uint64]uint32, len(sc.Ranges))
	for _, r := range sc.Ranges {
		if r.Size == 0 {
			continue
		}
		funcStart := uint64(r.PCOffset) - sc.CodeOff
		funcVA := sc.CodeVA + funcStart
		symbolSizes[funcVA] = r.Size
		if r.RefID >= 0 {
			symbolNames[funcVA] = naming.QualifiedCodeName(r.RefID, sc.Pool, r.PCOffset)
		} else {
			symbolNames[funcVA] = fmt.Sprintf("stub_%x", r.PCOffset)
		}
	}
	for va, name := range naming.BuildVMStubSymbols(sc.Info, dartfmtOptionsDefault()) {
		symbolNames[va] = name
	}
	for va, name := range naming.BuildDiscardedFunctionSymbols(sc.Result.Named, sc.Info.Version.CIDs, sc.Table, sc.Pool, sc.CodeVA, sc.CodeOff, sc.Info.Version.CodeIndexOneBased) {
		symbolNames[va] = name
	}

	return &AnalysisContext{
		EF:          sc.EF,
		Info:        sc.Info,
		Result:      sc.Result,
		Ranges:      sc.Ranges,
		InstrTable:  sc.Table,
		Pool:        sc.Pool,
		PoolDisplay: sc.PoolDisplay,
		Code:        sc.Code,
		CodeVA:      sc.CodeVA,
		CodeOff:     sc.CodeOff,
		SymbolNames: symbolNames,
		SymbolSizes: symbolSizes,
		IsARM64:     sc.IsARM64,
		DartVersion: sc.Info.Version.DartVersion,
	}, nil
}

func (c *AnalysisContext) Close() error {
	return c.EF.Close()
}

// SymbolLookup adapts Context.SymbolNames to the func(uint64)(string,bool)
// shape internal/decompiler/internal/disasm callers expect.
func (c *AnalysisContext) SymbolLookup(va uint64) (string, bool) {
	name, ok := c.SymbolNames[va]
	return name, ok
}

// PoolLookup adapts Context.PoolDisplay to the func(int)(string,bool)
// shape decompiler.EmitPseudocode expects.
func (c *AnalysisContext) PoolLookup(idx int) (string, bool) {
	s, ok := c.PoolDisplay[idx]
	if !ok {
		return "", false
	}
	return s, true
}

// ensureDecompileMaps builds, once, the per-binary maps that turn a bare
// FuncIR into a fully-resolved one: field names by (class, offset), each Code's
// receiver class, closure parents, and exception-handler / PcDescriptor tables.
// FuncIRFor used to omit all of these (they lived only in the cmd path), so
// pipeline-level decompilation left `.fNN` field offsets and receiver fields
// unresolved. Built lazily because not every Context consumer decompiles.
func (c *AnalysisContext) ensureDecompileMaps() {
	if c.enrichmentBuilt {
		return
	}
	c.enrichmentBuilt = true
	if c.Result == nil || c.Pool == nil || c.Info == nil {
		return
	}
	c.Enrichment = &DecompileEnrichment{}
	result := c.Result
	pl := c.Pool
	ct := c.Info.Version.CIDs
	// Field names by (classID, byteOffset), plus a global offset->name fallback
	// for offsets that are UNAMBIGUOUS across every class (used when the
	// receiver class of an access is unknown). Same construction as the cmd
	// path; the offset-only fallback is deliberately restricted to unique
	// offsets so it never invents a wrong field name.
	layouts := BuildClassLayouts(result, pl, c.Info.Version.CompressedPointers)
	perClass := map[int32]map[int32]string{}
	offsetNames := map[int32]map[string]bool{}
	c.Enrichment.ClassNameToID = BuildClassNameToID(layouts)
	for _, cl := range layouts {
		if perClass[cl.ClassID] == nil {
			perClass[cl.ClassID] = map[int32]string{}
		}
		for _, f := range cl.Fields {
			if strings.HasPrefix(f.Name, "f_0x") || strings.HasPrefix(f.Name, "field_0x") {
				continue
			}
			perClass[cl.ClassID][f.ByteOffset] = f.Name
			if offsetNames[f.ByteOffset] == nil {
				offsetNames[f.ByteOffset] = map[string]bool{}
			}
			offsetNames[f.ByteOffset][f.Name] = true
		}
	}
	globalByOffset := map[int32]string{}
	for off, names := range offsetNames {
		if len(names) == 1 {
			for n := range names {
				globalByOffset[off] = n
			}
		}
	}
	c.Enrichment.FieldNameResolver = func(classID int, byteOffset int64) string {
		if classID > 0 {
			// Accessor-recovered names first: a get:/set: accessor on this class
			// names the field it touches, recovering names the AOT precompiler
			// dropped from the Field objects (see buildAccessorFieldNames).
			if m, ok := c.Enrichment.AccessorFieldNames[classID]; ok {
				if n, ok2 := m[byteOffset]; ok2 {
					return n
				}
			}
			if m, ok := perClass[int32(classID)]; ok {
				if n, ok2 := m[int32(byteOffset)]; ok2 {
					return n
				}
			}
		}
		return globalByOffset[int32(byteOffset)]
	}

	// Receiver class per Code, via owner Function -> (PatchClass hop) -> Class.
	c.Enrichment.ParamTypeByCodeIndex = naming.CodeIndexToFunc(result, ct, c.Info.Version.CodeIndexOneBased)
	classByRef := make(map[int]*cluster.ClassInfo, len(result.Classes))
	for i := range result.Classes {
		classByRef[result.Classes[i].RefID] = &result.Classes[i]
	}
	effectiveClassRef := func(owner *cluster.NamedObject) int {
		ref := owner.OwnerRefID
		if o, ok := pl.RefToNamed[ref]; ok && ct.PatchClass != 0 && o.CID == ct.PatchClass {
			ref = o.OwnerRefID
		}
		return ref
	}
	c.Enrichment.ReceiverClassByCode = make(map[int]int, len(result.Codes))
	for _, ce := range result.Codes {
		if owner, ok := naming.ResolveCodeOwner(ce, pl.RefToNamed, c.Enrichment.ParamTypeByCodeIndex); ok && owner != nil {
			if classRef := effectiveClassRef(owner); classRef > 0 {
				if ci, ok2 := classByRef[classRef]; ok2 {
					c.Enrichment.ReceiverClassByCode[ce.RefID] = int(ci.ClassID)
				}
			}
		}
	}

	// Field TYPE by (ownerClassID, byteOffset) -> the field's declared type's
	// class ID, for typing field-load chains (`this.a.b`). Shared helper so the
	// cmd decompile path types chains identically.
	c.Enrichment.FieldTypeByClassOffset = BuildFieldTypeByClassOffset(result)

	c.Enrichment.ClosureParentByFunc = naming.BuildClosureParents(result, pl)

	// Signature enrichment (parameter types, generics, named params) + the pool
	// index needed for SuspendState async detection — the same maps the cmd
	// funcIRBuilder builds, so FuncIRFor produces an equally-enriched FuncIR.
	c.Enrichment.ParamFuncTypeByRef = make(map[int]*cluster.FuncTypeInfo, len(result.FuncTypes))
	for i := range result.FuncTypes {
		c.Enrichment.ParamFuncTypeByRef[result.FuncTypes[i].RefID] = &result.FuncTypes[i]
	}
	c.Enrichment.TypeParams = naming.NewTypeParamResolver(result, pl)
	c.Enrichment.FuncTypeGenerics = naming.BuildFuncTypeParamNames(result, pl)
	c.Enrichment.PoolByIndex = make(map[int]cluster.PoolEntry, len(result.Pool))
	for i := range result.Pool {
		c.Enrichment.PoolByIndex[result.Pool[i].Index] = result.Pool[i]
	}

	// Exception handlers + PcDescriptors per Code, for ground-truth try/catch.
	ehByRef := make(map[int][]cluster.ExceptionHandlerEntry, len(result.ExceptionHandlers))
	for i := range result.ExceptionHandlers {
		ehByRef[result.ExceptionHandlers[i].RefID] = result.ExceptionHandlers[i].Handlers
	}
	pdByRef := make(map[int][]cluster.PcDescriptorEntry, len(result.PcDescriptors))
	for i := range result.PcDescriptors {
		pdByRef[result.PcDescriptors[i].RefID] = result.PcDescriptors[i].Entries
	}
	c.Enrichment.ExcHandlersByCode = make(map[int][]cluster.ExceptionHandlerEntry)
	c.Enrichment.PcDescByCode = make(map[int][]cluster.PcDescriptorEntry)
	for _, ce := range result.Codes {
		if ce.ExceptionHandlersRef >= 0 {
			if h, ok := ehByRef[ce.ExceptionHandlersRef]; ok {
				c.Enrichment.ExcHandlersByCode[ce.RefID] = h
			}
		}
		if ce.PcDescriptorsRef >= 0 {
			if e, ok := pdByRef[ce.PcDescriptorsRef]; ok {
				c.Enrichment.PcDescByCode[ce.RefID] = e
			}
		}
	}

	c.buildAccessorFieldNames()
}

// buildAccessorFieldNames recovers instance-field names that the AOT precompiler
// dropped (Precompiler::DropFields drops Field objects in PRODUCT builds), using
// the accessor functions that survive for dynamic dispatch. A get:X / set:X
// accessor's NAME is the field name, and its body touches exactly one field
// offset on the receiver; mapping (ownerClass, offset) -> X recovers the name for
// EVERY access to that field across the binary. This is a deterministic recovery
// (not a fuzzy string correlation): measured 554-1396 real field names per
// binary that no existing tool (blutter included) recovers. Only unambiguous
// accessors (exactly one distinct field offset in the body) are accepted, so it
// never fabricates.
func (c *AnalysisContext) buildAccessorFieldNames() {
	c.Enrichment.AccessorFieldNames = map[int]map[int64]string{}
	identRe := regexp.MustCompile(`^[A-Za-z_]\w*$`)
	fieldDispRe := regexp.MustCompile(`\.f(\d+)\b`)
	symLk := func(va uint64) (string, bool) { s, ok := c.SymbolNames[va]; return s, ok && s != "" }
	poolLk := func(idx int) (string, bool) { s, ok := c.PoolDisplay[idx]; return s, ok }

	for _, r := range c.Ranges {
		if r.RefID < 0 || r.Size == 0 {
			continue
		}
		classID, ok := c.Enrichment.ReceiverClassByCode[r.RefID]
		if !ok || classID <= 0 {
			continue
		}
		nm := c.SymbolNames[c.CodeVA+(uint64(r.PCOffset)-c.CodeOff)]
		base := nm
		if i := strings.LastIndex(base, "."); i >= 0 {
			base = base[i+1:]
		}
		var fieldName string
		switch {
		case strings.HasPrefix(base, "get:"):
			fieldName = base[4:]
		case strings.HasPrefix(base, "set:"):
			fieldName = base[4:]
		default:
			continue
		}
		if !identRe.MatchString(fieldName) {
			continue
		}
		fir, err := c.FuncIRFor(r) // re-enters ensureDecompileMaps as a no-op
		if err != nil || fir == nil {
			continue
		}
		art := decompiler.EmitPseudocode(fir, symLk, poolLk)
		// Require EXACTLY ONE distinct field displacement in the accessor body,
		// so the (offset -> name) mapping is unambiguous.
		distinct := map[int64]bool{}
		for _, m := range fieldDispRe.FindAllStringSubmatch(art.Source, -1) {
			if d, err := strconv.ParseInt(m[1], 10, 64); err == nil {
				distinct[d] = true
			}
		}
		if len(distinct) != 1 {
			continue
		}
		for disp := range distinct {
			// disp is the tagged-pointer displacement; the field byte offset is
			// disp+1 (see dartFieldResolver).
			off := disp + 1
			if c.Enrichment.AccessorFieldNames[classID] == nil {
				c.Enrichment.AccessorFieldNames[classID] = map[int64]string{}
			}
			// A getter and setter agree on the name; first writer wins, and both
			// map to the same name anyway.
			if _, exists := c.Enrichment.AccessorFieldNames[classID][off]; !exists {
				c.Enrichment.AccessorFieldNames[classID][off] = fieldName
			}
		}
	}
}

// FuncIRFor builds the arch-neutral FuncIR for one CodeRange, mirroring
// decompile_native_cmd.go's buildFuncIR closure (arity inference is left
// to the caller -- ArgRegIndices requires a whole-binary call-edge
// aggregation pass that's only worth paying for when a caller actually
// needs it, see resolveArgRegIndices's doc comment in decompile_native_cmd.go).
func (c *AnalysisContext) FuncIRFor(r cluster.CodeRange) (*decompiler.FuncIR, error) {
	funcStart := uint64(r.PCOffset) - c.CodeOff
	funcEnd := funcStart + uint64(r.Size)
	if funcEnd > uint64(len(c.Code)) {
		funcEnd = uint64(len(c.Code))
	}
	if funcStart >= funcEnd {
		return nil, fmt.Errorf("empty function range")
	}
	funcCode := c.Code[funcStart:funcEnd]
	funcVA := c.CodeVA + funcStart
	name := c.SymbolNames[funcVA]

	var fir *decompiler.FuncIR
	if c.IsARM64 {
		insts := disasm.Disassemble(funcCode, disasm.Options{BaseAddr: funcVA})
		fir = decompiler.BuildARM64IR(name, insts)
	} else {
		xinsts := decompiler.DecodeX86Range(funcCode, funcVA)
		fir = decompiler.BuildX86IR(name, xinsts)
	}
	fir.ThreadStubOffsets = vmtables.ThreadStubOffsets(c.DartVersion, c.IsARM64)
	// Both tables, not just the stub one. ThreadFieldNames is what
	// applyStore consults to recognise the vm_tag store that marks an FFI
	// call target, so leaving it nil disables that detection silently --
	// see ThreadFieldOffsets. Both are keyed per architecture and per Dart
	// version by the same profile, so this is correct for ARM64 and x86_64
	// across 2.x and 3.x alike.
	var profile *snapshot.VersionProfile
	if c.Info != nil {
		profile = c.Info.Version
	}
	fir.ThreadFieldNames = ThreadFieldOffsets(c.DartVersion, c.IsARM64, profile)

	// Enrich: field names, receiver class, closure parent, and ground-truth
	// try/catch -- the metadata that turns `.fNN` into `.fieldName` and recovers
	// exception structure on the pipeline path (previously only the cmd path had
	// these).
	c.ensureDecompileMaps()

	// Confident real arity from aggregated call-site arg-register masks (opt-in;
	// only when BuildArgRegMasks was called).
	if c.Enrichment != nil && c.Enrichment.ArgRegMasks != nil {
		if masks, ok := c.Enrichment.ArgRegMasks[funcVA]; ok {
			if regIdx, confident := ResolveArgRegIndices(masks); confident {
				fir.ArgRegIndices = regIdx
			}
		}
	}

	if c.Enrichment == nil {
		return fir, nil
	}
	fir.FieldNameResolver = c.Enrichment.FieldNameResolver
	fir.ClassNameToID = c.Enrichment.ClassNameToID
	if c.Enrichment.FieldTypeByClassOffset != nil {
		fir.FieldTypeResolver = func(classID int, off int64) int {
			if m, ok := c.Enrichment.FieldTypeByClassOffset[classID]; ok {
				return m[off]
			}
			return 0
		}
	}
	if r.RefID >= 0 {
		if cid, ok := c.Enrichment.ReceiverClassByCode[r.RefID]; ok && cid > 0 {
			fir.ReceiverClassID = cid
		}
		if len(c.Enrichment.ClosureParentByFunc) > 0 {
			ce := cluster.CodeEntry{RefID: r.RefID, OwnerRef: r.OwnerRef, ClusterIndex: r.Index}
			if owner, ok := naming.ResolveCodeOwner(ce, c.Pool.RefToNamed, c.Enrichment.ParamTypeByCodeIndex); ok {
				if parent := c.Enrichment.ClosureParentByFunc[owner.RefID]; parent != "" &&
					parent != fir.Name && !strings.HasPrefix(fir.Name, parent+"_") {
					fir.EnclosingFunction = parent
				}
			}
		}
		c.wireTryCatch(fir, r)
		c.enrichSignatureAndAsync(fir, r)
	}
	return fir, nil
}

// enrichSignatureAndAsync attaches parameter types, generic type parameters,
// named-parameter names, local type hints, and SuspendState async detection to
// fir — the signature/async enrichment the cmd funcIRBuilder applies, so the
// pipeline path (export-dart, ffitrace, strxref, census) produces the same
// FuncIR rather than a poorer one.
func (c *AnalysisContext) enrichSignatureAndAsync(fir *decompiler.FuncIR, r cluster.CodeRange) {
	// ensureDecompileMaps early-returns on a minimal Context (nil Result/Pool/Info),
	// leaving the enrichment resolvers nil; nothing to attach then.
	if c.Pool == nil || c.Enrichment.TypeParams == nil {
		return
	}
	ce := cluster.CodeEntry{RefID: r.RefID, OwnerRef: r.OwnerRef, ClusterIndex: r.Index}
	if owner, ok := naming.ResolveCodeOwner(ce, c.Pool.RefToNamed, c.Enrichment.ParamTypeByCodeIndex); ok && owner != nil && owner.SignatureRefID > 0 {
		if ft, ok := c.Enrichment.ParamFuncTypeByRef[owner.SignatureRefID]; ok {
			names := c.Enrichment.TypeParams.ParamTypeNames(*ft)
			if ft.HasImplicit && len(names) > 0 {
				names = names[1:] // drop the implicit receiver's own type
			}
			fir.ParamTypeNames = names
			fir.NamedParamNames = c.Enrichment.TypeParams.NamedParamNames(*ft)
		}
		if params := c.Enrichment.FuncTypeGenerics[owner.SignatureRefID]; len(params) > 0 {
			out := make([]string, len(params))
			for i, p := range params {
				out[i] = p.String()
			}
			fir.TypeParamNames = out
		}
	}
	if len(fir.ParamTypeNames) > 0 {
		fir.LocalTypeHints = make(map[string]string)
		for i, tn := range fir.ParamTypeNames {
			if tn != "" {
				fir.LocalTypeHints[fmt.Sprintf("arg%d", i)] = tn
			}
		}
	}
	// Async state machine: a SuspendState CID loaded from the pool marks the
	// function as async (drives the await/async-for linearizer).
	if !fir.IsAsync && c.Info != nil && c.Info.Version.CIDs.SuspendState != 0 {
		for bi := range fir.Blocks {
			for _, ins := range fir.Blocks[bi].Instrs {
				if ins.Op != decompiler.OpLoadPool || ins.PoolIndex < 0 {
					continue
				}
				if pe, ok := c.Enrichment.PoolByIndex[ins.PoolIndex]; ok {
					if cid, ok2 := c.Pool.RefCID[pe.RefID]; ok2 && cid == c.Info.Version.CIDs.SuspendState {
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
}

// wireTryCatch attaches ground-truth exception-handler + try-region metadata to
// fir from the per-Code tables, matching the cmd path's construction.
func (c *AnalysisContext) wireTryCatch(fir *decompiler.FuncIR, r cluster.CodeRange) {
	handlers, ok := c.Enrichment.ExcHandlersByCode[r.RefID]
	if !ok {
		return
	}
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
	entries, ok := c.Enrichment.PcDescByCode[r.RefID]
	if !ok || len(entries) == 0 {
		return
	}
	funcStart := uint64(r.PCOffset) - c.CodeOff
	regions := cluster.BuildTryRegions(entries, r.Size)
	regions = cluster.ExpandOuterTryRegions(regions, handlers)
	for _, reg := range regions {
		if reg.TryIndex < 0 || reg.TryIndex >= len(fir.ExceptionHandlers) {
			continue
		}
		h := fir.ExceptionHandlers[reg.TryIndex]
		fir.TryRegions = append(fir.TryRegions, decompiler.TryRegionEntry{
			StartVA:   funcStart + c.CodeVA + uint64(reg.StartPC),
			EndVA:     funcStart + c.CodeVA + uint64(reg.EndPC),
			TryIndex:  reg.TryIndex,
			Handler:   h,
			HandlerVA: funcStart + c.CodeVA + uint64(h.PCOffset),
		})
	}
	fir.SnapTryRegionsToBlocks()
}

// BuildArgRegMasks runs the whole-binary call-edge pass that aggregates, per
// callee, the argument-register mask observed at each direct call site. It is
// opt-in (a caller that wants confident real arity in FuncIRFor calls it once
// before decompiling) because it disassembles every function. After it runs,
// FuncIRFor sets FuncIR.ArgRegIndices for callees with >= 2 agreeing sites.
func (c *AnalysisContext) BuildArgRegMasks() {
	if c.Enrichment == nil {
		c.Enrichment = &DecompileEnrichment{}
	}
	if c.Enrichment.ArgRegMasks != nil {
		return
	}
	c.Enrichment.ArgRegMasks = make(map[uint64][]uint8)
	symLk := func(va uint64) (string, bool) { s, ok := c.SymbolNames[va]; return s, ok && s != "" }
	var thrFields map[int]string
	if c.Info != nil {
		thrFields = vmtables.THRFieldsWithProfile(c.DartVersion, c.IsARM64, c.Info.Version)
	}
	for _, r := range c.Ranges {
		if r.Size == 0 {
			continue
		}
		fStart := uint64(r.PCOffset) - c.CodeOff
		fEnd := fStart + uint64(r.Size)
		if fEnd > uint64(len(c.Code)) {
			fEnd = uint64(len(c.Code))
		}
		if fStart >= fEnd {
			continue
		}
		fVA := c.CodeVA + fStart
		if c.IsARM64 {
			insts := disasm.Disassemble(c.Code[fStart:fEnd], disasm.Options{BaseAddr: fVA})
			if len(insts) == 0 {
				continue
			}
			for _, e := range disasm.ExtractCallEdgesCFG(c.SymbolNames[fVA], insts, symLk, nil) {
				if e.Kind == "bl" && e.ArgRegMask != 0 {
					c.Enrichment.ArgRegMasks[e.TargetPC] = append(c.Enrichment.ArgRegMasks[e.TargetPC], e.ArgRegMask)
				}
			}
			continue
		}
		scan := disasm.ScanX86FunctionCFG(c.Code[fStart:fEnd], fVA, symLk, c.PoolDisplay, c.SymbolNames[fVA], thrFields)
		for _, e := range scan.Edges {
			if e.Kind == "call" && e.ArgRegMask != 0 {
				c.Enrichment.ArgRegMasks[e.TargetPC] = append(c.Enrichment.ArgRegMasks[e.TargetPC], e.ArgRegMask)
			}
		}
	}
}

// FindStringRefs returns every ref ID (app-isolate OR VM-isolate --
// both tables, per this session's own VM-string resolution fixes)
// whose string value contains substr (case-insensitive). Cheap: a
// linear scan over the already-parsed string tables, no function
// disassembly involved.
func (c *AnalysisContext) FindStringRefs(substr string) []int {
	needle := strings.ToLower(substr)
	var refs []int
	if c.Pool == nil {
		return refs
	}
	for refID, s := range c.Pool.RefToStr {
		if strings.Contains(strings.ToLower(s), needle) {
			refs = append(refs, refID)
		}
	}
	for refID, s := range c.Pool.VmRefToStr {
		if strings.Contains(strings.ToLower(s), needle) {
			refs = append(refs, refID)
		}
	}
	return refs
}

// PoolIndicesForRefIDs returns every object-pool index whose entry is a
// PoolTagged reference to one of the given ref IDs -- i.e. every pool
// slot a real function could load via LDR/MOV [PP+idx*8] to get one of
// these strings. Cheap: a linear scan over the already-parsed pool
// entries, no function disassembly involved.
func (c *AnalysisContext) PoolIndicesForRefIDs(refIDs map[int]bool) []int {
	var indices []int
	if c.Result == nil {
		return indices
	}
	for _, pe := range c.Result.Pool {
		if pe.Kind == cluster.PoolTagged && refIDs[pe.RefID] {
			indices = append(indices, pe.Index)
		}
	}
	return indices
}
