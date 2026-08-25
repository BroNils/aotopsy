package pipeline

import (
	"fmt"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/disasm"
	"aotopsy/internal/elfx"
	"aotopsy/internal/snapshot"
)

// Context bundles everything a per-function tool (FFI-target tracing,
// CPU emulation, or any other future single-function analysis) needs
// from the existing static pipeline, built once per libapp.so and
// reused across however many functions get analyzed in one run.
//
// This factors out cmd/aotopsy/decompile_native_cmd.go's setup
// sequence (elfx.Open -> snapshot.Extract -> cluster.ScanClusters/
// ReadFill -> ParseInstructionsTable -> ResolveCodeRanges ->
// BuildPoolLookups) into a reusable, exported entry point, WITHOUT
// modifying decompile_native_cmd.go itself -- that command's own
// inline copy stays as-is to avoid regressing an already-verified
// code path; new callers should use LoadContext instead of
// duplicating the sequence again.
type Context struct {
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

	Pool *PoolLookups

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

	// Decompile enrichment, built once on demand by ensureDecompileMaps so a
	// FuncIR produced by FuncIRFor carries the same field-name / receiver-class /
	// closure-parent / try-catch metadata the cmd path wires. Nil until built.
	decompileMapsBuilt     bool
	fieldNameResolver      func(classID int, byteOffset int64) string
	receiverClassByCode    map[int]int
	closureParentByFunc    map[int]string
	excHandlersByCode      map[int][]cluster.ExceptionHandlerEntry
	pcDescByCode           map[int][]cluster.PcDescriptorEntry
	paramTypeByCodeIndex   map[int]*cluster.NamedObject
	classNameToID          map[string]int
	fieldTypeByClassOffset map[int]map[int64]int
}

// LoadContext opens libPath and runs the full static-analysis setup
// pipeline once. Callers must call Close() when done (closes the
// underlying ELF file).
func LoadContext(libPath string) (ctx *Context, err error) {
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
			symbolNames[funcVA] = QualifiedCodeName(r.RefID, sc.Pool, r.PCOffset)
		} else {
			symbolNames[funcVA] = fmt.Sprintf("stub_%x", r.PCOffset)
		}
	}
	for va, name := range BuildVMStubSymbols(sc.Info, dartfmtOptionsDefault()) {
		symbolNames[va] = name
	}
	for va, name := range BuildDiscardedFunctionSymbols(sc.Result.Named, sc.Info.Version.CIDs, sc.Table, sc.Pool, sc.CodeVA, sc.CodeOff, sc.Info.Version.CodeIndexOneBased) {
		symbolNames[va] = name
	}

	return &Context{
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

func (c *Context) Close() error {
	return c.EF.Close()
}

// SymbolLookup adapts Context.SymbolNames to the func(uint64)(string,bool)
// shape internal/decompiler/internal/disasm callers expect.
func (c *Context) SymbolLookup(va uint64) (string, bool) {
	name, ok := c.SymbolNames[va]
	return name, ok
}

// PoolLookup adapts Context.PoolDisplay to the func(int)(string,bool)
// shape decompiler.EmitPseudocode expects.
func (c *Context) PoolLookup(idx int) (string, bool) {
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
func (c *Context) ensureDecompileMaps() {
	if c.decompileMapsBuilt {
		return
	}
	c.decompileMapsBuilt = true
	if c.Result == nil || c.Pool == nil || c.Info == nil {
		return
	}
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
	c.classNameToID = make(map[string]int, len(layouts))
	for _, cl := range layouts {
		if cl.ClassName != "" && cl.ClassID > 0 {
			c.classNameToID[cl.ClassName] = int(cl.ClassID)
		}
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
	c.fieldNameResolver = func(classID int, byteOffset int64) string {
		if classID > 0 {
			if m, ok := perClass[int32(classID)]; ok {
				if n, ok2 := m[int32(byteOffset)]; ok2 {
					return n
				}
			}
		}
		return globalByOffset[int32(byteOffset)]
	}

	// Receiver class per Code, via owner Function -> (PatchClass hop) -> Class.
	c.paramTypeByCodeIndex = CodeIndexToFunc(result, ct, c.Info.Version.CodeIndexOneBased)
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
	c.receiverClassByCode = make(map[int]int, len(result.Codes))
	for _, ce := range result.Codes {
		if owner, ok := ResolveCodeOwner(ce, pl.RefToNamed, c.paramTypeByCodeIndex); ok && owner != nil {
			if classRef := effectiveClassRef(owner); classRef > 0 {
				if ci, ok2 := classByRef[classRef]; ok2 {
					c.receiverClassByCode[ce.RefID] = int(ci.ClassID)
				}
			}
		}
	}

	// Field TYPE by (ownerClassID, byteOffset) -> the field's declared type's
	// class ID. This types field-load chains (`this.a.b`): loading field `a` of a
	// known class yields an object whose class is `a`'s declared type, so the
	// next `.b` resolves. Only populated where the type resolves to a concrete
	// class (v3.x TypeInfo.ClassID); elsewhere it degrades to unknown (honest).
	typeClassByRef := make(map[int]int32, len(result.Types))
	for i := range result.Types {
		if result.Types[i].ClassID > 0 {
			typeClassByRef[result.Types[i].RefID] = result.Types[i].ClassID
		}
	}
	c.fieldTypeByClassOffset = map[int]map[int64]int{}
	for i := range result.Fields {
		f := &result.Fields[i]
		if f.HostOffset < 0 || f.TypeRefID < 0 {
			continue
		}
		tc, ok := typeClassByRef[f.TypeRefID]
		if !ok || tc <= 0 {
			continue
		}
		ownerClass, ok := classByRef[f.OwnerRefID]
		if !ok || ownerClass.ClassID <= 0 {
			continue
		}
		ocid := int(ownerClass.ClassID)
		if c.fieldTypeByClassOffset[ocid] == nil {
			c.fieldTypeByClassOffset[ocid] = map[int64]int{}
		}
		c.fieldTypeByClassOffset[ocid][int64(f.HostOffset)] = int(tc)
	}

	c.closureParentByFunc = BuildClosureParents(result, pl)

	// Exception handlers + PcDescriptors per Code, for ground-truth try/catch.
	ehByRef := make(map[int][]cluster.ExceptionHandlerEntry, len(result.ExceptionHandlers))
	for i := range result.ExceptionHandlers {
		ehByRef[result.ExceptionHandlers[i].RefID] = result.ExceptionHandlers[i].Handlers
	}
	pdByRef := make(map[int][]cluster.PcDescriptorEntry, len(result.PcDescriptors))
	for i := range result.PcDescriptors {
		pdByRef[result.PcDescriptors[i].RefID] = result.PcDescriptors[i].Entries
	}
	c.excHandlersByCode = make(map[int][]cluster.ExceptionHandlerEntry)
	c.pcDescByCode = make(map[int][]cluster.PcDescriptorEntry)
	for _, ce := range result.Codes {
		if ce.ExceptionHandlersRef >= 0 {
			if h, ok := ehByRef[ce.ExceptionHandlersRef]; ok {
				c.excHandlersByCode[ce.RefID] = h
			}
		}
		if ce.PcDescriptorsRef >= 0 {
			if e, ok := pdByRef[ce.PcDescriptorsRef]; ok {
				c.pcDescByCode[ce.RefID] = e
			}
		}
	}
}

// FuncIRFor builds the arch-neutral FuncIR for one CodeRange, mirroring
// decompile_native_cmd.go's buildFuncIR closure (arity inference is left
// to the caller -- ArgRegIndices requires a whole-binary call-edge
// aggregation pass that's only worth paying for when a caller actually
// needs it, see resolveArgRegIndices's doc comment in decompile_native_cmd.go).
func (c *Context) FuncIRFor(r cluster.CodeRange) (*decompiler.FuncIR, error) {
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
	fir.ThreadStubOffsets = disasm.ThreadStubOffsets(c.DartVersion, c.IsARM64)
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
	fir.FieldNameResolver = c.fieldNameResolver
	fir.ClassNameToID = c.classNameToID
	if c.fieldTypeByClassOffset != nil {
		fir.FieldTypeResolver = func(classID int, off int64) int {
			if m, ok := c.fieldTypeByClassOffset[classID]; ok {
				return m[off]
			}
			return 0
		}
	}
	if r.RefID >= 0 {
		if cid, ok := c.receiverClassByCode[r.RefID]; ok && cid > 0 {
			fir.ReceiverClassID = cid
		}
		if len(c.closureParentByFunc) > 0 {
			ce := cluster.CodeEntry{RefID: r.RefID, OwnerRef: r.OwnerRef, ClusterIndex: r.Index}
			if owner, ok := ResolveCodeOwner(ce, c.Pool.RefToNamed, c.paramTypeByCodeIndex); ok {
				if parent := c.closureParentByFunc[owner.RefID]; parent != "" &&
					parent != fir.Name && !strings.HasPrefix(fir.Name, parent+"_") {
					fir.EnclosingFunction = parent
				}
			}
		}
		c.wireTryCatch(fir, r)
	}
	return fir, nil
}

// wireTryCatch attaches ground-truth exception-handler + try-region metadata to
// fir from the per-Code tables, matching the cmd path's construction.
func (c *Context) wireTryCatch(fir *decompiler.FuncIR, r cluster.CodeRange) {
	handlers, ok := c.excHandlersByCode[r.RefID]
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
	entries, ok := c.pcDescByCode[r.RefID]
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

// FindStringRefs returns every ref ID (app-isolate OR VM-isolate --
// both tables, per this session's own VM-string resolution fixes)
// whose string value contains substr (case-insensitive). Cheap: a
// linear scan over the already-parsed string tables, no function
// disassembly involved.
func (c *Context) FindStringRefs(substr string) []int {
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
func (c *Context) PoolIndicesForRefIDs(refIDs map[int]bool) []int {
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
