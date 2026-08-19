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
	return fir, nil
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
