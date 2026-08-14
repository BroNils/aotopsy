package pipeline

import (
	"debug/elf"
	"fmt"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
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
func LoadContext(libPath string) (*Context, error) {
	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}

	ef, err := elfx.Open(libPath)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	isARM64 := ef.ELF.Machine == elf.EM_AARCH64

	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		_ = ef.Close()
		return nil, fmt.Errorf("extract: %w", err)
	}

	data := info.IsolateData.Data
	clusterStart, err := cluster.FindClusterDataStart(data)
	if err != nil {
		_ = ef.Close()
		return nil, fmt.Errorf("cluster start: %w", err)
	}
	result, err := cluster.ScanClusters(data, clusterStart, info.Version, false, opts)
	if err != nil {
		_ = ef.Close()
		return nil, fmt.Errorf("scan: %w", err)
	}
	if err := cluster.ReadFill(data, result, info.Version, false, info.IsolateHeader.TotalSize); err != nil {
		_ = ef.Close()
		return nil, fmt.Errorf("fill: %w", err)
	}

	table, tblErr := cluster.ParseInstructionsTable(data, &result.Header, info.Version, info.IsolateHeader)
	var ranges []cluster.CodeRange
	switch {
	case tblErr != nil && result.Header.InstructionTableDataOffset == 0 && info.Version.CodeTextOffsetDelta:
		ranges = cluster.ResolveCodeRangesFromTextOffset(result.Codes)
	case tblErr != nil:
		_ = ef.Close()
		return nil, fmt.Errorf("instrtable: %w", tblErr)
	default:
		codeRanges, err := cluster.ResolveCodeRanges(result.Codes, table)
		if err != nil {
			_ = ef.Close()
			return nil, fmt.Errorf("code ranges: %w", err)
		}
		stubRanges := cluster.ResolveStubRanges(table)
		ranges = cluster.MergeRanges(stubRanges, codeRanges)
	}

	code, codeOff, payloadLen, err := snapshot.CodeRegion(info.IsolateInstructions.Data)
	if err != nil {
		_ = ef.Close()
		return nil, fmt.Errorf("code region: %w", err)
	}
	codeEndOffset := uint32(codeOff) + uint32(payloadLen) //nolint:gosec // bounded snapshot payload offsets, well under 2^32
	cluster.SetLastRangeSize(ranges, codeEndOffset)
	codeVA := info.IsolateInstructions.VA + codeOff

	// Parse the VM-isolate snapshot region (info.VmData) for base-object
	// resolution (strings/names/CIDs shared across every app that uses
	// this Dart SDK build, not serialized per-app). Without this, pool
	// entries referencing VM-isolate objects show as opaque "<vm:NNN>"
	// placeholders instead of their real content -- confirmed as a real,
	// previously-unnoticed gap this exact session: cmd/aotopsy/
	// decompile_native_cmd.go ALSO passes nil here (an existing,
	// project-wide limitation, not something new), while cmd/aotopsy/
	// objects.go already does this correctly (its own "vm snapshot: N
	// clusters, N strings" stderr line, ~99% pool resolution on a real
	// app) -- this mirrors objects.go's exact proven pattern rather than
	// inventing a new one.
	var vmResult *cluster.Result
	if vmData := info.VmData.Data; len(vmData) >= 64 && info.VmHeader != nil {
		if vmStart, err := cluster.FindClusterDataStart(vmData); err == nil {
			if vmRes, err := cluster.ScanClusters(vmData, vmStart, info.Version, true, opts); err == nil {
				_ = cluster.ReadFill(vmData, vmRes, info.Version, true, info.VmHeader.TotalSize)
				vmResult = vmRes
			}
		}
	}

	pl := BuildPoolLookups(result, info.Version.CIDs, vmResult, info.Version.CodeIndexOneBased, info.Version.DartVersion, info.Version.TypeClassIdIsRef)
	poolDisplay := ResolvePoolDisplay(result.Pool, pl)

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
			symbolNames[funcVA] = QualifiedCodeName(r.RefID, pl, r.PCOffset)
		} else {
			symbolNames[funcVA] = fmt.Sprintf("stub_%x", r.PCOffset)
		}
	}
	for va, name := range BuildVMStubSymbols(info, opts) {
		symbolNames[va] = name
	}
	for va, name := range BuildDiscardedFunctionSymbols(result.Named, info.Version.CIDs, table, pl, codeVA, codeOff, info.Version.CodeIndexOneBased) {
		symbolNames[va] = name
	}

	return &Context{
		EF:          ef,
		Info:        info,
		Result:      result,
		Ranges:      ranges,
		InstrTable:  table,
		Pool:        pl,
		PoolDisplay: poolDisplay,
		Code:        code,
		CodeVA:      codeVA,
		CodeOff:     codeOff,
		SymbolNames: symbolNames,
		SymbolSizes: symbolSizes,
		IsARM64:     isARM64,
		DartVersion: info.Version.DartVersion,
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
