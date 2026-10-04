package analysis

import (
	"fmt"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/naming"
	"aotopsy/internal/snapshot"
)

// dartfmtOptionsDefault returns the standard Options used by most callers
// (LoadContext, funcdiff, cmd/aotopsy commands that don't need Strict
// mode or a custom MaxSteps).
func dartfmtOptionsDefault() dartfmt.Options {
	return dartfmt.Options{Mode: dartfmt.ModeBestEffort}
}

// SnapshotContext bundles everything that every snapshot-aware caller
// (pipeline.Run, LoadContext, cmd/aotopsy commands, funcdiff) needs from
// a single libapp.so parse: the ELF file, the snapshot info, the isolate
// and VM cluster results, the instructions table, code ranges, pool
// lookups, and the raw code bytes.
//
// This struct exists because the 10-step setup sequence (ELF → snapshot →
// cluster scan → fill → instructions table → code ranges → code region →
// VM snapshot → pool lookups → pool display) was copy-pasted across 8
// files. One fix to the sequence (e.g. adding VM snapshot parsing) had to
// be repeated 8 times, and one missed copy was a real, previously-
// unnoticed gap that left pool entries as opaque "<vm:NNN>" placeholders.
type SnapshotContext struct {
	EF       *elfx.File
	Info     *snapshot.Info
	Result   *cluster.Result // isolate snapshot cluster result
	VMResult *cluster.Result // VM snapshot cluster result (nil if no VM snapshot)
	// VMError records why a present legacy VM snapshot could not be parsed in
	// best-effort mode. Callers whose semantic identity depends on VM base
	// objects (funcdiff, evidence-quality gates) must fail closed instead of
	// silently treating the missing VM names as removals/renames.
	VMError     error
	Table       *cluster.InstructionsTable
	Ranges      []cluster.CodeRange
	Pool        *naming.PoolLookups
	PoolDisplay map[int]string

	// Code is the raw instructions-image byte slice; CodeVA is the
	// virtual address of Code[0]; CodeOff is the byte offset of Code[0]
	// within the isolate instructions region (subtract this from a
	// CodeRange.PCOffset to get an index into Code).
	Code    []byte
	CodeVA  uint64
	CodeOff uint64

	IsARM64 bool
}

// RequireCompleteVM rejects a legacy snapshot whose isolate half parsed but
// whose VM-isolate half did not. LoadSnapshot deliberately preserves that
// partial state in best-effort mode for low-level diagnostics, but semantic
// consumers (pipeline/decompiler/FFI/name resolution) cannot safely publish it:
// VM base objects participate in pool naming, call resolution and capability
// recovery, so treating a parse failure as an empty VM snapshot manufactures
// removals and unresolved names.
//
// Unified snapshots have no separate VM image and therefore never carry a
// VMError here.
func (sc *SnapshotContext) RequireCompleteVM() error {
	if sc == nil {
		return fmt.Errorf("snapshot context is nil")
	}
	if sc.VMError != nil {
		return fmt.Errorf("legacy VM snapshot incomplete: %w", sc.VMError)
	}
	return nil
}

// Image returns a CodeImage providing unified function slicing.
func (sc *SnapshotContext) Image() CodeImage {
	return CodeImage{
		CodeImage: cluster.CodeImage{Code: sc.Code, CodeVA: sc.CodeVA, CodeOff: sc.CodeOff},
		Pool:      sc.Pool,
	}
}

// Slice extracts a clamped FuncSlice from a CodeRange within this SnapshotContext.
func (sc *SnapshotContext) Slice(r cluster.CodeRange) (FuncSlice, bool) {
	return sc.Image().Slice(r)
}

// LoadSnapshot opens libPath and runs the full snapshot parse pipeline:
// ELF → snapshot extract → isolate cluster scan+fill → instructions table
// → code ranges → code region → VM snapshot parse → pool lookups → pool
// display. Returns a SnapshotContext with all fields populated.
//
// Callers that need additional ELF-derived data (FuncSymbols, logging,
// output directory creation) can access ctx.EF and ctx.Info directly.
//
// opts controls the dartfmt.Options used for cluster scanning. Pass
// dartfmt.Options{Mode: dartfmt.ModeBestEffort} for the default.
func LoadSnapshot(libPath string, opts dartfmt.Options) (*SnapshotContext, error) {
	ef, err := elfx.Open(libPath)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	isARM64 := ef.IsARM64()

	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		_ = ef.Close()
		return nil, fmt.Errorf("extract: %w", err)
	}

	if info.Version == nil {
		_ = ef.Close()
		return nil, fmt.Errorf("HALT_UNKNOWN_VERSION: snapshot hash %s has no verified parser profile", info.SnapshotHash())
	}
	if !info.Version.Supported {
		_ = ef.Close()
		return nil, fmt.Errorf("HALT_UNSUPPORTED_VERSION: Dart %s (hash %s)",
			info.Version.DartVersion, info.SnapshotHash())
	}

	// Isolate snapshot: cluster scan + fill.
	data := info.IsolateData.Data
	if len(data) < 64 {
		_ = ef.Close()
		return nil, fmt.Errorf("isolate data too short (%d bytes)", len(data))
	}

	clusterStart, err := snapshot.FindClusterDataStart(data)
	if err != nil {
		_ = ef.Close()
		return nil, fmt.Errorf("cluster start: %w", err)
	}

	result, err := cluster.ScanClusters(data, clusterStart, info.Version, false, opts)
	if err != nil {
		_ = ef.Close()
		return nil, fmt.Errorf("scan: %w", err)
	}

	var isoSize int64
	if info.IsolateHeader != nil {
		isoSize = info.IsolateHeader.TotalSize
	}
	if err := cluster.ReadFill(data, result, info.Version, false, isoSize, opts); err != nil {
		_ = ef.Close()
		return nil, fmt.Errorf("fill: %w", err)
	}

	// Instructions table + code ranges.
	var table *cluster.InstructionsTable
	var ranges []cluster.CodeRange
	tbl, tblErr := cluster.ParseInstructionsTable(data, &result.Header, info.Version, info.IsolateHeader)
	switch {
	case tblErr != nil && result.Header.InstructionTableDataOffset == 0 && info.Version.CodeTextOffsetDelta:
		ranges = cluster.ResolveCodeRangesFromTextOffset(result.Codes)
	case tblErr != nil:
		_ = ef.Close()
		return nil, fmt.Errorf("instrtable: %w", tblErr)
	default:
		table = tbl
		codeRanges, err := cluster.ResolveCodeRanges(result.Codes, table)
		if err != nil {
			_ = ef.Close()
			return nil, fmt.Errorf("code ranges: %w", err)
		}
		stubRanges := cluster.ResolveStubRanges(table)
		ranges = cluster.MergeRanges(stubRanges, codeRanges)
	}

	// Code region.
	code, codeOff, payloadLen, err := snapshot.CodeRegion(info.IsolateInstructions.Data, info.Version)
	if err != nil {
		_ = ef.Close()
		return nil, fmt.Errorf("code region: %w", err)
	}
	codeEndOffset, err := CheckedCodeEndOffset(codeOff, payloadLen)
	if err != nil {
		_ = ef.Close()
		return nil, fmt.Errorf("code region extent: %w", err)
	}
	cluster.SetLastRangeSize(ranges, codeEndOffset)
	codeVA, ok := checkedCodeVA(info.IsolateInstructions.VA, codeOff)
	if !ok {
		_ = ef.Close()
		return nil, fmt.Errorf("code region virtual address overflows uint64: base=0x%x off=0x%x", info.IsolateInstructions.VA, codeOff)
	}
	// A CodeRange is semantic input to every later stage: disassembly,
	// type inference, fingerprints, decompilation and FFI tracing all assume the
	// declared function body exists in full. Historically CodeImage.Slice clamps
	// a range at the image end for low-level/debug consumers, which meant a bad
	// range could otherwise turn into a plausible partial function here. Validate
	// the invariant once at the loader boundary so all semantic consumers see an
	// all-or-nothing image. Corpus measurement: 877,374 non-zero ranges across all
	// 93 registered samples, zero truncations and zero zero-sized ranges.
	codeImage := cluster.CodeImage{Code: code, CodeVA: codeVA, CodeOff: codeOff}
	for i, r := range ranges {
		if r.Size == 0 {
			_ = ef.Close()
			return nil, fmt.Errorf("code range %d ref=%d pc=0x%x has zero size", i, r.RefID, r.PCOffset)
		}
		if _, _, ok := codeImage.SliceExact(r); !ok {
			_ = ef.Close()
			return nil, fmt.Errorf("code range %d ref=%d pc=0x%x size=%d falls outside instructions image", i, r.RefID, r.PCOffset, r.Size)
		}
	}

	// VM snapshot: cluster scan + fill. Unified 3.13+ snapshots deliberately
	// have no separate VM snapshot; every legacy snapshot does. In best-effort
	// mode preserve any legacy VM incompleteness in VMError so identity-sensitive
	// callers can fail closed without forcing that policy on every caller.
	var vmResult *cluster.Result
	var vmErr error
	if !info.UnifiedSnapshot {
		vmData := info.VmData.Data
		switch {
		case info.VmHeader == nil:
			vmErr = fmt.Errorf("VM snapshot header unavailable")
		case len(vmData) < 64:
			vmErr = fmt.Errorf("VM snapshot data too short (%d bytes)", len(vmData))
		default:
			vmStart, startErr := snapshot.FindClusterDataStart(vmData)
			if startErr != nil {
				vmErr = fmt.Errorf("VM cluster start: %w", startErr)
			} else {
				vmRes, scanErr := cluster.ScanClusters(vmData, vmStart, info.Version, true, opts)
				if scanErr != nil {
					vmErr = fmt.Errorf("VM scan: %w", scanErr)
				} else if fillErr := cluster.ReadFill(vmData, vmRes, info.Version, true, info.VmHeader.TotalSize, opts); fillErr != nil {
					vmErr = fmt.Errorf("VM fill: %w", fillErr)
				} else {
					vmResult = vmRes
				}
			}
		}
		if vmErr != nil && opts.Mode == dartfmt.ModeStrict {
			_ = ef.Close()
			return nil, vmErr
		}
	}

	// Pool lookups + display.
	firstEntryWithCode := -1
	if table != nil {
		firstEntryWithCode = int(table.FirstEntryWithCode)
	}
	pl := naming.BuildPoolLookups(result, info.Version.CIDs, vmResult,
		info.Version.CodeIndexOneBased, firstEntryWithCode, info.Version.DartVersion)
	poolDisplay := naming.ResolvePoolDisplay(result.Pool, pl)

	return &SnapshotContext{
		EF:          ef,
		Info:        info,
		Result:      result,
		VMResult:    vmResult,
		VMError:     vmErr,
		Table:       table,
		Ranges:      ranges,
		Pool:        pl,
		PoolDisplay: poolDisplay,
		Code:        code,
		CodeVA:      codeVA,
		CodeOff:     codeOff,
		IsARM64:     isARM64,
	}, nil
}

func checkedCodeVA(base, off uint64) (uint64, bool) {
	if off > ^uint64(0)-base {
		return 0, false
	}
	return base + off, true
}

// Close releases the underlying ELF file. Callers must call this when done.
func (c *SnapshotContext) Close() error {
	if c.EF != nil {
		return c.EF.Close()
	}
	return nil
}

// LoadSnapshotRaw opens libPath and extracts snapshot info only
// (ELF → snapshot extract), without cluster scan/fill. For diagnostic
// commands that only need snapshot regions (dump, strings).
// Caller must close the returned ELF file.
func LoadSnapshotRaw(libPath string, opts dartfmt.Options) (*elfx.File, *snapshot.Info, error) {
	ef, err := elfx.Open(libPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open: %w", err)
	}
	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		_ = ef.Close()
		return nil, nil, fmt.Errorf("extract: %w", err)
	}
	return ef, info, nil
}

// LoadSnapshotIsolate opens libPath and runs ELF → snapshot → cluster
// scan + fill for the ISOLATE snapshot only (no VM, no pool, no ranges).
// For diagnostic commands that need cluster data but not the full
// pipeline (thr_audit, parity).
// Caller must close the returned ELF file.
func LoadSnapshotIsolate(libPath string, opts dartfmt.Options) (*elfx.File, *snapshot.Info, *cluster.Result, error) {
	ef, info, err := LoadSnapshotRaw(libPath, opts)
	if err != nil {
		return nil, nil, nil, err
	}
	if info.Version == nil {
		_ = ef.Close()
		return nil, nil, nil, fmt.Errorf("HALT_UNKNOWN_VERSION: snapshot hash %s has no verified parser profile", info.SnapshotHash())
	}
	if !info.Version.Supported {
		_ = ef.Close()
		return nil, nil, nil, fmt.Errorf("HALT_UNSUPPORTED_VERSION: Dart %s (hash %s)",
			info.Version.DartVersion, info.SnapshotHash())
	}
	data := info.IsolateData.Data
	if len(data) < 64 {
		_ = ef.Close()
		return nil, nil, nil, fmt.Errorf("isolate data too short (%d bytes)", len(data))
	}
	clusterStart, err := snapshot.FindClusterDataStart(data)
	if err != nil {
		_ = ef.Close()
		return nil, nil, nil, fmt.Errorf("cluster start: %w", err)
	}
	result, err := cluster.ScanClusters(data, clusterStart, info.Version, false, opts)
	if err != nil {
		_ = ef.Close()
		return nil, nil, nil, fmt.Errorf("scan: %w", err)
	}
	var isoSize int64
	if info.IsolateHeader != nil {
		isoSize = info.IsolateHeader.TotalSize
	}
	if err := cluster.ReadFill(data, result, info.Version, false, isoSize, opts); err != nil {
		_ = ef.Close()
		return nil, nil, nil, fmt.Errorf("fill: %w", err)
	}
	return ef, info, result, nil
}
