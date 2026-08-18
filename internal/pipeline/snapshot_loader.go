package pipeline

import (
	"fmt"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
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
	EF          *elfx.File
	Info        *snapshot.Info
	Result      *cluster.Result // isolate snapshot cluster result
	VMResult    *cluster.Result // VM snapshot cluster result (nil if no VM snapshot)
	Table       *cluster.InstructionsTable
	Ranges      []cluster.CodeRange
	Pool        *PoolLookups
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

	if info.Version != nil && !info.Version.Supported {
		_ = ef.Close()
		return nil, fmt.Errorf("HALT_UNSUPPORTED_VERSION: Dart %s (hash %s)",
			info.Version.DartVersion, info.VmHeader.SnapshotHash)
	}

	// Isolate snapshot: cluster scan + fill.
	data := info.IsolateData.Data
	if len(data) < 64 {
		_ = ef.Close()
		return nil, fmt.Errorf("isolate data too short (%d bytes)", len(data))
	}

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

	var isoSize int64
	if info.IsolateHeader != nil {
		isoSize = info.IsolateHeader.TotalSize
	}
	if err := cluster.ReadFill(data, result, info.Version, false, isoSize); err != nil {
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
	code, codeOff, payloadLen, err := snapshot.CodeRegion(info.IsolateInstructions.Data)
	if err != nil {
		_ = ef.Close()
		return nil, fmt.Errorf("code region: %w", err)
	}
	codeEndOffset := uint32(codeOff) + uint32(payloadLen) //nolint:gosec // bounded snapshot payload offsets
	cluster.SetLastRangeSize(ranges, codeEndOffset)
	codeVA := info.IsolateInstructions.VA + codeOff

	// VM snapshot: cluster scan + fill (best-effort, nil if absent).
	var vmResult *cluster.Result
	if vmData := info.VmData.Data; len(vmData) >= 64 && info.VmHeader != nil {
		if vmStart, err := cluster.FindClusterDataStart(vmData); err == nil {
			if vmRes, err := cluster.ScanClusters(vmData, vmStart, info.Version, true, opts); err == nil {
				_ = cluster.ReadFill(vmData, vmRes, info.Version, true, info.VmHeader.TotalSize)
				vmResult = vmRes
			}
		}
	}

	// Pool lookups + display.
	pl := BuildPoolLookups(result, info.Version.CIDs, vmResult,
		info.Version.CodeIndexOneBased, info.Version.DartVersion, info.Version.TypeClassIdIsRef)
	poolDisplay := ResolvePoolDisplay(result.Pool, pl)

	return &SnapshotContext{
		EF:          ef,
		Info:        info,
		Result:      result,
		VMResult:    vmResult,
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
	if info.Version != nil && !info.Version.Supported {
		_ = ef.Close()
		return nil, nil, nil, fmt.Errorf("HALT_UNSUPPORTED_VERSION: Dart %s (hash %s)",
			info.Version.DartVersion, info.VmHeader.SnapshotHash)
	}
	data := info.IsolateData.Data
	if len(data) < 64 {
		_ = ef.Close()
		return nil, nil, nil, fmt.Errorf("isolate data too short (%d bytes)", len(data))
	}
	clusterStart, err := cluster.FindClusterDataStart(data)
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
	if err := cluster.ReadFill(data, result, info.Version, false, isoSize); err != nil {
		_ = ef.Close()
		return nil, nil, nil, fmt.Errorf("fill: %w", err)
	}
	return ef, info, result, nil
}
