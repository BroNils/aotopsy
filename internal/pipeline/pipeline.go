// Package pipeline orchestrates aotopsy's ARM64 disassembly/call-graph/
// signal/Ghidra-IDA-metadata pipeline (Run) and its x86_64 counterpart's
// narrower disassembly/call-edge/signal stage (RunDisasmStageX86, in
// disasm_stage_x86.go), plus the shared name-resolution/pool-lookup
// surface (PoolLookups, helpers.go) most cmd/aotopsy files read from.
package pipeline

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"aotopsy/internal/cli"
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/disasm"
	"aotopsy/internal/elfx"
	"aotopsy/internal/snapshot"
)

// Opts controls pipeline execution.
type Opts struct {
	LibPath   string // path to libapp.so
	OutDir    string // output directory
	FromDir   string // reuse existing disasm output (skip ELF/disasm)
	Strict    bool
	MaxSteps  int
	Limit     int       // max functions (0=all)
	Graph     bool      // build callgraph DOTs
	Signal    bool      // run signal analysis
	SignalK   int       // signal context hops (default 2)
	Meta      bool      // produce flutter_meta.json
	DecompAll bool      // all functions vs signal-only in focus list
	Quiet     bool      // suppress verbose output (verbose is default)
	Log       io.Writer // stderr by default
}

// Result holds pipeline summary information.
type Result struct {
	OutDir      string
	LibPath     string // absolute
	DartVersion string
	PointerSize int
	FuncCount   int
	ClassCount  int
	SignalCount int
	MetaPath    string // empty if Meta=false
	Diags       []string
}

func (o *Opts) log() io.Writer {
	if o.Log != nil {
		return o.Log
	}
	return os.Stderr
}

func (o *Opts) logf(format string, args ...interface{}) {
	if !o.Quiet {
		_, _ = fmt.Fprintf(o.log(), format, args...)
	}
}

func (o *Opts) stagef(name string, format string, args ...interface{}) {
	if o.Quiet {
		return
	}
	detail := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(o.log(), "\n%s%s%s %s\n", cli.Pink, name, cli.Reset, detail)
}

// Run executes the full analysis pipeline.
func Run(opts Opts) (*Result, error) {
	if opts.SignalK <= 0 {
		opts.SignalK = 2
	}

	result := &Result{
		OutDir:  opts.OutDir,
		LibPath: opts.LibPath,
	}

	// If FromDir is set, skip ELF parsing and disassembly.
	if opts.FromDir != "" {
		return runFromExisting(&opts, result)
	}

	// Step 1: ELF open + snapshot extract.
	fmtOpts := dartfmt.Options{
		Mode:     dartfmt.ModeBestEffort,
		MaxSteps: opts.MaxSteps,
	}
	if opts.Strict {
		fmtOpts.Mode = dartfmt.ModeStrict
	}

	ef, err := elfx.Open(opts.LibPath)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = ef.Close() }()
	isARM64 := ef.IsARM64()

	info, err := snapshot.Extract(ef, fmtOpts)
	if err != nil {
		return nil, fmt.Errorf("extract: %w", err)
	}

	if info.Version != nil && info.Version.DartVersion != "" {
		opts.stagef("elf", "Dart SDK %s%s%s", cli.Gold, info.Version.DartVersion, cli.Reset)
		result.DartVersion = info.Version.DartVersion
	}
	if info.Version != nil && !info.Version.Supported {
		return nil, fmt.Errorf("HALT_UNSUPPORTED_VERSION: Dart %s (hash %s)", info.Version.DartVersion, info.VmHeader.SnapshotHash)
	}

	// Step 2: Parse isolate snapshot clusters + fill.
	data := info.IsolateData.Data
	if len(data) < 64 {
		return nil, fmt.Errorf("isolate data too short (%d bytes)", len(data))
	}

	clusterStart, err := cluster.FindClusterDataStart(data)
	if err != nil {
		return nil, fmt.Errorf("cluster start: %w", err)
	}

	clResult, err := cluster.ScanClusters(data, clusterStart, info.Version, false, fmtOpts)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}

	if err := cluster.ReadFill(data, clResult, info.Version, false, info.IsolateHeader.TotalSize); err != nil {
		return nil, fmt.Errorf("fill: %w", err)
	}

	// Step 3: Parse instructions table + resolve code ranges.
	// Pre-InstructionsTable versions (v2.10-v2.15) have InstructionTableDataOffset=0;
	// use TextOffset from Code fill instead.
	var ranges []cluster.CodeRange
	table, err := cluster.ParseInstructionsTable(data, &clResult.Header, info.Version, info.IsolateHeader)
	if err != nil && clResult.Header.InstructionTableDataOffset == 0 && info.Version.CodeTextOffsetDelta {
		// Pre-InstructionsTable: build ranges from TextOffset.
		codeRanges := cluster.ResolveCodeRangesFromTextOffset(clResult.Codes)
		ranges = codeRanges
		table = nil
	} else if err != nil {
		return nil, fmt.Errorf("instrtable: %w", err)
	} else {
		codeRanges, err := cluster.ResolveCodeRanges(clResult.Codes, table)
		if err != nil {
			return nil, fmt.Errorf("code ranges: %w", err)
		}
		stubRanges := cluster.ResolveStubRanges(table)
		ranges = cluster.MergeRanges(stubRanges, codeRanges)
	}

	code, codeOff, payloadLen, err := snapshot.CodeRegion(info.IsolateInstructions.Data)
	if err != nil {
		return nil, fmt.Errorf("code region: %w", err)
	}
	codeEndOffset := uint32(codeOff) + uint32(payloadLen)
	cluster.SetLastRangeSize(ranges, codeEndOffset)

	codeVA := info.IsolateInstructions.VA + codeOff

	opts.stagef("code", "%s%d%s bytes at VA %s0x%x%s",
		cli.Gold, payloadLen, cli.Reset, cli.Blue, codeVA, cli.Reset)
	if table != nil {
		opts.logf("  %sinstructions:%s %d entries (%d stubs + %d code)\n",
			cli.Muted, cli.Reset, table.Length, table.FirstEntryWithCode, int(table.Length)-int(table.FirstEntryWithCode))
	} else {
		opts.logf("  %sinstructions:%s text-offset mode (%d code ranges)\n",
			cli.Muted, cli.Reset, len(ranges))
	}
	opts.logf("  %sranges:%s %d\n",
		cli.Muted, cli.Reset, len(ranges))

	// Create output directory.
	if err := os.MkdirAll(opts.OutDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir output: %w", err)
	}

	// Parse the VM-isolate snapshot region (info.VmData) for base-object
	// resolution (strings/names/CIDs shared across every app that uses
	// this Dart SDK build). Without this, pool entries referencing
	// VM-isolate objects show as opaque "<vm:NNN>" placeholders instead
	// of their real content. This mirrors LoadContext's exact pattern
	// (context.go:140-150) and objects.go's proven approach.
	//
	// NOTE: This is a minimal inline fix (P0-7). The duplication with
	// LoadContext will be consolidated in P4-1 (SetupPipeline).
	var vmResult *cluster.Result
	if vmData := info.VmData.Data; len(vmData) >= 64 && info.VmHeader != nil {
		if vmStart, err := cluster.FindClusterDataStart(vmData); err == nil {
			if vmRes, err := cluster.ScanClusters(vmData, vmStart, info.Version, true, fmtOpts); err == nil {
				_ = cluster.ReadFill(vmData, vmRes, info.Version, true, info.VmHeader.TotalSize)
				vmResult = vmRes
			}
		}
	}

	// Build name lookups and pool display map.
	pl := BuildPoolLookups(clResult, info.Version.CIDs, vmResult, info.Version.CodeIndexOneBased)
	poolDisplay := ResolvePoolDisplay(clResult.Pool, pl)

	// Build and write class layouts.
	classLayouts := BuildClassLayouts(clResult, pl, info.Version.CompressedPointers)
	if len(classLayouts) > 0 {
		classesPath := filepath.Join(opts.OutDir, "classes.jsonl")
		classesFile, err := os.Create(classesPath)
		if err != nil {
			return nil, fmt.Errorf("create classes.jsonl: %w", err)
		}
		classesEnc := json.NewEncoder(classesFile)
		classesEnc.SetEscapeHTML(false)
		for i := range classLayouts {
			if err := classesEnc.Encode(&classLayouts[i]); err != nil {
				_ = classesFile.Close()
				return nil, fmt.Errorf("write classes.jsonl: %w", err)
			}
		}
		_ = classesFile.Close()
		opts.logf("  %sclasses:%s %d layouts\n", cli.Muted, cli.Reset, len(classLayouts))
	}
	result.ClassCount = len(classLayouts)

	// Write dart_meta.json.
	thrFields := disasm.THRFields(info.Version.DartVersion, isARM64)
	ptrSize := 8
	if info.Version.CompressedPointers {
		ptrSize = 4
	}
	result.PointerSize = ptrSize
	if err := WriteDartMeta(opts.OutDir, info.Version.DartVersion, info.Version.CompressedPointers, ptrSize, thrFields); err != nil {
		return nil, fmt.Errorf("write dart_meta.json: %w", err)
	}

	// Step 4: Per-function disassembly. x86_64 uses a separate, narrower
	// stage (internal/disasm/x86.go) -- see RunDisasmStageX86's doc
	// comment for exactly what it does and doesn't cover yet.
	var disasmResult *DisasmResult
	if isARM64 {
		disasmResult, err = RunDisasmStage(&opts, pl, poolDisplay, clResult, ranges, code, codeOff, codeVA, thrFields, info, table, fmtOpts)
	} else {
		disasmResult, err = RunDisasmStageX86(&opts, pl, poolDisplay, clResult, ranges, code, codeOff, codeVA, info, table, fmtOpts, thrFields)
	}
	if err != nil {
		return nil, err
	}
	result.FuncCount = disasmResult.Written

	// Step 4.5: Type inference — resolve dispatch-table BLR call sites
	// by inferring receiver ClassID at each call site.
	// Non-fatal: if it fails, BLR edges remain unresolved (as before).
	if err := RunTypeInferenceStage(&opts, isARM64, pl, clResult, ranges, code, codeOff, codeVA, info, table, thrFields); err != nil {
		opts.logf("  type inference: %v\n", err)
	}

	// Step 5: Signal analysis (if enabled) -- reads functions.jsonl/
	// call_edges.jsonl/string_refs.jsonl, which both disasm stages now
	// produce in the same schema, so this works unmodified for x86_64.
	if opts.Signal {
		sigResult, err := RunSignalStage(opts.OutDir, opts.SignalK, false, opts.Quiet, opts.log())
		if err != nil {
			return nil, fmt.Errorf("signal: %w", err)
		}
		result.SignalCount = sigResult.SignalCount
	}

	// Step 6: Flutter-meta generation (if enabled) -- Ghidra/IDA-oriented
	// metadata (register retyping tables, THR struct field layout) that
	// is genuinely ARM64-specific; not yet ported for x86_64.
	if opts.Meta {
		if !isARM64 {
			opts.logf("  %swarning:%s flutter_meta.json generation (Ghidra/IDA metadata) is ARM64-only -- skipping for x86_64\n", cli.Muted, cli.Reset)
		} else {
			metaPath, err := RunMetaStage(opts.OutDir, "", opts.DecompAll, opts.Quiet, opts.log())
			if err != nil {
				return nil, fmt.Errorf("meta: %w", err)
			}
			result.MetaPath = metaPath
		}
	}

	return result, nil
}

// runFromExisting runs signal/meta stages using pre-existing disasm output.
func runFromExisting(opts *Opts, result *Result) (*Result, error) {
	// Validate required files exist.
	for _, f := range []string{"functions.jsonl", "call_edges.jsonl"} {
		if _, err := os.Stat(filepath.Join(opts.FromDir, f)); err != nil {
			return nil, fmt.Errorf("--from dir missing %s: %w", f, err)
		}
	}

	outDir := opts.FromDir
	if opts.OutDir != "" {
		outDir = opts.OutDir
	}
	result.OutDir = outDir

	// Count existing functions.
	funcs, err := ReadJSONL[disasm.FuncRecord](filepath.Join(opts.FromDir, "functions.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("read functions.jsonl: %w", err)
	}
	result.FuncCount = len(funcs)

	if opts.Signal {
		sigResult, err := RunSignalStage(opts.FromDir, opts.SignalK, false, opts.Quiet, opts.log())
		if err != nil {
			return nil, fmt.Errorf("signal: %w", err)
		}
		result.SignalCount = sigResult.SignalCount
	}

	if opts.Meta {
		metaPath, err := RunMetaStage(opts.FromDir, "", opts.DecompAll, opts.Quiet, opts.log())
		if err != nil {
			return nil, fmt.Errorf("meta: %w", err)
		}
		result.MetaPath = metaPath
	}

	return result, nil
}
