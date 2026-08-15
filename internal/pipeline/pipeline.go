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
	"aotopsy/internal/signal"
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

	// Step 1-3: Load snapshot (ELF → snapshot → cluster → fill → table →
	// code ranges → VM snapshot → pool lookups → pool display).
	// This was previously inlined as ~120 lines copy-pasted across 8 files;
	// LoadSnapshot is the single shared implementation.
	fmtOpts := dartfmt.Options{
		Mode:     dartfmt.ModeBestEffort,
		MaxSteps: opts.MaxSteps,
	}
	if opts.Strict {
		fmtOpts.Mode = dartfmt.ModeStrict
	}

	sc, err := LoadSnapshot(opts.LibPath, fmtOpts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = sc.Close() }()

	ef := sc.EF
	info := sc.Info
	clResult := sc.Result
	table := sc.Table
	ranges := sc.Ranges
	code := sc.Code
	codeOff := sc.CodeOff
	codeVA := sc.CodeVA
	payloadLen := uint64(len(code))
	isARM64 := sc.IsARM64
	elfFuncSyms := ef.FuncSymbols()
	pl := sc.Pool
	poolDisplay := sc.PoolDisplay

	if info.Version != nil && info.Version.DartVersion != "" {
		opts.stagef("elf", "Dart SDK %s%s%s", cli.Gold, info.Version.DartVersion, cli.Reset)
		result.DartVersion = info.Version.DartVersion
	}

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

	// Write captured-data JSONL files (scripts, loading_units, kpi, instances,
	// contexts, type_arguments, exception_handlers, icdata).
	// These are produced from the fill-phase capture layer and provide
	// structured access to snapshot objects that were previously discarded.
	//
	// Note: ICData, Context and KernelProgramInfo do not appear in AOT
	// snapshots, so their files are never written.
	//
	// The reason is NOT "their serialization cluster is behind
	// #if !defined(DART_PRECOMPILED_RUNTIME)" -- an earlier version of this
	// comment claimed that, and it is wrong. Checked against
	// runtime/vm/app_snapshot.cc @ 3.9.2: Serializer::NewClusterForClass has
	// no such guard for kICDataCid, kContextCid or kKernelProgramInfoCid (the
	// serializer as a whole only exists in non-AOT-runtime builds, but
	// gen_snapshot is exactly such a build and it is what writes AOT
	// snapshots). The only one genuinely #if-guarded is KernelProgramInfo's
	// *deserialization* cluster.
	//
	// The real reasons:
	// - ICData: a JIT inline cache. The precompiler does not retain
	//   ic_data_array_, so nothing ever reaches the serializer.
	// - Context: allocated on the heap when a closure runs, not ahead of time.
	// - KernelProgramInfo: dropped because the kernel binary is not needed at
	//   runtime in AOT ("KernelProgramInfo objects are not written into a
	//   full AOT snapshot" -- SDK comment above the deserialization cluster).
	//
	// Confirmed empirically: 0 entries for all three across 16 corpus samples
	// (Dart 2.12.0 / 3.7.0 / 3.9.2 / 3.10.7 / 3.11.0 / 3.12.2, arm64 + x64).
	writeCapturedJSONL(&opts, clResult, pl, classLayouts, opts.log())

	// Write pool_immediates.jsonl for crypto constant identification.
	poolImmPath := filepath.Join(opts.OutDir, "pool_immediates.jsonl")
	poolImmFile, err := os.Create(poolImmPath)
	if err != nil {
		return nil, fmt.Errorf("create pool_immediates.jsonl: %w", err)
	}
	poolImmEnc := json.NewEncoder(poolImmFile)
	poolImmEnc.SetEscapeHTML(false)
	poolImmCount := 0
	for _, pe := range clResult.Pool {
		if pe.Kind == cluster.PoolImmediate {
			rec := struct {
				Index int    `json:"index"`
				Value int64  `json:"value"`
				Hex   string `json:"hex"`
			}{
				Index: pe.Index,
				Value: pe.Imm,
				Hex:   fmt.Sprintf("0x%x", uint64(pe.Imm)),
			}
			if err := poolImmEnc.Encode(&rec); err != nil {
				_ = poolImmFile.Close()
				return nil, fmt.Errorf("write pool_immediates.jsonl: %w", err)
			}
			poolImmCount++
		}
	}
	_ = poolImmFile.Close()

	// Write dart_meta.json.
	thrFields := disasm.THRFieldsWithProfile(info.Version.DartVersion, isARM64, info.Version)
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
		disasmResult, err = RunDisasmStage(&opts, pl, poolDisplay, clResult, ranges, code, codeOff, codeVA, thrFields, info, table, fmtOpts, elfFuncSyms)
	} else {
		disasmResult, err = RunDisasmStageX86(&opts, pl, poolDisplay, clResult, ranges, code, codeOff, codeVA, info, table, fmtOpts, thrFields, elfFuncSyms)
	}
	if err != nil {
		return nil, err
	}
	result.FuncCount = disasmResult.Written

	// Step 4.5: Type inference — resolve dispatch-table BLR call sites
	// by inferring receiver ClassID at each call site.
	// Non-fatal: if it fails, BLR edges remain unresolved (as before).
	// Runs BEFORE xref so that dispatch_table.jsonl is available for
	// selector_dispatch_xref.jsonl generation.
	if err := RunTypeInferenceStage(&opts, isARM64, pl, clResult, ranges, code, codeOff, codeVA, info, table, thrFields); err != nil {
		opts.logf("  type inference: %v\n", err)
	}

	// Step 4.6: Cross-referencing JSONL outputs (gap-analysis §6).
	// Reads functions.jsonl, call_edges.jsonl, string_refs.jsonl
	// produced by the disasm stage, and dispatch_table.jsonl produced
	// by the type inference stage.
	funcs, _ := ReadJSONL[disasm.FuncRecord](filepath.Join(opts.OutDir, "functions.jsonl"))
	edges, _ := ReadJSONL[disasm.CallEdgeRecord](filepath.Join(opts.OutDir, "call_edges.jsonl"))
	stringRefs, _ := ReadJSONL[disasm.StringRefRecord](filepath.Join(opts.OutDir, "string_refs.jsonl"))
	if err := writeXrefJSONL(opts.OutDir, clResult, pl, funcs, edges, stringRefs, info.Version.CompressedPointers); err != nil {
		opts.logf("  xref: %v\n", err)
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

		// Step 5.1: Entropy analysis (packed/encrypted section detection).
		if err := signal.WriteEntropyFindings(opts.OutDir, opts.LibPath); err != nil {
			opts.logf("  entropy: %v\n", err)
		}

		// Step 5.1b: Crypto algorithm identification from binary scan.
		// Dart AOT compiles integer constants to MOVZ/MOVK instructions,
		// so crypto constants appear as raw bytes in .text, not as pool
		// immediates. Scan the binary for known crypto constant patterns.
		cryptoFromBinary, _ := signal.IdentifyCryptoFromBinary(opts.LibPath)
		cryptoFromPool, _ := signal.IdentifyCryptoFromPoolImmediates(opts.OutDir)
		allCrypto := append(cryptoFromBinary, cryptoFromPool...)
		if len(allCrypto) > 0 {
			if err := signal.WriteCryptoFindings(opts.OutDir, allCrypto); err != nil {
				opts.logf("  crypto: %v\n", err)
			}
		}

		// Step 5.2: Data flow / taint analysis (simplified).
		// Identifies potential source→sink flows based on string patterns.
		if err := signal.WriteTaintFindings(opts.OutDir, stringRefs, edges); err != nil {
			opts.logf("  taint: %v\n", err)
		}

		// Step 5.3: YARA-style malware matching.
		if err := signal.WriteYaraFindings(opts.OutDir, stringRefs); err != nil {
			opts.logf("  yara: %v\n", err)
		}

		// Step 5.4: Call-graph behavioral analysis.
		if err := signal.WriteBehavioralFindings(opts.OutDir, funcs, edges); err != nil {
			opts.logf("  behavioral: %v\n", err)
		}
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

// writeCapturedJSONL writes all captured-data JSONL files from the fill-phase
// capture layer. Each file is written only if the corresponding data slice is
// non-empty. Errors are logged but non-fatal (captured data is supplementary).
func writeCapturedJSONL(opts *Opts, clResult *cluster.Result, pl *PoolLookups, layouts []DartClassLayout, log io.Writer) {
	type jsonlEntry struct {
		filename string
		label    string
		records  interface{}
	}

	entries := []jsonlEntry{
		{"scripts.jsonl", "scripts", BuildScripts(clResult, pl)},
		{"loading_units.jsonl", "loading_units", BuildLoadingUnits(clResult)},
		{"kpi.jsonl", "kpi", BuildKPI(clResult)},
		{"instances.jsonl", "instances", BuildInstances(clResult, layouts)},
		{"contexts.jsonl", "contexts", BuildContexts(clResult)},
		{"type_arguments.jsonl", "type_arguments", BuildTypeArguments(clResult)},
		{"exception_handlers.jsonl", "exception_handlers", BuildExceptionHandlers(clResult)},
		{"icdata.jsonl", "icdata", BuildICData(clResult)},
		{"closure_data.jsonl", "closure_data", BuildClosureData(clResult)},
		// Consumer for the Script/Library capture: gap §6 "No library ->
		// functions xref".
		{"library_functions.jsonl", "library_functions", BuildLibraryFunctions(clResult, pl)},
	}

	// Report the Code/loading-unit partition, and say plainly when it carries
	// no information. A single-unit app (no deferred imports) yields one
	// bucket, and printing "partitioned N codes into 1 unit" would dress that
	// up as a result it is not.
	if part := PartitionCodesByLoadingUnit(clResult); !opts.Quiet && part.UnitCount > 0 {
		if part.Degenerate {
			_, _ = fmt.Fprintf(log, "  %sloading units:%s 1 (root id %d), no deferred imports -- Code partition is trivial\n",
				cli.Muted, cli.Reset, part.RootUnitID)
		} else {
			_, _ = fmt.Fprintf(log, "  %sloading units:%s %d, codes %d root / %d deferred (defined in another unit's blob)\n",
				cli.Muted, cli.Reset, part.UnitCount, len(part.MainCodeRefs), len(part.DeferredCodeRefs))
		}
	}

	for _, entry := range entries {
		// Use reflection-free approach: check if the slice is empty by
		// converting to a known interface.
		if !hasRecords(entry.records) {
			continue
		}
		path := filepath.Join(opts.OutDir, entry.filename)
		f, err := os.Create(path)
		if err != nil {
			if !opts.Quiet {
				_, _ = fmt.Fprintf(log, "  %swarning:%s write %s: %v\n", cli.Muted, cli.Reset, entry.filename, err)
			}
			continue
		}
		enc := json.NewEncoder(f)
		enc.SetEscapeHTML(false)
		encodeAll(enc, entry.records)
		_ = f.Close()
		if !opts.Quiet {
			_, _ = fmt.Fprintf(log, "  %s%s:%s %d entries\n", cli.Muted, entry.label, cli.Reset, countRecords(entry.records))
		}
	}
}

// hasRecords returns true if the interface wraps a non-empty slice.
func hasRecords(v interface{}) bool {
	return countRecords(v) > 0
}

// countRecords returns the length of a slice wrapped in interface{}, or 0.
func countRecords(v interface{}) int {
	switch s := v.(type) {
	case []ScriptRecord:
		return len(s)
	case []LoadingUnitRecord:
		return len(s)
	case []KPIRecord:
		return len(s)
	case []InstanceRecord:
		return len(s)
	case []ContextRecord:
		return len(s)
	case []TypeArgumentsRecord:
		return len(s)
	case []ExceptionHandlerRecord:
		return len(s)
	case []ICDataRecord:
		return len(s)
	case []ClosureDataRecord:
		return len(s)
	case []LibraryFunctionsRecord:
		return len(s)
	}
	return 0
}

// encodeAll encodes each element of a slice via the given encoder.
func encodeAll(enc *json.Encoder, v interface{}) {
	switch s := v.(type) {
	case []ScriptRecord:
		for i := range s {
			_ = enc.Encode(&s[i])
		}
	case []LoadingUnitRecord:
		for i := range s {
			_ = enc.Encode(&s[i])
		}
	case []KPIRecord:
		for i := range s {
			_ = enc.Encode(&s[i])
		}
	case []InstanceRecord:
		for i := range s {
			_ = enc.Encode(&s[i])
		}
	case []ContextRecord:
		for i := range s {
			_ = enc.Encode(&s[i])
		}
	case []TypeArgumentsRecord:
		for i := range s {
			_ = enc.Encode(&s[i])
		}
	case []ExceptionHandlerRecord:
		for i := range s {
			_ = enc.Encode(&s[i])
		}
	case []ICDataRecord:
		for i := range s {
			_ = enc.Encode(&s[i])
		}
	case []ClosureDataRecord:
		for i := range s {
			_ = enc.Encode(&s[i])
		}
	case []LibraryFunctionsRecord:
		for i := range s {
			_ = enc.Encode(&s[i])
		}
	}
}
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
