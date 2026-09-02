// Package analysis orchestrates aotopsy's ARM64 disassembly/call-graph/
// signal/Ghidra-IDA-metadata pipeline (Run) and its x86_64 counterpart's
// narrower disassembly/call-edge/signal stage (RunDisasmStageX86, in
// disasm_stagex86.go). The shared name-resolution/pool-lookup surface
// (PoolLookups, BuildPoolLookups, etc.) lives in internal/naming, which
// analysis imports and which cmd/aotopsy files read from directly.
package analysis

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"aotopsy/internal/cli"
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/disasm"
	"aotopsy/internal/evidence"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/naming"
	"aotopsy/internal/output"
	"aotopsy/internal/signal"
	"aotopsy/internal/strutil"
	"aotopsy/internal/vmtables"
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
	Decompile bool      // emit per-function Dart pseudocode into <out>/dart/
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
	// DecompiledCount is the number of .dart files written; 0 unless
	// Opts.Decompile was set.
	DecompiledCount int
	Diags           []string
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

	// Record which binary this directory came from, first thing, so it is
	// there even if a later stage fails. Every stage that wants to name
	// the analysed file reads this; without it they fall back to guessing
	// from the output directory's own name.
	{
		dv, compressed := "", false
		if info.Version != nil {
			dv, compressed = info.Version.DartVersion, info.Version.CompressedPointers
		}
		if err := WriteProvenance(opts.OutDir, opts.LibPath, dv, isARM64, compressed); err != nil {
			opts.logf("  provenance: %v\n", err)
		}
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
	thrFields := vmtables.THRFieldsWithProfile(info.Version.DartVersion, isARM64, info.Version)
	ptrSize := 8
	if info.Version.CompressedPointers {
		ptrSize = 4
	}
	result.PointerSize = ptrSize
	if err := strutil.WriteDartMeta(opts.OutDir, info.Version.DartVersion, info.Version.CompressedPointers, ptrSize, thrFields); err != nil {
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
	tiOut, err := RunTypeInferenceStage(&opts, isARM64, pl, clResult, ranges, code, codeOff, codeVA, info, table, thrFields, sc.VMResult)
	if err != nil {
		opts.logf("  type inference: %v\n", err)
	}

	// Step 4.6: Cross-referencing JSONL outputs (gap-analysis §6).
	// Reads functions.jsonl, call_edges.jsonl, string_refs.jsonl
	// produced by the disasm stage, and dispatch_table.jsonl produced
	// by the type inference stage.
	funcs, _ := jsonutil.ReadJSONL[disasm.FuncRecord](filepath.Join(opts.OutDir, "functions.jsonl"))
	edges, _ := jsonutil.ReadJSONL[disasm.CallEdgeRecord](filepath.Join(opts.OutDir, "call_edges.jsonl"))
	stringRefs, _ := jsonutil.ReadJSONL[disasm.StringRefRecord](filepath.Join(opts.OutDir, "string_refs.jsonl"))
	if err := writeXrefJSONL(opts.OutDir, clResult, pl, funcs, edges, stringRefs, info.Version.CompressedPointers); err != nil {
		opts.logf("  xref: %v\n", err)
	}

	// Step 5: Signal analysis (if enabled) -- reads functions.jsonl/
	// call_edges.jsonl/string_refs.jsonl, which both disasm stages now
	// produce in the same schema, so this works unmodified for x86_64.
	var signalFindings []output.SignalFinding
	if opts.Signal {
		// false: step 9 below writes evidence.jsonl with these findings
		// plus the type-inference resolutions folded in.
		sigResult, err := RunSignalStage(opts.OutDir, opts.SignalK, false, opts.Quiet, opts.log(), false, opts.LibPath)
		if err != nil {
			return nil, fmt.Errorf("signal: %w", err)
		}
		result.SignalCount = sigResult.SignalCount
		signalFindings = sigResult.Findings

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

	// Step 7: R2 export (radare2 command script) — Item 18.
	// Exports recovered function names as r2 flags so analysts can
	// import them via `r2 -i aotopsy.r2 libapp.so`.
	if err := writeR2Export(opts.OutDir, ranges, pl, codeVA, codeOff); err != nil {
		opts.logf("  r2 export: %v\n", err)
	}

	// Step 8: Function fingerprint dictionary — Item 13.
	// Writes function_fingerprints.jsonl with SHA-256 hashes of each
	// function's instruction bytes, for cross-sample name transfer.
	if err := writeFunctionFingerprints(opts.OutDir, ranges, pl, code, codeOff, codeVA); err != nil {
		opts.logf("  fingerprints: %v\n", err)
	}

	// Step 9: Unified Evidence collection & export.
	//
	// Three of the collector's four sources were never called. Only
	// FromCallEdges ran, so evidence.jsonl held nothing but Kind "call" --
	// and the BLR resolutions it did carry had been through a round trip
	// via call_edges.jsonl, losing the confidence and slot index the type
	// analysis produced.
	evCollector := evidence.NewCollector()
	if len(edges) > 0 {
		evCollector.FromCallEdges(edges)
	}
	if tiOut != nil && tiOut.Inter != nil {
		// Sorted, because ranging a map here would reorder records that
		// tie on (PC, Kind) between runs of the same binary.
		names := make([]string, 0, len(tiOut.Inter.Functions))
		for name := range tiOut.Inter.Functions {
			names = append(names, name)
		}
		sort.Strings(names)
		className := func(id int) string { return tiOut.ClassIDToName[id] }
		for _, name := range names {
			fa := tiOut.Inter.Functions[name]
			if fa == nil {
				continue
			}
			evCollector.FromBLRResolutions(name, fa.Intra.BLRResolutions)
			evCollector.FromFieldAccesses(name, fa.Intra.FieldAccesses, className)
		}
	}
	if len(signalFindings) > 0 {
		evCollector.FromSignalFindings(signalFindings)
	}
	if err := evCollector.WriteJSONL(filepath.Join(opts.OutDir, "evidence.jsonl")); err != nil {
		opts.logf("  evidence: %v\n", err)
	}

	// Step 10: Platform channels endpoint extraction.
	// Scans for Flutter MethodChannel, BasicMessageChannel, and EventChannel endpoints.
	channels := BuildPlatformChannels(clResult, pl, edges)
	if len(channels) > 0 {
		if _, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "platform_channels.jsonl"), channels); err != nil {
			opts.logf("  platform channels: %v\n", err)
		}
	}

	// VM natives the snapshot can reach. Read from the pool rather than
	// from string_refs: nothing in generated code loads these names, so
	// the reference path never sees them.
	if caps := BuildNativeCapabilities(clResult, sc.VMResult); len(caps) > 0 {
		if _, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "native_capabilities.jsonl"), caps); err != nil {
			opts.logf("  native capabilities: %v\n", err)
		}
	}

	// Step 11: Semantic topology de-obfuscation map.
	// Infers class roles for obfuscated binaries based on superclass hierarchy and string accesses.
	deobfMap := BuildDeobfuscationMap(clResult, pl, stringRefs)
	if len(deobfMap) > 0 {
		if _, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "deobfuscate_map.jsonl"), deobfMap); err != nil {
			opts.logf("  deobfuscate: %v\n", err)
		}
	}

	// Step 12: Dart pseudocode. Off by default because it roughly triples
	// the output directory; announced when off so it is discoverable.
	if opts.Decompile {
		count, err := RunDecompileStage(&opts)
		if err != nil {
			return nil, fmt.Errorf("decompile: %w", err)
		}
		result.DecompiledCount = count
	} else {
		opts.logf("  %sdecompile:%s skipped -- pass --decompile to write per-function Dart pseudocode to %s/dart/\n",
			cli.Muted, cli.Reset, opts.OutDir)
	}

	return result, nil
}

// writeCapturedJSONL writes all captured-data JSONL files from the fill-phase
// capture layer. Each file is written only if the corresponding data slice is
// non-empty. Errors are logged but non-fatal (captured data is supplementary).
func writeCapturedJSONL(opts *Opts, clResult *cluster.Result, pl *naming.PoolLookups, layouts []DartClassLayout, log io.Writer) {
	// Build all records first, then write each non-empty slice.
	scripts := BuildScripts(clResult, pl)
	loadingUnits := BuildLoadingUnits(clResult)
	kpis := BuildKPI(clResult)
	instances := BuildInstances(clResult, layouts)
	contexts := BuildContexts(clResult)
	typeArgs := BuildTypeArguments(clResult)
	excHandlers := BuildExceptionHandlers(clResult)
	icdata := BuildICData(clResult)
	closureData := BuildClosureData(clResult)
	libFuncs := BuildLibraryFunctions(clResult, pl)
	ffiBridges := BuildFfiBridges(clResult, pl)

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

	// Write each non-empty slice via the generic WriteJSONLFile.
	type entry struct {
		filename string
		label    string
		count    int
		err      error
	}
	var entries []entry

	if len(scripts) > 0 {
		n, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "scripts.jsonl"), scripts)
		entries = append(entries, entry{"scripts.jsonl", "scripts", n, err})
	}
	if len(loadingUnits) > 0 {
		n, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "loading_units.jsonl"), loadingUnits)
		entries = append(entries, entry{"loading_units.jsonl", "loading_units", n, err})
	}
	if len(kpis) > 0 {
		n, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "kpi.jsonl"), kpis)
		entries = append(entries, entry{"kpi.jsonl", "kpi", n, err})
	}
	if len(instances) > 0 {
		n, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "instances.jsonl"), instances)
		entries = append(entries, entry{"instances.jsonl", "instances", n, err})
	}
	if len(contexts) > 0 {
		n, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "contexts.jsonl"), contexts)
		entries = append(entries, entry{"contexts.jsonl", "contexts", n, err})
	}
	if len(typeArgs) > 0 {
		n, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "type_arguments.jsonl"), typeArgs)
		entries = append(entries, entry{"type_arguments.jsonl", "type_arguments", n, err})
	}
	if len(excHandlers) > 0 {
		n, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "exception_handlers.jsonl"), excHandlers)
		entries = append(entries, entry{"exception_handlers.jsonl", "exception_handlers", n, err})
	}
	if len(icdata) > 0 {
		n, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "icdata.jsonl"), icdata)
		entries = append(entries, entry{"icdata.jsonl", "icdata", n, err})
	}
	if len(closureData) > 0 {
		n, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "closure_data.jsonl"), closureData)
		entries = append(entries, entry{"closure_data.jsonl", "closure_data", n, err})
	}
	// Consumer for the Script/Library capture: gap §6 "No library ->
	// functions xref".
	if len(libFuncs) > 0 {
		n, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "library_functions.jsonl"), libFuncs)
		entries = append(entries, entry{"library_functions.jsonl", "library_functions", n, err})
	}
	if len(ffiBridges) > 0 {
		n, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "ffi_bridges.jsonl"), ffiBridges)
		entries = append(entries, entry{"ffi_bridges.jsonl", "ffi_bridges", n, err})
	}

	for _, e := range entries {
		if e.err != nil {
			if !opts.Quiet {
				_, _ = fmt.Fprintf(log, "  %swarning:%s write %s: %v\n", cli.Muted, cli.Reset, e.filename, e.err)
			}
			continue
		}
		if !opts.Quiet {
			_, _ = fmt.Fprintf(log, "  %s%s:%s %d entries\n", cli.Muted, e.label, cli.Reset, e.count)
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
	funcs, err := jsonutil.ReadJSONL[disasm.FuncRecord](filepath.Join(opts.FromDir, "functions.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("read functions.jsonl: %w", err)
	}
	result.FuncCount = len(funcs)

	if opts.Signal {
		// true: --from-dir has no type-inference stage to fold in, so the
		// signal stage's own evidence.jsonl is the only one there will be.
		sigResult, err := RunSignalStage(opts.FromDir, opts.SignalK, false, opts.Quiet, opts.log(), true, opts.LibPath)
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
