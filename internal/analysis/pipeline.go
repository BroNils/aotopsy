// Package analysis orchestrates aotopsy's ARM64 disassembly/call-graph/
// signal/Ghidra-IDA-metadata pipeline (Run) and its x86_64 counterpart's
// narrower disassembly/call-edge/signal stage (RunDisasmStageX86, in
// disasm_stagex86.go). The shared name-resolution/pool-lookup surface
// (PoolLookups, BuildPoolLookups, etc.) lives in internal/naming, which
// analysis imports and which cmd/aotopsy files read from directly.
package analysis

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
	LibPath     string // path to libapp.so
	OutDir      string // output directory
	FromDir     string // reuse existing disasm output (skip ELF/disasm)
	Strict      bool
	MaxSteps    int
	Limit       int       // max functions (0=all)
	Graph       bool      // build callgraph DOTs
	Signal      bool      // run signal analysis
	SignalK     int       // signal context hops (default 2)
	SignalNoAsm bool      // skip asm/bin reads while regenerating signal output
	Meta        MetaMode  // whether flutter_meta.json is disabled, optional, or required
	DecompAll   bool      // all functions vs signal-only in focus list
	Decompile   bool      // emit per-function Dart pseudocode into <out>/dart/
	Quiet       bool      // suppress verbose output (verbose is default)
	Log         io.Writer // stderr by default
}

// MetaMode controls generation of flutter_meta.json. The artifact is currently
// ARM64-specific because the downstream Ghidra/IDA integration encodes the
// ARM64 Dart calling convention and register roles. A generic analysis may ask
// for it opportunistically, while the explicit `meta`/Ghidra/IDA commands must
// fail rather than report success without the requested artifact.
type MetaMode uint8

const (
	MetaDisabled MetaMode = iota
	MetaIfSupported
	MetaRequired
)

func collectExtendedSARIF(outDir string, crypto []signal.CryptoFinding) ([]output.SignalFinding, error) {
	var out []output.SignalFinding

	entropy, err := readOptionalJSONL[signal.EntropyFinding](filepath.Join(outDir, "entropy_findings.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("read entropy findings for SARIF: %w", err)
	}
	for _, f := range entropy {
		out = append(out, output.SignalFinding{
			Category:    "entropy",
			StringValue: fmt.Sprintf("%s section %s: entropy %.3f, size %d", f.Verdict, f.Section, f.Entropy, f.Size),
		})
	}

	for _, f := range crypto {
		out = append(out, output.SignalFinding{
			Category:    signal.CatCryptoConst,
			StringValue: fmt.Sprintf("%s (%s, pool=%d)", f.Algorithm, f.Constant, f.PoolIndex),
		})
	}

	taint, err := readOptionalJSONL[signal.TaintFinding](filepath.Join(outDir, "taint_findings.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("read taint findings for SARIF: %w", err)
	}
	for _, f := range taint {
		fn := f.SourceFn
		if fn == "" {
			fn = f.SinkFn
		}
		out = append(out, output.SignalFinding{
			Category:    "taint",
			StringValue: fmt.Sprintf("%s -> %s (%s, confidence=%s)", f.Source, f.Sink, f.FlowType, f.Confidence),
			Function:    fn,
		})
	}

	yara, err := readOptionalJSONL[signal.YaraFinding](filepath.Join(outDir, "yara_findings.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("read YARA findings for SARIF: %w", err)
	}
	for _, f := range yara {
		fn := ""
		if len(f.Functions) > 0 {
			fn = f.Functions[0]
		}
		out = append(out, output.SignalFinding{
			Category:    "yara",
			StringValue: fmt.Sprintf("%s/%s matched %s", f.RuleName, f.Category, strings.Join(f.Strings, ", ")),
			Function:    fn,
		})
	}

	behavioral, err := readOptionalJSONL[signal.BehavioralFinding](filepath.Join(outDir, "behavioral_findings.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("read behavioral findings for SARIF: %w", err)
	}
	for _, f := range behavioral {
		fn := ""
		if len(f.Functions) > 0 {
			fn = f.Functions[0]
		}
		out = append(out, output.SignalFinding{
			Category:    "behavioral",
			StringValue: fmt.Sprintf("%s/%s: %d edges, confidence=%s", f.Pattern, f.Category, f.EdgeCount, f.Confidence),
			Function:    fn,
		})
	}
	return out, nil
}

func readOptionalJSONL[T any](path string) ([]T, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return jsonutil.ReadJSONL[T](path, jsonutil.StandardLimits)
}

// Result holds pipeline summary information.
type Result struct {
	OutDir      string
	LibPath     string // absolute
	Arch        string // "arm64" or "x64" when known
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
	cli.NewLogger(o.log(), o.Quiet).Printf(format, args...)
}

func (o *Opts) stagef(name string, format string, args ...interface{}) {
	cli.NewLogger(o.log(), o.Quiet).Stage(name, format, args...)
}

func (o *Opts) warnf(format string, args ...interface{}) {
	cli.NewLogger(o.log(), o.Quiet).Warn(format, args...)
}

const maxReportedPipelineDiagnostics = 8

func (o *Opts) reportDiagnostics(result *Result, source string, diags []dartfmt.Diag) {
	if len(diags) == 0 {
		return
	}
	limit := len(diags)
	if limit > maxReportedPipelineDiagnostics {
		limit = maxReportedPipelineDiagnostics
	}
	for _, d := range diags[:limit] {
		msg := fmt.Sprintf("%s diagnostic: %s", source, d.String())
		result.Diags = append(result.Diags, msg)
		o.warnf("%s", msg)
	}
	if omitted := len(diags) - limit; omitted > 0 {
		msg := fmt.Sprintf("%s diagnostics: %d additional issue(s) suppressed", source, omitted)
		result.Diags = append(result.Diags, msg)
		o.warnf("%s", msg)
	}
}

// Run executes the full analysis pipeline. A fresh binary analysis is written
// into a sibling staging directory and published only after every requested
// stage succeeds, so a failed rerun cannot corrupt an existing generation.
func Run(opts Opts) (*Result, error) {
	if opts.FromDir != "" {
		return runFromExistingTransactional(opts)
	}
	if opts.OutDir == "" {
		return runPipeline(opts)
	}
	if opts.LibPath != "" {
		contains, err := output.ContainsPath(opts.OutDir, opts.LibPath)
		if err != nil {
			return nil, fmt.Errorf("compare output/source paths: %w", err)
		}
		if contains {
			return nil, fmt.Errorf("output directory must not contain the source binary: %s contains %s", opts.OutDir, opts.LibPath)
		}
	}

	finalOut := opts.OutDir
	tx, err := output.BeginDirTransaction(finalOut)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			tx.Abort()
		}
	}()

	staged := opts
	staged.OutDir = tx.StageDir()
	result, err := runPipeline(staged)
	if err != nil {
		return nil, err
	}
	stageDir := tx.StageDir()
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	committed = true
	result.OutDir = finalOut
	result.MetaPath = output.RebasePath(result.MetaPath, stageDir, finalOut)
	return result, nil
}

func runFromExistingTransactional(opts Opts) (*Result, error) {
	finalOut := opts.OutDir
	if finalOut == "" {
		finalOut = opts.FromDir
	}
	fromAbs, err := filepath.Abs(opts.FromDir)
	if err != nil {
		return nil, fmt.Errorf("resolve --from: %w", err)
	}
	finalAbs, err := filepath.Abs(finalOut)
	if err != nil {
		return nil, fmt.Errorf("resolve --out: %w", err)
	}
	if fromAbs != finalAbs {
		overlap, err := output.PathsOverlap(fromAbs, finalAbs)
		if err != nil {
			return nil, fmt.Errorf("compare --from/--out paths: %w", err)
		}
		if overlap {
			return nil, fmt.Errorf("--from and --out must not contain one another: %s vs %s", fromAbs, finalAbs)
		}
	}

	tx, err := output.BeginDirTransaction(finalAbs)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			tx.Abort()
		}
	}()
	if err := output.CloneTree(fromAbs, tx.StageDir()); err != nil {
		return nil, fmt.Errorf("clone --from: %w", err)
	}

	stageDir := tx.StageDir()
	staged := opts
	staged.FromDir = stageDir
	staged.OutDir = stageDir
	result, err := runPipeline(staged)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	committed = true
	result.OutDir = finalOut
	result.MetaPath = output.RebasePath(result.MetaPath, stageDir, finalOut)
	return result, nil
}

func runPipeline(opts Opts) (*Result, error) {
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
	if err := sc.RequireCompleteVM(); err != nil {
		return nil, err
	}

	ef := sc.EF
	info := sc.Info
	clResult := sc.Result
	opts.reportDiagnostics(result, "snapshot", info.Diags)
	opts.reportDiagnostics(result, "isolate cluster", clResult.Diags)
	if sc.VMResult != nil {
		opts.reportDiagnostics(result, "VM cluster", sc.VMResult.Diags)
	}
	table := sc.Table
	ranges := sc.Ranges
	// --limit is a population boundary for every per-function semantic stage,
	// not merely for functions.jsonl.  Keeping the full range set in typetrack,
	// fingerprints, evidence, or r2 while disassembly emitted only the first N
	// functions produces a directory whose artifacts disagree about what was
	// analysed.  Global snapshot metadata (classes, dispatch table, pool, etc.)
	// remains complete; only function-scoped work uses analysisRanges.
	analysisRanges := ranges
	if opts.Limit > 0 && opts.Limit < len(analysisRanges) {
		analysisRanges = analysisRanges[:opts.Limit]
	}
	code := sc.Code
	codeOff := sc.CodeOff
	codeVA := sc.CodeVA
	payloadLen := uint64(len(code))
	isARM64 := sc.IsARM64
	arch := "x64"
	if isARM64 {
		arch = "arm64"
	}
	result.Arch = arch
	rawFuncSyms, symErr := ef.FuncSymbols()
	if symErr != nil {
		return nil, fmt.Errorf("ELF function symbols: %w", symErr)
	}
	elfFuncSyms := prepareFuncSymbols(rawFuncSyms, ranges, codeVA, codeOff)
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
	var provenance Provenance
	{
		dv, compressed := "", false
		if info.Version != nil {
			dv, compressed = info.Version.DartVersion, info.Version.CompressedPointers
		}
		discarded := 0
		if table != nil {
			discarded = int(table.FirstEntryWithCode)
		}
		build := DetectBuildMode(len(clResult.CodeSourceMaps), discarded, len(ranges))
		var err error
		provenance, err = WriteProvenance(opts.OutDir, opts.LibPath, ef, dv, isARM64, compressed, build)
		if err != nil {
			return nil, fmt.Errorf("write provenance: %w", err)
		}
		if build.DwarfStackTraces {
			// Say it out loud. Without this line, "0 code source maps" and
			// "most functions named stub_<hex>" look like the analyser
			// failing, when they are what the binary was built to be.
			//
			// This describes how the binary was built, it is not a degradation of
			// the analysis, so it is an ordinary (quiet-able) log line and not a
			// Warn: warnings are always shown and must stay reserved for lost output.
			opts.logf("  %sbuild:%s dwarf stack traces (--split-debug-info/--obfuscate): "+
				"%d code source maps, %d discarded Code objects -- inline attribution unavailable\n",
				cli.Gold, cli.Reset, build.CodeSourceMaps, build.DiscardedCodes)
		}
	}

	// Build and write class layouts.
	classLayouts := BuildClassLayouts(clResult, pl, info.Version.CompressedPointers)
	if len(classLayouts) > 0 {
		classesPath := filepath.Join(opts.OutDir, "classes.jsonl")
		if _, err := jsonutil.WriteJSONLFile(classesPath, classLayouts); err != nil {
			return nil, fmt.Errorf("write classes.jsonl: %w", err)
		}
		opts.logf("  %sclasses:%s %d layouts\n", cli.Muted, cli.Reset, len(classLayouts))
	}
	result.ClassCount = len(classLayouts)

	// Write captured-data JSONL files (scripts, loading_units, instances,
	// contexts, type_arguments, exception_handlers, icdata).
	// These are produced from the fill-phase capture layer and provide
	// structured access to snapshot objects that were previously discarded.
	//
	// Note: ICData and Context do not appear in AOT snapshots, so their files
	// are never written.
	//
	// The reason is NOT "their serialization cluster is behind
	// #if !defined(DART_PRECOMPILED_RUNTIME)" -- an earlier version of this
	// comment claimed that, and it is wrong. Checked against
	// runtime/vm/app_snapshot.cc @ 3.9.2: Serializer::NewClusterForClass has
	// no such guard for kICDataCid or kContextCid (the serializer as a whole
	// only exists in non-AOT-runtime builds, but gen_snapshot is exactly such a
	// build and it is what writes AOT snapshots).
	//
	// The real reasons:
	// - ICData: a JIT inline cache. The precompiler does not retain
	//   ic_data_array_, so nothing ever reaches the serializer.
	// - Context: allocated on the heap when a closure runs, not ahead of time.
	//
	// KernelProgramInfo is not captured at all: the kernel binary is not needed
	// at runtime in AOT ("KernelProgramInfo objects are not written into a full
	// AOT snapshot" -- SDK comment above the deserialization cluster), so a
	// cluster under its CID is malformed and fails closed in the cluster
	// package (notSerializedInFullAOT).
	//
	// Confirmed empirically: 0 ICData/Context entries across 16 corpus samples
	// (Dart 2.12.0 / 3.7.0 / 3.9.2 / 3.10.7 / 3.11.0 / 3.12.2, arm64 + x64).
	if err := writeCapturedJSONL(&opts, clResult, pl, classLayouts, table); err != nil {
		return nil, err
	}

	// Write pool_immediates.jsonl for crypto constant identification.
	poolImmPath := filepath.Join(opts.OutDir, "pool_immediates.jsonl")
	type poolImmediateRecord struct {
		Index int    `json:"index"`
		Value int64  `json:"value"`
		Hex   string `json:"hex"`
	}
	poolImmediates := make([]poolImmediateRecord, 0)
	for _, pe := range clResult.Pool {
		if pe.Kind == cluster.PoolImmediate {
			poolImmediates = append(poolImmediates, poolImmediateRecord{
				Index: pe.Index,
				Value: pe.Imm,
				Hex:   fmt.Sprintf("0x%x", uint64(pe.Imm)),
			})
		}
	}
	if _, err := jsonutil.WriteJSONLFile(poolImmPath, poolImmediates); err != nil {
		return nil, fmt.Errorf("write pool_immediates.jsonl: %w", err)
	}

	// Write dart_meta.json.
	targetProfile, ok := vmtables.TargetProfileFromVersion(info.Version, isARM64)
	if !ok {
		return nil, fmt.Errorf("select VM target profile: missing snapshot version profile")
	}
	thrFields := vmtables.THRFields(targetProfile)
	ptrSize := 8
	if info.Version.CompressedPointers {
		ptrSize = 4
	}
	result.PointerSize = ptrSize
	targetArch := "x64"
	if isARM64 {
		targetArch = "arm64"
	}
	if err := strutil.WriteDartMeta(opts.OutDir, info.Version.DartVersion, targetArch, info.Version.CompressedPointers, ptrSize, thrFields); err != nil {
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
	// A failed type inference stage would make all downstream xrefs/evidence a
	// mixture of complete disassembly and silently degraded call semantics.
	// Fail the staged generation instead of publishing that partial result.
	// Runs BEFORE xref so that dispatch_table.jsonl is available for
	// selector_dispatch_xref.jsonl generation.
	tiOut, err := RunTypeInferenceStage(&opts, isARM64, pl, clResult, analysisRanges, code, codeOff, codeVA, info, table, thrFields, sc.VMResult)
	if err != nil {
		return nil, fmt.Errorf("type inference: %w", err)
	}

	// Step 4.6: Cross-referencing JSONL outputs (gap-analysis §6).
	// Reads functions.jsonl, call_edges.jsonl, string_refs.jsonl
	// produced by the disasm stage, and dispatch_table.jsonl produced
	// by the type inference stage.
	funcs, err := jsonutil.ReadJSONL[disasm.FuncRecord](filepath.Join(opts.OutDir, "functions.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		return nil, fmt.Errorf("xref input functions.jsonl: %w", err)
	}
	edges, err := jsonutil.ReadJSONL[disasm.CallEdgeRecord](filepath.Join(opts.OutDir, "call_edges.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		return nil, fmt.Errorf("xref input call_edges.jsonl: %w", err)
	}
	stringRefs, err := jsonutil.ReadJSONL[disasm.StringRefRecord](filepath.Join(opts.OutDir, "string_refs.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		return nil, fmt.Errorf("xref input string_refs.jsonl: %w", err)
	}
	var selectorTargets map[int][]string
	if tiOut != nil {
		selectorTargets = tiOut.SelectorTargets
	}
	if err := writeXrefJSONL(opts.OutDir, clResult, pl, funcs, edges, stringRefs, selectorTargets, info.Version.CompressedPointers); err != nil {
		return nil, fmt.Errorf("xref: %w", err)
	}

	// Step 5: Signal analysis (if enabled) -- reads functions.jsonl/
	// call_edges.jsonl/string_refs.jsonl, which both disasm stages now
	// produce in the same schema, so this works unmodified for x86_64.
	var signalFindings []output.SignalFinding
	if opts.Signal {
		// false: step 9 below writes evidence.jsonl with these findings
		// plus the type-inference resolutions folded in.
		sigResult, err := RunSignalStage(opts.OutDir, opts.OutDir, opts.SignalK, false, opts.Quiet, opts.log(), false)
		if err != nil {
			return nil, fmt.Errorf("signal: %w", err)
		}
		result.SignalCount = sigResult.SignalCount
		signalFindings = sigResult.Findings

		// Every optional detector owns a file whose absence means "no current
		// findings". Remove any prior-run file before running it so a clean rerun
		// cannot retain stale security evidence.
		for _, name := range []string{"entropy_findings.jsonl", "crypto_findings.jsonl", "taint_findings.jsonl", "yara_findings.jsonl", "behavioral_findings.jsonl"} {
			if err := os.Remove(filepath.Join(opts.OutDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("remove stale %s: %w", name, err)
			}
		}

		// Step 5.1: Entropy analysis (packed/encrypted section detection).
		if err := signal.WriteEntropyFindings(opts.OutDir, ef); err != nil {
			return nil, fmt.Errorf("entropy: %w", err)
		}

		// Step 5.1b: Crypto algorithm identification from binary scan.
		// Dart AOT compiles integer constants to MOVZ/MOVK instructions,
		// so crypto constants appear as raw bytes in .text, not as pool
		// immediates. Scan the binary for known crypto constant patterns.
		cryptoFromBinary, err := signal.IdentifyCryptoFromELF(ef)
		if err != nil {
			return nil, fmt.Errorf("crypto binary scan: %w", err)
		}
		cryptoFromPool, err := signal.IdentifyCryptoFromPoolImmediates(opts.OutDir)
		if err != nil {
			return nil, fmt.Errorf("crypto pool scan: %w", err)
		}
		allCrypto := append(cryptoFromBinary, cryptoFromPool...)
		if len(allCrypto) > 0 {
			if err := signal.WriteCryptoFindings(opts.OutDir, allCrypto); err != nil {
				return nil, fmt.Errorf("crypto: %w", err)
			}
		}

		// Step 5.2: Data flow / taint analysis (simplified).
		// Identifies potential source→sink flows based on string patterns.
		if err := signal.WriteTaintFindings(opts.OutDir, stringRefs, edges); err != nil {
			return nil, fmt.Errorf("taint: %w", err)
		}

		// Step 5.3: YARA-style malware matching.
		if err := signal.WriteYaraFindings(opts.OutDir, stringRefs); err != nil {
			return nil, fmt.Errorf("yara: %w", err)
		}

		// Step 5.4: Call-graph behavioral analysis.
		if err := signal.WriteBehavioralFindings(opts.OutDir, funcs, edges); err != nil {
			return nil, fmt.Errorf("behavioral: %w", err)
		}

		extended, err := collectExtendedSARIF(opts.OutDir, allCrypto)
		if err != nil {
			return nil, err
		}
		signalFindings = append(signalFindings, extended...)
		identity := output.ArtifactIdentity{URI: provenance.SourceName, Size: provenance.Size, SHA256: provenance.SHA256}
		if err := output.WriteSARIF(opts.OutDir, signalFindings, cli.Version, identity); err != nil {
			return nil, fmt.Errorf("write final sarif: %w", err)
		}
		opts.logf("  %sSARIF:%s %d findings\n", cli.Muted, cli.Reset, len(signalFindings))
	}

	// Step 6: Flutter-meta generation. The schema is ARM64-specific today;
	// required callers must fail rather than silently publish a generation
	// without the artifact they explicitly requested.
	if err := runMetaForTarget(&opts, result, opts.OutDir, opts.OutDir, targetArch, true); err != nil {
		return nil, err
	}

	// Step 7: R2 export (radare2 command script) — Item 18.
	// Exports recovered function names as r2 flags so analysts can
	// import them via `r2 -i aotopsy.r2 libapp.so`.
	if err := writeR2Export(opts.OutDir, analysisRanges, pl, codeVA, codeOff); err != nil {
		return nil, fmt.Errorf("r2 export: %w", err)
	}

	// Step 8: Unified Evidence collection & export.
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
			evCollector.FromBLRResolutions(name, fa.Intra.BLRResolutions, isARM64)
			evCollector.FromFieldAccesses(name, fa.Intra.FieldAccesses, className)
		}
	}
	if len(signalFindings) > 0 {
		evCollector.FromSignalFindings(signalFindings)
	}
	if err := evCollector.WriteJSONL(filepath.Join(opts.OutDir, "evidence.jsonl")); err != nil {
		return nil, fmt.Errorf("evidence: %w", err)
	}

	// Step 10: Platform channels endpoint extraction.
	// Scans for Flutter MethodChannel, BasicMessageChannel, and EventChannel endpoints.
	channels := BuildPlatformChannels(clResult, pl, edges, stringRefs)
	if len(channels) > 0 {
		if _, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "platform_channels.jsonl"), channels); err != nil {
			return nil, fmt.Errorf("platform channels: %w", err)
		}
	}

	// VM natives the snapshot can reach. Read from the pool rather than
	// from string_refs: nothing in generated code loads these names, so
	// the reference path never sees them.
	if caps := BuildNativeCapabilities(clResult, sc.VMResult); len(caps) > 0 {
		if _, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "native_capabilities.jsonl"), caps); err != nil {
			return nil, fmt.Errorf("native capabilities: %w", err)
		}
	}

	// Step 11: Semantic topology de-obfuscation map.
	// Infers class roles for obfuscated binaries based on superclass hierarchy and string accesses.
	deobfMap := BuildDeobfuscationMap(clResult, pl, stringRefs)
	if len(deobfMap) > 0 {
		if _, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "deobfuscate_map.jsonl"), deobfMap); err != nil {
			return nil, fmt.Errorf("write deobfuscate_map.jsonl: %w", err)
		}
	}

	// Step 12: Dart pseudocode. Off by default because it roughly triples
	// the output directory; announced when off so it is discoverable.
	if opts.Decompile {
		decompileCtx, err := analysisContextFromSnapshot(sc)
		if err != nil {
			return nil, fmt.Errorf("decompile context: %w", err)
		}
		count, err := RunDecompileStage(&opts, decompileCtx)
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

func prepareFuncSymbols(
	syms map[uint64]string,
	ranges []cluster.CodeRange,
	codeVA, codeOff uint64,
) map[uint64]string {
	if len(syms) == 0 {
		return nil
	}
	allowed := make(map[uint64]struct{}, len(ranges))
	for _, r := range ranges {
		pc := uint64(r.PCOffset)
		if pc < codeOff {
			continue
		}
		delta := pc - codeOff
		if delta > ^uint64(0)-codeVA {
			continue
		}
		allowed[codeVA+delta] = struct{}{}
	}
	out := make(map[uint64]string)
	for va, name := range syms {
		if _, ok := allowed[va]; ok {
			out[va] = name
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// writeCapturedJSONL writes all captured-data JSONL files from the fill-phase
// capture layer. Each file is written only if the corresponding data slice is
// non-empty. Any write failure is fatal: a pipeline result is not complete when
// one advertised artifact silently stayed stale or was omitted.
func writeCapturedJSONL(opts *Opts, clResult *cluster.Result, pl *naming.PoolLookups, layouts []DartClassLayout, table *cluster.InstructionsTable) error {
	// Build all records first, then write each non-empty slice.
	scripts := BuildScripts(clResult, pl)
	loadingUnits := BuildLoadingUnits(clResult)
	instances := BuildInstances(clResult, layouts)
	contexts := BuildContexts(clResult)
	typeArgs := BuildTypeArguments(clResult)
	excHandlers := BuildExceptionHandlers(clResult)
	decodedStackMaps, err := DecodeAllStackMaps(clResult, table)
	if err != nil {
		return fmt.Errorf("decode stack maps: %w", err)
	}
	stackMaps := BuildStackMaps(decodedStackMaps)
	icdata := BuildICData(clResult)
	closureData := BuildClosureData(clResult)
	libFuncs := BuildLibraryFunctions(clResult, pl)
	ffiBridges := BuildFfiBridges(clResult, pl)

	// Report the Code/loading-unit partition, and say plainly when it carries
	// no information. A single-unit app (no deferred imports) yields one
	// bucket, and printing "partitioned N codes into 1 unit" would dress that
	// up as a result it is not.
	if part := PartitionCodesByLoadingUnit(clResult); part.UnitCount > 0 {
		if part.Degenerate {
			opts.logf("  %sloading units:%s 1 (root id %d), no deferred imports -- Code partition is trivial\n",
				cli.Muted, cli.Reset, part.RootUnitID)
		} else {
			opts.logf("  %sloading units:%s %d, codes %d root / %d deferred (defined in another unit's blob)\n",
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
	if len(stackMaps) > 0 {
		n, err := jsonutil.WriteJSONLFile(filepath.Join(opts.OutDir, "stack_maps.jsonl"), stackMaps)
		entries = append(entries, entry{"stack_maps.jsonl", "stack_maps", n, err})
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
			return fmt.Errorf("write %s: %w", e.filename, e.err)
		}
		opts.logf("  %s%s:%s %d entries\n", cli.Muted, e.label, cli.Reset, e.count)
	}
	return nil
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
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir --out: %w", err)
	}
	prov, hasProv, err := ReadProvenance(opts.FromDir)
	if err != nil {
		return nil, fmt.Errorf("read --from provenance: %w", err)
	}
	if hasProv {
		if prov.Arch == "arm64" || prov.Arch == "x64" {
			result.Arch = prov.Arch
		}
		result.DartVersion = prov.DartVersion
	}

	// Count existing functions.
	funcs, err := jsonutil.ReadJSONL[disasm.FuncRecord](filepath.Join(opts.FromDir, "functions.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		return nil, fmt.Errorf("read functions.jsonl: %w", err)
	}
	result.FuncCount = len(funcs)

	if opts.Signal {
		// true: --from-dir has no type-inference stage to fold in, so the
		// signal stage's own evidence.jsonl is the only one there will be.
		sigResult, err := RunSignalStage(opts.FromDir, outDir, opts.SignalK, opts.SignalNoAsm, opts.Quiet, opts.log(), true)
		if err != nil {
			return nil, fmt.Errorf("signal: %w", err)
		}
		result.SignalCount = sigResult.SignalCount
	}

	if opts.Meta != MetaDisabled {
		archKnown := hasProv && (prov.Arch == "arm64" || prov.Arch == "x64")
		if err := runMetaForTarget(opts, result, opts.FromDir, outDir, prov.Arch, archKnown); err != nil {
			return nil, err
		}
	}

	return result, nil
}

func runMetaForTarget(opts *Opts, result *Result, inDir, outDir, arch string, archKnown bool) error {
	if opts.Meta == MetaDisabled {
		return nil
	}
	unsupportedReason := ""
	switch {
	case !archKnown:
		unsupportedReason = "analysis provenance does not identify an arm64/x64 architecture"
	case arch != "arm64":
		unsupportedReason = fmt.Sprintf("architecture %s is not supported", arch)
	}
	if unsupportedReason != "" {
		if opts.Meta == MetaRequired {
			return fmt.Errorf("meta: flutter_meta.json is ARM64-only: %s", unsupportedReason)
		}
		// --from clones a previous generation before rerunning stages. If this
		// target cannot safely regenerate ARM64-only metadata, do not retain a
		// stale flutter_meta.json from that cloned generation.
		if err := os.Remove(filepath.Join(outDir, "flutter_meta.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale flutter_meta.json: %w", err)
		}
		opts.warnf("flutter_meta.json generation skipped: %s", unsupportedReason)
		return nil
	}

	metaPath, err := RunMetaStage(inDir, outDir, arch, opts.DecompAll, opts.Quiet, opts.log())
	if err != nil {
		return fmt.Errorf("meta: %w", err)
	}
	result.MetaPath = metaPath
	return nil
}
