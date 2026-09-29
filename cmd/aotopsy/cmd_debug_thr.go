package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/output"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/thraudit"
)

// cmdTHRAudit implements "aotopsy _debug thr-audit" for auditing THR-relative memory accesses.
func cmdTHRAudit(args []string) error {
	fs := flag.NewFlagSet("thr-audit", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so")
	outPath := fs.String("out", "", "output JSONL path")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")
	limit := fs.Int("limit", 0, "max functions to scan (0 = all)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *libapp == "" || *outPath == "" {
		return fmt.Errorf("--lib and --out are required")
	}

	opts := dartfmt.Options{
		Mode:     dartfmt.ModeBestEffort,
		MaxSteps: *maxSteps,
	}

	ef, info, result, err := analysis.LoadSnapshotIsolate(*libapp, opts)
	if err != nil {
		return err
	}
	defer func() { _ = ef.Close() }()

	data := info.IsolateData.Data

	var ranges []cluster.CodeRange
	table, err := cluster.ParseInstructionsTable(data, &result.Header, info.Version, info.IsolateHeader)
	if err != nil && result.Header.InstructionTableDataOffset == 0 && info.Version.CodeTextOffsetDelta {
		ranges = cluster.ResolveCodeRangesFromTextOffset(result.Codes)
	} else if err != nil {
		return fmt.Errorf("instrtable: %w", err)
	} else {
		codeRanges, err := cluster.ResolveCodeRanges(result.Codes, table)
		if err != nil {
			return fmt.Errorf("code ranges: %w", err)
		}
		stubRanges := cluster.ResolveStubRanges(table)
		ranges = cluster.MergeRanges(stubRanges, codeRanges)
	}

	code, codeOff, payloadLen, err := snapshot.CodeRegion(info.IsolateInstructions.Data, info.Version)
	if err != nil {
		return fmt.Errorf("code region: %w", err)
	}
	codeEndOffset, err := analysis.CheckedCodeEndOffset(codeOff, payloadLen)
	if err != nil {
		return err
	}
	cluster.SetLastRangeSize(ranges, codeEndOffset)

	codeVA := info.IsolateInstructions.VA + codeOff

	return analysis.RunTHRAudit(analysis.THRAuditData{
		Info:    info,
		IsARM64: ef.IsARM64(),
		Result:  result,
		Table:   table,
		Ranges:  ranges,
		Code:    code,
		CodeOff: codeOff,
		CodeVA:  codeVA,
	}, *libapp, *outPath, *limit)
}

// cmdTHRClassify implements "aotopsy _debug thr-classify" for classifying unresolved THR offsets.
func cmdTHRClassify(args []string) error {
	fs := flag.NewFlagSet("thr-classify", flag.ExitOnError)
	inputPath := fs.String("in", "", "input thr_loads.jsonl path")
	outDir := fs.String("out", "", "output directory")
	maxGap := fs.Int("max-gap", 0x18, "max gap between offsets before splitting bands")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inputPath == "" || *outDir == "" {
		return fmt.Errorf("--in and --out are required")
	}

	records, err := thraudit.ReadAuditRecords(*inputPath, jsonutil.StandardLimits)
	if err != nil {
		return fmt.Errorf("read records: %w", err)
	}

	bands, err := thraudit.ClusterBands(records, *maxGap)
	if err != nil {
		return fmt.Errorf("cluster records: %w", err)
	}
	classified, err := thraudit.ClassifyRecords(records, bands)
	if err != nil {
		return fmt.Errorf("classify records: %w", err)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	classPath := filepath.Join(*outDir, "classified.jsonl")
	if _, err := jsonutil.WriteJSONLFile(classPath, classified); err != nil {
		return fmt.Errorf("write classified: %w", err)
	}

	summary := thraudit.Summarize(classified)
	fmt.Fprintf(os.Stderr, "%s (Dart %s): %d unresolved\n",
		summary.Sample, summary.DartVersion, summary.Total)

	classes := []thraudit.THRClass{
		thraudit.ClassRuntimeEntrypoint,
		thraudit.ClassObjectStoreCache,
		thraudit.ClassIsolateGroupPtr,
		thraudit.ClassUnknown,
	}
	for _, cls := range classes {
		count := summary.Counts[cls]
		pct := 0.0
		if summary.Total > 0 {
			pct = float64(count) / float64(summary.Total) * 100
		}
		fmt.Fprintf(os.Stderr, "  %-30s %4d (%5.1f%%)\n", cls, count, pct)
	}

	fmt.Fprintf(os.Stderr, "wrote %s\n", classPath)
	return nil
}

// cmdTHRCluster implements "aotopsy _debug thr-cluster" for clustering unresolved THR offsets into bands.
func cmdTHRCluster(args []string) error {
	fs := flag.NewFlagSet("thr-cluster", flag.ExitOnError)
	inputPath := fs.String("in", "", "input thr_loads.jsonl path")
	outDir := fs.String("out", "", "output directory for bands.json and bands.md")
	maxGap := fs.Int("max-gap", 0x18, "max gap between offsets before splitting bands")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inputPath == "" || *outDir == "" {
		return fmt.Errorf("--in and --out are required")
	}

	records, err := thraudit.ReadAuditRecords(*inputPath, jsonutil.StandardLimits)
	if err != nil {
		return fmt.Errorf("read records: %w", err)
	}

	br, err := thraudit.ClusterBands(records, *maxGap)
	if err != nil {
		return fmt.Errorf("cluster records: %w", err)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	jsonPath := filepath.Join(*outDir, "bands.json")
	if err := output.WriteJSONFile(jsonPath, br); err != nil {
		return fmt.Errorf("write json: %w", err)
	}

	mdPath := filepath.Join(*outDir, "bands.md")
	if err := output.WriteAtomic(mdPath, 0o644, func(w io.Writer) error {
		return thraudit.WriteBandsMD(w, br)
	}); err != nil {
		return fmt.Errorf("write markdown: %w", err)
	}

	fmt.Fprintf(os.Stderr, "%s: %d bands from %d unresolved accesses\n",
		br.Sample, len(br.Bands), br.TotalUnresolved)
	fmt.Fprintf(os.Stderr, "wrote %s\n", jsonPath)
	fmt.Fprintf(os.Stderr, "wrote %s\n", mdPath)

	return nil
}
