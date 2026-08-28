package main

import (
	"flag"
	"fmt"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/pipeline"
	"aotopsy/internal/snapshot"
)

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

	ef, info, result, err := pipeline.LoadSnapshotIsolate(*libapp, opts)
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

	code, codeOff, payloadLen, err := snapshot.CodeRegion(info.IsolateInstructions.Data)
	if err != nil {
		return fmt.Errorf("code region: %w", err)
	}
	codeEndOffset := uint32(codeOff) + uint32(payloadLen)
	cluster.SetLastRangeSize(ranges, codeEndOffset)

	codeVA := info.IsolateInstructions.VA + codeOff

	return analysis.RunTHRAudit(analysis.THRAuditData{
		Info:    info,
		IsARM64: ef.IsARM64(),
		Result:  result,
		Ranges:  ranges,
		Code:    code,
		CodeOff: codeOff,
		CodeVA:  codeVA,
	}, *libapp, *outPath, *limit)
}
