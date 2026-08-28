package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/disasm"
	"aotopsy/internal/naming"
	"aotopsy/internal/pipeline"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/thraudit"
	"aotopsy/internal/vmtables"
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
	isARM64 := ef.IsARM64()

	dartVersion := ""
	if info.Version != nil {
		dartVersion = info.Version.DartVersion
	}
	fmt.Fprintf(os.Stderr, "Dart SDK version: %s\n", dartVersion)

	data := info.IsolateData.Data

	// Parse instructions table (or use text-offset fallback for pre-v2.16).
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

	// Build name lookup.
	refToStr := make(map[int]string)
	for _, ps := range result.Strings {
		refToStr[ps.RefID] = ps.Value
	}

	refToNamed := make(map[int]*cluster.NamedObject)
	for i := range result.Named {
		no := &result.Named[i]
		refToNamed[no.RefID] = no
	}

	resolveName := func(no *cluster.NamedObject) string {
		if no.NameRefID >= 0 {
			if s, ok := refToStr[no.NameRefID]; ok {
				return s
			}
		}
		return ""
	}

	resolveOwnerName := func(no *cluster.NamedObject) string {
		if no.OwnerRefID < 0 {
			return ""
		}
		if owner, ok := refToNamed[no.OwnerRefID]; ok {
			return resolveName(owner)
		}
		return ""
	}

	// pipeline.CodeNameInfo rather than a local struct, so the
	// constructor rule ("the Function name already carries the class, do
	// not prepend the owner") is applied by CodeNameInfo.Qualified and
	// lives in exactly one place. A local copy of that branch was what
	// this file had, twice.
	// Resolved via pipeline.ResolveCodeOwner rather than trusting
	// ce.OwnerRef directly -- Code.OwnerRef is confirmed unreliable on
	// some real snapshots (Dart 3.7.0 x86_64: ~5.4% of functions get a
	// bogus shared owner resolving to CID 61/Mint), which would show up
	// here as an unnamed/misattributed function in the audit report.
	byCodeIndex := naming.CodeIndexToFunc(result, info.Version.CIDs, info.Version.CodeIndexOneBased)
	codeNames := make(map[int]naming.CodeNameInfo)
	for _, ce := range result.Codes {
		owner, ok := naming.ResolveCodeOwner(ce, refToNamed, byCodeIndex)
		if !ok {
			continue
		}
		fn := resolveName(owner)
		isCtor := owner.IsConstructor()
		if isCtor && fn != "" {
			fn = "new " + fn
		}
		codeNames[ce.RefID] = naming.CodeNameInfo{
			FuncName:      fn,
			OwnerName:     resolveOwnerName(owner),
			IsConstructor: isCtor,
		}
	}

	// Build symbol map.
	symbols := make(map[uint64]string)
	for _, r := range ranges {
		va := codeVA + uint64(r.PCOffset) - codeOff
		symbols[va] = codeNames[r.RefID].Qualified(r.PCOffset)
	}
	lookup := disasm.PlaceholderLookup(symbols)

	thrFields := vmtables.THRFields(dartVersion, isARM64)

	// Open output.
	outFile, err := os.Create(*outPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer func() { _ = outFile.Close() }()
	enc := json.NewEncoder(outFile)
	enc.SetEscapeHTML(false)

	// Derive sample name from libapp path.
	sample := *libapp

	n := len(ranges)
	if *limit > 0 && *limit < n {
		n = *limit
	}

	var totalAccesses, resolvedCount, unresolvedCount int

	for i := 0; i < n; i++ {
		r := &ranges[i]
		if r.Size == 0 {
			continue
		}

		funcStart := uint64(r.PCOffset) - codeOff
		funcEnd := funcStart + uint64(r.Size)
		if funcEnd > uint64(len(code)) {
			funcEnd = uint64(len(code))
		}
		if funcStart >= funcEnd {
			continue
		}
		funcCode := code[funcStart:funcEnd]
		funcVA := codeVA + funcStart

		funcName := codeNames[r.RefID].Qualified(r.PCOffset)

		var records []thraudit.THRAuditRecord
		if isARM64 {
			insts := disasm.Disassemble(funcCode, disasm.Options{
				BaseAddr: funcVA,
				Symbols:  lookup,
			})
			accesses := disasm.ExtractTHRAccesses(insts, thrFields)
			if len(accesses) == 0 {
				continue
			}
			records = disasm.BuildAuditRecords(accesses, insts, sample, dartVersion, funcName)
		} else {
			accesses := disasm.ExtractX86THRAccesses(funcCode, funcVA, thrFields)
			if len(accesses) == 0 {
				continue
			}
			insts := disasm.DecodeX86Simple(funcCode, funcVA)
			records = disasm.BuildX86AuditRecords(accesses, insts, sample, dartVersion, funcName)
		}
		for _, rec := range records {
			if err := enc.Encode(rec); err != nil {
				return fmt.Errorf("write record: %w", err)
			}
			totalAccesses++
			if rec.Resolved {
				resolvedCount++
			} else {
				unresolvedCount++
			}
		}
	}

	fmt.Fprintf(os.Stderr, "THR accesses: %d total, %d resolved, %d unresolved\n",
		totalAccesses, resolvedCount, unresolvedCount)
	fmt.Fprintf(os.Stderr, "wrote %s\n", *outPath)

	return nil
}
