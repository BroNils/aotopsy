package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/disasm"
	"aotopsy/internal/elfx"
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

	ef, err := elfx.Open(*libapp)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = ef.Close() }()
	isARM64 := ef.IsARM64()

	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}

	dartVersion := ""
	if info.Version != nil {
		dartVersion = info.Version.DartVersion
	}
	fmt.Fprintf(os.Stderr, "Dart SDK version: %s\n", dartVersion)
	if info.Version != nil && !info.Version.Supported {
		return fmt.Errorf("HALT_UNSUPPORTED_VERSION: Dart %s (hash %s)", info.Version.DartVersion, info.VmHeader.SnapshotHash)
	}

	// Parse isolate snapshot clusters + fill.
	data := info.IsolateData.Data
	if len(data) < 64 {
		return fmt.Errorf("isolate data too short (%d bytes)", len(data))
	}

	clusterStart, err := cluster.FindClusterDataStart(data)
	if err != nil {
		return fmt.Errorf("cluster start: %w", err)
	}

	result, err := cluster.ScanClusters(data, clusterStart, info.Version, false, opts)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	if err := cluster.ReadFill(data, result, info.Version, false, info.IsolateHeader.TotalSize); err != nil {
		return fmt.Errorf("fill: %w", err)
	}

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

	type codeInfo struct {
		funcName     string
		ownerName    string
		isConstructor bool
	}
	// Resolved via pipeline.ResolveCodeOwner rather than trusting
	// ce.OwnerRef directly -- Code.OwnerRef is confirmed unreliable on
	// some real snapshots (Dart 3.7.0 x86_64: ~5.4% of functions get a
	// bogus shared owner resolving to CID 61/Mint), which would show up
	// here as an unnamed/misattributed function in the audit report.
	byCodeIndex := pipeline.CodeIndexToFunc(result, info.Version.CIDs, info.Version.CodeIndexOneBased)
	codeNames := make(map[int]codeInfo)
	for _, ce := range result.Codes {
		owner, ok := pipeline.ResolveCodeOwner(ce, refToNamed, byCodeIndex)
		if !ok {
			continue
		}
		fn := resolveName(owner)
		isCtor := owner.IsConstructor()
		if isCtor && fn != "" {
			fn = "new " + fn
		}
		codeNames[ce.RefID] = codeInfo{
			funcName:      fn,
			ownerName:     resolveOwnerName(owner),
			isConstructor: isCtor,
		}
	}

	// Build symbol map.
	symbols := make(map[uint64]string)
	for _, r := range ranges {
		va := codeVA + uint64(r.PCOffset) - codeOff
		ci := codeNames[r.RefID]
		var name string
		if ci.isConstructor {
			name = qualifiedName("", ci.funcName, r.PCOffset)
		} else {
			name = qualifiedName(ci.ownerName, ci.funcName, r.PCOffset)
		}
		symbols[va] = name
	}
	lookup := disasm.PlaceholderLookup(symbols)

	// THR fields for resolved marking.
	thrFields := disasm.THRFields(dartVersion, isARM64)

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

		ci := codeNames[r.RefID]
		var funcName string
		if ci.isConstructor {
			funcName = qualifiedName("", ci.funcName, r.PCOffset)
		} else {
			funcName = qualifiedName(ci.ownerName, ci.funcName, r.PCOffset)
		}

		var records []disasm.THRAuditRecord
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
