package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/pipeline"
	"aotopsy/internal/snapshot"
)

type parityRow struct {
	SampleHash  string
	DartVersion string
	Supported   bool
	Status      string // OK, UNSUPPORTED, EXTRACT_FAIL, ALLOC_FAIL, FILL_FAIL
	Strings     int
	Named       int
	Codes       int
	CodeMap     int
	Clusters    int
	Error       string
}

func cmdParity(args []string) error {
	fs := flag.NewFlagSet("parity", flag.ExitOnError)
	samplesDir := fs.String("samples", "", "directory containing sample subdirs (each with libapp.so)")
	outDir := fs.String("out", "", "output directory for parity.csv and summary")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *samplesDir == "" || *outDir == "" {
		return fmt.Errorf("--samples and --out are required")
	}

	entries, err := os.ReadDir(*samplesDir)
	if err != nil {
		return fmt.Errorf("read samples dir: %w", err)
	}

	// Collect sample hashes that have libapp.so.
	var hashes []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		libpath := filepath.Join(*samplesDir, e.Name(), "libapp.so")
		if _, err := os.Stat(libpath); err == nil {
			hashes = append(hashes, e.Name())
		}
	}
	sort.Strings(hashes)

	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}

	var rows []parityRow
	for _, hash := range hashes {
		row := runParitySample(filepath.Join(*samplesDir, hash, "libapp.so"), hash, opts)
		rows = append(rows, row)
		_, _ = fmt.Fprintf(os.Stderr, "%-34s %-8s %-12s strings=%-6d named=%-6d codes=%-6d codemap=%-6d\n",
			hash, row.DartVersion, row.Status, row.Strings, row.Named, row.Codes, row.CodeMap)
	}

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Write parity.csv.
	csvPath := filepath.Join(*outDir, "parity.csv")
	if err := writeParityCSV(csvPath, rows); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stderr, "\nWrote %s (%d rows)\n", csvPath, len(rows))

	// Write summary.
	summaryPath := filepath.Join(*outDir, "parity_summary.md")
	if err := writeParitySummary(summaryPath, rows); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stderr, "Wrote %s\n", summaryPath)

	return nil
}

func runParitySample(libpath, hash string, opts dartfmt.Options) parityRow {
	row := parityRow{SampleHash: hash}

	ef, err := elfx.Open(libpath)
	if err != nil {
		row.Status = "EXTRACT_FAIL"
		row.Error = err.Error()
		return row
	}
	defer func() { _ = ef.Close() }()

	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		row.Status = "EXTRACT_FAIL"
		row.Error = err.Error()
		return row
	}

	if info.Version != nil {
		row.DartVersion = info.Version.DartVersion
		row.Supported = info.Version.Supported
	}

	if !row.Supported {
		row.Status = "UNSUPPORTED"
		return row
	}

	// Run pipeline on isolate snapshot.
	data := info.IsolateData.Data
	if len(data) < 64 {
		row.Status = "EXTRACT_FAIL"
		row.Error = "isolate data too short"
		return row
	}

	clusterStart, err := cluster.FindClusterDataStart(data)
	if err != nil {
		row.Status = "ALLOC_FAIL"
		row.Error = err.Error()
		return row
	}

	result, err := cluster.ScanClusters(data, clusterStart, info.Version, false, opts)
	if err != nil {
		row.Status = "ALLOC_FAIL"
		row.Error = err.Error()
		return row
	}
	row.Clusters = len(result.Clusters)

	if err := cluster.ReadFill(data, result, info.Version, false, info.IsolateHeader.TotalSize); err != nil {
		row.Status = "FILL_FAIL"
		row.Error = err.Error()
		row.Strings = len(result.Strings)
		row.Named = len(result.Named)
		row.Codes = len(result.Codes)
		return row
	}

	row.Strings = len(result.Strings)
	row.Named = len(result.Named)
	row.Codes = len(result.Codes)

	// Count code→function mappings. Resolved via pipeline.ResolveCodeOwner
	// rather than trusting ce.OwnerRef directly -- Code.OwnerRef is
	// confirmed unreliable on some real snapshots (Dart 3.7.0 x86_64:
	// ~5.4% of functions get a bogus shared owner resolving to CID
	// 61/Mint), which would show as a false parity regression here.
	refToNamed := make(map[int]*cluster.NamedObject, len(result.Named))
	for i := range result.Named {
		refToNamed[result.Named[i].RefID] = &result.Named[i]
	}
	byCodeIndex := pipeline.CodeIndexToFunc(result, info.Version.CIDs, info.Version.CodeIndexOneBased)
	for _, ce := range result.Codes {
		if _, ok := pipeline.ResolveCodeOwner(ce, refToNamed, byCodeIndex); ok {
			row.CodeMap++
		}
	}

	row.Status = "OK"
	return row
}

func writeParityCSV(path string, rows []parityRow) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{"sample_hash", "dart_version", "status", "clusters", "strings", "named", "codes", "code_map", "error"}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, r := range rows {
		record := []string{
			r.SampleHash,
			r.DartVersion,
			r.Status,
			strconv.Itoa(r.Clusters),
			strconv.Itoa(r.Strings),
			strconv.Itoa(r.Named),
			strconv.Itoa(r.Codes),
			strconv.Itoa(r.CodeMap),
			r.Error,
		}
		if err := w.Write(record); err != nil {
			return err
		}
	}
	return nil
}

func writeParitySummary(path string, rows []parityRow) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	// Count by status.
	statusCounts := make(map[string]int)
	versionCounts := make(map[string]int)
	var totalStrings, totalNamed, totalCodes, totalCodeMap int
	for _, r := range rows {
		statusCounts[r.Status]++
		if r.DartVersion != "" {
			versionCounts[r.DartVersion]++
		}
		totalStrings += r.Strings
		totalNamed += r.Named
		totalCodes += r.Codes
		totalCodeMap += r.CodeMap
	}

	_, _ = fmt.Fprintf(f, "# Parity Report\n\n")
	_, _ = fmt.Fprintf(f, "Total samples: %d\n\n", len(rows))

	_, _ = fmt.Fprintf(f, "## Status\n\n")
	_, _ = fmt.Fprintf(f, "| Status | Count |\n|--------|-------|\n")
	for _, st := range []string{"OK", "UNSUPPORTED", "EXTRACT_FAIL", "ALLOC_FAIL", "FILL_FAIL"} {
		if c, ok := statusCounts[st]; ok {
			_, _ = fmt.Fprintf(f, "| %s | %d |\n", st, c)
		}
	}

	_, _ = fmt.Fprintf(f, "\n## Version Coverage\n\n")
	_, _ = fmt.Fprintf(f, "| Version | Samples | Status |\n|---------|---------|--------|\n")
	var versions []string
	for v := range versionCounts {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	for _, v := range versions {
		supported := "supported"
		for _, r := range rows {
			if r.DartVersion == v && !r.Supported {
				supported = "unsupported"
				break
			}
		}
		_, _ = fmt.Fprintf(f, "| %s | %d | %s |\n", v, versionCounts[v], supported)
	}

	_, _ = fmt.Fprintf(f, "\n## Totals (OK samples only)\n\n")
	_, _ = fmt.Fprintf(f, "| Metric | Total |\n|--------|-------|\n")
	_, _ = fmt.Fprintf(f, "| Strings | %d |\n", totalStrings)
	_, _ = fmt.Fprintf(f, "| Named objects | %d |\n", totalNamed)
	_, _ = fmt.Fprintf(f, "| Code entries | %d |\n", totalCodes)
	_, _ = fmt.Fprintf(f, "| Code→function maps | %d |\n", totalCodeMap)

	// List failed samples.
	var failed []parityRow
	for _, r := range rows {
		if r.Status != "OK" && r.Status != "UNSUPPORTED" {
			failed = append(failed, r)
		}
	}
	if len(failed) > 0 {
		_, _ = fmt.Fprintf(f, "\n## Failures\n\n")
		_, _ = fmt.Fprintf(f, "| Hash | Version | Status | Error |\n|------|---------|--------|-------|\n")
		for _, r := range failed {
			errMsg := r.Error
			if len(errMsg) > 80 {
				errMsg = errMsg[:80] + "..."
			}
			errMsg = strings.ReplaceAll(errMsg, "|", "\\|")
			_, _ = fmt.Fprintf(f, "| %s | %s | %s | %s |\n", r.SampleHash, r.DartVersion, r.Status, errMsg)
		}
	}

	// List unsupported samples.
	var unsupported []parityRow
	for _, r := range rows {
		if r.Status == "UNSUPPORTED" {
			unsupported = append(unsupported, r)
		}
	}
	if len(unsupported) > 0 {
		_, _ = fmt.Fprintf(f, "\n## Unsupported Versions\n\n")
		_, _ = fmt.Fprintf(f, "| Hash | Version |\n|------|--------|\n")
		for _, r := range unsupported {
			_, _ = fmt.Fprintf(f, "| %s | %s |\n", r.SampleHash, r.DartVersion)
		}
	}

	return nil
}
