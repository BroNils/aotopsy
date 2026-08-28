package analysis

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/naming"
	"aotopsy/internal/pipeline"
)

// ParityRow is one row of the parity report.
type ParityRow struct {
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

// RunParity scans a samples directory and generates parity.csv + parity_summary.md.
func RunParity(samplesDir, outDir string) error {
	entries, err := os.ReadDir(samplesDir)
	if err != nil {
		return fmt.Errorf("read samples dir: %w", err)
	}

	// Collect sample hashes that have libapp.so.
	var hashes []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		libpath := filepath.Join(samplesDir, e.Name(), "libapp.so")
		if _, err := os.Stat(libpath); err == nil {
			hashes = append(hashes, e.Name())
		}
	}
	sort.Strings(hashes)

	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}

	var rows []ParityRow
	for _, hash := range hashes {
		row := runParitySample(filepath.Join(samplesDir, hash, "libapp.so"), hash, opts)
		rows = append(rows, row)
		_, _ = fmt.Fprintf(os.Stderr, "%-34s %-8s %-12s strings=%-6d named=%-6d codes=%-6d codemap=%-6d\n",
			hash, row.DartVersion, row.Status, row.Strings, row.Named, row.Codes, row.CodeMap)
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Write parity.csv.
	csvPath := filepath.Join(outDir, "parity.csv")
	if err := writeParityCSV(csvPath, rows); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stderr, "\nWrote %s (%d rows)\n", csvPath, len(rows))

	// Write summary.
	summaryPath := filepath.Join(outDir, "parity_summary.md")
	if err := writeParitySummary(summaryPath, rows); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stderr, "Wrote %s\n", summaryPath)

	return nil
}

func runParitySample(libpath, hash string, opts dartfmt.Options) ParityRow {
	row := ParityRow{SampleHash: hash}

	ef, info, result, err := pipeline.LoadSnapshotIsolate(libpath, opts)
	if err != nil {
		row.Status = "EXTRACT_FAIL"
		row.Error = err.Error()
		return row
	}
	defer func() { _ = ef.Close() }()

	if info.Version != nil {
		row.DartVersion = info.Version.DartVersion
		row.Supported = info.Version.Supported
	}

	if !row.Supported {
		row.Status = "UNSUPPORTED"
		return row
	}

	row.Clusters = len(result.Clusters)
	row.Strings = len(result.Strings)
	row.Named = len(result.Named)
	row.Codes = len(result.Codes)

	// Count code→function mappings. Resolved via naming.ResolveCodeOwner
	// rather than trusting ce.OwnerRef directly.
	refToNamed := make(map[int]*cluster.NamedObject, len(result.Named))
	for i := range result.Named {
		refToNamed[result.Named[i].RefID] = &result.Named[i]
	}
	byCodeIndex := naming.CodeIndexToFunc(result, info.Version.CIDs, info.Version.CodeIndexOneBased)
	for _, ce := range result.Codes {
		if _, ok := naming.ResolveCodeOwner(ce, refToNamed, byCodeIndex); ok {
			row.CodeMap++
		}
	}

	row.Status = "OK"
	return row
}

func writeParityCSV(path string, rows []ParityRow) error {
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

func writeParitySummary(path string, rows []ParityRow) error {
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
		if r.Status != "OK" {
			continue
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
	var failed []ParityRow
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
	var unsupported []ParityRow
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
