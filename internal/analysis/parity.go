package analysis

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"aotopsy/internal/cli"
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/naming"
	"aotopsy/internal/output"
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
	containsSamples, err := output.ContainsPath(outDir, samplesDir)
	if err != nil {
		return fmt.Errorf("compare parity input/output paths: %w", err)
	}
	if containsSamples {
		return fmt.Errorf("parity output directory must not contain the samples directory")
	}
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
		cli.Errf("%-34s %-8s %-12s strings=%-6d named=%-6d codes=%-6d codemap=%-6d\n",
			hash, row.DartVersion, row.Status, row.Strings, row.Named, row.Codes, row.CodeMap)
	}

	// Encode both managed artifacts completely before publishing either one.
	// A failed CSV flush or Markdown write therefore cannot leave a mixed
	// generation where parity.csv and parity_summary.md describe different runs.
	csvPath := filepath.Join(outDir, "parity.csv")
	var csvBuf bytes.Buffer
	if err := writeParityCSV(&csvBuf, rows); err != nil {
		return fmt.Errorf("encode %s: %w", csvPath, err)
	}
	summaryPath := filepath.Join(outDir, "parity_summary.md")
	var summaryBuf bytes.Buffer
	if err := writeParitySummary(&summaryBuf, rows); err != nil {
		return fmt.Errorf("encode %s: %w", summaryPath, err)
	}
	tx, err := output.BeginDirTransaction(outDir)
	if err != nil {
		return fmt.Errorf("begin parity output transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Abort()
		}
	}()
	if err := output.WriteArtifactFile(tx.StageDir(), "parity.csv", csvBuf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("stage parity.csv: %w", err)
	}
	if err := output.WriteArtifactFile(tx.StageDir(), "parity_summary.md", summaryBuf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("stage parity_summary.md: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("publish parity reports: %w", err)
	}
	committed = true
	cli.Errf("\nWrote %s (%d rows)\n", csvPath, len(rows))
	cli.Errf("Wrote %s\n", summaryPath)

	return nil
}

func runParitySample(libpath, hash string, opts dartfmt.Options) ParityRow {
	row := ParityRow{SampleHash: hash}

	ef, info, result, err := LoadSnapshotIsolate(libpath, opts)
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
	firstEntryWithCode := -1
	if info.Version.CodeIndexOneBased {
		table, tableErr := cluster.ParseInstructionsTable(info.IsolateData.Data, &result.Header, info.Version, info.IsolateHeader)
		if tableErr != nil {
			row.Status = "EXTRACT_FAIL"
			row.Error = fmt.Sprintf("instructions table: %v", tableErr)
			return row
		}
		firstEntryWithCode = int(table.FirstEntryWithCode)
	}

	// Count code→function mappings. Resolved via naming.ResolveCodeOwner
	// rather than trusting ce.OwnerRef directly.
	refToNamed := make(map[int]*cluster.NamedObject, len(result.Named))
	for i := range result.Named {
		refToNamed[result.Named[i].RefID] = &result.Named[i]
	}
	byCodeIndex := naming.CodeIndexToFunc(result, info.Version.CIDs, info.Version.CodeIndexOneBased, firstEntryWithCode)
	for _, ce := range result.Codes {
		if _, ok := naming.ResolveCodeOwner(ce, refToNamed, byCodeIndex, info.Version.CIDs); ok {
			row.CodeMap++
		}
	}

	row.Status = "OK"
	return row
}

func writeParityCSV(dst io.Writer, rows []ParityRow) error {
	w := csv.NewWriter(dst)

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
	w.Flush()
	return w.Error()
}

func writeParitySummary(dst io.Writer, rows []ParityRow) error {
	var writeErr error
	writef := func(format string, args ...any) {
		if writeErr != nil {
			return
		}
		_, writeErr = fmt.Fprintf(dst, format, args...)
	}

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

	writef("# Parity Report\n\n")
	writef("Total samples: %d\n\n", len(rows))

	writef("## Status\n\n")
	writef("| Status | Count |\n|--------|-------|\n")
	for _, st := range []string{"OK", "UNSUPPORTED", "EXTRACT_FAIL", "ALLOC_FAIL", "FILL_FAIL"} {
		if c, ok := statusCounts[st]; ok {
			writef("| %s | %d |\n", st, c)
		}
	}

	writef("\n## Version Coverage\n\n")
	writef("| Version | Samples | Status |\n|---------|---------|--------|\n")
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
		writef("| %s | %d | %s |\n", v, versionCounts[v], supported)
	}

	writef("\n## Totals (OK samples only)\n\n")
	writef("| Metric | Total |\n|--------|-------|\n")
	writef("| Strings | %d |\n", totalStrings)
	writef("| Named objects | %d |\n", totalNamed)
	writef("| Code entries | %d |\n", totalCodes)
	writef("| Code→function maps | %d |\n", totalCodeMap)

	// List failed samples.
	var failed []ParityRow
	for _, r := range rows {
		if r.Status != "OK" && r.Status != "UNSUPPORTED" {
			failed = append(failed, r)
		}
	}
	if len(failed) > 0 {
		writef("\n## Failures\n\n")
		writef("| Hash | Version | Status | Error |\n|------|---------|--------|-------|\n")
		for _, r := range failed {
			errMsg := r.Error
			if len(errMsg) > 80 {
				errMsg = errMsg[:80] + "..."
			}
			errMsg = strings.ReplaceAll(errMsg, "|", "\\|")
			writef("| %s | %s | %s | %s |\n", r.SampleHash, r.DartVersion, r.Status, errMsg)
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
		writef("\n## Unsupported Versions\n\n")
		writef("| Hash | Version |\n|------|--------|\n")
		for _, r := range unsupported {
			writef("| %s | %s |\n", r.SampleHash, r.DartVersion)
		}
	}

	return writeErr
}
