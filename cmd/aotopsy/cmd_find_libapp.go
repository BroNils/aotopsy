package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cli"
	"aotopsy/internal/output"
)

// cmdFindLibapp finds Dart libapp.so in a single APK/ZIP.
func cmdFindLibapp(args []string) error {
	fs := flag.NewFlagSet("find-libapp", flag.ExitOnError)
	apk := fs.String("apk", "", "Path to APK/zip file")
	outDir := fs.String("out", "", "Output directory for find_libapp.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *apk == "" {
		return fmt.Errorf("--apk is required")
	}

	result, err := analysis.FindLibappInZip(*apk)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			return err
		}
		base := strings.TrimSuffix(filepath.Base(*apk), filepath.Ext(*apk))
		outPath := filepath.Join(*outDir, base+"_find_libapp.json")
		if err := output.WriteFileAtomic(outPath, data, 0o644); err != nil {
			return err
		}
		cli.Errf("wrote %s\n", outPath)
	} else {
		fmt.Println(string(data))
	}
	return nil
}

// cmdFindLibappBatch processes a directory of APK/ZIP files and produces batch summaries.
func cmdFindLibappBatch(args []string) error {
	fs := flag.NewFlagSet("find-libapp-batch", flag.ExitOnError)
	dir := fs.String("dir", "samples/flutter", "Directory containing zip files")
	outDir := fs.String("out", "out/find-libapp", "Output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	containsInput, err := output.ContainsPath(*outDir, *dir)
	if err != nil {
		return fmt.Errorf("compare find-libapp batch input/output paths: %w", err)
	}
	if containsInput {
		return fmt.Errorf("find-libapp batch output directory must not contain the input archive directory")
	}

	entries, err := os.ReadDir(*dir)
	if err != nil {
		return fmt.Errorf("readdir %s: %w", *dir, err)
	}

	type summary struct {
		Name   string
		Result *analysis.FindResult
		Error  string
	}

	var results []summary
	var batchErrs []error
	tx, err := output.BeginDirTransaction(*outDir)
	if err != nil {
		return fmt.Errorf("begin find-libapp batch output: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Abort()
		}
	}()
	stageOutDir := tx.StageDir()

	for _, e := range entries {
		base, ok := archiveInputBase(e.Name())
		if !ok {
			continue
		}
		path := filepath.Join(*dir, e.Name())
		s := summary{Name: e.Name()}
		result, err := analysis.FindLibappInZip(path)
		if err != nil {
			s.Error = err.Error()
			batchErrs = append(batchErrs, fmt.Errorf("%s: %w", e.Name(), err))
		} else {
			s.Result = result
			outPath := filepath.Join(stageOutDir, base+"_find_libapp.json")
			if err := output.WriteJSONFile(outPath, result); err != nil {
				return fmt.Errorf("write %s: %w", outPath, err)
			}
		}
		results = append(results, s)
	}

	// Sort by name.
	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})

	// Generate no_libapp_report.md
	reportPath := filepath.Join(stageOutDir, "no_libapp_report.md")
	var noLibapp, found, notFlutter, noSupportedABI, failed int
	err = output.WriteAtomic(reportPath, 0o644, func(w io.Writer) error {
		writef := func(format string, args ...any) error {
			_, err := fmt.Fprintf(w, format, args...)
			return err
		}
		if err := writef("# No libapp.so Report\n\nSamples where `libapp.so` was not found at a standard supported ABI path.\n\n| Sample | Reason | Best Match | Details |\n|--------|--------|------------|---------|\n"); err != nil {
			return err
		}
		for _, s := range results {
			if s.Error != "" {
				failed++
				if err := writef("| %s | ERROR | - | %s |\n", markdownCell(s.Name), markdownCell(s.Error)); err != nil {
					return err
				}
				continue
			}
			if s.Result == nil {
				return fmt.Errorf("missing result without error for %s", s.Name)
			}
			hasStandard := false
			if s.Result.Best != nil {
				hasStandard = analysis.IsStandardLibappPath(s.Result.Best.PathInAPK)
			}
			if hasStandard {
				continue
			}

			noLibapp++
			name, _ := archiveInputBase(s.Name)
			if len(name) > 30 {
				name = name[:27] + "..."
			}
			reason := s.Result.Reason
			bestMatch, details := "-", "-"
			if s.Result.Best != nil {
				bestMatch = s.Result.Best.PathInAPK
				if len(bestMatch) > 50 {
					bestMatch = "..." + bestMatch[len(bestMatch)-47:]
				}
				sha := s.Result.Best.SHA256
				if len(sha) > 12 {
					sha = sha[:12]
				}
				details = fmt.Sprintf("hit=%s sha=%s", s.Result.Best.Hit, sha)
				if snap := s.Result.Best.SnapHash; snap != "" {
					if len(snap) > 12 {
						snap = snap[:12]
					}
					details += " snap=" + snap
				}
				found++
			} else {
				switch reason {
				case "NOT_FLUTTER":
					notFlutter++
					if len(s.Result.Candidates) > 0 {
						var names []string
						for _, c := range s.Result.Candidates {
							names = append(names, filepath.Base(c.PathInAPK))
						}
						details = fmt.Sprintf("%d .so files: %s", len(names), strings.Join(names, ", "))
					}
				case "NO_SUPPORTED_ABI":
					noSupportedABI++
				}
			}
			if err := writef("| %s | %s | %s | %s |\n", markdownCell(name), markdownCell(reason), markdownCell(bestMatch), markdownCell(details)); err != nil {
				return err
			}
		}
		if err := writef("\n**Summary:** %d samples without standard libapp.so path. ", noLibapp); err != nil {
			return err
		}
		return writef("%d found (renamed), %d NOT_FLUTTER, %d NO_SUPPORTED_ABI, %d ERROR.\n", found, notFlutter, noSupportedABI, failed)
	})
	if err != nil {
		return fmt.Errorf("write %s: %w", reportPath, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("publish find-libapp batch output: %w", err)
	}
	committed = true
	finalReportPath := filepath.Join(*outDir, "no_libapp_report.md")
	cli.Errf("find-libapp-batch: %d total archives, %d without standard libapp.so\n", len(results), noLibapp)
	cli.Errf("  FOUND (renamed): %d, NOT_FLUTTER: %d, NO_SUPPORTED_ABI: %d, ERROR: %d\n", found, notFlutter, noSupportedABI, failed)
	cli.Errf("wrote %s\n", finalReportPath)

	if len(batchErrs) > 0 {
		return fmt.Errorf("find-libapp-batch: %d archive(s) failed: %w", len(batchErrs), errors.Join(batchErrs...))
	}
	return nil
}

func archiveInputBase(name string) (string, bool) {
	ext := filepath.Ext(name)
	switch strings.ToLower(ext) {
	case ".zip", ".apk":
		return strings.TrimSuffix(name, ext), true
	default:
		return "", false
	}
}

func markdownCell(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "|", `\|`)
}
