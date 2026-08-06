package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func cmdFindLibappBatch(args []string) error {
	fs := flag.NewFlagSet("find-libapp-batch", flag.ExitOnError)
	dir := fs.String("dir", "samples/flutter", "Directory containing zip files")
	outDir := fs.String("out", "out/find-libapp", "Output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}

	entries, err := os.ReadDir(*dir)
	if err != nil {
		return fmt.Errorf("readdir %s: %w", *dir, err)
	}

	type summary struct {
		Name   string
		Result *FindResult
		Error  string
	}

	var results []summary

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".zip") {
			continue
		}
		path := filepath.Join(*dir, e.Name())
		s := summary{Name: e.Name()}

		result, err := findLibappInZip(path)
		if err != nil {
			s.Error = err.Error()
		} else {
			s.Result = result
			// Write individual JSON.
			data, _ := json.MarshalIndent(result, "", "  ")
			base := strings.TrimSuffix(e.Name(), ".zip")
			outPath := filepath.Join(*outDir, base+"_find_libapp.json")
			if err := os.WriteFile(outPath, data, 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "warning: write %s: %v\n", outPath, err)
			}
		}
		results = append(results, s)
	}

	// Sort by name.
	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})

	// Generate no_libapp_report.md — only entries that were NOT found via standard libapp.so path.
	reportPath := filepath.Join(*outDir, "no_libapp_report.md")
	f, err := os.Create(reportPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	_, _ = fmt.Fprintln(f, "# No libapp.so Report")
	_, _ = fmt.Fprintln(f)
	_, _ = fmt.Fprintln(f, "Samples where `lib/arm64-v8a/libapp.so` was not found at the standard path.")
	_, _ = fmt.Fprintln(f)
	_, _ = fmt.Fprintln(f, "| Sample | Reason | Best Match | Details |")
	_, _ = fmt.Fprintln(f, "|--------|--------|------------|---------|")

	var noLibapp, found, notFlutter, noArm int
	for _, s := range results {
		if s.Error != "" {
			continue
		}
		if s.Result == nil {
			continue
		}
		// Check if the standard path was the best match.
		hasStandard := false
		if s.Result.Best != nil {
			p := s.Result.Best.PathInAPK
			hasStandard = p == "lib/arm64-v8a/libapp.so" ||
				strings.HasSuffix(p, "!lib/arm64-v8a/libapp.so")
		}
		if hasStandard {
			continue
		}

		noLibapp++
		name := strings.TrimSuffix(s.Name, ".zip")
		if len(name) > 30 {
			name = name[:27] + "..."
		}

		reason := s.Result.Reason
		bestMatch := "-"
		details := "-"

		if s.Result.Best != nil {
			bestMatch = s.Result.Best.PathInAPK
			if len(bestMatch) > 50 {
				bestMatch = "..." + bestMatch[len(bestMatch)-47:]
			}
			details = fmt.Sprintf("hit=%s sha=%s", s.Result.Best.Hit, s.Result.Best.SHA256[:12])
			if s.Result.Best.SnapHash != "" {
				details += " snap=" + s.Result.Best.SnapHash[:12]
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
			case "NO_ARM64":
				noArm++
			}
		}

		_, _ = fmt.Fprintf(f, "| %s | %s | %s | %s |\n", name, reason, bestMatch, details)
	}

	_, _ = fmt.Fprintln(f)
	_, _ = fmt.Fprintf(f, "**Summary:** %d samples without standard libapp.so path. ", noLibapp)
	_, _ = fmt.Fprintf(f, "%d found (renamed), %d NOT_FLUTTER, %d NO_ARM64.\n", found, notFlutter, noArm)

	fmt.Fprintf(os.Stderr, "find-libapp-batch: %d total zips, %d without standard libapp.so\n", len(results), noLibapp)
	fmt.Fprintf(os.Stderr, "  FOUND (renamed): %d, NOT_FLUTTER: %d, NO_ARM64: %d\n", found, notFlutter, noArm)
	fmt.Fprintf(os.Stderr, "wrote %s\n", reportPath)

	return nil
}
