// extract_thr.go: Extracts Thread field offset tables from dart-lang/sdk's
// runtime_offsets_extracted.h for all supported Dart versions and architectures.
//
// Usage:
//   go run tools/extract_thr.go -tag 3.9.2 -arch x64 -compressed
//   go run tools/extract_thr.go -tag 2.12.0 -arch arm64 -nocompressed
//   go run tools/extract_thr.go -all  # extract all known versions
//
// Outputs Go map literals suitable for pasting into thrfields.go.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

type extractTarget struct {
	tag        string
	arch       string // "arm64" or "x64"
	compressed bool
}

// All supported versions and their THR table configurations.
var allTargets = []extractTarget{
	// ARM64 + compressed (v2.18+)
	{"2.18.0", "arm64", true},
	{"2.19.0", "arm64", true},
	{"3.0.5", "arm64", true},
	{"3.1.0", "arm64", true},
	{"3.2.5", "arm64", true},
	{"3.3.0", "arm64", true},
	{"3.4.3", "arm64", true},
	{"3.5.0", "arm64", true},
	{"3.6.2", "arm64", true},
	{"3.7.0", "arm64", true},
	{"3.8.1", "arm64", true},
	{"3.9.2", "arm64", true},
	{"3.10.7", "arm64", true},
	{"3.11.0", "arm64", true},
	{"3.12.2", "arm64", true},
	// ARM64 + non-compressed (v2.x)
	{"2.12.0", "arm64", false},
	{"2.13.0", "arm64", false},
	{"2.14.0", "arm64", false},
	{"2.15.0", "arm64", false},
	{"2.16.0", "arm64", false},
	{"2.17.6", "arm64", false},
	// x86_64 + compressed (v2.18+)
	{"2.18.0", "x64", true},
	{"2.19.0", "x64", true},
	{"3.0.5", "x64", true},
	{"3.1.0", "x64", true},
	{"3.2.5", "x64", true},
	{"3.3.0", "x64", true},
	{"3.4.3", "x64", true},
	{"3.5.0", "x64", true},
	{"3.6.2", "x64", true},
	{"3.7.0", "x64", true},
	{"3.8.1", "x64", true},
	{"3.9.2", "x64", true},
	{"3.10.7", "x64", true},
	{"3.11.0", "x64", true},
	{"3.12.2", "x64", true},
	// x86_64 + non-compressed (v2.x)
	{"2.12.0", "x64", false},
	{"2.13.0", "x64", false},
	{"2.14.0", "x64", false},
	{"2.15.0", "x64", false},
	{"2.16.0", "x64", false},
	{"2.17.6", "x64", false},
}

// parseOffset parses a C integer literal (hex "0xNNN" or decimal "NNN").
func parseOffset(s string) int {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		var v int
		fmt.Sscanf(s, "0x%x", &v)
		return v
	}
	var v int
	fmt.Sscanf(s, "%d", &v)
	return v
}

func fetchHeader(tag string) (string, error) {
	cmd := exec.Command("gh", "api", "-H", "Accept: application/vnd.github.raw+json",
		fmt.Sprintf("repos/dart-lang/sdk/contents/runtime/vm/compiler/runtime_offsets_extracted.h?ref=%s", tag))
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("gh api for tag %s: %w", tag, err)
	}
	return string(out), nil
}

func extractTHRFields(header, arch string, compressed bool) ([]struct {
	offset int
	name   string
}, error) {
	// For v2.x, DART_COMPRESSED_POINTERS may not exist in the file at all.
	// In that case, match only on PRODUCT + correct arch (ignore compressed flag).
	archUpper := strings.ToUpper(arch)
	var compressedStr string
	if compressed {
		compressedStr = "defined(DART_COMPRESSED_POINTERS)"
	} else {
		compressedStr = "!defined(DART_COMPRESSED_POINTERS)"
	}

	lines := strings.Split(header, "\n")
	inSection := false
	inProductBranch := false // true when inside #else (PRODUCT) of #if !defined(PRODUCT)
	var results []struct {
		offset int
		name   string
	}
	seen := map[int]string{} // deduplicate

	hasCompressedSections := strings.Contains(header, "DART_COMPRESSED_POINTERS")

	reSingle := regexp.MustCompile(`Thread_(\w+)_offset\s*=\s*(0x[0-9a-fA-F]+|\d+)`)
	reMulti := regexp.MustCompile(`Thread_(\w+)_offset\s*=\s*$`)
	reHex := regexp.MustCompile(`^\s*(0x[0-9a-fA-F]+|\d+)\s*;`)

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Track #if !defined(PRODUCT) ... #else ... #endif nesting
		if strings.HasPrefix(trimmed, "#if") && strings.Contains(trimmed, "!defined(PRODUCT)") {
			inProductBranch = false
			fmt.Fprintf(os.Stderr, "DEBUG: line %d #if !PRODUCT -> inProductBranch=false\n", i+1)
			continue
		}
		if strings.HasPrefix(trimmed, "#else") && !inProductBranch {
			inProductBranch = true
			inSection = false
			fmt.Fprintf(os.Stderr, "DEBUG: line %d #else -> inProductBranch=true\n", i+1)
			continue
		}
		if strings.HasPrefix(trimmed, "#endif") && !inSection && inProductBranch {
			// Only close the PRODUCT branch if this #endif matches the
			// outer #if !defined(PRODUCT), not a sub-section #endif.
			// The outer #endif has "!defined(PRODUCT)" in its comment.
			if strings.Contains(trimmed, "!defined(PRODUCT)") || strings.Contains(trimmed, "PRODUCT") {
				inProductBranch = false
				fmt.Fprintf(os.Stderr, "DEBUG: line %d #endif PRODUCT -> inProductBranch=false\n", i+1)
			}
			continue
		}

		if strings.HasPrefix(trimmed, "#if") {
			fullCond := line
			j := i + 1
			for j < len(lines) && strings.HasSuffix(strings.TrimSpace(lines[j]), "\\") {
				fullCond += " " + strings.TrimSpace(lines[j])
				j++
			}
			if j < len(lines) {
				fullCond += " " + strings.TrimSpace(lines[j])
			}

			isProduct := strings.Contains(fullCond, "defined(PRODUCT)") && !strings.Contains(fullCond, "!defined(PRODUCT)")
			isCorrectArch := strings.Contains(fullCond, "defined(TARGET_ARCH_"+archUpper+")")

			isCorrectCompressed := true
			if hasCompressedSections {
				if compressed {
					// C-1 fix: distinguish defined(DCP) from !defined(DCP).
					// strings.Contains("!defined(DCP)", "defined(DCP)") was true,
					// causing non-compressed sections to leak into compressed tables.
					isCorrectCompressed = strings.Contains(fullCond, compressedStr) &&
						!strings.Contains(fullCond, "!"+compressedStr)
				} else {
					isCorrectCompressed = strings.Contains(fullCond, compressedStr)
				}
			}

			// Match if:
			// 1. PRODUCT + arch + compressed (v3.x style), OR
			// 2. arch only AND in PRODUCT branch (v2.12 style, no compressed sections), OR
			// 3. arch + compressed AND in PRODUCT branch (v2.13+ style, compressed
			//    sections exist but PRODUCT is via #else branch)
			if isCorrectArch && isCorrectCompressed {
				if isProduct || (!hasCompressedSections && inProductBranch) || (hasCompressedSections && inProductBranch && !isProduct) {
					inSection = true
				}
			}
			continue
		}

		if inSection && strings.HasPrefix(trimmed, "#endif") {
			inSection = false
			continue
		}

		if !inSection {
			continue
		}

		// Try single-line match
		if m := reSingle.FindStringSubmatch(line); m != nil {
			name := m[1]
			offset := parseOffset(m[2])
			if _, exists := seen[offset]; !exists {
				seen[offset] = name
				results = append(results, struct {
					offset int
					name   string
				}{offset, name})
			}
			continue
		}

		// Try multi-line match
		if m := reMulti.FindStringSubmatch(line); m != nil {
			name := m[1]
			for j := i + 1; j < len(lines) && j <= i+3; j++ {
				if hm := reHex.FindStringSubmatch(lines[j]); hm != nil {
					offset := parseOffset(hm[1])
					if _, exists := seen[offset]; !exists {
						seen[offset] = name
						results = append(results, struct {
							offset int
							name   string
						}{offset, name})
					}
					break
				}
			}
		}
	}

	return results, nil
}

func generateGoMap(tag, arch string, compressed bool, entries []struct {
	offset int
	name   string
}) string {
	sort.Slice(entries, func(i, j int) bool { return entries[i].offset < entries[j].offset })

	var archSuffix string
	if arch == "x64" {
		archSuffix = "_x64"
	}
	compressSuffix := ""
	if !compressed {
		compressSuffix = "_nocompress"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "// v%s: PRODUCT AOT + %s + %s\n", tag, strings.ToUpper(arch),
		map[bool]string{true: "DART_COMPRESSED_POINTERS", false: "!DART_COMPRESSED_POINTERS"}[compressed])
	fmt.Fprintf(&b, "// Source: dartsdk/v%s/runtime/vm/compiler/runtime_offsets_extracted.h\n", tag)
	fmt.Fprintf(&b, "var thrV%s%s%s = map[int]string{\n", strings.ReplaceAll(tag, ".", ""), archSuffix, compressSuffix)
	for _, e := range entries {
		fmt.Fprintf(&b, "\t0x%x: %q,\n", e.offset, e.name)
	}
	fmt.Fprintf(&b, "}\n\n")
	return b.String()
}

func main() {
	tagFlag := flag.String("tag", "", "Dart SDK version tag (e.g., 3.9.2)")
	archFlag := flag.String("arch", "arm64", "architecture: arm64 or x64")
	compressedFlag := flag.Bool("compressed", false, "DART_COMPRESSED_POINTERS section")
	nocompressedFlag := flag.Bool("nocompressed", false, "!DART_COMPRESSED_POINTERS section")
	allFlag := flag.Bool("all", false, "extract all known versions")
	flag.Parse()

	if *allFlag {
		// Extract all targets, grouped by arch+compressed
		groups := map[string][]extractTarget{}
		for _, t := range allTargets {
			key := fmt.Sprintf("%s_%v", t.arch, t.compressed)
			groups[key] = append(groups[key], t)
		}

		for _, t := range allTargets {
			fmt.Fprintf(os.Stderr, "Extracting %s %s compressed=%v...\n", t.tag, t.arch, t.compressed)
			header, err := fetchHeader(t.tag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  SKIP: %v\n", err)
				continue
			}
			entries, err := extractTHRFields(header, t.arch, t.compressed)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ERROR: %v\n", err)
				continue
			}
			if len(entries) == 0 {
				fmt.Fprintf(os.Stderr, "  SKIP: 0 entries found\n")
				continue
			}
			fmt.Fprintf(os.Stderr, "  Found %d entries\n", len(entries))
			fmt.Print(generateGoMap(t.tag, t.arch, t.compressed, entries))
		}
		return
	}

	if *tagFlag == "" {
		fmt.Fprintln(os.Stderr, "Usage: extract_thr.go -tag <version> -arch <arm64|x64> [-compressed|-nocompressed] OR -all")
		os.Exit(1)
	}

	compressed := *compressedFlag
	if *nocompressedFlag {
		compressed = false
	}

	header, err := fetchHeader(*tagFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	entries, err := extractTHRFields(header, *archFlag, compressed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Found %d Thread field entries for %s %s compressed=%v\n",
		len(entries), *tagFlag, *archFlag, compressed)
	fmt.Print(generateGoMap(*tagFlag, *archFlag, compressed, entries))
}
