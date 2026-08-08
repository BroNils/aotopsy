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
	product    bool // true = PRODUCT, false = non-PRODUCT (Debug/Profile)
}

// All supported versions and their THR table configurations.
// Each target is a (version, arch, compressed, product) tuple.
// PRODUCT+compressed is the default for release APKs.
// non-PRODUCT and non-compressed variants are needed for debug/profile
// builds and pre-2.18 (non-compressed) builds.
var allTargets = []extractTarget{
	// ARM64 + compressed + PRODUCT (v2.18+)
	{"2.18.0", "arm64", true, true},
	{"2.19.0", "arm64", true, true},
	{"3.0.5", "arm64", true, true},
	{"3.1.0", "arm64", true, true},
	{"3.2.5", "arm64", true, true},
	{"3.3.0", "arm64", true, true},
	{"3.4.3", "arm64", true, true},
	{"3.5.0", "arm64", true, true},
	{"3.6.2", "arm64", true, true},
	{"3.7.0", "arm64", true, true},
	{"3.8.1", "arm64", true, true},
	{"3.9.2", "arm64", true, true},
	{"3.10.7", "arm64", true, true},
	{"3.11.0", "arm64", true, true},
	{"3.12.2", "arm64", true, true},
	// ARM64 + non-compressed + PRODUCT (v2.x)
	{"2.12.0", "arm64", false, true},
	{"2.13.0", "arm64", false, true},
	{"2.14.0", "arm64", false, true},
	{"2.15.0", "arm64", false, true},
	{"2.16.0", "arm64", false, true},
	{"2.17.6", "arm64", false, true},
	// x86_64 + compressed + PRODUCT (v2.18+)
	{"2.18.0", "x64", true, true},
	{"2.19.0", "x64", true, true},
	{"3.0.5", "x64", true, true},
	{"3.1.0", "x64", true, true},
	{"3.2.5", "x64", true, true},
	{"3.3.0", "x64", true, true},
	{"3.4.3", "x64", true, true},
	{"3.5.0", "x64", true, true},
	{"3.6.2", "x64", true, true},
	{"3.7.0", "x64", true, true},
	{"3.8.1", "x64", true, true},
	{"3.9.2", "x64", true, true},
	{"3.10.7", "x64", true, true},
	{"3.11.0", "x64", true, true},
	{"3.12.2", "x64", true, true},
	// x86_64 + non-compressed + PRODUCT (v2.x)
	{"2.12.0", "x64", false, true},
	{"2.13.0", "x64", false, true},
	{"2.14.0", "x64", false, true},
	{"2.15.0", "x64", false, true},
	{"2.16.0", "x64", false, true},
	{"2.17.6", "x64", false, true},
	// ARM64 + compressed + non-PRODUCT (v2.18+)
	{"2.18.0", "arm64", true, false},
	{"2.19.0", "arm64", true, false},
	{"3.0.5", "arm64", true, false},
	{"3.1.0", "arm64", true, false},
	{"3.2.5", "arm64", true, false},
	{"3.3.0", "arm64", true, false},
	{"3.4.3", "arm64", true, false},
	{"3.5.0", "arm64", true, false},
	{"3.6.2", "arm64", true, false},
	{"3.7.0", "arm64", true, false},
	{"3.8.1", "arm64", true, false},
	{"3.9.2", "arm64", true, false},
	{"3.10.7", "arm64", true, false},
	{"3.11.0", "arm64", true, false},
	{"3.12.2", "arm64", true, false},
	// ARM64 + non-compressed + non-PRODUCT (v2.x)
	{"2.12.0", "arm64", false, false},
	{"2.13.0", "arm64", false, false},
	{"2.14.0", "arm64", false, false},
	{"2.15.0", "arm64", false, false},
	{"2.16.0", "arm64", false, false},
	{"2.17.6", "arm64", false, false},
	// x86_64 + compressed + non-PRODUCT (v2.18+)
	{"2.18.0", "x64", true, false},
	{"2.19.0", "x64", true, false},
	{"3.0.5", "x64", true, false},
	{"3.1.0", "x64", true, false},
	{"3.2.5", "x64", true, false},
	{"3.3.0", "x64", true, false},
	{"3.4.3", "x64", true, false},
	{"3.5.0", "x64", true, false},
	{"3.6.2", "x64", true, false},
	{"3.7.0", "x64", true, false},
	{"3.8.1", "x64", true, false},
	{"3.9.2", "x64", true, false},
	{"3.10.7", "x64", true, false},
	{"3.11.0", "x64", true, false},
	{"3.12.2", "x64", true, false},
	// x86_64 + non-compressed + non-PRODUCT (v2.x)
	{"2.12.0", "x64", false, false},
	{"2.13.0", "x64", false, false},
	{"2.14.0", "x64", false, false},
	{"2.15.0", "x64", false, false},
	{"2.16.0", "x64", false, false},
	{"2.17.6", "x64", false, false},
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

func extractTHRFields(header, arch string, compressed, product bool) ([]struct {
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

	// No productStr here: PRODUCT matching is done via the preprocessor stack
	// below, not by substring-testing the section condition. A plain substring
	// test cannot work, because strings.Contains("!defined(PRODUCT)",
	// "defined(PRODUCT)") is true and because Dart 2.x arch conditions carry
	// no PRODUCT token at all.

	lines := strings.Split(header, "\n")
	var results []struct {
		offset int
		name   string
	}
	seen := map[int]string{} // deduplicate

	hasCompressedSections := strings.Contains(header, "DART_COMPRESSED_POINTERS")

	reSingle := regexp.MustCompile(`Thread_(\w+)_offset\s*=\s*(0x[0-9a-fA-F]+|\d+)`)
	reMulti := regexp.MustCompile(`Thread_(\w+)_offset\s*=\s*$`)
	reHex := regexp.MustCompile(`^\s*(0x[0-9a-fA-F]+|\d+)\s*;`)

	// runtime_offsets_extracted.h comes in TWO layouts, and the extractor has
	// to handle both. Verified by fetching the real headers:
	//
	//  A) Dart 3.x (e.g. 3.9.2): PRODUCT is part of each section's own
	//     condition ->
	//       #if defined(PRODUCT) && defined(TARGET_ARCH_ARM64) && defined(DCP)
	//
	//  B) Dart 2.x (e.g. 2.14.0, 2.17.6): one outer guard wraps everything and
	//     the arch conditions carry no PRODUCT token ->
	//       #if !defined(PRODUCT)          <- line 18
	//         #if defined(TARGET_ARCH_ARM64) && !defined(DCP)
	//         ...
	//       #else                          <- PRODUCT half starts here
	//         #if defined(TARGET_ARCH_ARM64) && !defined(DCP)
	//       #endif
	//
	// The previous implementation was wrong for both:
	//
	//   - Layout A, non-PRODUCT: the "track the outer guard" branch matched
	//     `#if ... !defined(PRODUCT) ...` and `continue`d, so a layout-A
	//     non-PRODUCT section header never reached the arch/compression
	//     matcher. Result: 0 entries, which is how four empty "_nonproduct"
	//     tables ended up committed in internal/disasm.
	//   - Layout B, PRODUCT: an earlier revision handled this via
	//     `inProductBranch` fallbacks, which a later edit deleted in favour of
	//     a plain `isProduct` string test. Since layout-B arch conditions
	//     contain no PRODUCT token, that test can never be true. Result:
	//     2.17.6 went 96 -> 0 entries and 2.14.0 went 92 -> 0, i.e. the 2.x
	//     tables already in the tree could no longer be reproduced.
	//
	// Fix: track the preprocessor nesting with an explicit stack, so "am I in
	// a PRODUCT region?" is answered by the enclosing guards when the section
	// itself is silent about it (layout B) and by the section's own condition
	// when it is not (layout A).
	type frame struct {
		// productState is +1 inside a defined(PRODUCT) region, -1 inside a
		// !defined(PRODUCT) region, 0 when this frame says nothing about it.
		productState int
		// isSection is true when this #if selected an arch/compression block
		// we want to harvest offsets from.
		isSection bool
	}
	var stack []frame

	// enclosingProduct reports the innermost non-zero productState, or 0.
	enclosingProduct := func() int {
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].productState != 0 {
				return stack[i].productState
			}
		}
		return 0
	}
	inSection := func() bool {
		for _, f := range stack {
			if f.isSection {
				return true
			}
		}
		return false
	}

	wantProduct := 1
	if !product {
		wantProduct = -1
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(trimmed, "#if"):
			// Join line-continuations so multi-line conditions are seen whole.
			fullCond := line
			j := i
			for strings.HasSuffix(strings.TrimSpace(lines[j]), "\\") && j+1 < len(lines) {
				j++
				fullCond += " " + strings.TrimSpace(lines[j])
			}
			fullCond = strings.ReplaceAll(fullCond, "\\", " ")

			f := frame{}

			// What does this condition itself say about PRODUCT?
			switch {
			case strings.Contains(fullCond, "!defined(PRODUCT)"):
				f.productState = -1
			case strings.Contains(fullCond, "defined(PRODUCT)"):
				f.productState = 1
			}

			// A harvestable section must name our arch. Layout-B outer guards
			// don't, so they only contribute productState.
			if strings.Contains(fullCond, "defined(TARGET_ARCH_"+archUpper+")") {
				okCompressed := true
				if hasCompressedSections {
					if compressed {
						okCompressed = strings.Contains(fullCond, compressedStr) &&
							!strings.Contains(fullCond, "!"+compressedStr)
					} else {
						okCompressed = strings.Contains(fullCond, compressedStr)
					}
				}
				// Section's own PRODUCT token wins (layout A); otherwise
				// inherit from the enclosing guard (layout B).
				effProduct := f.productState
				if effProduct == 0 {
					effProduct = enclosingProduct()
				}
				if okCompressed && effProduct == wantProduct {
					f.isSection = true
				}
			}

			stack = append(stack, f)
			i = j // skip the continuation lines we consumed
			continue

		case strings.HasPrefix(trimmed, "#else"), strings.HasPrefix(trimmed, "#elif"):
			// Flip the current frame: the #else of `#if !defined(PRODUCT)` is
			// the PRODUCT half (layout B). A section frame stops harvesting
			// once we leave its true-branch.
			if len(stack) > 0 {
				top := &stack[len(stack)-1]
				top.productState = -top.productState
				top.isSection = false
				// Re-evaluate: the #else half of a PRODUCT guard can itself be
				// the half we want, but it contains nested arch #ifs which will
				// be handled when we reach them.
			}
			continue

		case strings.HasPrefix(trimmed, "#endif"):
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}

		if !inSection() {
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

func generateGoMap(tag, arch string, compressed, product bool, entries []struct {
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
	productSuffix := ""
	if !product {
		productSuffix = "_nonproduct"
	}

	var b strings.Builder
	modeStr := "PRODUCT"
	if !product {
		modeStr = "non-PRODUCT"
	}
	compressStr := "DART_COMPRESSED_POINTERS"
	if !compressed {
		compressStr = "!DART_COMPRESSED_POINTERS"
	}
	fmt.Fprintf(&b, "// v%s: %s + %s + %s\n", tag, modeStr, strings.ToUpper(arch), compressStr)
	fmt.Fprintf(&b, "// Source: dartsdk/v%s/runtime/vm/compiler/runtime_offsets_extracted.h\n", tag)
	fmt.Fprintf(&b, "var thrV%s%s%s%s = map[int]string{\n", strings.ReplaceAll(tag, ".", ""), archSuffix, compressSuffix, productSuffix)
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
	productFlag := flag.Bool("product", false, "PRODUCT build mode (default)")
	nonproductFlag := flag.Bool("nonproduct", false, "non-PRODUCT build mode (Debug/Profile)")
	allFlag := flag.Bool("all", false, "extract all known versions")
	flag.Parse()

	if *allFlag {
		for _, t := range allTargets {
			fmt.Fprintf(os.Stderr, "Extracting %s %s compressed=%v product=%v...\n", t.tag, t.arch, t.compressed, t.product)
			header, err := fetchHeader(t.tag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  SKIP: %v\n", err)
				continue
			}
			entries, err := extractTHRFields(header, t.arch, t.compressed, t.product)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ERROR: %v\n", err)
				continue
			}
			if len(entries) == 0 {
				fmt.Fprintf(os.Stderr, "  SKIP: 0 entries found\n")
				continue
			}
			fmt.Fprintf(os.Stderr, "  Found %d entries\n", len(entries))
			fmt.Print(generateGoMap(t.tag, t.arch, t.compressed, t.product, entries))
		}
		return
	}

	if *tagFlag == "" {
		fmt.Fprintln(os.Stderr, "Usage: extract_thr.go -tag <version> -arch <arm64|x64> [-compressed|-nocompressed] [-product|-nonproduct] OR -all")
		os.Exit(1)
	}

	compressed := *compressedFlag
	if *nocompressedFlag {
		compressed = false
	}
	product := !*nonproductFlag
	if *productFlag {
		product = true
	}

	header, err := fetchHeader(*tagFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	entries, err := extractTHRFields(header, *archFlag, compressed, product)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Found %d Thread field entries for %s %s compressed=%v product=%v\n",
		len(entries), *tagFlag, *archFlag, compressed, product)
	fmt.Print(generateGoMap(*tagFlag, *archFlag, compressed, product, entries))
}
