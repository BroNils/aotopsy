package compare

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// BlutterComparison compares aotopsy's output against blutter's output
// for the same binary, identifying gaps and strengths.
//
// This is the implementation of Tier 5 item 16 (blutter comparison).
// blutter (worawit/blutter) is the closest tool in scope: it recovers
// function names, class structures, and object pool contents from
// Dart AOT libapp.so. Comparing aotopsy's output against blutter's
// turns "we think we're good" into a measurement.
//
// blutter output files (from README.md, gh api verified):
//
//	asm/*  — assembly with symbols
//	objs.txt — complete nested dump of Object Pool
//	pp.txt — all Dart objects in Object Pool
//	blutter_frida.js — frida script template
//
// aotopsy output files:
//
//	functions.jsonl — function records with names
//	call_edges.jsonl — call graph edges
//	classes.jsonl — class layouts
//	pool_immediates.jsonl — pool immediate values
//	string_refs.jsonl — string references
//
// The comparison checks:
//  1. Name coverage: % of functions named by each tool
//  2. Name agreement: do both tools assign the same name to the same VA?
//  3. Class coverage: how many classes each tool recovers
//  4. Pool coverage: how many pool entries each tool resolves
type BlutterComparison struct {
	BlutterDir string // path to blutter output directory
	AotopsyDir string // path to aotopsy output directory

	// Results
	BlutterFuncCount  int
	BlutterNamedCount int
	AotopsyFuncCount  int
	AotopsyNamedCount int

	// Name agreement: functions named by both tools at the same VA
	BothNamed int
	Agree     int
	Disagree  int

	// Unique to each tool
	OnlyBlutter int
	OnlyAotopsy int

	// Class coverage
	BlutterClasses int
	AotopsyClasses int

	// Disagreement samples (first 10)
	Disagreements []BlutterDisagreement
}

// BlutterDisagreement is one function where aotopsy and blutter
// assign different names to the same address.
type BlutterDisagreement struct {
	VA          string
	AotopsyName string
	BlutterName string
}

// CompareBlutter runs the comparison and returns a report.
//
// blutterDir should point to the directory containing blutter's
// output (asm/, objs.txt, pp.txt). aotopsyDir should point to
// the directory containing aotopsy's output (functions.jsonl,
// classes.jsonl, etc).
func CompareBlutter(blutterDir, aotopsyDir string) (*BlutterComparison, error) {
	c := &BlutterComparison{
		BlutterDir: blutterDir,
		AotopsyDir: aotopsyDir,
	}

	// Load blutter function names from asm/ directory.
	blutterNames, err := loadBlutterFuncNames(blutterDir)
	if err != nil {
		return nil, fmt.Errorf("load blutter names: %w", err)
	}
	c.BlutterFuncCount = len(blutterNames)
	for _, name := range blutterNames {
		if name != "" && !strings.HasPrefix(name, "sub_") {
			c.BlutterNamedCount++
		}
	}

	// Load aotopsy function names from functions.jsonl.
	aotopsyNames, err := loadAotopsyFuncNames(aotopsyDir)
	if err != nil {
		return nil, fmt.Errorf("load aotopsy names: %w", err)
	}
	c.AotopsyFuncCount = len(aotopsyNames)
	for _, name := range aotopsyNames {
		if name != "" && !strings.HasPrefix(name, "sub_") && !strings.HasPrefix(name, "stub_") {
			c.AotopsyNamedCount++
		}
	}

	// Compare names at the same VA.
	allVAs := make(map[string]bool)
	for va := range blutterNames {
		allVAs[va] = true
	}
	for va := range aotopsyNames {
		allVAs[va] = true
	}

	for va := range allVAs {
		bName, bOk := blutterNames[va]
		aName, aOk := aotopsyNames[va]

		bNamed := bOk && bName != "" && !strings.HasPrefix(bName, "sub_")
		aNamed := aOk && aName != "" && !strings.HasPrefix(aName, "sub_") && !strings.HasPrefix(aName, "stub_")

		switch {
		case bNamed && aNamed:
			c.BothNamed++
			// Normalize names for comparison (strip _hex suffix, etc).
			if normalizeName(bName) == normalizeName(aName) {
				c.Agree++
			} else {
				c.Disagree++
				if len(c.Disagreements) < 10 {
					c.Disagreements = append(c.Disagreements, BlutterDisagreement{
						VA:          va,
						AotopsyName: aName,
						BlutterName: bName,
					})
				}
			}
		case bNamed && !aNamed:
			c.OnlyBlutter++
		case !bNamed && aNamed:
			c.OnlyAotopsy++
		}
	}

	// Count classes.
	c.AotopsyClasses = countLines(filepath.Join(aotopsyDir, "classes.jsonl"))
	c.BlutterClasses = countBlutterClasses(blutterDir)

	return c, nil
}

// Summary renders a human-readable comparison report.
func (c *BlutterComparison) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== Blutter vs Aotopsy Comparison ===\n\n")
	fmt.Fprintf(&b, "Function names:\n")
	fmt.Fprintf(&b, "  blutter: %d total, %d named (%.1f%%)\n",
		c.BlutterFuncCount, c.BlutterNamedCount, pct(c.BlutterNamedCount, c.BlutterFuncCount))
	fmt.Fprintf(&b, "  aotopsy: %d total, %d named (%.1f%%)\n",
		c.AotopsyFuncCount, c.AotopsyNamedCount, pct(c.AotopsyNamedCount, c.AotopsyFuncCount))
	fmt.Fprintf(&b, "\nName agreement (both named, same VA):\n")
	fmt.Fprintf(&b, "  both named: %d\n", c.BothNamed)
	fmt.Fprintf(&b, "  agree: %d (%.1f%%)\n", c.Agree, pct(c.Agree, c.BothNamed))
	fmt.Fprintf(&b, "  disagree: %d\n", c.Disagree)
	fmt.Fprintf(&b, "\nUnique coverage:\n")
	fmt.Fprintf(&b, "  only blutter: %d\n", c.OnlyBlutter)
	fmt.Fprintf(&b, "  only aotopsy: %d\n", c.OnlyAotopsy)
	fmt.Fprintf(&b, "\nClass coverage:\n")
	fmt.Fprintf(&b, "  blutter: %d\n", c.BlutterClasses)
	fmt.Fprintf(&b, "  aotopsy: %d\n", c.AotopsyClasses)

	if len(c.Disagreements) > 0 {
		fmt.Fprintf(&b, "\nSample disagreements (first 10):\n")
		for _, d := range c.Disagreements {
			fmt.Fprintf(&b, "  %s: aotopsy=%s blutter=%s\n", d.VA, d.AotopsyName, d.BlutterName)
		}
	}
	return b.String()
}

// loadBlutterFuncNames scans blutter's asm/ directory for function
// names. blutter emits assembly files with function names as labels.
func loadBlutterFuncNames(blutterDir string) (map[string]string, error) {
	asmDir := filepath.Join(blutterDir, "asm")
	entries, err := os.ReadDir(asmDir)
	if err != nil {
		// asm/ might not exist; return empty.
		return make(map[string]string), nil
	}
	names := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		path := filepath.Join(asmDir, entry.Name())
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			// blutter format: function name is in a comment or label.
			// Look for "0xADDR: <name>" or "; <name>" patterns.
			if strings.HasPrefix(line, "0x") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) >= 2 {
					va := strings.TrimSpace(parts[0])
					rest := strings.TrimSpace(parts[1])
					// Extract function name from the line.
					name := extractFuncNameFromAsm(rest)
					if name != "" {
						names[va] = name
					}
				}
			}
		}
		_ = f.Close()
	}
	return names, nil
}

// loadAotopsyFuncNames reads functions.jsonl and returns VA → name.
func loadAotopsyFuncNames(aotopsyDir string) (map[string]string, error) {
	path := filepath.Join(aotopsyDir, "functions.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return make(map[string]string), nil
	}
	defer func() { _ = f.Close() }()
	names := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Parse JSON: {"pc":"0x...","name":"...","size":...}
		pc := extractJSONField(line, "\"pc\":\"")
		name := extractJSONField(line, "\"name\":\"")
		if pc != "" && name != "" {
			names[pc] = name
		}
	}
	return names, nil
}

// extractFuncNameFromAsm extracts a function name from an assembly line.
func extractFuncNameFromAsm(line string) string {
	// blutter typically has the function name as the first symbol.
	// This is a simplified parser; real blutter output may vary.
	if idx := strings.Index(line, ";"); idx >= 0 {
		return strings.TrimSpace(line[idx+1:])
	}
	return ""
}

// extractJSONField extracts a string field value from a JSON line.
func extractJSONField(line, key string) string {
	idx := strings.Index(line, key)
	if idx < 0 {
		return ""
	}
	start := idx + len(key)
	end := strings.Index(line[start:], "\"")
	if end < 0 {
		return ""
	}
	return line[start : start+end]
}

// normalizeName strips address suffixes and normalizes naming
// conventions for comparison.
func normalizeName(name string) string {
	// Strip _hex suffix.
	name = stripHexSuffix(name)
	// Strip "new " prefix (aotopsy adds it for constructors).
	name = strings.TrimPrefix(name, "new ")
	// Strip owner prefix for comparison (both tools may qualify
	// differently).
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		name = name[idx+1:]
	}
	return name
}

// countLines counts non-empty lines in a file.
func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count
}

// countBlutterClasses counts class definitions in blutter output.
func countBlutterClasses(blutterDir string) int {
	// blutter emits class info in objs.txt or pp.txt.
	// This is a simplified counter.
	path := filepath.Join(blutterDir, "objs.txt")
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "class ") {
			count++
		}
	}
	return count
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}

// SortedVAs returns sorted VAs from a name map (for deterministic output).
func SortedVAs(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
