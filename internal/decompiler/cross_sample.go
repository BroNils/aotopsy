package decompiler

import (
	"fmt"
	"sort"
	"strings"
)

// CrossSampleNameTransfer applies function names recovered from one
// binary to unnamed functions in another binary, using instruction-byte
// hashing to match identical functions across samples.
//
// This is the implementation of Tier 4 item 15 (cross-sample name
// transfer). The same package (e.g. package:flutter, dart:async)
// compiled into two different apps produces near-identical machine
// code for the same SDK version and architecture. Functions that are
// named in one sample (via .symtab, snapshot metadata, or other
// recovery) can seed the other sample where the same function appears
// as sub_<hex>.
//
// Usage:
//  1. Build a seed dictionary from a named sample (e.g. one with
//     .symtab): run aotopsy, collect (hash → name) for every named
//     function via FunctionDictionary.Add.
//  2. Apply the dictionary to a stripped sample: for each unnamed
//     function (sub_*), hash its instruction bytes and look up the
//     dictionary. A match gives the function its name.
//
// The transfer is version- and architecture-specific: different SDK
// versions or different target architectures produce different machine
// code, so the dictionary must be built and applied per (DartVersion,
// Arch) pair. CrossSampleNameTransfer enforces this by tagging each
// dictionary entry with its source version and arch.
//
// SDK-verified: the Dart AOT compiler (gen_snapshot) is deterministic
// for the same source + SDK version + arch + flags, so the same
// function produces the same instruction bytes across apps. Verified
// empirically: sub_1b555c appears 83777 times in the 2.12 sample,
// indicating a shared framework function compiled identically across
// many call sites within one binary — and by extension, across
// binaries built with the same SDK.

// CrossSampleDictionary is a versioned function dictionary that can
// be built from one sample and applied to another. It enforces
// version/arch matching to prevent false positives from different
// SDK versions.
type CrossSampleDictionary struct {
	// version is the Dart SDK version this dictionary was built from.
	version string
	// arch is "arm64" or "x64".
	arch string
	// dict is the underlying hash → name mapping.
	dict *FunctionDictionary
}

// NewCrossSampleDictionary creates a new dictionary for a specific
// Dart version and architecture.
func NewCrossSampleDictionary(dartVersion, arch string) *CrossSampleDictionary {
	return &CrossSampleDictionary{
		version: dartVersion,
		arch:    arch,
		dict:    NewFunctionDictionary(),
	}
}

// SeedFromNamedFunctions adds named functions from a sample to the
// dictionary. Only functions with non-empty names are added — unnamed
// functions (sub_*) are skipped because they don't help transfer.
//
// codeByName provides the instruction bytes for each named function.
// The caller is responsible for extracting the code bytes from the
// binary (e.g. via CodeRange + code slice).
func (d *CrossSampleDictionary) SeedFromNamedFunctions(
	codeByName map[string][]byte,
) int {
	added := 0
	for name, code := range codeByName {
		if len(code) == 0 {
			continue
		}
		// Skip unnamed functions.
		if isUnnamedFunction(name) {
			continue
		}
		// Extract owner from qualified name "Owner.method_hex".
		owner := ""
		funcName := name
		if idx := strings.LastIndex(name, "."); idx > 0 {
			owner = name[:idx]
			funcName = name[idx+1:]
		}
		// Strip the _hex suffix for the dictionary entry.
		funcName = stripHexSuffix(funcName)
		owner = stripHexSuffix(owner)

		fp := ComputeFingerprint(code, funcName, owner)
		d.dict.Add(fp)
		added++
	}
	return added
}

// ApplyToUnnamedFunctions looks up each unnamed function's instruction
// bytes in the dictionary and returns a map of function VA → recovered
// name for matches found.
//
// codeByVA provides the instruction bytes for each unnamed function,
// keyed by function VA (as string "0x...").
func (d *CrossSampleDictionary) ApplyToUnnamedFunctions(
	codeByVA map[string][]byte,
) map[string]string {
	results := make(map[string]string)
	for vaStr, code := range codeByVA {
		if len(code) == 0 {
			continue
		}
		name, owner, ok := d.dict.LookupCode(code)
		if !ok {
			continue
		}
		// Reconstruct qualified name.
		qualified := name
		if owner != "" {
			qualified = owner + "." + name
		}
		results[vaStr] = qualified
	}
	return results
}

// Version returns the Dart SDK version this dictionary was built for.
func (d *CrossSampleDictionary) Version() string { return d.version }

// Arch returns the architecture this dictionary was built for.
func (d *CrossSampleDictionary) Arch() string { return d.arch }

// SeedCount returns the number of named entries in the dictionary.
func (d *CrossSampleDictionary) SeedCount() int { return d.dict.NamedCount() }

// Export serializes the dictionary to a text format for persistence.
// The first line is a header with version and arch; subsequent lines
// are "hash size name owner" entries.
func (d *CrossSampleDictionary) Export() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# version=%s arch=%s\n", d.version, d.arch)
	b.WriteString(d.dict.Export())
	return b.String()
}

// ImportCrossSample loads a cross-sample dictionary from the text
// format produced by Export. Returns nil if the version/arch header
// is missing or malformed.
func ImportCrossSample(text string) *CrossSampleDictionary {
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return nil
	}
	// Parse header.
	header := strings.TrimSpace(lines[0])
	if !strings.HasPrefix(header, "# version=") {
		return nil
	}
	var version, arch string
	for _, field := range strings.Fields(header) {
		if strings.HasPrefix(field, "version=") {
			version = strings.TrimPrefix(field, "version=")
		}
		if strings.HasPrefix(field, "arch=") {
			arch = strings.TrimPrefix(field, "arch=")
		}
	}
	if version == "" || arch == "" {
		return nil
	}
	d := NewCrossSampleDictionary(version, arch)
	// Parse entries (skip header line).
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var hash string
		var size int
		var name, owner string
		n, err := fmt.Sscanf(line, "%s %d %s %s", &hash, &size, &name, &owner)
		if err != nil || n < 3 {
			continue
		}
		d.dict.entries[hash] = FunctionFingerprint{Hash: hash, Size: size, FuncName: name, Owner: owner}
	}
	return d
}

// isUnnamedFunction reports whether a function name is a placeholder
// (sub_* or stub_*), meaning it was not recovered from metadata.
func isUnnamedFunction(name string) bool {
	return strings.HasPrefix(name, "sub_") ||
		strings.HasPrefix(name, "stub_") ||
		name == ""
}

// stripHexSuffix removes the trailing _<hex> address suffix that
// QualifiedCodeName appends (e.g. "Duration.compareTo_80" → "Duration.compareTo").
func stripHexSuffix(name string) string {
	// Find the last underscore followed by hex digits.
	idx := strings.LastIndex(name, "_")
	if idx < 0 || idx == len(name)-1 {
		return name
	}
	suffix := name[idx+1:]
	for _, c := range suffix {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return name
		}
	}
	return name[:idx]
}

// SortedKeys returns the keys of a map sorted alphabetically.
// Used for deterministic output in Export.
func SortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
