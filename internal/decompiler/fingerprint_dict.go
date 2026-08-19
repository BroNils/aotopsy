package decompiler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// FunctionFingerprint is a content hash of a function's raw instruction
// bytes, used to identify the same function across different compiled
// binaries. Functions compiled from the same Dart source with the same
// SDK version, arch, and compiler flags produce near-identical machine
// code, so the same fingerprint appears in multiple apps.
//
// This is the implementation of Tier 4 item 13 (known-function
// dictionary): hash compiled bodies from the SDK and popular packages,
// then match unnamed functions (sub_*) against the dictionary to
// recover their names.
//
// The hash is computed over the raw instruction bytes only (not the
// function's metadata), because the same source compiled into two
// different apps produces the same instructions but different pool
// entries, different ref IDs, and potentially different owner names.
// The instruction bytes are the stable identity.
type FunctionFingerprint struct {
	Hash     string // SHA-256 of instruction bytes
	Size     int    // instruction byte count
	FuncName string // recovered name (empty if unknown)
	Owner    string // owning class (empty if unknown)
}

// ComputeFingerprint hashes a function's raw instruction bytes.
// The code slice is the function's machine code bytes (from
// FuncIR or CodeRange), and the name/owner are the resolved names
// (empty for unnamed functions).
func ComputeFingerprint(code []byte, name, owner string) FunctionFingerprint {
	h := sha256.Sum256(code)
	return FunctionFingerprint{
		Hash:     hex.EncodeToString(h[:]),
		Size:     len(code),
		FuncName: name,
		Owner:    owner,
	}
}

// FunctionDictionary is a lookup from instruction-byte hash to
// function name. Built from samples where names ARE recovered
// (via symtab, snapshot metadata, or other means), then applied
// to samples where names are NOT recovered.
//
// Usage:
//  1. Build: run aotopsy on a sample with .symtab, collect
//     (hash → name) for every named function.
//  2. Apply: run aotopsy on a stripped sample, look up each
//     unnamed function's hash in the dictionary.
//
// The dictionary is version- and architecture-specific: the same
// Dart source compiled with different SDK versions or different
// target architectures produces different machine code. Callers
// must build and apply per (DartVersion, Arch) pair.
type FunctionDictionary struct {
	entries map[string]FunctionFingerprint
}

// NewFunctionDictionary creates an empty dictionary.
func NewFunctionDictionary() *FunctionDictionary {
	return &FunctionDictionary{entries: make(map[string]FunctionFingerprint)}
}

// Add registers a function's fingerprint in the dictionary.
// If the function has a name, it becomes a seed for cross-sample
// name transfer. If the function is unnamed (sub_*), it is still
// recorded so that duplicate detection works.
func (d *FunctionDictionary) Add(fp FunctionFingerprint) {
	if existing, ok := d.entries[fp.Hash]; ok {
		// Keep the named entry if one exists.
		if existing.FuncName != "" && fp.FuncName == "" {
			return
		}
	}
	d.entries[fp.Hash] = fp
}

// Lookup returns the function name for a given instruction-byte hash,
// or ("", false) if the hash is not in the dictionary.
func (d *FunctionDictionary) Lookup(hash string) (string, string, bool) {
	fp, ok := d.entries[hash]
	if !ok || fp.FuncName == "" {
		return "", "", false
	}
	return fp.FuncName, fp.Owner, true
}

// LookupCode hashes the code bytes and looks up the result.
func (d *FunctionDictionary) LookupCode(code []byte) (string, string, bool) {
	h := sha256.Sum256(code)
	return d.Lookup(hex.EncodeToString(h[:]))
}

// Size returns the number of entries in the dictionary.
func (d *FunctionDictionary) Size() int {
	return len(d.entries)
}

// NamedCount returns the number of entries with a non-empty function name.
func (d *FunctionDictionary) NamedCount() int {
	count := 0
	for _, fp := range d.entries {
		if fp.FuncName != "" {
			count++
		}
	}
	return count
}

// Export serializes the dictionary to a text format for persistence.
// Each line: hash size name owner
func (d *FunctionDictionary) Export() string {
	hashes := make([]string, 0, len(d.entries))
	for h := range d.entries {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	var b strings.Builder
	for _, h := range hashes {
		fp := d.entries[h]
		// Skip unnamed entries — they don't help cross-sample transfer.
		if fp.FuncName == "" {
			continue
		}
		fmt.Fprintf(&b, "%s %d %s %s\n", fp.Hash, fp.Size, fp.FuncName, fp.Owner)
	}
	return b.String()
}

// Import loads a dictionary from the text format produced by Export.
func ImportDictionary(text string) *FunctionDictionary {
	d := NewFunctionDictionary()
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var hash string
		var size int
		var name, owner string
		n, err := fmt.Sscanf(line, "%s %d %s %s", &hash, &size, &name, &owner)
		if err != nil || n < 3 {
			continue
		}
		d.entries[hash] = FunctionFingerprint{Hash: hash, Size: size, FuncName: name, Owner: owner}
	}
	return d
}
