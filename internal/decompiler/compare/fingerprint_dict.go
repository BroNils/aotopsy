package compare

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	functionDictionarySchema        = 1
	defaultDictionaryMaxBytes int64 = 64 << 20
	maxDictionaryLineBytes          = 1 << 20
)

// FunctionFingerprint is a content hash of raw instruction bytes. It is useful
// for finding cross-binary CANDIDATES, not proving semantic function identity:
// pool-relative instructions can be byte-identical while the referenced object
// pool entries differ, and trivial functions can share machine code.
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
	Hash     string `json:"hash"`            // SHA-256 of instruction bytes
	Size     int    `json:"size"`            // instruction byte count
	FuncName string `json:"name"`            // recovered name (empty if unknown)
	Owner    string `json:"owner,omitempty"` // owning class (empty if unknown)
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

// FunctionDictionary is a lookup from instruction-byte hash to candidate name.
// Consumers must treat Lookup/LookupCode as heuristic evidence and must not
// overwrite authoritative snapshot/compiler metadata from it alone.
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
	dartVersion string
	arch        string
	entries     map[string]FunctionFingerprint
	ambiguous   map[string]bool
}

type dictionaryMetadata struct {
	Kind        string `json:"kind"`
	Schema      int    `json:"schema"`
	DartVersion string `json:"dart_version"`
	Arch        string `json:"arch"`
}

type dictionaryFunctionLine struct {
	Kind     string `json:"kind"`
	Hash     string `json:"hash"`
	Size     int    `json:"size"`
	FuncName string `json:"name"`
	Owner    string `json:"owner,omitempty"`
}

// NewFunctionDictionary creates an empty dictionary pinned to one exact Dart
// SDK version and architecture. Cross-version/cross-architecture transfer is
// not a supported mode: identical instruction bytes are not enough evidence to
// transfer semantic names across a compiler/ABI boundary.
func NewFunctionDictionary(dartVersion, arch string) (*FunctionDictionary, error) {
	if dartVersion == "" {
		return nil, fmt.Errorf("fingerprint dictionary: empty Dart version")
	}
	if arch != "arm64" && arch != "x64" {
		return nil, fmt.Errorf("fingerprint dictionary: unsupported arch %q", arch)
	}
	return &FunctionDictionary{
		dartVersion: dartVersion,
		arch:        arch,
		entries:     make(map[string]FunctionFingerprint),
		ambiguous:   make(map[string]bool),
	}, nil
}

func (d *FunctionDictionary) DartVersion() string { return d.dartVersion }
func (d *FunctionDictionary) Arch() string        { return d.arch }

// ValidateTarget refuses a dictionary whose compiler/ABI identity differs
// from the snapshot being analysed.
func (d *FunctionDictionary) ValidateTarget(dartVersion, arch string) error {
	if d == nil {
		return fmt.Errorf("fingerprint dictionary: nil dictionary")
	}
	if d.dartVersion != dartVersion || d.arch != arch {
		return fmt.Errorf("fingerprint dictionary target mismatch: dictionary=%s/%s binary=%s/%s",
			d.dartVersion, d.arch, dartVersion, arch)
	}
	return nil
}

// Add registers a function's fingerprint in the dictionary.
// If the function has a name, it becomes a seed for cross-sample
// name transfer. If the function is unnamed (sub_*), it is still
// recorded so that duplicate detection works.
func (d *FunctionDictionary) Add(fp FunctionFingerprint) {
	if existing, ok := d.entries[fp.Hash]; ok {
		if existing.FuncName != "" && fp.FuncName != "" &&
			(existing.FuncName != fp.FuncName || existing.Owner != fp.Owner) {
			d.ambiguous[fp.Hash] = true
			return
		}
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
	if !ok || fp.FuncName == "" || d.ambiguous[hash] {
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
		if fp.FuncName != "" && !d.ambiguous[fp.Hash] {
			count++
		}
	}
	return count
}

// Export serializes the dictionary as deterministic JSONL. The first line is
// mandatory metadata; subsequent lines are named functions. No legacy
// versionless format is accepted because silently applying it defeats the
// dictionary's safety contract.
func (d *FunctionDictionary) Export() (string, error) {
	if err := d.ValidateTarget(d.dartVersion, d.arch); err != nil {
		return "", err
	}
	hashes := make([]string, 0, len(d.entries))
	for h := range d.entries {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	var b strings.Builder
	meta := dictionaryMetadata{Kind: "metadata", Schema: functionDictionarySchema, DartVersion: d.dartVersion, Arch: d.arch}
	if err := encodeDictionaryLine(&b, meta); err != nil {
		return "", err
	}
	for _, h := range hashes {
		fp := d.entries[h]
		// Skip unnamed entries — they don't help cross-sample transfer.
		if fp.FuncName == "" || d.ambiguous[h] {
			continue
		}
		line := dictionaryFunctionLine{Kind: "function", Hash: fp.Hash, Size: fp.Size, FuncName: fp.FuncName, Owner: fp.Owner}
		if err := encodeDictionaryLine(&b, line); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

func encodeDictionaryLine(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// ImportDictionary loads a metadata-bearing JSONL dictionary from r with a
// total byte budget. The reader is never first materialized with os.ReadFile,
// so an attacker-controlled dictionary cannot force an unbounded allocation
// before the limit is checked.
func ImportDictionary(r io.Reader, maxBytes int64) (*FunctionDictionary, error) {
	if maxBytes <= 0 {
		maxBytes = defaultDictionaryMaxBytes
	}
	lr := &io.LimitedReader{R: r, N: maxBytes + 1}
	s := bufio.NewScanner(lr)
	s.Buffer(make([]byte, 64<<10), maxDictionaryLineBytes)
	lineNo := 0
	var d *FunctionDictionary
	for s.Scan() {
		lineNo++
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		if d == nil {
			var meta dictionaryMetadata
			if err := decodeDictionaryLine(line, &meta); err != nil {
				return nil, fmt.Errorf("dictionary line %d metadata: %w", lineNo, err)
			}
			if meta.Kind != "metadata" || meta.Schema != functionDictionarySchema {
				return nil, fmt.Errorf("dictionary line %d: unsupported metadata kind/schema", lineNo)
			}
			var err error
			d, err = NewFunctionDictionary(meta.DartVersion, meta.Arch)
			if err != nil {
				return nil, fmt.Errorf("dictionary line %d: %w", lineNo, err)
			}
			continue
		}
		var rec dictionaryFunctionLine
		if err := decodeDictionaryLine(line, &rec); err != nil {
			return nil, fmt.Errorf("dictionary line %d: %w", lineNo, err)
		}
		if rec.Kind != "function" {
			return nil, fmt.Errorf("dictionary line %d: unexpected kind %q", lineNo, rec.Kind)
		}
		fp := FunctionFingerprint{Hash: rec.Hash, Size: rec.Size, FuncName: rec.FuncName, Owner: rec.Owner}
		if len(fp.Hash) != sha256.Size*2 || fp.Size <= 0 || fp.FuncName == "" {
			return nil, fmt.Errorf("dictionary line %d: invalid required fields", lineNo)
		}
		if _, err := hex.DecodeString(fp.Hash); err != nil {
			return nil, fmt.Errorf("dictionary line %d: invalid hash: %w", lineNo, err)
		}
		d.Add(fp)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("dictionary scan: %w", err)
	}
	if lr.N <= 0 {
		return nil, fmt.Errorf("dictionary exceeds %d-byte limit", maxBytes)
	}
	if d == nil {
		return nil, fmt.Errorf("dictionary: missing metadata")
	}
	return d, nil
}

func decodeDictionaryLine(line string, dst any) error {
	dec := json.NewDecoder(strings.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return fmt.Errorf("trailing data: %w", err)
	}
	return nil
}
