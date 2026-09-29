package analysis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"aotopsy/internal/disasm"
	"aotopsy/internal/strutil"
)

const (
	maxMetadataArtifactBytes = int64(64 << 20)
	maxAsmArtifactBytes      = int64(4 << 20)
	maxFunctionBinBytes      = int64(64 << 20)
)

// readFileBounded prevents a reused/corrupted output directory from turning a
// small metadata read into unbounded memory amplification. It reads at most
// limit+1 bytes so the size violation is detected even for pseudo-files whose
// stat size is not trustworthy.
func readFileBounded(path string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("read %s: invalid byte limit %d", path, limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	r := io.LimitReader(f, limit+1)
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("artifact exceeds %d-byte limit", limit)
	}
	return b, nil
}

func readJSONBounded[T any](path string, limit int64) (T, error) {
	var out T
	b, err := readFileBounded(path, limit)
	if err != nil {
		return out, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("decode %s: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return out, fmt.Errorf("decode %s: multiple JSON values", path)
		}
		return out, fmt.Errorf("decode trailing data in %s: %w", path, err)
	}
	return out, nil
}

// DisasmArtifactFiles binds functions.jsonl to index.jsonl by the producer-owned
// function identity (RefID, PCOffset), not by row order. index.jsonl is the
// canonical artifact-path surface; reconstructing paths from qualified names is
// unsound because closure naming and filename sanitization are not reversible.
func DisasmArtifactFiles(funcs []disasm.FuncRecord, index []strutil.DisasmIndexEntry) (map[string]string, error) {
	if len(funcs) != len(index) {
		return nil, fmt.Errorf("disassembly artifact index mismatch: functions=%d index=%d", len(funcs), len(index))
	}
	type identity struct {
		refID    int
		pcOffset uint32
	}
	indexByID := make(map[identity]strutil.DisasmIndexEntry, len(index))
	for i, idx := range index {
		id := identity{refID: idx.RefID, pcOffset: idx.PCOffset}
		if _, dup := indexByID[id]; dup {
			return nil, fmt.Errorf("disassembly artifact index has duplicate identity ref=%d pc_offset=%#x at record %d", idx.RefID, idx.PCOffset, i+1)
		}
		indexByID[id] = idx
	}
	out := make(map[string]string, len(funcs))
	for i := range funcs {
		f := funcs[i]
		id := identity{refID: f.RefID, pcOffset: f.PCOffset}
		idx, ok := indexByID[id]
		if !ok {
			return nil, fmt.Errorf("disassembly artifact index missing identity ref=%d pc_offset=%#x for function record %d", f.RefID, f.PCOffset, i+1)
		}
		if f.Name == "" || f.Size < 0 || int(idx.Size) != f.Size {
			return nil, fmt.Errorf("disassembly artifact index mismatch at record %d", i+1)
		}
		rel := filepath.Clean(filepath.FromSlash(idx.File))
		if filepath.IsAbs(rel) || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("disassembly artifact index has unsafe path %q", idx.File)
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 2 || parts[0] != "asm" || filepath.Ext(rel) != ".txt" {
			return nil, fmt.Errorf("disassembly artifact index has invalid asm path %q", idx.File)
		}
		if prior, dup := out[f.Name]; dup {
			// Dart can emit multiple Code objects that share one deduplicated
			// machine-code range. They consequently have distinct snapshot
			// identities but the same resolved display name and the same canonical
			// asm artifact. A function name is therefore not globally unique.
			//
			// Accept only that exact aliasing case. Two identities with the same
			// display name but different artifacts would make a name-keyed consumer
			// ambiguous and must still fail loudly rather than selecting one by row
			// order.
			if prior != rel {
				return nil, fmt.Errorf("disassembly artifact index has ambiguous function name %q: %q and %q", f.Name, prior, rel)
			}
			continue
		}
		out[f.Name] = rel
	}
	return out, nil
}

// ReadFunctionBin reads the raw machine-code sibling of a canonical asm/index
// path from asmRoot under a strict per-function budget and requires its length
// to agree with functions.jsonl. asmRoot is the directory corresponding to the
// producer's top-level "asm" directory; callers may substitute an explicitly
// relocated copy without reconstructing filenames from display names.
func ReadFunctionBin(asmRoot, txtRel string, expectedSize int) ([]byte, error) {
	if expectedSize < 0 || int64(expectedSize) > maxFunctionBinBytes {
		return nil, fmt.Errorf("invalid function size %d (limit %d)", expectedSize, maxFunctionBinBytes)
	}
	rel := filepath.Clean(txtRel)
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if filepath.IsAbs(rel) || len(parts) < 2 || parts[0] != "asm" || filepath.Ext(rel) != ".txt" {
		return nil, fmt.Errorf("invalid canonical asm artifact path %q", txtRel)
	}
	underAsm, err := filepath.Rel("asm", rel)
	if err != nil || underAsm == "." || underAsm == ".." || strings.HasPrefix(underAsm, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("canonical asm artifact path %q escapes asm root", txtRel)
	}
	binRel := strings.TrimSuffix(underAsm, filepath.Ext(underAsm)) + ".bin"
	b, err := readFileBounded(filepath.Join(asmRoot, binRel), maxFunctionBinBytes)
	if err != nil {
		return nil, err
	}
	if len(b) != expectedSize {
		return nil, fmt.Errorf("function bin size %d does not match metadata size %d", len(b), expectedSize)
	}
	return b, nil
}
