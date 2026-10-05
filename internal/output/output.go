// Package output writes aotopsy analysis results to files.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"aotopsy/internal/artifactfs"
	"aotopsy/internal/disasm"
	"aotopsy/internal/snapshot"
)

// WriteSnapshotInfoJSON writes parser/debug metadata. Pipeline provenance lives
// in provenance.json; sharing one filename for two incompatible schemas made
// whichever writer ran last silently destroy the other's artifact.
func WriteSnapshotInfoJSON(dir string, info *snapshot.Info) error {
	return writeJSON(filepath.Join(dir, "snapshot_info.json"), info)
}

// SymbolEntry represents a named code address.
type SymbolEntry struct {
	Address uint64 `json:"address"`
	Name    string `json:"name"`
	Size    uint64 `json:"size,omitempty"`
}

// WriteSymbolsJSON writes symbols to symbols.json.
func WriteSymbolsJSON(dir string, symbols []SymbolEntry) error {
	ordered := append([]SymbolEntry(nil), symbols...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Address != ordered[j].Address {
			return ordered[i].Address < ordered[j].Address
		}
		if ordered[i].Name != ordered[j].Name {
			return ordered[i].Name < ordered[j].Name
		}
		return ordered[i].Size < ordered[j].Size
	})
	return writeJSON(filepath.Join(dir, "symbols.json"), ordered)
}

// WriteJSONFile atomically replaces a JSON artifact after successful encode,
// sync and close. It is shared by higher-level pipeline metadata writers that
// own their schema outside this package.
func WriteJSONFile(path string, v any) error { return writeJSON(path, v) }

// WriteStagedArtifact publishes rel beneath root like WriteArtifactAtomic but
// defers fsync to the enclosing DirTransaction.Commit. root MUST be the
// unpublished stage directory of such a transaction; the pipeline writes tens of
// thousands of per-function files this way and syncing each one here as well as
// at Commit made a 8k-function app 3-4x slower than a plain write.
func WriteStagedArtifact(root, rel string, perm os.FileMode, write func(io.Writer) error) error {
	return artifactfs.WriteAtomicUnderStaged(root, rel, perm, write)
}

// WriteASM writes disassembled instructions to asm/<name>.txt into a transaction
// stage (fsync deferred to the transaction's Commit).
// name may contain path separators (e.g., "OwnerClass/func_hex") for directory grouping.
func WriteASM(dir string, name string, insts []disasm.Inst, lookup disasm.SymbolLookup, annotators ...disasm.Annotator) error {
	text := disasm.Format(insts, lookup, annotators...)
	return WriteStagedArtifact(dir, "asm/"+name+".txt", 0o644, func(w io.Writer) error {
		_, err := io.WriteString(w, text)
		return err
	})
}

// WriteASMSingle writes all instructions to a single asm.txt file.
func WriteASMSingle(dir string, insts []disasm.Inst, lookup disasm.SymbolLookup, annotators ...disasm.Annotator) error {
	text := disasm.Format(insts, lookup, annotators...)
	return WriteArtifactAtomic(dir, "asm.txt", 0o644, func(w io.Writer) error {
		_, err := io.WriteString(w, text)
		return err
	})
}

// WriteBin writes raw instruction bytes to asm/<name>.bin for CFG construction.
// name may contain path separators (e.g., "OwnerClass/func_hex") for directory grouping.
func WriteBin(dir string, name string, data []byte) error {
	return WriteStagedArtifact(dir, "asm/"+name+".bin", 0o644, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

func writeJSON(path string, v any) error {
	return WriteAtomic(path, 0o644, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return fmt.Errorf("output: encode %s: %w", path, err)
		}
		return nil
	})
}

// WriteAtomic publishes a complete artifact or leaves the previous artifact
// untouched. Encoding/write/sync/close failures are all observable by callers.
// It is shared by pipeline stages that need streaming renderers rather than a
// JSONL-specific writer.
func WriteAtomic(path string, perm os.FileMode, write func(io.Writer) error) error {
	return artifactfs.WriteAtomic(path, perm, write)
}

// WriteArtifactAtomic publishes rel beneath root without a separate path
// preflight. rel is validated with portable Windows/Unix rules and every parent
// directory is pinned while it is traversed. Use this for any path derived from
// recovered binary names.
func WriteArtifactAtomic(root, rel string, perm os.FileMode, write func(io.Writer) error) error {
	return artifactfs.WriteAtomicUnder(root, rel, perm, write)
}

// WriteFileAtomic is the byte-slice convenience form of WriteAtomic.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return WriteAtomic(path, perm, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// WriteArtifactFile is the byte-slice convenience form of WriteArtifactAtomic.
func WriteArtifactFile(root, rel string, data []byte, perm os.FileMode) error {
	return WriteArtifactAtomic(root, rel, perm, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}
