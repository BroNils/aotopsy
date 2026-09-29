// Package output writes aotopsy analysis results to files.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
	return writeJSON(filepath.Join(dir, "symbols.json"), symbols)
}

// WriteJSONFile atomically replaces a JSON artifact after successful encode,
// sync and close. It is shared by higher-level pipeline metadata writers that
// own their schema outside this package.
func WriteJSONFile(path string, v any) error { return writeJSON(path, v) }

// WriteASM writes disassembled instructions to asm/<name>.txt.
// name may contain path separators (e.g., "OwnerClass/func_hex") for directory grouping.
func WriteASM(dir string, name string, insts []disasm.Inst, lookup disasm.SymbolLookup, annotators ...disasm.Annotator) error {
	path, err := ArtifactPath(filepath.Join(dir, "asm"), name+".txt")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("output: mkdir asm: %w", err)
	}

	text := disasm.Format(insts, lookup, annotators...)
	return WriteAtomic(path, 0o644, func(w io.Writer) error {
		_, err := io.WriteString(w, text)
		return err
	})
}

// WriteASMSingle writes all instructions to a single asm.txt file.
func WriteASMSingle(dir string, insts []disasm.Inst, lookup disasm.SymbolLookup, annotators ...disasm.Annotator) error {
	path := filepath.Join(dir, "asm.txt")
	text := disasm.Format(insts, lookup, annotators...)
	return WriteAtomic(path, 0o644, func(w io.Writer) error {
		_, err := io.WriteString(w, text)
		return err
	})
}

// WriteBin writes raw instruction bytes to asm/<name>.bin for CFG construction.
// name may contain path separators (e.g., "OwnerClass/func_hex") for directory grouping.
func WriteBin(dir string, name string, data []byte) error {
	path, err := ArtifactPath(filepath.Join(dir, "asm"), name+".bin")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("output: mkdir asm: %w", err)
	}
	return WriteAtomic(path, 0o644, func(w io.Writer) error {
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

// ArtifactPath resolves a relative artifact name beneath base while rejecting
// absolute paths, empty/dot segments, traversal, and either slash spelling.
// Callers that derive artifact names from recovered/untrusted binary metadata
// must use this instead of filepath.Join directly.
func ArtifactPath(base, name string) (string, error) {
	if name == "" || filepath.IsAbs(name) {
		return "", fmt.Errorf("output: unsafe artifact name %q", name)
	}
	normalized := strings.ReplaceAll(name, `\`, `/`)
	localName := filepath.FromSlash(normalized)
	// filepath.IsLocal adds the platform-specific lexical checks that are easy
	// to miss here. On Windows in particular this rejects drive-relative/ADS
	// colon spellings and reserved DOS device names such as NUL and CON.
	if !filepath.IsLocal(localName) {
		return "", fmt.Errorf("output: unsafe artifact name %q", name)
	}
	for _, part := range strings.Split(normalized, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("output: unsafe artifact name %q", name)
		}
	}
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("output: resolve artifact base: %w", err)
	}
	target := filepath.Join(baseAbs, localName)
	baseCanonical, err := canonicalPath(baseAbs)
	if err != nil {
		return "", fmt.Errorf("output: resolve artifact base: %w", err)
	}
	targetCanonical, err := canonicalPath(target)
	if err != nil {
		return "", fmt.Errorf("output: resolve artifact path %q: %w", name, err)
	}
	rel, err := filepath.Rel(baseCanonical, targetCanonical)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("output: artifact name %q escapes output root", name)
	}
	return target, nil
}

// WriteAtomic publishes a complete artifact or leaves the previous artifact
// untouched. Encoding/write/sync/close failures are all observable by callers.
// It is shared by pipeline stages that need streaming renderers rather than a
// JSONL-specific writer.
func WriteAtomic(path string, perm os.FileMode, write func(io.Writer) error) (err error) {
	if write == nil {
		return fmt.Errorf("output: nil writer for %s", path)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("output: resolve %s: %w", path, err)
	}
	absPath = filepath.Clean(absPath)
	dirInput := filepath.Dir(absPath)
	finalName := filepath.Base(absPath)
	if finalName == "." || !filepath.IsLocal(finalName) {
		return fmt.Errorf("output: unsafe output filename %q", finalName)
	}
	if err := os.MkdirAll(dirInput, 0o755); err != nil {
		return fmt.Errorf("output: mkdir %s: %w", dirInput, err)
	}
	dir, err := canonicalPath(dirInput)
	if err != nil {
		return fmt.Errorf("output: resolve parent %s: %w", dirInput, err)
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("output: stat parent %s: %w", dir, err)
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return fmt.Errorf("output: parent %s is not a regular directory", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("output: open parent %s: %w", dir, err)
	}
	defer func() { _ = root.Close() }()
	pinnedDir, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("output: stat pinned parent %s: %w", dir, err)
	}
	if !os.SameFile(dirInfo, pinnedDir) {
		return fmt.Errorf("output: parent %s changed while being opened", dir)
	}

	tmpName, tmp, err := makeTempFileInRoot(root, ".aotopsy-write-stage-", 0o600)
	if err != nil {
		return fmt.Errorf("output: create temp for %s: %w", path, err)
	}
	tmpInfo, err := tmp.Stat()
	if err != nil {
		_ = tmp.Close()
		_ = root.Remove(tmpName)
		return fmt.Errorf("output: stat temp for %s: %w", path, err)
	}
	defer func() {
		_ = tmp.Close()
		if tmpName != "" {
			if exists, same, _ := fileNameHasIdentity(root, tmpName, tmpInfo); exists && same {
				_ = root.Remove(tmpName)
			}
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		return fmt.Errorf("output: chmod temp for %s: %w", path, err)
	}
	if err := write(tmp); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("output: sync %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("output: close %s: %w", path, err)
	}
	exists, same, err := fileNameHasIdentity(root, tmpName, tmpInfo)
	if err != nil {
		return fmt.Errorf("output: verify temp for %s: %w", path, err)
	}
	if !exists || !same {
		return fmt.Errorf("output: temp for %s changed before publication", path)
	}
	if err := root.Rename(tmpName, finalName); err != nil {
		return fmt.Errorf("output: publish %s: %w", path, err)
	}
	tmpName = ""
	return nil
}

// WriteFileAtomic is the byte-slice convenience form of WriteAtomic.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return WriteAtomic(path, perm, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}
