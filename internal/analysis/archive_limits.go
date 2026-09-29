package analysis

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// APKs are untrusted input. These limits are intentionally far above the
// libapp.so sizes in the local corpus while preventing a tiny compressed entry
// from expanding without bound onto disk or through the heap.
const (
	maxLibappEntryBytes    uint64 = 256 << 20 // 256 MiB per native library
	maxNestedAPKBytes      uint64 = 512 << 20 // 512 MiB per nested APK
	maxArchiveProbeBytes   uint64 = 512 << 20 // aggregate .so bytes examined per APK level
	maxArchiveWorkBytes    uint64 = 1 << 30   // cumulative declared/expanded work across outer+nested archives
	maxArchiveCandidates          = 128
	maxNestedAPKCandidates        = 32
)

type archiveWorkBudget struct {
	declared uint64
	expanded uint64
}

func (b *archiveWorkBudget) reserveDeclared(name string, n uint64) error {
	if b == nil {
		return nil
	}
	if n > maxArchiveWorkBytes || b.declared > maxArchiveWorkBytes-n {
		return fmt.Errorf("archive %q exceeds %d-byte cumulative declared expansion budget", name, maxArchiveWorkBytes)
	}
	b.declared += n
	return nil
}

func (b *archiveWorkBudget) chargeExpanded(name string, n uint64) error {
	if b == nil {
		return nil
	}
	if n > maxArchiveWorkBytes || b.expanded > maxArchiveWorkBytes-n {
		return fmt.Errorf("archive %q exceeds %d-byte cumulative expanded-byte budget", name, maxArchiveWorkBytes)
	}
	b.expanded += n
	return nil
}

// extractZipEntryToTemp copies one zip entry through a hard byte limit and
// computes its SHA-256 without rereading the whole expanded file into memory.
// The caller owns the returned path and must remove it.
func extractZipEntryToTemp(f *zip.File, pattern string, maxBytes uint64, work *archiveWorkBudget) (path string, n int64, sha string, err error) {
	if f.UncompressedSize64 > maxBytes {
		return "", 0, "", fmt.Errorf("zip entry %q expands to %d bytes, limit is %d", f.Name, f.UncompressedSize64, maxBytes)
	}
	if err := work.reserveDeclared(f.Name, f.UncompressedSize64); err != nil {
		return "", 0, "", err
	}
	rc, err := f.Open()
	if err != nil {
		return "", 0, "", err
	}
	defer func() { _ = rc.Close() }()

	tmp, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", 0, "", err
	}
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmp.Name())
		}
	}()

	h := sha256.New()
	// Read one byte beyond the limit so forged/unknown zip metadata cannot turn
	// the header check above into the only line of defence.
	limited := io.LimitReader(rc, int64(maxBytes)+1)
	n, err = io.Copy(io.MultiWriter(tmp, h), limited)
	if budgetErr := work.chargeExpanded(f.Name, uint64(n)); budgetErr != nil {
		return "", n, "", budgetErr
	}
	if err != nil {
		return "", n, "", err
	}
	if uint64(n) > maxBytes {
		return "", n, "", fmt.Errorf("zip entry %q exceeded %d-byte expansion limit", f.Name, maxBytes)
	}
	if err := tmp.Close(); err != nil {
		return "", n, "", err
	}
	ok = true
	return tmp.Name(), n, hex.EncodeToString(h.Sum(nil)), nil
}

func checkedArchiveBudget(total *uint64, f *zip.File, perEntry, aggregate uint64) error {
	if f.UncompressedSize64 > perEntry {
		return fmt.Errorf("archive entry %q expands to %d bytes, per-entry limit is %d", f.Name, f.UncompressedSize64, perEntry)
	}
	if *total > aggregate-f.UncompressedSize64 {
		return fmt.Errorf("archive candidate expansion exceeds %d-byte aggregate limit", aggregate)
	}
	*total += f.UncompressedSize64
	return nil
}
