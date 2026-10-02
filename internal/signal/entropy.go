package signal

import (
	"debug/elf"
	"fmt"
	"math"
	"path/filepath"

	"aotopsy/internal/elfx"
	"aotopsy/internal/jsonutil"
)

// EntropyFinding is a packed/encrypted section detection finding.
type EntropyFinding struct {
	Section string  `json:"section"`
	Offset  uint64  `json:"offset"`
	Size    uint64  `json:"size"`
	Entropy float64 `json:"entropy"`
	Verdict string  `json:"verdict"` // "packed", "encrypted", "normal"
}

const maxEntropyScanBytes = uint64(256 << 20)

// ShannonEntropy computes the Shannon entropy of a byte slice.
// Returns a value between 0 (all same byte) and 8 (perfectly random).
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// AnalyzeEntropy analyzes validated ELF sections for high-entropy
// (packed/encrypted) regions. ELF parsing and range/resource policy belong to
// elfx; this detector must not maintain a second, weaker parser for untrusted
// input. The aggregate materialized section budget also bounds alias-induced
// repeated work even when multiple non-allocated sections share file bytes.
// Sections with entropy > 7.0 are flagged as "packed" or "encrypted".
func AnalyzeEntropy(ef *elfx.File) ([]EntropyFinding, error) {
	if ef == nil {
		return nil, fmt.Errorf("entropy: nil ELF source")
	}

	var findings []EntropyFinding
	var entropyBytes uint64
	for _, s := range ef.Sections() {
		if s.Type == elf.SHT_NOBITS || s.Size == 0 {
			continue
		}
		name := s.Name
		if name == "" {
			name = fmt.Sprintf("section_%d", s.Index)
		}
		if s.Size > maxEntropyScanBytes-entropyBytes {
			return nil, fmt.Errorf("entropy: section scan budget exceeds %d bytes", maxEntropyScanBytes)
		}
		sectionData, err := ef.ReadSection(s.Index, maxEntropyScanBytes-entropyBytes)
		if err != nil {
			return nil, fmt.Errorf("entropy: read section %q: %w", name, err)
		}
		entropyBytes += s.Size
		entropy := ShannonEntropy(sectionData)

		verdict := "normal"
		if entropy > 7.5 {
			verdict = "encrypted"
		} else if entropy > 7.0 {
			verdict = "packed"
		}

		if verdict != "normal" {
			findings = append(findings, EntropyFinding{
				Section: name,
				Offset:  s.Offset,
				Size:    s.Size,
				Entropy: entropy,
				Verdict: verdict,
			})
		}
	}

	return findings, nil
}

// WriteEntropyFindings writes entropy findings to entropy_findings.jsonl using
// the same validated descriptor as the rest of the pipeline.
func WriteEntropyFindings(outDir string, source *elfx.File) error {
	findings, err := AnalyzeEntropy(source)
	if err != nil {
		return err // surface the read/parse error instead of swallowing it
	}
	path := filepath.Join(outDir, "entropy_findings.jsonl")
	if _, err := jsonutil.WriteJSONLFile(path, findings); err != nil {
		return fmt.Errorf("write entropy findings: %w", err)
	}
	return nil
}
