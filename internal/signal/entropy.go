package signal

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"aotopsy/internal/jsonutil"
)

// EntropyFinding is a packed/encrypted section detection finding.
type EntropyFinding struct {
	Section string  `json:"section"`
	Offset  int     `json:"offset"`
	Size    int     `json:"size"`
	Entropy float64 `json:"entropy"`
	Verdict string  `json:"verdict"` // "packed", "encrypted", "normal"
}

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

// AnalyzeEntropy analyzes ELF sections for high-entropy (packed/encrypted) regions.
// It reads the ELF file and computes entropy for each section.
// Sections with entropy > 7.0 are flagged as "packed" or "encrypted".
func AnalyzeEntropy(libPath string) ([]EntropyFinding, error) {
	data, err := os.ReadFile(libPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", libPath, err)
	}

	var findings []EntropyFinding

	// Parse ELF header to find sections
	if len(data) < 64 {
		return findings, nil
	}
	// Check ELF magic
	if data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return findings, nil
	}
	is64Bit := data[4] == 2
	if !is64Bit {
		return findings, nil // only handle 64-bit ELF
	}

	// ELF64 header
	e_shoff := binary.LittleEndian.Uint64(data[40:48])
	e_shentsize := binary.LittleEndian.Uint16(data[58:60])
	e_shnum := binary.LittleEndian.Uint16(data[60:62])
	e_shstrndx := binary.LittleEndian.Uint16(data[62:64])

	if e_shoff == 0 || e_shnum == 0 || e_shentsize == 0 {
		return findings, nil
	}

	// ELF64 section headers are 64 bytes. Accepting a smaller entry size lets the
	// fixed-offset reads below spill into the next entry and turns malformed input
	// into made-up sections.
	if e_shentsize < 64 {
		return nil, fmt.Errorf("malformed ELF: section header entry size %d < 64", e_shentsize)
	}

	// Checked arithmetic is mandatory here: all of these fields are attacker-
	// controlled uint64s. Converting a wrapped offset to int before checking it
	// was the root cause of a slice-bounds panic on e_shoff=MaxUint64-20.
	checkedRange := func(off, size uint64) (int, int, bool) {
		if off > uint64(len(data)) || size > uint64(len(data))-off {
			return 0, 0, false
		}
		return int(off), int(off + size), true
	}
	sectionHeaderOffset := func(i uint16) (uint64, bool) {
		stride := uint64(e_shentsize)
		idx := uint64(i)
		if idx != 0 && stride > ^uint64(0)/idx {
			return 0, false
		}
		delta := idx * stride
		if e_shoff > ^uint64(0)-delta {
			return 0, false
		}
		return e_shoff + delta, true
	}

	// The whole table must fit, not merely whichever entries we happen to touch.
	lastOff, ok := sectionHeaderOffset(e_shnum - 1)
	if !ok {
		return nil, fmt.Errorf("malformed ELF: section table offset overflow")
	}
	if _, _, ok := checkedRange(lastOff, uint64(e_shentsize)); !ok {
		return nil, fmt.Errorf("malformed ELF: section table exceeds file")
	}

	// Read section header string table.
	if int(e_shstrndx) >= int(e_shnum) {
		return nil, fmt.Errorf("malformed ELF: shstrndx %d >= section count %d", e_shstrndx, e_shnum)
	}
	shstrtabOff, ok := sectionHeaderOffset(e_shstrndx)
	if !ok {
		return nil, fmt.Errorf("malformed ELF: string-table section offset overflow")
	}
	shStart, _, ok := checkedRange(shstrtabOff, uint64(e_shentsize))
	if !ok {
		return nil, fmt.Errorf("malformed ELF: string-table section header out of bounds")
	}
	shstrtabShOff := binary.LittleEndian.Uint64(data[shStart+24 : shStart+32])
	shstrtabSize := binary.LittleEndian.Uint64(data[shStart+32 : shStart+40])
	shstrStart, shstrEnd, ok := checkedRange(shstrtabShOff, shstrtabSize)
	if !ok {
		return nil, fmt.Errorf("malformed ELF: section-name string table out of bounds")
	}

	// A valid ELF normally scans each file byte at most once across its sections.
	// Permit one file's worth of overlap for unusual toolchains, but reject a
	// hostile table that aliases the same giant byte range thousands of times.
	maxEntropyBytes := uint64(len(data)) * 2
	if len(data) > int(^uint(0)>>1)/2 { // defensive on theoretical huge slices
		maxEntropyBytes = ^uint64(0)
	}
	var entropyBytes uint64

	// Analyze each section
	for i := uint16(0); i < e_shnum; i++ {
		shOff, ok := sectionHeaderOffset(i)
		if !ok {
			return nil, fmt.Errorf("malformed ELF: section %d header offset overflow", i)
		}
		shStart, _, ok := checkedRange(shOff, uint64(e_shentsize))
		if !ok {
			return nil, fmt.Errorf("malformed ELF: section %d header out of bounds", i)
		}
		shName := binary.LittleEndian.Uint32(data[shStart : shStart+4])
		shType := binary.LittleEndian.Uint32(data[shStart+4 : shStart+8])
		shAddr := binary.LittleEndian.Uint64(data[shStart+16 : shStart+24])
		shOffset := binary.LittleEndian.Uint64(data[shStart+24 : shStart+32])
		shSize := binary.LittleEndian.Uint64(data[shStart+32 : shStart+40])

		// Skip NOBITS sections (BSS)
		if shType == 8 { // SHT_NOBITS
			continue
		}
		if shSize == 0 || shOffset == 0 {
			continue
		}

		// Get section name
		name := ""
		if uint64(shName) < shstrtabSize {
			nameStart := shstrStart + int(shName)
			nameEnd := nameStart
			for nameEnd < shstrEnd && data[nameEnd] != 0 {
				nameEnd++
			}
			name = string(data[nameStart:nameEnd])
		}
		if name == "" {
			name = fmt.Sprintf("section_%d", i)
		}

		// Compute entropy for this section
		sectionStart, sectionEnd, ok := checkedRange(shOffset, shSize)
		if !ok {
			return nil, fmt.Errorf("malformed ELF: section %d range [0x%x,+0x%x) exceeds file", i, shOffset, shSize)
		}
		if entropyBytes > maxEntropyBytes-shSize {
			return nil, fmt.Errorf("malformed ELF: entropy scan budget exceeded (%d bytes > %d)", entropyBytes+shSize, maxEntropyBytes)
		}
		entropyBytes += shSize
		sectionData := data[sectionStart:sectionEnd]
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
				Offset:  int(shOffset),
				Size:    int(shSize),
				Entropy: entropy,
				Verdict: verdict,
			})
		}

		_ = shAddr // available if needed
	}

	return findings, nil
}

// WriteEntropyFindings writes entropy findings to entropy_findings.jsonl.
func WriteEntropyFindings(outDir, libPath string) error {
	findings, err := AnalyzeEntropy(libPath)
	if err != nil {
		return err // surface the read/parse error instead of swallowing it
	}
	path := filepath.Join(outDir, "entropy_findings.jsonl")
	if _, err := jsonutil.WriteJSONLFile(path, findings); err != nil {
		return fmt.Errorf("write entropy findings: %w", err)
	}
	return nil
}
