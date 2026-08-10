package signal

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
)

// EntropyFinding is a packed/encrypted section detection finding.
type EntropyFinding struct {
	Section    string  `json:"section"`
	Offset     int     `json:"offset"`
	Size       int     `json:"size"`
	Entropy    float64 `json:"entropy"`
	Verdict    string  `json:"verdict"` // "packed", "encrypted", "normal"
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

	// Read section header string table
	if int(e_shstrndx) >= int(e_shnum) {
		return findings, nil
	}
	shstrtabOff := e_shoff + uint64(e_shstrndx)*uint64(e_shentsize)
	if int(shstrtabOff)+40 > len(data) {
		return findings, nil
	}
	shstrtabShOff := binary.LittleEndian.Uint64(data[shstrtabOff+24:shstrtabOff+32])
	shstrtabSize := binary.LittleEndian.Uint64(data[shstrtabOff+32:shstrtabOff+40])

	// Analyze each section
	for i := uint16(0); i < e_shnum; i++ {
		shOff := e_shoff + uint64(i)*uint64(e_shentsize)
		if int(shOff)+40 > len(data) {
			break
		}
		shName := binary.LittleEndian.Uint32(data[shOff:shOff+4])
		shType := binary.LittleEndian.Uint32(data[shOff+4:shOff+8])
		shAddr := binary.LittleEndian.Uint64(data[shOff+16:shOff+24])
		shOffset := binary.LittleEndian.Uint64(data[shOff+24:shOff+32])
		shSize := binary.LittleEndian.Uint64(data[shOff+32:shOff+40])

		// Skip NOBITS sections (BSS)
		if shType == 8 { // SHT_NOBITS
			continue
		}
		if shSize == 0 || shOffset == 0 {
			continue
		}

		// Get section name
		name := ""
		if shstrtabShOff+uint64(shName) < shstrtabShOff+shstrtabSize && int(shstrtabShOff+uint64(shName)) < len(data) {
			nameEnd := int(shstrtabShOff + uint64(shName))
			for nameEnd < len(data) && data[nameEnd] != 0 && nameEnd < int(shstrtabShOff+shstrtabSize) {
				nameEnd++
			}
			name = string(data[shstrtabShOff+uint64(shName) : nameEnd])
		}
		if name == "" {
			name = fmt.Sprintf("section_%d", i)
		}

		// Compute entropy for this section
		end := shOffset + shSize
		if end > uint64(len(data)) {
			end = uint64(len(data))
		}
		if shOffset >= end {
			continue
		}
		sectionData := data[shOffset:end]
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
	if len(findings) == 0 {
		return nil
	}
	path := filepath.Join(outDir, "entropy_findings.jsonl")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, e := range findings {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}
