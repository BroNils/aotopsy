package thraudit

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"

	"aotopsy/internal/jsonutil"
	"aotopsy/internal/sdk"
)

const (
	ArchARM64 = "arm64"
	ArchX64   = "x64"
)

// THRAuditRecord is a JSONL output record for thr-audit.
type THRAuditRecord struct {
	Sample      string   `json:"sample"`
	DartVersion string   `json:"dart_version"`
	Arch        string   `json:"arch"`
	PC          string   `json:"pc"`
	Insn        string   `json:"insn"`
	THROffset   string   `json:"thr_offset"`
	IsStore     bool     `json:"is_store"`
	DstReg      int      `json:"dst_reg,omitempty"`
	SrcReg      int      `json:"src_reg,omitempty"`
	Width       int      `json:"width"`
	FuncName    string   `json:"func_name"`
	Resolved    bool     `json:"resolved"`
	Context     []string `json:"context"`
}

// Band represents a contiguous group of unresolved THR offsets.
type Band struct {
	ID      int          `json:"id"`
	MinOff  int          `json:"min_offset"`
	MaxOff  int          `json:"max_offset"`
	Count   int          `json:"count"`
	Offsets []BandOffset `json:"offsets"`
}

// BandOffset is a single offset within a band, with frequency.
type BandOffset struct {
	Offset int `json:"offset"`
	Freq   int `json:"freq"`
}

// BandResult holds clustering output for one sample.
type BandResult struct {
	Sample          string `json:"sample"`
	DartVersion     string `json:"dart_version"`
	Arch            string `json:"arch"`
	TotalUnresolved int    `json:"total_unresolved"`
	Bands           []Band `json:"bands"`
}

// ClusterBands groups unresolved THR audit records into bands.
// Split threshold: gap > maxGap between consecutive unique offsets.
func ClusterBands(records []THRAuditRecord, maxGap int) (BandResult, error) {
	if maxGap < 0 {
		return BandResult{}, fmt.Errorf("thraudit: max gap must be non-negative")
	}
	sample, dartVersion, arch, err := validateRecordSet(records)
	if err != nil {
		return BandResult{}, err
	}
	// Filter unresolved only.
	var unresolved []THRAuditRecord
	for _, r := range records {
		if r.Resolved {
			continue
		}
		unresolved = append(unresolved, r)
	}

	if len(unresolved) == 0 {
		return BandResult{Sample: sample, DartVersion: dartVersion, Arch: arch}, nil
	}

	// Count frequency per offset.
	freqMap := make(map[int]int)
	for _, r := range unresolved {
		off, err := parseTHROffset(r.THROffset)
		if err != nil {
			return BandResult{}, fmt.Errorf("thraudit: %s at %s: %w", r.FuncName, r.PC, err)
		}
		freqMap[off]++
	}

	// Sort unique offsets.
	offsets := make([]int, 0, len(freqMap))
	for off := range freqMap {
		offsets = append(offsets, off)
	}
	sort.Ints(offsets)

	// Split into bands by gap.
	var bands []Band
	bandID := 0
	bandStart := 0

	for i := 1; i <= len(offsets); i++ {
		split := i == len(offsets)
		if !split {
			gap := uint64(offsets[i]) - uint64(offsets[i-1])
			if gap > uint64(maxGap) {
				split = true
			}
		}
		if split {
			bandOffsets := make([]BandOffset, 0, i-bandStart)
			totalCount := 0
			for j := bandStart; j < i; j++ {
				f := freqMap[offsets[j]]
				bandOffsets = append(bandOffsets, BandOffset{Offset: offsets[j], Freq: f})
				totalCount += f
			}
			bands = append(bands, Band{
				ID:      bandID,
				MinOff:  offsets[bandStart],
				MaxOff:  offsets[i-1],
				Count:   totalCount,
				Offsets: bandOffsets,
			})
			bandID++
			bandStart = i
		}
	}

	return BandResult{
		Sample:          sample,
		DartVersion:     dartVersion,
		Arch:            arch,
		TotalUnresolved: len(unresolved),
		Bands:           bands,
	}, nil
}

// WriteBandsJSON writes the band result as JSON.
func WriteBandsJSON(w io.Writer, br BandResult) error {
	// Retained for streaming callers; durable file publication should use
	// jsonutil.WriteJSONFile or output.WriteJSONFile.
	b, err := marshalBands(br)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// WriteBandsMD writes the band result as a markdown table.
func WriteBandsMD(w io.Writer, br BandResult) error {
	writef := func(format string, args ...any) error {
		_, err := fmt.Fprintf(w, format, args...)
		return err
	}
	if err := writef("# THR Unresolved Bands: %s (Dart %s, %s)\n\n", br.Sample, br.DartVersion, br.Arch); err != nil {
		return err
	}
	if err := writef("Total unresolved: %d\n\n", br.TotalUnresolved); err != nil {
		return err
	}
	if err := writef("| Band | Range | Slots | Count | Top Offsets |\n"); err != nil {
		return err
	}
	if err := writef("|------|-------|-------|-------|-------------|\n"); err != nil {
		return err
	}

	for _, b := range br.Bands {
		slots := (b.MaxOff-b.MinOff)/8 + 1
		topOffsets := topN(b.Offsets, 10)
		if err := writef("| %d | 0x%03x–0x%03x | %d | %d | %s |\n",
			b.ID, b.MinOff, b.MaxOff, slots, b.Count, topOffsets); err != nil {
			return err
		}
	}
	return writef("\n")
}

// topN returns a formatted string of the top N offsets by frequency.
func topN(offsets []BandOffset, n int) string {
	sorted := make([]BandOffset, len(offsets))
	copy(sorted, offsets)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Freq > sorted[j].Freq
	})
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	var parts []string
	for _, bo := range sorted {
		parts = append(parts, fmt.Sprintf("0x%x(%d)", bo.Offset, bo.Freq))
	}
	return strings.Join(parts, " ")
}

// parseTHROffset parses the canonical producer representation, e.g. "0x2f0".
// It rejects signs, trailing junk and values that cannot fit the host int.
func parseTHROffset(s string) (int, error) {
	if len(s) < 3 || !strings.HasPrefix(s, "0x") {
		return 0, fmt.Errorf("invalid THR offset %q", s)
	}
	v, err := strconv.ParseUint(s[2:], 16, 64)
	if err != nil || v > uint64(math.MaxInt) {
		return 0, fmt.Errorf("invalid THR offset %q", s)
	}
	return int(v), nil
}

// THRClass is a heuristic classification for an unresolved THR access.
type THRClass string

const (
	ClassRuntimeEntrypoint THRClass = "RUNTIME_ENTRYPOINT_ARRAY"
	ClassObjectStoreCache  THRClass = "OBJECTSTORE_OR_CACHE"
	ClassIsolateGroupPtr   THRClass = "ISOLATE_OR_GROUP_PTR"
	ClassUnknown           THRClass = "UNKNOWN"
)

// ClassifiedRecord is a classified THR audit record.
type ClassifiedRecord struct {
	THRAuditRecord
	BandID int      `json:"band_id"`
	Class  THRClass `json:"class"`
}

// ClassifySummary holds per-class counts for one sample.
type ClassifySummary struct {
	Sample      string           `json:"sample"`
	DartVersion string           `json:"dart_version"`
	Arch        string           `json:"arch"`
	Total       int              `json:"total"`
	Counts      map[THRClass]int `json:"counts"`
}

// ClassifyRecords classifies unresolved THR audit records using heuristics
// on the surrounding instruction context.
func ClassifyRecords(records []THRAuditRecord, bands BandResult) ([]ClassifiedRecord, error) {
	sample, version, arch, err := validateRecordSet(records)
	if err != nil {
		return nil, err
	}
	if sample != bands.Sample || version != bands.DartVersion || arch != bands.Arch {
		return nil, fmt.Errorf("thraudit: band provenance %q/%q/%q does not match records %q/%q/%q",
			bands.Sample, bands.DartVersion, bands.Arch, sample, version, arch)
	}
	// Build offset→bandID map.
	offsetBand := make(map[int]int)
	for _, b := range bands.Bands {
		for _, bo := range b.Offsets {
			if _, exists := offsetBand[bo.Offset]; exists {
				return nil, fmt.Errorf("thraudit: duplicate offset 0x%x across bands", bo.Offset)
			}
			offsetBand[bo.Offset] = b.ID
		}
	}

	var result []ClassifiedRecord
	for _, r := range records {
		if r.Resolved {
			continue
		}
		off, err := parseTHROffset(r.THROffset)
		if err != nil {
			return nil, err
		}
		bandID, ok := offsetBand[off]
		if !ok {
			return nil, fmt.Errorf("thraudit: unresolved offset 0x%x has no band", off)
		}

		cls := ClassifyFromContext(r)

		result = append(result, ClassifiedRecord{
			THRAuditRecord: r,
			BandID:         bandID,
			Class:          cls,
		})
	}
	return result, nil
}

// ClassifyFromContext applies heuristic rules to the instruction context.
func ClassifyFromContext(r THRAuditRecord) THRClass {
	// A THR store is not, by itself, evidence of a runtime entrypoint. Thread
	// contains many mutable fields (vm_tag, safepoint state, stack limits, etc.).
	// The old unconditional rule mislabeled every unknown store.
	if r.IsStore {
		return ClassUnknown
	}
	switch r.Arch {
	case ArchARM64:
		return classifyARM64(r)
	case ArchX64:
		return classifyX64(r)
	default:
		return ClassUnknown
	}
}

func classifyARM64(r THRAuditRecord) THRClass {

	// Find the current instruction index in context.
	curIdx := -1
	for i, line := range r.Context {
		if strings.HasPrefix(line, "> ") {
			curIdx = i
			break
		}
	}
	if curIdx < 0 {
		return ClassUnknown
	}

	// Get next 1-2 context lines.
	var next1, next2 string
	if curIdx+1 < len(r.Context) {
		next1 = strings.TrimPrefix(r.Context[curIdx+1], "  ")
	}
	if curIdx+2 < len(r.Context) {
		next2 = strings.TrimPrefix(r.Context[curIdx+2], "  ")
	}

	// Extract the destination register from the current LDR instruction.
	dstReg := extractDstReg(r.Insn)

	// Rule 1: LDR Xn → BLR Xn (direct call through entry point).
	if dstReg != "" && containsBLR(next1, dstReg) {
		return ClassRuntimeEntrypoint
	}

	// Rule 2: LDR Xn → STR Xn, [X26, ...] → BLR Xn
	// (save entry point to vm_tag, then call).
	if dstReg != "" && isSTRtoTHR(next1, dstReg) && containsBLR(next2, dstReg) {
		return ClassRuntimeEntrypoint
	}

	// Rule 3: LDR X5 → MOV X4 → LDR X30, [X26, ...]
	// (runtime entry argument passing pattern: load target, set argc, load call stub).
	if dstReg == "X5" && strings.Contains(next1, "MOV X4,") {
		if strings.Contains(next2, "LDR X30, [X26,") {
			return ClassRuntimeEntrypoint
		}
	}

	// Rule 4: LDR X9 → BLR X10 (stack overflow check pattern).
	// Context: LDR X10, [X26, #resolved] + LDR X9, [X26, #unresolved] → BLR X10
	if dstReg == "X9" && containsBLR(next1, "X10") {
		return ClassRuntimeEntrypoint
	}

	// Rule 5: LDR Xn → STUR/STR to object (not X26 base).
	// Value stored into an object field → OBJECTSTORE_OR_CACHE.
	if dstReg != "" && isStoreToObject(next1, dstReg) {
		return ClassObjectStoreCache
	}

	// Rule 6: LDR Xn → CMP Wn/Xn (type CID check or sentinel comparison).
	// The loaded value is a cached constant used for type checks.
	if dstReg != "" && isCMPwithReg(next1, dstReg) {
		return ClassObjectStoreCache
	}

	// Rule 7: LDR X0 → LDR X0, [X0, #imm] (pointer chase through THR).
	// Loads a struct pointer from THR, then dereferences a field.
	if dstReg != "" && isDerefSameReg(next1, dstReg) {
		return ClassIsolateGroupPtr
	}

	// Rule 8: LDR Xn → B (unconditional branch).
	// Load cached constant from THR in a conditional path, then branch past alternative.
	if strings.Contains(next1, "B .+") && !strings.Contains(next1, "BL ") && !strings.Contains(next1, "BLR ") {
		return ClassObjectStoreCache
	}

	return ClassUnknown
}

// classifyX64 deliberately implements only architecture-correct evidence. A
// direct THR load immediately consumed by CALL/JMP through the same canonical
// destination register is strong runtime-entrypoint evidence. Other uses stay
// UNKNOWN rather than borrowing ARM64 X26/X15 text heuristics.
func classifyX64(r THRAuditRecord) THRClass {
	if r.DstReg < 0 || r.DstReg > 15 {
		return ClassUnknown
	}
	curIdx := currentContextIndex(r.Context)
	if curIdx < 0 || curIdx+1 >= len(r.Context) {
		return ClassUnknown
	}
	reg := strings.ToUpper(sdk.X86RegName(r.DstReg))
	if reg == "" {
		return ClassUnknown
	}
	next := strings.ToUpper(strings.TrimPrefix(r.Context[curIdx+1], "  "))
	if containsRegOperand(next, "CALL "+reg) || containsRegOperand(next, "JMP "+reg) {
		return ClassRuntimeEntrypoint
	}
	return ClassUnknown
}

func currentContextIndex(context []string) int {
	for i, line := range context {
		if strings.HasPrefix(line, "> ") {
			return i
		}
	}
	return -1
}

// extractDstReg extracts the destination register from an LDR instruction text.
// E.g., "LDR X16, [X26,#1824]" → "X16"
func extractDstReg(insn string) string {
	insn = strings.TrimSpace(insn)
	if !strings.HasPrefix(insn, "LDR ") {
		return ""
	}
	parts := strings.SplitN(insn[4:], ",", 2)
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

// containsBLR checks if an instruction line contains BLR with the given register.
// Uses word-boundary check to avoid false positives where reg (e.g. "X1")
// matches as a substring of a wider register name (e.g. "BLR X11").
func containsBLR(line, reg string) bool {
	return containsRegOperand(line, "BLR "+reg)
}

// isSTRtoTHR checks if an instruction stores the given register to THR.
func isSTRtoTHR(line, reg string) bool {
	return strings.Contains(line, "STR "+reg+", [X26,")
}

// isStoreToObject checks if an instruction stores the register to a non-THR address.
func isStoreToObject(line, reg string) bool {
	// Match STUR Wn/Xn or STR Wn/Xn where the register number matches.
	regNum := strings.TrimPrefix(reg, "X")
	wReg := "W" + regNum
	if strings.Contains(line, "STUR "+wReg+",") || strings.Contains(line, "STUR "+reg+",") {
		if !strings.Contains(line, "[X26,") {
			return true
		}
	}
	if strings.Contains(line, "STR "+wReg+",") || strings.Contains(line, "STR "+reg+",") {
		if !strings.Contains(line, "[X26,") {
			return true
		}
	}
	return false
}

// isCMPwithReg checks if the instruction is a CMP using the given register
// (or its W-form equivalent).
//
// The third clause uses a word-boundary check to avoid false positives where
// wReg (e.g. "W1") matches as a substring of a wider register name (e.g.
// "W11" or "W15"). Without this, CMP X11, X2 would incorrectly match
// isCMPwithReg(line, "X1").
func isCMPwithReg(line, reg string) bool {
	regNum := strings.TrimPrefix(reg, "X")
	wReg := "W" + regNum
	if strings.Contains(line, "CMP "+wReg+",") {
		return true
	}
	if strings.Contains(line, "CMP "+reg+",") {
		return true
	}
	if !strings.Contains(line, "CMP") {
		return false
	}
	// Check ", <wReg>" with word-boundary: the character after wReg must
	// not be a digit (which would indicate a wider register like W11).
	return containsRegOperand(line, ", "+wReg) || containsRegOperand(line, ", "+reg)
}

// containsRegOperand checks if line contains substr followed by a
// non-digit character (or end of string), preventing substring matches
// like "W1" inside "W11".
func containsRegOperand(line, substr string) bool {
	idx := strings.Index(line, substr)
	for idx >= 0 {
		after := idx + len(substr)
		if after >= len(line) {
			return true
		}
		c := line[after]
		if c < '0' || c > '9' {
			return true
		}
		// Digit follows → this is a wider register (e.g. W11), keep searching.
		next := strings.Index(line[idx+1:], substr)
		if next < 0 {
			return false
		}
		idx = idx + 1 + next
	}
	return false
}

// isDerefSameReg checks if the instruction loads from the same register
// (e.g., LDR X0, [X0, #imm]).
func isDerefSameReg(line, reg string) bool {
	return strings.Contains(line, "LDR "+reg+", ["+reg+",")
}

// Summarize builds a ClassifySummary from classified records.
func Summarize(records []ClassifiedRecord) ClassifySummary {
	if len(records) == 0 {
		return ClassifySummary{}
	}
	counts := make(map[THRClass]int)
	for _, r := range records {
		counts[r.Class]++
	}
	return ClassifySummary{
		Sample:      records[0].Sample,
		DartVersion: records[0].DartVersion,
		Arch:        records[0].Arch,
		Total:       len(records),
		Counts:      counts,
	}
}

// ReadAuditRecords reads strict, bounded JSONL. Unknown/duplicate/missing keys,
// blank lines and oversized inputs are rejected by jsonutil before records are
// handed to the classifier.
func ReadAuditRecords(path string, limits jsonutil.Limits) ([]THRAuditRecord, error) {
	records, err := jsonutil.ReadJSONL[THRAuditRecord](path, limits)
	if err != nil {
		return nil, err
	}
	if _, _, _, err := validateRecordSet(records); err != nil {
		return nil, err
	}
	return records, nil
}

func validateRecordSet(records []THRAuditRecord) (sample, version, arch string, err error) {
	for i, r := range records {
		if r.Sample == "" || r.DartVersion == "" {
			return "", "", "", fmt.Errorf("thraudit: record %d missing sample/version provenance", i)
		}
		if r.Arch != ArchARM64 && r.Arch != ArchX64 {
			return "", "", "", fmt.Errorf("thraudit: record %d has unsupported architecture %q", i, r.Arch)
		}
		if _, err := parseTHROffset(r.THROffset); err != nil {
			return "", "", "", fmt.Errorf("thraudit: record %d: %w", i, err)
		}
		if i == 0 {
			sample, version, arch = r.Sample, r.DartVersion, r.Arch
			continue
		}
		if r.Sample != sample || r.DartVersion != version || r.Arch != arch {
			return "", "", "", fmt.Errorf("thraudit: mixed provenance at record %d: got %q/%q/%q, want %q/%q/%q",
				i, r.Sample, r.DartVersion, r.Arch, sample, version, arch)
		}
	}
	return sample, version, arch, nil
}

func marshalBands(br BandResult) ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(br); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}
