package thraudit

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"aotopsy/internal/jsonutil"
	"aotopsy/internal/sdk"
)

const (
	ArchARM64 = "arm64"
	ArchX64   = "x64"
	SchemaV1  = 1
)

type AccessMode string

const (
	AccessRead      AccessMode = "read"
	AccessWrite     AccessMode = "write"
	AccessReadWrite AccessMode = "read_write"
)

// Provenance identifies the exact analysis target that produced a THR record.
// The SHA-256 is over the opened libapp.so descriptor; Sample is only a display
// name and is deliberately not trusted as identity.
type Provenance struct {
	Sample             string `json:"sample"`
	SampleSHA256       string `json:"sample_sha256"`
	DartVersion        string `json:"dart_version"`
	Arch               string `json:"arch"`
	BuildMode          string `json:"build_mode"`
	CompressedPointers bool   `json:"compressed_pointers"`
}

// THRAuditRecord is a JSONL output record for thr-audit.
type THRAuditRecord struct {
	Provenance
	SchemaVersion int        `json:"schema_version"`
	PC            string     `json:"pc"`
	Insn          string     `json:"insn"`
	THROffset     int64      `json:"thr_offset"`
	Access        AccessMode `json:"access"`
	DstReg        *int       `json:"dst_reg,omitempty"` // GPR receiving the memory value (including an RMW old-value result), when one exists.
	SrcReg        *int       `json:"src_reg,omitempty"` // GPR source/operand when memory is written from one, when one exists.
	Width         int        `json:"width"`
	FuncName      string     `json:"func_name"`
	Resolved      bool       `json:"resolved"`
	FieldName     string     `json:"field_name,omitempty"`
	Context       []string   `json:"context"`
}

// Band represents a contiguous group of unresolved THR offsets.
type Band struct {
	ID      int          `json:"id"`
	MinOff  int64        `json:"min_offset"`
	MaxOff  int64        `json:"max_offset"`
	Count   int          `json:"count"`
	Offsets []BandOffset `json:"offsets"`
}

// BandOffset is a single offset within a band, with frequency.
type BandOffset struct {
	Offset int64 `json:"offset"`
	Freq   int   `json:"freq"`
}

// BandResult holds clustering output for one sample.
type BandResult struct {
	Provenance
	TotalUnresolved int    `json:"total_unresolved"`
	Bands           []Band `json:"bands"`
}

// ClusterBands groups unresolved THR audit records into bands.
// Split threshold: gap > maxGap between consecutive unique offsets.
func ClusterBands(records []THRAuditRecord, maxGap int64) (BandResult, error) {
	if maxGap < 0 {
		return BandResult{}, fmt.Errorf("thraudit: max gap must be non-negative")
	}
	provenance, err := validateRecordSet(records)
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
		return BandResult{Provenance: provenance}, nil
	}

	// Count frequency per offset.
	freqMap := make(map[int64]int)
	for _, r := range unresolved {
		freqMap[r.THROffset]++
	}

	// Sort unique offsets.
	offsets := make([]int64, 0, len(freqMap))
	for off := range freqMap {
		offsets = append(offsets, off)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })

	// Split into bands by gap.
	var bands []Band
	bandID := 0
	bandStart := 0

	for i := 1; i <= len(offsets); i++ {
		split := i == len(offsets)
		if !split {
			gap, ok := offsetDistance(offsets[i-1], offsets[i])
			if !ok || gap > uint64(maxGap) {
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
		Provenance:      provenance,
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
	if err := writef("| Band | Range | Distinct Offsets | Count | Top Offsets |\n"); err != nil {
		return err
	}
	if err := writef("|------|-------|------------------|-------|-------------|\n"); err != nil {
		return err
	}

	for _, b := range br.Bands {
		topOffsets := topN(b.Offsets, 10)
		if err := writef("| %d | %s–%s | %d | %d | %s |\n",
			b.ID, FormatTHROffset(b.MinOff), FormatTHROffset(b.MaxOff), len(b.Offsets), b.Count, topOffsets); err != nil {
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
		if sorted[i].Freq != sorted[j].Freq {
			return sorted[i].Freq > sorted[j].Freq
		}
		return sorted[i].Offset < sorted[j].Offset
	})
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	var parts []string
	for _, bo := range sorted {
		parts = append(parts, fmt.Sprintf("%s(%d)", FormatTHROffset(bo.Offset), bo.Freq))
	}
	return strings.Join(parts, " ")
}

// FormatTHROffset renders signed Thread-relative displacements without the
// invalid "0x-10" spelling and without overflowing on MinInt64.
func FormatTHROffset(off int64) string {
	if off >= 0 {
		return fmt.Sprintf("0x%x", uint64(off))
	}
	mag := uint64(-(off + 1)) + 1
	return fmt.Sprintf("-0x%x", mag)
}

func offsetDistance(lo, hi int64) (uint64, bool) {
	if hi < lo {
		return 0, false
	}
	if lo < 0 && hi >= 0 {
		left := uint64(-(lo + 1)) + 1
		right := uint64(hi)
		if ^uint64(0)-left < right {
			return 0, false
		}
		return left + right, true
	}
	return uint64(hi - lo), true
}

// THRClass is intentionally evidence-shaped. These labels describe only what
// the nearby machine instructions prove; they never claim that an unresolved
// offset is a specific runtime entry, ObjectStore slot, isolate, or group field.
type THRClass string

const (
	ClassIndirectControlTarget THRClass = "INDIRECT_CONTROL_TARGET"
	ClassValueStored           THRClass = "VALUE_STORED"
	ClassValueCompared         THRClass = "VALUE_COMPARED"
	ClassPointerDereference    THRClass = "POINTER_DEREFERENCE"
	ClassUnknown               THRClass = "UNKNOWN"
)

type EvidenceConfidence string

const (
	ConfidenceHeuristic  EvidenceConfidence = "heuristic"
	ConfidenceUnresolved EvidenceConfidence = "unresolved"
)

// ClassifiedRecord is a classified THR audit record.
type ClassifiedRecord struct {
	THRAuditRecord
	BandID         int                `json:"band_id"`
	HeuristicClass THRClass           `json:"heuristic_class"`
	Confidence     EvidenceConfidence `json:"confidence"`
}

// ClassifySummary holds per-class counts for one sample.
type ClassifySummary struct {
	Provenance
	Total  int              `json:"total"`
	Counts map[THRClass]int `json:"counts"`
}

// ClassifyRecords classifies unresolved THR audit records using heuristics
// on the surrounding instruction context.
func ClassifyRecords(records []THRAuditRecord, bands BandResult) ([]ClassifiedRecord, error) {
	provenance, err := validateRecordSet(records)
	if err != nil {
		return nil, err
	}
	if provenance != bands.Provenance {
		return nil, fmt.Errorf("thraudit: band provenance does not match audit records")
	}
	// Build offset→bandID map.
	offsetBand := make(map[int64]int)
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
		bandID, ok := offsetBand[r.THROffset]
		if !ok {
			return nil, fmt.Errorf("thraudit: unresolved offset %s has no band", FormatTHROffset(r.THROffset))
		}

		cls := ClassifyFromContext(r)
		confidence := ConfidenceHeuristic
		if cls == ClassUnknown {
			confidence = ConfidenceUnresolved
		}

		result = append(result, ClassifiedRecord{
			THRAuditRecord: r,
			BandID:         bandID,
			HeuristicClass: cls,
			Confidence:     confidence,
		})
	}
	return result, nil
}

// ClassifyFromContext applies heuristic rules to the instruction context.
func ClassifyFromContext(r THRAuditRecord) THRClass {
	// Classification is deliberately limited to read-only observations. A write
	// or read-modify-write says that Thread state changes, but it does not identify
	// which semantic field was changed.
	if r.Access != AccessRead {
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

	// Use the decoder-produced register identity rather than reparsing disassembly
	// text. This also keeps paired LDP reads classifiable as separate records.
	dstReg := ""
	if r.DstReg != nil && *r.DstReg >= 0 && *r.DstReg <= 30 {
		dstReg = fmt.Sprintf("X%d", *r.DstReg)
	}

	// LDR Xn → BLR Xn proves only that the loaded value becomes an indirect
	// control-flow target. The field may be a stub, runtime entry, or something
	// else; naming the category "runtime entrypoint" would overclaim.
	if dstReg != "" && containsBLR(next1, dstReg) {
		return ClassIndirectControlTarget
	}

	// LDR Xn → STR Xn, [X26,...] → BLR Xn still proves only eventual indirect
	// control transfer through the loaded value.
	if dstReg != "" && isSTRtoTHR(next1, dstReg) && containsBLR(next2, dstReg) {
		return ClassIndirectControlTarget
	}

	// A subsequent store proves data-flow use only, not ObjectStore/cache identity.
	if dstReg != "" && isStoreToObject(next1, dstReg) {
		return ClassValueStored
	}

	// A comparison proves the loaded value is compared. It does not prove that it
	// is a type, sentinel, or cached object.
	if dstReg != "" && isCMPwithReg(next1, dstReg) {
		return ClassValueCompared
	}

	// Pointer chase is structural evidence only; the pointee could be any Thread
	// pointer field, not specifically Isolate/IsolateGroup.
	if dstReg != "" && isDerefSameReg(next1, dstReg) {
		return ClassPointerDereference
	}

	return ClassUnknown
}

// classifyX64 deliberately implements only architecture-correct structural
// evidence. A direct THR memory CALL/JMP, or a loaded register immediately used
// as CALL/JMP target, proves indirect control flow but not the semantic field.
func classifyX64(r THRAuditRecord) THRClass {
	upperInsn := strings.ToUpper(strings.TrimSpace(r.Insn))
	if (strings.HasPrefix(upperInsn, "CALL ") || strings.HasPrefix(upperInsn, "JMP ")) && strings.Contains(upperInsn, "[R14") {
		return ClassIndirectControlTarget
	}
	if r.DstReg == nil || *r.DstReg < 0 || *r.DstReg > 15 {
		return ClassUnknown
	}
	curIdx := currentContextIndex(r.Context)
	if curIdx < 0 || curIdx+1 >= len(r.Context) {
		return ClassUnknown
	}
	reg := strings.ToUpper(sdk.X86RegName(*r.DstReg))
	if reg == "" {
		return ClassUnknown
	}
	next := strings.ToUpper(strings.TrimPrefix(r.Context[curIdx+1], "  "))
	if containsRegOperand(next, "CALL "+reg) || containsRegOperand(next, "JMP "+reg) {
		return ClassIndirectControlTarget
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
		counts[r.HeuristicClass]++
	}
	return ClassifySummary{
		Provenance: records[0].Provenance,
		Total:      len(records),
		Counts:     counts,
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
	if _, err := validateRecordSet(records); err != nil {
		return nil, err
	}
	return records, nil
}

func validateRecordSet(records []THRAuditRecord) (Provenance, error) {
	var provenance Provenance
	for i, r := range records {
		if r.SchemaVersion != SchemaV1 {
			return Provenance{}, fmt.Errorf("thraudit: record %d schema_version=%d, want %d", i, r.SchemaVersion, SchemaV1)
		}
		if r.Sample == "" || r.DartVersion == "" || r.BuildMode == "" {
			return Provenance{}, fmt.Errorf("thraudit: record %d missing sample/version/profile provenance", i)
		}
		if len(r.SampleSHA256) != 64 {
			return Provenance{}, fmt.Errorf("thraudit: record %d has invalid sample_sha256", i)
		}
		if raw, decodeErr := hex.DecodeString(r.SampleSHA256); decodeErr != nil || len(raw) != 32 || r.SampleSHA256 != strings.ToLower(r.SampleSHA256) {
			return Provenance{}, fmt.Errorf("thraudit: record %d has invalid sample_sha256", i)
		}
		if r.Arch != ArchARM64 && r.Arch != ArchX64 {
			return Provenance{}, fmt.Errorf("thraudit: record %d has unsupported architecture %q", i, r.Arch)
		}
		if !strings.HasPrefix(r.PC, "0x") {
			return Provenance{}, fmt.Errorf("thraudit: record %d has invalid PC %q", i, r.PC)
		}
		if _, parseErr := strconv.ParseUint(strings.TrimPrefix(r.PC, "0x"), 16, 64); parseErr != nil {
			return Provenance{}, fmt.Errorf("thraudit: record %d has invalid PC %q", i, r.PC)
		}
		if r.Access != AccessRead && r.Access != AccessWrite && r.Access != AccessReadWrite {
			return Provenance{}, fmt.Errorf("thraudit: record %d has invalid access mode %q", i, r.Access)
		}
		validWidth := false
		if r.Arch == ArchARM64 {
			validWidth = r.Width == 4 || r.Width == 8
		} else {
			validWidth = r.Width == 1 || r.Width == 2 || r.Width == 4 || r.Width == 8 || r.Width == 16
		}
		if !validWidth {
			return Provenance{}, fmt.Errorf("thraudit: record %d has invalid %s width %d", i, r.Arch, r.Width)
		}
		regMax := 15
		if r.Arch == ArchARM64 {
			regMax = 30
		}
		for label, reg := range map[string]*int{"dst_reg": r.DstReg, "src_reg": r.SrcReg} {
			if reg != nil && (*reg < 0 || *reg > regMax) {
				return Provenance{}, fmt.Errorf("thraudit: record %d %s=%d outside %s GPR range", i, label, *reg, r.Arch)
			}
		}
		if r.Access == AccessRead && r.SrcReg != nil {
			return Provenance{}, fmt.Errorf("thraudit: record %d read carries src_reg", i)
		}
		if r.Access == AccessWrite && r.DstReg != nil {
			return Provenance{}, fmt.Errorf("thraudit: record %d write-only access carries dst_reg", i)
		}
		if r.Resolved != (r.FieldName != "") {
			return Provenance{}, fmt.Errorf("thraudit: record %d resolved/field_name disagree", i)
		}
		currentLines := 0
		for _, line := range r.Context {
			if strings.HasPrefix(line, "> ") {
				currentLines++
			}
		}
		if currentLines != 1 {
			return Provenance{}, fmt.Errorf("thraudit: record %d context has %d current-instruction markers", i, currentLines)
		}
		if i == 0 {
			provenance = r.Provenance
			continue
		}
		if r.Provenance != provenance {
			return Provenance{}, fmt.Errorf("thraudit: mixed provenance at record %d", i)
		}
	}
	return provenance, nil
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
