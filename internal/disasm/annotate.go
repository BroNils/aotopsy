package disasm

import "fmt"

// Annotator returns an optional inline comment for an instruction.
// Empty string means no annotation. Receives the full Inst for access
// to both raw encoding and address.
type Annotator func(inst Inst) string

// ARM64 register numbers for Dart AOT.
const (
	regPP  = 27 // X27 = object pool pointer
	regTHR = 26 // X26 = thread pointer
)

// isLDR64UnsignedOffset returns true if the raw 32-bit ARM64 instruction is
// LDR Xt, [Xn, #imm] (64-bit, unsigned offset). Returns the base register
// number and the byte offset.
//
// Encoding: size=11 | 111 | V=0 | 01 | opc=01 | imm12 | Rn | Rt
// Mask: 0xFFC00000, Value: 0xF9400000
func isLDR64UnsignedOffset(raw uint32) (baseReg int, byteOffset int, ok bool) {
	if raw&0xFFC00000 != 0xF9400000 {
		return 0, 0, false
	}
	rn := int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	return rn, imm12 << 3, true // scaled by 8 for 64-bit
}

// isADD64Immediate returns true if the raw instruction is ADD Xd, Xn, #imm
// (64-bit). Returns dest reg, source reg, and the effective immediate value
// (with shift applied).
//
// Encoding: sf=1 | op=0 | S=0 | 100010 | sh | imm12 | Rn | Rd
// Mask: 0x7F800000, Value: 0x11000000 (with sf=1 → 0x91000000)
func isADD64Immediate(raw uint32) (rd, rn int, immValue int, ok bool) {
	if raw&0xFF000000 != 0x91000000 {
		return 0, 0, 0, false
	}
	rd = int(raw & 0x1F)
	rn = int((raw >> 5) & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	shift := int((raw >> 22) & 0x3)
	if shift == 1 {
		immValue = imm12 << 12
	} else {
		immValue = imm12
	}
	return rd, rn, immValue, true
}

// IsLDR64UnsignedOffsetExported is the exported version of isLDR64UnsignedOffset
// for use outside the disasm package (e.g. extracting string refs in cmd/).
func IsLDR64UnsignedOffsetExported(raw uint32) (baseReg int, byteOffset int, ok bool) {
	return isLDR64UnsignedOffset(raw)
}

// PPAnnotator annotates LDR Xt, [X27, #imm] instructions with pool entry info.
// pool maps pool index → display string.
func PPAnnotator(pool map[int]string) Annotator {
	return func(inst Inst) string {
		baseReg, byteOff, ok := isLDR64UnsignedOffset(inst.Raw)
		if !ok || baseReg != regPP {
			return ""
		}
		idx := byteOff / 8
		if s, found := pool[idx]; found {
			return fmt.Sprintf("PP[%d] %s", idx, s)
		}
		return fmt.Sprintf("PP[%d]", idx)
	}
}

// THRAnnotator annotates LDR Xt, [X26, #imm] instructions with thread offset.
// If fields is non-nil, resolved field names are included.
func THRAnnotator(fields map[int]string) Annotator {
	return func(inst Inst) string {
		baseReg, byteOff, ok := isLDR64UnsignedOffset(inst.Raw)
		if !ok || baseReg != regTHR {
			return ""
		}
		if fields != nil {
			if name, found := fields[byteOff]; found {
				return fmt.Sprintf("THR.%s", name)
			}
		}
		return fmt.Sprintf("THR+0x%x", byteOff)
	}
}

// THRContextAnnotator pre-computes THR annotations for an instruction stream,
// including classification labels for unresolved offsets using instruction context.
// It handles LDR64, LDR32, STR64, and STR32 on X26.
// Replaces the simple THRAnnotator when full context is available.
func THRContextAnnotator(insts []Inst, fields map[int]string) Annotator {
	anns := make(map[uint64]string)

	for i, inst := range insts {
		raw := inst.Raw
		var byteOff int
		var isStore bool
		var width int
		detected := false

		// LDR X64 [X26, #imm]
		if base, off, ok := isLDR64UnsignedOffset(raw); ok && base == regTHR {
			byteOff, width = off, 8
			detected = true
		}
		// LDR W32 [X26, #imm]
		if !detected {
			if base, off, _, ok := isLDR32UnsignedOffset(raw); ok && base == regTHR {
				byteOff, width = off, 4
				detected = true
			}
		}
		// STR X64 [X26, #imm]
		if !detected {
			if base, off, _, ok := isSTR64UnsignedOffset(raw); ok && base == regTHR {
				byteOff, width = off, 8
				isStore = true
				detected = true
			}
		}
		// STR W32 [X26, #imm]
		if !detected {
			if base, off, _, ok := isSTR32UnsignedOffset(raw); ok && base == regTHR {
				byteOff, width = off, 4
				isStore = true
				detected = true
			}
		}

		if !detected {
			continue
		}

		// Resolved?
		if fields != nil {
			if name, found := fields[byteOff]; found {
				anns[inst.Addr] = fmt.Sprintf("THR.%s", name)
				continue
			}
		}

		// Unresolved — classify from context.
		rec := buildContextRecord(insts, i, byteOff, isStore, width)
		cls := classifyFromContext(rec)

		label := thrAnnotationLabel(byteOff, isStore, width, cls)
		anns[inst.Addr] = label
	}

	return func(inst Inst) string {
		if s, ok := anns[inst.Addr]; ok {
			return s
		}
		return ""
	}
}

// buildContextRecord constructs a THRAuditRecord from instruction context
// for classification. Only the fields needed by classifyFromContext are populated.
func buildContextRecord(insts []Inst, idx, byteOff int, isStore bool, width int) THRAuditRecord {
	var ctx []string
	for d := -2; d <= 2; d++ {
		j := idx + d
		if j >= 0 && j < len(insts) {
			prefix := "  "
			if d == 0 {
				prefix = "> "
			}
			ctx = append(ctx, fmt.Sprintf("%s0x%x: %s", prefix, insts[j].Addr, insts[j].Text))
		}
	}

	return THRAuditRecord{
		THROffset: fmt.Sprintf("0x%x", byteOff),
		Insn:      insts[idx].Text,
		IsStore:   isStore,
		Width:     width,
		Context:   ctx,
	}
}

// thrAnnotationLabel builds the disasm annotation string for an unresolved THR access.
func thrAnnotationLabel(byteOff int, isStore bool, width int, cls THRClass) string {
	var classTag string
	switch cls {
	case ClassRuntimeEntrypoint:
		classTag = "RUNTIME_ENTRY"
	case ClassObjectStoreCache:
		classTag = "OBJSTORE"
	case ClassIsolateGroupPtr:
		classTag = "ISO_GROUP"
	default:
		classTag = "UNKNOWN"
	}

	op := "LDR"
	if isStore {
		op = "STR"
	}
	wStr := ""
	if width == 4 {
		wStr = "w32 "
	}

	return fmt.Sprintf("THR+0x%x %s%s[%s]", byteOff, wStr, op, classTag)
}

// PeepholeState tracks state for multi-instruction annotation patterns.
// Fase 7 PART B: tracks register liveness to avoid false positives when
// the ADD destination register is overwritten between ADD and LDR.
type PeepholeState struct {
	pool       map[int]string
	prevRaw    uint32
	prevValid  bool
	addDestReg int  // destination register from ADD (for liveness tracking)
	addImm     int  // immediate from ADD (for combined offset)
	addValid   bool // true if prev was ADD Xd, X27, #imm
}

// NewPeepholeState creates a peephole annotator for ADD+LDR PP patterns.
func NewPeepholeState(pool map[int]string) *PeepholeState {
	return &PeepholeState{pool: pool, addDestReg: -1}
}

// Reset clears the peephole state. Call between functions.
func (p *PeepholeState) Reset() {
	p.prevValid = false
	p.addValid = false
	p.addDestReg = -1
}

// Annotate checks for ADD Xd, X27, #upper followed by LDR Xt, [Xd, #lower].
// Call this for each instruction in sequence. Returns annotation for the
// current instruction (may annotate the LDR in a two-instruction sequence).
// Fase 7 PART B: if an instruction between ADD and LDR defines the ADD's
// destination register, the ADD result is killed and no annotation is made.
func (p *PeepholeState) Annotate(inst Inst) string {
	result := ""

	// First, check if current is LDR Xt, [Xd, #lower] matching a pending ADD.
	// Do this BEFORE checking for register kills, because LDR reads the base
	// register (addDestReg) before writing the destination register.
	if p.addValid && p.addDestReg >= 0 {
		baseReg, ldrOff, ldrOK := isLDR64UnsignedOffset(inst.Raw)
		if ldrOK && baseReg == p.addDestReg {
			combined := p.addImm + ldrOff
			idx := combined / 8
			if s, found := p.pool[idx]; found {
				result = fmt.Sprintf("PP[%d] %s", idx, s)
			} else {
				result = fmt.Sprintf("PP[%d]", idx)
			}
			p.addValid = false // consumed
		}
	}

	// If not consumed by LDR, check if current instruction kills the ADD dest.
	if p.addValid && p.addDestReg >= 0 {
		if dstRegOfInst(inst.Raw) == p.addDestReg {
			p.addValid = false
		}
	}

	// Check if current instruction is a new ADD Xd, X27, #upper.
	addRd, addRn, addImm, addOK := isADD64Immediate(inst.Raw)
	if addOK && addRn == regPP {
		p.addDestReg = addRd
		p.addImm = addImm
		p.addValid = true
	}

	p.prevRaw = inst.Raw
	p.prevValid = true

	return result
}
