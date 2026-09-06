package disasm

import (
	"fmt"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/sdk"
	"aotopsy/internal/thraudit"
)

// Annotator returns an optional inline comment for an instruction.
// Empty string means no annotation. Receives the full Inst for access
// to both raw encoding and address.
type Annotator func(inst Inst) string

// ARM64 register numbers for Dart AOT — now shared from internal/sdk.
// Instruction decoders are now shared from internal/arm64.

// PPAnnotator annotates LDR Xt, [X27, #imm] instructions with pool entry info.
// pool maps pool index → display string.
func PPAnnotator(pool map[int]string) Annotator {
	return func(inst Inst) string {
		baseReg, byteOff, ok := arm64.LDR64UnsignedOffset(inst.Raw)
		if !ok || baseReg != sdk.ARM64PP {
			return ""
		}
		idx, idxOK := ARM64PoolIndex(byteOff)
		if !idxOK {
			return ""
		}
		if s, found := pool[idx]; found {
			return fmt.Sprintf("PP[%d] %s", idx, s)
		}
		return fmt.Sprintf("PP[%d]", idx)
	}
}

// THRContextAnnotator pre-computes THR annotations for an instruction stream,
// including classification labels for unresolved offsets using instruction context.
// It handles LDR64, LDR32, STR64, and STR32 on X26.
func THRContextAnnotator(insts []Inst, fields map[int]string) Annotator {
	anns := make(map[uint64]string)

	for i, inst := range insts {
		raw := inst.Raw
		var byteOff int
		var isStore bool
		var width int
		detected := false

		// LDR X64 [X26, #imm]
		if base, off, ok := arm64.LDR64UnsignedOffset(raw); ok && base == sdk.ARM64THR {
			byteOff, width = off, 8
			detected = true
		}
		// LDR W32 [X26, #imm]
		if !detected {
			if base, off, _, ok := arm64.LDR32UnsignedOffset(raw); ok && base == sdk.ARM64THR {
				byteOff, width = off, 4
				detected = true
			}
		}
		// STR X64 [X26, #imm]
		if !detected {
			if base, off, _, ok := arm64.STR64UnsignedOffset(raw); ok && base == sdk.ARM64THR {
				byteOff, width = off, 8
				isStore = true
				detected = true
			}
		}
		// STR W32 [X26, #imm]
		if !detected {
			if base, off, _, ok := arm64.STR32UnsignedOffset(raw); ok && base == sdk.ARM64THR {
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
		cls := thraudit.ClassifyFromContext(rec)

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
func buildContextRecord(insts []Inst, idx, byteOff int, isStore bool, width int) thraudit.THRAuditRecord {
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

	return thraudit.THRAuditRecord{
		THROffset: fmt.Sprintf("0x%x", byteOff),
		Insn:      insts[idx].Text,
		IsStore:   isStore,
		Width:     width,
		Context:   ctx,
	}
}

// thrAnnotationLabel builds the disasm annotation string for an unresolved THR access.
func thrAnnotationLabel(byteOff int, isStore bool, width int, cls thraudit.THRClass) string {
	var classTag string
	switch cls {
	case thraudit.ClassRuntimeEntrypoint:
		classTag = "RUNTIME_ENTRY"
	case thraudit.ClassObjectStoreCache:
		classTag = "OBJSTORE"
	case thraudit.ClassIsolateGroupPtr:
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
		baseReg, ldrOff, ldrOK := arm64.LDR64UnsignedOffset(inst.Raw)
		if !ldrOK {
			baseReg, ldrOff, _, ldrOK = arm64.LDR32UnsignedOffset(inst.Raw)
		}
		if !ldrOK {
			base, _, off, ok := arm64.LDUR64(inst.Raw)
			if ok {
				baseReg, ldrOff, ldrOK = base, off, true
			}
		}
		if ldrOK && baseReg == p.addDestReg {
			combined := p.addImm + ldrOff
			if idx, idxOK := ARM64PoolIndex(combined); idxOK {
				if s, found := p.pool[idx]; found {
					result = fmt.Sprintf("PP[%d] %s", idx, s)
				} else {
					result = fmt.Sprintf("PP[%d]", idx)
				}
			}
			p.addValid = false // consumed
		}
	}

	// If not consumed by LDR, check if current instruction kills the ADD dest.
	if p.addValid && p.addDestReg >= 0 {
		for _, rd := range arm64.DstRegsOfInst(inst.Raw) {
			if rd == p.addDestReg {
				p.addValid = false
				break
			}
		}
	}

	// Check if current instruction is a new ADD Xd, X27, #upper.
	addRd, addRn, addImm, addOK := arm64.ADD64Immediate(inst.Raw)
	if addOK && addRn == sdk.ARM64PP {
		p.addDestReg = addRd
		p.addImm = addImm
		p.addValid = true
	}

	return result
}
