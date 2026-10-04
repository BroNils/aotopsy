package disasm

import (
	"fmt"
	"strings"

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

// THRContextAnnotator pre-computes THR annotations from the same canonical
// extractor used by the audit JSON. This keeps inline annotations from drifting
// away from audit semantics and also covers paired LDP Thread reads.
func THRContextAnnotator(insts []Inst, fields map[int]string) Annotator {
	anns := make(map[uint64]string)
	byPC := make(map[uint64][]THRAccess)
	for _, access := range ExtractTHRAccesses(insts, fields) {
		byPC[access.PC] = append(byPC[access.PC], access)
	}
	for i, inst := range insts {
		accesses := byPC[inst.Addr]
		if len(accesses) == 0 {
			continue
		}
		labels := make([]string, 0, len(accesses))
		for _, access := range accesses {
			if access.Resolved {
				labels = append(labels, fmt.Sprintf("THR.%s", access.FieldName))
				continue
			}
			rec := buildContextRecord(insts, i, access)
			labels = append(labels, thrAnnotationLabel(access.THROffset, access.Access, access.Width, thraudit.ClassifyFromContext(rec)))
		}
		anns[inst.Addr] = strings.Join(labels, "; ")
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
func buildContextRecord(insts []Inst, idx int, access THRAccess) thraudit.THRAuditRecord {
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
		Provenance: thraudit.Provenance{Arch: thraudit.ArchARM64},
		THROffset:  access.THROffset,
		Insn:       insts[idx].Text,
		Access:     access.Access,
		DstReg:     access.DstReg,
		SrcReg:     access.SrcReg,
		Width:      access.Width,
		Context:    ctx,
	}
}

// thrAnnotationLabel builds the disasm annotation string for an unresolved THR access.
func thrAnnotationLabel(byteOff int64, access thraudit.AccessMode, width int, cls thraudit.THRClass) string {
	var classTag string
	switch cls {
	case thraudit.ClassIndirectControlTarget, thraudit.ClassValueStored, thraudit.ClassValueCompared, thraudit.ClassPointerDereference:
		classTag = "HEURISTIC_" + string(cls)
	default:
		classTag = "UNRESOLVED"
	}
	return fmt.Sprintf("THR%s %s%dB[%s]", signedOffsetSuffix(byteOff), access, width, classTag)
}

func signedOffsetSuffix(off int64) string {
	if off >= 0 {
		return "+" + thraudit.FormatTHROffset(off)
	}
	return thraudit.FormatTHROffset(off)
}

// PPContextAnnotator renders the canonical per-register pool-load facts from
// ExtractARM64PoolAccesses. Scalar loads keep the historical single-note format;
// an LDP with two independent pool slots renders both registers explicitly so
// one inline comment can never imply that both destination registers hold the
// same object.
func PPContextAnnotator(insts []Inst, pool map[int]string) Annotator {
	anns := make(map[uint64]string)
	byPC := make(map[uint64][]ARM64PoolAccess)
	for _, access := range ExtractARM64PoolAccesses(insts, pool) {
		if access.Kind != ARM64PoolAccessLoad || access.RegClass != ARM64PoolRegGPR {
			continue
		}
		byPC[access.PC] = append(byPC[access.PC], access)
	}
	for pc, group := range byPC {
		if len(group) == 1 {
			anns[pc] = group[0].Note
			continue
		}
		text := ""
		for i, access := range group {
			if i != 0 {
				text += ", "
			}
			text += fmt.Sprintf("X%d=%s", access.Reg, access.Note)
		}
		anns[pc] = text
	}

	return func(inst Inst) string { return anns[inst.Addr] }
}
