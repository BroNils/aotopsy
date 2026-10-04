package disasm

import (
	"fmt"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/sdk"
	"aotopsy/internal/thraudit"
)

// THRAccess describes a single THR-relative memory access in the instruction stream.
type THRAccess struct {
	PC        uint64              `json:"pc"`
	InsnText  string              `json:"insn"`
	THROffset int64               `json:"thr_offset"`
	Access    thraudit.AccessMode `json:"access"`
	DstReg    *int                `json:"dst_reg,omitempty"` // GPR receiving the memory value/readback, when one exists.
	SrcReg    *int                `json:"src_reg,omitempty"` // GPR source/operand for a memory write, when one exists.
	Width     int                 `json:"width"`
	Resolved  bool                `json:"resolved"`
	FieldName string              `json:"field_name,omitempty"`
}

func resolveTHRField(fields map[int]string, off int64) (string, bool) {
	if fields == nil {
		return "", false
	}
	i := int(off)
	if int64(i) != off {
		return "", false
	}
	name, ok := fields[i]
	return name, ok
}

func arm64AuditGPR(reg int) *int {
	// Architectural encoding 31 is ZR for these data registers, not a tracked
	// X0-X30 GPR. A load into ZR still reads Thread memory and a store from ZR
	// still writes zero, but neither has a meaningful register provenance edge.
	if reg < 0 || reg > 30 {
		return nil
	}
	out := reg
	return &out
}

// ARM64 instruction decoders are now shared from internal/arm64.

// ExtractTHRAccesses scans decoded instructions for THR-relative memory operations.
// Returns all THR accesses found. fields is optional (for marking resolved).
func ExtractTHRAccesses(insts []Inst, fields map[int]string) []THRAccess {
	var result []THRAccess
	for _, inst := range insts {
		raw := inst.Raw

		// Pair accesses are split into one record per Thread slot. Only the
		// non-writeback forms are admissible here: pre/post-index addressing would
		// redefine X26 itself, after which a stateless THR scan could no longer
		// claim that later X26-relative instructions use the canonical Thread base.
		if p, ok := arm64.LoadPair64(raw); ok && p.BaseReg == sdk.ARM64THR &&
			(p.Mode == arm64.PairOffset || p.Mode == arm64.PairNonTemporal) {
			off1 := int64(p.ByteOffset)
			off2 := off1 + 8
			name1, resolved1 := resolveTHRField(fields, off1)
			result = append(result, THRAccess{
				PC:        inst.Addr,
				InsnText:  inst.Text,
				THROffset: off1,
				Access:    thraudit.AccessRead,
				DstReg:    arm64AuditGPR(p.Reg1),
				Width:     8,
				Resolved:  resolved1,
				FieldName: name1,
			})
			name2, resolved2 := resolveTHRField(fields, off2)
			result = append(result, THRAccess{
				PC:        inst.Addr,
				InsnText:  inst.Text,
				THROffset: off2,
				Access:    thraudit.AccessRead,
				DstReg:    arm64AuditGPR(p.Reg2),
				Width:     8,
				Resolved:  resolved2,
				FieldName: name2,
			})
			continue
		}

		if p, ok := arm64.StorePair64(raw); ok && p.BaseReg == sdk.ARM64THR &&
			(p.Mode == arm64.PairOffset || p.Mode == arm64.PairNonTemporal) {
			off1 := int64(p.ByteOffset)
			off2 := off1 + 8
			name1, resolved1 := resolveTHRField(fields, off1)
			result = append(result, THRAccess{
				PC:        inst.Addr,
				InsnText:  inst.Text,
				THROffset: off1,
				Access:    thraudit.AccessWrite,
				SrcReg:    arm64AuditGPR(p.Reg1),
				Width:     8,
				Resolved:  resolved1,
				FieldName: name1,
			})
			name2, resolved2 := resolveTHRField(fields, off2)
			result = append(result, THRAccess{
				PC:        inst.Addr,
				InsnText:  inst.Text,
				THROffset: off2,
				Access:    thraudit.AccessWrite,
				SrcReg:    arm64AuditGPR(p.Reg2),
				Width:     8,
				Resolved:  resolved2,
				FieldName: name2,
			})
			continue
		}

		// Canonical 64-bit immediate decoder covers both the usual unsigned LDR
		// form and signed/unscaled LDUR/LDTR. Preserve signed byte displacement.
		// As above, reject pre/post-index because they overwrite THR itself.
		if m, ok := arm64.Load64Immediate(raw); ok && m.BaseReg == sdk.ARM64THR &&
			(m.Mode == arm64.AddressOffset || m.Mode == arm64.AddressUnprivileged) {
			off := int64(m.ByteOffset)
			name, resolved := resolveTHRField(fields, off)
			result = append(result, THRAccess{
				PC:        inst.Addr,
				InsnText:  inst.Text,
				THROffset: off,
				Access:    thraudit.AccessRead,
				DstReg:    arm64AuditGPR(m.Reg),
				Width:     8,
				Resolved:  resolved,
				FieldName: name,
			})
			continue
		}

		if m, ok := arm64.Store64Immediate(raw); ok && m.BaseReg == sdk.ARM64THR &&
			(m.Mode == arm64.AddressOffset || m.Mode == arm64.AddressUnprivileged) {
			off := int64(m.ByteOffset)
			name, resolved := resolveTHRField(fields, off)
			result = append(result, THRAccess{
				PC:        inst.Addr,
				InsnText:  inst.Text,
				THROffset: off,
				Access:    thraudit.AccessWrite,
				SrcReg:    arm64AuditGPR(m.Reg),
				Width:     8,
				Resolved:  resolved,
				FieldName: name,
			})
			continue
		}

		// 32-bit signed/unscaled forms are separate helpers today; handle them
		// before the unsigned forms so negative Thread displacements survive.
		if base, dst, off, ok := arm64.LDUR32(raw); ok && base == sdk.ARM64THR {
			off64 := int64(off)
			name, resolved := resolveTHRField(fields, off64)
			result = append(result, THRAccess{
				PC:        inst.Addr,
				InsnText:  inst.Text,
				THROffset: off64,
				Access:    thraudit.AccessRead,
				DstReg:    arm64AuditGPR(dst),
				Width:     4,
				Resolved:  resolved,
				FieldName: name,
			})
			continue
		}

		if base, src, off, ok := arm64.STUR32(raw); ok && base == sdk.ARM64THR {
			off64 := int64(off)
			name, resolved := resolveTHRField(fields, off64)
			result = append(result, THRAccess{
				PC:        inst.Addr,
				InsnText:  inst.Text,
				THROffset: off64,
				Access:    thraudit.AccessWrite,
				SrcReg:    arm64AuditGPR(src),
				Width:     4,
				Resolved:  resolved,
				FieldName: name,
			})
			continue
		}

		if base, off, dst, ok := arm64.LDR32UnsignedOffset(raw); ok && base == sdk.ARM64THR {
			off64 := int64(off)
			name, resolved := resolveTHRField(fields, off64)
			result = append(result, THRAccess{
				PC:        inst.Addr,
				InsnText:  inst.Text,
				THROffset: off64,
				Access:    thraudit.AccessRead,
				DstReg:    arm64AuditGPR(dst),
				Width:     4,
				Resolved:  resolved,
				FieldName: name,
			})
			continue
		}

		if base, off, src, ok := arm64.STR32UnsignedOffset(raw); ok && base == sdk.ARM64THR {
			off64 := int64(off)
			name, resolved := resolveTHRField(fields, off64)
			result = append(result, THRAccess{
				PC:        inst.Addr,
				InsnText:  inst.Text,
				THROffset: off64,
				Access:    thraudit.AccessWrite,
				SrcReg:    arm64AuditGPR(src),
				Width:     4,
				Resolved:  resolved,
				FieldName: name,
			})
			continue
		}
	}
	return result
}

// BuildAuditRecords converts THRAccess entries into audit records with context.
func BuildAuditRecords(accesses []THRAccess, allInsts []Inst, provenance thraudit.Provenance, funcName string) []thraudit.THRAuditRecord {
	// Build PC→index map for context lookup.
	pcIdx := make(map[uint64]int, len(allInsts))
	for i, inst := range allInsts {
		pcIdx[inst.Addr] = i
	}

	records := make([]thraudit.THRAuditRecord, 0, len(accesses))
	for _, a := range accesses {
		// Build context: prev 2, current, next 2
		var ctx []string
		if idx, ok := pcIdx[a.PC]; ok {
			for d := -2; d <= 2; d++ {
				j := idx + d
				if j >= 0 && j < len(allInsts) {
					prefix := "  "
					if d == 0 {
						prefix = "> "
					}
					ctx = append(ctx, fmt.Sprintf("%s0x%x: %s", prefix, allInsts[j].Addr, allInsts[j].Text))
				}
			}
		}

		rec := thraudit.THRAuditRecord{
			Provenance:    provenance,
			SchemaVersion: thraudit.SchemaV1,
			PC:            fmt.Sprintf("0x%x", a.PC),
			Insn:          a.InsnText,
			THROffset:     a.THROffset,
			Access:        a.Access,
			DstReg:        a.DstReg,
			SrcReg:        a.SrcReg,
			Width:         a.Width,
			FuncName:      funcName,
			Resolved:      a.Resolved,
			FieldName:     a.FieldName,
			Context:       ctx,
		}
		records = append(records, rec)
	}
	return records
}

// UnresolvedRecordFromAudit converts the richer audit schema into the compact
// unresolved_thr.jsonl pipeline artifact without inventing semantic meaning.
// Callers must pass an unresolved record; exact field names belong in the
// resolved audit stream, not in a heuristic summary.
func UnresolvedRecordFromAudit(r thraudit.THRAuditRecord) UnresolvedTHRRecord {
	cls := thraudit.ClassifyFromContext(r)
	confidence := thraudit.ConfidenceHeuristic
	if cls == thraudit.ClassUnknown {
		confidence = thraudit.ConfidenceUnresolved
	}
	return UnresolvedTHRRecord{
		FuncName:       r.FuncName,
		PC:             r.PC,
		THROffset:      r.THROffset,
		Width:          r.Width,
		Access:         r.Access,
		HeuristicClass: cls,
		Confidence:     confidence,
	}
}
