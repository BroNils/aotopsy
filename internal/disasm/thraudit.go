package disasm

import "fmt"

// THRAccess describes a single THR-relative memory access in the instruction stream.
type THRAccess struct {
	PC        uint64 `json:"pc"`
	InsnText  string `json:"insn"`
	THROffset int    `json:"thr_offset"`
	IsStore   bool   `json:"is_store"`
	DstReg    int    `json:"dst_reg,omitempty"` // for loads
	SrcReg    int    `json:"src_reg,omitempty"` // for stores
	Width     int    `json:"width"`             // 4 or 8
	Resolved  bool   `json:"resolved"`          // whether THRFields has a name for this offset
}

// isLDR32UnsignedOffset detects LDR Wt, [Xn, #imm] (32-bit unsigned offset).
// Encoding: size=10 | 111 | V=0 | 01 | opc=01 | imm12 | Rn | Rt
// Mask: 0xFFC00000, Value: 0xB9400000
func isLDR32UnsignedOffset(raw uint32) (baseReg int, byteOffset int, dstReg int, ok bool) {
	if raw&0xFFC00000 != 0xB9400000 {
		return 0, 0, 0, false
	}
	rn := int((raw >> 5) & 0x1F)
	rt := int(raw & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	return rn, imm12 << 2, rt, true // scaled by 4 for 32-bit
}

// isSTR64UnsignedOffset detects STR Xt, [Xn, #imm] (64-bit unsigned offset).
// Encoding: size=11 | 111 | V=0 | 01 | opc=00 | imm12 | Rn | Rt
// Mask: 0xFFC00000, Value: 0xF9000000
func isSTR64UnsignedOffset(raw uint32) (baseReg int, byteOffset int, srcReg int, ok bool) {
	if raw&0xFFC00000 != 0xF9000000 {
		return 0, 0, 0, false
	}
	rn := int((raw >> 5) & 0x1F)
	rt := int(raw & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	return rn, imm12 << 3, rt, true
}

// isSTR32UnsignedOffset detects STR Wt, [Xn, #imm] (32-bit unsigned offset).
// Encoding: size=10 | 111 | V=0 | 01 | opc=00 | imm12 | Rn | Rt
// Mask: 0xFFC00000, Value: 0xB9000000
func isSTR32UnsignedOffset(raw uint32) (baseReg int, byteOffset int, srcReg int, ok bool) {
	if raw&0xFFC00000 != 0xB9000000 {
		return 0, 0, 0, false
	}
	rn := int((raw >> 5) & 0x1F)
	rt := int(raw & 0x1F)
	imm12 := int((raw >> 10) & 0xFFF)
	return rn, imm12 << 2, rt, true
}

// ExtractTHRAccesses scans decoded instructions for THR-relative memory operations.
// Returns all THR accesses found. fields is optional (for marking resolved).
func ExtractTHRAccesses(insts []Inst, fields map[int]string) []THRAccess {
	var result []THRAccess
	for _, inst := range insts {
		raw := inst.Raw

		// LDR X64 [X26, #imm]
		if base, off, ok := isLDR64UnsignedOffset(raw); ok && base == regTHR {
			dst := int(raw & 0x1F)
			_, resolved := fields[off]
			result = append(result, THRAccess{
				PC:        inst.Addr,
				InsnText:  inst.Text,
				THROffset: off,
				DstReg:    dst,
				Width:     8,
				Resolved:  resolved,
			})
			continue
		}

		// LDR W32 [X26, #imm]
		if base, off, dst, ok := isLDR32UnsignedOffset(raw); ok && base == regTHR {
			_, resolved := fields[off]
			result = append(result, THRAccess{
				PC:        inst.Addr,
				InsnText:  inst.Text,
				THROffset: off,
				DstReg:    dst,
				Width:     4,
				Resolved:  resolved,
			})
			continue
		}

		// STR X64 [X26, #imm]
		if base, off, src, ok := isSTR64UnsignedOffset(raw); ok && base == regTHR {
			_, resolved := fields[off]
			result = append(result, THRAccess{
				PC:        inst.Addr,
				InsnText:  inst.Text,
				THROffset: off,
				IsStore:   true,
				SrcReg:    src,
				Width:     8,
				Resolved:  resolved,
			})
			continue
		}

		// STR W32 [X26, #imm]
		if base, off, src, ok := isSTR32UnsignedOffset(raw); ok && base == regTHR {
			_, resolved := fields[off]
			result = append(result, THRAccess{
				PC:        inst.Addr,
				InsnText:  inst.Text,
				THROffset: off,
				IsStore:   true,
				SrcReg:    src,
				Width:     4,
				Resolved:  resolved,
			})
			continue
		}
	}
	return result
}

// THRAuditRecord is a JSONL output record for thr-audit.
type THRAuditRecord struct {
	Sample      string   `json:"sample"`
	DartVersion string   `json:"dart_version"`
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

// BuildAuditRecords converts THRAccess entries into audit records with context.
func BuildAuditRecords(accesses []THRAccess, allInsts []Inst, sample, dartVersion, funcName string) []THRAuditRecord {
	// Build PC→index map for context lookup.
	pcIdx := make(map[uint64]int, len(allInsts))
	for i, inst := range allInsts {
		pcIdx[inst.Addr] = i
	}

	records := make([]THRAuditRecord, 0, len(accesses))
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

		rec := THRAuditRecord{
			Sample:      sample,
			DartVersion: dartVersion,
			PC:          fmt.Sprintf("0x%x", a.PC),
			Insn:        a.InsnText,
			THROffset:   fmt.Sprintf("0x%x", a.THROffset),
			IsStore:     a.IsStore,
			Width:       a.Width,
			FuncName:    funcName,
			Resolved:    a.Resolved,
			Context:     ctx,
		}
		if a.IsStore {
			rec.SrcReg = a.SrcReg
		} else {
			rec.DstReg = a.DstReg
		}
		records = append(records, rec)
	}
	return records
}
