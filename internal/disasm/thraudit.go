package disasm

import (
	"fmt"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/sdk"
	"aotopsy/internal/thraudit"
)

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
// ARM64 instruction decoders are now shared from internal/arm64.

// ExtractTHRAccesses scans decoded instructions for THR-relative memory operations.
// Returns all THR accesses found. fields is optional (for marking resolved).
func ExtractTHRAccesses(insts []Inst, fields map[int]string) []THRAccess {
	var result []THRAccess
	for _, inst := range insts {
		raw := inst.Raw

		// LDR X64 [X26, #imm]
		if base, off, ok := arm64.LDR64UnsignedOffset(raw); ok && base == sdk.ARM64THR {
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
		if base, off, dst, ok := arm64.LDR32UnsignedOffset(raw); ok && base == sdk.ARM64THR {
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
		if base, off, src, ok := arm64.STR64UnsignedOffset(raw); ok && base == sdk.ARM64THR {
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
		if base, off, src, ok := arm64.STR32UnsignedOffset(raw); ok && base == sdk.ARM64THR {
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

// BuildAuditRecords converts THRAccess entries into audit records with context.
func BuildAuditRecords(accesses []THRAccess, allInsts []Inst, sample, dartVersion, funcName string) []thraudit.THRAuditRecord {
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
