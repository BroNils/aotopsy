package disasm

import (
	"fmt"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/sdk"
)

// ARM64PoolLoad is one statically-identified object-pool word loaded into a
// register. A single LDP instruction produces two records, one per destination,
// because the adjacent pool entries are independent values and must never share
// one provenance label merely because one machine instruction loaded both.
type ARM64PoolLoad struct {
	PC        uint64
	Reg       int
	PoolIndex int
	Note      string
	// Direct is true when PP itself is the memory base. False means the SDK
	// materialized the byte offset/address in a temporary first.
	Direct bool
}

type arm64PoolAddrKind uint8

const (
	arm64PoolAddrUnknown arm64PoolAddrKind = iota
	arm64PoolAddrAbsolute
	arm64PoolAddrRelative
)

type arm64PoolAddrFact struct {
	kind  arm64PoolAddrKind
	value int64
}

func poolLoadNote(index int, pool map[int]string) string {
	if s, ok := pool[index]; ok {
		return fmt.Sprintf("PP[%d] %s", index, s)
	}
	return fmt.Sprintf("PP[%d]", index)
}

// ExtractARM64PoolLoads recovers the exact pool slot(s) read by ARM64 object-
// pool load sequences. It follows only constants constructed inside the same
// basic block, so a branch that bypasses an address-building prefix cannot
// fabricate a pool fact at a join.
//
// The handled shapes are the SDK's LoadWordFromPoolIndex and
// LoadDoubleWordFromPoolIndex lowerings across the supported releases:
// direct LDR/LDP from PP, ADD-immediate address construction (including two
// consecutive ADDs), and the large-offset MOVZ/MOVK + register-add/register-
// offset forms. All instruction semantics come from internal/arch/arm64.
func ExtractARM64PoolLoads(insts []Inst, pool map[int]string) []ARM64PoolLoad {
	if len(insts) == 0 {
		return nil
	}

	cfg := BuildCFG("pp-loads", insts)
	var out []ARM64PoolLoad
	maxInt := int64(int(^uint(0) >> 1))

	record := func(pc uint64, reg int, byteOff int64, direct bool) {
		if reg < 0 || reg >= 31 || byteOff < 0 || byteOff > maxInt {
			return
		}
		idx, ok := ARM64PoolIndex(int(byteOff))
		if !ok {
			return
		}
		out = append(out, ARM64PoolLoad{
			PC:        pc,
			Reg:       reg,
			PoolIndex: idx,
			Note:      poolLoadNote(idx, pool),
			Direct:    direct,
		})
	}

	for _, blk := range cfg.Blocks {
		var facts [31]arm64PoolAddrFact

		factFor := func(reg int) arm64PoolAddrFact {
			if reg == sdk.ARM64PP {
				return arm64PoolAddrFact{kind: arm64PoolAddrRelative}
			}
			if reg >= 0 && reg < len(facts) {
				return facts[reg]
			}
			return arm64PoolAddrFact{}
		}
		baseOffset := func(reg int) (int64, bool, bool) {
			f := factFor(reg)
			if f.kind != arm64PoolAddrRelative {
				return 0, false, false
			}
			return f.value, true, reg == sdk.ARM64PP
		}
		setFact := func(reg int, f arm64PoolAddrFact) {
			if reg >= 0 && reg < len(facts) {
				facts[reg] = f
			}
		}
		killDefs := func(raw uint32) {
			for _, rd := range arm64.DstRegsOfInst(raw) {
				if rd >= 0 && rd < len(facts) {
					facts[rd] = arm64PoolAddrFact{}
				}
			}
		}
		add := func(a, b int64) (int64, bool) {
			if b > 0 && a > (1<<63-1)-b {
				return 0, false
			}
			if b < 0 && a < (-1<<63)-b {
				return 0, false
			}
			return a + b, true
		}

		for i := blk.Start; i < blk.End && i < len(insts); i++ {
			inst := insts[i]
			if IsARM64SemanticBarrier(inst) {
				facts = [31]arm64PoolAddrFact{}
				continue
			}

			// Scalar unsigned-offset load. The base may be PP itself or a
			// PP-relative temporary built by one/two ADD-immediate instructions.
			if base, low, ok := arm64.LDR64UnsignedOffset(inst.Raw); ok {
				if upper, known, direct := baseOffset(base); known {
					if total, ok := add(upper, int64(low)); ok {
						record(inst.Addr, int(inst.Raw&0x1f), total, direct)
					}
				}
				killDefs(inst.Raw)
				continue
			}

			// Register-offset LDR. Large pool offsets are materialized as an
			// absolute byte count and then used unscaled against PP.
			if base, rm, rt, scaled, ok := arm64.LDR64RegisterOffset(inst.Raw); ok {
				baseOff, baseKnown, direct := baseOffset(base)
				idxFact := factFor(rm)
				if baseKnown && idxFact.kind == arm64PoolAddrAbsolute {
					idxOff := idxFact.value
					if scaled {
						if idxOff < 0 || idxOff > (1<<63-1)/8 {
							idxOff = -1
						} else {
							idxOff *= 8
						}
					}
					if idxOff >= 0 {
						if total, ok := add(baseOff, idxOff); ok {
							record(inst.Addr, rt, total, direct)
						}
					}
				}
				killDefs(inst.Raw)
				continue
			}

			// Pair loads use adjacent pool words. Only the non-writeback PairOffset
			// form is a pool lowering in the exact SDK implementation.
			if pair, ok := arm64.LoadPair64(inst.Raw); ok {
				if pair.Mode == arm64.PairOffset {
					if upper, known, direct := baseOffset(pair.BaseReg); known {
						if first, ok := add(upper, int64(pair.ByteOffset)); ok {
							record(inst.Addr, pair.Reg1, first, direct)
							if second, ok := add(first, 8); ok {
								record(inst.Addr, pair.Reg2, second, direct)
							}
						}
					}
				}
				killDefs(inst.Raw)
				continue
			}

			// Exact MOV register alias: carry an address-building constant/fact.
			if rd, rm, ok := arm64.MOVOrr(inst.Raw); ok {
				setFact(rd, factFor(rm))
				continue
			}

			// Large-offset fallback materializes a 32-bit byte displacement.
			if rd, imm, ok := arm64.MOVZ64(inst.Raw); ok {
				setFact(rd, arm64PoolAddrFact{kind: arm64PoolAddrAbsolute, value: int64(imm)})
				continue
			}
			if rd, imm, shift, ok := arm64.MOVK64(inst.Raw); ok {
				old := factFor(rd)
				if old.kind != arm64PoolAddrAbsolute || shift < 0 || shift > 48 {
					setFact(rd, arm64PoolAddrFact{})
					continue
				}
				mask := int64(0xffff) << uint(shift)
				old.value = (old.value &^ mask) | (int64(imm) << uint(shift))
				setFact(rd, old)
				continue
			}

			if rd, rn, imm, ok := arm64.ADD64Immediate(inst.Raw); ok {
				f := factFor(rn)
				if f.kind == arm64PoolAddrUnknown {
					setFact(rd, arm64PoolAddrFact{})
					continue
				}
				if v, ok := add(f.value, int64(imm)); ok {
					f.value = v
					setFact(rd, f)
				} else {
					setFact(rd, arm64PoolAddrFact{})
				}
				continue
			}

			if rd, rn, rm, shift, amount, ok := arm64.ADD64Register(inst.Raw); ok {
				if shift != arm64.ShiftLSL || amount != 0 {
					setFact(rd, arm64PoolAddrFact{})
					continue
				}
				a := factFor(rn)
				b := factFor(rm)
				var result arm64PoolAddrFact
				switch {
				case a.kind == arm64PoolAddrAbsolute && b.kind == arm64PoolAddrAbsolute:
					result.kind = arm64PoolAddrAbsolute
				case a.kind == arm64PoolAddrRelative && b.kind == arm64PoolAddrAbsolute,
					a.kind == arm64PoolAddrAbsolute && b.kind == arm64PoolAddrRelative:
					result.kind = arm64PoolAddrRelative
				default:
					setFact(rd, arm64PoolAddrFact{})
					continue
				}
				if v, ok := add(a.value, b.value); ok {
					result.value = v
					setFact(rd, result)
				} else {
					setFact(rd, arm64PoolAddrFact{})
				}
				continue
			}

			killDefs(inst.Raw)
		}
	}

	return out
}

func arm64PoolNotesByPC(loads []ARM64PoolLoad) map[uint64]map[int]string {
	if len(loads) == 0 {
		return nil
	}
	out := make(map[uint64]map[int]string)
	for _, load := range loads {
		m := out[load.PC]
		if m == nil {
			m = make(map[int]string)
			out[load.PC] = m
		}
		m[load.Reg] = load.Note
	}
	return out
}
