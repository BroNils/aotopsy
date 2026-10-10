package disasm

import (
	"fmt"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/sdk"
)

// ARM64PoolAccessKind describes whether machine code reads or writes a pool
// slot. The distinction matters to provenance consumers: a store is a genuine
// machine-code xref to the slot, but it does not define the source register as
// containing the pool value.
type ARM64PoolAccessKind uint8

const (
	ARM64PoolAccessLoad ARM64PoolAccessKind = iota
	ARM64PoolAccessStore
)

// ARM64PoolRegisterClass identifies the register file used by the access.
// Only GPR loads can establish object-pointer provenance for call/decompiler
// consumers; FP/SIMD loads are still real pool xrefs but carry immediate data.
type ARM64PoolRegisterClass uint8

const (
	ARM64PoolRegGPR ARM64PoolRegisterClass = iota
	ARM64PoolRegFP
)

// ARM64PoolAccess is one statically-identified object-pool word access. Reg is
// interpreted in RegClass: the destination register for loads and the source
// register for stores. A single LDP produces two load records, and a 16-byte Q
// load also produces two records for the two physical 8-byte pool entries it
// spans.
type ARM64PoolAccess struct {
	PC        uint64
	Reg       int
	PoolIndex int
	Note      string
	Kind      ARM64PoolAccessKind
	RegClass  ARM64PoolRegisterClass
	// Direct is true only for a one-instruction immediate-offset access whose
	// memory base is PP itself. False includes ADD-derived bases and the large
	// MOVZ/MOVK register-offset fallback even though that fallback still uses PP
	// as the architectural memory base.
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

func poolAccessNote(index int, pool map[int]string) string {
	if s, ok := pool[index]; ok {
		return fmt.Sprintf("PP[%d] %s", index, s)
	}
	return fmt.Sprintf("PP[%d]", index)
}

// ExtractARM64PoolAccesses recovers the exact pool slot(s) addressed by ARM64
// object-pool load/store sequences. It follows only constants constructed
// inside the same basic block, so a branch that bypasses an address-building
// prefix cannot fabricate a pool fact at a join.
//
// The handled shapes are the SDK's LoadWordFromPoolIndex,
// StoreWordToPoolIndex, LoadDoubleWordFromPoolIndex, and LoadS/D/QImmediate
// lowerings across the supported releases: direct LDR/STR/LDP/FP loads from PP,
// ADD-immediate address construction (including two consecutive ADDs for pair
// loads), and large-offset materialization followed by register-add or
// register-offset access. The generic PrepareLargeOffset path can materialize a
// positive pool displacement with MOVZ/MOVK, shifted MOVZ, or logical-immediate
// ORR; all are tracked. Register-offset pool accesses are deliberately limited
// to the SDK's unscaled byte-offset form; scaled [base,index,LSL #N] addressing
// is a different compiler shape. All instruction semantics come from
// internal/arch/arm64.
func ExtractARM64PoolAccesses(insts []Inst, pool map[int]string) []ARM64PoolAccess {
	if len(insts) == 0 {
		return nil
	}

	cfg := BuildCFG("pp-accesses", insts)
	var out []ARM64PoolAccess
	maxInt := int64(int(^uint(0) >> 1))

	record := func(kind ARM64PoolAccessKind, regClass ARM64PoolRegisterClass, pc uint64, reg int, byteOff int64, width int, direct bool) {
		if reg < 0 || reg >= 32 || (regClass == ARM64PoolRegGPR && reg >= 31) || byteOff < 0 || byteOff > maxInt || width <= 0 {
			return
		}
		// Pool entries are 8-byte words. A Q load spans two consecutive entries;
		// S/D/GPR accesses stay within one. Record one physical xref per touched
		// slot so strxref can target either half of an Immediate128 entry.
		slots := (width + sdk.PoolElementSize - 1) / sdk.PoolElementSize
		for slot := 0; slot < slots; slot++ {
			off, ok := addInt64(byteOff, int64(slot*sdk.PoolElementSize))
			if !ok || off > maxInt {
				return
			}
			idx, ok := ARM64PoolIndex(int(off))
			if !ok {
				return
			}
			out = append(out, ARM64PoolAccess{
				PC:        pc,
				Reg:       reg,
				PoolIndex: idx,
				Note:      poolAccessNote(idx, pool),
				Kind:      kind,
				RegClass:  regClass,
				Direct:    direct,
			})
		}
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
			return addInt64(a, b)
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
						record(ARM64PoolAccessLoad, ARM64PoolRegGPR, inst.Addr, int(inst.Raw&0x1f), total, 8, direct)
					}
				}
				killDefs(inst.Raw)
				continue
			}

			// Register-offset LDR. Large pool offsets are materialized as an
			// absolute byte count and then used unscaled against PP. Reject the
			// scaled form: it is not emitted by LoadWordFromPoolIndex.
			if base, rm, rt, scaled, ok := arm64.LDR64RegisterOffset(inst.Raw); ok {
				baseOff, baseKnown, _ := baseOffset(base)
				idxFact := factFor(rm)
				if !scaled && baseKnown && idxFact.kind == arm64PoolAddrAbsolute && idxFact.value >= 0 {
					if total, ok := add(baseOff, idxFact.value); ok {
						record(ARM64PoolAccessLoad, ARM64PoolRegGPR, inst.Addr, rt, total, 8, false)
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
							record(ARM64PoolAccessLoad, ARM64PoolRegGPR, inst.Addr, pair.Reg1, first, 8, direct)
							if second, ok := add(first, 8); ok {
								record(ARM64PoolAccessLoad, ARM64PoolRegGPR, inst.Addr, pair.Reg2, second, 8, direct)
							}
						}
					}
				}
				killDefs(inst.Raw)
				continue
			}

			// StoreWordToPoolIndex mirrors the scalar load lowering: direct
			// unsigned-offset STR, ADD-derived base + STR, or a materialized
			// byte displacement used as an unscaled register offset.
			if base, low, src, ok := arm64.STR64UnsignedOffset(inst.Raw); ok {
				if upper, known, direct := baseOffset(base); known {
					if total, ok := add(upper, int64(low)); ok {
						record(ARM64PoolAccessStore, ARM64PoolRegGPR, inst.Addr, src, total, 8, direct)
					}
				}
				killDefs(inst.Raw)
				continue
			}

			if base, rm, src, scaled, ok := arm64.STR64RegisterOffset(inst.Raw); ok {
				baseOff, baseKnown, _ := baseOffset(base)
				idxFact := factFor(rm)
				if !scaled && baseKnown && idxFact.kind == arm64PoolAddrAbsolute && idxFact.value >= 0 {
					if total, ok := add(baseOff, idxFact.value); ok {
						record(ARM64PoolAccessStore, ARM64PoolRegGPR, inst.Addr, src, total, 8, false)
					}
				}
				killDefs(inst.Raw)
				continue
			}

			// LoadS/D/QImmediate uses the same PrepareLargeOffset address
			// construction as scalar GPR loads, but reads FP/SIMD immediates.
			// Q is 16 bytes and therefore references two adjacent pool slots.
			if base, rt, low, width, ok := arm64.FPLoadUnsignedOffset(inst.Raw); ok {
				if upper, known, direct := baseOffset(base); known {
					if total, ok := add(upper, int64(low)); ok {
						record(ARM64PoolAccessLoad, ARM64PoolRegFP, inst.Addr, rt, total, width, direct)
					}
				}
				continue
			}

			if base, rm, rt, width, scaled, ok := arm64.FPLoadRegisterOffset(inst.Raw); ok {
				baseOff, baseKnown, _ := baseOffset(base)
				idxFact := factFor(rm)
				if !scaled && baseKnown && idxFact.kind == arm64PoolAddrAbsolute && idxFact.value >= 0 {
					if total, ok := add(baseOff, idxFact.value); ok {
						record(ARM64PoolAccessLoad, ARM64PoolRegFP, inst.Addr, rt, total, width, false)
					}
				}
				continue
			}

			// Exact MOV register alias: carry an address-building constant/fact.
			if rd, rm, ok := arm64.MOVOrr(inst.Raw); ok {
				setFact(rd, factFor(rm))
				continue
			}

			// Large-offset fallback materializes a 32-bit byte displacement.
			if rd, imm, shift, ok := arm64.MOVZ64Shifted(inst.Raw); ok {
				value := uint64(imm) << uint(shift)
				if value > uint64(1<<63-1) {
					setFact(rd, arm64PoolAddrFact{})
				} else {
					setFact(rd, arm64PoolAddrFact{kind: arm64PoolAddrAbsolute, value: int64(value)})
				}
				continue
			}
			if rd, imm, ok := arm64.ORR64ImmediateFromZR(inst.Raw); ok {
				if imm > uint64(1<<63-1) {
					setFact(rd, arm64PoolAddrFact{})
				} else {
					setFact(rd, arm64PoolAddrFact{kind: arm64PoolAddrAbsolute, value: int64(imm)})
				}
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

func arm64PoolNotesByPC(accesses []ARM64PoolAccess) map[uint64]map[int]string {
	if len(accesses) == 0 {
		return nil
	}
	out := make(map[uint64]map[int]string)
	for _, access := range accesses {
		if access.Kind != ARM64PoolAccessLoad || access.RegClass != ARM64PoolRegGPR {
			continue
		}
		m := out[access.PC]
		if m == nil {
			m = make(map[int]string)
			out[access.PC] = m
		}
		m[access.Reg] = access.Note
	}
	return out
}

func addInt64(a, b int64) (int64, bool) {
	if b > 0 && a > (1<<63-1)-b {
		return 0, false
	}
	if b < 0 && a < (-1<<63)-b {
		return 0, false
	}
	return a + b, true
}
