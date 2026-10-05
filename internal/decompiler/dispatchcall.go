package decompiler

import (
	"regexp"
	"strconv"
	"strings"

	"aotopsy/internal/sdk"
)

// A dispatch-table call is how Dart AOT does polymorphic instance dispatch, and
// it used to render as an unresolved indirect call -- the single largest
// remaining category of those. FlowGraphCompiler::EmitDispatchTableCall:
//
//	x86_64 (flow_graph_compiler_x64.cc)
//	  const Register table_reg = RAX;
//	  const intptr_t offset = (selector_offset - DispatchTable origin)
//	                          * compiler::target::kWordSize;
//	  __ LoadDispatchTable(table_reg);
//	  __ call(compiler::Address(table_reg, cid_reg, TIMES_8, offset));
//
//	ARM64 (flow_graph_compiler_arm64.cc)
//	  const intptr_t offset = selector_offset - DispatchTable origin;
//	  2.10/2.12: AddImmediate(cid_reg, cid_reg, offset); load via cid_reg
//	  2.13+:     AddImmediate(LR, cid_reg, offset); load via LR
//
// So the SELECTOR is in the instruction stream on both targets -- scaled into
// the call's displacement on x86_64, and into the immediate of the `add`/`sub`
// that computes LR on ARM64. What is NOT there is the receiver's class id, so
// the call has no single target: the slot is `selector_offset + cid`.
//
// The selector NAME is deliberately not recovered. The obvious route -- read
// the dispatch table at `selector + cid` for every cid and take the majority
// method name -- was built and measured on dart-3.12.2-x64, and it does not
// hold: selector 16421 gives 72 distinct method names over 2565 slots, selector
// 16 gives 152 over 3228. The table is PACKED, so a selector occupies only the
// cids that actually implement it and the surrounding slots belong to other
// selectors. There is signal in the vote (toString, ==, <anonymous closure>
// each dominate different offsets) but not enough to name one without
// inventing, so the offset is reported instead: it is a stable identifier, and
// two call sites sharing one call the same selector.
var (
	// `[rax+8*rcx+0x200a8]`, `[rax+8*rcx-0x80]`, `[rax+8*rcx]` -- the x86_64
	// shape. The displacement is signed because the GDT register points at a
	// biased origin element; selectors below that origin use a negative offset.
	// The index register is caller-selected in Dart 2.10/2.12 and fixed by
	// DispatchTableNullErrorABI from 2.13 onward. Capture it so the exact SDK
	// predicate can reject a modern call using a legacy-only register shape.
	// The table register is RAX by construction (`const Register table_reg = RAX`).
	x64DispatchCallRe = regexp.MustCompile(`^\[rax\+8\*([a-z0-9]+)(?:([+-])0x([0-9a-f]+))?\]$`)
	// `add/sub Xindex, Xcid, #imm`, the instruction that computes the ARM64
	// dispatch index. Xindex is LR from 2.13 onward but is the incoming cid_reg
	// itself in 2.10/2.12.
	arm64IndexAddRe = regexp.MustCompile(`^(add|sub)\s+(x[0-9]+),\s*(x[0-9]+),\s*#(?:0x([0-9a-f]+)|(\d+))`)
	// Large selector offsets do not fit AddImmediate's immediate forms. The SDK
	// materializes them in TMP2 (x17) and then uses a register ADD. Track the
	// common MOVZ form exactly; MOVK/ORR variants remain conservatively unknown.
	arm64Tmp2MovzRe     = regexp.MustCompile(`^movz\s+x17,\s*#(?:0x([0-9a-f]+)|(\d+))(?:,\s*lsl\s*#(\d+))?$`)
	arm64IndexAddTmp2Re = regexp.MustCompile(`^add\s+(x[0-9]+),\s*(x[0-9]+),\s*x17$`)
	// `ldr x30, [x21,xN,lsl #3]` -- the dispatch-table load itself. x21 is
	// DISPATCH_TABLE_REG (constants_arm64.h), indexed by LR and scaled by the
	// word size. The loaded target always lands in LR before `blr x30`.
	arm64DispatchLoadRe = regexp.MustCompile(`^ldr\s+x30,\s*\[x21,\s*(x[0-9]+),\s*lsl\s*#3\]`)
)

// dispatchSelectorUnknown marks a call recognised as a dispatch-table call
// whose selector offset could not be read -- the `add`/`sub` that sets LR was
// not in the same block, or the offset was materialised some other way. The
// call is still worth naming as what it is.
const dispatchSelectorUnknown = -1

// annotateDispatchCalls marks every call that is a dispatch-table call and
// records its selector offset.
//
// It runs over the built blocks rather than inside the two lifters because the
// ARM64 form needs the instruction BEFORE the call, and one pass with the
// stream in hand is simpler than threading a predecessor through both.
func annotateDispatchCalls(fir *FuncIR) {
	isARM64 := fir.LinkReg != ""
	origin, ok := sdk.DispatchTableOriginElement(fir.DartVersion, isARM64)
	if !ok {
		return
	}

	for bi := range fir.Blocks {
		blk := &fir.Blocks[bi]
		// lastIndexImm is the offset most recently written into the register used
		// as the dispatch-table index by an add/sub, or none. Reset per block: a value flowing in from a
		// predecessor is not something this pass can claim to know.
		lastIndexImm, haveIndex := 0, false
		lastIndexReg := ""
		tmp2Val, haveTmp2 := 0, false
		dispatchLoadSeen := false
		for i := range blk.Instrs {
			ins := &blk.Instrs[i]
			if ins.Op != OpCall {
				if isARM64 {
					switch {
					case arm64DispatchLoadRe.MatchString(ins.Src):
						// The load reads LR and writes it back; it consumes
						// the index rather than destroying it. If an add/sub was
						// recovered, require the load to use its destination.
						m := arm64DispatchLoadRe.FindStringSubmatch(ins.Src)
						idxReg, regOK := arm64RegNumber(m[1])
						dispatchLoadSeen = regOK && sdk.IsARM64DispatchTableIndexReg(fir.DartVersion, idxReg) && (!haveIndex || m[1] == lastIndexReg)
					case arm64IndexAddRe.MatchString(ins.Src):
						m := arm64IndexAddRe.FindStringSubmatch(ins.Src)
						dstReg, dstOK := arm64RegNumber(m[2])
						srcReg, srcOK := arm64RegNumber(m[3])
						if !dstOK || !srcOK || !sdk.IsARM64DispatchTableIndexComputation(fir.DartVersion, dstReg, srcReg) {
							haveIndex, dispatchLoadSeen = false, false
							break
						}
						v := parseImmDec(m[4], m[5])
						if m[1] == "sub" {
							v = -v
						}
						lastIndexImm, lastIndexReg, haveIndex = v, m[2], true
					case arm64Tmp2MovzRe.MatchString(ins.Src):
						m := arm64Tmp2MovzRe.FindStringSubmatch(ins.Src)
						v := parseImmDec(m[1], m[2])
						shift := 0
						if m[3] != "" {
							shift, _ = strconv.Atoi(m[3])
						}
						tmp2Val, haveTmp2 = v<<shift, true
					case arm64IndexAddTmp2Re.MatchString(ins.Src):
						m := arm64IndexAddTmp2Re.FindStringSubmatch(ins.Src)
						dstReg, dstOK := arm64RegNumber(m[1])
						srcReg, srcOK := arm64RegNumber(m[2])
						if !haveTmp2 || !dstOK || !srcOK || !sdk.IsARM64DispatchTableIndexComputation(fir.DartVersion, dstReg, srcReg) {
							haveIndex, dispatchLoadSeen = false, false
							break
						}
						lastIndexImm, lastIndexReg, haveIndex = tmp2Val, m[1], true
					default:
						// Invalidate tracked constants/facts only on actual writes. Text
						// mentions of x17/x30 as sources must not destroy provenance.
						if definesReg(ins, "x17") {
							haveTmp2 = false
						}
						if definesReg(ins, "x30") {
							haveIndex, dispatchLoadSeen = false, false
						}
					}
				}
				continue
			}
			if isARM64 {
				if ins.Target == fir.LinkReg && dispatchLoadSeen {
					ins.IsDispatchCall = true
					if haveIndex {
						ins.DispatchSelector = lastIndexImm + origin
					} else {
						ins.DispatchSelector = dispatchSelectorUnknown
					}
				}
				haveIndex, dispatchLoadSeen = false, false
				continue
			}
			if m := x64DispatchCallRe.FindStringSubmatch(ins.Target); m != nil {
				idxReg, regOK := x86RegNumber(m[1])
				if !regOK || !sdk.IsDispatchTableClassIDReg(fir.DartVersion, sdk.ArchX86, idxReg) {
					continue
				}
				disp := 0
				if m[3] != "" {
					if v, err := strconv.ParseInt(m[3], 16, 64); err == nil {
						disp = int(v)
						if m[2] == "-" {
							disp = -disp
						}
					}
				}
				// The x86_64 displacement is scaled by the word size; the
				// ARM64 one is not (its Address is Scaled by the assembler).
				// A genuine GDT displacement is word-aligned and cannot address
				// before selector zero, even though the regex accepts the full
				// signed addressing syntax.
				if disp%8 != 0 || disp/8+origin < 0 {
					continue
				}
				ins.IsDispatchCall = true
				ins.DispatchSelector = disp/8 + origin
			}
		}
	}
}

func definesReg(ins *Instr, reg string) bool {
	for _, defined := range ins.DefRegs {
		if defined == reg {
			return true
		}
	}
	return false
}

func parseImmDec(hex, dec string) int {
	if hex != "" {
		if v, err := strconv.ParseInt(hex, 16, 64); err == nil {
			return int(v)
		}
		return 0
	}
	if v, err := strconv.Atoi(dec); err == nil {
		return v
	}
	return 0
}

func arm64RegNumber(name string) (int, bool) {
	if !strings.HasPrefix(name, "x") {
		return 0, false
	}
	reg, err := strconv.Atoi(strings.TrimPrefix(name, "x"))
	return reg, err == nil && reg >= 0 && reg <= 30
}

func x86RegNumber(name string) (int, bool) {
	for reg := 0; reg < 16; reg++ {
		if sdk.X86RegName(reg) == name {
			return reg, true
		}
	}
	return 0, false
}
