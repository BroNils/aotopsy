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
//	  const intptr_t offset = (selector_offset - DispatchTable::kOriginElement)
//	                          * compiler::target::kWordSize;
//	  __ LoadDispatchTable(table_reg);
//	  __ call(compiler::Address(table_reg, cid_reg, TIMES_8, offset));
//
//	ARM64 (flow_graph_compiler_arm64.cc)
//	  const intptr_t offset = selector_offset - DispatchTable::kOriginElement;
//	  __ AddImmediate(LR, cid_reg, offset);
//	  __ Call(compiler::Address(DISPATCH_TABLE_REG, LR, UXTX, Address::Scaled));
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
	// `[rax+8*rcx+0x200a8]`, `[rax+8*rcx]` -- the x86_64 shape. The index
	// register is DispatchTableNullErrorABI::kClassIdReg and is not fixed by
	// the SDK, so it is matched loosely; the table register is RAX by
	// construction (`const Register table_reg = RAX`).
	x64DispatchCallRe = regexp.MustCompile(`^\[rax\+8\*[a-z0-9]+(?:\+0x([0-9a-f]+))?\]$`)
	// `add x30, x0, #0x1234` / `sub x30, x0, #0x1234`, the instruction that
	// computes LR before the ARM64 dispatch call.
	arm64LRAddRe = regexp.MustCompile(`^(add|sub)\s+x30,\s*[a-z0-9]+,\s*#(?:0x([0-9a-f]+)|(\d+))`)
	// `ldr x30, [x21,x30,lsl #3]` -- the dispatch-table load itself. x21 is
	// DISPATCH_TABLE_REG (constants_arm64.h), indexed by LR and scaled by the
	// word size, which is what `Call(Address(DISPATCH_TABLE_REG, LR, UXTX,
	// Scaled))` assembles to: a load followed by `blr`. This instruction alone
	// identifies the call; the `add`/`sub` above it supplies the selector.
	arm64DispatchLoadRe = regexp.MustCompile(`^ldr\s+x30,\s*\[x21,\s*x30,\s*lsl\s*#3\]`)
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
	origin := sdk.DispatchTableOriginElement(isARM64)

	for bi := range fir.Blocks {
		blk := &fir.Blocks[bi]
		// lastLRImm is the offset most recently written into LR by an
		// add/sub, or none. Reset per block: a value flowing in from a
		// predecessor is not something this pass can claim to know.
		lastLRImm, haveLR := 0, false
		dispatchLoadSeen := false
		for i := range blk.Instrs {
			ins := &blk.Instrs[i]
			if ins.Op != OpCall {
				if isARM64 {
					switch {
					case arm64DispatchLoadRe.MatchString(ins.Src):
						// The load reads LR and writes it back; it consumes
						// the offset rather than destroying it.
						dispatchLoadSeen = true
					case arm64LRAddRe.MatchString(ins.Src):
						m := arm64LRAddRe.FindStringSubmatch(ins.Src)
						v := parseImmDec(m[2], m[3])
						if m[1] == "sub" {
							v = -v
						}
						lastLRImm, haveLR = v, true
					case strings.Contains(ins.Src, "x30"):
						// Any other write to LR invalidates both.
						haveLR, dispatchLoadSeen = false, false
					}
				}
				continue
			}
			if isARM64 {
				if ins.Target == fir.LinkReg && dispatchLoadSeen {
					ins.IsDispatchCall = true
					if haveLR {
						ins.DispatchSelector = lastLRImm + origin
					} else {
						ins.DispatchSelector = dispatchSelectorUnknown
					}
				}
				haveLR, dispatchLoadSeen = false, false
				continue
			}
			if m := x64DispatchCallRe.FindStringSubmatch(ins.Target); m != nil {
				disp := 0
				if m[1] != "" {
					if v, err := strconv.ParseInt(m[1], 16, 64); err == nil {
						disp = int(v)
					}
				}
				// The x86_64 displacement is scaled by the word size; the
				// ARM64 one is not (its Address is Scaled by the assembler).
				ins.IsDispatchCall = true
				ins.DispatchSelector = disp/8 + origin
			}
		}
	}
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
