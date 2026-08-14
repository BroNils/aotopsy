package decompiler

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/arch/x86/x86asm"

	"aotopsy/internal/arch"
	"aotopsy/internal/disasm"
)

// x86_64 Dart AOT reserved-register convention (confirmed empirically
// against this project's own live captures):
// PP=r15 (object pool pointer), THR=r14 (Thread*). Dart's x64 calling
// convention is NOT plain SysV; RDI/RSI/RDX/RCX/R8/R9 are used here only
// as a readable arg0..arg5 naming convention for pseudocode display, not
// a claim about the real Dart ABI's exact register assignment.
const (
	x86PoolReg   = "r15"
	x86ThreadReg = "r14"
	x86FrameReg  = "rbp"
	x86ReturnReg = "rax"
	// x86StackReg is the Dart stack pointer. constants_x64.h:
	// `const Register SPREG = RSP;`.
	x86StackReg = "rsp"
)

var x86ArgRegs = []string{"rdi", "rsi", "rdx", "rcx", "r8", "r9"}

// x86Inst is one decoded x86_64 instruction, kept minimal (this package
// doesn't need a general-purpose x86 disassembler elsewhere, unlike
// ARM64 which aotopsy already has via internal/disasm).
type x86Inst struct {
	Addr uint64
	Len  int
	Inst x86asm.Inst
}

// DecodeX86Range decodes every instruction in the ENTIRE given byte range
// starting at baseVA, stopping only at a decode error or end of data --
// matching internal/disasm.Disassemble's ARM64 convention exactly.
//
// This function used to stop at the first RET, on the mistaken
// assumption that RET always means "end of function." That is wrong for
// any function with more than one return statement (e.g. an early-return
// guard clause followed by more logic, like MathTools.factorial's `if (n
// <= 1) return 1;` early exit followed by the real recursive-multiply
// case) -- confirmed as a real bug by testing this decompiler against a
// from-scratch-compiled sample app and comparing the pseudocode against
// the known Dart source: the early-RET-stop caused everything after the
// first return to be silently missing, making the recursive call/branch
// resolve as "unresolved branch target" even though the bytes were right
// there in the CodeRange the caller already sized correctly.
func DecodeX86Range(data []byte, baseVA uint64) []x86Inst {
	var out []x86Inst
	off := 0
	for off < len(data) {
		inst, err := x86asm.Decode(data[off:], 64)
		if err != nil || inst.Len == 0 {
			break
		}
		out = append(out, x86Inst{Addr: baseVA + uint64(off), Len: inst.Len, Inst: inst})
		off += inst.Len
	}
	return out
}

// BuildX86IR lifts a decoded x86_64 instruction range into FuncIR, using
// the same leader/partition/successor algorithm as
// internal/disasm.BuildCFG (kept as a local, simpler implementation since
// x86 instructions are variable-length and carry structured Args, unlike
// ARM64's fixed 4-byte raw-encoding approach).
func BuildX86IR(name string, insts []x86Inst) *FuncIR {
	if len(insts) == 0 {
		return newFuncIR(name, 0)
	}
	fir := newFuncIR(name, insts[0].Addr)
	fir.ArgRegs = x86ArgRegs
	fir.FrameReg = x86FrameReg
	fir.ReturnReg = x86ReturnReg
	fir.PoolReg = x86PoolReg
	// PP is tagged on x86_64, so FieldAddress has already subtracted the
	// heap-object tag and the displacement is 16+8*index-1.
	fir.PoolIndexOf = disasm.X64PoolIndex
	fir.ThreadReg = x86ThreadReg
	fir.StackReg = x86StackReg

	funcStart := insts[0].Addr
	funcEnd := insts[len(insts)-1].Addr + uint64(insts[len(insts)-1].Len) //nolint:gosec // instruction length is always non-negative

	addrToIdx := make(map[uint64]int, len(insts))
	for i, in := range insts {
		addrToIdx[in.Addr] = i
	}

	leaders := map[int]bool{0: true}
	kind := make([]branchKind, len(insts)) // classification per instruction
	target := make([]uint64, len(insts))
	hasTarget := make([]bool, len(insts))

	for i, in := range insts {
		k, tgt, ok := classifyX86Branch(in)
		kind[i] = k
		if ok {
			target[i] = tgt
			hasTarget[i] = true
		}
		if k == branchNone {
			continue
		}
		if i+1 < len(insts) {
			leaders[i+1] = true
		}
		if ok && tgt >= funcStart && tgt < funcEnd {
			if idx, exists := addrToIdx[tgt]; exists {
				leaders[idx] = true
			}
		}
	}

	sorted := make([]int, 0, len(leaders))
	for idx := range leaders {
		sorted = append(sorted, idx)
	}
	sort.Ints(sorted)

	leaderToBlock := make(map[int]int, len(sorted))
	blocks := make([]Block, len(sorted))
	for i, start := range sorted {
		end := len(insts)
		if i+1 < len(sorted) {
			end = sorted[i+1]
		}
		blocks[i] = Block{ID: i, StartVA: insts[start].Addr}
		for j := start; j < end; j++ {
			blocks[i].Instrs = append(blocks[i].Instrs, liftX86Instr(insts[j], kind[j], target[j], hasTarget[j]))
		}
		leaderToBlock[start] = i
	}

	for i, start := range sorted {
		end := len(insts)
		if i+1 < len(sorted) {
			end = sorted[i+1]
		}
		if end <= start {
			continue
		}
		lastIdx := end - 1
		k := kind[lastIdx]
		switch k {
		case branchNone:
			if nb, ok := leaderToBlock[end]; ok {
				blocks[i].Succs = append(blocks[i].Succs, Succ{BlockID: nb})
			}
		case branchRet:
			blocks[i].IsTerm = true
		case branchJmpDirect:
			if hasTarget[lastIdx] {
				if idx, ok := addrToIdx[target[lastIdx]]; ok {
					if bid, ok := leaderToBlock[idx]; ok {
						blocks[i].Succs = append(blocks[i].Succs, Succ{BlockID: bid})
						break
					}
				}
			}
			blocks[i].IsTerm = true
		case branchJmpIndirect:
			blocks[i].IsTerm = true
		case branchCond:
			if hasTarget[lastIdx] {
				if idx, ok := addrToIdx[target[lastIdx]]; ok {
					if bid, ok := leaderToBlock[idx]; ok {
						blocks[i].Succs = append(blocks[i].Succs, Succ{BlockID: bid, Cond: "T"})
					}
				}
			}
			if nb, ok := leaderToBlock[end]; ok {
				blocks[i].Succs = append(blocks[i].Succs, Succ{BlockID: nb, Cond: "F"})
			}
		}
	}

	for _, b := range blocks {
		fir.addBlock(b)
	}
	return fir
}

type branchKind int

const (
	branchNone branchKind = iota
	branchRet
	branchJmpDirect
	branchJmpIndirect
	branchCond
)

func classifyX86Branch(in x86Inst) (branchKind, uint64, bool) {
	op := in.Inst.Op
	if op == x86asm.RET {
		return branchRet, 0, false
	}
	if arch.IsX86CondJump(op) {
		if tgt, ok := arch.X86RelTarget(in.Inst, in.Addr, in.Len); ok {
			return branchCond, tgt, true
		}
		return branchCond, 0, false
	}
	if op == x86asm.JMP {
		if tgt, ok := arch.X86RelTarget(in.Inst, in.Addr, in.Len); ok {
			return branchJmpDirect, tgt, true
		}
		return branchJmpIndirect, 0, false
	}
	return branchNone, 0, false
}

// x86CondOp maps a Jcc opcode to a Dart comparison operator, applied
// against the block's last CMP/TEST operands (same lastCmp mechanism as
// ARM64's B.cc). Unsigned variants (A/AE/B/BE) map to the same operators
// as their signed counterparts (G/GE/L/LE), the same known simplification
// flutterdec's own cond_from_cmp makes.
func x86CondOp(op x86asm.Op) string {
	switch op {
	case x86asm.JE:
		return "=="
	case x86asm.JNE:
		return "!="
	case x86asm.JL, x86asm.JB:
		return "<"
	case x86asm.JLE, x86asm.JBE:
		return "<="
	case x86asm.JG, x86asm.JA:
		return ">"
	case x86asm.JGE, x86asm.JAE:
		return ">="
	}
	return "?"
}

func liftX86Instr(in x86Inst, k branchKind, tgt uint64, hasTgt bool) Instr {
	src := strings.ToLower(in.Inst.String())
	ir := Instr{Addr: in.Addr, Src: src, PoolIndex: -1}

	switch {
	case k == branchRet:
		ir.Op = OpReturn
	case in.Inst.Op == x86asm.CALL:
		ir.Op = OpCall
		if r, ok := arch.X86RelTarget(in.Inst, in.Addr, in.Len); ok {
			ir.Target = fmt.Sprintf("0x%x", r)
		} else {
			ir.Target = x86IndirectTargetText(in)
		}
	case k == branchJmpDirect:
		ir.Op = OpJump
		ir.Target = fmt.Sprintf("0x%x", tgt)
	case k == branchJmpIndirect:
		ir.Op = OpJump
		ir.Target = x86IndirectTargetText(in)
	case k == branchCond:
		ir.Op = OpBranch
		ir.CondKind = "cmp"
		ir.CondOp = x86CondOp(in.Inst.Op)
		if hasTgt {
			ir.Target = fmt.Sprintf("0x%x", tgt)
		}
	case in.Inst.Op == x86asm.MOV && isX86PoolLoad(in):
		ir.Op = OpLoadPool
		ir.PoolIndex = x86PoolIndex(in)
		if len(in.Inst.Args) > 0 {
			if reg, ok := in.Inst.Args[0].(x86asm.Reg); ok {
				ir.Target = strings.ToLower(reg.String())
			}
		}
	}
	return ir
}

// x86IndirectTargetText renders an indirect call/jump target operand as
// readable text (register name, or a "[base+disp]" memory description)
// for the emitter's call-intent resolution to inspect.
func x86IndirectTargetText(in x86Inst) string {
	for _, arg := range in.Inst.Args {
		if arg == nil {
			continue
		}
		if reg, ok := arg.(x86asm.Reg); ok {
			return strings.ToLower(reg.String())
		}
		if mem, ok := arg.(x86asm.Mem); ok {
			return strings.ToLower(mem.String())
		}
	}
	return ""
}

// isX86PoolLoad recognizes "mov reg, [r15+disp]" -- a load from the
// object pool register.
func isX86PoolLoad(in x86Inst) bool {
	for _, arg := range in.Inst.Args {
		mem, ok := arg.(x86asm.Mem)
		if !ok {
			continue
		}
		if strings.ToLower(mem.Base.String()) == x86PoolReg {
			return true
		}
	}
	return false
}

// x86PoolIndex converts a "[r15+disp]" displacement to a pool slot index
// using this project's own already-established x86_64 convention
// (disp/8 - 2, confirmed identical in cmd/aotopsy/x64refs.go and
// gdtcall.go's poolIdx computation -- x86_64's PP register points 2
// slots further into the pool array than ARM64's does, unlike ARM64
// where idx is a plain byteOff/8 with no adjustment, per
// internal/disasm/annotate.go's PPAnnotator).
func x86PoolIndex(in x86Inst) int {
	for _, arg := range in.Inst.Args {
		mem, ok := arg.(x86asm.Mem)
		if !ok || strings.ToLower(mem.Base.String()) != x86PoolReg {
			continue
		}
		idx, idxOK := disasm.X64PoolIndex(mem.Disp)
		if !idxOK {
			return -1
		}
		return idx
	}
	return -1
}
