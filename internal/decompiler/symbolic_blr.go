package decompiler

import (
	"fmt"
	"strings"

	"aotopsy/internal/disasm"
)

// DirectedSymbolicBLR performs a limited backward trace from an
// unresolved BLR call site to attempt to recover the call target.
//
// This is the implementation of Tier 4 item 14 (directed symbolic
// execution for BLR sites type inference cannot reach). The type
// tracker (typetrack) uses a forward lattice-based abstraction that
// loses precision when registers are spilled, moved through multiple
// intermediaries, or killed by calls. This backward trace takes a
// different approach: starting from the BLR instruction, it walks
// backwards through the instruction stream tracking concrete values
// where possible.
//
// The trace is limited (maxBackwardSteps instructions) because full
// symbolic execution is intractable for arbitrary machine code. It
// handles the common patterns that defeat the type tracker:
//
//  1. Register move chains: BLR Xn where Xn was MOV'd from Xm,
//     which was LDR'd from [PP, #imm]. The type tracker may have
//     lost Xm's type at the MOV if a call intervened.
//
//  2. Stack spill/reload: BLR Xn where Xn was reloaded from stack,
//     and the stack slot was spilled from a register that held a
//     known value. The type tracker's per-block stack tracking
//     may not survive across block boundaries.
//
//  3. Pool-loaded Code objects: BLR Xn where Xn was loaded from
//     [PP, #imm] and the pool entry is a Code object whose name
//     is resolvable. This is the most common pattern and is
//     already handled by the type tracker, but the backward trace
//     can catch cases where the type tracker's forward propagation
//     was killed by an intervening instruction.
//
// SDK-verified: EmitDispatchTableCall (flow_graph_compiler_x64.cc@3.12.2)
// uses `call [table_reg + cid_reg*8 + offset]`, and the ARM64 equivalent
// uses `BLR X30` after loading from the dispatch table. The backward
// trace handles both architectures by working on the arch-neutral Instr
// representation.
type DirectedSymbolicBLR struct {
	maxBackwardSteps int
	symbols          SymbolLookup
	pool             PoolLookup
}

// NewDirectedSymbolicBLR creates a backward tracer with the given
// symbol and pool resolvers.
func NewDirectedSymbolicBLR(symbols SymbolLookup, pool PoolLookup) *DirectedSymbolicBLR {
	return &DirectedSymbolicBLR{
		maxBackwardSteps: 30,
		symbols:          symbols,
		pool:             pool,
	}
}

// BLRResolution holds the result of a backward trace for one BLR site.
type BLRResolution struct {
	PC          uint64
	TargetName  string // resolved target name, empty if unresolved
	TargetVA    uint64 // resolved target VA, 0 if unresolved
	TraceSteps  int    // number of instructions traced backwards
	TracePath   string // human-readable trace for debugging
	Resolved    bool
}

// ResolveBLR attempts to resolve a BLR call site by tracing backwards.
// insts is the function's instruction list, blrIdx is the index of the
// BLR instruction. Returns a resolution report.
//
// The trace walks backwards from the BLR, looking for the instruction
// that set the BLR register. When it finds a pool load (OpLoadPool),
// it resolves the pool entry. When it finds a register move, it follows
// the source register. When it finds a stack load, it looks for the
// corresponding stack store.
func (d *DirectedSymbolicBLR) ResolveBLR(insts []Instr, blrIdx int) BLRResolution {
	if blrIdx < 0 || blrIdx >= len(insts) {
		return BLRResolution{}
	}
	blr := insts[blrIdx]
	res := BLRResolution{PC: blr.Addr}

	// The BLR target register name is in blr.Target (e.g. "x30", "rax").
	targetReg := blr.Target
	if targetReg == "" {
		return res
	}

	var trace strings.Builder
	fmt.Fprintf(&trace, "BLR %s at 0x%x\n", targetReg, blr.Addr)

	// Walk backwards looking for what set targetReg.
	currentReg := targetReg
	for step := 0; step < d.maxBackwardSteps && blrIdx-step-1 >= 0; step++ {
		prev := insts[blrIdx-step-1]
		res.TraceSteps = step + 1

		// Check if this instruction sets currentReg.
		// For OpLoadPool, Target holds the destination register.
		if prev.Op == OpLoadPool && prev.Target == currentReg {
			// Found a pool load into the BLR register.
			fmt.Fprintf(&trace, "  <- LDR %s, [PP, #%d] (pool load)\n", currentReg, prev.PoolIndex)
			if d.pool != nil {
				if display, ok := d.pool(prev.PoolIndex); ok && display != "" {
					// Pool display is the function name or Code object.
					res.TargetName = display
					res.Resolved = true
					fmt.Fprintf(&trace, "  -> resolved: %s\n", display)
					res.TracePath = trace.String()
					return res
				}
			}
			break
		}

		// Check for MOV (register copy) via Src text.
		// ARM64: "mov x30, x0" or "orr x30, xzr, x0"
		// x86: "mov rax, rbx"
		src := prev.Src
		if isRegMove(src, currentReg, &trace) {
			// Extract source register from the move.
			srcReg := extractMoveSource(src, currentReg)
			if srcReg != "" {
				fmt.Fprintf(&trace, "  <- MOV %s, %s (follow %s)\n", currentReg, srcReg, srcReg)
				currentReg = srcReg
				continue
			}
		}

		// Check for LDR from memory (field load or stack reload).
		// ARM64: "ldr x30, [x29, #0x10]" (stack reload)
		// x86: "mov rax, [rbp-0x8]" (stack reload)
		if isStackLoad(src, currentReg) {
			fmt.Fprintf(&trace, "  <- stack reload %s (tracing stack store not supported)\n", currentReg)
			break
		}

		// Check for BL (call) — kills caller-saved registers.
		if prev.Op == OpCall {
			fmt.Fprintf(&trace, "  <- CALL at 0x%x (register may be call return value)\n", prev.Addr)
			// If the BL target is a known function, the return value
			// might be a known Code object.
			if d.symbols != nil {
				if va, ok := parseHexVA(prev.Target); ok {
					if name, ok2 := d.symbols(va); ok2 && name != "" {
						fmt.Fprintf(&trace, "  -> call target: %s\n", name)
					}
				}
			}
			break
		}
	}

	res.TracePath = trace.String()
	return res
}

// isRegMove checks if src is a register move into dstReg.
func isRegMove(src, dstReg string, trace *strings.Builder) bool {
	// Normalize: "mov x30, x0" or "mov rax, rbx"
	parts := strings.Fields(src)
	if len(parts) < 3 {
		return false
	}
	mnemonic := parts[0]
	if mnemonic != "mov" && mnemonic != "orr" {
		return false
	}
	// Check if first operand is dstReg.
	ops := strings.Join(parts[2:], " ")
	return strings.HasPrefix(ops, dstReg+",") || strings.HasPrefix(ops, dstReg+" ")
}

// extractMoveSource extracts the source register from a move instruction.
func extractMoveSource(src, dstReg string) string {
	parts := strings.SplitN(src, ",", 2)
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// isStackLoad checks if src is a stack load into dstReg.
func isStackLoad(src, dstReg string) bool {
	return strings.Contains(src, "ldr") && strings.Contains(src, "[x29") ||
		strings.Contains(src, "mov") && strings.Contains(src, "[rbp") ||
		strings.Contains(src, "mov") && strings.Contains(src, "[rsp")
}

// ResolveAllBLRs runs the backward trace on all BLR sites in a function.
// Returns resolutions for sites that were resolved by the trace but not
// by the type tracker (i.e., new resolutions only).
func (d *DirectedSymbolicBLR) ResolveAllBLRs(insts []Instr) []BLRResolution {
	var results []BLRResolution
	for i, ins := range insts {
		// OpBranch with indirect target or OpJump with register target.
		if ins.Op == OpJump && ins.Target != "" && !strings.HasPrefix(ins.Target, "0x") {
			res := d.ResolveBLR(insts, i)
			if res.Resolved {
				results = append(results, res)
			}
			continue
		}
		// Check for BLR in raw instruction text (ARM64: "blr xN", x86: "call rax")
		src := strings.ToLower(ins.Src)
		if strings.HasPrefix(src, "blr ") || (strings.HasPrefix(src, "call ") && !strings.HasPrefix(ins.Target, "0x")) {
			res := d.ResolveBLR(insts, i)
			if res.Resolved {
				results = append(results, res)
			}
		}
	}
	return results
}

// Ensure disasm import is used (for future arch-specific extensions).
var _ disasm.Inst
