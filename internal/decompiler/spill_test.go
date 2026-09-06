package decompiler

import (
	"strings"
	"testing"

	"aotopsy/internal/sdk"
)

// TestForwardedExpressionDoesNotExplode is a guard against exponential growth
// in the value-forwarding representation.
//
// Register values are expression TEXT and arithmetic emits no statement of its
// own, so an instruction whose operands both read the same register doubles the
// stored expression. Dart's `_SystemHash.combine` reads its accumulator three
// times per round, and `SystemHash.hash20` chains twenty rounds: before
// setReg's spill, a two-block 896-byte function emitted ~570 MB and took the
// process out of memory.
//
// Nothing else catches this. maxStepsPerEmitter counts walk steps, and the walk
// here is trivial -- the blowup is entirely in string length. Every corpus test
// caps at 400 functions, and the offender sits well past that.
func TestForwardedExpressionDoesNotExplode(t *testing.T) {
	fir := newFuncIR("combine_chain", 0x8000)
	fir.ArgRegs = arm64ArgRegs
	fir.FrameReg = sdk.ARM64FrameRegStr
	fir.ReturnReg = sdk.ARM64ReturnRegStr

	// Each round is `x0 = (x0 + x0) + x0`, i.e. three reads of the register
	// being written -- the same shape as _SystemHash.combine, which is what
	// makes the expression grow geometrically rather than linearly.
	const rounds = 24
	var instrs []Instr
	addr := uint64(0x8000)
	for i := 0; i < rounds; i++ {
		instrs = append(instrs,
			Instr{Addr: addr, Op: OpOther, Src: "add x1, x0, x0"},
			Instr{Addr: addr + 4, Op: OpOther, Src: "add x0, x1, x0"},
		)
		addr += 8
	}
	instrs = append(instrs, Instr{Addr: addr, Op: OpReturn, Src: "ret"})
	fir.addBlock(Block{ID: 0, StartVA: 0x8000, Instrs: instrs})

	art := EmitPseudocode(fir, nil, nil)

	// Without the bound this is astronomically large; with it, linear in the
	// instruction count. The threshold is deliberately loose -- the point is
	// the difference between linear and exponential, not a byte-exact figure.
	if n := len(art.Source); n > 64*1024 {
		t.Fatalf("emitted %d bytes for %d instructions; expression forwarding is growing geometrically",
			n, len(instrs))
	}
	if probs := ValidateSource(art.Source); len(probs) > 0 {
		t.Errorf("spilled source does not validate: %v\n%s", probs, art.Source)
	}
	// The computation must still be present: dropping the over-long value
	// instead of naming it would delete the arithmetic from the output with
	// nothing saying so.
	if !strings.Contains(art.Source, "_t") {
		t.Errorf("no temporary was materialized, so the chain was silently dropped:\n%s", art.Source)
	}
}

// TestSpilledTempsAreDeclaredBeforeUse checks the property that makes the
// spill safe to emit: every `_tN` that is read has been declared earlier in
// the source. A temp minted in one state and read after a clone or join would
// otherwise be an undefined variable.
func TestSpilledTempsAreDeclaredBeforeUse(t *testing.T) {
	fir := newFuncIR("branchy_chain", 0x9000)
	fir.ArgRegs = arm64ArgRegs
	fir.FrameReg = sdk.ARM64FrameRegStr
	fir.ReturnReg = sdk.ARM64ReturnRegStr

	long := func(dst string, n int) []Instr {
		var out []Instr
		a := uint64(0x9000)
		for i := 0; i < n; i++ {
			out = append(out,
				Instr{Addr: a, Op: OpOther, Src: "add x1, " + dst + ", " + dst},
				Instr{Addr: a + 4, Op: OpOther, Src: "add " + dst + ", x1, " + dst})
			a += 8
		}
		return out
	}

	b0 := long("x0", 12)
	b0 = append(b0, Instr{Addr: 0x9100, Op: OpBranch, Src: "cbz x2, 0x9200",
		Target: "0x9200", CondKind: "eqz", CondReg: "x2"})
	fir.addBlock(Block{ID: 0, StartVA: 0x9000, Instrs: b0,
		Succs: []Succ{{BlockID: 1, Cond: "T"}, {BlockID: 2, Cond: "F"}}})
	fir.addBlock(Block{ID: 1, StartVA: 0x9200, Instrs: append(long("x0", 6),
		Instr{Addr: 0x9280, Op: OpReturn, Src: "ret"})})
	fir.addBlock(Block{ID: 2, StartVA: 0x9300, Instrs: append(long("x0", 6),
		Instr{Addr: 0x9380, Op: OpReturn, Src: "ret"})})

	src := EmitPseudocode(fir, nil, nil).Source

	declared := map[string]bool{}
	for _, line := range strings.Split(src, "\n") {
		trim := strings.TrimSpace(line)
		// Reads first: a name used on a line that also declares it is fine
		// (`var _t2 = _t1 + 1;`), but a name read before any declaration is not.
		for _, tok := range tokensLike(trim, "_t") {
			if strings.HasPrefix(trim, "var "+tok+" =") {
				continue
			}
			if !declared[tok] {
				t.Errorf("%s is read before it is declared:\n%s", tok, src)
				return
			}
		}
		if strings.HasPrefix(trim, "var _t") {
			if i := strings.Index(trim, " ="); i > 4 {
				declared[strings.TrimSpace(trim[4:i])] = true
			}
		}
	}
}

// tokensLike returns the identifiers in s that start with prefix.
func tokensLike(s, prefix string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		if !strings.HasPrefix(s[i:], prefix) {
			continue
		}
		if i > 0 && (isIdentByte(s[i-1])) {
			continue
		}
		j := i
		for j < len(s) && isIdentByte(s[j]) {
			j++
		}
		out = append(out, s[i:j])
		i = j
	}
	return out
}

func isIdentByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
