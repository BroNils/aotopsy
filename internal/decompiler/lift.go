package decompiler

import (
	"fmt"
	"strconv"
	"strings"
)

// LiftState is the per-function symbolic-execution state: register and
// stack-slot "values" are pseudocode expression FRAGMENTS stored as
// strings (not an expression tree), built via string concatenation --
// this mirrors flutterdec's control_flow/expression_lift.rs LiftState
// exactly (the report's central architectural finding: this decompiler
// family is a string-rewriting system, not an AST-based one).
type LiftState struct {
	Regs    map[string]string // register name -> expr string
	Locals  map[int64]string  // frame-relative byte offset -> local var name
	LastCmp [2]string
	HasCmp  bool
	// Pool resolves an object-pool index to its display text. Set by the
	// emitter, which is the only layer that has the deserialized pool; nil
	// in unit tests that lift instructions in isolation, in which case a
	// pool operand renders as `pool[N]` rather than its contents.
	Pool PoolLookup
}

// newLiftState seeds the registers that hold a known value for the whole of
// generated code. nullReg is FuncIR.NullReg: on ARM64 the SDK reserves R22 to
// cache Object::null(), so seeding it means every read renders as `null`
// rather than `x22` -- in conditions, arguments and field bases alike. Pass
// "" where the architecture has no such register (x86_64, which loads null
// from the object pool instead).
func newLiftState(nullReg string) *LiftState {
	s := &LiftState{Regs: make(map[string]string), Locals: make(map[int64]string)}
	if nullReg != "" {
		s.Regs[nullReg] = "null"
	}
	return s
}

// Clone returns a deep-enough copy for the emitter's "try branch A with a
// snapshot, then branch B with the same snapshot" flow-sensitive walk
// (flutterdec's emit_block does this per branch instead of a real
// dataflow join across paths).
//
// P4-6 (E-004/E-005): Locals is intentionally shared by reference (not
// deep-copied). emitBranch relies on this sharing for cross-branch local-name
// visibility: when branch A defines a local at frame offset N and branch B
// also accesses offset N, both branches see the same name. Deep-copying
// Locals would break this — branch B would lose names defined in branch A.
// Regs IS deep-copied because register state is path-local (each branch's
// register values diverge after the branch condition), while Locals is
// frame-global (a stack slot is the same slot regardless of which branch
// wrote to it).
func (s *LiftState) Clone() *LiftState {
	c := &LiftState{Regs: make(map[string]string, len(s.Regs)), Locals: s.Locals, LastCmp: s.LastCmp, HasCmp: s.HasCmp, Pool: s.Pool}
	for k, v := range s.Regs {
		c.Regs[k] = v
	}
	return c
}

// operand is a parsed instruction operand: either a bare register/
// immediate token, or a "[base+disp]" memory reference.
type operand struct {
	raw     string
	isMem   bool
	memBase string
	memDisp int64
	hasDisp bool
}

// splitOperands splits "mnemonic op1, op2, op3" into (mnemonic, [op1,
// op2, op3]), respecting bracket depth so memory operands with an
// internal comma-free "[base+disp]" shape stay intact as one token.
func splitOperands(src string) (string, []string) {
	src = strings.TrimSpace(src)
	sp := strings.IndexAny(src, " \t")
	if sp < 0 {
		return src, nil
	}
	mnemonic := src[:sp]
	rest := strings.TrimSpace(src[sp+1:])
	return mnemonic, splitTopLevelCommas(rest)
}

// splitTopLevelCommas splits a comma list while respecting '['/']'
// bracket depth, shared by splitOperands and the ARM64/x86 lifters'
// standalone operand-string splitting needs.
func splitTopLevelCommas(rest string) []string {
	var ops []string
	depth := 0
	start := 0
	for i, c := range rest {
		switch c {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				ops = append(ops, strings.TrimSpace(rest[start:i]))
				start = i + 1
			}
		}
	}
	if start < len(rest) {
		if tail := strings.TrimSpace(rest[start:]); tail != "" {
			ops = append(ops, tail)
		}
	}
	return ops
}

// parseOperand recognizes ARM64 "[x1, #0x8]" and x86 "[rbx+0x8]" /
// "qword ptr [rbx+0x8]" memory syntax; everything else is a bare token
// (register or immediate).
func parseOperand(tok string) operand {
	tok = strings.TrimSpace(tok)
	lb := strings.Index(tok, "[")
	rb := strings.LastIndex(tok, "]")
	if lb < 0 || rb < lb {
		return operand{raw: cleanImmPrefix(tok)}
	}
	inner := tok[lb+1 : rb]
	inner = strings.ReplaceAll(inner, ",", "+")
	parts := splitSignedTerms(inner)
	op := operand{isMem: true}
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if i == 0 {
			// The base register is never itself a signed numeric term
			// (splitSignedTerms only splits on a LATER +/- as a term
			// boundary), so it can't carry a leading sign here.
			op.memBase = strings.TrimPrefix(p, "#")
			continue
		}
		if v, ok := parseSignedImm(p); ok {
			op.memDisp += v
			op.hasDisp = true
		}
	}
	return op
}

// splitSignedTerms splits an ARM64/x86 memory-operand inner string like
// "rbp-0x8", "x1+0x10", or "rax+rcx*4+0x8" into ["rbp", "-0x8"] /
// ["x1", "+0x10"] / ["rax", "+rcx*4", "+0x8"] -- i.e. every term after
// the first KEEPS its sign, unlike a plain FieldsFunc split on '+' alone
// (which mishandles the far more common x86 "[base-disp]" bare-minus
// shape entirely -- this was a real bug found testing against a real
// libapp.so, see decompiler_test.go's regression coverage).
func splitSignedTerms(inner string) []string {
	var terms []string
	start := 0
	for i := 1; i < len(inner); i++ {
		c := inner[i]
		if c != '+' && c != '-' {
			continue
		}
		// A '-' immediately after 'e'/'E' (e.g. hex digits never produce
		// this, but be defensive) is not a term boundary; in practice
		// our tokens are plain "0x.." or decimal, so this simple rule is
		// sufficient.
		terms = append(terms, strings.TrimSpace(inner[start:i]))
		start = i
	}
	terms = append(terms, strings.TrimSpace(inner[start:]))
	return terms
}

// parseSignedImm parses a term that may itself carry a leading sign
// (from splitSignedTerms) and, for x86's "reg*scale" index terms,
// returns not-ok (scaled-index addressing isn't modeled as a constant
// displacement).
func parseSignedImm(term string) (int64, bool) {
	term = strings.TrimSpace(term)
	neg := false
	if strings.HasPrefix(term, "-") {
		neg = true
		term = term[1:]
	} else if strings.HasPrefix(term, "+") {
		term = term[1:]
	}
	term = strings.TrimSpace(term)
	if strings.Contains(term, "*") {
		return 0, false // scaled-index register term, not a constant
	}
	v, ok := parseImm(term)
	if !ok {
		return 0, false
	}
	if neg {
		v = -v
	} else if v > 0x7FFFFFFF && v <= 0xFFFFFFFF {
		// x86asm's default Mem.String() renders some negative 32-bit
		// displacements as a raw unsigned hex pattern with a leading
		// '+' instead of a proper minus sign (e.g. "RBP+0xffffff08" for
		// what is really RBP-0xf8) -- confirmed by testing this
		// decompiler against a real libapp.so, where "[RBP-0x8]" used a
		// real minus but "[RBP+0xffffff08]" (a bigger, still-negative
		// displacement) did not. Reinterpret any unsigned term in the
		// int32 negative range as its signed int32 value.
		v = int64(int32(uint32(v))) //nolint:gosec // v is range-checked above to fit in 32 bits before this reinterpret cast
	}
	return v, true
}

func cleanImmPrefix(tok string) string {
	return strings.TrimPrefix(strings.TrimSpace(tok), "#")
}

func parseImm(s string) (int64, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "#"))
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	}
	var v int64
	var err error
	if strings.HasPrefix(s, "0x") {
		v, err = strconv.ParseInt(s[2:], 16, 64)
	} else {
		v, err = strconv.ParseInt(s, 10, 64)
	}
	if err != nil {
		return 0, false
	}
	if neg {
		v = -v
	}
	return v, true
}

// shiftedOperand resolves operand i, applying the ARM64 shifted-register
// suffix that may follow it ("lsr #32", "asr #2", "lsl #3").
//
// ok is false when a suffix is present but is not a shift this can render.
// Callers use it to clear HasCmp, so the emitter falls back to its
// placeholder instead of printing a condition that omits part of what the
// instruction tests -- silence beats a confident wrong answer.
func shiftedOperand(fir *FuncIR, s *LiftState, ops []string, i int) (string, bool) {
	expr := operandExpr(fir, s, ops[i])
	if len(ops) <= i+1 {
		return expr, true
	}
	spec := strings.ToLower(strings.TrimSpace(ops[i+1]))
	idx := strings.Index(spec, "#")
	if idx < 0 {
		return expr, false
	}
	amt := strings.TrimSpace(spec[idx+1:])
	switch {
	case strings.HasPrefix(spec, "lsr"), strings.HasPrefix(spec, "asr"):
		return fmt.Sprintf("(%s >> %s)", expr, amt), true
	case strings.HasPrefix(spec, "lsl"):
		return fmt.Sprintf("(%s << %s)", expr, amt), true
	}
	return expr, false
}

// negateExpr renders the arithmetic negation of an operand expression,
// folding the sign into a literal where it can.
func negateExpr(expr string) string {
	if v, ok := parseImm(expr); ok {
		return strconv.FormatInt(-v, 10)
	}
	return "-" + expr
}

// lookupReg resolves a register token to its current symbolic expression,
// falling back to the register name itself if unknown (matching
// flutterdec's lookup_reg).
func (s *LiftState) lookupReg(tok string) string {
	tok = strings.ToLower(strings.TrimSpace(tok))
	if isZeroReg(tok) {
		return "0"
	}
	if v, ok := s.Regs[tok]; ok {
		if v == ffiCallTargetSentinel || strings.HasPrefix(v, thrStubSentinelPrefix) {
			// Internal-only markers (see applyStore / the ldr/mov
			// THR-stub-offset check in ApplyOther) -- must never leak into
			// displayed pseudocode. A register can still hold one of these
			// values when it's ALSO used as a regular argument/expression
			// elsewhere (e.g. reused across a nearby call), not just as
			// the one indirect-call target emitIndirectCall specifically
			// checks for (which reads s.Regs directly, bypassing this
			// filter, since it needs the real marker).
			return tok
		}
		return v
	}
	return tok
}

func isZeroReg(tok string) bool {
	return tok == "xzr" || tok == "wzr"
}

// operandExpr resolves any operand (register or memory) to an
// expression string, handling frame-relative loads as local-variable
// references (fir.FrameReg) and other base registers as a generic field
// access (fieldExpr) -- mirrors flutterdec's operand_expr.
func operandExpr(fir *FuncIR, s *LiftState, tok string) string {
	op := parseOperand(tok)
	if !op.isMem {
		if v, ok := parseImm(op.raw); ok {
			return strconv.FormatInt(v, 10)
		}
		return s.lookupReg(op.raw)
	}
	base := strings.ToLower(op.memBase)
	if base == fir.FrameReg && op.hasDisp {
		if name, ok := s.Locals[op.memDisp]; ok {
			return name
		}
		return localName(op.memDisp)
	}
	if base == fir.PoolReg {
		return poolOperandExpr(fir, s, op)
	}
	baseExpr := s.lookupReg(base)
	if !op.hasDisp {
		return baseExpr
	}
	if expr, ok := threadFieldExpr(fir, base, op.memDisp); ok {
		return expr
	}
	if expr, ok := stackSlotExpr(fir, base, op.memDisp); ok {
		return expr
	}
	return fieldExpr(baseExpr, op.memDisp, dartFieldResolver(fir, base))
}

// localName renders a frame-relative byte offset as a valid Dart
// identifier -- found via real-binary testing that a literal minus sign
// (e.g. "local_-8") is not a legal Dart identifier at all, so negative
// offsets use an "m" prefix on the magnitude instead, matching
// fieldExpr's own "-1 => base.m1" convention below.
func localName(off int64) string {
	if off < 0 {
		return fmt.Sprintf("local_m%d", -off)
	}
	return fmt.Sprintf("local_%d", off)
}

// fieldExpr renders a base+offset expression as a Dart-ish field access,
// mirroring flutterdec's field_expr (including its "-1 => ._tag"
// special-case for the Dart object-header/class-id tag field).
//
// When resolver is non-nil, it is consulted to replace the synthetic
// fNN/mNN name with the real Dart field name from the class layout
// (e.g. base.name instead of base.f8).
// isPointerDecompression recognises the instruction that turns a 32-bit
// compressed pointer back into a full address, so it can be rendered as the
// object it produces rather than as arithmetic.
//
// Both architectures emit it from the same place in dart-lang/sdk, inside
// `#if defined(DART_COMPRESSED_POINTERS)`:
//
//	ARM64  assembler_arm64.h  add(dst, dst, Operand(HEAP_BITS, LSL, 32))
//	x86_64 assembler_x64.cc   movl(dest, slot);
//	                          addq(dest, Address(THR, heap_base_offset()))
//
// On ARM64 that is `ADD Xd, Xn, X28, LSL #32`. HEAP_BITS holds
// `write_barrier_mask << 32 | heap_base >> 32` (constants_arm64.h), so
// shifting it left by 32 drops the mask off the top and leaves
// `(heap_base >> 32) << 32`, which IS heap_base -- pointer_tagging.h's
// kHeapBaseMask = ~(4GB-1) makes the heap 4GB-aligned, so the low bits it
// clears are already zero. The register is reserved
// (kReservedCpuRegisters includes HEAP_BITS) and its only other use shifts
// RIGHT by 32 to recover the write-barrier mask, so a left shift by 32 is
// unambiguous.
//
// On x86_64 it is an add of THR.heap_base, which P-5's Thread field naming
// already renders by name.
//
// Measured before this: 33264 occurrences of `+ (x28 << 32)` in the 3.x
// ARM64 output and 47041 of `THR.heap_base` on x86_64 -- the single largest
// source of noise in either, and it says nothing a reader of Dart wants,
// since compression is invisible at source level.
// srcTok is the added operand and shiftTok its ARM64 shift suffix ("" when
// there is none). The x86_64 form is two-operand (`add dst, [r14+off]`) and
// the ARM64 form three-operand, so both call sites pass their own operands.
func isPointerDecompression(fir *FuncIR, mnemonic, srcTok, shiftTok string) bool {
	if mnemonic != "add" {
		return false
	}
	// ARM64: the heap-bits register shifted left by 32.
	if fir.HeapBitsReg != "" && strings.ToLower(strings.TrimSpace(srcTok)) == fir.HeapBitsReg {
		spec := strings.ToLower(strings.TrimSpace(shiftTok))
		i := strings.Index(spec, "#")
		return strings.HasPrefix(spec, "lsl") && i >= 0 && strings.TrimSpace(spec[i+1:]) == "32"
	}
	// x86_64: an add of the Thread's heap_base field.
	if fir.ThreadFieldNames != nil {
		if op := parseOperand(srcTok); op.isMem && op.hasDisp &&
			strings.ToLower(op.memBase) == fir.ThreadReg {
			return fir.ThreadFieldNames[op.memDisp] == "heap_base"
		}
	}
	return false
}

// cachedVMObjectValues are the Thread fields that cache a VM OBJECT rather
// than an address, so loading one yields that object itself.
//
// dart-lang/sdk's thread.h lists them in CACHED_VM_OBJECTS_LIST alongside the
// stub entry points; these three are the ones with a spelling in source.
// x86_64 reaches null this way because constants_x64.h defines no NULL_REG --
// where ARM64 reads R22, x64 reads Thread.
var cachedVMObjectValues = map[string]string{
	"object_null": "null",
	"bool_true":   "true",
	"bool_false":  "false",
}

// stackSlotExpr renders a stack-pointer-relative access as a slot rather than
// a field, reporting ok=false when the base is not the Dart stack pointer.
//
// The SDK names the register SPREG -- R15 on ARM64 ("SP in Dart code" in
// constants_arm64.h), RSP on x86_64. A displacement off it is a stack slot,
// so field notation misdescribes it: the output claimed `x15.m16` and
// `rsp.f8` for stack traffic, and `rsp._tag` for an object header the stack
// pointer does not have.
func stackSlotExpr(fir *FuncIR, baseReg string, off int64) (string, bool) {
	if fir.StackReg == "" || baseReg != fir.StackReg {
		return "", false
	}
	if off < 0 {
		return fmt.Sprintf("[SP-%d]", -off), true
	}
	return fmt.Sprintf("[SP+%d]", off), true
}

// threadFieldExpr renders a Thread-relative access using the SDK-derived
// field table, reporting ok=false when the base is not THR or the offset is
// not in the table (in which case the caller falls back to THR.fNN).
func threadFieldExpr(fir *FuncIR, baseReg string, off int64) (string, bool) {
	if baseReg != fir.ThreadReg || fir.ThreadFieldNames == nil {
		return "", false
	}
	name, ok := fir.ThreadFieldNames[off]
	if !ok {
		return "", false
	}
	if v, isValue := cachedVMObjectValues[name]; isValue {
		return v, true
	}
	return "THR." + name, true
}

// dartFieldResolver returns the Dart field-name resolver for a memory access
// off baseReg, or nil when naming that base's offsets as Dart fields would be
// a fabrication.
//
// THR is the case that matters. The Thread structure is a VM struct, not a
// Dart object, so its offsets have nothing to do with any class's field
// layout -- but fieldExpr was handed the resolver for every base, and the
// resolver's offset-only fallback names any offset that happens to carry the
// same field name in every Dart class that has one there. The result was
// confident nonsense: 43528 `THR.radius` in the x86_64 sample, plus
// `THR.orientation` and `THR.tilt`. Thread has no such fields.
//
// Rendering `THR.f88` instead says only what is known. THR offsets that ARE
// identified come from the SDK-derived tables in internal/disasm
// (thrfields.go / thrfields_x64.go), applied by the annotator, not from
// class layouts.
func dartFieldResolver(fir *FuncIR, baseReg string) func(int64, int64) string {
	if fir.FieldNameResolver == nil || baseReg == fir.ThreadReg ||
		baseReg == fir.PoolReg || baseReg == fir.StackReg {
		return nil
	}
	// A2: pass ReceiverClassID so the resolver can use the per-class field
	// map rather than the offset-only fallback.
	rcid := fir.ReceiverClassID
	return func(_ int64, off int64) string { return fir.FieldNameResolver(rcid, off) }
}

func fieldExpr(base string, off int64, resolver func(int64, int64) string) string {
	if resolver != nil {
		if name := resolver(0, off); name != "" {
			return base + "." + name
		}
	}
	switch {
	case off == -1:
		return base + "._tag"
	case off >= 0:
		return fmt.Sprintf("%s.f%d", base, off)
	default:
		return fmt.Sprintf("%s.m%d", base, -off)
	}
}

// ApplyOther lifts one OpOther instruction: updates register/local
// values in-place and returns an assignment statement line to emit, if
// the instruction is a store to something other than a tracked local
// (matching flutterdec's apply_other_lift's stur/str handling).
func ApplyOther(fir *FuncIR, s *LiftState, ins Instr) (line string, hasLine bool) {
	mnemonic, ops := splitOperands(ins.Src)
	mnemonic = normalizeMnemonic(mnemonic)

	switch mnemonic {
	case "mov", "movz", "lea":
		if len(ops) >= 2 {
			// x86_64 uses "mov" for BOTH directions (ARM64 has distinct
			// str/stur mnemonics, handled below) -- "mov [mem], reg" is a
			// STORE and must go through applyStore like str/stur does, not
			// be treated as a register destination. Confirmed a real,
			// previously-silent gap: x86 MOV-to-memory was setting
			// s.Regs["[r14+0x628]"] instead of recognizing the memory
			// write, silently dropping it AND (found while wiring FFI-call
			// detection) never triggering applyStore's THR.vm_tag_offset
			// check for x86_64 at all. LEA never writes memory (always
			// computes an address into a register), so it's excluded here.
			if mnemonic != "lea" && strings.HasPrefix(strings.TrimSpace(ops[0]), "[") {
				return applyStore(fir, s, ops[0], ops[1])
			}
			dst := strings.ToLower(ops[0])
			// mirrors the ldr/ldur THR-stub-offset check below -- x86_64
			// uses "mov" for register loads too (no separate ldr mnemonic).
			if mnemonic != "lea" && fir.ThreadStubOffsets != nil {
				if memOp := parseOperand(ops[1]); memOp.isMem && memOp.hasDisp && strings.ToLower(memOp.memBase) == fir.ThreadReg {
					if name, ok := fir.ThreadStubOffsets[memOp.memDisp]; ok {
						s.Regs[dst] = thrStubSentinelPrefix + name
						return "", false
					}
				}
			}
			s.Regs[dst] = operandExpr(fir, s, ops[1])
		}
	case "movk":
		// MOVK (ARM64 move-keep) inserts a 16-bit immediate at a shifted
		// position while preserving other bits. Unlike mov/movz which
		// overwrite the full register, movk merges with the existing value.
		// Format: movk dst, #imm, lsl #shift
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			imm := operandExpr(fir, s, ops[1])
			shift := "0"
			if len(ops) >= 3 {
				// ops[2] is like "lsl #16" — extract the shift amount.
				shiftSpec := strings.TrimSpace(ops[2])
				if idx := strings.Index(shiftSpec, "#"); idx >= 0 {
					shift = strings.TrimSpace(shiftSpec[idx+1:])
				}
			}
			old := s.lookupReg(dst)
			s.Regs[dst] = fmt.Sprintf("(%s | (%s << %s))", old, imm, shift)
		}
	case "add", "sub":
		if len(ops) >= 3 {
			dst := strings.ToLower(ops[0])
			shiftTok := ""
			if len(ops) >= 4 {
				shiftTok = ops[3]
			}
			if isPointerDecompression(fir, mnemonic, ops[2], shiftTok) {
				s.Regs[dst] = operandExpr(fir, s, ops[1])
				break
			}
			lhs := operandExpr(fir, s, ops[1])
			rhs := operandExpr(fir, s, ops[2])
			// ARM64 shifted register operand: add x0, x1, x2, lsl #3
			// The shift in ops[3] must be applied to rhs before the add/sub.
			if len(ops) >= 4 {
				shiftSpec := strings.TrimSpace(ops[3])
				// shiftSpec is like "lsl #3" or "lsr #2" — extract the
				// shift amount after the "#" and apply as left shift
				// (lsl) or right shift (lsr/asr/ror).
				if idx := strings.Index(shiftSpec, "#"); idx >= 0 {
					shiftAmt := strings.TrimSpace(shiftSpec[idx+1:])
					if strings.HasPrefix(shiftSpec, "lsr") || strings.HasPrefix(shiftSpec, "asr") {
						rhs = fmt.Sprintf("(%s >> %s)", rhs, shiftAmt)
					} else {
						rhs = fmt.Sprintf("(%s << %s)", rhs, shiftAmt)
					}
				}
			}
			if v, ok := boolFromNullOffset(fir, mnemonic, lhs, ops[2]); ok {
				s.Regs[dst] = v
				break
			}
			s.Regs[dst] = simplifyBinExpr(mnemonic, lhs, rhs)
		} else if len(ops) == 2 {
			// x86 two-operand form: dst is also the first source.
			dst := strings.ToLower(ops[0])
			if isPointerDecompression(fir, mnemonic, ops[1], "") {
				break // dst already holds the compressed pointer
			}
			lhs := s.lookupReg(dst)
			rhs := operandExpr(fir, s, ops[1])
			s.Regs[dst] = simplifyBinExpr(mnemonic, lhs, rhs)
		}
	case "mul", "imul", "and", "orr", "or", "eor", "xor":
		op := binOpSymbol(mnemonic)
		if len(ops) >= 3 {
			dst := strings.ToLower(ops[0])
			s.Regs[dst] = fmt.Sprintf("(%s %s %s)", operandExpr(fir, s, ops[1]), op, operandExpr(fir, s, ops[2]))
		} else if len(ops) == 2 {
			dst := strings.ToLower(ops[0])
			s.Regs[dst] = fmt.Sprintf("(%s %s %s)", s.lookupReg(dst), op, operandExpr(fir, s, ops[1]))
		}
	case "lsl", "shl":
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			idx := 1
			lhs := s.lookupReg(dst)
			if len(ops) >= 3 {
				lhs = operandExpr(fir, s, ops[1])
				idx = 2
			}
			s.Regs[dst] = fmt.Sprintf("(%s << %s)", lhs, operandExpr(fir, s, ops[idx]))
		}
	case "lsr", "asr", "shr", "sar":
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			idx := 1
			lhs := s.lookupReg(dst)
			if len(ops) >= 3 {
				lhs = operandExpr(fir, s, ops[1])
				idx = 2
			}
			s.Regs[dst] = fmt.Sprintf("(%s >> %s)", lhs, operandExpr(fir, s, ops[idx]))
		}
	case "ubfx":
		if len(ops) >= 4 {
			dst := strings.ToLower(ops[0])
			src := operandExpr(fir, s, ops[1])
			expr := fmt.Sprintf("bitField(%s, %s, %s)", src, cleanImmPrefix(ops[2]), cleanImmPrefix(ops[3]))
			// The well-known Dart object class-id bitfield idiom
			// (lsb=0xc, width=0x14 on ARM64) renders directly as
			// classId(...) instead of the generic bitField(...) form.
			if strings.TrimPrefix(ops[2], "#") == "0xc" && strings.TrimPrefix(ops[3], "#") == "0x14" {
				expr = fmt.Sprintf("classId(%s)", strings.TrimSuffix(src, "._tag"))
			}
			s.Regs[dst] = expr
		}
	case "ldr", "ldur":
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			if fir.ThreadStubOffsets != nil {
				if memOp := parseOperand(ops[1]); memOp.isMem && memOp.hasDisp && strings.ToLower(memOp.memBase) == fir.ThreadReg {
					if name, ok := fir.ThreadStubOffsets[memOp.memDisp]; ok {
						s.Regs[dst] = thrStubSentinelPrefix + name
						return "", false
					}
				}
			}
			s.Regs[dst] = operandExpr(fir, s, ops[1])
		}
	// The three flag-setting compares. dart-lang/sdk's
	// runtime/vm/compiler/assembler/assembler_arm64.h at 3.9.2 defines each
	// in terms of the operation whose flags it takes:
	//
	//	cmp(rn, o) -> subs(ZR, rn, o)   flags from rn - o   =>  rn == o
	//	cmn(rn, o) -> adds(ZR, rn, o)   flags from rn + o   =>  rn == -o
	//	tst(rn, o) -> ands(ZR, rn, o)   flags from rn & o   =>  (rn & o) == 0
	//
	// `o` is a shifted-register Operand, which is why a third token can be
	// present. Dropping it, or conflating cmn with cmp, states a condition
	// the binary does not test.
	case "cmp":
		if len(ops) >= 2 {
			rhs, ok := shiftedOperand(fir, s, ops, 1)
			s.LastCmp = [2]string{operandExpr(fir, s, ops[0]), rhs}
			s.HasCmp = ok
		}
	case "cmn":
		// Flags come from rn + o, so equality means rn == -o. Sharing the
		// cmp path, as this used to, reported the wrong sign.
		if len(ops) >= 2 {
			rhs, ok := shiftedOperand(fir, s, ops, 1)
			s.LastCmp = [2]string{operandExpr(fir, s, ops[0]), negateExpr(rhs)}
			s.HasCmp = ok
		}
	case "test", "tst":
		// The condition is `(a & b) == 0`, not `a == 0`. Storing [a, "0"]
		// unconditionally is only right for the self-test idiom `test r, r`,
		// and on this corpus that idiom is the rare case: 878 of 878 ARM64
		// TST and 1556 of 1612 x86_64 TEST instructions have DISTINCT
		// operands, so the second one was being dropped almost everywhere.
		// The write-barrier check
		//
		//	AND X16, X17, X16, LSR #2
		//	TST X16, X28              ; X28 = HEAP_BITS
		//	B EQ, ...
		//
		// rendered as `(x17 & x16) == 0`, losing the `& X28` that is the
		// whole point of the test.
		if len(ops) >= 2 {
			lhs := operandExpr(fir, s, ops[0])
			rhs, ok := shiftedOperand(fir, s, ops, 1)
			if rhs == lhs {
				// `x & x` is zero exactly when x is; say that instead.
				s.LastCmp = [2]string{lhs, "0"}
			} else {
				s.LastCmp = [2]string{fmt.Sprintf("(%s & %s)", lhs, rhs), "0"}
			}
			s.HasCmp = ok
		}
	case "str", "stur":
		if len(ops) >= 2 {
			return applyStore(fir, s, ops[1], ops[0])
		}
	// P3-feasible-1: Unary operations — common in Dart AOT compiled code.
	case "mvn", "not":
		// mvn (ARM64) / not (x86_64): bitwise NOT
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.Regs[dst] = fmt.Sprintf("(~%s)", operandExpr(fir, s, ops[1]))
		}
	case "neg":
		// neg: arithmetic negation (ARM64 and x86_64)
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.Regs[dst] = fmt.Sprintf("(-%s)", operandExpr(fir, s, ops[1]))
		}
	// P3-feasible-1: Zero/sign-extend moves (x86_64)
	case "movzx":
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.Regs[dst] = operandExpr(fir, s, ops[1])
		}
	case "movsxd":
		// movsxd sign-extends a 32-bit value to 64-bit — needs a cast
		// to preserve sign-extension semantics in the pseudocode.
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.Regs[dst] = fmt.Sprintf("(int64)(%s)", operandExpr(fir, s, ops[1]))
		}
	case "movsx":
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.Regs[dst] = fmt.Sprintf("(int)(%s)", operandExpr(fir, s, ops[1]))
		}
	// P3-feasible-1: Address generation (ARM64)
	case "adr", "adrp":
		if len(ops) >= 2 {
			dst := strings.ToLower(ops[0])
			s.Regs[dst] = operandExpr(fir, s, ops[1])
		}
	// P3-feasible-1: Load/store pair (ARM64) — ldp/stp load/store two registers.
	// We model them as two separate assignments.
	case "ldp":
		if len(ops) >= 3 {
			dst1 := strings.ToLower(ops[0])
			s.Regs[dst1] = operandExpr(fir, s, ops[2])
			// Second register gets the next memory location (base+8).
			// Build a new memory operand with disp+8 and resolve it
			// through operandExpr so frame-relative loads produce the
			// correct local name (e.g. local_24 instead of *(local_16 + 8)).
			dst2 := strings.ToLower(ops[1])
			if op := parseOperand(ops[2]); op.isMem {
				memPlus8 := fmt.Sprintf("[%s, #%d]", op.memBase, op.memDisp+8)
				s.Regs[dst2] = operandExpr(fir, s, memPlus8)
			} else {
				s.Regs[dst2] = fmt.Sprintf("*(%s + 8)", operandExpr(fir, s, ops[2]))
			}
		}
	case "stp":
		if len(ops) >= 3 {
			// Store pair: stp src1, src2, [mem] — emit as two stores.
			// M-1 (oracle-audit): previously only stored ops[0], silently
			// dropped ops[1]. Now store both: src1 to [mem], src2 to [mem+8].
			line1, handled := applyStore(fir, s, ops[2], ops[0])
			// Second store: src2 to [mem+8]. Reuse parseOperand to extract
			// the base register and displacement from ops[2], then add 8.
			// Process the second store regardless of whether the first was
			// handled (the first may be a THR store that returns "", false,
			// but the second store to [mem+8] must still be emitted).
			op := parseOperand(ops[2])
			if op.isMem {
				memPlus8 := fmt.Sprintf("[%s, #%d]", op.memBase, op.memDisp+8)
				line2, _ := applyStore(fir, s, memPlus8, ops[1])
				if line2 != "" {
					if line1 != "" {
						return line1 + "\n" + line2, true
					}
					return line2, true
				}
			}
			return line1, handled
		}
	// P3-feasible-1: Stack operations (x86_64) — push/pop are mov + sp adjust.
	case "push":
		if len(ops) >= 1 {
			return fmt.Sprintf("push(%s);", operandExpr(fir, s, ops[0])), true
		}
	case "pop":
		if len(ops) >= 1 {
			dst := strings.ToLower(ops[0])
			s.Regs[dst] = "/* pop */"
		}
	}
	return "", false
}

// ffiCallTargetSentinel marks a register as "was just stored into a Thread
// field" -- Dart AOT's native/FFI-leaf-call bookkeeping idiom (see
// applyStore's THR-store handling below for the full rationale).
// emit.go's emitIndirectCall checks for this instead of falling back to a
// raw "indirectTarget_xN" name when that same register is used as an
// indirect call target shortly after.
const ffiCallTargetSentinel = "__ffi_call_target"

// thrStubSentinelPrefix marks a register as "was just loaded from a known
// Thread-cached stub entry-point offset" (dart-lang/sdk's
// CACHED_VM_STUBS_ADDRESSES_LIST, e.g. Thread::write_barrier_entry_point_
// or Thread::stack_overflow_shared_without_fpu_regs_entry_point_) -- the
// resolved stub name is appended after the prefix. emit.go's
// emitIndirectCall checks for this instead of falling back to a raw
// "indirectTarget_xN"/dynamicCall name when that same register is used as
// an indirect call target shortly after. See internal/disasm.
// ThreadStubOffsets's doc comment for how the offset table itself was
// derived (dart-lang/sdk's generated runtime_offsets_extracted.h, cross-
// checked against real compiled sample disassembly).
const thrStubSentinelPrefix = "__thr_stub:"

// applyStore handles a store instruction: writes to a tracked local
// (silent, no emitted line) or emits an explicit assignment statement to
// a computed field-access expression (mirroring flutterdec's stur/str
// handling in apply_other_lift).
func applyStore(fir *FuncIR, s *LiftState, memTok, srcTok string) (string, bool) {
	op := parseOperand(memTok)
	valExpr := operandExpr(fir, s, srcTok)
	if !op.isMem {
		return "", false
	}
	base := strings.ToLower(op.memBase)
	if base == fir.ThreadReg && op.hasDisp {
		// Dart AOT's native/FFI-leaf-call bookkeeping stores the call
		// target into Thread::vm_tag_ immediately before calling that
		// same register (il_arm64.cc/il_x64.cc FfiCallInstr::EmitNativeCode).
		// The offset differs by architecture and version, so we check
		// the SDK-derived ThreadFieldNames table for the "vm_tag" field
		// name rather than hardcoding a specific offset.
		//
		// Previously this fired on ANY store to ANY Thread field, which
		// marked 43528 stores as FFI bookkeeping on the x86_64 sample —
		// most of them write_barrier, stack_overflow checks, etc., not
		// FFI calls at all. That caused the next BLR through the same
		// register to be mislabelled as an FFI call.
		isVMTagStore := false
		if fir.ThreadFieldNames != nil {
			if name, ok := fir.ThreadFieldNames[op.memDisp]; ok && name == "vm_tag" {
				isVMTagStore = true
			}
		}
		if isVMTagStore {
			// Suppress the emitted line (pure bookkeeping, not application
			// logic) but mark the register so the upcoming indirect call is
			// named instead of showing a raw register name.
			s.Regs[strings.ToLower(srcTok)] = ffiCallTargetSentinel
			return "", false
		}
		// A store to a non-vm_tag Thread field is real application logic
		// (e.g. write_barrier_mask, store_buffer_block). Emit it normally.
	}
	if base == fir.FrameReg && op.hasDisp {
		name, ok := s.Locals[op.memDisp]
		if !ok {
			name = localName(op.memDisp)
			s.Locals[op.memDisp] = name
		}
		s.Regs[name] = valExpr
		return fmt.Sprintf("%s = %s;", name, valExpr), true
	}
	baseExpr := s.lookupReg(base)
	lhs := baseExpr
	if op.hasDisp {
		if expr, ok := threadFieldExpr(fir, base, op.memDisp); ok {
			lhs = expr
		} else if expr, ok := stackSlotExpr(fir, base, op.memDisp); ok {
			lhs = expr
		} else {
			lhs = fieldExpr(baseExpr, op.memDisp, dartFieldResolver(fir, base))
		}
	} else if !isSimpleLvalueExpr(baseExpr) {
		// baseExpr is itself a compound expression (e.g. "(x15 - 32)",
		// found testing against a real libapp.so where a computed
		// pointer is stored through directly) -- render it as a pointer
		// dereference rather than an invalid "(x - y) = value;" lvalue.
		lhs = fmt.Sprintf("*(%s)", baseExpr)
	}
	return fmt.Sprintf("%s = %s;", lhs, valExpr), true
}

// isSimpleLvalueExpr reports whether expr is plain enough (an
// identifier, optionally with .field/[index] access) to appear
// unwrapped on the left of an assignment.
func isSimpleLvalueExpr(expr string) bool {
	for _, r := range expr {
		if r == '(' || r == ' ' || r == '+' || r == '-' || r == '*' {
			return false
		}
	}
	return expr != ""
}

func normalizeMnemonic(m string) string {
	return strings.ToLower(strings.TrimSpace(m))
}

func binOpSymbol(mnemonic string) string {
	switch mnemonic {
	case "mul", "imul":
		return "*"
	case "and":
		return "&"
	case "orr", "or":
		return "|"
	case "eor", "xor":
		return "^"
	}
	return "?"
}

// simplifyBinExpr constant-folds/zero-eliminates add/sub the way
// flutterdec's simplify_bin_expr does for its most common cases.
func simplifyBinExpr(mnemonic, lhs, rhs string) string {
	op := "+"
	if mnemonic == "sub" {
		op = "-"
	}
	if rhs == "0" {
		return lhs
	}
	if lv, ok := parseImm(lhs); ok {
		if rv, ok := parseImm(rhs); ok {
			if op == "+" {
				return strconv.FormatInt(lv+rv, 10)
			}
			return strconv.FormatInt(lv-rv, 10)
		}
	}
	return fmt.Sprintf("(%s %s %s)", lhs, op, rhs)
}

// boolFromNullOffset recognises the Dart AOT idiom that materialises `true`
// and `false` as fixed offsets from the null object:
//
//	ADD Xd, NULL_REG, #32   ->  true
//	ADD Xd, NULL_REG, #48   ->  false
//
// The SDK decodes exactly this in runtime/vm/instructions_arm64.cc:
//
//	if (instr->IsAddSubImmOp() && ... (instr->RnField() == NULL_REG)) {
//	  if (imm == kTrueOffsetFromNull)  { *obj = Object::bool_true().ptr(); ... }
//	  else if (imm == kFalseOffsetFromNull) { *obj = Object::bool_false().ptr(); ... }
//
// and runtime/vm/pointer_tagging.h fixes the offsets, unchanged at 2.12.0,
// 3.1.0 and 3.9.2:
//
//	kObjectAlignment     = 2 * word_size          // 16 on 64-bit
//	kTrueOffsetFromNull  = kObjectAlignment * 2   // 32
//	kFalseOffsetFromNull = kObjectAlignment * 3   // 48
//
// Without this the pseudocode reads `null + 32`, which looks like arithmetic
// on null and is not what the instruction means.
func boolFromNullOffset(fir *FuncIR, mnemonic, lhs, imm string) (string, bool) {
	// lhs is the RESOLVED left operand, not the register token, so the
	// idiom is still recognised when null reached the register by a copy.
	if fir.NullReg == "" || mnemonic != "add" || strings.TrimSpace(lhs) != "null" {
		return "", false
	}
	v, ok := parseImm(imm)
	if !ok {
		return "", false
	}
	switch v {
	case kTrueOffsetFromNull:
		return "true", true
	case kFalseOffsetFromNull:
		return "false", true
	}
	return "", false
}

// Offsets of the canonical bool objects from null, in bytes. See
// boolFromNullOffset for the SDK references.
const (
	kTrueOffsetFromNull  = 32
	kFalseOffsetFromNull = 48
)
