package decompiler

import (
	"fmt"
	"strings"
)

// Push model (<= 2.19.0). Arguments are pushed with PushArgumentInstr and the
// caller drops them after the call (`Drop(argc)`), so the argument COUNT is the
// size of the stack-pointer adjustment that follows the call:
//
//	arm64  STR X0,[X15,#-8]! ... BLR X30; ADD X15,X15,#8*argc
//	x64    PUSH r ...        ... CALL;    ADD RSP, 8*argc
//
// Batched pushes use PushPair(reg, pending) (ArgumentsPusher, il_arm64.cc), so
// within `STP Xa, Xb, [X15, #-16]!` Xb is the EARLIER argument. Pushed values
// are therefore kept in push order and the call takes the last argc of them.

// pushedByStp returns the two values of an `stp xa, xb, [sp, #-16]!` in push
// order (earlier argument first).
func pushedByStp(first, second string) []string { return []string{second, first} }

// isArm64PreIndexSPPush reports whether memTok is `[<stack reg>, #-N]!`.
func isArm64PreIndexSPPush(fir *FuncIR, memTok string) bool {
	tok := strings.TrimSpace(memTok)
	if !strings.HasSuffix(tok, "!") {
		return false
	}
	op := parseOperand(tok)
	return op.isMem && op.hasDisp && op.memDisp < 0 && strings.ToLower(op.memBase) == fir.StackReg
}

// parseSPAdjust returns the byte count of `add <sp>, <sp>, #N` (arm64) or
// `add rsp, N` (x64), or 0 when src is anything else.
func parseSPAdjust(fir *FuncIR, src string) int64 {
	mn, ops := splitOperands(strings.ToLower(src))
	if mn != "add" {
		return 0
	}
	switch {
	case len(ops) == 3 && strings.TrimSpace(ops[0]) == fir.StackReg && strings.TrimSpace(ops[1]) == fir.StackReg:
		v, ok := parseSignedImm(cleanImmPrefix(strings.TrimSpace(ops[2])))
		if ok && v > 0 {
			return v
		}
	case len(ops) == 2 && strings.TrimSpace(ops[0]) == fir.StackReg:
		v, ok := parseSignedImm(cleanImmPrefix(strings.TrimSpace(ops[1])))
		if ok && v > 0 {
			return v
		}
	}
	return 0
}

// takePushedArgs returns the arguments of the push-model call about to be
// emitted in source order and removes their push statements. It always clears
// the block's push record.
func (e *emitter) takePushedArgs(calleeName string) []string {
	pushed := e.state.Pushed
	e.state.Pushed = nil
	drop := e.dropAfterCall
	if e.movesStackArgs() || drop == 0 || drop%8 != 0 || isStubLikeCallee(calleeName) {
		return nil
	}
	n := int(drop / 8)
	if n > len(pushed) {
		return nil
	}
	args := append([]string(nil), pushed[len(pushed)-n:]...)
	for i := len(args) - 1; i >= 0; i-- {
		e.dropEmittedLine(fmt.Sprintf("push(%s);", args[i]))
	}
	return args
}
