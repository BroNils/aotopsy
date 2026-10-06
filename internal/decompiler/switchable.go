package decompiler

import (
	"fmt"
	"regexp"
	"strings"
)

// Switchable calls.
//
// An AOT instance call is lowered by FlowGraphCompiler::EmitInstanceCallAOT
// (flow_graph_compiler_{arm64,x64}.cc, shape verified at 2.10.0, 2.12.0, 3.9.2
// and 3.13.0 for x64, and by the audit for arm64):
//
//	receiver <- [SP + (ic_data.SizeWithoutTypeArgs() - 1) * kWordSize]   (R0 / RDX)
//	IC_DATA_REG <- UnlinkedCall from the object pool                      (R5 / RBX)
//	LR / RCX    <- SwitchableCallMiss stub from the object pool
//	call
//	drop(SizeWithTypeArgs())
//
// UnlinkedCall holds {target_name, args_descriptor} (cluster fill spec), so the
// pool entry names the called selector. The receiver's slot displacement gives
// the argument count without the type arguments, which is how the receiver is
// told apart from a leading type-arguments vector.
//
// The stack arguments of the call are already bound by outargs.go (3.0.5+) /
// outargs_push.go (<= 2.19.0); the first of them is the receiver. Nothing is
// printed unless that binding succeeded and the receiver is exactly the first
// bound argument.

var (
	identNameRe = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
	// binaryOperators are the Dart operator method names with exactly one
	// operand besides the receiver (language spec, user-definable operators).
	binaryOperators = map[string]bool{
		"+": true, "-": true, "*": true, "/": true, "~/": true, "%": true,
		"<": true, "<=": true, ">": true, ">=": true, "==": true,
		"<<": true, ">>": true, ">>>": true, "&": true, "|": true, "^": true,
	}
)

// switchableName returns display when it is the target name of an UnlinkedCall
// (a bare selector, optionally prefixed `dyn:`), else "". Strings, objects and
// every display that is not a plain selector are rejected.
func switchableName(display string) string {
	n := strings.TrimPrefix(display, "dyn:")
	n = strings.TrimPrefix(strings.TrimPrefix(n, "get:"), "set:")
	switch {
	case identNameRe.MatchString(n), binaryOperators[n], n == "[]", n == "[]=", n == "unary-", n == "~":
		return display
	}
	return ""
}

// switchableReceiverDisp finds the receiver load that precedes a switchable
// call -- `ldr x0, [x15, #d]` on ARM64, `mov rdx, [rsp + d]` on x86_64 -- and
// returns d, or -1. The scan stops at the previous call.
func switchableReceiverDisp(fir *FuncIR, instrs []Instr) int64 {
	recvReg := fir.ReturnReg // R0 on ARM64
	mnemonics := map[string]bool{"ldr": true, "ldur": true}
	if fir.ICDataReg == "rbx" { // x86_64: RDX
		recvReg = "rdx"
		mnemonics = map[string]bool{"mov": true}
	}
	for i := len(instrs) - 1; i >= 0; i-- {
		if instrs[i].Op == OpCall {
			return -1
		}
		mn, ops := splitOperands(strings.ToLower(instrs[i].Src))
		if !mnemonics[mn] || len(ops) < 2 || canonReg(ops[0]) != canonReg(recvReg) {
			continue
		}
		op := parseOperand(ops[1])
		if !op.isMem || strings.ToLower(op.memBase) != fir.StackReg || op.memDisp < 0 || op.memDisp%8 != 0 {
			return -1
		}
		return op.memDisp
	}
	return -1
}

// switchableCallExpr renders a recognised switchable call from the bound
// stack arguments (receiver first). ok is false when anything is missing.
func (e *emitter) switchableCallExpr(bound []string) (string, bool) {
	name := e.state.ICName
	if name == "" || e.recvDisp < 0 || len(bound) == 0 {
		return "", false
	}
	if len(bound) != int(e.recvDisp/8)+1 { // type arguments, or an unbound slot
		return "", false
	}
	recv, args := bound[0], bound[1:]
	dyn := strings.HasPrefix(name, "dyn:")
	sel := strings.TrimPrefix(name, "dyn:")
	text := ""
	switch {
	case strings.HasPrefix(sel, "get:") && len(args) == 0:
		text = fmt.Sprintf("%s.%s", recv, strings.TrimPrefix(sel, "get:"))
	case strings.HasPrefix(sel, "set:") && len(args) == 1:
		text = fmt.Sprintf("%s.%s = %s", recv, strings.TrimPrefix(sel, "set:"), args[0])
	case sel == "[]" && len(args) == 1:
		text = fmt.Sprintf("%s[%s]", recv, args[0])
	case sel == "[]=" && len(args) == 2:
		text = fmt.Sprintf("%s[%s] = %s", recv, args[0], args[1])
	case binaryOperators[sel] && len(args) == 1:
		text = fmt.Sprintf("(%s %s %s)", recv, sel, args[0])
	case sel == "unary-" && len(args) == 0:
		text = fmt.Sprintf("-%s", recv)
	case sel == "~" && len(args) == 0:
		text = fmt.Sprintf("~%s", recv)
	case identNameRe.MatchString(sel):
		text = fmt.Sprintf("%s.%s(%s)", recv, sel, strings.Join(args, ", "))
	default:
		return "", false
	}
	if dyn {
		text += " /* dynamic */"
	}
	return text, true
}

// applyPairedPoolLoad records the two pool words an LDP loaded. The pair
// {IC_DATA_REG, LR} is EmitInstanceCallAOT's {UnlinkedCall, stub} load (the
// order of the two pool slots flips at 3.10.7 but the destination registers do
// not, so the registers -- not the order -- identify the shape).
func (e *emitter) applyPairedPoolLoad(ins Instr) {
	if len(ins.PoolLoads) != 2 || e.pool == nil {
		return
	}
	var ic, lr bool
	for _, l := range ins.PoolLoads {
		disp, ok := e.pool(l.Index)
		if !ok {
			return
		}
		shown := dartPoolDisplay(disp)
		e.state.setReg(l.Reg, shown)
		switch canonReg(l.Reg) {
		case canonReg(e.fir.ICDataReg):
			ic = true
			e.state.ICName = switchableName(shown)
		case canonReg(e.fir.LinkReg):
			lr = true
		}
	}
	if !(ic && lr) {
		e.state.ICName = ""
	}
}
