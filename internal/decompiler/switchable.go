package decompiler

import (
	"fmt"
	"regexp"
	"strings"
)

// Switchable and megamorphic calls.
//
// An AOT instance call is lowered by FlowGraphCompiler::EmitInstanceCallAOT
// (flow_graph_compiler_{arm64,x64}.cc, read at x64 2.10.0 / 2.12.0 / 3.9.2 /
// 3.13.0 and verified on every arm64 corpus sample, see
// analysis/switchable_corpus_test.go):
//
//	receiver <- [SP + (ic_data.SizeWithoutTypeArgs() - 1) * kWordSize]   (R0 / RDX)
//	IC_DATA_REG <- UnlinkedCall from the object pool                      (R5 / RBX)
//	LR / RCX    <- SwitchableCallMiss stub from the object pool
//	call
//	drop(SizeWithTypeArgs())
//
// and, through 2.x AOT, EmitMegamorphicInstanceCall emits the same sequence
// with a MegamorphicCache and the MegamorphicCall stub. Both objects are
// CallSiteData: target_name (the selector) and args_descriptor come first.
//
// The call is recognised by the OBJECT in IC_DATA_REG, resolved through
// FuncIR.CallSiteAt, never by how the pool entry prints. The descriptor gives
// the exact argument count, so the stack arguments already bound to the call
// (outargs.go for 3.0.5+, outargs_push.go for <= 2.19.0) are rendered only when
// there are exactly that many; the first of them is the receiver.

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

// instrWritesReg reports whether the instruction's write-set contains reg.
func instrWritesReg(ins Instr, reg string) bool {
	for _, r := range ins.DefRegs {
		if r == reg {
			return true
		}
	}
	return false
}

// noteCallSiteLoad records the CallSiteData loaded into the IC register from
// the given pool slot (nothing when the slot holds another kind of object).
func (e *emitter) noteCallSiteLoad(reg string, poolIndex int) {
	if e.fir.CallSiteAt == nil || poolIndex < 0 || canonReg(reg) != canonReg(e.fir.ICDataReg) {
		return
	}
	if site, ok := e.fir.CallSiteAt(poolIndex); ok {
		e.state.ICSite = &site
	}
}

// applyPairedPoolLoad records the two pool words an LDP loaded. The pair
// {IC_DATA_REG, LR} is EmitInstanceCallAOT's {UnlinkedCall, stub} load; the
// order of the two pool slots flips at 3.10.7 but the destination registers do
// not, so the registers identify the shape.
func (e *emitter) applyPairedPoolLoad(ins Instr) {
	if len(ins.PoolLoads) != 2 {
		return
	}
	var ic, lr bool
	for _, l := range ins.PoolLoads {
		if e.pool != nil {
			if disp, ok := e.pool(l.Index); ok {
				e.state.setReg(l.Reg, dartPoolDisplay(disp))
			}
		}
		switch canonReg(l.Reg) {
		case canonReg(e.fir.ICDataReg):
			ic = true
			e.noteCallSiteLoad(l.Reg, l.Index)
		case canonReg(e.fir.LinkReg):
			lr = true
		}
	}
	if !(ic && lr) {
		e.state.ICSite = nil
	}
}

// switchableCallExpr renders a recognised call from the stack arguments bound
// to it (receiver first, preceded by the type-argument vector when the
// descriptor says one is passed). ok is false when the count does not match.
func (e *emitter) switchableCallExpr(bound []string) (string, bool) {
	site := e.state.ICSite
	if site == nil || len(bound) == 0 {
		return "", false
	}
	var typeArgs string
	args := bound
	if site.TypeArgsLen > 0 {
		if len(bound) != site.Count+1 {
			return "", false
		}
		typeArgs, args = bound[0], bound[1:]
	} else if len(bound) != site.Count {
		return "", false
	}
	recv, rest := args[0], args[1:]
	for idx := range site.NamedArgs {
		if idx < site.Positional || idx >= site.Count {
			return "", false
		}
	}
	rendered := make([]string, len(rest))
	for i, a := range rest {
		if name, ok := site.NamedArgs[i+1]; ok {
			a = name + ": " + a
		}
		rendered[i] = a
	}

	dyn := strings.HasPrefix(site.Selector, "dyn:")
	sel := strings.TrimPrefix(site.Selector, "dyn:")
	text := ""
	switch {
	case strings.HasPrefix(sel, "get:") && len(rest) == 0:
		text = fmt.Sprintf("%s.%s", recv, strings.TrimPrefix(sel, "get:"))
	case strings.HasPrefix(sel, "set:") && len(rest) == 1:
		text = fmt.Sprintf("%s.%s = %s", recv, strings.TrimPrefix(sel, "set:"), rest[0])
	case sel == "[]" && len(rest) == 1:
		text = fmt.Sprintf("%s[%s]", recv, rest[0])
	case sel == "[]=" && len(rest) == 2:
		text = fmt.Sprintf("%s[%s] = %s", recv, rest[0], rest[1])
	case binaryOperators[sel] && len(rest) == 1:
		text = fmt.Sprintf("(%s %s %s)", recv, sel, rest[0])
	case sel == "unary-" && len(rest) == 0:
		text = fmt.Sprintf("-%s", recv)
	case sel == "~" && len(rest) == 0:
		text = fmt.Sprintf("~%s", recv)
	case identNameRe.MatchString(sel):
		targs := ""
		if typeArgs != "" {
			targs = fmt.Sprintf("/* typeArgs: %s */", typeArgs)
		}
		text = fmt.Sprintf("%s.%s%s(%s)", recv, sel, targs, strings.Join(rendered, ", "))
	default:
		return "", false
	}
	if dyn {
		text += " /* dynamic */"
	}
	return text, true
}
