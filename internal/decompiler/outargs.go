package decompiler

import (
	"fmt"
	"sort"
	"strings"

	"aotopsy/internal/sdk"
	"aotopsy/internal/snapshot"
)

// Binding stack-passed call arguments to the call.
//
// From Dart 3.0.5 on (verified against il_arm64.cc / il_x64.cc: the
// PushArgumentInstr emitter is gone and MoveArgumentInstr::EmitNativeCode
// stores each argument to `[SP + sp_relative_index * kWordSize]`) the
// compiler reserves an outgoing-argument area in the prologue and every stack
// argument of a call is written by a MoveArgument inserted IMMEDIATELY before
// the call (FlowGraph::InsertMoveArguments: "Insert all MoveArgument
// instructions immediately before call"). There is no push and no drop after
// the call, so the argument COUNT is not printed anywhere -- but it does not
// need to be: the SP-relative slots written since the previous call are
// exactly this call's stack arguments.
//
// Slot order (dart_calling_conventions.cc ComputeCallingConvention): stack
// slots are assigned from the LAST argument downward, so the last stack
// argument is at SP+0 and the first stack argument is the deepest, at
// SP+8*(k-1). The arguments in source order are therefore the slots from the
// highest offset down to 0. (In 3.4.0+ register CC the first arguments of
// eligible callees travel in registers instead; those are already in args and
// the stack ones follow, matching "first max_arguments_in_registers go to
// registers, the rest to the stack".)
//
// The binding is deliberately conservative:
//   - only for versions with the MoveArgument model (>= 3.0.5); the <= 2.19.0
//     push model needs stack-pointer tracking the lifter does not have;
//   - only when the written offsets are exactly {0, 8, ..., 8(k-1)} -- a gap
//     means a stale slot or an unknown layout, and nothing is bound;
//   - not for calls to GC/allocation/runtime stubs (their arguments are not
//     Dart arguments).

// movesStackArgs reports whether this FuncIR's SDK version passes stack
// arguments with MoveArgument (>= 3.0.5).
func (e *emitter) movesStackArgs() bool {
	return snapshot.VersionAtLeast(e.fir.DartVersion, "3.0.5")
}

// hasRegisterCC reports whether this SDK version has the register calling
// convention: dart_calling_conventions.cc and Function::
// MaxNumberOfParametersInRegisters first appear at 3.4.3 (absent in every
// supported release before it).
func (e *emitter) hasRegisterCC() bool {
	return snapshot.VersionAtLeast(e.fir.DartVersion, "3.4.0")
}

// takeOutgoingStackArgs returns the stack arguments of the call about to be
// emitted, in source order, and removes the now-redundant slot stores from the
// emitted lines. It always clears the block's slot record (the call consumes
// or invalidates it). A nil result means nothing was bound.
func (e *emitter) takeOutgoingStackArgs(calleeName string) []string {
	slots := e.state.OutSlots
	e.state.OutSlots = nil
	if len(slots) == 0 || !e.movesStackArgs() || isStubLikeCallee(calleeName) {
		return nil
	}
	offs := make([]int64, 0, len(slots))
	for off := range slots {
		offs = append(offs, off)
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	for i, off := range offs {
		if off != int64(i)*8 {
			return nil // gap: not a plain outgoing-argument run
		}
	}
	args := make([]string, 0, len(offs))
	for i := len(offs) - 1; i >= 0; i-- { // deepest slot = first argument
		args = append(args, slots[offs[i]])
	}
	// The stores were emitted as statements when they were lifted; they are the
	// argument list now, so drop them (exact text match, newest first, only
	// within the current block).
	for _, off := range offs {
		e.dropEmittedLine(fmt.Sprintf("%s = %s;", sdk.StackSlotName(off), slots[off]))
	}
	return args
}

// dropEmittedLine removes the most recent emitted line equal (trimmed) to text,
// searching back only as far as the current block's first line.
func (e *emitter) dropEmittedLine(text string) {
	for i := len(e.lines) - 1; i >= e.blockLineStart && i >= 0; i-- {
		if strings.TrimSpace(e.lines[i]) == text {
			e.lines = append(e.lines[:i], e.lines[i+1:]...)
			return
		}
	}
}

// isStubLikeCallee reports callee names whose stack/register arguments are not
// Dart arguments (allocation, write-barrier, stack-overflow and similar VM
// stubs), by the same name conventions the emitter already uses elsewhere.
func isStubLikeCallee(name string) bool {
	if name == "" {
		return false
	}
	if isSlowPathStubName(name) {
		return true
	}
	return strings.HasPrefix(name, "Allocate") || strings.Contains(name, "Stub") ||
		strings.HasPrefix(name, "native_transition") || strings.HasPrefix(name, "CallToRuntime")
}
