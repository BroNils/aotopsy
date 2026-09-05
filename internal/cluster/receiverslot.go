package cluster

// Receiver frame-slot recovery for Dart versions before 3.4.3.
//
// Up to and including 3.3.0 there is no register calling convention --
// `DartCallingConvention` does not exist in constants_arm64.h at that tag and
// first appears at 3.4.3 -- so arguments arrive on the stack and the receiver
// has to be located in the frame.
//
// Whether there IS a static slot is decided by
// PrologueBuilder::BuildParameterHandling (prologue_builder.cc), which emits
// two different shapes.
//
// A function with no optional parameters uses a CONSTANT index:
//
//	copy_args_prologue += IntConstant(0);
//	copy_args_prologue += LoadFpRelativeSlot(
//	    kWordSize * (frame_layout.param_end_from_fp + fixed_params_size - param_offset), ...);
//
// so parameter i sits at a static FP + (kParamEndSlotFromFp + N - i) *
// wordSize, with kParamEndSlotFromFp = 1 on both ARM64 and x64. The receiver
// is parameter 0, the highest slot. Confirmed on a real 2.12.0 arm64 binary: a
// two-parameter operator+ loads its receiver with `ldr x3, [x29, #24]`.
//
// A function WITH optional parameters uses a RUNTIME index:
//
//	copy_args_prologue += LoadArgDescriptor();
//	copy_args_prologue += LoadNativeField(Slot::ArgumentsDescriptor_count());
//	... SmiBinaryOp(kSUB) with min_num_pos_args ...
//	copy_args_prologue += LoadLocal(optional_count_var);   // dynamic index
//	copy_args_prologue += LoadFpRelativeSlot(/* static displacement */ ...);
//
// and LoadFpRelativeSlot is LoadIndexedUnsafeInstr(Pop(), offset, ...) -- a
// dynamic index plus a static displacement. The parameter's address therefore
// depends on how many arguments the CALLER passed, and no static slot exists.
// On 2.12.0 arm64 this compiles to, for RangeError.range:
//
//	MOV  X1, X4                 ; ARGS_DESC_REG
//	LDUR X2, [X1,#31]           ; ArgumentsDescriptor.count
//	SUB  X1, X2, #0x8           ; count - min_num_pos_args
//	ADD  X2, X29, X1, LSL #2    ; FP + optional_count * wordSize
//	LDR  X2, [X2,#40]           ; + static displacement -> receiver
//
// A previous draft of this file derived FP-24 / FP-32 for that case from
// ParsedFunction::AllocateVariables and FrameLayout::FrameSlotForVariableIndex.
// Those describe the LocalVariable index, which in optimized AOT code the
// register allocator is free to keep in a register -- in the sample above
// nothing is spilled at all. The derivation was real and the conclusion was
// wrong; see docs/findings-repo/010.
//
// Verified by reading prologue_builder.cc, base_flow_graph_builder.cc,
// parser.cc, scopes.cc, frame_layout.h and object.h at tag 3.3.0, and
// cross-checked at 2.12.0, 2.17.6, 2.19.0, 3.0.5, 3.1.0, 3.2.5 and 3.4.3.

// ParamEndSlotFromFP is kParamEndSlotFromFp: one slot past the last parameter.
// 1 on ARM64 (stack_frame_arm64.h) and x64 (stack_frame_x64.h).
const ParamEndSlotFromFP = 1

// ReceiverFrameSlot returns the FP-relative BYTE offset at which the receiver
// of an instance method arrives, for Dart versions before 3.4.3.
//
// numFixedWithReceiver is num_fixed_parameters as the SDK counts it (the
// implicit receiver included). numOptional is NumOptionalParameters().
// suspendable is modifier() != kNoModifier.
//
// ok is false in two different situations, and neither is a failure of this
// function:
//
//   - The arity is unknown (numFixedWithReceiver <= 0). From Dart 2.14 the
//     arity lives on FunctionType behind a WeakSerializationReference the AOT
//     serializer does not write, so this is the common case on 2.14..3.3.0 --
//     measured at ~80% of functions. Code-based recovery is the only route
//     there; see typetrack.RecoverReceiverStackSlot*.
//   - The function copies its parameters. There is then no static slot AT
//     ALL: PrologueBuilder::BuildParameterHandling loads each parameter at a
//     runtime index derived from ArgumentsDescriptor.count, so the address
//     depends on what the CALLER passed. Returning a made-up offset here
//     produced a seed no load could ever match.
func ReceiverFrameSlot(numFixedWithReceiver, numOptional int, suspendable bool, wordSize int64) (int64, bool) {
	if numFixedWithReceiver <= 0 {
		return 0, false
	}
	if numOptional > 0 || suspendable {
		// Function::MakesCopyOfParameters(). No static slot exists.
		return 0, false
	}
	return int64(ParamEndSlotFromFP+numFixedWithReceiver) * wordSize, true
}
