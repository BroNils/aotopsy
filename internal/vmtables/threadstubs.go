package vmtables

// threadStubFieldNames maps the exact Thread field names exported by
// runtime_offsets_extracted.h to the VM stub names declared by
// CACHED_VM_STUBS_ADDRESSES_LIST in runtime/vm/thread.h.
//
// The byte offsets themselves intentionally do NOT live here. They are a
// subset of the profile-specific THR field table, so duplicating them in a
// second per-version table allowed the two sources to drift independently.
// ThreadStubOffsets derives its offsets from THRFields, leaving one SDK-derived
// source of truth for version/architecture/pointer-compression layout.
var threadStubFieldNames = map[string]string{
	"write_barrier_entry_point":                          "WriteBarrier",
	"array_write_barrier_entry_point":                    "ArrayWriteBarrier",
	"call_to_runtime_entry_point":                        "CallToRuntime",
	"allocate_mint_with_fpu_regs_entry_point":            "AllocateMintSharedWithFPURegs",
	"allocate_mint_without_fpu_regs_entry_point":         "AllocateMintSharedWithoutFPURegs",
	"allocate_object_entry_point":                        "AllocateObject",
	"allocate_object_parameterized_entry_point":          "AllocateObjectParameterized",
	"allocate_object_slow_entry_point":                   "AllocateObjectSlow",
	"stack_overflow_shared_without_fpu_regs_entry_point": "StackOverflowSharedWithoutFPURegs",
	"stack_overflow_shared_with_fpu_regs_entry_point":    "StackOverflowSharedWithFPURegs",
	"megamorphic_call_checked_entry":                     "MegamorphicCall",
	"switchable_call_miss_entry":                         "SwitchableCallMiss",
	"optimize_entry":                                     "OptimizeFunction",
	"deoptimize_entry":                                   "Deoptimize",
	"call_native_through_safepoint_entry_point":          "CallNativeThroughSafepoint",
	"jump_to_frame_entry_point":                          "JumpToFrame",
	"slow_type_test_entry_point":                         "SlowTypeTest",
	"resume_interpreter_adjusted_entry_point":            "ResumeInterpreter",
	"bootstrap_native_wrapper_entry_point":               "BootstrapNativeCallWrapper",
	"no_scope_native_wrapper_entry_point":                "NoScopeNativeCallWrapper",
	"auto_scope_native_wrapper_entry_point":              "AutoScopeNativeCallWrapper",
	"interpret_call_entry_point":                         "InterpretCall",
}

// ThreadStubOffsets returns the exact THR-relative offset -> VM-stub map for
// target. Unsupported profiles return nil rather than borrowing a neighbouring
// version or compression mode.
func ThreadStubOffsets(target TargetProfile) map[int64]string {
	fields := THRFields(target)
	if len(fields) == 0 {
		return nil
	}
	out := make(map[int64]string)
	for off, field := range fields {
		if stub, ok := threadStubFieldNames[field]; ok {
			out[int64(off)] = stub
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
