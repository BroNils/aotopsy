package decompiler

import (
	"strings"
	"testing"
)

// The tests here are what internal/pipeline's TestDecompilerFeatures claimed
// to be. That test's doc comment promised it "checks that decompiler output
// contains expected features (ffi_call, field names, etc.)", and its body
// counted the lines in functions.jsonl -- a file the decompiler does not
// write, in a package that never invokes the emitter. It could not have
// noticed either feature disappearing.
//
// These do, and hermetically: a hand-built FuncIR through EmitPseudocode,
// no sample binary, so they run in a bare clone.

// featureFuncIR builds an ARM64 FuncIR shell with one block of instructions.
func featureFuncIR(name string, instrs []Instr) *FuncIR {
	fir := newFuncIR(name, 0x1000)
	fir.ArgRegs = arm64ArgRegs
	fir.FrameReg = arm64FrameReg
	fir.ReturnReg = arm64ReturnReg
	fir.LinkReg = arm64LinkReg
	fir.PoolReg = arm64PoolReg
	fir.ThreadReg = arm64ThreadReg
	fir.NullReg = arm64NullReg
	fir.addBlock(Block{ID: 0, StartVA: 0x1000, Instrs: instrs})
	return fir
}

// TestFeatureFFICallIsNamed covers the FFI native-call shape.
//
// Dart AOT's TransitionGeneratedToNative stores the call target into
// Thread::vm_tag_ before dispatching it, and no other calling convention
// writes the target into Thread state that way -- so a BLR through a register
// last stored to vm_tag is a confirmed FFI leaf call, not a guess. The emitter
// must name it rather than fall back to dynamicCall on a raw register.
//
// The vm_tag offset is deliberately NOT hardcoded here: it is looked up
// through fir.ThreadFieldNames, the same SDK-derived table
// (runtime_offsets_extracted.h) the real pipeline supplies. An earlier version
// fired on ANY Thread store and mislabelled 43528 write-barrier and
// stack-overflow stores as FFI calls, which is why the table lookup exists.
func TestFeatureFFICallIsNamed(t *testing.T) {
	const vmTagOff = 0x1a0
	fir := featureFuncIR("ffi_caller", []Instr{
		{Addr: 0x1000, Op: OpOther, Src: "ldr x1, [x27, #0x100]"},
		{Addr: 0x1004, Op: OpOther, Src: "str x1, [x26, #0x1a0]"},
		{Addr: 0x1008, Op: OpCall, Src: "blr x1", Target: "x1"},
		{Addr: 0x100c, Op: OpReturn, Src: "ret"},
	})
	fir.ThreadFieldNames = map[int64]string{vmTagOff: "vm_tag"}

	art := EmitPseudocode(fir, nil, nil)
	if !strings.Contains(art.Source, FFICallMarker) {
		t.Errorf("a BLR through a register stored to Thread.vm_tag must emit %q, got:\n%s",
			FFICallMarker, art.Source)
	}
	// The store itself is bookkeeping, not application logic, so it must be
	// suppressed rather than emitted as an assignment. (The emitter does name
	// vm_tag in the trailing comment on the call, which is the point of it --
	// so this looks for the assignment specifically.)
	if strings.Contains(art.Source, "vm_tag =") {
		t.Errorf("the vm_tag bookkeeping store was emitted as an assignment:\n%s", art.Source)
	}
}

// A store to a Thread field that is NOT vm_tag must not mark the register.
// This is the regression direction of the same feature: without it, every
// write-barrier store turns the next indirect call into a fake FFI call.
func TestFeatureNonVMTagThreadStoreIsNotFFI(t *testing.T) {
	fir := featureFuncIR("not_ffi", []Instr{
		{Addr: 0x1000, Op: OpOther, Src: "ldr x1, [x27, #0x100]"},
		{Addr: 0x1004, Op: OpOther, Src: "str x1, [x26, #0x1a8]"},
		{Addr: 0x1008, Op: OpCall, Src: "blr x1", Target: "x1"},
		{Addr: 0x100c, Op: OpReturn, Src: "ret"},
	})
	fir.ThreadFieldNames = map[int64]string{
		0x1a0: "vm_tag",
		0x1a8: "write_barrier_mask",
	}

	art := EmitPseudocode(fir, nil, nil)
	if strings.Contains(art.Source, FFICallMarker) {
		t.Errorf("a store to write_barrier_mask must not make the next BLR an FFI call:\n%s",
			art.Source)
	}
}

// TestFeatureFieldNamesResolve covers instance-field naming: a load at a byte
// offset off an object register renders as base.fieldName, resolved through
// FieldNameResolver with the receiver's class ID.
func TestFeatureFieldNamesResolve(t *testing.T) {
	fir := featureFuncIR("field_reader", []Instr{
		{Addr: 0x1000, Op: OpOther, Src: "ldr x2, [x0, #0x10]"},
		// The load lands in x2, which nothing reads; move it into the
		// return register so the expression actually reaches the output.
		{Addr: 0x1004, Op: OpOther, Src: "mov x0, x2"},
		{Addr: 0x1008, Op: OpReturn, Src: "ret"},
	})
	fir.ReceiverClassID = 77
	fir.FieldNameResolver = func(classID int, byteOffset int64) string {
		if classID == 77 && byteOffset == 0x10 {
			return "itemCount"
		}
		return ""
	}

	art := EmitPseudocode(fir, nil, nil)
	if !strings.Contains(art.Source, "itemCount") {
		t.Errorf("a field load must render with its resolved name, got:\n%s", art.Source)
	}
}

// The resolver must never be consulted for THR, PP or SP relative loads.
// Those displacements address Thread fields, pool slots and stack slots, not
// instance fields, and running them through a class layout produced confident
// nonsense -- 43528 `THR.radius` on the x86_64 sample, plus THR.orientation
// and THR.tilt. Thread has no such fields.
func TestFeatureFieldNamesSkipThreadPoolAndStack(t *testing.T) {
	for _, tc := range []struct{ name, src, base string }{
		{"thread", "ldr x2, [x26, #0x10]", "x26"},
		{"pool", "ldr x2, [x27, #0x10]", "x27"},
		{"stack", "ldr x2, [x15, #0x10]", "x15"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fir := featureFuncIR("no_fields_here", []Instr{
				{Addr: 0x1000, Op: OpOther, Src: tc.src},
				{Addr: 0x1004, Op: OpOther, Src: "mov x0, x2"},
				{Addr: 0x1008, Op: OpReturn, Src: "ret"},
			})
			fir.StackReg = arm64StackReg
			fir.ReceiverClassID = 77
			fir.FieldNameResolver = func(int, int64) string { return "radius" }

			art := EmitPseudocode(fir, nil, nil)
			if strings.Contains(art.Source, "radius") {
				t.Errorf("a %s-relative load must not be named as an instance field, got:\n%s",
					tc.name, art.Source)
			}
		})
	}
}
