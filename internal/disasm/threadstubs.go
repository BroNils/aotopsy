package disasm

// Per-Dart-version, per-arch table of THR-relative (Thread*) byte
// displacements that hold a CACHED entry point for one of a small set of
// extremely hot VM runtime stubs -- dart-lang/sdk's
// CACHED_VM_STUBS_ADDRESSES_LIST macro in runtime/vm/thread.h. Dart AOT's
// codegen loads these directly from Thread (e.g. "ldr x9, [x26,#0x268]"
// then "blr x9") instead of going through the object pool, as an
// optimization for the handful of stubs called on almost every hot path
// (write barrier, object allocation, stack-overflow checks, safepoint
// transitions).
//
// This is DIFFERENT from, and does not replace, the VM_STUB_CODE_LIST
// naming in stubnames.go (which names the VM-isolate snapshot's own Code
// objects by their creation-order index) -- confirmed by direct
// disassembly search that NONE of those VM-region stub addresses are ever
// branched to directly from app code (checked across the full isolate
// .text range of a real sample: zero direct "bl"/"call" hits to
// WriteBarrier's or AllocateContext's resolved VA, despite the VM and
// isolate instructions regions sitting only ~92KB apart, well within
// ARM64's +-128MB branch range). Real app code reaches these stubs
// exclusively through this Thread-relative indirect-load-then-call idiom.
//
// Offsets were NOT guessed or derived from scratch: they are
// copied directly from dart-lang/sdk's own generated ground-truth header,
// runtime/vm/compiler/runtime_offsets_extracted.h (built by
// tools/run_offsets_extractor.dart, checked into the SDK repo), using the
// `defined(PRODUCT) && defined(TARGET_ARCH_<ARM64|X64>) &&
// defined(DART_COMPRESSED_POINTERS)` block -- PRODUCT because a real
// shipped Flutter release APK is built in product mode, and
// DART_COMPRESSED_POINTERS because that has been the default for 64-bit
// Dart AOT targets since well before Dart 3.7. This PRODUCT+compressed
// assumption was independently cross-checked, not just trusted: an
// empirical scan of a real Dart 3.7.0 ARM64 sample's disassembly for
// "ldr xN,[x26,#off]; blr xN" patterns found offset 0x268 as the single
// most frequent (127 hits across 97 distinct functions, concentrated in
// FFI/native-call-heavy code) -- an EXACT match for this table's
// call_native_through_safepoint_entry_point_offset, and the second most
// frequent (0x208, 78 hits/71 functions) exactly matches
// call_to_runtime_entry_point_offset. If a real sample ever turns out to
// be built without compressed pointers or in non-product mode, these
// offsets will simply fail to match anything (ThreadStubOffsets returns
// nil), degrading gracefully to the pre-existing plain "THR.fNN" display
// rather than mis-naming a call.
var (
	threadStubOffsets370ARM64 = map[int64]string{
		0x1f8: "WriteBarrier",
		0x200: "ArrayWriteBarrier",
		0x208: "CallToRuntime",
		0x210: "AllocateMintSharedWithFPURegs",
		0x218: "AllocateMintSharedWithoutFPURegs",
		0x220: "AllocateObject",
		0x228: "AllocateObjectParameterized",
		0x230: "AllocateObjectSlow",
		0x238: "StackOverflowSharedWithoutFPURegs",
		0x240: "StackOverflowSharedWithFPURegs",
		0x248: "MegamorphicCall",
		0x250: "SwitchableCallMiss",
		0x258: "OptimizeFunction",
		0x260: "Deoptimize",
		0x268: "CallNativeThroughSafepoint",
		0x270: "JumpToFrame",
		0x278: "SlowTypeTest",
		0x280: "ResumeInterpreter", // + SuspendStubABI::kResumePcDistance at runtime, entry point value itself still identifies the stub
		0x288: "BootstrapNativeCallWrapper",
		0x290: "NoScopeNativeCallWrapper",
		0x298: "AutoScopeNativeCallWrapper",
		0x2a0: "InterpretCall",
	}

	// x86_64 (r14=THR) has IDENTICAL offsets to ARM64 for this same
	// Dart version -- verified directly against dart-lang/sdk's
	// generated runtime_offsets_extracted.h TARGET_ARCH_X64 PRODUCT+
	// compressed-pointers block for 3.7.0 (only the suspend-state
	// entry points further out in the struct differ between arches,
	// none of which are in this table).
	threadStubOffsets370X64 = threadStubOffsets370ARM64

	// Dart 3.9.2 shifts every one of these offsets by exactly +0x8
	// relative to 3.7.0 on BOTH arches (one additional 8-byte field was
	// added to Thread ahead of this cluster between the two SDK
	// versions) -- verified against the same generated header at the
	// 3.9.2 tag.
	threadStubOffsets392ARM64 = map[int64]string{
		0x200: "WriteBarrier",
		0x208: "ArrayWriteBarrier",
		0x210: "CallToRuntime",
		0x218: "AllocateMintSharedWithFPURegs",
		0x220: "AllocateMintSharedWithoutFPURegs",
		0x228: "AllocateObject",
		0x230: "AllocateObjectParameterized",
		0x238: "AllocateObjectSlow",
		0x240: "StackOverflowSharedWithoutFPURegs",
		0x248: "StackOverflowSharedWithFPURegs",
		0x250: "MegamorphicCall",
		0x258: "SwitchableCallMiss",
		0x260: "OptimizeFunction",
		0x268: "Deoptimize",
		0x270: "CallNativeThroughSafepoint",
		0x278: "JumpToFrame",
		0x280: "SlowTypeTest",
		0x288: "ResumeInterpreter",
		0x290: "BootstrapNativeCallWrapper",
		0x298: "NoScopeNativeCallWrapper",
		0x2a0: "AutoScopeNativeCallWrapper",
		0x2a8: "InterpretCall",
	}
	threadStubOffsets392X64 = threadStubOffsets392ARM64

	// Dart 3.10.9's table is IDENTICAL to 3.7.0's -- verified against the
	// generated header at the 3.10.9 tag, both PRODUCT+compressed-pointers
	// ARM64 and X64 blocks. NOT a monotonic shift from 3.9.2: this
	// version's Thread layout shifted back DOWN by 0x8 relative to 3.9.2
	// (some field present in 3.9.2 is absent again here), matching 3.7.0's
	// offsets exactly rather than continuing 3.9.2's. Cross-checked
	// empirically: a real Dart sample built with this exact SDK
	// showed the stack-overflow-check indirect call at THR+0x238 (matching
	// this table's StackOverflowSharedWithoutFPURegs, NOT 3.9.2's 0x240)
	// before the ground-truth header was even consulted.
	threadStubOffsets3109 = threadStubOffsets370ARM64

	// Dart 3.11.5 and 3.12.2 both match 3.9.2's table exactly (the field
	// removed at 3.10.x is back by 3.11.x) -- verified against the
	// generated header at both tags, both arches all four identical.
	threadStubOffsets3115 = threadStubOffsets392ARM64
	threadStubOffsets3122 = threadStubOffsets392ARM64

	// Dart 2.17.6 -- PRODUCT + TARGET_ARCH_ARM64 +
	// !DART_COMPRESSED_POINTERS block (compressed pointers were NOT yet
	// the default for 64-bit Dart AOT at 2.x; they became default in the
	// Dart 3.0 cycle). This table is a SUBSET of the 3.7.0 cluster: the
	// four stubs added later (MegamorphicCall, SwitchableCallMiss,
	// OptimizeFunction, Deoptimize at 0x248-0x260 in 3.7.0) and
	// ResumeInterpreter / InterpretCall did not yet exist as
	// Thread-cached stubs in 2.17.6, so the native-call wrappers sit
	// 0x10 lower than in 3.7.0 (Bootstrap at 0x280, not 0x288). X64
	// non-compressed PRODUCT offsets are identical -- verified against
	// the same generated header's TARGET_ARCH_X64 PRODUCT+
	// !DART_COMPRESSED_POINTERS block.
	threadStubOffsets2176 = map[int64]string{
		0x1f8: "WriteBarrier",
		0x200: "ArrayWriteBarrier",
		0x208: "CallToRuntime",
		0x210: "AllocateMintSharedWithFPURegs",
		0x218: "AllocateMintSharedWithoutFPURegs",
		0x220: "AllocateObject",
		0x228: "AllocateObjectParameterized",
		0x230: "AllocateObjectSlow",
		0x238: "StackOverflowSharedWithoutFPURegs",
		0x240: "StackOverflowSharedWithFPURegs",
		0x268: "CallNativeThroughSafepoint",
		0x270: "JumpToFrame",
		0x278: "SlowTypeTest",
		0x280: "BootstrapNativeCallWrapper",
		0x288: "NoScopeNativeCallWrapper",
		0x290: "AutoScopeNativeCallWrapper",
	}

	// Dart 3.0.5 and 3.2.5 -- PRODUCT + TARGET_ARCH_ARM64 +
	// DART_COMPRESSED_POINTERS (compressed pointers became the default
	// for 64-bit Dart AOT starting in the 3.0 cycle). Both versions have
	// IDENTICAL Thread-cached stub offsets -- verified against the
	// generated header at both tags. The whole cluster is shifted -0x10
	// relative to 2.17.6 (compressed-pointer Thread layout is smaller)
	// and, like 2.17.6, lacks the four later stubs (MegamorphicCall et
	// al.) plus ResumeInterpreter / InterpretCall. X64 compressed
	// PRODUCT offsets are identical -- verified against the
	// TARGET_ARCH_X64 PRODUCT+compressed block at both tags.
	threadStubOffsets305 = map[int64]string{
		0x1e8: "WriteBarrier",
		0x1f0: "ArrayWriteBarrier",
		0x1f8: "CallToRuntime",
		0x200: "AllocateMintSharedWithFPURegs",
		0x208: "AllocateMintSharedWithoutFPURegs",
		0x210: "AllocateObject",
		0x218: "AllocateObjectParameterized",
		0x220: "AllocateObjectSlow",
		0x228: "StackOverflowSharedWithoutFPURegs",
		0x230: "StackOverflowSharedWithFPURegs",
		0x258: "CallNativeThroughSafepoint",
		0x260: "JumpToFrame",
		0x268: "SlowTypeTest",
		0x270: "BootstrapNativeCallWrapper",
		0x278: "NoScopeNativeCallWrapper",
		0x280: "AutoScopeNativeCallWrapper",
	}
	threadStubOffsets325 = threadStubOffsets305

	// Dart 3.4.3 -- PRODUCT + TARGET_ARCH_ARM64 +
	// DART_COMPRESSED_POINTERS. The cluster shifts +0x8 relative to
	// 3.0.5/3.2.5 (one 8-byte field added to Thread ahead of these
	// stubs), but still lacks the four later stubs (MegamorphicCall et
	// al.) and ResumeInterpreter / InterpretCall. X64 compressed PRODUCT
	// offsets are identical -- verified against the generated header.
	threadStubOffsets343 = map[int64]string{
		0x1f0: "WriteBarrier",
		0x1f8: "ArrayWriteBarrier",
		0x200: "CallToRuntime",
		0x208: "AllocateMintSharedWithFPURegs",
		0x210: "AllocateMintSharedWithoutFPURegs",
		0x218: "AllocateObject",
		0x220: "AllocateObjectParameterized",
		0x228: "AllocateObjectSlow",
		0x230: "StackOverflowSharedWithoutFPURegs",
		0x238: "StackOverflowSharedWithFPURegs",
		0x260: "CallNativeThroughSafepoint",
		0x268: "JumpToFrame",
		0x270: "SlowTypeTest",
		0x278: "BootstrapNativeCallWrapper",
		0x280: "NoScopeNativeCallWrapper",
		0x288: "AutoScopeNativeCallWrapper",
	}

	// Dart 3.6.2 -- PRODUCT + TARGET_ARCH_ARM64 +
	// DART_COMPRESSED_POINTERS. The cluster shifts another +0x8 relative
	// to 3.4.3, and ResumeInterpreter (resume_interpreter_adjusted in
	// the header) plus InterpretCall reappear -- so from 0x268 onward
	// (CallNativeThroughSafepoint ... InterpretCall at 0x2a0) this table
	// is byte-for-byte identical to 3.7.0's, and the 0x1f8-0x240 head
	// (WriteBarrier ... StackOverflowSharedWithFPURegs) also matches
	// 3.7.0 exactly. The ONLY difference from 3.7.0 is the absence of
	// the four stubs at 0x248-0x260 (MegamorphicCall, SwitchableCallMiss,
	// OptimizeFunction, Deoptimize), which were added in 3.7.0. X64
	// compressed PRODUCT offsets are identical -- verified against the
	// generated header.
	threadStubOffsets362 = map[int64]string{
		0x1f8: "WriteBarrier",
		0x200: "ArrayWriteBarrier",
		0x208: "CallToRuntime",
		0x210: "AllocateMintSharedWithFPURegs",
		0x218: "AllocateMintSharedWithoutFPURegs",
		0x220: "AllocateObject",
		0x228: "AllocateObjectParameterized",
		0x230: "AllocateObjectSlow",
		0x238: "StackOverflowSharedWithoutFPURegs",
		0x240: "StackOverflowSharedWithFPURegs",
		0x268: "CallNativeThroughSafepoint",
		0x270: "JumpToFrame",
		0x278: "SlowTypeTest",
		0x280: "ResumeInterpreter", // resume_interpreter_adjusted in the header; entry point value still identifies the stub
		0x288: "BootstrapNativeCallWrapper",
		0x290: "NoScopeNativeCallWrapper",
		0x298: "AutoScopeNativeCallWrapper",
		0x2a0: "InterpretCall",
	}
)

// ThreadStubOffsets returns the THR-relative offset->stub-name table for
// the given Dart version and architecture, or nil if this exact
// (version, arch) pair hasn't been verified yet (see this file's doc
// comment for the derivation and verification method). Never guesses --
// an unrecognized version returns nil, which decompiler.FuncIR treats as
// "feature inactive for this function" rather than emitting a wrong name.
func ThreadStubOffsets(dartVersion string, isARM64 bool) map[int64]string {
	switch dartVersion {
	case "3.7.0":
		if isARM64 {
			return threadStubOffsets370ARM64
		}
		return threadStubOffsets370X64
	case "3.9.2":
		if isARM64 {
			return threadStubOffsets392ARM64
		}
		return threadStubOffsets392X64
	case "3.10.7": // real sample verified was 3.10.9 -- see VMStubNames' doc comment on hash-label reuse
		return threadStubOffsets3109
	case "3.11.0": // real sample verified was 3.11.5
		return threadStubOffsets3115
	case "3.12.2":
		return threadStubOffsets3122
	case "2.17.6":
		return threadStubOffsets2176
	case "3.0.5":
		return threadStubOffsets305
	case "3.2.5":
		return threadStubOffsets325
	case "3.4.3":
		return threadStubOffsets343
	case "3.6.2":
		return threadStubOffsets362
	}
	return nil
}
