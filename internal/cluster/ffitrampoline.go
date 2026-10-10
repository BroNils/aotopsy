package cluster

import "aotopsy/internal/snapshot"

// FfiDirection is the statically provable direction of an FFI bridge.
// Unknown is explicit because malformed or unsupported metadata must not be
// converted into a confident outbound/callback claim.
type FfiDirection string

const (
	FfiDirectionUnknown  FfiDirection = "unknown"
	FfiDirectionOutbound FfiDirection = "outbound"
	FfiDirectionCallback FfiDirection = "callback"
)

// FfiTrampolineInfo holds decoded metadata for an FfiTrampolineData object.
// Dart FFI trampolines connect Dart functions to native callbacks and, on
// older SDKs, outbound FFI calls.
//
// FfiKindRaw is intentionally left uninterpreted. Its field and enum changed
// meaning across supported SDKs: Dart 3.1 writes callback_kind_ (SDK @3.1.0
// runtime/vm/raw_object.h:1440); the supported Dart 3.2.5 tree writes
// ffi_function_kind_ (SDK @3.2.5 runtime/vm/raw_object.h:1510) and call.cc:50
// uses FfiFunctionKind::kCall for outbound trampolines; from Dart 3.3
// kFfiTrampoline is callback-only and the byte describes FfiCallbackKind.
// Treating one numeric table as stable across those versions fabricates
// semantics that are not in the snapshot.
type FfiTrampolineInfo struct {
	RefID                        int
	SignatureTypeRef             int   // TypePtr: Dart-side signature (e.g. int Function(Pointer, int))
	CSignatureRef                int   // FunctionTypePtr: C-side signature (e.g. Int32 Function(Pointer<Uint8>, Uint32))
	CallbackTargetRef            int   // FunctionPtr snapshot ref: RefNull for no callback target, otherwise the Dart callback target
	CallbackExceptionalReturnRef int   // InstancePtr: Value returned if Dart callback throws
	CallbackID                   int32 // exact decoded ID; non-callback sentinel is version-dependent (0 through 2.18, -1 from 2.19)
	FfiKindRaw                   uint8 // exact serialized callback_kind_/ffi_function_kind_ byte
}

// ClassifyFfiTrampolineDirection applies only source-grounded rules to a
// decoded FfiTrampolineData object.
//
// Through Dart 3.2.5, the VM creates kFfiTrampoline Functions for both
// directions. UntaggedFfiTrampolineData documents callback_target as the
// discriminator: a callback has a Dart target, while an outbound call has
// null. Starting in Dart 3.3.0 the outbound call.cc trampoline implementation
// is gone and Function::kFfiTrampoline is explicitly
// IsFfiCallbackTrampoline(); outbound Pointer.asFunction calls are ordinary
// vm:ffi:call-closure closures instead.
//
// Exact SDK evidence:
//   - @2.10.0 runtime/vm/raw_object.h:1142-1160 documents callback_target_ and
//     the callback_id sentinel; clustered_snapshot.cc:923-967 serializes both
//     the pointer fields and callback_id in Full AOT.
//   - @2.10.0 runtime/vm/compiler/ffi/call.cc:17-61 and callback.cc:15-64 both
//     create FunctionLayout::kFfiTrampoline, proving the shared-kind model at
//     the oldest supported release.
//   - @3.2.5 runtime/vm/compiler/ffi/call.cc:17-76 still creates
//     UntaggedFunction::kFfiTrampoline and marks FfiFunctionKind::kCall.
//   - @3.3.0 runtime/vm/object.h:3898-3909 names the kind
//     IsFfiCallbackTrampoline/IsFfiCallClosure; pkg/vm/lib/transformations/ffi/
//     use_sites.dart:447-467 creates #ffiClosureN with vm:ffi:call-closure.
//
// Only repository-supported exact versions are classified. Future/unknown
// versions stay unknown until their SDK source has been verified.
func ClassifyFfiTrampolineDirection(dartVersion string, info FfiTrampolineInfo) FfiDirection {
	if snapshot.ProfileForVersion(dartVersion) == nil {
		return FfiDirectionUnknown
	}
	if snapshot.VersionAtLeast(dartVersion, "3.3.0") {
		return FfiDirectionCallback
	}
	if info.CallbackTargetRef == RefNull {
		return FfiDirectionOutbound
	}
	if info.CallbackTargetRef > RefNull {
		return FfiDirectionCallback
	}
	return FfiDirectionUnknown
}
