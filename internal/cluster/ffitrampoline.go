package cluster

// FfiTrampolineInfo holds decoded metadata for an FfiTrampolineData object.
// Dart FFI trampolines connect Dart functions to native callbacks and, on
// older SDKs, outbound FFI calls.
//
// CallbackKindRaw is intentionally left uninterpreted. The serialized byte
// changed meaning across supported SDKs: Dart 3.1 writes callback_kind_ whose
// FfiCallbackKind is {kSync,kAsync}; Dart 3.3 writes ffi_function_kind_ whose
// enum is callback locality/type; Dart 3.12 has five callback locality/type
// values. Treating one numeric table as a stable Sync/Async/Leaf/Callback enum
// fabricates semantics that are not in the snapshot.
type FfiTrampolineInfo struct {
	RefID                        int
	SignatureTypeRef             int   // TypePtr: Dart-side signature (e.g. int Function(Pointer, int))
	CSignatureRef                int   // FunctionTypePtr: C-side signature (e.g. Int32 Function(Pointer<Uint8>, Uint32))
	CallbackTargetRef            int   // FunctionPtr: Target Dart method for native callbacks, -1 if none
	CallbackExceptionalReturnRef int   // InstancePtr: Value returned if Dart callback throws
	CallbackID                   int32 // Native callback ID (-1 if non-callback)
	CallbackKindRaw              uint8 // exact serialized callback_kind_/ffi_function_kind_ byte
}
