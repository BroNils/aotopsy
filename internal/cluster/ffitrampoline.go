package cluster

// FfiTrampolineInfo holds decoded metadata for an FfiTrampolineData object.
// Dart FFI trampolines connect Dart functions to native C function pointers,
// native callbacks, or FFI calls.
//
// Source: runtime/vm/raw_object.h UntaggedFfiTrampolineData @3.12.2
type FfiTrampolineInfo struct {
	RefID                        int
	SignatureTypeRef             int   // TypePtr: Dart-side signature (e.g. int Function(Pointer, int))
	CSignatureRef                int   // FunctionTypePtr: C-side signature (e.g. Int32 Function(Pointer<Uint8>, Uint32))
	CallbackTargetRef            int   // FunctionPtr: Target Dart method for native callbacks, -1 if none
	CallbackExceptionalReturnRef int   // InstancePtr: Value returned if Dart callback throws
	CallbackID                   int32 // Native callback ID (-1 if non-callback)
	FfiFunctionKind              uint8 // 0=Sync, 1=Async, 2=Leaf, 3=Callback
}

// FfiFunctionKind names for logging and export.
const (
	FfiKindSync     uint8 = 0
	FfiKindAsync    uint8 = 1
	FfiKindLeaf     uint8 = 2
	FfiKindCallback uint8 = 3
)

// FfiKindString returns the human-readable kind name.
func FfiKindString(kind uint8) string {
	switch kind {
	case FfiKindSync:
		return "sync"
	case FfiKindAsync:
		return "async"
	case FfiKindLeaf:
		return "leaf"
	case FfiKindCallback:
		return "callback"
	default:
		return "unknown"
	}
}
