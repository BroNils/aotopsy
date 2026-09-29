package vmtables

// The order VM-isolate stub Code objects appear in the instructions image.
//
// This is NOT the order of VM_STUB_CODE_LIST, and assuming it was made every
// VM stub name wrong. Ground truth, from the `.symtab` of a Dart 3.12.2 build
// (both architectures, 173 FUNC symbols in the VM instructions region):
//
//	lowest address   void.<optimized out>      <- UnknownDartCode, a 5-byte stub
//	                 stub EnsureDeeplyImmutable
//	                 stub CheckedStoreIntoShared
//	                 ...
//	highest address  stub JumpToFrame          <- VM_STUB_CODE_LIST entry 0
//
// so the image is laid out in REVERSE of the list, and the previous
// forward-by-index assignment named the lowest address `JumpToFrame` -- the
// stub that is actually at the highest. Every one of the 164 names was
// wrong. It survived because the only check ever applied was "index 0 is a
// small function", which is equally true of UnknownDartCode at the other end.
//
// For SDKs that expose VM_TYPE_TESTING_STUB_CODE_LIST separately, those 9
// entries sit immediately after the Subtype*TestCache group. Dart 2.10 is
// older: it inlines the same 9 stubs directly after Subtype6TestCache. That
// historical difference is normalized at the VMStubNames boundary, so every
// consumer below sees the exact SDK emission order and never composes lists.
//
//	164 VM_STUB_CODE_LIST (incl. the PROBE_POINT_STUBS_LIST expansion)
//	  9 VM_TYPE_TESTING_STUB_CODE_LIST
//	---
//	173 = the Code count in the VM snapshot, exactly
//
// Verified on 3.12.2 ARM64 and x86_64. The other supported versions share
// the same two SDK lists and the same serializer, so the same composition
// applies; internal/analysis's symbol-table differential gate is what would
// catch it if a symbol-bearing sample of another version ever says otherwise.

// vmTypeTestingStubNames is VM_TYPE_TESTING_STUB_CODE_LIST from
// runtime/vm/stub_code_list.h, in declaration order. Stable across every
// supported version.
var vmTypeTestingStubNames = []string{
	"DefaultTypeTest",
	"DefaultNullableTypeTest",
	"TopTypeTypeTest",
	"UnreachableTypeTest",
	"TypeParameterTypeTest",
	"NullableTypeParameterTypeTest",
	"SlowTypeTest",
	"LazySpecializeTypeTest",
	"LazySpecializeNullableTypeTest",
}

// subtypeTestCacheAnchor is the last entry of VM_STUB_CODE_LIST's
// subtype-test-cache group; the type-testing stubs follow it.
const subtypeTestCacheAnchor = "Subtype7TestCache"

// VMStubNamesInImageOrder returns the stub names in the order their Code
// objects appear in the VM instructions image, lowest address first -- ready
// to be zipped against address-sorted code ranges. Returns nil for a version
// with no verified list, so callers name nothing rather than guessing.
func VMStubNamesInImageOrder(dartVersion string) []string {
	list := VMStubNames(dartVersion)
	if list == nil {
		return nil
	}
	// The image is laid out in reverse of emission order.
	out := make([]string, len(list))
	for i, n := range list {
		out[len(list)-1-i] = n
	}
	return out
}

// VMStubNamesInClusterOrder returns the stub names in the order their Code
// objects appear in the VM snapshot's Code cluster (creation/emission order),
// including type-testing stubs exactly where the SDK emits them. This matches
// vmResult.Codes[i] ordering, which is the order Code objects were serialized
// into the cluster — the same as StubCode::Init emission order.
//
// Use this (NOT VMStubNamesInImageOrder) when zipping against vmResult.Codes
// directly, as BuildPoolLookups does for pool-display naming. The image-order
// function is for address-sorted ranges, as BuildVMStubSymbols does for
// VA→name symbol mapping.
func VMStubNamesInClusterOrder(dartVersion string) []string {
	list := VMStubNames(dartVersion)
	if list == nil {
		return nil
	}
	return list
}

// composeVMStubEmissionOrder inserts the type-testing stubs after the
// subtype-test-cache group. If the anchor is missing -- a list shape this
// code has not seen -- the type-testing stubs are appended at the end rather
// than dropped, and the caller's count check will notice if that is wrong.
func composeVMStubEmissionOrder(list []string) []string {
	anchor := -1
	for i, n := range list {
		if n == subtypeTestCacheAnchor {
			anchor = i
			break
		}
	}
	out := make([]string, 0, len(list)+len(vmTypeTestingStubNames))
	if anchor < 0 {
		out = append(out, list...)
		return append(out, vmTypeTestingStubNames...)
	}
	out = append(out, list[:anchor+1]...)
	out = append(out, vmTypeTestingStubNames...)
	return append(out, list[anchor+1:]...)
}
