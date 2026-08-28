package decompiler

import "aotopsy/internal/sdk"

// Async stub role classification is now shared from internal/sdk.
// The SDK knowledge (stub name patterns from VM_STUB_CODE_LIST and
// CACHED_VM_STUBS_ADDRESSES_LIST) is in sdk.ClassifyStubRole.
//
// This file provides thin wrappers that map sdk.StubRole to the decompiler's
// local asyncRole type, so call.go and emit.go don't need to change.

type asyncRole int

const (
	asyncRoleNone   asyncRole = iota
	asyncRoleInit             // enters an async function
	asyncRoleAwait            // suspends at an await point
	asyncRoleReturn           // completes an async function
)

// asyncStubRole classifies a call target name. Returns asyncRoleNone for
// anything that is not one of the async stubs.
func asyncStubRole(name string) asyncRole {
	switch sdk.ClassifyStubRole(name) {
	case sdk.StubRoleAsyncInit:
		return asyncRoleInit
	case sdk.StubRoleAsyncAwait:
		return asyncRoleAwait
	case sdk.StubRoleAsyncReturn:
		return asyncRoleReturn
	default:
		return asyncRoleNone
	}
}

// isAsyncStubName reports whether a call to this name proves the caller is an
// async function, regardless of which of the three roles it plays.
func isAsyncStubName(name string) bool {
	return sdk.IsAsyncStubName(name)
}
