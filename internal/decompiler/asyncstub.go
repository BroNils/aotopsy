package decompiler

import "strings"

// Recognising the async/await stubs by name.
//
// Two different namespaces reach this, and they spell the same stub
// differently, which is why one shared classifier exists instead of a
// `strings.Contains` at each call site:
//
//	VM stub slots, from the Thread field table (snake_case):
//	  suspend_state_init_async_entry_point
//	  suspend_state_init_async_star_entry_point
//	  suspend_state_await_entry_point
//	  suspend_state_await_with_type_check_entry_point
//	  suspend_state_return_async_entry_point
//	  suspend_state_return_async_not_future_entry_point
//	  return_async_stub / return_async_star_stub / return_async_not_future_stub
//
//	Dart-side symbols, from the snapshot (camelCase):
//	  _SuspendState._initAsync, _SuspendState._returnAsync, InitAsyncStub
//
// A bare `strings.Contains(name, "init_async")` matched every real name but
// also `reinit_async_data`, which is what prompted a rewrite to
// `HasSuffix(name, "initasync")`. That rewrite matched **nothing at all** --
// every real name has an underscore between the words -- so it removed the
// true positives along with the false ones, silently. Both spellings and the
// exclusions below are pinned by tests.
//
// The snake_case rule is segment-aware AND requires the name to end the way a
// VM stub slot ends (`_entry_point` or `_stub`). Segments alone would still
// admit `init_async_helper`; the terminator requirement is what excludes it.
// The camelCase forms already carry their own boundary (a capital or a
// leading underscore), so they need no extra guard.

type asyncRole int

const (
	asyncRoleNone   asyncRole = iota
	asyncRoleInit             // enters an async function
	asyncRoleAwait            // suspends at an await point
	asyncRoleReturn           // completes an async function
)

// NOT handled, deliberately: the camelCase await spellings `Await` /
// `AwaitWithTypeCheck` from VM_STUB_CODE_LIST (stub_code_list.h @3.9.2,
// verified). They reach this only as ELF symbol names like
// `_iso_stub_AwaitStub`, which exist solely on builds that kept a symbol
// table, and the code being replaced here did not match them either
// (`Contains(name,"await") && Contains(name,"suspend")` -- no "suspend" in
// that spelling). Adding them would change output rather than preserve it,
// so it is recorded instead of smuggled into a bug fix.

// vmStubTerminators are how a Thread-table stub slot name ends. Requiring one
// is what separates a real stub from an ordinary function whose name happens
// to contain the same words.
var vmStubTerminators = []string{"_entry_point", "_stub"}

func looksLikeVMStubName(name string) bool {
	for _, suffix := range vmStubTerminators {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// hasSegmentPair reports whether name, split on '_', contains a and b as
// consecutive whole segments. `reinit_async_data` has segments
// [reinit async data], so it does NOT contain the pair (init, async) --
// which a substring match cannot tell.
func hasSegmentPair(name, a, b string) bool {
	segs := strings.Split(name, "_")
	for i := 0; i+1 < len(segs); i++ {
		if segs[i] == a && segs[i+1] == b {
			return true
		}
	}
	return false
}

// asyncStubRole classifies a call target name. Returns asyncRoleNone for
// anything that is not one of the async stubs.
func asyncStubRole(name string) asyncRole {
	// Dart-side symbols first: these carry their own word boundary.
	switch {
	case strings.Contains(name, "InitAsync") || strings.Contains(name, "_initAsync"):
		return asyncRoleInit
	case strings.Contains(name, "ReturnAsync") || strings.Contains(name, "_returnAsync"):
		return asyncRoleReturn
	}

	// VM stub slots. `await` is checked first because
	// suspend_state_await_entry_point contains neither init nor return.
	if !looksLikeVMStubName(name) {
		return asyncRoleNone
	}
	switch {
	case hasSegmentPair(name, "state", "await") || hasSegmentPair(name, "suspend", "await"):
		return asyncRoleAwait
	case hasSegmentPair(name, "init", "async"):
		return asyncRoleInit
	case hasSegmentPair(name, "return", "async"):
		return asyncRoleReturn
	}
	return asyncRoleNone
}

// isAsyncStubName reports whether a call to this name proves the caller is an
// async function, regardless of which of the three roles it plays.
func isAsyncStubName(name string) bool { return asyncStubRole(name) != asyncRoleNone }
