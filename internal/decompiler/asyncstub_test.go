package decompiler

import "testing"

// Every name below is real. The snake_case ones are Thread stub slots,
// verified against dart-lang/sdk `runtime/vm/compiler/runtime_offsets_list.h`
// at tag 3.9.2; the camelCase ones are VM_STUB_CODE_LIST entries from
// `runtime/vm/stub_code_list.h` at the same tag.
func TestAsyncStubRoleMatchesRealStubNames(t *testing.T) {
	cases := []struct {
		name string
		want asyncRole
	}{
		// Thread stub slots -- these are what the THR sentinel path sees.
		{"suspend_state_init_async_entry_point", asyncRoleInit},
		{"suspend_state_init_async_star_entry_point", asyncRoleInit},
		{"suspend_state_await_entry_point", asyncRoleAwait},
		{"suspend_state_await_with_type_check_entry_point", asyncRoleAwait},
		{"suspend_state_return_async_entry_point", asyncRoleReturn},
		{"suspend_state_return_async_not_future_entry_point", asyncRoleReturn},
		{"suspend_state_return_async_star_entry_point", asyncRoleReturn},
		{"return_async_stub", asyncRoleReturn},
		{"return_async_star_stub", asyncRoleReturn},
		{"return_async_not_future_stub", asyncRoleReturn},
		// Dart-side symbol spellings.
		{"InitAsyncStub", asyncRoleInit},
		{"_SuspendState._initAsync", asyncRoleInit},
		{"ReturnAsyncStub", asyncRoleReturn},
		{"_SuspendState._returnAsync", asyncRoleReturn},
	}
	for _, tc := range cases {
		if got := asyncStubRole(tc.name); got != tc.want {
			t.Errorf("asyncStubRole(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The rewrite this replaces used `HasSuffix(name, "initasync")`, which
// matches none of the names above -- every real one has an underscore between
// the words. It removed the true positives along with the false ones, and no
// test noticed. This is that test.
func TestAsyncStubRoleDoesNotSilentlyMatchNothing(t *testing.T) {
	realNames := []string{
		"suspend_state_init_async_entry_point",
		"suspend_state_return_async_entry_point",
		"return_async_stub",
	}
	for _, n := range realNames {
		if asyncStubRole(n) == asyncRoleNone {
			t.Fatalf("%q classified as not-async; async detection is dead again", n)
		}
	}
}

// The false positives that prompted the rewrite must stay excluded. Segments
// alone are not enough for the third case -- `init_async_helper` does contain
// the segment pair -- which is why a VM stub terminator is also required.
func TestAsyncStubRoleRejectsLookalikes(t *testing.T) {
	for _, n := range []string{
		"reinit_async_data",                        // "reinit" is one segment, not "re"+"init"
		"init_async_helper",                        // right segments, but not a stub slot name
		"my_return_async_helper",                   // ditto
		"async_stack_trace",                        // a Thread field, but data not a stub
		"Duration.compareTo",                       // ordinary Dart method
		"suspend_state_init_sync_star_entry_point", // sync*, not async
		"",
	} {
		if got := asyncStubRole(n); got != asyncRoleNone {
			t.Errorf("asyncStubRole(%q) = %v, want asyncRoleNone", n, got)
		}
	}
}

// isAsyncStubName is what emit.go's pre-pass uses: any role proves the caller
// is async.
func TestIsAsyncStubName(t *testing.T) {
	if !isAsyncStubName("suspend_state_await_entry_point") {
		t.Error("await stub must prove the caller is async")
	}
	if isAsyncStubName("reinit_async_data") {
		t.Error("lookalike must not prove anything")
	}
}
