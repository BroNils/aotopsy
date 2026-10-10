package sdk

import (
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
	"aotopsy/internal/snapshot"
)

// TestSuspendableStubRolesMatchSDK derives the suspendable-stub vocabulary
// from VM_STUB_CODE_LIST at every supported exact release. Presence is part of
// the fact: a name that exists in a neighboring SDK must not be projected into
// this one merely because its spelling is plausible.
func TestSuspendableStubRolesMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	wantRole := map[string]StubRole{
		"Await":                  StubRoleAsyncAwait,
		"AwaitWithTypeCheck":     StubRoleAsyncAwait,
		"InitAsync":              StubRoleAsyncInit,
		"Resume":                 StubRoleSuspendResume,
		"ReturnAsync":            StubRoleAsyncReturn,
		"ReturnAsyncNotFuture":   StubRoleAsyncReturn,
		"InitAsyncStar":          StubRoleAsyncStarInit,
		"YieldAsyncStar":         StubRoleAsyncStarYield,
		"ReturnAsyncStar":        StubRoleAsyncStarReturn,
		"InitSyncStar":           StubRoleSyncStarInit,
		"YieldSyncStar":          StubRoleSyncStarSuspend,
		"ReturnSyncStar":         StubRoleSyncStarReturn,
		"SuspendSyncStarAtStart": StubRoleSyncStarSuspend,
		"SuspendSyncStarAtYield": StubRoleSyncStarSuspend,
	}

	for _, version := range snapshot.SupportedVersions() {
		version := version
		t.Run(version, func(t *testing.T) {
			src, err := sdktest.SDKFileAtTag("runtime/vm/stub_code_list.h", version)
			if err != nil {
				t.Fatal(err)
			}
			for name, role := range wantRole {
				sdkHas := strings.Contains(src, "V("+name+")")
				got := ClassifyStubRole(version, name+"Stub")
				oursHas := got != StubRoleNone
				if oursHas != sdkHas {
					t.Errorf("%s presence: SDK=%v classifier=%v role=%v", name, sdkHas, oursHas, got)
					continue
				}
				if sdkHas && got != role {
					t.Errorf("%s role=%v, want %v", name, got, role)
				}
			}

			// The named suspendable VM stubs and SuspendStubABI appeared together
			// in 2.18. A source-list match without the ABI (or vice versa) would be
			// a partially modeled transition.
			_, abiOK := SuspendStubRegs(version, ArchARM64)
			hasAwaitStub := strings.Contains(src, "V(Await)")
			if abiOK != hasAwaitStub {
				t.Errorf("SuspendStubABI presence=%v but VM_STUB_CODE_LIST Await presence=%v", abiOK, hasAwaitStub)
			}
		})
	}
}

func TestStubClassifierRejectsUnsupportedVersion(t *testing.T) {
	for _, name := range []string{"AwaitStub", "stack_overflow_stub", "AllocateObjectStub"} {
		if got := ClassifyStubRole("3.99.0", name); got != StubRoleNone {
			t.Errorf("unsupported version classified %q as %v", name, got)
		}
	}
}
