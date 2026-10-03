package sdk

import (
	"strings"

	"aotopsy/internal/snapshot"
)

// ── Stub role classification ──────────────────────────────────────────
//
// Source: runtime/vm/stub_code_list.h VM_STUB_CODE_LIST,
// runtime/vm/thread.h CACHED_VM_STUBS_ADDRESSES_LIST.
//
// Dart AOT stubs are identified by name patterns. Two different namespaces
// reach the classifier:
//
//  1. VM stub slots from the Thread field table (snake_case):
//     suspend_state_init_async_entry_point, return_async_stub, etc.
//  2. Dart-side symbols from the snapshot (camelCase):
//     _SuspendState._initAsync, InitAsyncStub, etc.
//
// A unified classifier lets the decompiler, signal, and disasm packages all
// agree on what a stub does, instead of each independently classifying by
// substring.

// StubRole classifies what kind of VM stub a name represents.
type StubRole int

const (
	StubRoleNone            StubRole = iota // not a recognized stub
	StubRoleAsyncInit                       // enters an async function
	StubRoleAsyncAwait                      // suspends at an await point
	StubRoleAsyncReturn                     // completes an async function
	StubRoleAsyncStarInit                   // enters an async* generator
	StubRoleAsyncStarYield                  // suspends an async* generator at yield/yield*
	StubRoleAsyncStarReturn                 // completes an async* generator
	StubRoleSyncStarInit                    // enters a sync* generator
	StubRoleSyncStarSuspend                 // suspends a sync* generator at start/yield
	StubRoleSyncStarReturn                  // completes a legacy sync* generator
	StubRoleSuspendResume                   // resumes a suspendable function; kind-neutral
	StubRoleAllocate                        // allocation stub (AllocateObject, etc.)
	StubRoleWriteBarrier                    // write barrier stub
	StubRoleStackOverflow                   // stack overflow check stub
	StubRoleTypeTest                        // type test / subtype check stub
	StubRoleSafepoint                       // safepoint / deoptimization stub
	StubRoleRuntime                         // call_to_runtime / other runtime stub
	StubRoleError                           // null_error / range_error / etc.
)

// vmStubTerminators are how a Thread-table stub slot name ends. Requiring one
// is what separates a real stub from an ordinary function whose name happens
// to contain the same words.
var vmStubTerminators = []string{"_entry_point", "_stub"}

// LooksLikeVMStubName reports whether name ends with a VM stub terminator
// (_entry_point or _stub), distinguishing real stubs from ordinary functions
// that happen to contain the same words.
func LooksLikeVMStubName(name string) bool {
	for _, suffix := range vmStubTerminators {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// HasSegmentPair reports whether name, split on '_', contains a and b as
// consecutive whole segments. `reinit_async_data` has segments
// [reinit async data], so it does NOT contain the pair (init, async) --
// which a substring match cannot tell.
func HasSegmentPair(name, a, b string) bool {
	segs := strings.Split(name, "_")
	for i := 0; i+1 < len(segs); i++ {
		if segs[i] == a && segs[i+1] == b {
			return true
		}
	}
	return false
}

// ClassifyStubRole classifies a call target or THR stub name into its role for
// an exact Dart version. Suspendable-function roles are versioned because the
// compact SuspendStubABI and its stub vocabulary do not exist before 2.18.0.
func ClassifyStubRole(dartVersion, name string) StubRole {
	if !isSupportedDartVersion(dartVersion) {
		return StubRoleNone
	}
	// Dart-side helpers and named stubs use a finite SDK vocabulary. Match the
	// terminal symbol exactly rather than looking for an async substring: an app
	// function named MyInitAsyncCache is ordinary user code, not a VM stub.
	leaf := name
	if i := strings.LastIndex(leaf, "::"); i >= 0 {
		leaf = leaf[i+2:]
	}
	if i := strings.LastIndexByte(leaf, '.'); i >= 0 {
		leaf = leaf[i+1:]
	}
	leaf = strings.TrimSuffix(leaf, "Stub")
	if role, ok := classifySuspendableLeaf(dartVersion, leaf); ok {
		return role
	}

	// VM stub slots require a terminator.
	if !LooksLikeVMStubName(name) {
		// Fall through to mundane-pattern classification for non-stub-terminated names.
		return classifyMundanePattern(name)
	}

	if isSupportedDartVersion(dartVersion) && snapshot.VersionAtLeast(dartVersion, "2.18.0") {
		// Thread-slot spellings. These names come from the exact Thread table, so
		// broad segment matching is acceptable only after the version proves the
		// SuspendStubABI exists.
		switch {
		case HasSegmentPair(name, "state", "await") || HasSegmentPair(name, "suspend", "await"):
			return StubRoleAsyncAwait
		case HasSegmentPair(name, "yield", "async"):
			return StubRoleAsyncStarYield
		case HasSegmentPair(name, "init", "async") && strings.Contains(name, "async_star"):
			return StubRoleAsyncStarInit
		case HasSegmentPair(name, "return", "async") && strings.Contains(name, "async_star"):
			return StubRoleAsyncStarReturn
		case HasSegmentPair(name, "init", "async"):
			return StubRoleAsyncInit
		case HasSegmentPair(name, "return", "async"):
			return StubRoleAsyncReturn
		case HasSegmentPair(name, "init", "sync"), HasSegmentPair(name, "init", "syncstar"):
			return StubRoleSyncStarInit
		case HasSegmentPair(name, "suspend", "sync"), HasSegmentPair(name, "yield", "sync"):
			return StubRoleSyncStarSuspend
		case HasSegmentPair(name, "return", "sync"):
			return StubRoleSyncStarReturn
		case name == "resume_stub":
			return StubRoleSuspendResume
		}
	}

	// Other VM stub roles.
	return classifyMundanePattern(name)
}

func classifySuspendableLeaf(dartVersion, leaf string) (StubRole, bool) {
	if !isSupportedDartVersion(dartVersion) || !snapshot.VersionAtLeast(dartVersion, "2.18.0") {
		return StubRoleNone, false
	}
	switch leaf {
	case "InitAsync", "_initAsync":
		return StubRoleAsyncInit, true
	case "Await", "_await":
		return StubRoleAsyncAwait, true
	case "AwaitWithTypeCheck", "_awaitWithTypeCheck":
		if snapshot.VersionAtLeast(dartVersion, "3.0.5") {
			return StubRoleAsyncAwait, true
		}
	case "ReturnAsync", "ReturnAsyncNotFuture", "_returnAsync", "_returnAsyncNotFuture":
		return StubRoleAsyncReturn, true
	case "InitAsyncStar", "_initAsyncStar":
		return StubRoleAsyncStarInit, true
	case "YieldAsyncStar", "_yieldAsyncStar":
		return StubRoleAsyncStarYield, true
	case "ReturnAsyncStar", "_returnAsyncStar":
		return StubRoleAsyncStarReturn, true
	case "InitSyncStar", "_initSyncStar":
		return StubRoleSyncStarInit, true
	case "YieldSyncStar", "_yieldSyncStar":
		if dartVersion == "2.18.0" {
			return StubRoleSyncStarSuspend, true
		}
	case "SuspendSyncStarAtStart", "SuspendSyncStarAtYield", "_suspendSyncStarAtStart", "_suspendSyncStarAtYield":
		if snapshot.VersionAtLeast(dartVersion, "2.19.0") {
			return StubRoleSyncStarSuspend, true
		}
	case "ReturnSyncStar", "_returnSyncStar":
		if dartVersion == "2.18.0" {
			return StubRoleSyncStarReturn, true
		}
	case "Resume", "_resume":
		return StubRoleSuspendResume, true
	}
	return StubRoleNone, false
}

// classifyMundanePattern classifies names by the same patterns signal's
// IsMundaneTHR used, but returns a structured role instead of a boolean.
func classifyMundanePattern(name string) StubRole {
	lower := strings.ToLower(name)
	// Thread fields that are DATA, not stubs. A call whose target came
	// out of one of these is not a stub call at all, and treating it as
	// an unrecognised stub made every virtual call look like a signal:
	// 3371 dispatch_table_array edges on a single x86_64 sample, which is
	// simply "this function makes a virtual call".
	switch lower {
	case "dispatch_table_array", "isolate", "isolate_group",
		"object_null", "bool_true", "bool_false",
		"predefined_symbols_address", "field_table_values":
		return StubRoleRuntime
	}

	patterns := []struct {
		pattern string
		role    StubRole
	}{
		// Leaf runtime entries: libc math, memory-move, sanitizer hooks.
		// They are runtime calls the compiler emits, not app behaviour.
		{"libc", StubRoleRuntime},
		{"dartmodulo", StubRoleRuntime},
		{"memorymove", StubRoleRuntime},
		{"ensureremembered", StubRoleWriteBarrier},
		{"wb_wrapper", StubRoleWriteBarrier},
		// GC bookkeeping. The underscore-separated patterns below miss
		// these because the SDK spells them in CamelCase:
		// StoreBufferBlockProcess, OldMarkingStackBlockProcess.
		{"storebuffer", StubRoleWriteBarrier},
		{"markingstack", StubRoleWriteBarrier},
		{"allocate", StubRoleAllocate},
		{"write_barrier", StubRoleWriteBarrier},
		{"store_buffer", StubRoleWriteBarrier},
		{"type_test", StubRoleTypeTest},
		{"subtype_check", StubRoleTypeTest},
		{"call_to_runtime", StubRoleRuntime},
		{"stack_overflow", StubRoleStackOverflow},
		{"null_error", StubRoleError},
		{"range_error", StubRoleError},
		{"error_", StubRoleError},
		{"deoptimize", StubRoleSafepoint},
		{"megamorphic_call", StubRoleSafepoint},
		{"switchable_call", StubRoleSafepoint},
		{"monomorphic_", StubRoleSafepoint},
		{"lazy_deopt", StubRoleSafepoint},
		{"safepoint", StubRoleSafepoint},
	}
	for _, p := range patterns {
		if strings.Contains(lower, p.pattern) {
			// Exception: call_native_through_safepoint_ep is interesting (FFI/JNI).
			if strings.Contains(lower, "native") {
				return StubRoleNone
			}
			return p.role
		}
	}
	return StubRoleNone
}

// IsAsyncStubName reports whether a call to this name proves the caller is an
// async or async* function. sync* and the kind-neutral Resume stub deliberately
// return false: both use the same suspension machinery but are not async Dart
// functions.
func IsAsyncStubName(dartVersion, name string) bool {
	role := ClassifyStubRole(dartVersion, name)
	switch role {
	case StubRoleAsyncInit, StubRoleAsyncAwait, StubRoleAsyncReturn,
		StubRoleAsyncStarInit, StubRoleAsyncStarYield, StubRoleAsyncStarReturn:
		return true
	default:
		return false
	}
}

// IsMundaneStub reports whether a stub name represents compiler bookkeeping
// (allocation, write barrier, stack overflow, type test, deoptimization, etc.)
// that carries no source-level meaning. This is the shared replacement for
// signal.IsMundaneTHR.
func IsMundaneStub(dartVersion, name string) bool {
	role := ClassifyStubRole(dartVersion, name)
	switch role {
	case StubRoleAllocate, StubRoleWriteBarrier, StubRoleStackOverflow,
		StubRoleTypeTest, StubRoleSafepoint, StubRoleRuntime, StubRoleError,
		StubRoleSuspendResume:
		return true
	default:
		return false
	}
}
