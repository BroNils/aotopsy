package signal

import (
	"testing"

	"aotopsy/internal/sdk"
)

func TestClassifyURL(t *testing.T) {
	cats := ClassifyString("https://api.icloseli.com/oauth/accessToken")
	if !containsCat(cats, CatURL) {
		t.Errorf("expected url category, got %v", cats)
	}
	if !containsCat(cats, CatAuth) {
		t.Errorf("expected auth category for oauth/accessToken, got %v", cats)
	}
}

func TestClassifyCrypto(t *testing.T) {
	for _, s := range []string{
		"AES/CBC/PKCS7PADDING", "sha256", "HMAC-SHA1", "encrypt",
		"xor cipher", "XOR decrypt key", "encryptAndStoreSecretToken",
		"Ciphertext:", "Nonce must have 12 bytes",
		"PartnerVerify_CHMACSHA256", "SALT",
		"RSA", "rsa_public_key",
	} {
		cats := ClassifyString(s)
		if !containsCat(cats, CatEncryption) {
			t.Errorf("expected crypto category for %q, got %v", s, cats)
		}
	}
}

func TestClassifyCryptoFalsePositives(t *testing.T) {
	for _, s := range []string{
		"skipTraversal",
		"TraversalEdgeBehavior.",
		"FocusTraversalPolicy",
		"SliverSafeArea",
		"set:_indexOrNext@1026248",
		"get:descendantsAreTraversable",
	} {
		cats := ClassifyString(s)
		if containsCat(cats, CatEncryption) {
			t.Errorf("should NOT be crypto: %q, got %v", s, cats)
		}
	}
}

func TestClassifyAuth(t *testing.T) {
	for _, s := range []string{"password", "Bearer token", "jwt", "apikey", "Authorization"} {
		cats := ClassifyString(s)
		if !containsCat(cats, CatAuth) {
			t.Errorf("expected auth category for %q, got %v", s, cats)
		}
	}
}

func TestClassifyNet(t *testing.T) {
	cats := ClassifyString("GET")
	if !containsCat(cats, CatNet) {
		t.Errorf("expected net category for GET, got %v", cats)
	}
	cats = ClassifyString("socket connection")
	if !containsCat(cats, CatNet) {
		t.Errorf("expected net category for socket, got %v", cats)
	}
}

func TestClassifyFileExt(t *testing.T) {
	cats := ClassifyString("classes.dex")
	if !containsCat(cats, CatFileExt) {
		t.Errorf("expected file_ext for classes.dex, got %v", cats)
	}
	cats = ClassifyString("data.json")
	if !containsCat(cats, CatFileExt) {
		t.Errorf("expected file_ext for data.json, got %v", cats)
	}
}

func TestClassifyBase64Key(t *testing.T) {
	cats := ClassifyString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/==")
	if !containsCat(cats, CatBase64Key) {
		t.Errorf("expected base64_key, got %v", cats)
	}
}

func TestClassifyAuthFalsePositive(t *testing.T) {
	// Flutter framework camelCase identifiers should not trigger auth.
	for _, s := range []string{"brieflyShowPassword", "nativeSpellCheckServiceDefined", "platformBrightness"} {
		cats := ClassifyString(s)
		if containsCat(cats, CatAuth) {
			t.Errorf("should NOT be auth: %q, got %v", s, cats)
		}
	}
}

func TestClassifyMundane(t *testing.T) {
	// Normal runtime error strings should not be classified.
	cats := ClassifyString("Index out of range")
	if len(cats) != 0 {
		t.Errorf("expected no categories for mundane string, got %v", cats)
	}
}

func TestClassifyIP(t *testing.T) {
	cats := ClassifyString("192.168.1.1:8080")
	if !containsCat(cats, CatHost) {
		t.Errorf("expected host category for IP literal, got %v", cats)
	}
}

func TestClassifySIM(t *testing.T) {
	for _, s := range []string{"checkSimCard", "SIM card check failed:", "IMEI", "sim_operator"} {
		cats := ClassifyString(s)
		if !containsCat(cats, CatSIM) {
			t.Errorf("expected sim category for %q, got %v", s, cats)
		}
	}
	// "similar" should NOT trigger sim
	cats := ClassifyString("similar results")
	if containsCat(cats, CatSIM) {
		t.Errorf("'similar' should NOT be sim, got %v", cats)
	}
}

func TestClassifySMS(t *testing.T) {
	for _, s := range []string{`{"type": "sms", "description" : "SMS log"}`, "send_sms", "SmsManager"} {
		cats := ClassifyString(s)
		if !containsCat(cats, CatSMS) {
			t.Errorf("expected sms category for %q, got %v", s, cats)
		}
	}
}

func TestClassifyContacts(t *testing.T) {
	for _, s := range []string{"ContactAddressModel", "/customer/contactAddress?contractId=", "read_contacts", "call_log"} {
		cats := ClassifyString(s)
		if !containsCat(cats, CatContacts) {
			t.Errorf("expected contacts category for %q, got %v", s, cats)
		}
	}
}

func TestClassifyLocation(t *testing.T) {
	for _, s := range []string{
		"RequestCurrentLocation error",
		"geolocationEnabled",
		"geofence",
		"enableLocation",
		"IsEnableLocationService",
		"LocationException",
		"lastKnownLocation",
		"fusedLocationProvider",
		"GPS coordinates",
		"GeolocationPermissionsCallback",
		"[MobileDataCollector] RequestCurrentLocation error => ",
		"[MobileDataCollector] IsEnableLocationService error => ",
		"requestCurrentLocationSimple",
	} {
		cats := ClassifyString(s)
		if !containsCat(cats, CatLocation) {
			t.Errorf("expected location category for %q, got %v", s, cats)
		}
	}
	// Framework noise should NOT match.
	for _, s := range []string{
		"layout ( location = 0 ) out vec4 oColor;",
		"FloatingActionButtonLocation.endFloat",
		"get:localPosition",
		"TextPosition(offset: ",
		"ScrollPositionAlignmentPolicy.",
	} {
		cats := ClassifyString(s)
		if containsCat(cats, CatLocation) {
			t.Errorf("should NOT be location: %q, got %v", s, cats)
		}
	}
}

func TestClassifyDeviceInfo(t *testing.T) {
	for _, s := range []string{"Device ID", "getDeviceID", "device_id", "installReferrer", "installerStore"} {
		cats := ClassifyString(s)
		if !containsCat(cats, CatDeviceInfo) {
			t.Errorf("expected device category for %q, got %v", s, cats)
		}
	}
}

func TestClassifyCloaking(t *testing.T) {
	for _, s := range []string{
		"Keyword check failed: ",
		"Keyword mismatch: expected ",
		"checkKeywords",
		"is_allowed",
		"checkAndLaunchRedirect",
		"app_country",
	} {
		cats := ClassifyString(s)
		if !containsCat(cats, CatCloaking) {
			t.Errorf("expected cloaking category for %q, got %v", s, cats)
		}
	}
}

func TestClassifyDataCollect(t *testing.T) {
	for _, s := range []string{
		"[MobileDataCollector] SendAllMobileData",
		"StartMobileDataCollectionEvent",
		"Collect data fail",
	} {
		cats := ClassifyString(s)
		if !containsCat(cats, CatDataCollect) {
			t.Errorf("expected data category for %q, got %v", s, cats)
		}
	}
}

func TestClassifyCamera(t *testing.T) {
	for _, s := range []string{"camera_permission", "CAMERA_OPEN_FAILED", "getAvailableCameras"} {
		cats := ClassifyString(s)
		if !containsCat(cats, CatCamera) {
			t.Errorf("expected camera category for %q, got %v", s, cats)
		}
	}
}

func TestClassifyAttribution(t *testing.T) {
	for _, s := range []string{
		"utm_medium=organic",
		"utm_source=(not20%set)&utm_medium=(not20%set)",
		"getAdjustDeviceID",
		"install_referrer",
		"referrer data",
		"campaign_id=123",
		"AppsFlyer conversion",
		"adjustConfig params",
		"kochava tracker init",
	} {
		cats := ClassifyString(s)
		if !containsCat(cats, CatAttribution) {
			t.Errorf("expected attribution category for %q, got %v", s, cats)
		}
	}
	// False positives: generic words that happen to appear.
	for _, s := range []string{
		"callbackParameters",
		"partnerParameters",
		"flutter4.38.1",
		"addSessionCallbackParameter",
	} {
		cats := ClassifyString(s)
		if containsCat(cats, CatAttribution) {
			t.Errorf("should NOT be attribution: %q, got %v", s, cats)
		}
	}
}

func TestIsMundaneStub(t *testing.T) {
	mundane := []string{
		"AllocateArray_ep",
		"AllocateObject_ep",
		"write_barrier_entry_point",
		"store_buffer_ep",
		"type_test_stub",
		"subtype_check_ep",
		"call_to_runtime_ep",
	}
	for _, name := range mundane {
		if !sdk.IsMundaneStub(name) {
			t.Errorf("expected %q to be mundane", name)
		}
	}

	interesting := []string{
		"call_native_through_safepoint_ep",
		"active_exception_ep",
	}
	for _, name := range interesting {
		if sdk.IsMundaneStub(name) {
			t.Errorf("expected %q to NOT be mundane", name)
		}
	}
}

// TestThreadDataFieldsAreNotStubs pins the largest false-positive source
// the signal graph had.
//
// A call whose target came out of THR.dispatch_table_array is a virtual
// call, not a stub call. Counting it as an unrecognised stub marked every
// function that makes a virtual call as signal: 3371 such edges on one
// x86_64 sample, which took its "interesting THR call" count from 13 to
// 1374 -- 97% noise.
func TestThreadDataFieldsAreNotStubs(t *testing.T) {
	notStubs := []string{
		"dispatch_table_array",
		"isolate",
		"isolate_group",
		"object_null",
		"bool_true",
		"field_table_values",
		// Leaf runtime entries the compiler emits, not app behaviour.
		"LibcPow_entry_point",
		"LibcRound_entry_point",
		"DartModulo_entry_point",
		"MemoryMove_entry_point",
		// GC bookkeeping, spelled CamelCase upstream so the
		// underscore-separated patterns missed it.
		"StoreBufferBlockProcess_entry_point",
		"OldMarkingStackBlockProcess_entry_point",
		"NewMarkingStackBlockProcess_entry_point",
		"EnsureRememberedAndMarkingDeferred_entry_point",
		"wb_wrapper_R3",
	}
	for _, name := range notStubs {
		if !sdk.IsMundaneStub(name) {
			t.Errorf("%q should carry no signal: it is VM bookkeeping or a Thread data field, "+
				"not a call into app behaviour", name)
		}
	}
}

// TestGeneratorSuspendStubsAreAsync: generators suspend through the same
// machinery as async functions. Keying only on "async" left the sync_star
// stubs classified as unrecognised, reporting them as a gap in our tables
// when they are the strongest evidence a function is a generator.
func TestGeneratorSuspendStubsAreAsync(t *testing.T) {
	for _, name := range []string{
		"suspend_state_init_sync_star_entry_point",
		"suspend_state_suspend_sync_star_at_start_entry_point",
		"suspend_state_return_sync_star_entry_point",
		"suspend_state_init_async_entry_point",
		"suspend_state_await_entry_point",
	} {
		if !sdk.IsAsyncStubName(name) {
			t.Errorf("IsAsyncStubName(%q) = false; suspension is what these stubs are for", name)
		}
	}
}
