package cluster

import "testing"

func TestClassifyFfiTrampolineDirectionVersionBoundary(t *testing.T) {
	legacyOutbound := FfiTrampolineInfo{CallbackTargetRef: RefNull}
	legacyCallback := FfiTrampolineInfo{CallbackTargetRef: 77}

	if got := ClassifyFfiTrampolineDirection("3.2.5", legacyOutbound); got != FfiDirectionOutbound {
		t.Fatalf("3.2.5 null callback_target direction = %q, want outbound", got)
	}
	if got := ClassifyFfiTrampolineDirection("3.2.5", legacyCallback); got != FfiDirectionCallback {
		t.Fatalf("3.2.5 non-null callback_target direction = %q, want callback", got)
	}

	// From 3.3 the Function kind itself is callback-only; a malformed null target
	// must not resurrect the old outbound interpretation.
	if got := ClassifyFfiTrampolineDirection("3.3.0", legacyOutbound); got != FfiDirectionCallback {
		t.Fatalf("3.3.0 null callback_target direction = %q, want callback", got)
	}
	if got := ClassifyFfiTrampolineDirection("3.13.0", legacyOutbound); got != FfiDirectionCallback {
		t.Fatalf("3.13.0 null callback_target direction = %q, want callback", got)
	}

	for _, version := range []string{"", "3.99.0", "4.0.0"} {
		if got := ClassifyFfiTrampolineDirection(version, legacyCallback); got != FfiDirectionUnknown {
			t.Errorf("unsupported %q direction = %q, want unknown", version, got)
		}
	}
}
