package evidence

import (
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
	"aotopsy/internal/snapshot"
)

// TestEvidenceSDKReferencesMatchExactSDK verifies every SDK source family that
// evidence.jsonl can cite. The test is opt-in because it walks all supported
// exact Dart releases; SDKFileAtTag prefers the per-version local working trees.
// THR-derived evidence intentionally carries no sdk_ref: its names can be
// reconstructed from runtime_entry_list.h plus header anchors, so pretending
// every name is a literal runtime_offsets_extracted.h symbol would be false.
func TestEvidenceSDKReferencesMatchExactSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	const (
		arm64File = "runtime/vm/compiler/backend/flow_graph_compiler_arm64.cc"
		x64File   = "runtime/vm/compiler/backend/flow_graph_compiler_x64.cc"
	)

	versions := snapshot.SupportedVersions()
	if len(versions) == 0 {
		t.Fatal("snapshot.SupportedVersions() is empty")
	}
	for _, version := range versions {
		for _, file := range []string{arm64File, x64File} {
			src, err := sdktest.SDKFileAtTag(file, version)
			if err != nil {
				t.Fatalf("read %s@%s: %v", file, version, err)
			}
			if !strings.Contains(src, "FlowGraphCompiler::EmitDispatchTableCall(") {
				t.Errorf("%s@%s has no FlowGraphCompiler::EmitDispatchTableCall", file, version)
			}
		}
	}
}
