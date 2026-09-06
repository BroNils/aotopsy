package naming

import "testing"

// TestTypeTestingStubNameDerivesFromBareName pins the split that made the type
// names usable.
//
// buildTypeNames computes a Type's Dart-source name, type arguments and all,
// and used to bake `TypeTestingStub_` into it on the spot. That made the name
// unusable for the thing a Type in the object pool actually is -- a type -- so
// 517 pool entries per binary rendered as the bare placeholder `<Type>` while
// their name sat computed and discarded one map away.
func TestTypeTestingStubNameDerivesFromBareName(t *testing.T) {
	names := map[int]string{
		1: "RenderBox",
		2: "List<int>",
	}
	for ref, want := range map[int]string{
		1: "TypeTestingStub_RenderBox",
		2: "TypeTestingStub_List<int>",
	} {
		if got := TypeTestingStubName(names, ref); got != want {
			t.Errorf("ref %d: got %q, want %q", ref, got, want)
		}
	}
	// A type that could not be named yields nothing rather than a bare prefix:
	// `TypeTestingStub_` alone would be a label that looks like a name.
	if got := TypeTestingStubName(names, 99); got != "" {
		t.Errorf("unnamed type produced %q, want empty", got)
	}
	if got := TypeTestingStubName(nil, 1); got != "" {
		t.Errorf("nil map produced %q, want empty", got)
	}
}
