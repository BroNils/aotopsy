package snapshot

import "testing"

func TestInfoPrimaryHeaderUsesUnifiedHeader(t *testing.T) {
	h := &Header{SnapshotHash: "unified-hash", TotalSize: 123}
	i := &Info{UnifiedSnapshot: true, IsolateHeader: h}
	if got := i.PrimaryHeader(); got != h {
		t.Fatalf("PrimaryHeader=%p, want isolate/unified %p", got, h)
	}
	if got := i.SnapshotHash(); got != "unified-hash" {
		t.Fatalf("SnapshotHash=%q", got)
	}
}

func TestInfoPrimaryHeaderPrefersLegacyVM(t *testing.T) {
	vm := &Header{SnapshotHash: "vm"}
	iso := &Header{SnapshotHash: "iso"}
	i := &Info{VmHeader: vm, IsolateHeader: iso}
	if got := i.PrimaryHeader(); got != vm {
		t.Fatalf("PrimaryHeader=%p, want VM %p", got, vm)
	}
}
