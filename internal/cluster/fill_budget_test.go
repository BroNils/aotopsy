package cluster

import (
	"strings"
	"testing"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

func TestReadFillRejectsCaptureAboveMaxBytesBeforeParsing(t *testing.T) {
	const arrayCID = 100
	profile := &snapshot.VersionProfile{CIDs: &snapshot.CIDTable{Array: arrayCID}}
	result := &Result{
		FillStart:     1,
		AllocComplete: true,
		Clusters: []ClusterMeta{{
			CID:      arrayCID,
			Count:    1,
			StartRef: 2,
			StopRef:  3,
			Lengths:  []int64{1_000_000},
		}},
	}
	err := ReadFill([]byte{0, 0x80}, result, profile, false, 0, dartfmt.Options{MaxBytes: 1024})
	if err == nil || !strings.Contains(err.Error(), "exceeds max_bytes") {
		t.Fatalf("ReadFill oversized capture error = %v, want max_bytes rejection", err)
	}
	// Budget rejection must happen before any decoded capture is retained.
	if len(result.Arrays) != 0 {
		t.Fatalf("budget rejection retained %d arrays", len(result.Arrays))
	}
}
