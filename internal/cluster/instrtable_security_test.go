package cluster

import (
	"math"
	"testing"

	"aotopsy/internal/snapshot"
)

func TestParseInstructionsTableRejectsOffsetOverflow(t *testing.T) {
	profile := &snapshot.VersionProfile{DartVersion: "3.12.2"}
	hdr := &Header{InstructionTableDataOffset: math.MaxInt64}
	isoHeader := &snapshot.Header{TotalSize: 64}
	if _, err := ParseInstructionsTable(make([]byte, 128), hdr, profile, isoHeader); err == nil {
		t.Fatal("instruction table accepted overflowing data-image-relative offset")
	}
}

func TestParseInstructionsTableRejectsRoundUpOverflow(t *testing.T) {
	profile := &snapshot.VersionProfile{DartVersion: "3.12.2"}
	hdr := &Header{InstructionTableDataOffset: 1}
	isoHeader := &snapshot.Header{TotalSize: math.MaxInt64}
	if _, err := ParseInstructionsTable(make([]byte, 128), hdr, profile, isoHeader); err == nil {
		t.Fatal("instruction table accepted overflowing rounded data-image start")
	}
}
