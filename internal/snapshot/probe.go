package snapshot

import "bytes"

// ProbeSnapshotMagic scans data for the Dart snapshot magic bytes (0xf5f5dcdc).
// Returns the byte offset of the first occurrence, or -1 if not found.
func ProbeSnapshotMagic(data []byte) int {
	return bytes.Index(data, snapshotMagic[:])
}
