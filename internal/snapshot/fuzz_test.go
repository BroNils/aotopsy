package snapshot

import "testing"

// FuzzParseImageHeader asserts the image-header parser never panics on arbitrary
// input. AOTopsy ingests untrusted libapp.so bytes; a malformed header must
// return an error, not crash. Run: go test ./internal/snapshot/ -run '^$' -fuzz=FuzzParseImageHeader
func FuzzParseImageHeader(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic; error is an acceptable outcome.
		_, _ = ParseImageHeader(data)
	})
}

// FuzzParseInstructionsSection fuzzes both the payload and the offset — an
// attacker-controlled offset must never index out of bounds.
func FuzzParseInstructionsSection(f *testing.F) {
	f.Add([]byte{}, uint64(0))
	f.Add(make([]byte, 128), uint64(0))
	f.Add(make([]byte, 16), uint64(1<<40))
	f.Fuzz(func(t *testing.T, data []byte, offset uint64) {
		_, _ = ParseInstructionsSection(data, offset)
	})
}
