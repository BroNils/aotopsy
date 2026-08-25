package cluster

import "testing"

// FuzzDecodeCodeSourceMap asserts the CodeSourceMap bytecode interpreter never
// panics on arbitrary payloads. It runs a little stack machine over untrusted
// bytes, so a malformed program must terminate with an error, not crash or hang.
// Run: go test ./internal/cluster/ -run '^$' -fuzz=FuzzDecodeCodeSourceMap
func FuzzDecodeCodeSourceMap(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = DecodeCodeSourceMap(payload)
	})
}

// FuzzDecodePcDescriptors asserts the Pc-descriptors decoder never panics on
// arbitrary payloads (varint-encoded, attacker-controlled lengths).
func FuzzDecodePcDescriptors(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x80})
	f.Add([]byte{0x7f, 0x7f, 0x7f})
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = DecodePcDescriptors(payload)
	})
}
