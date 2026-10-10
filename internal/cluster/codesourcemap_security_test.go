package cluster

import "testing"

func encodeCSMTestOp(op uint8, arg int32) []byte {
	v := int32(arg)<<3 | int32(op)
	var out []byte
	for {
		low := v & 0x7f
		rest := v >> 7
		if (rest == 0 && low < 64) || (rest == -1 && low >= 64) {
			out = append(out, byte(192+int(int8(low<<1)>>1)))
			return out
		}
		out = append(out, byte(low))
		v = rest
	}
}

func TestCodeSourceMapEntriesShareUnchangedPersistentStack(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeCSMTestOp(CSMPushFunction, 7)...)
	payload = append(payload, encodeCSMTestOp(CSMAdvancePC, 1)...)
	payload = append(payload, encodeCSMTestOp(CSMAdvancePC, 1)...)

	entries, err := DecodeCodeSourceMap(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if entries[0].inlineStack == nil || entries[0].inlineStack != entries[1].inlineStack {
		t.Fatal("unchanged inline stack was copied instead of shared persistently")
	}
	stack := entries[1].InlineStack()
	if len(stack) != 1 || stack[0] != 7 {
		t.Fatalf("materialized inline stack = %v, want [7]", stack)
	}
}

func TestCodeSourceMapRejectsNegativeInlineID(t *testing.T) {
	payload := encodeCSMTestOp(CSMPushFunction, -1)
	if _, err := DecodeCodeSourceMap(payload); err == nil {
		t.Fatal("negative inline function id was accepted")
	}
}
