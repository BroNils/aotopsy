package analysis

import (
	"os"
	"testing"

	"aotopsy/internal/cluster"
)

// TestCodeSourceMapDecoded checks CodeSourceMap capture and decoding on a real
// snapshot.
//
// What a CodeSourceMap gives is PC -> (inlined function stack, raw token
// position). It does NOT give PC -> file:line by itself: a TokenPosition is a
// source offset, and mapping it to a line needs Script.line_starts, which AOT
// normally drops. So this asserts the inlining information -- which is real and
// not obtainable any other way -- and treats token positions as opaque.
func TestCodeSourceMapDecoded(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_ARM64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_ARM64 not set")
	}
	res := clusterOnly(t, libPath)

	if len(res.CodeSourceMaps) == 0 {
		t.Skip("no CodeSourceMap objects in this snapshot (AOT may drop them; " +
			"absence is not a parse failure)")
	}

	var totalEntries, withInline, maxDepth, withPos int
	var maxPC uint32
	for _, csm := range res.CodeSourceMaps {
		for _, e := range csm.Entries {
			totalEntries++
			if len(e.InlineStack) > 0 {
				withInline++
				if len(e.InlineStack) > maxDepth {
					maxDepth = len(e.InlineStack)
				}
			}
			if e.TokenPos != cluster.CSMNoPosition {
				withPos++
			}
			if e.PCOffset > maxPC {
				maxPC = e.PCOffset
			}
			// Inline stack entries index Code.inlined_id_to_function, so they
			// must be non-negative.
			for _, id := range e.InlineStack {
				if id < 0 {
					t.Fatalf("negative inline function id %d; ArgField sign "+
						"extension is likely wrong", id)
				}
			}
		}
	}

	t.Logf("objects=%d entries=%d with_inline=%d max_inline_depth=%d with_token_pos=%d max_pc=0x%x",
		len(res.CodeSourceMaps), totalEntries, withInline, maxDepth, withPos, maxPC)

	if totalEntries == 0 {
		t.Fatal("CodeSourceMap objects found but every stream decoded to no entries; " +
			"AdvancePC is what emits entries, so the op decode is likely wrong")
	}
	// A desynced stream shows up immediately as absurd PCs, since PC only ever
	// advances by AdvancePC deltas.
	if maxPC > 1<<22 {
		t.Errorf("max pc_offset 0x%x is implausible for a single function; the "+
			"op/arg split is probably wrong", maxPC)
	}
	// Flutter inlines heavily; some PC must sit inside an inlined frame.
	if withInline == 0 {
		t.Error("no PC has a non-empty inline stack, which is implausible for a " +
			"Flutter app -- PushFunction/PopFunction handling is suspect")
	}
	// Sanity: inlining nests, but not absurdly.
	if maxDepth > 64 {
		t.Errorf("max inline depth %d is implausible; PopFunction may not be firing", maxDepth)
	}

	// InlineStackAt must agree with a linear scan.
	csm := &res.CodeSourceMaps[0]
	if len(csm.Entries) > 1 {
		target := csm.Entries[1].PCOffset
		stack, _, ok := csm.InlineStackAt(target)
		if !ok {
			t.Errorf("InlineStackAt(0x%x) found nothing despite an entry there", target)
		} else if len(stack) != len(csm.Entries[1].InlineStack) {
			t.Errorf("InlineStackAt depth %d != entry depth %d",
				len(stack), len(csm.Entries[1].InlineStack))
		}
		// A PC before the first entry has no state.
		if first := csm.Entries[0].PCOffset; first > 0 {
			if _, _, ok := csm.InlineStackAt(first - 1); ok {
				t.Error("InlineStackAt resolved a PC before the first entry")
			}
		}
	}
}

// TestDecodeCodeSourceMapOps unit-tests the bytecode against hand-built streams.
// The op/arg packing (op in the low 3 bits, arg sign-extended above) and the
// rule that only AdvancePC emits an entry are what these pin down.
func TestDecodeCodeSourceMapOps(t *testing.T) {
	// pack builds one op word the way CodeSourceMapOps::Write does, using
	// Dart's MARKER varint (BaseWriteStream::Write<T>, the inverse of
	// ReadStream::Read<T>(kEndByteMarker)) -- NOT SLEB128. 7 data bits per
	// byte, and the final byte is offset by kEndByteMarker == 192 so that it
	// reads back as a value in [-64, 63].
	const endByteMarker = 192
	pack := func(op uint8, arg int32) []byte {
		v := int32(arg)<<3 | int32(op)
		var out []byte
		for {
			// Low 7 bits, with the remainder shifted arithmetically so the
			// sign survives.
			low := v & 0x7f
			rest := v >> 7
			// The last byte is the one where `rest` equals the sign extension
			// of `low`, i.e. nothing left to encode.
			if (rest == 0 && low < 64) || (rest == -1 && low >= 64) {
				out = append(out, byte(endByteMarker+int(int8(low<<1)>>1)))
				return out
			}
			out = append(out, byte(low))
			v = rest
		}
	}
	cat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}

	stream := cat(
		pack(cluster.CSMChangePosition, 100),
		pack(cluster.CSMAdvancePC, 4), // entry at pc 4, pos 100, no inlining
		pack(cluster.CSMPushFunction, 7),
		pack(cluster.CSMChangePosition, 250),
		pack(cluster.CSMAdvancePC, 8), // entry at pc 12, pos 250, inline [7]
		pack(cluster.CSMPopFunction, 0),
		pack(cluster.CSMAdvancePC, 4), // entry at pc 16, pos 250, no inlining
	)
	entries, err := cluster.DecodeCodeSourceMap(stream)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3 (only AdvancePC emits one): %+v", len(entries), entries)
	}
	want := []struct {
		pc    uint32
		pos   int32
		depth int
	}{{4, 100, 0}, {12, 250, 1}, {16, 250, 0}}
	for i, w := range want {
		if entries[i].PCOffset != w.pc {
			t.Errorf("entry %d pc = 0x%x, want 0x%x", i, entries[i].PCOffset, w.pc)
		}
		if entries[i].TokenPos != w.pos {
			t.Errorf("entry %d token_pos = %d, want %d", i, entries[i].TokenPos, w.pos)
		}
		if len(entries[i].InlineStack) != w.depth {
			t.Errorf("entry %d inline depth = %d, want %d", i, len(entries[i].InlineStack), w.depth)
		}
	}
	if len(entries[1].InlineStack) == 1 && entries[1].InlineStack[0] != 7 {
		t.Errorf("inline id = %d, want 7", entries[1].InlineStack[0])
	}

	// No position set before the first ChangePosition.
	e2, err := cluster.DecodeCodeSourceMap(pack(cluster.CSMAdvancePC, 4))
	if err != nil || len(e2) != 1 {
		t.Fatalf("decode: %v entries=%d", err, len(e2))
	}
	if e2[0].TokenPos != cluster.CSMNoPosition {
		t.Errorf("token_pos = %d, want CSMNoPosition", e2[0].TokenPos)
	}

	// A pop with an empty stack is a stream we do not understand; it must be
	// reported rather than yielding a bogus inline stack.
	if _, err := cluster.DecodeCodeSourceMap(pack(cluster.CSMPopFunction, 0)); err == nil {
		t.Error("pop on empty inline stack did not error")
	}
	// Unknown opcode likewise.
	if _, err := cluster.DecodeCodeSourceMap(pack(6, 0)); err == nil {
		t.Error("unknown opcode did not error")
	}
}
