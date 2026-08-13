package cluster

import "testing"

// Dart 2.10-2.15 AOT writes each Code's instructions position as a DELTA
// against a running total, not as an absolute offset:
//
//	runtime/vm/clustered_snapshot.cc @2.12.0, Deserializer::ReadInstructions:
//	    previous_text_offset_ += ReadUnsigned();
//	    const uword payload_start =
//	        image_reader_->GetBareInstructionsAt(previous_text_offset_);
//
// Reading it as an absolute value collapsed 7714 Code objects onto 409
// distinct offsets (851 of them zero) in the 2.12 sample, so most ranges got
// size 0 and were skipped: the pipeline analysed 395 of 7714 functions.
//
// This test pins the size computation that consumes those offsets. The
// accumulation itself lives in readFillCode and is covered end-to-end by the
// Dart 2.12 sample tests.
func TestResolveCodeRangesFromTextOffset(t *testing.T) {
	t.Run("sizes come from the next distinct offset", func(t *testing.T) {
		// Three Code objects share offset 100 -- the AOT compiler
		// deduplicates identical instructions, so this is normal, not a
		// parse error. All three describe the same payload and must get the
		// same non-zero size.
		codes := []CodeEntry{
			{RefID: 1, ClusterIndex: 0, TextOffset: 100},
			{RefID: 2, ClusterIndex: 1, TextOffset: 100},
			{RefID: 3, ClusterIndex: 2, TextOffset: 100},
			{RefID: 4, ClusterIndex: 3, TextOffset: 160},
			{RefID: 5, ClusterIndex: 4, TextOffset: 200},
		}
		ranges := ResolveCodeRangesFromTextOffset(codes)
		if len(ranges) != 5 {
			t.Fatalf("got %d ranges, want 5", len(ranges))
		}
		want := map[uint32]uint32{100: 60, 160: 40}
		zero := 0
		for _, r := range ranges {
			if r.PCOffset == 200 {
				continue // last range: size set by SetLastRangeSize
			}
			if r.Size == 0 {
				zero++
			}
			if w := want[r.PCOffset]; r.Size != w {
				t.Errorf("range at 0x%x: size %d, want %d", r.PCOffset, r.Size, w)
			}
		}
		if zero != 0 {
			t.Errorf("%d shared-offset ranges got size 0 and would be skipped by the disasm stage", zero)
		}
	})

	t.Run("order is stable for shared offsets", func(t *testing.T) {
		codes := []CodeEntry{
			{RefID: 9, ClusterIndex: 0, TextOffset: 10},
			{RefID: 3, ClusterIndex: 1, TextOffset: 10},
			{RefID: 7, ClusterIndex: 2, TextOffset: 10},
			{RefID: 1, ClusterIndex: 3, TextOffset: 20},
		}
		first := ResolveCodeRangesFromTextOffset(codes)
		for i := 0; i < 20; i++ {
			again := ResolveCodeRangesFromTextOffset(codes)
			for j := range first {
				if first[j].RefID != again[j].RefID {
					t.Fatalf("range order is not stable at %d: %d vs %d", j, first[j].RefID, again[j].RefID)
				}
			}
		}
		// Ties broken by RefID, so the run at offset 10 is 3, 7, 9.
		wantRefs := []int{3, 7, 9, 1}
		for i, w := range wantRefs {
			if first[i].RefID != w {
				t.Errorf("range[%d].RefID = %d, want %d", i, first[i].RefID, w)
			}
		}
	})
}
