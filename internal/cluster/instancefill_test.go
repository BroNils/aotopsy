package cluster

import (
	"testing"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

// instanceProfile is the minimum VersionProfile readFillInstance reads.
func instanceProfile(version string, compressed bool) *snapshot.VersionProfile {
	return &snapshot.VersionProfile{
		DartVersion:        version,
		FillRefUnsigned:    true,
		CompressedPointers: compressed,
		PreCanonicalSplit:  version == "2.10.0",
	}
}

// tagged32 encodes v (0..63) as the single terminator byte ReadTagged32
// expects: values above 127 terminate, and the reader subtracts 192.
func tagged32(v byte) byte { return v + 192 }

// unsignedByte encodes v (0..127) for ReadUnsigned, whose terminator
// subtracts 128.
func unsignedByte(v byte) byte { return v + 128 }

// An unboxed field slot costs exactly TWO 32-bit reads, a boxed one costs a
// single ref, and the bitmap is indexed in COMPRESSED words when pointers are
// compressed. All three come from the SDK at 3.9.2:
//
//	app_snapshot.cc  InstanceSerializationCluster::WriteFill
//	   unboxed_fields_bitmap.Get(offset / kCompressedWordSize)
//	   offset += kCompressedWordSize
//	datastream.h     ReadWordWith32BitReads
//	   kNumRead32PerWord = kBitsPerWord / kBitsPerInt32   // 64/32 = 2
//
// kBitsPerWord is the machine word and does not shrink when pointers are
// compressed, which is why the count stays 2. A comment in readFillInstance
// used to justify the 2 by claiming the bitmap was machine-word indexed --
// it is not -- and warned the code would need revisiting if the bitmap ever
// became compressed-word indexed, which it already was. This test pins the
// behaviour so the reasoning cannot drift again.
func TestReadFillInstanceUnboxedSlotCostsTwoReads(t *testing.T) {
	// Compressed pointers: header is 2 compressed words, so with
	// NextFieldOffsetInWords = 5 there are 3 field slots at indices 2,3,4.
	// Mark index 3 unboxed -> bitmap bit 3.
	const nfo = 5
	bitmap := byte(1 << 3)

	data := []byte{
		unsignedByte(bitmap), // unboxed-fields bitmap
		unsignedByte(7),      // slot 2: boxed -> one ref
		tagged32(1),          // slot 3: unboxed -> lo
		tagged32(2),          // slot 3: unboxed -> hi
		unsignedByte(9),      // slot 4: boxed -> one ref
	}
	s := dartfmt.NewStream(data)
	cm := &ClusterMeta{CID: 100, Count: 1, StartRef: 50, NextFieldOffsetInWords: nfo}

	got, err := readFillInstance(s, cm, instanceProfile("3.9.2", true /*compressedPointers*/), nil)
	if err != nil {
		t.Fatalf("readFillInstance: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d instances, want 1", len(got))
	}
	// Every byte must be consumed: one short and the next cluster in a real
	// snapshot would be misparsed from that point on.
	if s.Position() != len(data) {
		t.Errorf("consumed %d of %d bytes; an unboxed slot must cost exactly two 32-bit reads",
			s.Position(), len(data))
	}
	if got[0].HeaderWords != 2 {
		t.Errorf("HeaderWords = %d, want 2 for compressed pointers", got[0].HeaderWords)
	}
	if got[0].NumFieldSlots != nfo-2 {
		t.Errorf("NumFieldSlots = %d, want %d", got[0].NumFieldSlots, nfo-2)
	}
}

// Without compressed pointers the header is one machine word and slots are
// machine-word sized, but the unboxed read count is unchanged -- it follows
// kBitsPerWord, not the pointer width.
func TestReadFillInstanceUnboxedCountIsIndependentOfCompression(t *testing.T) {
	const nfo = 3 // header 1 word + 2 field slots at indices 1,2
	bitmap := byte(1 << 2)

	data := []byte{
		unsignedByte(bitmap),
		unsignedByte(7), // slot 1: boxed
		tagged32(1),     // slot 2: unboxed lo
		tagged32(2),     // slot 2: unboxed hi
	}
	s := dartfmt.NewStream(data)
	cm := &ClusterMeta{CID: 100, Count: 1, StartRef: 50, NextFieldOffsetInWords: nfo}

	got, err := readFillInstance(s, cm, instanceProfile("3.9.2", false /*compressedPointers*/), nil)
	if err != nil {
		t.Fatalf("readFillInstance: %v", err)
	}
	if s.Position() != len(data) {
		t.Errorf("consumed %d of %d bytes", s.Position(), len(data))
	}
	if got[0].HeaderWords != 1 {
		t.Errorf("HeaderWords = %d, want 1 without compressed pointers", got[0].HeaderWords)
	}
}

// At 2.10 the Instance cluster carries NO bitmap of its own: the only copy is
// the one the Class cluster's fill stored per class id. Reading the stream as
// if a bitmap were there, or defaulting it to zero, both mis-size the fill --
// zero turns every unboxed slot from two 32-bit reads into one ref, which is
// how the 2.10 roots section ended up 392 bytes past where FillEnd said it was.
func TestReadFillInstance210TakesTheBitmapFromTheClassCluster(t *testing.T) {
	const cid = 200
	const nfo = 4 // uncompressed: header 1 word, slots at index 1, 2, 3

	// Slot at word index 2 is unboxed.
	bitmaps := map[int32]uint64{cid: 1 << 2}

	data := []byte{
		0,               // is_canonical (raw byte, 2.10 only)
		unsignedByte(7), // slot 1: boxed -> one ref
		tagged32(1),     // slot 2: unboxed -> lo
		tagged32(2),     // slot 2: unboxed -> hi
		unsignedByte(9), // slot 3: boxed -> one ref
	}
	s := dartfmt.NewStream(data)
	cm := &ClusterMeta{CID: cid, Count: 1, StartRef: 50, NextFieldOffsetInWords: nfo}

	got, err := readFillInstance(s, cm, instanceProfile("2.10.0", false), bitmaps)
	if err != nil {
		t.Fatalf("readFillInstance: %v", err)
	}
	if s.Position() != len(data) {
		t.Fatalf("consumed %d of %d bytes; the class-cluster bitmap was not applied",
			s.Position(), len(data))
	}
	if len(got[0].Fields) != 2 {
		t.Errorf("captured %d boxed fields, want 2 (the unboxed slot must not be one)",
			len(got[0].Fields))
	}
}

// The same cluster with no entry in the class map must read every slot as a
// ref -- an absent class id means an empty bitmap, not "unknown, guess".
func TestReadFillInstance210AbsentClassMeansNoUnboxedFields(t *testing.T) {
	const nfo = 3
	data := []byte{
		0,               // is_canonical
		unsignedByte(7), // slot 1
		unsignedByte(9), // slot 2
	}
	s := dartfmt.NewStream(data)
	cm := &ClusterMeta{CID: 42, Count: 1, StartRef: 50, NextFieldOffsetInWords: nfo}

	got, err := readFillInstance(s, cm, instanceProfile("2.10.0", false), map[int32]uint64{})
	if err != nil {
		t.Fatalf("readFillInstance: %v", err)
	}
	if s.Position() != len(data) {
		t.Fatalf("consumed %d of %d bytes", s.Position(), len(data))
	}
	if len(got[0].Fields) != 2 {
		t.Errorf("captured %d fields, want 2", len(got[0].Fields))
	}
}

// The recovered field byte offsets must be in the same units the bitmap
// indexes, or InstanceFieldTypes keys land on the wrong field.
func TestReadFillInstanceFieldOffsetsUseTheCompressedWordSize(t *testing.T) {
	const nfo = 4 // compressed: header 2, slots at index 2 and 3
	data := []byte{
		unsignedByte(0), // no unboxed fields
		unsignedByte(7),
		unsignedByte(9),
	}
	s := dartfmt.NewStream(data)
	cm := &ClusterMeta{CID: 100, Count: 1, StartRef: 50, NextFieldOffsetInWords: nfo}

	got, err := readFillInstance(s, cm, instanceProfile("3.9.2", true), nil)
	if err != nil {
		t.Fatalf("readFillInstance: %v", err)
	}
	if len(got[0].Fields) != 2 {
		t.Fatalf("got %d captured fields, want 2", len(got[0].Fields))
	}
	// Slot index 2 and 3, four bytes apart.
	if got[0].Fields[0].ByteOffset != 8 || got[0].Fields[1].ByteOffset != 12 {
		t.Errorf("byte offsets = %d, %d; want 8, 12 (compressed word = 4)",
			got[0].Fields[0].ByteOffset, got[0].Fields[1].ByteOffset)
	}
}
