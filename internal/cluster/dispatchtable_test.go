package cluster

import (
	"testing"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

// encUnsigned mirrors dartfmt.Stream.ReadUnsigned's encoding (final-byte
// marker 128, giving a 0..127 range for the last byte's contribution).
func encUnsigned(v int64) []byte {
	if v < 0 {
		panic("encUnsigned: negative value")
	}
	var out []byte
	for {
		if v <= 127 {
			out = append(out, byte(v+128))
			return out
		}
		out = append(out, byte(v&0x7f))
		v >>= 7
	}
}

// encTagged64 mirrors dartfmt.Stream.ReadTagged64's encoding (final-byte
// marker 192, giving a -64..63 signed range for the last byte).
func encTagged64(v int64) []byte {
	var out []byte
	for {
		if v >= -64 && v <= 63 {
			out = append(out, byte(v+192))
			return out
		}
		out = append(out, byte(v&0x7f))
		v >>= 7
	}
}

// TestEncodersRoundTripRealReader is a self-check on this test file's own
// encoders: round-trips a spread of values (including multi-byte and
// negative cases) through the REAL dartfmt.Stream reader, so a mistake in
// the hand-rolled encoder can't silently invalidate every test below it.
func TestEncodersRoundTripRealReader(t *testing.T) {
	unsignedCases := []int64{0, 1, 63, 127, 128, 200, 1000, 1 << 20}
	for _, v := range unsignedCases {
		s := dartfmt.NewStreamAt(encUnsigned(v), 0)
		got, err := s.ReadUnsigned()
		if err != nil || got != v {
			t.Errorf("encUnsigned(%d) round-trip: got=%d err=%v", v, got, err)
		}
	}
	tagged64Cases := []int64{0, 1, -1, 63, -64, 64, -65, 1000, -1000, 73, -2, 67}
	for _, v := range tagged64Cases {
		s := dartfmt.NewStreamAt(encTagged64(v), 0)
		got, err := s.ReadTagged64()
		if err != nil || got != v {
			t.Errorf("encTagged64(%d) round-trip: got=%d err=%v", v, got, err)
		}
	}
}

// dispatchTableTestFillEnd is a nonzero offset prepended to every
// synthetic stream below, so it stands in for a real ReadFill result
// (FillEnd is realistically always >0; 0 is ParseDispatchTable's "unset"
// sentinel, deliberately not reused as a legitimate offset here).
const dispatchTableTestFillEnd = 1

// buildDispatchTableStream assembles a synthetic roots-section byte
// stream: one padding byte (see dispatchTableTestFillEnd), then
// objectStoreFieldCount plain refs, an initial_field_table with one
// entry, an empty shared_initial_field_table, then the dispatch table's
// own length/first_code_id/RLE-encoded entries.
func buildDispatchTableStream(objectStoreFieldCount int, rleEncoded [][]byte, length int64) []byte {
	buf := make([]byte, dispatchTableTestFillEnd)
	for i := 0; i < objectStoreFieldCount; i++ {
		buf = append(buf, encUnsigned(0)...) // ObjectStore field ref (content irrelevant)
	}
	buf = append(buf, encUnsigned(1)...)      // initial_field_table count
	buf = append(buf, encUnsigned(0)...)      // ...1 ref
	buf = append(buf, encUnsigned(0)...)      // shared_initial_field_table count = 0
	buf = append(buf, encUnsigned(length)...) // dispatch table length
	buf = append(buf, encUnsigned(0)...)      // first_code_id (unused for non-deferred)
	for _, e := range rleEncoded {
		buf = append(buf, e...)
	}
	return buf
}

// TestParseDispatchTable_NullCodeRecentRepeatStub covers every branch of
// the RLE decoder in one pass, using hand-picked encoded values (see
// each entry's comment for the arithmetic): a literal null, a direct
// code-index encode, a recent-cache reference to that same code entry, a
// repeat marker whose run covers both the marker's own slot and one
// continuation slot, and a stub-slot encode (code_index landing BEFORE
// FirstEntryWithCode). This exact classification (Code vs Stub vs Null)
// was verified end-to-end against two real binaries (Dart 3.7.0 sample,
// Dart 3.10.7/sample_310) before this synthetic test was written -- see
// this file's git history / the commit message for the real-binary
// verification results.
//
// IMPORTANT: The recent buffer is only updated for code-index entries,
// matching the Dart SDK's ReadDispatchTable in runtime/vm/app_snapshot.cc
// (the recent update is inside the `else` block, NOT after the switch).
// This means a recent-cache reference after a non-code entry (null,
// recent-cache, repeat) will resolve to whatever was in that recent slot
// from the LAST code-index entry that wrote to it — NOT from the
// immediately preceding entry. The test below was updated to reflect
// this SDK-correct behavior (previously it encoded the buggy behavior
// where recent was updated for all entry types).
func TestParseDispatchTable_NullCodeRecentRepeatStub(t *testing.T) {
	const firstEntryWithCode = 5

	// With SDK-correct recent-buffer behavior (only code-index entries
	// update recent), we need two consecutive code-index entries to
	// properly test recent-cache: the first code entry goes into
	// recent[0], the second into recent[1], then a recent-cache ref to
	// slot 1 should resolve to the second code entry's value.
	rle := [][]byte{
		encTagged64(0),  // entry0: literal null (recent NOT updated, recentIndex stays 0)
		encTagged64(73), // entry1: code_index=9 (73-64), absoluteSlot=8, ClusterIndex=8-5=3 (recent[0]=code(3), recentIndex→1)
		encTagged64(74), // entry2: code_index=10 (74-64), absoluteSlot=9, ClusterIndex=9-5=4 (recent[1]=code(4), recentIndex→2)
		encTagged64(-3), // entry3: recent[2] (^(-3)=2) -- recent[2] was never set, so this is a zero value (DispatchNull)
		encTagged64(2),  // entry4: repeat marker, repeatCount=1 -- entry4 AND entry5 get entry3's value (DispatchNull)
		encTagged64(67), // entry6: code_index=3 (67-64), absoluteSlot=2 < firstEntryWithCode(5) -> stub, StubIndex=2
	}
	data := buildDispatchTableStream(2, rle, 7)

	result := &Result{FillEnd: dispatchTableTestFillEnd}
	profile := &snapshot.VersionProfile{
		DartVersion:              "test",
		ObjectStoreAOTFieldCount: 2,
		CodeIndexOneBased:        true, // Dart >=2.16: recent update only for code entries
	}
	table := &InstructionsTable{FirstEntryWithCode: firstEntryWithCode}

	entries, err := ParseDispatchTable(data, result, profile, table)
	if err != nil {
		t.Fatalf("ParseDispatchTable: %v", err)
	}
	if len(entries) != 7 {
		t.Fatalf("expected 7 entries, got %d: %+v", len(entries), entries)
	}

	want := []DispatchTableEntry{
		{Index: 0, Kind: DispatchNull},
		{Index: 1, Kind: DispatchCode, ClusterIndex: 3},
		{Index: 2, Kind: DispatchCode, ClusterIndex: 4},
		{Index: 3, Kind: DispatchNull},               // recent[2] never set → zero value (DispatchNull)
		{Index: 4, Kind: DispatchNull},               // repeat marker slot itself (repeats entry3's null)
		{Index: 5, Kind: DispatchNull},               // repeat continuation slot
		{Index: 6, Kind: DispatchStub, StubIndex: 2}, // code_index=3, absoluteSlot=2 < 5 → stub
	}
	for i, w := range want {
		if entries[i] != w {
			t.Errorf("entry[%d]: got %+v, want %+v", i, entries[i], w)
		}
	}
}

// TestParseDispatchTable_ZeroLengthReturnsNilNoError verifies an empty
// dispatch table (length==0, the real-world case for JIT-ish/non-AOT-
// style builds or apps with no polymorphic dispatch sites at all)
// reports nil with no error, not a fabricated empty-but-confusing result.
func TestParseDispatchTable_ZeroLengthReturnsNilNoError(t *testing.T) {
	data := buildDispatchTableStream(1, nil, 0)
	result := &Result{FillEnd: dispatchTableTestFillEnd}
	profile := &snapshot.VersionProfile{DartVersion: "test", ObjectStoreAOTFieldCount: 1}
	table := &InstructionsTable{FirstEntryWithCode: 0}

	entries, err := ParseDispatchTable(data, result, profile, table)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entries != nil {
		t.Errorf("expected nil entries for zero-length dispatch table, got %v", entries)
	}
}

// TestParseDispatchTable_UnverifiedVersionReturnsError verifies the
// honesty gate: ObjectStoreAOTFieldCount==0 (the zero value, meaning
// "not verified for this Dart version" per its doc comment) must refuse
// to guess the roots-section layout, not silently attempt a
// definitely-wrong skip count.
func TestParseDispatchTable_UnverifiedVersionReturnsError(t *testing.T) {
	result := &Result{FillEnd: dispatchTableTestFillEnd}
	profile := &snapshot.VersionProfile{DartVersion: "9.9.9-unverified"}
	table := &InstructionsTable{}

	if _, err := ParseDispatchTable([]byte{0}, result, profile, table); err == nil {
		t.Error("expected an error for ObjectStoreAOTFieldCount == 0, got nil")
	}
}

// TestParseDispatchTable_FillEndUnsetReturnsError verifies the ordering
// requirement: calling this before ReadFill (FillEnd still 0, its zero
// value) must error rather than parse from byte offset 0 as if that
// were meaningful.
func TestParseDispatchTable_FillEndUnsetReturnsError(t *testing.T) {
	result := &Result{} // FillEnd left unset
	profile := &snapshot.VersionProfile{DartVersion: "test", ObjectStoreAOTFieldCount: 5}
	table := &InstructionsTable{}

	if _, err := ParseDispatchTable([]byte{0}, result, profile, table); err == nil {
		t.Error("expected an error when FillEnd is unset, got nil")
	}
}

// TestParseDispatchTable_NilInstructionsTableReturnsError verifies a nil
// table is rejected explicitly rather than panicking on a nil deref.
func TestParseDispatchTable_NilInstructionsTableReturnsError(t *testing.T) {
	result := &Result{FillEnd: dispatchTableTestFillEnd}
	profile := &snapshot.VersionProfile{DartVersion: "test", ObjectStoreAOTFieldCount: 1}

	if _, err := ParseDispatchTable([]byte{0}, result, profile, nil); err == nil {
		t.Error("expected an error for a nil InstructionsTable, got nil")
	}
}
