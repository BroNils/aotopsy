package dartfmt

import (
	"errors"
	"testing"
)

func TestReadUnsigned_SingleByte(t *testing.T) {
	// Single-byte encoding: byte > 127 means terminal.
	// Value = byte - 128.
	tests := []struct {
		in   byte
		want int64
	}{
		{128, 0},   // 128 - 128 = 0
		{129, 1},   // 129 - 128 = 1
		{255, 127}, // 255 - 128 = 127
	}
	for _, tt := range tests {
		s := NewStream([]byte{tt.in})
		got, err := s.ReadUnsigned()
		if err != nil {
			t.Errorf("ReadUnsigned(%d): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ReadUnsigned(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestReadUnsigned_MultiByte(t *testing.T) {
	// Multi-byte: data bytes (<=127) carry 7 bits each, terminal (>127) ends.
	// Example: [5, 128+3] = 5 | (3 << 7) = 5 + 384 = 389
	tests := []struct {
		in   []byte
		want int64
	}{
		{[]byte{0, 128}, 0},       // 0 | (0 << 7) = 0
		{[]byte{1, 128}, 1},       // 1 | (0 << 7) = 1
		{[]byte{5, 131}, 389},     // 5 | (3 << 7) = 5 + 384
		{[]byte{127, 128}, 127},   // 127 | (0 << 7)
		{[]byte{127, 255}, 16383}, // 127 | (127 << 7) = 127 + 16256
		{[]byte{0, 0, 128}, 0},    // three bytes, value 0
		{[]byte{1, 1, 128}, 129},  // 1 | (1 << 7) | (0 << 14) = 1 + 128
	}
	for _, tt := range tests {
		s := NewStream(tt.in)
		got, err := s.ReadUnsigned()
		if err != nil {
			t.Errorf("ReadUnsigned(%v): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ReadUnsigned(%v) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestReadUnsigned_EOF(t *testing.T) {
	s := NewStream([]byte{})
	_, err := s.ReadUnsigned()
	if err != ErrStreamEOF {
		t.Errorf("expected EOF, got %v", err)
	}

	// Data byte with no terminator.
	s = NewStream([]byte{5})
	_, err = s.ReadUnsigned()
	if err != ErrStreamEOF {
		t.Errorf("expected EOF for unterminated, got %v", err)
	}
}

func TestReadUnsignedRejectsTenthSignBitGroup(t *testing.T) {
	// Nine continuation groups consume bits 0..62. A tenth group starts at bit
	// 63 and cannot represent a non-negative intptr_t. The old decoder accepted
	// terminal 0x81 here and returned MinInt64 with nil error.
	data := append(make([]byte, 9), byte(0x81))
	s := NewStream(data)
	if _, err := s.ReadUnsigned(); err != ErrStreamOverrun {
		t.Fatalf("ReadUnsigned oversized terminal error = %v, want ErrStreamOverrun", err)
	}
}

func TestReadUnsignedAcceptsMaxInt64(t *testing.T) {
	// Eight full continuation groups followed by a 7-bit terminal group at bit
	// 56 encode MaxInt64 exactly.
	data := append([]byte{0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f}, byte(0xff))
	s := NewStream(data)
	got, err := s.ReadUnsigned()
	if err != nil {
		t.Fatal(err)
	}
	if got != int64(^uint64(0)>>1) {
		t.Fatalf("ReadUnsigned(max) = %d, want MaxInt64", got)
	}
}

func TestReadUnsigned64AcceptsBit63AndMaxUint64(t *testing.T) {
	// Nine continuation groups occupy bits 0..62; terminal 0x81 contributes
	// one at bit 63. This exact shape is valid for SDK ReadUnsigned<uint64_t>
	// but intentionally invalid for intptr_t ReadUnsigned().
	bit63 := append(make([]byte, 9), byte(0x81))
	got, err := NewStream(bit63).ReadUnsigned64()
	if err != nil {
		t.Fatal(err)
	}
	if got != uint64(1)<<63 {
		t.Fatalf("ReadUnsigned64(bit63) = %#x, want %#x", got, uint64(1)<<63)
	}

	max := append([]byte{0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f}, byte(0x81))
	got, err = NewStream(max).ReadUnsigned64()
	if err != nil {
		t.Fatal(err)
	}
	if got != ^uint64(0) {
		t.Fatalf("ReadUnsigned64(max) = %#x, want MaxUint64", got)
	}
}

func TestReadUnsigned64RejectsOversizedFinalGroup(t *testing.T) {
	data := append(make([]byte, 9), byte(0x82)) // contribution 2 at bit 63
	if _, err := NewStream(data).ReadUnsigned64(); err != ErrStreamOverrun {
		t.Fatalf("ReadUnsigned64 oversized terminal error = %v, want ErrStreamOverrun", err)
	}
	data = append(make([]byte, 10), byte(0x80)) // continuation at bit 63
	if _, err := NewStream(data).ReadUnsigned64(); err != ErrStreamOverrun {
		t.Fatalf("ReadUnsigned64 oversized continuation error = %v, want ErrStreamOverrun", err)
	}
}

func TestReadTagged32_SingleByte(t *testing.T) {
	// Terminal byte > 127: value = byte - 192.
	// Range: 128→(128-192)=wraps, 192→0, 255→63.
	// Actually for uint32: 192→0, 255→63, 128→(128-192) wraps to 0xFFFFFF80...
	// But stored as uint32, so 128-192 = -64 → 0xFFFFFFC0.
	tests := []struct {
		in   byte
		want uint32
	}{
		{192, 0},
		{193, 1},
		{255, 63},
	}
	for _, tt := range tests {
		s := NewStream([]byte{tt.in})
		got, err := s.ReadTagged32()
		if err != nil {
			t.Errorf("ReadTagged32(%d): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ReadTagged32(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestReadTagged32_MultiByte(t *testing.T) {
	// Data bytes (<=127) carry 7 bits, terminal (>127) subtracts 192.
	tests := []struct {
		in   []byte
		want uint32
	}{
		{[]byte{0, 192}, 0},   // 0 | (0 << 7)
		{[]byte{1, 192}, 1},   // 1 | (0 << 7)
		{[]byte{5, 195}, 389}, // 5 | (3 << 7) = 5 + 384
	}
	for _, tt := range tests {
		s := NewStream(tt.in)
		got, err := s.ReadTagged32()
		if err != nil {
			t.Errorf("ReadTagged32(%v): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ReadTagged32(%v) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestReadTaggedWidthsRejectOversizedFinalGroup(t *testing.T) {
	// At bit 14 only two signed bits remain in an int16, so contribution +2
	// (terminal byte 194) is out of range.
	if _, err := NewStream([]byte{0, 0, 194}).ReadTagged16(); err != ErrStreamOverrun {
		t.Fatalf("ReadTagged16 oversized final group error = %v, want ErrStreamOverrun", err)
	}
	// At bit 28 only four signed bits remain in an int32, so contribution +8
	// (terminal byte 200) is out of range.
	if _, err := NewStream([]byte{0, 0, 0, 0, 200}).ReadTagged32(); err != ErrStreamOverrun {
		t.Fatalf("ReadTagged32 oversized final group error = %v, want ErrStreamOverrun", err)
	}
}

func TestReadTaggedSignedWidthBoundariesAndFollowingByte(t *testing.T) {
	t.Run("int16", func(t *testing.T) {
		for _, tc := range []struct {
			buf  []byte
			want uint16
		}{
			{[]byte{0x7f, 0x7f, 0xc1}, 0x7fff},
			{[]byte{0x00, 0x00, 0xbe}, 0x8000},
		} {
			s := NewStream(append(append([]byte(nil), tc.buf...), 0xaa))
			got, err := s.ReadTagged16()
			if err != nil || got != tc.want {
				t.Fatalf("ReadTagged16(%x) = %#x, %v; want %#x", tc.buf, got, err, tc.want)
			}
			if s.Position() != len(tc.buf) {
				t.Fatalf("position = %d, want %d", s.Position(), len(tc.buf))
			}
			b, err := s.ReadByte()
			if err != nil || b != 0xaa {
				t.Fatalf("following marker = %#x, %v", b, err)
			}
		}
	})

	t.Run("int32", func(t *testing.T) {
		for _, tc := range []struct {
			buf  []byte
			want uint32
		}{
			{[]byte{0x7f, 0x7f, 0x7f, 0x7f, 0xc7}, 0x7fffffff},
			{[]byte{0x00, 0x00, 0x00, 0x00, 0xb8}, 0x80000000},
		} {
			got, err := NewStream(tc.buf).ReadTagged32()
			if err != nil || got != tc.want {
				t.Fatalf("ReadTagged32(%x) = %#x, %v; want %#x", tc.buf, got, err, tc.want)
			}
		}
	})

	t.Run("int64", func(t *testing.T) {
		max := append(make([]byte, 9), byte(0xc0))
		for i := 0; i < 9; i++ {
			max[i] = 0x7f
		}
		if got, err := NewStream(max).ReadTagged64(); err != nil || got != int64(^uint64(0)>>1) {
			t.Fatalf("ReadTagged64(max) = %d, %v", got, err)
		}
		min := append(make([]byte, 9), byte(0xbf))
		if got, err := NewStream(min).ReadTagged64(); err != nil || got != -1<<63 {
			t.Fatalf("ReadTagged64(min) = %d, %v", got, err)
		}
	})
}

func TestReadTagged64_SingleByte(t *testing.T) {
	tests := []struct {
		in   byte
		want int64
	}{
		{192, 0},
		{193, 1},
		{255, 63},
		// Negative: 128-192 = -64
		{128, -64},
		{191, -1},
	}
	for _, tt := range tests {
		s := NewStream([]byte{tt.in})
		got, err := s.ReadTagged64()
		if err != nil {
			t.Errorf("ReadTagged64(%d): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ReadTagged64(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestReadRefId_SingleByte(t *testing.T) {
	// Signed byte < 0 (bit 7 set) terminates immediately.
	// result = int8(byte) + 128
	tests := []struct {
		in   byte
		want int64
	}{
		{0x80, 0},   // int8(0x80) = -128, + 128 = 0
		{0xFF, 127}, // int8(0xFF) = -1, + 128 = 127
	}
	for _, tt := range tests {
		s := NewStream([]byte{tt.in})
		got, err := s.ReadRefId()
		if err != nil {
			t.Errorf("ReadRefId(%d): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ReadRefId(0x%02x) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestReadRefId_MultiByte(t *testing.T) {
	// Non-negative bytes accumulate: result = byte + (result << 7).
	// First byte 1, second byte 0x80: result = 1, then (1<<7) + int8(0x80) = 128 + (-128) = 0, + 128 = 128.
	s := NewStream([]byte{1, 0x80})
	got, err := s.ReadRefId()
	if err != nil {
		t.Fatalf("ReadRefId: %v", err)
	}
	if got != 128 {
		t.Errorf("ReadRefId([1, 0x80]) = %d, want 128", got)
	}
}

func TestReadRefIdRejectsFifthByte(t *testing.T) {
	// The SDK's compact ref-id decoder is bounded to four bytes. Four
	// continuation bytes are therefore already malformed; the fifth byte must
	// not be consumed as a belated terminator.
	s := NewStream([]byte{1, 1, 1, 1, 0x80})
	if _, err := s.ReadRefId(); !errors.Is(err, ErrStreamOverrun) {
		t.Fatalf("ReadRefId five-byte encoding error = %v, want ErrStreamOverrun", err)
	}
	if got := s.Position(); got != 4 {
		t.Fatalf("ReadRefId consumed %d bytes, want exactly four", got)
	}
}

func TestReadCString(t *testing.T) {
	s := NewStream([]byte("hello\x00world\x00"))
	got, err := s.ReadCString()
	if err != nil {
		t.Fatalf("ReadCString: %v", err)
	}
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
	got, err = s.ReadCString()
	if err != nil {
		t.Fatalf("ReadCString: %v", err)
	}
	if got != "world" {
		t.Errorf("got %q, want %q", got, "world")
	}
}

func TestStreamPosition(t *testing.T) {
	s, err := NewStreamAt([]byte{0, 0, 0, 0, 128}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if s.Position() != 3 {
		t.Errorf("position = %d, want 3", s.Position())
	}
	if s.Remaining() != 2 {
		t.Errorf("remaining = %d, want 2", s.Remaining())
	}
	v, err := s.ReadUnsigned()
	if err != nil {
		t.Fatal(err)
	}
	if v != 0 {
		t.Errorf("ReadUnsigned = %d, want 0", v)
	}
}

func TestReadDouble(t *testing.T) {
	// Encode a known double (e.g. 0.0 -> int64 0 -> tagged64: [192])
	s := NewStream([]byte{192})
	f, err := s.ReadDouble()
	if err != nil {
		t.Fatalf("ReadDouble: %v", err)
	}
	if f != 0.0 {
		t.Errorf("ReadDouble = %f, want 0.0", f)
	}
}

func TestStreamRejectsNegativeLengthsAndPositions(t *testing.T) {
	if _, err := NewStreamAt([]byte{0x7f}, -1); err == nil {
		t.Fatal("negative constructor offset was accepted")
	}
	if _, err := NewStreamAt([]byte{0x7f}, 2); err == nil {
		t.Fatal("constructor offset past end was accepted")
	}

	s := NewStream([]byte{1, 2, 3})
	if err := s.SetPosition(-100); err == nil {
		t.Fatal("negative SetPosition was accepted")
	}
	if s.Position() != 0 {
		t.Fatalf("rejected SetPosition changed position to %d", s.Position())
	}
	if err := s.SetPosition(4); err == nil {
		t.Fatal("SetPosition past end was accepted")
	}
	if _, err := s.ReadBytes(-1); !errors.Is(err, ErrStreamOverrun) {
		t.Fatalf("ReadBytes(-1) error = %v, want ErrStreamOverrun", err)
	}
	if err := s.Skip(-1); !errors.Is(err, ErrStreamOverrun) {
		t.Fatalf("Skip(-1) error = %v, want ErrStreamOverrun", err)
	}
	if s.Position() != 0 {
		t.Fatalf("rejected negative operations moved stream to %d", s.Position())
	}

	// Addition-based bounds checks overflow for this request when pos > 0.
	// The stream must reject it before any allocation or slice expression.
	s, err := NewStreamAt([]byte{1, 2, 3}, 1)
	if err != nil {
		t.Fatal(err)
	}
	maxInt := int(^uint(0) >> 1)
	if _, err := s.ReadBytes(maxInt); !errors.Is(err, ErrStreamEOF) {
		t.Fatalf("ReadBytes(MaxInt) error = %v, want ErrStreamEOF", err)
	}
	if err := s.Skip(maxInt); !errors.Is(err, ErrStreamEOF) {
		t.Fatalf("Skip(MaxInt) error = %v, want ErrStreamEOF", err)
	}
}

func TestReadSLEB128ExactDartEncodingAndPosition(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
		bits int
		want int64
	}{
		{"zero", []byte{0x00}, 64, 0},
		{"one", []byte{0x01}, 64, 1},
		{"63", []byte{0x3f}, 64, 63},
		{"minus one", []byte{0x7f}, 64, -1},
		{"minus 64", []byte{0x40}, 64, -64},
		{"64", []byte{0xc0, 0x00}, 64, 64},
		{"minus 65", []byte{0xbf, 0x7f}, 64, -65},
		{"128", []byte{0x80, 0x01}, 64, 128},
		{"minus 128", []byte{0x80, 0x7f}, 64, -128},
		{"1000", []byte{0xe8, 0x07}, 64, 1000},
		{"minus 1000", []byte{0x98, 0x78}, 64, -1000},
		{"large", []byte{0xd6, 0xe8, 0xc8, 0x00}, 32, 0x123456},
		{"negative three byte", []byte{0xd6, 0xe8, 0x48}, 32, -904106},
		{"max int32", []byte{0xff, 0xff, 0xff, 0xff, 0x07}, 32, 1<<31 - 1},
		{"min int32", []byte{0x80, 0x80, 0x80, 0x80, 0x78}, 32, -1 << 31},
		{"max int64", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}, 64, 1<<63 - 1},
		{"min int64", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f}, 64, -1 << 63},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStream(append(append([]byte(nil), tc.buf...), 0xaa))
			got, err := s.ReadSLEB128(tc.bits)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("ReadSLEB128 = %d, want %d", got, tc.want)
			}
			if s.Position() != len(tc.buf) {
				t.Fatalf("position = %d, want %d", s.Position(), len(tc.buf))
			}
			marker, err := s.ReadByte()
			if err != nil || marker != 0xaa {
				t.Fatalf("following marker = %#x, %v; want 0xaa", marker, err)
			}
		})
	}
}

func TestReadULEB128ExactDartEncodingAndPosition(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
		bits int
		want uint64
	}{
		{"zero", []byte{0x00}, 64, 0},
		{"127", []byte{0x7f}, 64, 127},
		{"128", []byte{0x80, 0x01}, 64, 128},
		{"624485", []byte{0xe5, 0x8e, 0x26}, 64, 624485},
		{"max uint32", []byte{0xff, 0xff, 0xff, 0xff, 0x0f}, 32, 1<<32 - 1},
		{"max uint64", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, 64, ^uint64(0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStream(append(append([]byte(nil), tc.buf...), 0xaa))
			got, err := s.ReadULEB128(tc.bits)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("ReadULEB128 = %d, want %d", got, tc.want)
			}
			if s.Position() != len(tc.buf) {
				t.Fatalf("position = %d, want %d", s.Position(), len(tc.buf))
			}
			marker, err := s.ReadByte()
			if err != nil || marker != 0xaa {
				t.Fatalf("following marker = %#x, %v; want 0xaa", marker, err)
			}
		})
	}
}

func TestReadULEB128MalformedIsBounded(t *testing.T) {
	s := NewStream([]byte{0x80})
	if _, err := s.ReadULEB128(64); !errors.Is(err, ErrStreamEOF) {
		t.Fatalf("truncated ULEB128 error = %v, want ErrStreamEOF", err)
	}
	if s.Position() != 1 {
		t.Fatalf("truncated ULEB128 position = %d, want 1", s.Position())
	}

	// uint32 has at most five bytes. The fifth may carry only four payload bits,
	// and an overlong continuation must not consume the next field.
	s = NewStream([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0xaa})
	if _, err := s.ReadULEB128(32); !errors.Is(err, ErrStreamOverrun) {
		t.Fatalf("overlong ULEB128 error = %v, want ErrStreamOverrun", err)
	}
	if s.Position() != 5 {
		t.Fatalf("overlong ULEB128 consumed %d bytes, want 5", s.Position())
	}
	marker, err := s.ReadByte()
	if err != nil || marker != 0xaa {
		t.Fatalf("following marker = %#x, %v; want 0xaa", marker, err)
	}

	if _, err := NewStream([]byte{0xff, 0xff, 0xff, 0xff, 0x10}).ReadULEB128(32); !errors.Is(err, ErrStreamOverrun) {
		t.Fatalf("overflowing final uint32 ULEB128 group error = %v, want ErrStreamOverrun", err)
	}
	if _, err := NewStream([]byte{0}).ReadULEB128(0); err == nil {
		t.Fatal("zero-width ULEB128 was accepted")
	}
	if _, err := NewStream([]byte{0}).ReadULEB128(65); err == nil {
		t.Fatal("65-bit ULEB128 was accepted")
	}
}

func TestReadSLEB128MalformedIsBounded(t *testing.T) {
	s := NewStream([]byte{0x80})
	if _, err := s.ReadSLEB128(64); !errors.Is(err, ErrStreamEOF) {
		t.Fatalf("truncated SLEB128 error = %v, want ErrStreamEOF", err)
	}
	if s.Position() != 1 {
		t.Fatalf("truncated SLEB128 position = %d, want 1", s.Position())
	}

	// A 32-bit SLEB128 may consume at most five bytes. The sixth byte belongs
	// to the next field and must remain unread when the fifth still continues.
	s = NewStream([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0xaa})
	if _, err := s.ReadSLEB128(32); !errors.Is(err, ErrStreamOverrun) {
		t.Fatalf("overlong SLEB128 error = %v, want ErrStreamOverrun", err)
	}
	if s.Position() != 5 {
		t.Fatalf("overlong SLEB128 consumed %d bytes, want 5", s.Position())
	}
	marker, err := s.ReadByte()
	if err != nil || marker != 0xaa {
		t.Fatalf("following marker = %#x, %v; want 0xaa", marker, err)
	}

	if _, err := NewStream([]byte{0}).ReadSLEB128(0); err == nil {
		t.Fatal("zero-width SLEB128 was accepted")
	}
	if _, err := NewStream([]byte{0}).ReadSLEB128(65); err == nil {
		t.Fatal("65-bit SLEB128 was accepted")
	}
	// Five bytes are allowed for int32, but the final byte may only carry the
	// four signed bits that fit at bit 28. This terminal lacks the required sign
	// extension and must fail rather than truncate to MinInt32.
	if _, err := NewStream([]byte{0x80, 0x80, 0x80, 0x80, 0x08}).ReadSLEB128(32); !errors.Is(err, ErrStreamOverrun) {
		t.Fatalf("non-canonical overflowing int32 SLEB128 error = %v, want ErrStreamOverrun", err)
	}
}

func TestAlignMatchesDartOffsetSemanticsAndFailsWithoutMoving(t *testing.T) {
	s, err := NewStreamAt(make([]byte, 32), 6)
	if err != nil {
		t.Fatal(err)
	}
	// Utils::RoundUp(6, 8, 3) == 13: 13+3 is divisible by 8.
	if err := s.Align(8, 3); err != nil {
		t.Fatal(err)
	}
	if s.Position() != 13 {
		t.Fatalf("aligned position = %d, want 13", s.Position())
	}

	for _, tc := range []struct {
		alignment int
		offset    int
	}{
		{0, 0}, {3, 0}, {8, -1}, {8, 8},
	} {
		before := s.Position()
		if err := s.Align(tc.alignment, tc.offset); err == nil {
			t.Fatalf("Align(%d,%d) succeeded", tc.alignment, tc.offset)
		}
		if s.Position() != before {
			t.Fatalf("failed Align(%d,%d) moved from %d to %d", tc.alignment, tc.offset, before, s.Position())
		}
	}

	short, err := NewStreamAt(make([]byte, 10), 9)
	if err != nil {
		t.Fatal(err)
	}
	if err := short.Align(8, 0); !errors.Is(err, ErrStreamEOF) {
		t.Fatalf("truncated Align error = %v, want ErrStreamEOF", err)
	}
	if short.Position() != 9 {
		t.Fatalf("truncated Align moved to %d, want 9", short.Position())
	}
}
