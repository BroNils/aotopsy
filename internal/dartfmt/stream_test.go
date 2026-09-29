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
	s := NewStreamAt([]byte{0, 0, 0, 0, 128}, 3)
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
	s := NewStreamAt([]byte{0x7f}, -1)
	if s.Position() != 0 {
		t.Fatalf("negative constructor offset was not clamped: %d", s.Position())
	}
	if _, err := s.ReadByte(); err != nil {
		t.Fatalf("read after negative constructor offset: %v", err)
	}

	s = NewStream([]byte{1, 2, 3})
	s.SetPosition(-100)
	if s.Position() != 0 {
		t.Fatalf("negative SetPosition was not clamped: %d", s.Position())
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
	s = NewStreamAt([]byte{1, 2, 3}, 1)
	maxInt := int(^uint(0) >> 1)
	if _, err := s.ReadBytes(maxInt); !errors.Is(err, ErrStreamEOF) {
		t.Fatalf("ReadBytes(MaxInt) error = %v, want ErrStreamEOF", err)
	}
	if err := s.Skip(maxInt); !errors.Is(err, ErrStreamEOF) {
		t.Fatalf("Skip(MaxInt) error = %v, want ErrStreamEOF", err)
	}
}
