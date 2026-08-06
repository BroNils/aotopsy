package dartfmt

import (
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
