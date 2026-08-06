// Dart snapshot data stream reader.
// Implements the custom variable-length integer encodings used by the Dart VM.

package dartfmt

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrStreamEOF     = errors.New("stream: unexpected end of data")
	ErrStreamOverrun = errors.New("stream: value too large")
)

// Stream reads Dart snapshot data using the VM's encoding conventions.
type Stream struct {
	data []byte
	pos  int
	end  int
}

// NewStream creates a stream over the given data.
func NewStream(data []byte) *Stream {
	return &Stream{data: data, pos: 0, end: len(data)}
}

// NewStreamAt creates a stream starting at offset within data.
func NewStreamAt(data []byte, offset int) *Stream {
	if offset > len(data) {
		offset = len(data)
	}
	return &Stream{data: data, pos: offset, end: len(data)}
}

// Position returns the current read position.
func (s *Stream) Position() int { return s.pos }

// SetPosition sets the read position.
func (s *Stream) SetPosition(pos int) {
	if pos > s.end {
		pos = s.end
	}
	s.pos = pos
}

// Remaining returns bytes left to read.
func (s *Stream) Remaining() int { return s.end - s.pos }

// ReadByte reads a single byte.
func (s *Stream) ReadByte() (byte, error) {
	if s.pos >= s.end {
		return 0, ErrStreamEOF
	}
	b := s.data[s.pos]
	s.pos++
	return b, nil
}

// ReadBytes reads n bytes into a new slice.
func (s *Stream) ReadBytes(n int) ([]byte, error) {
	if s.pos+n > s.end {
		return nil, ErrStreamEOF
	}
	out := make([]byte, n)
	copy(out, s.data[s.pos:s.pos+n])
	s.pos += n
	return out, nil
}

// ReadUint8 reads a uint8.
func (s *Stream) ReadUint8() (uint8, error) {
	return s.ReadByte()
}

// ReadUint16 reads a little-endian uint16.
func (s *Stream) ReadUint16() (uint16, error) {
	if s.pos+2 > s.end {
		return 0, ErrStreamEOF
	}
	v := binary.LittleEndian.Uint16(s.data[s.pos:])
	s.pos += 2
	return v, nil
}

// ReadUint32 reads a little-endian uint32.
func (s *Stream) ReadUint32() (uint32, error) {
	if s.pos+4 > s.end {
		return 0, ErrStreamEOF
	}
	v := binary.LittleEndian.Uint32(s.data[s.pos:])
	s.pos += 4
	return v, nil
}

// ReadUint64 reads a little-endian uint64.
func (s *Stream) ReadUint64() (uint64, error) {
	if s.pos+8 > s.end {
		return 0, ErrStreamEOF
	}
	v := binary.LittleEndian.Uint64(s.data[s.pos:])
	s.pos += 8
	return v, nil
}

// ReadInt32 reads a little-endian int32.
func (s *Stream) ReadInt32() (int32, error) {
	v, err := s.ReadUint32()
	return int32(v), err
}

// Dart variable-length integer encoding constants.
const (
	dataBitsPerByte        = 7
	byteMask               = (1 << dataBitsPerByte) - 1 // 0x7f
	maxUnsignedDataPerByte = byteMask                   // 127

	// ReadUnsigned end marker: final byte encodes 7 unsigned bits (0-127).
	endUnsignedByteMarker = 255 - maxUnsignedDataPerByte // 128

	// Read<T> (signed) end marker: final byte encodes 7 signed bits (-64..63).
	// Used by Read<uint32_t> for cluster tags.
	minDataPerByte = -(1 << (dataBitsPerByte - 1)) // -64
	maxDataPerByte = (^byte(0x40)) & byteMask      // 63
	endByteMarker  = 255 - maxDataPerByte          // 192
)

// ReadUnsigned reads a Dart-encoded unsigned variable-length integer.
//
// Encoding: each byte carries 7 bits of data in little-endian order.
// If byte > 127: it's the last byte; value contribution = byte - 128.
// If byte <= 127: it's a data byte; 7 bits contribute to the value.
func (s *Stream) ReadUnsigned() (int64, error) {
	b, err := s.ReadByte()
	if err != nil {
		return 0, err
	}
	if b > maxUnsignedDataPerByte {
		return int64(b) - endUnsignedByteMarker, nil
	}

	var r int64
	var shift uint
	for {
		r |= int64(b) << shift
		shift += dataBitsPerByte
		b, err = s.ReadByte()
		if err != nil {
			return 0, err
		}
		if b > maxUnsignedDataPerByte {
			r |= int64(b-endUnsignedByteMarker) << shift
			return r, nil
		}
		if shift >= 63 {
			return 0, ErrStreamOverrun
		}
	}
}

// ReadTagged32 reads a Dart-encoded uint32 using the signed variable-length
// encoding (kEndByteMarker = 192). Used for cluster tags and Read<int32_t>.
//
// Same structure as ReadUnsigned but the terminator byte subtracts 192 instead
// of 128, giving a 7-bit signed range (-64..63) for the final contribution.
func (s *Stream) ReadTagged32() (uint32, error) {
	b, err := s.ReadByte()
	if err != nil {
		return 0, err
	}
	if b > maxUnsignedDataPerByte {
		return uint32(b) - uint32(endByteMarker), nil
	}

	var r uint32
	var shift uint
	for {
		r |= uint32(b) << shift
		shift += dataBitsPerByte
		b, err = s.ReadByte()
		if err != nil {
			return 0, err
		}
		if b > maxUnsignedDataPerByte {
			r |= (uint32(b) - uint32(endByteMarker)) << shift
			return r, nil
		}
		if shift >= 28 {
			return 0, ErrStreamOverrun
		}
	}
}

// ReadTagged64 reads a Dart-encoded int64 using the signed variable-length
// encoding (kEndByteMarker = 192). Used for Read<int64_t> (e.g. Mint values).
func (s *Stream) ReadTagged64() (int64, error) {
	b, err := s.ReadByte()
	if err != nil {
		return 0, err
	}
	if b > maxUnsignedDataPerByte {
		return int64(b) - int64(endByteMarker), nil
	}

	var r int64
	var shift uint
	for {
		r |= int64(b) << shift
		shift += dataBitsPerByte
		b, err = s.ReadByte()
		if err != nil {
			return 0, err
		}
		if b > maxUnsignedDataPerByte {
			r |= (int64(b) - int64(endByteMarker)) << shift
			return r, nil
		}
		if shift >= 63 {
			return 0, ErrStreamOverrun
		}
	}
}

// ReadRefId reads a Dart reference ID using the optimized big-endian encoding.
//
// Uses signed bytes with big-endian accumulation:
//
//	result = byte + (result << 7)
//
// Terminates when byte < 0 (bit 7 set, interpreted as signed).
// Final result = accumulated + 128.
func (s *Stream) ReadRefId() (int64, error) {
	var result int64
	for i := 0; i < 5; i++ { // max 4 stages + safety
		if s.pos >= s.end {
			return 0, ErrStreamEOF
		}
		// Read as signed int8.
		b := int8(s.data[s.pos])
		s.pos++
		result = int64(b) + (result << 7)
		if b < 0 {
			return result + 128, nil
		}
	}
	return 0, ErrStreamOverrun
}

// ReadCString reads a null-terminated string.
func (s *Stream) ReadCString() (string, error) {
	start := s.pos
	for s.pos < s.end {
		if s.data[s.pos] == 0 {
			str := string(s.data[start:s.pos])
			s.pos++ // skip null terminator
			return str, nil
		}
		s.pos++
	}
	return "", fmt.Errorf("stream: unterminated string at offset %d", start)
}

// Align advances position to the next alignment boundary.
func (s *Stream) Align(alignment int) {
	if alignment <= 0 {
		return
	}
	rem := s.pos % alignment
	if rem != 0 {
		s.pos += alignment - rem
	}
	if s.pos > s.end {
		s.pos = s.end
	}
}

// Skip advances the position by n bytes.
func (s *Stream) Skip(n int) error {
	if s.pos+n > s.end {
		return ErrStreamEOF
	}
	s.pos += n
	return nil
}
