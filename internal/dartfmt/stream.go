// Dart snapshot data stream reader.
// Implements the custom variable-length integer encodings used by the Dart VM.

package dartfmt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
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

// NewStreamAt creates a stream starting at offset within data. Invalid offsets
// are malformed input: silently clamping them can turn a corrupt absolute
// offset into a plausible parse from byte 0 or EOF.
func NewStreamAt(data []byte, offset int) (*Stream, error) {
	if offset < 0 || offset > len(data) {
		return nil, fmt.Errorf("stream: start offset %d outside [0,%d]", offset, len(data))
	}
	return &Stream{data: data, pos: offset, end: len(data)}, nil
}

// Position returns the current read position.
func (s *Stream) Position() int { return s.pos }

// SetPosition sets the read position without silently normalizing an invalid
// offset. Rewinds are used only for diagnostics today, but keeping the primitive
// fail-loud prevents future parser code from masking a bad wire offset.
func (s *Stream) SetPosition(pos int) error {
	if pos < 0 || pos > s.end {
		return fmt.Errorf("stream: position %d outside [0,%d]", pos, s.end)
	}
	s.pos = pos
	return nil
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
	// Use subtraction instead of s.pos+n so an attacker-controlled n cannot
	// overflow int and turn an out-of-bounds request into a negative index or
	// enormous allocation. Negative lengths are malformed input, never a seek.
	if n < 0 {
		return nil, ErrStreamOverrun
	}
	if n > s.end-s.pos {
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
	if 2 > s.end-s.pos {
		return 0, ErrStreamEOF
	}
	v := binary.LittleEndian.Uint16(s.data[s.pos:])
	s.pos += 2
	return v, nil
}

// ReadUint32 reads a little-endian uint32.
func (s *Stream) ReadUint32() (uint32, error) {
	if 4 > s.end-s.pos {
		return 0, ErrStreamEOF
	}
	v := binary.LittleEndian.Uint32(s.data[s.pos:])
	s.pos += 4
	return v, nil
}

// ReadUint64 reads a little-endian uint64.
func (s *Stream) ReadUint64() (uint64, error) {
	if 8 > s.end-s.pos {
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
	// intptr_t is signed. The largest valid unsigned value the VM stores in
	// this API is therefore MaxInt64, whose final 7-bit group starts at bit 56.
	// A tenth group starting at bit 63 would set the sign bit and turn an
	// attacker-controlled length/offset negative after an apparently successful
	// read.
	return s.readVarint(endUnsignedByteMarker, 56, 0, 127)
}

// ReadUnsigned64 reads the SDK's ReadUnsigned<uint64_t>() encoding. It is
// deliberately separate from ReadUnsigned: the latter models intptr_t and must
// reject bit 63, while Dart uses the uint64_t form for unboxed-field bitmaps
// where that bit is valid data.
//
// A uint64_t value can use nine 7-bit continuation groups (bits 0..62) and a
// tenth TERMINAL group at bit 63. Only terminal contributions 0 or 1 fit that
// final position; accepting 2..127 would silently truncate attacker-controlled
// high bits just like C++ unsigned shifting beyond the logical field width.
func (s *Stream) ReadUnsigned64() (uint64, error) {
	b, err := s.ReadByte()
	if err != nil {
		return 0, err
	}
	if b > maxUnsignedDataPerByte {
		return uint64(b - endUnsignedByteMarker), nil
	}

	var r uint64
	var shift uint
	for {
		r |= uint64(b) << shift
		// A continuation group beginning at bit 63 would claim seven more data
		// bits when only one bit remains in uint64. The valid bit-63 group must
		// be terminal and is handled after the next read below.
		if shift >= 63 {
			return 0, ErrStreamOverrun
		}
		shift += dataBitsPerByte
		b, err = s.ReadByte()
		if err != nil {
			return 0, err
		}
		if b > maxUnsignedDataPerByte {
			contrib := uint64(b - endUnsignedByteMarker)
			if shift > 63 || (shift == 63 && contrib > 1) {
				return 0, ErrStreamOverrun
			}
			r |= contrib << shift
			return r, nil
		}
	}
}

// readVarint decodes the SDK's variable-length integer encoding: data
// bytes carry dataBitsPerByte bits each, and the final byte is marked by
// exceeding maxUnsignedDataPerByte, with endMarker subtracted from it.
//
// ReadUnsigned, ReadTagged32 and ReadTagged64 were three full copies of
// this loop, differing only in which end marker to subtract and how wide
// the result is -- so establishing that took a byte-by-byte diff of three
// 25-line functions. This is snapshot deserialisation: a divergence
// between the copies would not fail loudly, it would silently misread a
// length or an offset.
//
// maxShift is the shift at which the value no longer fits the target
// width, and the stream is treated as overrun. It is NOT a detail that
// can be dropped by widening everything to int64 and truncating at the
// end: a 32-bit read of an oversized value must fail, not silently keep
// its low bits.
func (s *Stream) readVarint(endMarker int64, maxShift uint, finalMin, finalMax int64) (int64, error) {
	b, err := s.ReadByte()
	if err != nil {
		return 0, err
	}
	if b > maxUnsignedDataPerByte {
		return int64(b) - endMarker, nil
	}

	var r int64
	var shift uint
	for {
		r |= int64(b) << shift
		if shift >= maxShift {
			return 0, ErrStreamOverrun
		}
		shift += dataBitsPerByte
		b, err = s.ReadByte()
		if err != nil {
			return 0, err
		}
		if b > maxUnsignedDataPerByte {
			contrib := int64(b) - endMarker
			if shift > maxShift || (shift == maxShift && (contrib < finalMin || contrib > finalMax)) {
				return 0, ErrStreamOverrun
			}
			r |= contrib << shift
			return r, nil
		}
	}
}

// ReadTagged16 reads a Dart-encoded 16-bit scalar using the same signed marker
// scheme as ReadTagged32. The VM has a dedicated Read16 path whose final group
// starts at bit 14; accepting the 4th/5th bytes of a 32-bit read would consume
// bytes belonging to the next field on malformed input.
func (s *Stream) ReadTagged16() (uint16, error) {
	v, err := s.readVarint(int64(endByteMarker), 14, -2, 1)
	if err != nil {
		return 0, err
	}
	return uint16(v), nil
}

// ReadTagged32 reads a Dart-encoded uint32 using the signed variable-length
// encoding (kEndByteMarker = 192). Used for cluster tags and Read<int32_t>.
//
// Same structure as ReadUnsigned but the terminator byte subtracts 192 instead
// of 128, giving a 7-bit signed range (-64..63) for the final contribution.
func (s *Stream) ReadTagged32() (uint32, error) {
	v, err := s.readVarint(int64(endByteMarker), 28, -8, 7)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

// ReadTagged64 reads a Dart-encoded int64 using the signed variable-length
// encoding (kEndByteMarker = 192). Used for Read<int64_t> (e.g. Mint values).
func (s *Stream) ReadTagged64() (int64, error) {
	return s.readVarint(int64(endByteMarker), 63, -1, 0)
}

// ReadDouble reads a float64 by reading a Tagged64 and bit-casting to float64 (runtime/vm/datastream.h Read<double>).
func (s *Stream) ReadDouble() (float64, error) {
	v, err := s.ReadTagged64()
	if err != nil {
		return 0, err
	}
	return math.Float64frombits(uint64(v)), nil
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
	for i := 0; i < 4; i++ { // SDK ReadRefId is bounded to four encoded bytes
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

// ReadULEB128 reads one standard unsigned LEB128 value using Dart's
// ReadStream::ReadLEB128 convention: seven low-order payload bits per byte and
// bit 7 means another byte follows. This is a different encoding from
// ReadUnsigned, whose final byte is marked by adding 128.
//
// bits is the logical destination width. Rejecting payload bits outside that
// width is intentionally stricter than the VM's debug ASSERTs: malformed input
// must not truncate high bits and leave the stream aligned on a plausible next
// field.
func (s *Stream) ReadULEB128(bits int) (uint64, error) {
	const (
		moreBit  = byte(0x80)
		dataMask = byte(0x7f)
	)
	if bits <= 0 || bits > 64 {
		return 0, fmt.Errorf("stream: invalid ULEB128 width %d", bits)
	}

	maxBytes := (bits + dataBitsPerByte - 1) / dataBitsPerByte
	var value uint64
	var shift uint
	for i := 0; i < maxBytes; i++ {
		b, err := s.ReadByte()
		if err != nil {
			return 0, err
		}
		payload := uint64(b & dataMask)
		remaining := bits - int(shift)
		if remaining < dataBitsPerByte {
			maxPayload := uint64(1<<remaining) - 1
			if payload > maxPayload {
				return 0, ErrStreamOverrun
			}
		}
		value |= payload << shift
		shift += dataBitsPerByte
		if b&moreBit == 0 {
			return value, nil
		}
		if i == maxBytes-1 {
			return 0, ErrStreamOverrun
		}
	}
	return 0, ErrStreamOverrun
}

// ReadSLEB128 reads one standard signed LEB128 value using Dart's
// ReadStream::ReadSLEB128 convention: seven low-order payload bits per byte,
// bit 7 means another byte follows, and bit 6 of the final byte is the sign.
//
// bits is the logical destination width (for example 32 for
// kind_and_metadata and 64 for intptr_t pc deltas). The width is part of the
// wire contract: accepting an oversized value and truncating it would move the
// stream to a valid-looking next field with corrupted metadata.
func (s *Stream) ReadSLEB128(bits int) (int64, error) {
	const (
		moreBit  = byte(0x80)
		signBit  = byte(0x40)
		dataMask = byte(0x7f)
	)
	if bits <= 0 || bits > 64 {
		return 0, fmt.Errorf("stream: invalid SLEB128 width %d", bits)
	}

	maxBytes := (bits + dataBitsPerByte - 1) / dataBitsPerByte
	var value uint64
	var shift uint
	for i := 0; i < maxBytes; i++ {
		b, err := s.ReadByte()
		if err != nil {
			return 0, err
		}
		payload := uint64(b & dataMask)
		remaining := bits - int(shift)
		if remaining < dataBitsPerByte {
			lowMask := uint64(1<<remaining) - 1
			low := payload & lowMask
			high := payload &^ lowMask
			signSet := low&(uint64(1)<<uint(remaining-1)) != 0
			expectedHigh := uint64(0)
			if signSet {
				expectedHigh = uint64(dataMask) &^ lowMask
			}
			if high != expectedHigh {
				return 0, ErrStreamOverrun
			}
			payload = low
		}
		value |= payload << shift
		shift += dataBitsPerByte

		if b&moreBit == 0 {
			if b&signBit != 0 {
				if shift < uint(bits) {
					value |= ^uint64(0) << shift
				} else if bits < 64 {
					value |= ^((uint64(1) << uint(bits)) - 1)
				}
			}
			return int64(value), nil
		}
		if i == maxBytes-1 {
			return 0, ErrStreamOverrun
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

// Align advances to the next SDK Utils::RoundUp(position, alignment, offset)
// boundary. Dart added the offset parameter to ReadStream::Align in 2.19; an
// offset of zero is the older behavior. Utils::RoundUp requires a power-of-two
// alignment and offset < alignment, so invalid values fail instead of being
// silently normalized. If the aligned position lies past the input, the stream
// is left unchanged.
func (s *Stream) Align(alignment, offset int) error {
	if alignment <= 0 || alignment&(alignment-1) != 0 {
		return fmt.Errorf("stream: alignment %d is not a positive power of two", alignment)
	}
	if offset < 0 || offset >= alignment {
		return fmt.Errorf("stream: alignment offset %d outside [0,%d)", offset, alignment)
	}

	// Compute (pos+offset) % alignment without overflowing int.
	rem := s.pos % alignment
	threshold := alignment - offset
	var mod int
	if rem >= threshold {
		mod = rem - threshold
	} else {
		mod = rem + offset
	}
	if mod == 0 {
		return nil
	}
	delta := alignment - mod
	if delta > s.end-s.pos {
		return ErrStreamEOF
	}
	s.pos += delta
	return nil
}

// Skip advances the position by n bytes.
func (s *Stream) Skip(n int) error {
	if n < 0 {
		return ErrStreamOverrun
	}
	if n > s.end-s.pos {
		return ErrStreamEOF
	}
	s.pos += n
	return nil
}
