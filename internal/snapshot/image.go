// Image header and InstructionsSection parsing for Dart AOT instruction snapshots.

package snapshot

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ImageHeader represents the header at the start of a Dart AOT instructions image.
// Layout (arm64, 64-bit words):
//
//	+0x00: ImageSize (uword) — total size of image including header
//	+0x08: InstructionsSectionOffset (uword) — offset from image start to InstructionsSection object
type ImageHeader struct {
	ImageSize                 uint64
	InstructionsSectionOffset uint64
}

// InstructionsSection represents the InstructionsSection heap object.
// Layout (arm64):
//
//	+0x00: tags_ (uword) — object header tag
//	+0x08: payload_length_ (uword) — instruction bytes that follow
//	+0x10: bss_offset_ (int64) — offset to BSS section
//	+0x18: instructions_relocated_address_ (uword)
//	+0x20: build_id_offset_ (int64)
//	+0x28: data[] — actual machine code starts here
type InstructionsSection struct {
	Tags                         uint64
	PayloadLength                uint64
	BSSOffset                    int64
	InstructionsRelocatedAddress uint64
	BuildIDOffset                int64
	CodeOffset                   uint64 // file offset where actual code begins (computed)
}

const (
	imageHeaderSize           = 16 // 2 * 8 bytes (arm64)
	instructionsSectionFields = 40 // 5 * 8 bytes (tag + 4 fields)
)

// ParseImageHeader reads the Image header from raw instruction section bytes.
func ParseImageHeader(data []byte) (*ImageHeader, error) {
	if len(data) < imageHeaderSize {
		return nil, errors.New("image: data too short for header")
	}
	return &ImageHeader{
		ImageSize:                 binary.LittleEndian.Uint64(data[0:8]),
		InstructionsSectionOffset: binary.LittleEndian.Uint64(data[8:16]),
	}, nil
}

// ParseInstructionsSection reads the InstructionsSection object from raw bytes.
// offset is the byte offset within the image where the object starts.
func ParseInstructionsSection(data []byte, offset uint64) (*InstructionsSection, error) {
	end := offset + instructionsSectionFields
	if uint64(len(data)) < end {
		return nil, fmt.Errorf("image: data too short for InstructionsSection at 0x%x", offset)
	}

	d := data[offset:]
	return &InstructionsSection{
		Tags:                         binary.LittleEndian.Uint64(d[0:8]),
		PayloadLength:                binary.LittleEndian.Uint64(d[8:16]),
		BSSOffset:                    int64(binary.LittleEndian.Uint64(d[16:24])),
		InstructionsRelocatedAddress: binary.LittleEndian.Uint64(d[24:32]),
		BuildIDOffset:                int64(binary.LittleEndian.Uint64(d[32:40])),
		CodeOffset:                   offset + instructionsSectionFields,
	}, nil
}

// CodeRegion extracts the actual machine code bytes from an instruction image.
// Returns the code bytes, their VA offset from the image start, and the payload length.
func CodeRegion(imageData []byte) (code []byte, codeOffsetInImage uint64, payloadLen uint64, err error) {
	hdr, err := ParseImageHeader(imageData)
	if err != nil {
		return nil, 0, 0, err
	}

	sect, err := ParseInstructionsSection(imageData, hdr.InstructionsSectionOffset)
	if err != nil {
		return nil, 0, 0, err
	}

	codeStart := sect.CodeOffset
	codeEnd := codeStart + sect.PayloadLength
	if codeEnd > uint64(len(imageData)) {
		// Clamp to available data.
		codeEnd = uint64(len(imageData))
	}
	if codeStart >= codeEnd {
		return nil, codeStart, 0, nil
	}

	return imageData[codeStart:codeEnd], codeStart, sect.PayloadLength, nil
}
