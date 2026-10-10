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
	imageHeaderSize            = 16 // 2 * 8 bytes (arm64)
	instructionsSection210     = 16 // tags + payload_length on 64-bit Dart 2.10
	instructionsSectionFields  = 40 // 5 * 8 bytes (tag + 4 fields)
	instructionsSectionAligned = 64 // 3.5+: HeaderSize() aligned to kPayloadAlignment=32
)

// InstructionsSectionHeaderSize returns the exact serialized header size for a
// supported Dart profile. The layout is a profile dimension rather than a
// version comparison so a new compatibility family cannot silently inherit the
// nearest known image format.
func InstructionsSectionHeaderSize(profile *VersionProfile) (uint64, error) {
	if !IsExactSupportedProfile(profile) {
		return 0, errors.New("image: exact supported Dart profile required")
	}
	switch profile.InstructionsImage {
	case InstructionsImageLegacy210:
		return instructionsSection210, nil
	case InstructionsImageSection40:
		return instructionsSectionFields, nil
	case InstructionsImageSection64:
		return instructionsSectionAligned, nil
	default:
		return 0, fmt.Errorf("image: unverified instructions image layout for %s", profile.DartVersion)
	}
}

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
// offset is the byte offset within the image where the object starts and
// headerSize is the SDK-version-specific HeaderSize().
func ParseInstructionsSection(data []byte, offset, headerSize uint64) (*InstructionsSection, error) {
	if headerSize < instructionsSectionFields {
		return nil, fmt.Errorf("image: InstructionsSection header size %d < %d", headerSize, instructionsSectionFields)
	}
	if offset > uint64(len(data)) || headerSize > uint64(len(data))-offset {
		return nil, fmt.Errorf("image: data too short for InstructionsSection at 0x%x", offset)
	}

	start := int(offset)
	d := data[start : start+instructionsSectionFields]
	return &InstructionsSection{
		Tags:                         binary.LittleEndian.Uint64(d[0:8]),
		PayloadLength:                binary.LittleEndian.Uint64(d[8:16]),
		BSSOffset:                    int64(binary.LittleEndian.Uint64(d[16:24])),
		InstructionsRelocatedAddress: binary.LittleEndian.Uint64(d[24:32]),
		BuildIDOffset:                int64(binary.LittleEndian.Uint64(d[32:40])),
		CodeOffset:                   offset + headerSize,
	}, nil
}

// CodeRegion extracts the actual machine code bytes from an instruction image.
// Returns the code bytes, their VA offset from the image start, and the payload
// length.
//
// Dart 2.10's Image header second word is bss_offset, not an
// InstructionsSectionOffset. Bare AOT still serializes an InstructionsSection
// object immediately after the 16-byte Image header, though: its 64-bit layout
// is tags + payload_length, so machine code starts at byte 32. Later releases
// put an explicit InstructionsSectionOffset in the Image header and expand the
// section header itself.
func CodeRegion(imageData []byte, profile *VersionProfile) (code []byte, codeOffsetInImage uint64, payloadLen uint64, err error) {
	hdr, err := ParseImageHeader(imageData)
	if err != nil {
		return nil, 0, 0, err
	}
	if !IsExactSupportedProfile(profile) {
		return nil, 0, 0, errors.New("image: exact supported Dart profile required")
	}
	if profile.ImageHeaderSize == 0 {
		return nil, 0, 0, fmt.Errorf("image: unverified Image header size for %s", profile.DartVersion)
	}
	minImageHeader := profile.ImageHeaderSize
	if hdr.ImageSize < minImageHeader {
		return nil, 0, 0, fmt.Errorf("image: declared image size %d is smaller than verified header %d", hdr.ImageSize, minImageHeader)
	}
	if hdr.ImageSize > uint64(len(imageData)) {
		return nil, 0, 0, fmt.Errorf("image: declared image size %d exceeds available %d bytes", hdr.ImageSize, len(imageData))
	}
	imageData = imageData[:int(hdr.ImageSize)]

	// Dart 2.10 is the only supported format without an Image-header field that
	// points at InstructionsSection. That distinction is carried explicitly by
	// the profile rather than inferred from a version string.
	if profile.InstructionsImage == InstructionsImageLegacy210 {
		sectionOff := uint64(imageHeaderSize)
		headerSize, err := InstructionsSectionHeaderSize(profile)
		if err != nil {
			return nil, 0, 0, err
		}
		codeStart := sectionOff + headerSize
		if hdr.ImageSize < codeStart {
			return nil, 0, 0, fmt.Errorf("image: legacy image size %d is too small for InstructionsSection header", hdr.ImageSize)
		}
		payloadLen := binary.LittleEndian.Uint64(imageData[sectionOff+8 : sectionOff+16])
		if payloadLen > hdr.ImageSize-codeStart {
			return nil, codeStart, 0, fmt.Errorf("image: legacy payload length 0x%x exceeds image size 0x%x", payloadLen, hdr.ImageSize)
		}
		return imageData[int(codeStart):int(codeStart+payloadLen)], codeStart, payloadLen, nil
	}
	if profile.InstructionsImage != InstructionsImageSection40 && profile.InstructionsImage != InstructionsImageSection64 {
		return nil, 0, 0, fmt.Errorf("image: unverified instructions image layout for %s", profile.DartVersion)
	}
	if hdr.InstructionsSectionOffset < minImageHeader || hdr.InstructionsSectionOffset >= hdr.ImageSize {
		return nil, 0, 0, fmt.Errorf("image: invalid InstructionsSection offset 0x%x for image size 0x%x",
			hdr.InstructionsSectionOffset, hdr.ImageSize)
	}

	headerSize, err := InstructionsSectionHeaderSize(profile)
	if err != nil {
		return nil, 0, 0, err
	}
	sect, err := ParseInstructionsSection(imageData, hdr.InstructionsSectionOffset, headerSize)
	if err != nil {
		return nil, 0, 0, err
	}

	codeStart := sect.CodeOffset
	if codeStart > hdr.ImageSize {
		return nil, codeStart, 0, fmt.Errorf("image: code start 0x%x exceeds image size 0x%x", codeStart, hdr.ImageSize)
	}
	if sect.PayloadLength > hdr.ImageSize-codeStart {
		return nil, codeStart, 0, fmt.Errorf("image: payload length 0x%x at 0x%x exceeds image size 0x%x",
			sect.PayloadLength, codeStart, hdr.ImageSize)
	}
	codeEnd := codeStart + sect.PayloadLength

	return imageData[int(codeStart):int(codeEnd)], codeStart, sect.PayloadLength, nil
}
