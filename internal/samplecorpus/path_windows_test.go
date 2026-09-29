//go:build windows

package samplecorpus

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestDecodeLXReparseData(t *testing.T) {
	target := "/home/example/dev/aotopsy_samples/dart-3.9.2-arm64.so"
	dataLen := 4 + len(target)
	buf := make([]byte, 8+dataLen)
	binary.LittleEndian.PutUint32(buf[0:4], ioReparseTagLXSymbolicLink)
	binary.LittleEndian.PutUint16(buf[4:6], uint16(dataLen))
	binary.LittleEndian.PutUint32(buf[8:12], 2)
	copy(buf[12:], target)

	version, got, err := decodeLXReparseData(buf)
	if err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("version = %d, want 2", version)
	}
	if got != target {
		t.Fatalf("decoded target = %q, want %q", got, target)
	}
}

func TestDecodeLXReparseDataVersion1HasNoPayload(t *testing.T) {
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint32(buf[0:4], ioReparseTagLXSymbolicLink)
	binary.LittleEndian.PutUint16(buf[4:6], 4)
	binary.LittleEndian.PutUint32(buf[8:12], 1)

	version, target, err := decodeLXReparseData(buf)
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 || target != "" {
		t.Fatalf("decoded version=%d target=%q, want version=1 with file-backed target", version, target)
	}
}

func TestDecodeLXReparseDataRejectsMalformedPayload(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{name: "short", data: make([]byte, 11), want: "only 11 bytes"},
		{name: "wrong tag", data: make([]byte, 12), want: "not an LX symbolic link"},
		{name: "oversized", data: lxReparseHeader(2, 100), want: "invalid LX reparse data length"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := decodeLXReparseData(tc.data)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func lxReparseHeader(version uint32, dataLen uint16) []byte {
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint32(buf[0:4], ioReparseTagLXSymbolicLink)
	binary.LittleEndian.PutUint16(buf[4:6], dataLen)
	binary.LittleEndian.PutUint32(buf[8:12], version)
	return buf
}
