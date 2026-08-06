package disasm

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestDisassembleNOP(t *testing.T) {
	// ARM64 NOP = 0xd503201f
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], 0xd503201f)
	binary.LittleEndian.PutUint32(data[4:8], 0xd503201f)

	insts := Disassemble(data, Options{BaseAddr: 0x1000})
	if len(insts) != 2 {
		t.Fatalf("got %d instructions, want 2", len(insts))
	}
	if insts[0].Addr != 0x1000 {
		t.Errorf("addr[0] = 0x%x, want 0x1000", insts[0].Addr)
	}
	if insts[1].Addr != 0x1004 {
		t.Errorf("addr[1] = 0x%x, want 0x1004", insts[1].Addr)
	}
	if !strings.Contains(strings.ToLower(insts[0].Text), "nop") {
		t.Errorf("expected NOP, got: %s", insts[0].Text)
	}
}

func TestDisassembleMaxSteps(t *testing.T) {
	// 100 NOPs but max 10.
	data := make([]byte, 400)
	for i := 0; i < 100; i++ {
		binary.LittleEndian.PutUint32(data[i*4:], 0xd503201f)
	}

	insts := Disassemble(data, Options{MaxSteps: 10})
	if len(insts) != 10 {
		t.Fatalf("got %d instructions, want 10", len(insts))
	}
}

func TestDisassembleEmpty(t *testing.T) {
	insts := Disassemble(nil, Options{})
	if len(insts) != 0 {
		t.Fatalf("got %d instructions for nil data", len(insts))
	}
}

func TestDisassembleShort(t *testing.T) {
	// Less than 4 bytes.
	insts := Disassemble([]byte{0x01, 0x02}, Options{})
	if len(insts) != 0 {
		t.Fatalf("got %d instructions for 2 bytes", len(insts))
	}
}

func TestFormat(t *testing.T) {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, 0xd503201f)
	insts := Disassemble(data, Options{BaseAddr: 0x1000})

	syms := map[uint64]string{0x1000: "nop_func"}
	text := Format(insts, PlaceholderLookup(syms))
	if !strings.Contains(text, "0x00001000") {
		t.Errorf("missing address in output: %s", text)
	}
	if !strings.Contains(text, "<nop_func>") {
		t.Errorf("missing symbol in output: %s", text)
	}
}

func TestFormatDeterministic(t *testing.T) {
	data := make([]byte, 20)
	for i := 0; i < 5; i++ {
		binary.LittleEndian.PutUint32(data[i*4:], 0xd503201f)
	}
	insts := Disassemble(data, Options{BaseAddr: 0x2000})
	out1 := Format(insts, nil)
	out2 := Format(insts, nil)
	if out1 != out2 {
		t.Error("non-deterministic output")
	}
}
