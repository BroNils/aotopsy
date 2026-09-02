// Package disasm provides ARM64 disassembly for Dart AOT code regions.
package disasm

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
)

// Inst is a decoded ARM64 instruction with address and raw bytes.
type Inst struct {
	Addr     uint64
	Raw      uint32
	Size     int // always 4 for ARM64
	Mnemonic string
	Operands string
	Text     string // full disassembly line
}

// SymbolLookup resolves an address to a symbolic name. Returns ("", false) if unknown.
type SymbolLookup func(addr uint64) (name string, ok bool)

// Options controls disassembly behavior.
type Options struct {
	BaseAddr uint64       // VA of the first byte in Data
	MaxSteps int          // maximum instructions to decode; 0 = 10M
	Symbols  SymbolLookup // optional symbol resolver
}

const defaultMaxSteps = 10_000_000

func (o Options) effectiveMax() int {
	if o.MaxSteps > 0 {
		return o.MaxSteps
	}
	return defaultMaxSteps
}

// Disassemble decodes ARM64 instructions from a byte region.
// Returns decoded instructions up to MaxSteps or end of data.
func Disassemble(data []byte, opts Options) []Inst {
	maxSteps := opts.effectiveMax()
	n := len(data) / 4
	if n > maxSteps {
		n = maxSteps
	}

	result := make([]Inst, 0, n)
	for i := 0; i < n; i++ {
		off := i * 4
		if off+4 > len(data) {
			break
		}
		raw := binary.LittleEndian.Uint32(data[off : off+4])
		addr := opts.BaseAddr + uint64(off)

		inst, err := arm64asm.Decode(data[off : off+4])
		var mnemonic, operands, text string
		if err != nil {
			mnemonic = ".word"
			operands = fmt.Sprintf("0x%08x", raw)
			text = fmt.Sprintf(".word 0x%08x", raw)
		} else {
			text = inst.String()
			// Split into mnemonic and operands.
			parts := strings.SplitN(text, " ", 2)
			mnemonic = parts[0]
			if len(parts) > 1 {
				operands = parts[1]
			}
		}

		result = append(result, Inst{
			Addr:     addr,
			Raw:      raw,
			Size:     4,
			Mnemonic: mnemonic,
			Operands: operands,
			Text:     text,
		})
	}
	return result
}

// Format renders a slice of instructions as stable text output.
// Each line: <addr>  <hex bytes>  <disasm>  ; <comments>
// Annotators are checked in order; first non-empty result is used.
func Format(insts []Inst, lookup SymbolLookup, annotators ...Annotator) string {
	var b strings.Builder
	for _, inst := range insts {
		// Address.
		fmt.Fprintf(&b, "0x%08x  ", inst.Addr)
		// Raw bytes (little-endian hex).
		fmt.Fprintf(&b, "%02x %02x %02x %02x  ",
			byte(inst.Raw), byte(inst.Raw>>8), byte(inst.Raw>>16), byte(inst.Raw>>24))
		// Disassembly.
		b.WriteString(inst.Text)
		// Symbol comment.
		commented := false
		if lookup != nil {
			if name, ok := lookup(inst.Addr); ok {
				fmt.Fprintf(&b, "  ; <%s>", name)
				commented = true
			}
		}
		// Instruction annotators (PP loads, THR loads, etc).
		if !commented {
			for _, ann := range annotators {
				if s := ann(inst); s != "" {
					fmt.Fprintf(&b, "  ; %s", s)
					break
				}
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// DisasmOne decodes a single ARM64 instruction from its raw encoding.
// Returns the disassembly text, or "" if decoding fails.
func DisasmOne(raw uint32, addr uint64) string {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, raw)
	inst, err := arm64asm.Decode(buf)
	if err != nil {
		return ""
	}
	return inst.String()
}

// PlaceholderLookup returns a SymbolLookup that generates sub_<hexaddr> names
// for a set of known function entry points.
func PlaceholderLookup(entryPoints map[uint64]string) SymbolLookup {
	return func(addr uint64) (string, bool) {
		if name, ok := entryPoints[addr]; ok {
			return name, true
		}
		return "", false
	}
}
