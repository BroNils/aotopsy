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
	Size     int // 4 for decoded ARM64 instructions; 1-3 for a truncated bad tail
	Mnemonic string
	Operands string
	Text     string // full disassembly line
	// Bad marks bytes that cannot form a valid decoded instruction: either a
	// rejected 32-bit word or a truncated 1-3 byte tail. Listing recovery keeps
	// them visible as `.word`/`.byte`, but semantic analyses must treat them as a
	// control-flow/provenance barrier rather than flowing facts through bytes
	// whose instruction semantics are unknown.
	Bad bool
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
	full := len(data) / 4
	n := full
	if len(data)%4 != 0 {
		n++
	}
	if n > maxSteps {
		n = maxSteps
	}

	result := make([]Inst, 0, n)
	for i := 0; i < full && len(result) < n; i++ {
		off := i * 4
		addr, ok := checkedInstructionAddr(opts.BaseAddr, off, 4)
		if !ok {
			break
		}
		raw := binary.LittleEndian.Uint32(data[off : off+4])

		inst, err := arm64asm.Decode(data[off : off+4])
		var mnemonic, operands, text string
		bad := false
		if err != nil {
			bad = true
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
			Bad:      bad,
		})
	}

	// AArch64 instructions are fixed-width. A final 1-3 bytes therefore cannot
	// be an instruction and must remain visible as malformed input rather than
	// disappearing from the listing and semantic analyses.
	if rem := len(data) % 4; rem != 0 && len(result) < n {
		off := full * 4
		if addr, ok := checkedInstructionAddr(opts.BaseAddr, off, rem); ok {
			var raw uint32
			parts := make([]string, 0, rem)
			for i := 0; i < rem; i++ {
				b := data[off+i]
				raw |= uint32(b) << (8 * i)
				parts = append(parts, fmt.Sprintf("0x%02x", b))
			}
			operands := strings.Join(parts, ", ")
			result = append(result, Inst{
				Addr:     addr,
				Raw:      raw,
				Size:     rem,
				Mnemonic: ".byte",
				Operands: operands,
				Text:     ".byte " + operands,
				Bad:      true,
			})
		}
	}
	return result
}

func checkedInstructionAddr(base uint64, off, size int) (uint64, bool) {
	if off < 0 || size <= 0 {
		return 0, false
	}
	span := uint64(off) + uint64(size-1)
	if span < uint64(off) || span > ^uint64(0)-base {
		return 0, false
	}
	return base + uint64(off), true
}

// Format renders a slice of instructions as stable text output.
// Each line: <addr>  <hex bytes>  <disasm>  ; <comments>
// Annotators are checked in order; first non-empty result is used.
func Format(insts []Inst, lookup SymbolLookup, annotators ...Annotator) string {
	var b strings.Builder
	for _, inst := range insts {
		// Address.
		fmt.Fprintf(&b, "0x%08x  ", inst.Addr)
		// Raw bytes (little-endian hex). Synthetic callers historically leave
		// Size at zero, so preserve the four-byte display in that case.
		size := inst.Size
		if size <= 0 || size > 4 {
			size = 4
		}
		for i := 0; i < 4; i++ {
			if i < size {
				fmt.Fprintf(&b, "%02x ", byte(inst.Raw>>uint(8*i)))
			} else {
				b.WriteString("   ")
			}
		}
		b.WriteByte(' ')
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
func DisasmOne(raw uint32) string {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], raw)
	inst, err := arm64asm.Decode(buf[:])
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
