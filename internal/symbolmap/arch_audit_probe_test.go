package symbolmap

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"testing"

	archarm64 "aotopsy/internal/arch/arm64"
	"aotopsy/internal/elfx"
	"aotopsy/internal/samplecorpus"
)

func TestArchAuditX86ScannerPreservesCallAcrossBudgetBoundary(t *testing.T) {
	data := make([]byte, maxScanChunkBytes+32)
	for i := range data {
		data[i] = 0x90 // NOP
	}
	callOff := maxScanChunkBytes - 2
	copy(data[callOff:], []byte{0xE8, 0, 0, 0, 0}) // CALL next instruction
	sec := execSection{Name: ".text", Addr: 0x400000, Size: uint64(len(data)), Data: data}
	syms := map[uint64]symbolInfo{
		sec.Addr: {Name: "entry", VA: sec.Addr, Size: sec.Size, Type: elf.STT_FUNC},
	}
	sites := scanX86CallSites([]execSection{sec}, syms, []uint64{sec.Addr}, false)
	if len(sites) != 1 {
		t.Fatalf("x86 scanner found %d call sites, want 1 complete boundary CALL: %+v", len(sites), sites)
	}
	wantFrom := sec.Addr + uint64(callOff)
	wantTarget := wantFrom + 5
	if sites[0].FromVA != wantFrom || sites[0].TargetVA != wantTarget || sites[0].Indirect {
		t.Fatalf("boundary CALL = %+v, want from=%#x target=%#x direct", sites[0], wantFrom, wantTarget)
	}
}

func TestArchAuditARM64ScannerKeepsFourByteAlignmentAcrossBudgetBoundary(t *testing.T) {
	data := make([]byte, maxScanChunkBytes+64)
	for off := 0; off+4 <= len(data); off += 4 {
		binary.LittleEndian.PutUint32(data[off:], 0xD503201F) // NOP
	}
	blOff := maxScanChunkBytes + 4
	binary.LittleEndian.PutUint32(data[blOff:], 0x94000001) // BL +4
	sec := execSection{Name: ".text", Addr: 0x800000, Size: uint64(len(data)), Data: data}
	syms := map[uint64]symbolInfo{
		sec.Addr: {Name: "entry", VA: sec.Addr, Size: sec.Size, Type: elf.STT_FUNC},
	}
	sites := scanARM64CallSites([]execSection{sec}, syms, []uint64{sec.Addr}, false)
	if len(sites) != 1 {
		t.Fatalf("ARM64 scanner found %d call sites, want 1 aligned BL: %+v", len(sites), sites)
	}
	wantFrom := sec.Addr + uint64(blOff)
	if sites[0].FromVA != wantFrom || sites[0].TargetVA != wantFrom+4 || sites[0].Indirect {
		t.Fatalf("boundary BL = %+v, want from=%#x target=%#x direct", sites[0], wantFrom, wantFrom+4)
	}
}

func TestArchAuditCorpusARM64ChunksStayInstructionAligned(t *testing.T) {
	// No samples/ at all is a legitimate state (fresh clone, CI) and skips; a
	// populated but incomplete corpus is drift and fails.
	if err := samplecorpus.RequireCompleteCorpus(); err != nil {
		if errors.Is(err, samplecorpus.ErrNoCorpus) {
			t.Skip("no samples/ directory in this checkout")
		}
		t.Fatal(err)
	}
	type totals struct {
		chunks, misaligned int
		bl, blr, b         int
	}
	count := func(chunks []scanChunk) totals {
		var out totals
		for _, c := range chunks {
			out.chunks++
			if c.VA%4 != 0 || len(c.Data)%4 != 0 {
				out.misaligned++
			}
			for off := 0; off+4 <= len(c.Data); off += 4 {
				raw := binary.LittleEndian.Uint32(c.Data[off : off+4])
				pc := c.VA + uint64(off)
				if _, ok := archarm64.BL(raw, pc); ok {
					out.bl++
				}
				if _, ok := archarm64.BLR(raw); ok {
					out.blr++
				}
				if _, ok := archarm64.B(raw, pc); ok {
					out.b++
				}
			}
		}
		return out
	}

	var samples, badSamples, badChunks int
	for _, s := range samplecorpus.Registry {
		if s.Arch != "arm64" || s.SymbolOracle {
			continue
		}
		path, err := samplecorpus.RequireSample(s.FileName())
		if err != nil {
			t.Fatal(err)
		}
		ef, err := elfx.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", s.FileName(), err)
		}
		secs, err := collectExecSections(ef)
		_ = ef.Close()
		if err != nil {
			t.Fatalf("exec sections %s: %v", s.FileName(), err)
		}
		samples++
		aligned := count(buildARM64ScanChunks(secs, nil, nil))
		if aligned.misaligned > 0 {
			badSamples++
			badChunks += aligned.misaligned
			if badSamples <= 8 {
				t.Logf("%s: chunks=%+v", s.FileName(), aligned)
			}
		}
	}
	if badSamples > 0 {
		t.Fatalf("ARM64 chunker produced misaligned ranges in %d/%d stripped ARM64 samples (%d chunks)", badSamples, samples, badChunks)
	}
	t.Logf("ARM64 chunk alignment census: samples=%d misaligned=0", samples)
}
