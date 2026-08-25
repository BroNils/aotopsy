// Package symbolmap diffs a stripped libapp.so against an unstripped build
// of the SAME binary: it disassembles the stripped binary's own direct
// call/branch instructions and resolves each target VA against the real
// function symbols recovered from the unstripped side (exact match, or
// nearest-symbol-at-or-below within a bounded distance). Ported from
// flutterdec's pipeline/symbol_map.rs (Rust, ARM64-only via Capstone),
// generalized here to also support x86_64 by reusing aotopsy's own
// disassemblers instead of Capstone.
package symbolmap

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/arch/x86/x86asm"

	"aotopsy/internal/disasm"
)

// MatchKind classifies how a call-site's target VA was resolved.
type MatchKind string

const (
	MatchExact      MatchKind = "exact"
	MatchNearest    MatchKind = "nearest"
	MatchUnresolved MatchKind = "unresolved"
)

// CallSite is one direct call/branch instruction found in the stripped
// binary, with its target resolved (or not) against the unstripped symbols.
type CallSite struct {
	FromVA       uint64    `json:"from_va"`
	TargetVA     uint64    `json:"target_va"`
	Match        MatchKind `json:"match"`
	SymbolName   string    `json:"symbol_name,omitempty"`
	SymbolVA     uint64    `json:"symbol_va,omitempty"`
	SymbolOffset uint64    `json:"symbol_offset,omitempty"`
}

// TargetSummary aggregates all call sites sharing the same target VA.
type TargetSummary struct {
	TargetVA     uint64    `json:"target_va"`
	CallCount    int       `json:"call_count"`
	Match        MatchKind `json:"match"`
	SymbolName   string    `json:"symbol_name,omitempty"`
	SymbolVA     uint64    `json:"symbol_va,omitempty"`
	SymbolOffset uint64    `json:"symbol_offset,omitempty"`
}

// Options controls the comparison.
type Options struct {
	// NearestMaxDistance bounds how far below a target VA the nearest
	// preceding symbol may sit and still count as MatchNearest (handles
	// inlining/tail-call offset drift). 0 disables nearest-matching.
	NearestMaxDistance uint64
	// IncludeBranches also scans unconditional direct branches (ARM64 B /
	// x86 JMP rel), not just calls (ARM64 BL / x86 CALL rel32).
	IncludeBranches bool
	// RequireExecMatch aborts with an error if the two binaries' exec
	// section bytes don't match exactly -- a safety check that they're
	// really the same build (stripped vs. debug build of one binary).
	RequireExecMatch bool
}

// Report is the full comparison result.
type Report struct {
	StrippedPath     string          `json:"stripped_path"`
	UnstrippedPath   string          `json:"unstripped_path"`
	Machine          string          `json:"machine"`
	ExecLayoutMatch  bool            `json:"exec_layout_match"`
	ExecBytesMatch   bool            `json:"exec_bytes_match"`
	UnstrippedSymCnt int             `json:"unstripped_symbol_count"`
	CallSites        []CallSite      `json:"call_sites"`
	Targets          []TargetSummary `json:"targets"`
	ExactCount       int             `json:"exact_count"`
	NearestCount     int             `json:"nearest_count"`
	UnresolvedCount  int             `json:"unresolved_count"`
	Notes            []string        `json:"notes,omitempty"`
}

type execSection struct {
	Name string
	Addr uint64
	Size uint64
	Data []byte
}

// Compare runs the full stripped-vs-unstripped diff.
func Compare(strippedPath, unstrippedPath string, opts Options) (*Report, error) {
	sf, err := elf.Open(strippedPath)
	if err != nil {
		return nil, fmt.Errorf("symbolmap: open stripped: %w", err)
	}
	defer func() { _ = sf.Close() }()
	uf, err := elf.Open(unstrippedPath)
	if err != nil {
		return nil, fmt.Errorf("symbolmap: open unstripped: %w", err)
	}
	defer func() { _ = uf.Close() }()

	if sf.Machine != uf.Machine {
		return nil, fmt.Errorf("symbolmap: machine mismatch: stripped=%s unstripped=%s", sf.Machine, uf.Machine)
	}
	if sf.Machine != elf.EM_AARCH64 && sf.Machine != elf.EM_X86_64 {
		return nil, fmt.Errorf("symbolmap: unsupported machine %s (only AArch64/x86_64)", sf.Machine)
	}

	rep := &Report{
		StrippedPath:   strippedPath,
		UnstrippedPath: unstrippedPath,
		Machine:        sf.Machine.String(),
	}

	strippedExec, err := collectExecSections(sf)
	if err != nil {
		return nil, err
	}
	unstrippedExec, err := collectExecSections(uf)
	if err != nil {
		return nil, err
	}
	rep.ExecLayoutMatch, rep.ExecBytesMatch = compareExecLayouts(strippedExec, unstrippedExec)
	if opts.RequireExecMatch && !rep.ExecBytesMatch {
		return nil, fmt.Errorf("symbolmap: --require-exec-match set but exec section bytes differ between the two binaries")
	}

	symbols, symVAs := collectSymbols(uf)
	rep.UnstrippedSymCnt = len(symbols)

	var callSites []CallSite
	switch sf.Machine {
	case elf.EM_AARCH64:
		callSites = scanARM64CallSites(strippedExec, opts.IncludeBranches)
	case elf.EM_X86_64:
		callSites = scanX86CallSites(strippedExec, opts.IncludeBranches)
	}

	targetCounts := make(map[uint64]int, len(callSites))
	for i := range callSites {
		cs := &callSites[i]
		kind, name, symVA, off := resolveTarget(symbols, symVAs, cs.TargetVA, opts.NearestMaxDistance)
		cs.Match = kind
		cs.SymbolName = name
		cs.SymbolVA = symVA
		cs.SymbolOffset = off
		targetCounts[cs.TargetVA]++
		switch kind {
		case MatchExact:
			rep.ExactCount++
		case MatchNearest:
			rep.NearestCount++
		default:
			rep.UnresolvedCount++
		}
	}
	rep.CallSites = callSites

	targets := make([]TargetSummary, 0, len(targetCounts))
	seen := make(map[uint64]bool, len(targetCounts))
	for _, cs := range callSites {
		if seen[cs.TargetVA] {
			continue
		}
		seen[cs.TargetVA] = true
		targets = append(targets, TargetSummary{
			TargetVA:     cs.TargetVA,
			CallCount:    targetCounts[cs.TargetVA],
			Match:        cs.Match,
			SymbolName:   cs.SymbolName,
			SymbolVA:     cs.SymbolVA,
			SymbolOffset: cs.SymbolOffset,
		})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].CallCount > targets[j].CallCount })
	rep.Targets = targets

	if !rep.ExecLayoutMatch {
		rep.Notes = append(rep.Notes, "exec section layout differs between stripped/unstripped binaries -- results may be unreliable")
	}

	return rep, nil
}

func collectExecSections(f *elf.File) ([]execSection, error) {
	var out []execSection
	for _, s := range f.Sections {
		if s.Flags&elf.SHF_EXECINSTR == 0 || s.Size == 0 {
			continue
		}
		data, err := s.Data()
		if err != nil {
			return nil, fmt.Errorf("symbolmap: read section %s: %w", s.Name, err)
		}
		out = append(out, execSection{Name: s.Name, Addr: s.Addr, Size: s.Size, Data: data})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out, nil
}

// compareExecLayouts checks whether the stripped side's exec sections
// exist at the exact same (addr, size) in the unstripped side, and if so
// whether the raw bytes match exactly.
func compareExecLayouts(stripped, unstripped []execSection) (layoutMatch, bytesMatch bool) {
	byKey := make(map[[2]uint64]execSection, len(unstripped))
	for _, s := range unstripped {
		byKey[[2]uint64{s.Addr, s.Size}] = s
	}
	if len(stripped) == 0 {
		return false, false
	}
	layoutMatch = true
	bytesMatch = true
	for _, s := range stripped {
		u, ok := byKey[[2]uint64{s.Addr, s.Size}]
		if !ok {
			layoutMatch = false
			bytesMatch = false
			continue
		}
		if !bytes.Equal(u.Data, s.Data) {
			bytesMatch = false
		}
	}
	return layoutMatch, bytesMatch
}

// isUsefulSymbolName rejects empty, "$"-prefixed (ARM mapping symbols),
// and ".L"-prefixed local-label names.
func isUsefulSymbolName(name string) bool {
	if name == "" {
		return false
	}
	if strings.HasPrefix(name, "$") {
		return false
	}
	if strings.HasPrefix(name, ".L") {
		return false
	}
	return true
}

// collectSymbols gathers STT_FUNC/STT_NOTYPE symbols with a nonzero value
// and a useful name from both .symtab and .dynsym, keeping the longest
// name on a VA collision. Returns the name map plus a sorted VA slice for
// nearest-below lookups.
func collectSymbols(f *elf.File) (map[uint64]string, []uint64) {
	byVA := make(map[uint64]string)
	add := func(syms []elf.Symbol) {
		for _, s := range syms {
			typ := elf.ST_TYPE(s.Info)
			if typ != elf.STT_FUNC && typ != elf.STT_NOTYPE {
				continue
			}
			if s.Value == 0 || !isUsefulSymbolName(s.Name) {
				continue
			}
			if existing, ok := byVA[s.Value]; !ok || len(s.Name) > len(existing) {
				byVA[s.Value] = s.Name
			}
		}
	}
	if syms, err := f.Symbols(); err == nil {
		add(syms)
	}
	if syms, err := f.DynamicSymbols(); err == nil {
		add(syms)
	}
	vas := make([]uint64, 0, len(byVA))
	for va := range byVA {
		vas = append(vas, va)
	}
	sort.Slice(vas, func(i, j int) bool { return vas[i] < vas[j] })
	return byVA, vas
}

// resolveTarget implements exact-match-then-nearest-below-within-distance,
// via binary search over the sorted VA slice (Go equivalent of Rust's
// BTreeMap::range(..=target).next_back()).
func resolveTarget(symbols map[uint64]string, sortedVAs []uint64, targetVA uint64, nearestMaxDistance uint64) (MatchKind, string, uint64, uint64) {
	if name, ok := symbols[targetVA]; ok {
		return MatchExact, name, targetVA, 0
	}
	if nearestMaxDistance == 0 || len(sortedVAs) == 0 {
		return MatchUnresolved, "", 0, 0
	}
	// Largest VA <= targetVA.
	idx := sort.Search(len(sortedVAs), func(i int) bool { return sortedVAs[i] > targetVA })
	if idx == 0 {
		return MatchUnresolved, "", 0, 0
	}
	symVA := sortedVAs[idx-1]
	delta := targetVA - symVA
	if delta > nearestMaxDistance {
		return MatchUnresolved, "", 0, 0
	}
	return MatchNearest, symbols[symVA], symVA, delta
}

// --- ARM64 call/branch scanning ---

// scanARM64CallSites decodes BL (call) and, if includeBranches, B
// (unconditional direct branch) instructions across every exec section,
// reusing the raw-encoding branch-target math already proven in
// internal/disasm/branch.go's B-decoding (BL uses the same imm26*4
// sign-extended offset, just a different top-6-bit opcode).
func scanARM64CallSites(sections []execSection, includeBranches bool) []CallSite {
	var out []CallSite
	for _, sec := range sections {
		insts := disasm.Disassemble(sec.Data, disasm.Options{BaseAddr: sec.Addr})
		for _, inst := range insts {
			if target, ok := decodeARM64BL(inst.Raw, inst.Addr); ok {
				out = append(out, CallSite{FromVA: inst.Addr, TargetVA: target})
				continue
			}
			if includeBranches {
				if target, ok := decodeARM64B(inst.Raw, inst.Addr); ok {
					out = append(out, CallSite{FromVA: inst.Addr, TargetVA: target})
				}
			}
		}
	}
	return out
}

// decodeARM64BL decodes "BL imm26": 100101 imm26.
func decodeARM64BL(raw uint32, pc uint64) (uint64, bool) {
	if raw&0xFC000000 != 0x94000000 {
		return 0, false
	}
	imm26 := raw & 0x03FFFFFF
	offset := signExtend26(imm26) * 4
	return uint64(int64(pc) + int64(offset)), true //nolint:gosec // signed branch offset re-added to a real VA; result is a valid address by construction
}

// decodeARM64B decodes unconditional "B imm26": 000101 imm26 (distinct
// from BL only in the top opcode bit).
func decodeARM64B(raw uint32, pc uint64) (uint64, bool) {
	if raw&0xFC000000 != 0x14000000 {
		return 0, false
	}
	imm26 := raw & 0x03FFFFFF
	offset := signExtend26(imm26) * 4
	return uint64(int64(pc) + int64(offset)), true //nolint:gosec // signed branch offset re-added to a real VA; result is a valid address by construction
}

// signExtend26 sign-extends a 26-bit immediate field to a signed 32-bit
// value; val is always masked to 26 bits by the caller, so the int32
// conversions below never lose information.
func signExtend26(val uint32) int32 {
	const bits = 26
	sign := uint32(1) << (bits - 1)
	mask := sign - 1
	if val&sign != 0 {
		return int32(val | ^mask) //nolint:gosec // val is a 26-bit field; result fits in int32
	}
	return int32(val & mask) //nolint:gosec // val is a 26-bit field; result fits in int32
}

// --- x86_64 call/branch scanning ---

// scanX86CallSites decodes direct CALL rel32 (and, if includeBranches,
// direct JMP rel32) instructions using golang.org/x/arch/x86/x86asm --
// the same decoder cmd/aotopsy/x64refs.go already uses for Dart-AOT
// call-graph scanning, reused here over raw ELF exec sections instead of
// Dart cluster code ranges.
func scanX86CallSites(sections []execSection, includeBranches bool) []CallSite {
	var out []CallSite
	for _, sec := range sections {
		data := sec.Data
		off := 0
		for off < len(data) {
			inst, err := x86asm.Decode(data[off:], 64)
			if err != nil || inst.Len == 0 {
				off++
				continue
			}
			isCall := inst.Op == x86asm.CALL
			isJmp := includeBranches && inst.Op == x86asm.JMP
			if isCall || isJmp {
				for _, arg := range inst.Args {
					if arg == nil {
						continue
					}
					if rel, ok := arg.(x86asm.Rel); ok {
						addr := sec.Addr + uint64(off)
						target := uint64(int64(addr) + int64(inst.Len) + int64(rel)) //nolint:gosec // rel is a decoded rel32; result is a valid address by construction
						out = append(out, CallSite{FromVA: addr, TargetVA: target})
						break
					}
				}
			}
			off += inst.Len
		}
	}
	return out
}

// WriteCallSitesTSV writes one row per call site (matching flutterdec's
// symbol_call_sites.tsv shape).
func WriteCallSitesTSV(path string, sites []CallSite) error {
	f, err := os.Create(path) //nolint:gosec // path is an explicit CLI-provided output target, not untrusted input
	if err != nil {
		return fmt.Errorf("symbolmap: create %s: %w", path, err)
	}
	if _, err := fmt.Fprintln(f, "from_va\ttarget_va\tmatch\tsymbol_name\tsymbol_va\tsymbol_offset"); err != nil {
		_ = f.Close()
		return fmt.Errorf("symbolmap: write %s: %w", path, err)
	}
	for _, cs := range sites {
		if _, err := fmt.Fprintf(f, "0x%x\t0x%x\t%s\t%s\t0x%x\t%d\n",
			cs.FromVA, cs.TargetVA, cs.Match, cs.SymbolName, cs.SymbolVA, cs.SymbolOffset); err != nil {
			_ = f.Close()
			return fmt.Errorf("symbolmap: write %s: %w", path, err)
		}
	}
	return f.Close()
}
