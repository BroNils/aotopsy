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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/arch/x86/x86asm"

	"aotopsy/internal/arch/arm64"
	"aotopsy/internal/arch/x86"
	"aotopsy/internal/disasm"
	"aotopsy/internal/elfx"
	"aotopsy/internal/output"
)

// MatchKind classifies how a call-site's target VA was resolved.
type MatchKind string

const (
	MatchExact      MatchKind = "exact"
	MatchNearest    MatchKind = "nearest"
	MatchUnresolved MatchKind = "unresolved"
)

type SiteKind string

const (
	SiteCall   SiteKind = "call"
	SiteBranch SiteKind = "branch"
)

// CallSite is one direct call/branch instruction found in the stripped
// binary, with its target resolved (or not) against the unstripped symbols.
type CallSite struct {
	FromVA       uint64    `json:"from_va"`
	TargetVA     uint64    `json:"target_va,omitempty"`
	TargetValid  bool      `json:"target_valid,omitempty"`
	Kind         SiteKind  `json:"kind"`
	Indirect     bool      `json:"indirect,omitempty"`
	Reg          string    `json:"reg,omitempty"`
	Via          string    `json:"via,omitempty"`
	Match        MatchKind `json:"match"`
	SymbolName   string    `json:"symbol_name,omitempty"`
	SymbolVA     uint64    `json:"symbol_va,omitempty"`
	SymbolOffset uint64    `json:"symbol_offset,omitempty"`
}

// SymbolRecord is one executable symbol imported from the verified unstripped
// twin.  Aliases sharing the same VA are retained rather than discarded.
type SymbolRecord struct {
	VA       uint64   `json:"va"`
	Size     uint64   `json:"size,omitempty"`
	Name     string   `json:"name"`
	Aliases  []string `json:"aliases,omitempty"`
	Type     string   `json:"type"`
	Binding  string   `json:"binding"`
	Section  string   `json:"section"`
	Category string   `json:"category,omitempty"`
}

// TargetSummary aggregates all call sites sharing the same target VA.
type TargetSummary struct {
	TargetVA     uint64    `json:"target_va"`
	CallCount    int       `json:"call_count"`
	BranchCount  int       `json:"branch_count,omitempty"`
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
	// ImportSymbols exposes the complete executable reverse symbol table from
	// the verified unstripped twin, not merely symbols reached by call sites.
	ImportSymbols bool
}

// Report is the full comparison result.
type Report struct {
	StrippedPath     string          `json:"stripped_path"`
	UnstrippedPath   string          `json:"unstripped_path"`
	Machine          string          `json:"machine"`
	ExecLayoutMatch  bool            `json:"exec_layout_match"`
	ExecBytesMatch   bool            `json:"exec_bytes_match"`
	UnstrippedSymCnt int             `json:"unstripped_symbol_count"`
	Symbols          []SymbolRecord  `json:"symbols,omitempty"`
	CallSites        []CallSite      `json:"call_sites"`
	Targets          []TargetSummary `json:"targets"`
	ExactCount       int             `json:"exact_count"`
	NearestCount     int             `json:"nearest_count"`
	UnresolvedCount  int             `json:"unresolved_count"`
	IndirectCount    int             `json:"indirect_count,omitempty"`
	Notes            []string        `json:"notes,omitempty"`
}

type execSection struct {
	Name string
	Addr uint64
	Size uint64
	Data []byte
}

type symbolInfo struct {
	Name        string
	VA          uint64
	Size        uint64
	Type        elf.SymType
	Binding     elf.SymBind
	Section     elf.SectionIndex
	SectionName string
	Aliases     []string
	Category    string
}

const maxExecBytes = 256 << 20

// Compare runs the full stripped-vs-unstripped diff.
func Compare(strippedPath, unstrippedPath string, opts Options) (*Report, error) {
	sf, err := elfx.Open(strippedPath)
	if err != nil {
		return nil, fmt.Errorf("symbolmap: open stripped: %w", err)
	}
	defer func() { _ = sf.Close() }()
	uf, err := elfx.Open(unstrippedPath)
	if err != nil {
		return nil, fmt.Errorf("symbolmap: open unstripped: %w", err)
	}
	defer func() { _ = uf.Close() }()

	if sf.Machine() != uf.Machine() {
		return nil, fmt.Errorf("symbolmap: machine mismatch: stripped=%s unstripped=%s", sf.Machine(), uf.Machine())
	}

	rep := &Report{
		StrippedPath:   strippedPath,
		UnstrippedPath: unstrippedPath,
		Machine:        sf.Machine().String(),
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
	if !rep.ExecLayoutMatch || !rep.ExecBytesMatch {
		return nil, fmt.Errorf("symbolmap: executable layout/bytes differ; inputs are not a verified stripped/unstripped pair of the same build")
	}

	symbols, symVAs, err := collectSymbols(uf)
	if err != nil {
		return nil, err
	}
	rep.UnstrippedSymCnt = len(symbols)
	if opts.ImportSymbols {
		rep.Symbols = exportSymbols(symbols, symVAs)
	}

	var callSites []CallSite
	switch sf.Machine() {
	case elf.EM_AARCH64:
		callSites = scanARM64CallSites(strippedExec, symbols, symVAs, opts.IncludeBranches)
	case elf.EM_X86_64:
		callSites = scanX86CallSites(strippedExec, symbols, symVAs, opts.IncludeBranches)
	default:
		return nil, fmt.Errorf("symbolmap: unsupported machine %s", sf.Machine())
	}

	targetCalls := make(map[uint64]int, len(callSites))
	targetBranches := make(map[uint64]int, len(callSites))
	for i := range callSites {
		cs := &callSites[i]
		if cs.Indirect || !cs.TargetValid {
			cs.Match = MatchUnresolved
			if cs.Indirect {
				rep.IndirectCount++
			}
			rep.UnresolvedCount++
			continue
		}
		kind, name, symVA, off := resolveTarget(symbols, symVAs, cs.TargetVA, opts.NearestMaxDistance)
		cs.Match = kind
		cs.SymbolName = name
		cs.SymbolVA = symVA
		cs.SymbolOffset = off
		if cs.Kind == SiteBranch {
			targetBranches[cs.TargetVA]++
		} else {
			targetCalls[cs.TargetVA]++
		}
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

	targets := make([]TargetSummary, 0, len(targetCalls)+len(targetBranches))
	seen := make(map[uint64]bool, len(targetCalls)+len(targetBranches))
	for _, cs := range callSites {
		if cs.Indirect || !cs.TargetValid {
			continue
		}
		if seen[cs.TargetVA] {
			continue
		}
		seen[cs.TargetVA] = true
		targets = append(targets, TargetSummary{
			TargetVA:     cs.TargetVA,
			CallCount:    targetCalls[cs.TargetVA],
			BranchCount:  targetBranches[cs.TargetVA],
			Match:        cs.Match,
			SymbolName:   cs.SymbolName,
			SymbolVA:     cs.SymbolVA,
			SymbolOffset: cs.SymbolOffset,
		})
	}
	sort.Slice(targets, func(i, j int) bool {
		iTotal := targets[i].CallCount + targets[i].BranchCount
		jTotal := targets[j].CallCount + targets[j].BranchCount
		if iTotal != jTotal {
			return iTotal > jTotal
		}
		return targets[i].TargetVA < targets[j].TargetVA
	})
	rep.Targets = targets

	return rep, nil
}

func collectExecSections(f *elfx.File) ([]execSection, error) {
	sections, err := f.ExecutableSections(maxExecBytes)
	if err != nil {
		return nil, fmt.Errorf("symbolmap: executable sections: %w", err)
	}
	out := make([]execSection, 0, len(sections))
	for _, s := range sections {
		out = append(out, execSection{Name: s.Name, Addr: s.Addr, Size: s.Size, Data: s.Data})
	}
	return out, nil
}

// compareExecLayouts checks whether the stripped side's exec sections
// exist at the exact same (addr, size) in the unstripped side, and if so
// whether the raw bytes match exactly.
func compareExecLayouts(stripped, unstripped []execSection) (layoutMatch, bytesMatch bool) {
	if len(stripped) == 0 || len(stripped) != len(unstripped) {
		return false, false
	}
	byKey := make(map[[2]uint64]execSection, len(unstripped))
	for _, s := range unstripped {
		byKey[[2]uint64{s.Addr, s.Size}] = s
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

// collectSymbols gathers executable function-like symbols from .symtab and
// .dynsym.  Same-VA names are aliases, not collisions to discard.  The primary
// name prefers a real function/IFUNC over STT_NOTYPE and otherwise uses a stable
// lexical tie-break so output is deterministic.
func collectSymbols(f *elfx.File) (map[uint64]symbolInfo, []uint64, error) {
	byVA := make(map[uint64]symbolInfo)
	add := func(syms []elfx.ExecutableSymbol) error {
		for _, s := range syms {
			if !isUsefulSymbolName(s.Name) {
				continue
			}
			candidate := symbolInfo{
				Name:        s.Name,
				VA:          s.Addr,
				Size:        s.Size,
				Type:        s.Type,
				Binding:     s.Binding,
				Section:     s.Section,
				SectionName: s.SectionName,
				Category:    symbolCategory(s.Name),
			}
			if existing, ok := byVA[s.Addr]; ok {
				names := append([]string{existing.Name}, existing.Aliases...)
				names = append(names, s.Name)
				names = uniqueSortedStrings(names)
				if betterPrimarySymbol(candidate, existing) {
					candidate.Aliases = removeString(names, candidate.Name)
					byVA[s.Addr] = candidate
				} else {
					existing.Aliases = removeString(names, existing.Name)
					byVA[s.Addr] = existing
				}
			} else {
				byVA[s.Addr] = candidate
			}
		}
		return nil
	}
	syms, err := f.ExecutableSymbols()
	if err != nil {
		return nil, nil, fmt.Errorf("symbolmap: executable symbols: %w", err)
	}
	if err := add(syms); err != nil {
		return nil, nil, err
	}
	vas := make([]uint64, 0, len(byVA))
	for va := range byVA {
		vas = append(vas, va)
	}
	sort.Slice(vas, func(i, j int) bool { return vas[i] < vas[j] })
	return byVA, vas, nil
}

func betterPrimarySymbol(a, b symbolInfo) bool {
	score := func(s symbolInfo) int {
		switch s.Type {
		case elf.STT_FUNC, elf.STT_GNU_IFUNC:
			return 2
		case elf.STT_NOTYPE:
			return 1
		default:
			return 0
		}
	}
	if sa, sb := score(a), score(b); sa != sb {
		return sa > sb
	}
	if (a.Size > 0) != (b.Size > 0) {
		return a.Size > 0
	}
	return a.Name < b.Name
}

func uniqueSortedStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func removeString(in []string, remove string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != remove {
			out = append(out, s)
		}
	}
	return out
}

func symbolCategory(name string) string {
	switch {
	case strings.HasPrefix(name, "stub ") || strings.HasPrefix(name, "_iso_stub_"):
		return "stub"
	case strings.HasPrefix(name, "new "):
		return "constructor"
	case strings.HasPrefix(name, "as "):
		return "cast"
	case strings.Contains(name, "Trampoline"):
		return "trampoline"
	case strings.Contains(name, "Padding"):
		return "padding"
	default:
		return ""
	}
}

func exportSymbols(symbols map[uint64]symbolInfo, sortedVAs []uint64) []SymbolRecord {
	out := make([]SymbolRecord, 0, len(sortedVAs))
	for _, va := range sortedVAs {
		s := symbols[va]
		out = append(out, SymbolRecord{
			VA:       s.VA,
			Size:     s.Size,
			Name:     s.Name,
			Aliases:  append([]string(nil), s.Aliases...),
			Type:     s.Type.String(),
			Binding:  s.Binding.String(),
			Section:  s.SectionName,
			Category: s.Category,
		})
	}
	return out
}

// resolveTarget implements exact-match-then-nearest-below-within-distance,
// via binary search over the sorted VA slice (Go equivalent of Rust's
// BTreeMap::range(..=target).next_back()).
func resolveTarget(symbols map[uint64]symbolInfo, sortedVAs []uint64, targetVA uint64, nearestMaxDistance uint64) (MatchKind, string, uint64, uint64) {
	if sym, ok := symbols[targetVA]; ok {
		return MatchExact, sym.Name, targetVA, 0
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
	sym := symbols[symVA]
	delta := targetVA - symVA
	if sym.Size > 0 && delta >= sym.Size {
		return MatchUnresolved, "", 0, 0
	}
	if delta > nearestMaxDistance {
		return MatchUnresolved, "", 0, 0
	}
	return MatchNearest, sym.Name, symVA, delta
}

// --- call/branch scanning ---

// scanChunk is a disjoint executable byte range. Ranges are partitioned at
// verified function symbols, then split to keep disassembly memory bounded.
type scanChunk struct {
	Name string
	VA   uint64
	Data []byte
}

const maxScanChunkBytes = 1 << 20

func buildARM64ScanChunks(sections []execSection, symbols map[uint64]symbolInfo, sortedVAs []uint64) []scanChunk {
	return buildScanChunksWithSplitter(sections, symbols, sortedVAs, nil)
}

// buildX86ScanChunks keeps every arbitrary size-budget split on an x86
// instruction boundary. x86 instructions are variable length; cutting at a raw
// byte offset can turn the tail of one instruction into an opcode in the next
// chunk and can silently drop a CALL/JMP that straddles the boundary.
func buildX86ScanChunks(sections []execSection, symbols map[uint64]symbolInfo, sortedVAs []uint64) []scanChunk {
	return buildScanChunksWithSplitter(sections, symbols, sortedVAs, x86.SplitAtInstructionBoundary)
}

func buildScanChunksWithSplitter(
	sections []execSection,
	symbols map[uint64]symbolInfo,
	sortedVAs []uint64,
	split func([]byte, int) int,
) []scanChunk {
	var funcs []symbolInfo
	for _, va := range sortedVAs {
		s := symbols[va]
		if s.Type == elf.STT_FUNC || s.Type == elf.STT_GNU_IFUNC {
			funcs = append(funcs, s)
		}
	}
	var out []scanChunk
	appendRange := func(sec execSection, name string, start, end uint64) {
		if start >= end || start < sec.Addr {
			return
		}
		secEnd, ok := checkedAdd64(sec.Addr, uint64(len(sec.Data)))
		if !ok || end > secEnd {
			return
		}
		for start < end {
			lo := start - sec.Addr
			remaining := end - start
			chunkLen := int(remaining)
			if remaining > maxScanChunkBytes {
				chunkLen = maxScanChunkBytes
				if split != nil {
					scanLen := chunkLen + 15
					if uint64(scanLen) > remaining {
						scanLen = int(remaining)
					}
					if n := split(sec.Data[int(lo):int(lo)+scanLen], maxScanChunkBytes); n > 0 && n <= maxScanChunkBytes {
						chunkLen = n
					}
				}
			}
			chunkEnd := start + uint64(chunkLen)
			hi := chunkEnd - sec.Addr
			out = append(out, scanChunk{Name: name, VA: start, Data: sec.Data[int(lo):int(hi)]})
			start = chunkEnd
		}
	}

	for _, sec := range sections {
		secEnd, ok := checkedAdd64(sec.Addr, uint64(len(sec.Data)))
		if !ok {
			continue
		}
		var inSec []symbolInfo
		for _, s := range funcs {
			if s.VA >= sec.Addr && s.VA < secEnd {
				inSec = append(inSec, s)
			}
		}
		cursor := sec.Addr
		for i, s := range inSec {
			if s.VA > cursor {
				appendRange(sec, "", cursor, s.VA)
			}
			if s.VA < cursor {
				continue
			}
			end := secEnd
			if s.Size > 0 {
				if sizedEnd, ok := checkedAdd64(s.VA, s.Size); ok && sizedEnd < end {
					end = sizedEnd
				}
			}
			if i+1 < len(inSec) && inSec[i+1].VA < end {
				end = inSec[i+1].VA
			}
			appendRange(sec, s.Name, s.VA, end)
			if end > cursor {
				cursor = end
			}
		}
		if cursor < secEnd {
			appendRange(sec, "", cursor, secEnd)
		}
	}
	return out
}

func checkedAdd64(a, b uint64) (uint64, bool) {
	if a > math.MaxUint64-b {
		return 0, false
	}
	return a + b, true
}

func scanARM64CallSites(sections []execSection, symbols map[uint64]symbolInfo, sortedVAs []uint64, includeBranches bool) []CallSite {
	lookup := func(addr uint64) (string, bool) {
		s, ok := symbols[addr]
		return s.Name, ok
	}
	var out []CallSite
	for _, chunk := range buildARM64ScanChunks(sections, symbols, sortedVAs) {
		insts := disasm.Disassemble(chunk.Data, disasm.Options{BaseAddr: chunk.VA, MaxSteps: len(chunk.Data)/4 + 1})
		for _, edge := range disasm.ExtractCallEdgesCFG(chunk.Name, insts, lookup, nil, nil) {
			cs := CallSite{FromVA: edge.FromPC, Kind: SiteCall, Reg: edge.Reg, Via: edge.Via}
			switch edge.Kind {
			case "bl":
				cs.TargetVA, cs.TargetValid = edge.TargetPC, edge.TargetValid
			case "blr":
				cs.Indirect = true
			default:
				continue
			}
			out = append(out, cs)
		}
		if includeBranches {
			for _, inst := range insts {
				if arm64.IsBEncoding(inst.Raw) {
					target, valid := arm64.B(inst.Raw, inst.Addr)
					out = append(out, CallSite{FromVA: inst.Addr, TargetVA: target, TargetValid: valid, Kind: SiteBranch})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FromVA < out[j].FromVA })
	return out
}

func scanX86CallSites(sections []execSection, symbols map[uint64]symbolInfo, sortedVAs []uint64, includeBranches bool) []CallSite {
	lookup := func(addr uint64) (string, bool) {
		s, ok := symbols[addr]
		return s.Name, ok
	}
	var out []CallSite
	for _, chunk := range buildX86ScanChunks(sections, symbols, sortedVAs) {
		// symbolmap intentionally has no Dart snapshot profile. Pass no version so
		// the disassembler fails closed and does not assert a dispatch-table ABI.
		res := disasm.ScanX86FunctionCFG("", chunk.Data, chunk.VA, lookup, nil, chunk.Name, nil)
		for _, edge := range res.Edges {
			cs := CallSite{FromVA: edge.FromPC, Kind: SiteCall, Reg: edge.Reg, Via: edge.Via}
			switch edge.Kind {
			case "call":
				cs.TargetVA, cs.TargetValid = edge.TargetPC, edge.TargetValid
			case "call_indirect":
				cs.Indirect = true
			default:
				continue
			}
			out = append(out, cs)
		}
		if includeBranches {
			x86.Walk(chunk.Data, chunk.VA, func(d x86.Decoded) bool {
				if !d.Bad && d.Inst.Op == x86asm.JMP {
					target, valid := x86.RelTarget(d.Inst, d.VA, d.Len)
					out = append(out, CallSite{FromVA: d.VA, TargetVA: target, TargetValid: valid, Kind: SiteBranch})
				}
				return true
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FromVA < out[j].FromVA })
	return out
}

// WriteCallSitesTSV writes one row per call site (matching flutterdec's
// symbol_call_sites.tsv shape).
func WriteCallSitesTSV(path string, sites []CallSite) error {
	data, err := encodeCallSitesTSV(sites)
	if err != nil {
		return err
	}
	if err := output.WriteFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("symbolmap: write %s: %w", path, err)
	}
	return nil
}

func encodeCallSitesTSV(sites []CallSite) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Comma = '\t'
	w.UseCRLF = false
	if err := w.Write([]string{"from_va", "target_va", "kind", "indirect", "reg", "via", "match", "symbol_name", "symbol_va", "symbol_offset"}); err != nil {
		return nil, fmt.Errorf("symbolmap: encode header: %w", err)
	}
	for _, cs := range sites {
		targetVA := ""
		if !cs.Indirect && cs.TargetValid {
			targetVA = fmt.Sprintf("0x%x", cs.TargetVA)
		}
		symbolVA := ""
		if cs.Match == MatchExact || cs.Match == MatchNearest {
			symbolVA = fmt.Sprintf("0x%x", cs.SymbolVA)
		}
		if err := w.Write([]string{
			fmt.Sprintf("0x%x", cs.FromVA), targetVA, string(cs.Kind), strconv.FormatBool(cs.Indirect),
			spreadsheetSafe(cs.Reg), spreadsheetSafe(cs.Via), string(cs.Match), spreadsheetSafe(cs.SymbolName), symbolVA, strconv.FormatUint(cs.SymbolOffset, 10),
		}); err != nil {
			return nil, fmt.Errorf("symbolmap: encode row: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("symbolmap: encode TSV: %w", err)
	}
	return buf.Bytes(), nil
}

// WriteArtifacts publishes the symbolmap directory as one generation. Optional
// artifacts omitted from the stage are absent after commit, so a stale reverse
// map can never survive a successful rerun.
func WriteArtifacts(dir string, rep *Report) error {
	if rep == nil {
		return fmt.Errorf("symbolmap: nil report")
	}
	tsv, err := encodeCallSitesTSV(rep.CallSites)
	if err != nil {
		return err
	}
	encodeJSON := func(v any) ([]byte, error) {
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(data, '\n'), nil
	}
	targets, err := encodeJSON(rep.Targets)
	if err != nil {
		return fmt.Errorf("symbolmap: encode target summary: %w", err)
	}
	report, err := encodeJSON(rep)
	if err != nil {
		return fmt.Errorf("symbolmap: encode report: %w", err)
	}

	tx, err := output.BeginDirTransaction(dir)
	if err != nil {
		return fmt.Errorf("symbolmap: begin output transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Abort()
		}
	}()
	stage := tx.StageDir()
	for _, artifact := range []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{"symbol_call_sites.tsv", tsv, 0o600},
		{"symbol_target_summary.json", targets, 0o644},
		{"symbol_map_report.json", report, 0o644},
	} {
		if err := output.WriteArtifactFile(stage, artifact.name, artifact.data, artifact.perm); err != nil {
			return fmt.Errorf("symbolmap: stage %s: %w", artifact.name, err)
		}
	}
	if rep.Symbols != nil {
		reverse, err := encodeJSON(rep.Symbols)
		if err != nil {
			return fmt.Errorf("symbolmap: encode reverse symbol map: %w", err)
		}
		if err := output.WriteArtifactFile(stage, "symbol_reverse_map.json", reverse, 0o644); err != nil {
			return fmt.Errorf("symbolmap: stage reverse symbol map: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("symbolmap: publish artifacts: %w", err)
	}
	committed = true
	return nil
}

func spreadsheetSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@':
		return "'" + s
	default:
		return s
	}
}
