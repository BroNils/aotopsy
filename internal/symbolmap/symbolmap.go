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
	"encoding/binary"
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
	"aotopsy/internal/elfx"
	"aotopsy/internal/output"
	"aotopsy/internal/snapshot"
)

// MatchKind classifies how a call-site's target VA was resolved.
type MatchKind string

const (
	MatchExact          MatchKind = "exact"
	MatchNearest        MatchKind = "nearest"
	MatchUnresolved     MatchKind = "unresolved"
	ReportSchemaVersion           = 1
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
	SchemaVersion     int             `json:"schema_version"`
	StrippedPath      string          `json:"stripped_path"`
	UnstrippedPath    string          `json:"unstripped_path"`
	Machine           string          `json:"machine"`
	StrippedBuildID   string          `json:"stripped_build_id"`
	UnstrippedBuildID string          `json:"unstripped_build_id"`
	BuildIDMatch      bool            `json:"build_id_match"`
	ExecLayoutMatch   bool            `json:"exec_layout_match"`
	ExecBytesMatch    bool            `json:"exec_bytes_match"`
	UnstrippedSymCnt  int             `json:"unstripped_symbol_count"`
	Symbols           []SymbolRecord  `json:"symbols,omitempty"`
	CallSites         []CallSite      `json:"call_sites"`
	Targets           []TargetSummary `json:"targets"`
	ExactCount        int             `json:"exact_count"`
	NearestCount      int             `json:"nearest_count"`
	UnresolvedCount   int             `json:"unresolved_count"`
	IndirectCount     int             `json:"indirect_count"`
	Notes             []string        `json:"notes,omitempty"`
}

type execSection struct {
	Index  int
	Name   string
	Type   elf.SectionType
	Addr   uint64
	Size   uint64
	Offset uint64
	Flags  elf.SectionFlag
	Align  uint64
	Data   []byte
}

type symbolInfo struct {
	Name        string
	VA          uint64
	Size        uint64
	Type        elf.SymType
	Binding     elf.SymBind
	Section     elf.SectionIndex
	SectionName string
	SectionEnd  uint64
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
	if sf.StaticSymbolsPresent() {
		return nil, fmt.Errorf("symbolmap: stripped input still carries a static .symtab; refusing to use it as the recovery side")
	}
	if !uf.StaticSymbolsPresent() {
		return nil, fmt.Errorf("symbolmap: unstripped input has no static .symtab ground truth")
	}

	rep := &Report{
		SchemaVersion:  ReportSchemaVersion,
		StrippedPath:   strippedPath,
		UnstrippedPath: unstrippedPath,
		Machine:        sf.Machine().String(),
	}
	strippedBuildID, err := sf.GNUBuildID()
	if err != nil {
		return nil, fmt.Errorf("symbolmap: stripped GNU build-id: %w", err)
	}
	unstrippedBuildID, err := uf.GNUBuildID()
	if err != nil {
		return nil, fmt.Errorf("symbolmap: unstripped GNU build-id: %w", err)
	}
	rep.StrippedBuildID = strippedBuildID.ID
	rep.UnstrippedBuildID = unstrippedBuildID.ID
	rep.BuildIDMatch = strippedBuildID.ID == unstrippedBuildID.ID
	if err := requireSameBuildID(strippedBuildID, unstrippedBuildID); err != nil {
		return nil, err
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
	strippedCode, err := snapshotCodeSections(sf, strippedExec)
	if err != nil {
		return nil, err
	}

	symbols, symVAs, nearestVAs, err := collectSymbols(uf, unstrippedExec)
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
		callSites, err = scanARM64CallSites(strippedCode, opts.IncludeBranches)
	case elf.EM_X86_64:
		callSites, err = scanX86CallSites(strippedCode, opts.IncludeBranches)
	default:
		return nil, fmt.Errorf("symbolmap: unsupported machine %s", sf.Machine())
	}
	if err != nil {
		return nil, err
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
		kind, name, symVA, off := resolveTarget(symbols, nearestVAs, cs.TargetVA, opts.NearestMaxDistance)
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

// snapshotCodeSections narrows executable Images to the actual machine-code
// payload using only mapped metadata from the stripped side. This is the
// oracle-independent replacement for the old .symtab-driven function chunking:
// x86 in particular must not start decoding at Image/InstructionsSection header
// bytes, because those bytes can form a syntactically valid false CALL.
func snapshotCodeSections(f *elfx.File, sections []execSection) ([]execSection, error) {
	identity, err := snapshot.ExtractIdentity(f)
	if err != nil {
		return nil, fmt.Errorf("symbolmap: stripped snapshot identity: %w", err)
	}
	profile := snapshot.DetectVersion(identity.SnapshotHash)
	if !snapshot.IsExactSupportedProfile(profile) {
		return nil, fmt.Errorf("symbolmap: snapshot hash %s has no exact supported instructions-image profile", identity.SnapshotHash)
	}

	names := []string{snapshot.SymVmSnapshotInstructions, snapshot.SymIsolateSnapshotInstructions}
	if identity.Unified {
		names = []string{snapshot.SymUnifiedSnapshotText}
	}
	out := make([]execSection, 0, len(names))
	matchedSections := make(map[int]bool, len(sections))
	type snapshotRange struct{ lo, hi uint64 }
	var ranges []snapshotRange
	for _, name := range names {
		addr, size, err := f.DynamicSnapshotSymbol(name)
		if err != nil {
			return nil, fmt.Errorf("symbolmap: stripped snapshot text %s: %w", name, err)
		}
		if size == 0 {
			return nil, fmt.Errorf("symbolmap: stripped snapshot text %s has zero size", name)
		}
		symEnd, ok := checkedAdd64(addr, size)
		if !ok {
			return nil, fmt.Errorf("symbolmap: stripped snapshot text %s range overflows", name)
		}
		for _, r := range ranges {
			if addr < r.hi && r.lo < symEnd {
				return nil, fmt.Errorf("symbolmap: snapshot text %s overlaps another snapshot text range", name)
			}
		}
		ranges = append(ranges, snapshotRange{lo: addr, hi: symEnd})
		var sec *execSection
		for i := range sections {
			candidate := &sections[i]
			secEnd, ok := checkedAdd64(candidate.Addr, candidate.Size)
			if ok && addr >= candidate.Addr && symEnd <= secEnd {
				if sec != nil {
					return nil, fmt.Errorf("symbolmap: snapshot text %s matches multiple executable sections", name)
				}
				sec = candidate
			}
		}
		if sec == nil {
			return nil, fmt.Errorf("symbolmap: snapshot text %s [0x%x,+0x%x) is not contained in one executable section", name, addr, size)
		}
		matchedSections[sec.Index] = true
		delta := addr - sec.Addr
		if delta > uint64(len(sec.Data)) || size > uint64(len(sec.Data))-delta {
			return nil, fmt.Errorf("symbolmap: snapshot text %s exceeds executable section bytes", name)
		}
		image := sec.Data[int(delta):int(delta+size)]
		code, codeOff, payloadLen, err := snapshot.CodeRegion(image, profile)
		if err != nil {
			return nil, fmt.Errorf("symbolmap: snapshot code region %s: %w", name, err)
		}
		if payloadLen == 0 || uint64(len(code)) != payloadLen || codeOff > size || payloadLen > size-codeOff {
			return nil, fmt.Errorf("symbolmap: invalid snapshot code bounds for %s: offset=0x%x payload=0x%x image=0x%x", name, codeOff, payloadLen, size)
		}
		codeVA, ok := checkedAdd64(addr, codeOff)
		if !ok {
			return nil, fmt.Errorf("symbolmap: snapshot code VA overflows for %s", name)
		}
		imageFileOff, ok := checkedAdd64(sec.Offset, delta)
		if !ok {
			return nil, fmt.Errorf("symbolmap: snapshot image file offset overflows for %s", name)
		}
		codeFileOff, ok := checkedAdd64(imageFileOff, codeOff)
		if !ok {
			return nil, fmt.Errorf("symbolmap: snapshot code file offset overflows for %s", name)
		}
		out = append(out, execSection{
			Index: sec.Index, Name: sec.Name, Type: sec.Type, Addr: codeVA, Size: payloadLen,
			Offset: codeFileOff, Flags: sec.Flags, Align: sec.Align, Data: code,
		})
	}
	if len(matchedSections) != len(sections) {
		return nil, fmt.Errorf("symbolmap: executable section set contains %d section(s) with no snapshot text identity; refusing unclassified code scan", len(sections)-len(matchedSections))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out, nil
}

func requireSameBuildID(stripped, unstripped elfx.BuildIDEvidence) error {
	if len(stripped.Conflicts) != 0 || stripped.ID == "" {
		return fmt.Errorf("symbolmap: stripped input has no unique GNU build-id: %s", strings.Join(stripped.Conflicts, "; "))
	}
	if len(unstripped.Conflicts) != 0 || unstripped.ID == "" {
		return fmt.Errorf("symbolmap: unstripped input has no unique GNU build-id: %s", strings.Join(unstripped.Conflicts, "; "))
	}
	if stripped.ID != unstripped.ID {
		return fmt.Errorf("symbolmap: GNU build-id mismatch: stripped=%s unstripped=%s", stripped.ID, unstripped.ID)
	}
	return nil
}

func collectExecSections(f *elfx.File) ([]execSection, error) {
	sections, err := f.ExecutableSections(maxExecBytes)
	if err != nil {
		return nil, fmt.Errorf("symbolmap: executable sections: %w", err)
	}
	out := make([]execSection, 0, len(sections))
	for _, s := range sections {
		out = append(out, execSection{
			Index: s.Index, Name: s.Name, Type: s.Type, Addr: s.Addr, Size: s.Size,
			Offset: s.Offset, Flags: s.Flags, Align: s.Addralign, Data: s.Data,
		})
	}
	return out, nil
}

// compareExecLayouts requires the executable section map itself to match, not
// merely a bag of same-sized byte ranges. Section name, type, VA, size, file
// offset, flags and alignment are part of the verified-build boundary; only
// after that structural identity is established are the raw bytes compared.
func compareExecLayouts(stripped, unstripped []execSection) (layoutMatch, bytesMatch bool) {
	if len(stripped) == 0 || len(stripped) != len(unstripped) {
		return false, false
	}
	layoutMatch = true
	bytesMatch = true
	for i, s := range stripped {
		u := unstripped[i]
		if s.Name != u.Name || s.Type != u.Type || s.Addr != u.Addr || s.Size != u.Size ||
			s.Offset != u.Offset || s.Flags != u.Flags || s.Align != u.Align {
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

// collectSymbols gathers executable function-like symbols from the verified
// unstripped twin's static .symtab only. Same-VA names are aliases, not
// collisions to discard. Terminal zero-size labels at the end of an executable
// section are excluded because they name no executable byte.
//
// allVAs drives deterministic export. nearestVAs contains only FUNC/IFUNC
// starts: STT_NOTYPE labels may be exact branch targets, but must never make an
// unrelated following address look like a high-confidence function match.
func collectSymbols(f *elfx.File, execSections []execSection) (map[uint64]symbolInfo, []uint64, []uint64, error) {
	byVA := make(map[uint64]symbolInfo)
	sectionEnds := make(map[elf.SectionIndex]uint64, len(execSections))
	for _, sec := range execSections {
		end, ok := checkedAdd64(sec.Addr, sec.Size)
		if !ok {
			return nil, nil, nil, fmt.Errorf("symbolmap: executable section %q overflows VA space", sec.Name)
		}
		sectionEnds[elf.SectionIndex(sec.Index)] = end
	}
	add := func(syms []elfx.ExecutableSymbol) error {
		for _, s := range syms {
			if !isUsefulSymbolName(s.Name) {
				continue
			}
			sectionEnd, ok := sectionEnds[s.Section]
			if !ok {
				return fmt.Errorf("symbolmap: symbol %q references executable section %d absent from verified layout", s.Name, s.Section)
			}
			if s.Addr >= sectionEnd {
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
				SectionEnd:  sectionEnd,
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
	syms, err := f.StaticExecutableSymbols()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("symbolmap: static executable symbols: %w", err)
	}
	if err := add(syms); err != nil {
		return nil, nil, nil, err
	}
	allVAs := make([]uint64, 0, len(byVA))
	for va := range byVA {
		allVAs = append(allVAs, va)
	}
	sort.Slice(allVAs, func(i, j int) bool { return allVAs[i] < allVAs[j] })
	nearestVAs := make([]uint64, 0, len(allVAs))
	for _, va := range allVAs {
		s := byVA[va]
		if isCallableSymbol(s) {
			nearestVAs = append(nearestVAs, va)
		}
	}
	nextSymbolInSection := make(map[uint64]uint64, len(allVAs))
	nextBySection := make(map[elf.SectionIndex]uint64, len(execSections))
	for i := len(allVAs) - 1; i >= 0; i-- {
		va := allVAs[i]
		s := byVA[va]
		if next, ok := nextBySection[s.Section]; ok {
			nextSymbolInSection[va] = next
		}
		nextBySection[s.Section] = va
	}
	for _, va := range nearestVAs {
		s := byVA[va]
		if s.Size > 0 {
			end, ok := checkedAdd64(s.VA, s.Size)
			if !ok || end > s.SectionEnd {
				return nil, nil, nil, fmt.Errorf("symbolmap: symbol %q exceeds verified executable section", s.Name)
			}
			s.SectionEnd = end
		} else {
			end := s.SectionEnd
			if next, ok := nextSymbolInSection[va]; ok && next < end {
				end = next
			}
			s.SectionEnd = end
		}
		byVA[va] = s
	}
	return byVA, allVAs, nearestVAs, nil
}

func isCallableSymbol(s symbolInfo) bool {
	if s.Type != elf.STT_FUNC && s.Type != elf.STT_GNU_IFUNC {
		return false
	}
	return !isSnapshotContainerSymbol(s)
}

func isSnapshotContainerSymbol(s symbolInfo) bool {
	switch s.Name {
	case snapshot.SymVmSnapshotInstructions, snapshot.SymIsolateSnapshotInstructions, snapshot.SymUnifiedSnapshotText:
		// Older Dart ELF writers encode whole snapshot instruction Images as
		// STT_FUNC. They are containers whose leading bytes are object headers,
		// not callable functions; retain them in reverse-map metadata only.
		return true
	default:
		return false
	}
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
func resolveTarget(symbols map[uint64]symbolInfo, nearestVAs []uint64, targetVA uint64, nearestMaxDistance uint64) (MatchKind, string, uint64, uint64) {
	if sym, ok := symbols[targetVA]; ok && !isSnapshotContainerSymbol(sym) {
		return MatchExact, sym.Name, targetVA, 0
	}
	if nearestMaxDistance == 0 || len(nearestVAs) == 0 {
		return MatchUnresolved, "", 0, 0
	}
	// Largest function/IFUNC VA <= targetVA.
	idx := sort.Search(len(nearestVAs), func(i int) bool { return nearestVAs[i] > targetVA })
	if idx == 0 {
		return MatchUnresolved, "", 0, 0
	}
	symVA := nearestVAs[idx-1]
	sym := symbols[symVA]
	delta := targetVA - symVA
	if targetVA >= sym.SectionEnd {
		return MatchUnresolved, "", 0, 0
	}
	if delta > nearestMaxDistance {
		return MatchUnresolved, "", 0, 0
	}
	return MatchNearest, sym.Name, symVA, delta
}

// --- call/branch scanning ---

// scanChunk is a disjoint executable byte range. It is derived exclusively
// from the stripped executable sections; unstripped .symtab addresses are not
// allowed to influence decode boundaries or provenance on the side being
// measured.
type scanChunk struct {
	VA   uint64
	Data []byte
}

const maxScanChunkBytes = 1 << 20

func buildARM64ScanChunks(sections []execSection) []scanChunk {
	return buildScanChunksWithSplitter(sections, nil)
}

// buildX86ScanChunks keeps every arbitrary size-budget split on an x86
// instruction boundary. x86 instructions are variable length; cutting at a raw
// byte offset can turn the tail of one instruction into an opcode in the next
// chunk and can silently drop a CALL/JMP that straddles the boundary.
func buildX86ScanChunks(sections []execSection) []scanChunk {
	return buildScanChunksWithSplitter(sections, x86.SplitAtInstructionBoundary)
}

func buildScanChunksWithSplitter(
	sections []execSection,
	split func([]byte, int) int,
) []scanChunk {
	var out []scanChunk
	appendRange := func(sec execSection, start, end uint64) {
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
			out = append(out, scanChunk{VA: start, Data: sec.Data[int(lo):int(hi)]})
			start = chunkEnd
		}
	}

	for _, sec := range sections {
		secEnd, ok := checkedAdd64(sec.Addr, uint64(len(sec.Data)))
		if !ok {
			continue
		}
		appendRange(sec, sec.Addr, secEnd)
	}
	return out
}

func checkedAdd64(a, b uint64) (uint64, bool) {
	if a > math.MaxUint64-b {
		return 0, false
	}
	return a + b, true
}

func scanARM64CallSites(sections []execSection, includeBranches bool) ([]CallSite, error) {
	for _, sec := range sections {
		if sec.Addr&3 != 0 || len(sec.Data)%4 != 0 {
			return nil, fmt.Errorf("symbolmap: ARM64 executable section %q is not 4-byte aligned/bounded", sec.Name)
		}
	}
	var out []CallSite
	for _, chunk := range buildARM64ScanChunks(sections) {
		for off := 0; off < len(chunk.Data); off += 4 {
			pc := chunk.VA + uint64(off)
			raw := binary.LittleEndian.Uint32(chunk.Data[off : off+4])
			if arm64.IsBLEncoding(raw) {
				target, valid := arm64.BL(raw, pc)
				out = append(out, CallSite{FromVA: pc, TargetVA: target, TargetValid: valid, Kind: SiteCall})
				continue
			}
			if rn, ok := arm64.BLR(raw); ok {
				out = append(out, CallSite{FromVA: pc, Kind: SiteCall, Indirect: true, Reg: fmt.Sprintf("X%d", rn)})
				continue
			}
			if includeBranches {
				if target, ok := arm64.B(raw, pc); ok {
					out = append(out, CallSite{FromVA: pc, TargetVA: target, TargetValid: true, Kind: SiteBranch})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FromVA < out[j].FromVA })
	return out, nil
}

func scanX86CallSites(sections []execSection, includeBranches bool) ([]CallSite, error) {
	var out []CallSite
	for _, chunk := range buildX86ScanChunks(sections) {
		x86.Walk(chunk.Data, chunk.VA, func(d x86.Decoded) bool {
			if d.Bad {
				return true
			}
			if d.Inst.Op == x86asm.CALL {
				if _, direct := d.Inst.Args[0].(x86asm.Rel); direct {
					target, valid := x86.RelTarget(d.Inst, d.VA, d.Len)
					out = append(out, CallSite{FromVA: d.VA, TargetVA: target, TargetValid: valid, Kind: SiteCall})
					return true
				}
				cs := CallSite{FromVA: d.VA, Kind: SiteCall, Indirect: true}
				if mem, ok := d.Inst.Args[0].(x86asm.Mem); ok {
					cs.Reg = x86.FormatMemoryTarget(mem)
				} else if d.Inst.Args[0] != nil {
					cs.Reg = d.Inst.Args[0].String()
				}
				out = append(out, cs)
				return true
			}
			if includeBranches && d.Inst.Op == x86asm.JMP {
				if target, ok := x86.RelTarget(d.Inst, d.VA, d.Len); ok {
					out = append(out, CallSite{FromVA: d.VA, TargetVA: target, TargetValid: true, Kind: SiteBranch})
				}
			}
			return true
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FromVA < out[j].FromVA })
	return out, nil
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
	if rep.SchemaVersion != ReportSchemaVersion {
		return fmt.Errorf("symbolmap: report schema version %d, want %d", rep.SchemaVersion, ReportSchemaVersion)
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
