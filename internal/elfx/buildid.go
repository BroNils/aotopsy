package elfx

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const (
	maxBuildIDNoteBytes   = 1 << 20
	maxBuildIDNoteRegions = 128
)

// BuildIDEvidence is the bounded GNU build-id identity recovered from mapped
// ELF note data. ID is empty when no unique identity can be established.
// Conflicts are kept explicit rather than choosing one competing note.
type BuildIDEvidence struct {
	ID        string
	Source    string
	Conflicts []string
}

// GNUBuildID hand-parses NT_GNU_BUILD_ID notes from runtime-mapped evidence.
// PT_NOTE is primary. Allocated SHT_NOTE sections are only accepted when their
// VA/offset/size agree with the unique file-backed PT_LOAD mapping. Arbitrary
// section-table-only bytes are not identity evidence.
func (f *File) GNUBuildID() (BuildIDEvidence, error) {
	if f == nil || f.elfFile == nil {
		return BuildIDEvidence{}, fmt.Errorf("elfx: unavailable ELF")
	}
	if err := f.checkStable(); err != nil {
		return BuildIDEvidence{}, err
	}
	ptIDs := make(map[string]bool, 2)
	mappedSectionIDs := make(map[string]bool, 2)
	addIDs := func(dst map[string]bool, found []string) {
		for _, id := range found {
			if id == "" || dst[id] {
				continue
			}
			if len(dst) < 2 {
				dst[id] = true
			}
		}
	}

	progRegions := 0
	for _, p := range f.Programs() {
		if p.Type != elf.PT_NOTE || p.Filesz == 0 {
			continue
		}
		progRegions++
		if progRegions > maxBuildIDNoteRegions {
			return BuildIDEvidence{}, fmt.Errorf("PT_NOTE count exceeds limit %d", maxBuildIDNoteRegions)
		}
		if p.Filesz > maxBuildIDNoteBytes {
			return BuildIDEvidence{}, fmt.Errorf("PT_NOTE %d size %d exceeds limit %d", p.Index, p.Filesz, maxBuildIDNoteBytes)
		}
		data, err := f.ReadProgram(p.Index, maxBuildIDNoteBytes)
		if err != nil {
			return BuildIDEvidence{}, fmt.Errorf("read PT_NOTE %d: %w", p.Index, err)
		}
		found, err := parseBuildIDNotes(data, binary.LittleEndian)
		if err != nil {
			return BuildIDEvidence{}, fmt.Errorf("parse PT_NOTE %d: %w", p.Index, err)
		}
		addIDs(ptIDs, found)
	}

	sectionRegions := 0
	for _, s := range f.Sections() {
		if s.Type != elf.SHT_NOTE || s.Size == 0 || strings.HasPrefix(s.Name, ".zdebug_") {
			continue
		}
		if !mappedFileBackedSection(f, s) {
			continue
		}
		sectionRegions++
		if sectionRegions > maxBuildIDNoteRegions {
			return BuildIDEvidence{}, fmt.Errorf("mapped SHT_NOTE count exceeds limit %d", maxBuildIDNoteRegions)
		}
		if s.Size > maxBuildIDNoteBytes {
			return BuildIDEvidence{}, fmt.Errorf("mapped SHT_NOTE %q size %d exceeds limit %d", s.Name, s.Size, maxBuildIDNoteBytes)
		}
		data, err := f.ReadSection(s.Index, maxBuildIDNoteBytes)
		if err != nil {
			return BuildIDEvidence{}, fmt.Errorf("read mapped SHT_NOTE %q: %w", s.Name, err)
		}
		found, err := parseBuildIDNotes(data, binary.LittleEndian)
		if err != nil {
			return BuildIDEvidence{}, fmt.Errorf("parse mapped SHT_NOTE %q: %w", s.Name, err)
		}
		addIDs(mappedSectionIDs, found)
	}

	id, source, conflicts := resolveBuildIDEvidence(ptIDs, mappedSectionIDs)
	return BuildIDEvidence{ID: id, Source: source, Conflicts: conflicts}, nil
}

func mappedFileBackedSection(f *File, s SectionInfo) bool {
	if f == nil || s.Flags&elf.SHF_ALLOC == 0 || s.Type == elf.SHT_NOBITS || s.Size == 0 {
		return false
	}
	off, err := f.VAToFileOffset(s.Addr)
	if err != nil || off != s.Offset {
		return false
	}
	remaining, err := f.FileBackedRemaining(s.Addr)
	return err == nil && s.Size <= remaining
}

func resolveBuildIDEvidence(ptIDs, mappedSectionIDs map[string]bool) (string, string, []string) {
	pt := sortedBuildIDs(ptIDs)
	sht := sortedBuildIDs(mappedSectionIDs)
	var conflicts []string
	if len(pt) > 1 {
		conflicts = append(conflicts, fmt.Sprintf("conflicting GNU build-id notes from pt_note: %s", strings.Join(pt, ", ")))
	}
	if len(sht) > 1 {
		conflicts = append(conflicts, fmt.Sprintf("conflicting GNU build-id notes from mapped_sht_note: %s", strings.Join(sht, ", ")))
	}
	if len(conflicts) != 0 {
		return "", "", conflicts
	}
	switch {
	case len(pt) == 1 && len(sht) == 1:
		if pt[0] != sht[0] {
			return "", "", []string{fmt.Sprintf("conflicting GNU build-id evidence: pt_note=%s mapped_sht_note=%s", pt[0], sht[0])}
		}
		return pt[0], "pt_note+mapped_sht_note", nil
	case len(pt) == 1:
		return pt[0], "pt_note", nil
	case len(sht) == 1:
		return sht[0], "mapped_sht_note", nil
	default:
		return "", "", nil
	}
}

func sortedBuildIDs(ids map[string]bool) []string {
	keys := make([]string, 0, len(ids))
	for id := range ids {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	return keys
}

func parseBuildIDNotes(data []byte, bo binary.ByteOrder) ([]string, error) {
	off := 0
	var ids []string
	for off < len(data) {
		if len(data)-off < 12 {
			if allZeroBytes(data[off:]) {
				return ids, nil
			}
			return nil, fmt.Errorf("truncated ELF note header at offset %d", off)
		}
		namesz := bo.Uint32(data[off:])
		descsz := bo.Uint32(data[off+4:])
		ntype := bo.Uint32(data[off+8:])
		off += 12
		if uint64(namesz) > uint64(len(data)-off) {
			return nil, fmt.Errorf("ELF note name at offset %d exceeds region", off)
		}
		nameEnd := off + int(namesz)
		rawName := data[off:nameEnd]
		exactGNUOwner := namesz == 4 && bytes.Equal(rawName, []byte{'G', 'N', 'U', 0})
		off = align4(nameEnd)
		if off > len(data) {
			return nil, fmt.Errorf("ELF note name padding exceeds region")
		}
		if uint64(descsz) > uint64(len(data)-off) {
			return nil, fmt.Errorf("ELF note descriptor at offset %d exceeds region", off)
		}
		descEnd := off + int(descsz)
		desc := data[off:descEnd]
		off = align4(descEnd)
		if off > len(data) {
			return nil, fmt.Errorf("ELF note descriptor padding exceeds region")
		}
		if exactGNUOwner && ntype == 3 {
			id := hex.EncodeToString(desc)
			if id != "" && !containsString(ids, id) && len(ids) < 2 {
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}

func allZeroBytes(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func align4(n int) int { return (n + 3) &^ 3 }
