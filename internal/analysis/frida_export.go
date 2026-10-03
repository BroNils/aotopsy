package analysis

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"aotopsy/internal/cli"
	"aotopsy/internal/disasm"
	"aotopsy/internal/elfx"
	"aotopsy/internal/evidence"
	"aotopsy/internal/frida"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/sdk"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/vmtables"
)

var fridaHexOffsetRE = regexp.MustCompile(`^0x[0-9A-Fa-f]+$`)

type fridaDispatchRecord struct {
	Index    int    `json:"index"`
	Kind     string `json:"kind"`
	Target   string `json:"target,omitempty"`
	SlotInfo string `json:"slot_info,omitempty"`
}

// BuildFridaMetadata builds validated Frida metadata from the exact artifacts
// produced by the pipeline. Malformed/missing mandatory artifacts are fatal:
// --from is a trust boundary, not a best-effort report reader.
func BuildFridaMetadata(ctx *AnalysisContext, dir string) (frida.FridaMetadata, error) {
	if ctx == nil || ctx.Info == nil || ctx.Info.Version == nil {
		return frida.FridaMetadata{}, fmt.Errorf("frida metadata: missing analysis context/version")
	}
	provBytes, provDigest, err := readFridaGenerationArtifact(filepath.Join(dir, ProvenanceFileName), ProvenanceFileName, maxMetadataArtifactBytes, true)
	if err != nil {
		return frida.FridaMetadata{}, fmt.Errorf("frida metadata: provenance: %w", err)
	}
	prov, err := jsonutil.DecodeStrictObject[Provenance](provBytes)
	if err != nil {
		return frida.FridaMetadata{}, fmt.Errorf("frida metadata: provenance: %w", err)
	}
	if len(prov.SHA256) != 64 || prov.Size <= 0 || prov.SourceName == "" || prov.DartVersion == "" {
		return frida.FridaMetadata{}, fmt.Errorf("frida metadata: incomplete provenance identity")
	}
	isARM64 := ctx.IsARM64
	arch := "x64"
	thrReg := sdk.X86ThreadRegStr
	ppReg := sdk.X86PoolRegStr
	dtReg := "rax"
	if isARM64 {
		arch = "arm64"
		thrReg = sdk.ARM64ThreadRegStr
		ppReg = sdk.ARM64PoolRegStr
		dtReg = "x21"
	}
	if prov.Arch != arch || prov.DartVersion != ctx.DartVersion || prov.CompressedPointers != ctx.Info.Version.CompressedPointers {
		return frida.FridaMetadata{}, fmt.Errorf("frida metadata: provenance does not match analysis context")
	}
	if ctx.EF != nil {
		sha, err := ctx.EF.SHA256()
		if err != nil {
			return frida.FridaMetadata{}, fmt.Errorf("frida metadata: hash context binary: %w", err)
		}
		if !strings.EqualFold(sha, prov.SHA256) || ctx.EF.FileSize() != prov.Size {
			return frida.FridaMetadata{}, fmt.Errorf("frida metadata: provenance SHA/size does not match context binary")
		}
	}

	bitOffset, bitWidth := snapshot.ClassIdTagLayout(ctx.DartVersion)
	heapMode, heapReg, heapTHRField := "none", "", ""
	if ctx.Info.Version.CompressedPointers {
		if isARM64 {
			if snapshot.VersionAtLeast(ctx.DartVersion, "2.14.0") {
				heapMode, heapReg = "heap_bits", sdk.ARM64HeapBitsStr
			} else {
				heapMode, heapReg = "register", sdk.ARM64HeapBaseLegacyStr
			}
		} else {
			heapMode, heapTHRField = "thread_field", "heap_base"
		}
	}
	pointerSize := 8
	if ctx.Info.Version.CompressedPointers {
		pointerSize = 4
	}
	var thrFields map[int]string
	if target, ok := vmtables.TargetProfileFromVersion(ctx.Info.Version, isARM64); ok {
		thrFields = vmtables.THRFields(target)
	}
	meta := frida.FridaMetadata{
		SchemaVersion:      frida.MetadataSchemaVersion,
		AnalyzerVersion:    cli.Version,
		AnalyzerCommit:     cli.Commit,
		SourceSHA256:       strings.ToLower(prov.SHA256),
		SourceSize:         prov.Size,
		ModuleName:         prov.SourceName,
		DartVersion:        ctx.DartVersion,
		Architecture:       arch,
		CompressedPointers: ctx.Info.Version.CompressedPointers,
		PointerSize:        pointerSize,
		THRFields:          thrFields,
		THRReg:             thrReg,
		PPReg:              ppReg,
		DTReg:              dtReg,
		HeapBaseMode:       heapMode,
		HeapBaseReg:        heapReg,
		HeapBaseTHRField:   heapTHRField,
		HeaderBitOffset:    bitOffset,
		HeaderBitWidth:     bitWidth,
	}
	meta.RuntimeIdentity, err = fridaRuntimeIdentityRegions(ctx.EF)
	if err != nil {
		return frida.FridaMetadata{}, fmt.Errorf("frida metadata: runtime identity: %w", err)
	}

	funcBytes, funcDigest, err := readFridaGenerationArtifact(filepath.Join(dir, "functions.jsonl"), "functions.jsonl", jsonutil.StandardLimits.MaxBytes, true)
	if err != nil {
		return frida.FridaMetadata{}, fmt.Errorf("frida metadata: functions: %w", err)
	}
	funcs, err := jsonutil.DecodeJSONL[disasm.FuncRecord](funcBytes, jsonutil.StandardLimits)
	if err != nil {
		return frida.FridaMetadata{}, fmt.Errorf("frida metadata: functions: %w", err)
	}
	for i, f := range funcs {
		if f.Name == "" || !fridaHexOffsetRE.MatchString(f.PC) || f.Size < 0 {
			return frida.FridaMetadata{}, fmt.Errorf("frida metadata: functions line %d has invalid pc/name/size", i+1)
		}
		meta.Functions = append(meta.Functions, frida.FridaFunction{VA: f.PC, Name: f.Name, Owner: f.Owner, Size: f.Size})
	}

	edgeBytes, edgeDigest, err := readFridaGenerationArtifact(filepath.Join(dir, "call_edges.jsonl"), "call_edges.jsonl", jsonutil.StandardLimits.MaxBytes, true)
	if err != nil {
		return frida.FridaMetadata{}, fmt.Errorf("frida metadata: call edges: %w", err)
	}
	edges, err := jsonutil.DecodeJSONL[disasm.CallEdgeRecord](edgeBytes, jsonutil.StandardLimits)
	if err != nil {
		return frida.FridaMetadata{}, fmt.Errorf("frida metadata: call edges: %w", err)
	}
	if err := frida.ValidateStaticCallEdges(edges); err != nil {
		return frida.FridaMetadata{}, fmt.Errorf("frida metadata: call edges: %w", err)
	}
	for i, e := range edges {
		if !fridaHexOffsetRE.MatchString(e.FromPC) {
			if e.Kind == "blr" || e.Kind == "call_indirect" {
				return frida.FridaMetadata{}, fmt.Errorf("frida metadata: call edge line %d has invalid from_pc %q", i+1, e.FromPC)
			}
			continue
		}
		p, ok := frida.RuntimeProbeForEdge(e)
		if !ok {
			continue // unsupported target recipe: fail closed, not wrong probe.
		}
		if p.Via == "dispatch_table" {
			p.ClassIDReg = frida.DispatchClassIDRegister(arch, ctx.DartVersion)
		}
		meta.CallProbes = append(meta.CallProbes, p)
	}

	dispatchBytes, dispatchDigest, err := readFridaGenerationArtifact(filepath.Join(dir, "dispatch_table.jsonl"), "dispatch_table.jsonl", jsonutil.StandardLimits.MaxBytes, false)
	if err != nil {
		return frida.FridaMetadata{}, fmt.Errorf("frida metadata: dispatch table: %w", err)
	}
	var dispatch []fridaDispatchRecord
	if dispatchDigest.Present {
		dispatch, err = jsonutil.DecodeJSONL[fridaDispatchRecord](dispatchBytes, jsonutil.StandardLimits)
		if err != nil {
			return frida.FridaMetadata{}, fmt.Errorf("frida metadata: dispatch table: %w", err)
		}
	}
	for _, e := range dispatch {
		if e.Kind == "code" && e.Target != "" {
			meta.DispatchTable = append(meta.DispatchTable, frida.FridaDispatchEntry{Index: e.Index, Kind: e.Kind, Target: e.Target})
		}
	}

	refBytes, refDigest, err := readFridaGenerationArtifact(filepath.Join(dir, "string_refs.jsonl"), "string_refs.jsonl", jsonutil.StandardLimits.MaxBytes, false)
	if err != nil {
		return frida.FridaMetadata{}, fmt.Errorf("frida metadata: string refs: %w", err)
	}
	var refs []disasm.StringRefRecord
	if refDigest.Present {
		refs, err = jsonutil.DecodeJSONL[disasm.StringRefRecord](refBytes, jsonutil.StandardLimits)
		if err != nil {
			return frida.FridaMetadata{}, fmt.Errorf("frida metadata: string refs: %w", err)
		}
	}
	for _, r := range refs {
		if r.Value != "" {
			meta.StringRefs = append(meta.StringRefs, frida.FridaStringRef{FromFunc: r.Func, Value: r.Value, Kind: r.Kind})
		}
	}

	evidenceBytes, evidenceDigest, err := readFridaGenerationArtifact(filepath.Join(dir, "evidence.jsonl"), "evidence.jsonl", jsonutil.StandardLimits.MaxBytes, false)
	if err != nil {
		return frida.FridaMetadata{}, fmt.Errorf("frida metadata: evidence: %w", err)
	}
	if evidenceDigest.Present {
		records, err := jsonutil.DecodeJSONL[evidence.Evidence](evidenceBytes, jsonutil.StandardLimits)
		if err != nil {
			return frida.FridaMetadata{}, fmt.Errorf("frida metadata: evidence: %w", err)
		}
		if err := evidence.NewCollectorFromRecords(ctx.DartVersion, records).ValidateStatic(); err != nil {
			return frida.FridaMetadata{}, fmt.Errorf("frida metadata: evidence: %w", err)
		}
	}

	meta.Artifacts = []frida.ArtifactDigest{provDigest, funcDigest, edgeDigest, dispatchDigest, refDigest, evidenceDigest}
	if err := frida.FinalizeMetadata(&meta); err != nil {
		return frida.FridaMetadata{}, fmt.Errorf("frida metadata: semantic validation: %w", err)
	}
	return meta, nil
}

func fridaRuntimeIdentityRegions(source *elfx.File) ([]frida.RuntimeRegionDigest, error) {
	if source == nil {
		return nil, fmt.Errorf("missing ELF source")
	}
	segments := source.LoadSegments()
	if len(segments) == 0 {
		return nil, fmt.Errorf("ELF has no load segments")
	}
	minVaddr := segments[0].Vaddr
	for _, seg := range segments[1:] {
		if seg.Vaddr < minVaddr {
			minVaddr = seg.Vaddr
		}
	}

	var regions []frida.RuntimeRegionDigest
	const maxBuildIDNoteBytes = uint64(1 << 20)
	for _, note := range source.Sections() {
		if note.Name != ".note.gnu.build-id" || note.Type != elf.SHT_NOTE || note.Size == 0 || note.Addr < minVaddr {
			continue
		}
		if !sectionIsFileBackedLoad(segments, note.Addr, note.Size) {
			continue
		}
		data, err := source.ReadSection(note.Index, maxBuildIDNoteBytes)
		if err != nil {
			return nil, fmt.Errorf("read GNU build-id note: %w", err)
		}
		regions = append(regions, runtimeRegionDigest("gnu_build_id", note.Addr-minVaddr, data))
		break
	}

	for _, seg := range segments {
		// Writable PT_LOAD bytes may be relocated by the dynamic loader. Every
		// file-backed non-writable segment is immutable after load, so hashing all
		// of them verifies code, read-only snapshot data, ELF metadata and (when
		// present) the GNU build-id without depending on Module.path being a real
		// filesystem path (Android can expose base.apk!/lib/... here).
		if seg.Flags&elf.PF_W != 0 || seg.Filesz == 0 {
			continue
		}
		if seg.Vaddr < minVaddr {
			return nil, fmt.Errorf("immutable load segment is outside supported range")
		}
		digest, err := source.HashProgram(seg.Index)
		if err != nil {
			return nil, fmt.Errorf("hash immutable load segment: %w", err)
		}
		kind := "readonly"
		if seg.Flags&elf.PF_X != 0 {
			kind = "executable"
		}
		regions = append(regions, frida.RuntimeRegionDigest{
			Kind:   kind,
			Offset: fmt.Sprintf("0x%x", seg.Vaddr-minVaddr),
			Size:   int64(seg.Filesz),
			SHA256: digest,
		})
	}
	if len(regions) == 0 {
		return nil, fmt.Errorf("ELF has no runtime-verifiable identity region")
	}
	return regions, nil
}

func sectionIsFileBackedLoad(segments []elfx.SegmentInfo, addr, size uint64) bool {
	end, carry := bits.Add64(addr, size, 0)
	if carry != 0 {
		return false
	}
	for _, seg := range segments {
		segEnd, carry := bits.Add64(seg.Vaddr, seg.Filesz, 0)
		if carry == 0 && addr >= seg.Vaddr && end <= segEnd {
			return true
		}
	}
	return false
}

func runtimeRegionDigest(kind string, offset uint64, data []byte) frida.RuntimeRegionDigest {
	sum := sha256.Sum256(data)
	return frida.RuntimeRegionDigest{
		Kind: kind, Offset: fmt.Sprintf("0x%x", offset), Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]),
	}
}

func readFridaGenerationArtifact(path, name string, limit int64, required bool) ([]byte, frida.ArtifactDigest, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if !required && os.IsNotExist(err) {
			return nil, frida.DigestArtifact(name, nil, false), nil
		}
		return nil, frida.ArtifactDigest{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, frida.ArtifactDigest{}, fmt.Errorf("%s is not a regular non-symlink file", path)
	}
	if info.Size() < 0 || info.Size() > limit {
		return nil, frida.ArtifactDigest{}, fmt.Errorf("%s is %d bytes, exceeds limit %d", path, info.Size(), limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, frida.ArtifactDigest{}, err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil {
		return nil, frida.ArtifactDigest{}, err
	}
	if !os.SameFile(info, opened) {
		return nil, frida.ArtifactDigest{}, fmt.Errorf("%s changed while being opened", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, frida.ArtifactDigest{}, err
	}
	if int64(len(b)) > limit {
		return nil, frida.ArtifactDigest{}, fmt.Errorf("%s exceeds byte limit %d", path, limit)
	}
	return b, frida.DigestArtifact(name, b, true), nil
}
