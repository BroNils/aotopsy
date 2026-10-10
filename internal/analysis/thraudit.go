package analysis

import (
	"fmt"
	"math"
	"path/filepath"

	"aotopsy/internal/cli"
	"aotopsy/internal/cluster"
	"aotopsy/internal/disasm"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/naming"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/thraudit"
	"aotopsy/internal/vmtables"
)

// THRAuditData holds the pre-loaded snapshot data needed for THR audit.
type THRAuditData struct {
	Info         *snapshot.Info
	IsARM64      bool
	SampleSHA256 string
	Result       *cluster.Result
	Table        *cluster.InstructionsTable
	Ranges       []cluster.CodeRange
	Code         []byte
	CodeOff      uint64
	CodeVA       uint64
}

// Image returns a CodeImage providing unified function slicing.
func (d THRAuditData) Image() CodeImage {
	return CodeImage{
		CodeImage: cluster.CodeImage{Code: d.Code, CodeVA: d.CodeVA, CodeOff: d.CodeOff},
	}
}

// Slice extracts a clamped FuncSlice from a CodeRange within this THRAuditData.
func (d THRAuditData) Slice(r cluster.CodeRange) (FuncSlice, bool) {
	return d.Image().Slice(r)
}

// RunTHRAudit scans every function for THR-relative memory accesses
// and writes the results as JSONL to outPath. Takes pre-loaded data.
func RunTHRAudit(data THRAuditData, libapp, outPath string, limit int) error {
	isARM64 := data.IsARM64
	dartVersion := ""
	if data.Info.Version != nil {
		dartVersion = data.Info.Version.DartVersion
	}
	cli.Errf("Dart SDK version: %s\n", dartVersion)

	// Build name lookup.
	refToStr := make(map[int]string)
	for _, ps := range data.Result.Strings {
		refToStr[ps.RefID] = ps.Value
	}

	refToNamed := make(map[int]*cluster.NamedObject)
	for i := range data.Result.Named {
		no := &data.Result.Named[i]
		refToNamed[no.RefID] = no
	}

	resolveName := func(no *cluster.NamedObject) string {
		if no.NameRefID >= 0 {
			if s, ok := refToStr[no.NameRefID]; ok {
				return s
			}
		}
		return ""
	}

	resolveOwnerName := func(no *cluster.NamedObject) string {
		if no.OwnerRefID < 0 {
			return ""
		}
		if owner, ok := refToNamed[no.OwnerRefID]; ok {
			return resolveName(owner)
		}
		return ""
	}

	firstEntryWithCode := -1
	if data.Table != nil {
		firstEntryWithCode = int(data.Table.FirstEntryWithCode)
	}
	byCodeIndex := naming.CodeIndexToFunc(data.Result, data.Info.Version.CIDs, data.Info.Version.CodeIndexOneBased, firstEntryWithCode)
	codeNames := make(map[int]naming.CodeNameInfo)
	for _, ce := range data.Result.Codes {
		owner, ok := naming.ResolveCodeOwner(ce, refToNamed, byCodeIndex, data.Info.Version.CIDs)
		if !ok {
			continue
		}
		fn := resolveName(owner)
		isCtor := owner.IsConstructor()
		if isCtor && fn != "" {
			fn = "new " + fn
		}
		codeNames[ce.RefID] = naming.CodeNameInfo{
			FuncName:      fn,
			OwnerName:     resolveOwnerName(owner),
			IsConstructor: isCtor,
		}
	}

	// Build symbol map.
	symbols := make(map[uint64]string)
	im := data.Image()
	for _, r := range data.Ranges {
		va, ok := im.FuncVA(r)
		if !ok {
			continue
		}
		symbols[va] = codeNames[r.RefID].Qualified(r.PCOffset)
	}
	lookup := disasm.PlaceholderLookup(symbols)

	targetProfile, ok := vmtables.TargetProfileFromVersion(data.Info.Version, isARM64)
	if !ok {
		return fmt.Errorf("select THR audit target profile: missing snapshot version profile")
	}
	thrFields := vmtables.THRFields(targetProfile)
	if len(thrFields) == 0 {
		return fmt.Errorf("select THR audit table: no exact table for Dart %s arch=%v compressed=%v build=%s",
			targetProfile.DartVersion, targetProfile.Architecture, targetProfile.CompressedPointers, targetProfile.BuildMode.String())
	}
	arch := thraudit.ArchX64
	if isARM64 {
		arch = thraudit.ArchARM64
	}
	provenance := thraudit.Provenance{
		Sample:             filepath.Base(libapp),
		SampleSHA256:       data.SampleSHA256,
		DartVersion:        targetProfile.DartVersion,
		Arch:               arch,
		BuildMode:          targetProfile.BuildMode.String(),
		CompressedPointers: targetProfile.CompressedPointers,
	}

	writer, err := jsonutil.NewJSONLWriter[thraudit.THRAuditRecord](outPath)
	if err != nil {
		return fmt.Errorf("create audit output: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = writer.Abort()
		}
	}()

	n := len(data.Ranges)
	if limit > 0 && limit < n {
		n = limit
	}

	var totalAccesses, resolvedCount, unresolvedCount int

	for i := range n {
		r := &data.Ranges[i]
		fs, ok := data.Image().SliceExact(*r)
		if !ok {
			return fmt.Errorf("invalid code range ref=%d pc_off=0x%x size=%d", r.RefID, r.PCOffset, r.Size)
		}
		funcCode := fs.Code
		funcVA := fs.VA

		funcName := codeNames[r.RefID].Qualified(r.PCOffset)

		var records []thraudit.THRAuditRecord
		if isARM64 {
			insts := disasm.Disassemble(funcCode, disasm.Options{
				BaseAddr: funcVA,
				Symbols:  lookup,
			})
			accesses := disasm.ExtractTHRAccesses(insts, thrFields)
			if len(accesses) == 0 {
				continue
			}
			records = disasm.BuildAuditRecords(accesses, insts, provenance, funcName)
		} else {
			accesses := disasm.ExtractX86THRAccesses(funcCode, funcVA, thrFields)
			if len(accesses) == 0 {
				continue
			}
			insts := disasm.DecodeX86Simple(funcCode, funcVA)
			records = disasm.BuildX86AuditRecords(accesses, insts, provenance, funcName)
		}
		for _, rec := range records {
			if err := writer.Write(&rec); err != nil {
				return fmt.Errorf("write record: %w", err)
			}
			totalAccesses++
			if rec.Resolved {
				resolvedCount++
			} else {
				unresolvedCount++
			}
		}
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("commit audit output: %w", err)
	}
	committed = true

	cli.Errf("THR accesses: %d total, %d resolved, %d unresolved\n",
		totalAccesses, resolvedCount, unresolvedCount)
	cli.Errf("wrote %s\n", outPath)

	return nil
}

// CheckedCodeEndOffset converts the instructions payload extent into the
// uint32 coordinate system used by CodeRange without allowing truncation or
// wraparound.
func CheckedCodeEndOffset(codeOff, payloadLen uint64) (uint32, error) {
	if codeOff > math.MaxUint32 || payloadLen > math.MaxUint32 {
		return 0, fmt.Errorf("code range extent overflows uint32: off=%d len=%d", codeOff, payloadLen)
	}
	end := codeOff + payloadLen
	if end < codeOff || end > math.MaxUint32 {
		return 0, fmt.Errorf("code range extent overflows uint32: off=%d len=%d", codeOff, payloadLen)
	}
	return uint32(end), nil
}
