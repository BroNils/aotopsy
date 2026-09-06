package analysis

import (
	"encoding/json"
	"fmt"
	"os"

	"aotopsy/internal/cluster"
	"aotopsy/internal/disasm"
	"aotopsy/internal/naming"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/thraudit"
	"aotopsy/internal/vmtables"
)

// THRAuditData holds the pre-loaded snapshot data needed for THR audit.
type THRAuditData struct {
	Info    *snapshot.Info
	IsARM64 bool
	Result  *cluster.Result
	Ranges  []cluster.CodeRange
	Code    []byte
	CodeOff uint64
	CodeVA  uint64
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
	fmt.Fprintf(os.Stderr, "Dart SDK version: %s\n", dartVersion)

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

	byCodeIndex := naming.CodeIndexToFunc(data.Result, data.Info.Version.CIDs, data.Info.Version.CodeIndexOneBased)
	codeNames := make(map[int]naming.CodeNameInfo)
	for _, ce := range data.Result.Codes {
		owner, ok := naming.ResolveCodeOwner(ce, refToNamed, byCodeIndex)
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

	thrFields := vmtables.THRFields(dartVersion, isARM64)

	// Open output.
	outFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer func() { _ = outFile.Close() }()
	enc := json.NewEncoder(outFile)
	enc.SetEscapeHTML(false)

	sample := libapp

	n := len(data.Ranges)
	if limit > 0 && limit < n {
		n = limit
	}

	var totalAccesses, resolvedCount, unresolvedCount int

	for i := range n {
		r := &data.Ranges[i]
		fs, ok := data.Slice(*r)
		if !ok {
			continue
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
			records = disasm.BuildAuditRecords(accesses, insts, sample, dartVersion, funcName)
		} else {
			accesses := disasm.ExtractX86THRAccesses(funcCode, funcVA, thrFields)
			if len(accesses) == 0 {
				continue
			}
			insts := disasm.DecodeX86Simple(funcCode, funcVA)
			records = disasm.BuildX86AuditRecords(accesses, insts, sample, dartVersion, funcName)
		}
		for _, rec := range records {
			if err := enc.Encode(rec); err != nil {
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

	fmt.Fprintf(os.Stderr, "THR accesses: %d total, %d resolved, %d unresolved\n",
		totalAccesses, resolvedCount, unresolvedCount)
	fmt.Fprintf(os.Stderr, "wrote %s\n", outPath)

	return nil
}
