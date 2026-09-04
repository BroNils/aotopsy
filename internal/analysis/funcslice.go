package analysis

import (
	"fmt"

	"aotopsy/internal/cluster"
	"aotopsy/internal/naming"
)

// FuncSlice represents a single function sliced out of an instructions image.
type FuncSlice struct {
	Range cluster.CodeRange
	Code  []byte
	VA    uint64
	Name  string // QualifiedCodeName or stub_<pcoffset>
	Owner string
}

// CodeImage encapsulates the instruction image bytes, virtual address base,
// and offset, providing unified, clamped function slicing.
type CodeImage struct {
	Code    []byte
	CodeVA  uint64
	CodeOff uint64
	Pool    *naming.PoolLookups
	ElfSyms map[uint64]string
}

// NewCodeImage constructs a CodeImage from raw image components.
func NewCodeImage(code []byte, codeVA, codeOff uint64, pool *naming.PoolLookups, elfSyms map[uint64]string) CodeImage {
	return CodeImage{
		Code:    code,
		CodeVA:  codeVA,
		CodeOff: codeOff,
		Pool:    pool,
		ElfSyms: elfSyms,
	}
}

// Slice extracts a clamped FuncSlice from a CodeRange.
// Returns false if the range is empty or falls outside the image.
func (im CodeImage) Slice(r cluster.CodeRange) (FuncSlice, bool) {
	if r.Size == 0 || uint64(r.PCOffset) < im.CodeOff {
		return FuncSlice{}, false
	}
	funcStart := uint64(r.PCOffset) - im.CodeOff
	var funcCode []byte
	if len(im.Code) > 0 {
		if funcStart >= uint64(len(im.Code)) {
			return FuncSlice{}, false
		}
		funcEnd := funcStart + uint64(r.Size)
		if funcEnd > uint64(len(im.Code)) {
			funcEnd = uint64(len(im.Code))
		}
		if funcStart >= funcEnd {
			return FuncSlice{}, false
		}
		funcCode = im.Code[funcStart:funcEnd]
	}
	funcVA := im.CodeVA + funcStart

	var funcName string
	var owner string
	if r.RefID >= 0 && im.Pool != nil {
		if ci, ok := im.Pool.CodeNames[r.RefID]; ok {
			funcName = ci.Qualified(r.PCOffset)
			owner = ci.OwnerName
		} else {
			funcName = naming.QualifiedCodeName(r.RefID, im.Pool, r.PCOffset)
		}
	} else if im.ElfSyms != nil && im.ElfSyms[funcVA] != "" {
		funcName = im.ElfSyms[funcVA]
	} else {
		funcName = fmt.Sprintf("stub_%x", r.PCOffset)
	}

	return FuncSlice{
		Range: r,
		Code:  funcCode,
		VA:    funcVA,
		Name:  funcName,
		Owner: owner,
	}, true
}

// Each iterates through ranges up to limit (or all if limit <= 0),
// invoking fn on each valid FuncSlice. If fn returns false, iteration stops.
func (im CodeImage) Each(ranges []cluster.CodeRange, limit int, fn func(FuncSlice) bool) int {
	count := 0
	for _, r := range ranges {
		if limit > 0 && count >= limit {
			break
		}
		fs, ok := im.Slice(r)
		if !ok {
			continue
		}
		count++
		if !fn(fs) {
			break
		}
	}
	return count
}
