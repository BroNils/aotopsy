package main

import (
	"fmt"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/disasm"
	"aotopsy/internal/pipeline"
	"aotopsy/internal/snapshot"
)

// This file holds the buildFuncIR logic, extracted from the 202-baris closure
// in decompile_native_cmd.go. The closure captured 20 variables from the outer
// scope; they are now explicit fields on funcIRBuilder so the function is
// testable and its dependencies are visible.

// funcIRBuilder holds the shared state needed to build a decompiler.FuncIR
// from a cluster.CodeRange. All fields are set once by the caller and read
// by Build, which is called once per function range.
type funcIRBuilder struct {
	code                   []byte
	codeOff                uint64
	codeVA                 uint64
	symbolNames            map[uint64]string
	isARM64                bool
	info                   *snapshot.Info
	buildArgRegMasks       func() map[uint64][]uint8
	paramTypeNamesFor      func(r cluster.CodeRange) []string
	genericParamNamesFor   func(r cluster.CodeRange) []string
	namedParamNamesFor     func(r cluster.CodeRange) []string
	fieldNameResolver      func(classID int, byteOffset int64) string
	closureParents         map[int]string
	pl                     *poolLookups
	paramTypeByCodeIndex   map[int]*cluster.NamedObject
	codeRefToReceiverClass map[int]int
	codeRefToExcHandlers   map[int][]cluster.ExceptionHandlerEntry
	codeRefToPcDesc        map[int][]cluster.PcDescriptorEntry
	codeRefToCSM           map[int]*cluster.CodeSourceMapInfo
	codeRefToInlinedNames  map[int][]string
	poolEntryByIndex       func(idx int) (cluster.PoolEntry, bool)
}

// Build constructs a decompiler.FuncIR from a code range, wiring all the
// per-function metadata (arg regs, thread stubs, param types, exception
// handlers, inline frames, switch cases, async detection).
func (b *funcIRBuilder) Build(r cluster.CodeRange) (*decompiler.FuncIR, error) {
	funcStart := uint64(r.PCOffset) - b.codeOff
	funcEnd := funcStart + uint64(r.Size)
	if funcEnd > uint64(len(b.code)) {
		funcEnd = uint64(len(b.code))
	}
	if funcStart >= funcEnd {
		return nil, fmt.Errorf("empty function range")
	}
	funcCode := b.code[funcStart:funcEnd]
	funcVA := b.codeVA + funcStart
	name := b.symbolNames[funcVA]

	var fir *decompiler.FuncIR
	if b.isARM64 {
		insts := disasm.Disassemble(funcCode, disasm.Options{BaseAddr: funcVA})
		fir = decompiler.BuildARM64IR(name, insts)
	} else {
		xinsts := decompiler.DecodeX86Range(funcCode, funcVA)
		fir = decompiler.BuildX86IR(name, xinsts)
	}
	if masks, ok := b.buildArgRegMasks()[funcVA]; ok {
		if regIdx, confident := resolveArgRegIndices(masks); confident {
			fir.ArgRegIndices = regIdx
		}
	}
	fir.ThreadStubOffsets = disasm.ThreadStubOffsets(b.info.Version.DartVersion, b.isARM64)
	fir.ThreadFieldNames = pipeline.ThreadFieldOffsets(b.info.Version.DartVersion, b.isARM64, b.info.Version)
	fir.ParamTypeNames = b.paramTypeNamesFor(r)
	fir.TypeParamNames = b.genericParamNamesFor(r)
	// Item 11: Named parameter names for named optional parameters.
	if b.namedParamNamesFor != nil {
		fir.NamedParamNames = b.namedParamNamesFor(r)
	}
	fir.FieldNameResolver = b.fieldNameResolver

	// A1: Local variable type inference from ParamTypeNames.
	if len(fir.ParamTypeNames) > 0 {
		fir.LocalTypeHints = make(map[string]string)
		for i, typeName := range fir.ParamTypeNames {
			if typeName != "" {
				fir.LocalTypeHints[fmt.Sprintf("arg%d", i)] = typeName
			}
		}
	}
	// A2: Set ReceiverClassID from codeRefToReceiverClass map.
	if r.RefID >= 0 {
		if cid, ok := b.codeRefToReceiverClass[r.RefID]; ok && cid > 0 {
			fir.ReceiverClassID = cid
		}
	}
	if len(b.closureParents) > 0 && r.RefID >= 0 {
		ce := cluster.CodeEntry{RefID: r.RefID, OwnerRef: r.OwnerRef, ClusterIndex: r.Index}
		if owner, ok := pipeline.ResolveCodeOwner(ce, b.pl.RefToNamed, b.paramTypeByCodeIndex); ok {
			parent := b.closureParents[owner.RefID]
			if parent != "" && parent != fir.Name &&
				!strings.HasPrefix(fir.Name, parent+"_") {
				fir.EnclosingFunction = parent
			}
		}
	}
	// Wire exception handlers from cluster capture → decompiler FuncIR.
	if handlers, ok := b.codeRefToExcHandlers[r.RefID]; ok {
		fir.ExceptionHandlers = make([]decompiler.ExceptionHandlerEntry, len(handlers))
		for i, h := range handlers {
			fir.ExceptionHandlers[i] = decompiler.ExceptionHandlerEntry{
				PCOffset:        h.PCOffset,
				OuterTryIndex:   h.OuterTryIndex,
				NeedsStacktrace: h.NeedsStacktrace,
				HasCatchAll:     h.HasCatchAll,
				IsGenerated:     h.IsGenerated,
			}
		}

		if entries, ok := b.codeRefToPcDesc[r.RefID]; ok && len(entries) > 0 {
			regions := cluster.BuildTryRegions(entries, r.Size)
			regions = cluster.ExpandOuterTryRegions(regions, handlers)
			for _, reg := range regions {
				if reg.TryIndex < 0 || reg.TryIndex >= len(fir.ExceptionHandlers) {
					continue
				}
				h := fir.ExceptionHandlers[reg.TryIndex]
				fir.TryRegions = append(fir.TryRegions, decompiler.TryRegionEntry{
					StartVA:   funcStart + b.codeVA + uint64(reg.StartPC),
					EndVA:     funcStart + b.codeVA + uint64(reg.EndPC),
					TryIndex:  reg.TryIndex,
					Handler:   h,
					HandlerVA: funcStart + b.codeVA + uint64(h.PCOffset),
				})
			}
			fir.SnapTryRegionsToBlocks()
		}
	}

	// Inlined-frame annotation.
	if csm, ok := b.codeRefToCSM[r.RefID]; ok && csm != nil && len(fir.Blocks) > 0 {
		names := b.codeRefToInlinedNames[r.RefID]
		for bi := range fir.Blocks {
			blockVA := fir.Blocks[bi].StartVA
			pcOff := uint32(blockVA - b.codeVA)
			stack, _, ok := csm.InlineStackAt(pcOff)
			if !ok || len(stack) == 0 {
				continue
			}
			var frames []string
			for _, id := range stack {
				if int(id) < len(names) && names[id] != "" {
					frames = append(frames, names[id])
				}
			}
			if len(frames) == 0 {
				continue
			}
			if fir.InlineFrames == nil {
				fir.InlineFrames = make(map[uint64][]string)
			}
			fir.InlineFrames[blockVA] = frames
		}
	}
	// P6: Switch/case recovery — detect IndirectGoto pattern (br xN).
	if b.isARM64 && len(fir.Blocks) > 0 {
		for bi := range fir.Blocks {
			for _, ins := range fir.Blocks[bi].Instrs {
				if ins.Op != decompiler.OpJump || strings.HasPrefix(ins.Target, "0x") || ins.Target == "" {
					continue
				}
				var cases []decompiler.SwitchCase
				for ci := bi + 1; ci < len(fir.Blocks) && len(cases) < 64; ci++ {
					cases = append(cases, decompiler.SwitchCase{
						Index:   len(cases),
						BlockID: fir.Blocks[ci].ID,
					})
				}
				if len(cases) >= 2 {
					fir.SwitchCases = cases
				}
				break
			}
		}
	}

	// P7: Async/await detection via SuspendState CID in pool loads.
	if !fir.IsAsync && b.info.Version.CIDs.SuspendState != 0 {
		for bi := range fir.Blocks {
			for _, ins := range fir.Blocks[bi].Instrs {
				if ins.Op != decompiler.OpLoadPool || ins.PoolIndex < 0 {
					continue
				}
				if pe, ok := b.poolEntryByIndex(ins.PoolIndex); ok {
					if cid, ok2 := b.pl.RefCID[pe.RefID]; ok2 && cid == b.info.Version.CIDs.SuspendState {
						fir.IsAsync = true
						break
					}
				}
			}
			if fir.IsAsync {
				break
			}
		}
	}

	return fir, nil
}
