package main

import (
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/disasm"
	"aotopsy/internal/pipeline"
	"aotopsy/internal/snapshot"
)

type poolLookups = pipeline.PoolLookups

func buildPoolLookups(result *cluster.Result, ct *snapshot.CIDTable, vmResult *cluster.Result, codeIndexOneBased bool, dartVersion string, typeClassIDIsRef bool) *poolLookups {
	return pipeline.BuildPoolLookups(result, ct, vmResult, codeIndexOneBased, dartVersion, typeClassIDIsRef)
}

// threadFieldOffsets adapts internal/disasm's Thread field table (keyed by
// int offset) to the int64 keys the decompiler's memory-displacement handling
// uses. Returns nil when no table covers the version, which leaves THR
// accesses rendering as THR.fNN.
func threadFieldOffsets(dartVersion string, isARM64 bool, profile *snapshot.VersionProfile) map[int64]string {
	src := disasm.THRFieldsWithProfile(dartVersion, isARM64, profile)
	if len(src) == 0 {
		return nil
	}
	out := make(map[int64]string, len(src))
	for off, name := range src {
		out[int64(off)] = name
	}
	return out
}

func resolvePoolDisplay(pool []cluster.PoolEntry, l *poolLookups) map[int]string {
	return pipeline.ResolvePoolDisplay(pool, l)
}

func buildVMStubSymbols(info *snapshot.Info, opts dartfmt.Options) map[uint64]string {
	return pipeline.BuildVMStubSymbols(info, opts)
}

func buildDiscardedFunctionSymbols(named []cluster.NamedObject, ct *snapshot.CIDTable, table *cluster.InstructionsTable, l *poolLookups, codeVA, codeOff uint64, codeIndexOneBased bool) map[uint64]string {
	return pipeline.BuildDiscardedFunctionSymbols(named, ct, table, l, codeVA, codeOff, codeIndexOneBased)
}
