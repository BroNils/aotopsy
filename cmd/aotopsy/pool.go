package main

import (
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/pipeline"
	"aotopsy/internal/snapshot"
)

type poolLookups = pipeline.PoolLookups

func buildPoolLookups(result *cluster.Result, ct *snapshot.CIDTable, vmResult *cluster.Result, codeIndexOneBased bool) *poolLookups {
	return pipeline.BuildPoolLookups(result, ct, vmResult, codeIndexOneBased)
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
