package pipeline

import (
	"fmt"

	"aotopsy/internal/cluster"
)

// ResolvedDispatchEntry is one DispatchTable slot with its real name
// resolved via this project's existing VA->name symbol table, closing
// the gap ARCHITECTURE.md's "DispatchTable parsing" investigation
// identified: `EmitDispatchTableCall` computes its target purely from
// `class_id + selector_offset`, with no name in the instruction stream
// at all -- this recovers the real target name statically, without
// executing anything.
type ResolvedDispatchEntry struct {
	Index int
	Kind  cluster.DispatchTableEntryKind
	// Name is the resolved function/stub name for DispatchCode/
	// DispatchStub entries (ctx.SymbolNames' own display strings, e.g.
	// "MyClass.myMethod_1a2b3c" or "stub_4d5e"), empty for DispatchNull
	// or if the target ClusterIndex/StubIndex isn't in ctx.Ranges at all
	// (should not happen for a correctly-parsed table; surfaced as
	// empty rather than silently guessing).
	Name string
}

// ResolveDispatchTable parses ctx's DispatchTable (see
// cluster.ParseDispatchTable) and resolves every non-null entry to a
// real name via ctx.Ranges/ctx.SymbolNames -- the same symbol table
// every other command in this project already uses.
//
// Returns an error if ctx.InstrTable is nil (see Context.InstrTable's
// doc comment) or if this Dart version's ObjectStore roots-section
// layout hasn't been verified (see snapshot.VersionProfile.
// ObjectStoreAOTFieldCount's doc comment) -- never a silent guess.
func ResolveDispatchTable(ctx *Context) ([]ResolvedDispatchEntry, error) {
	// TARGET 3: For Dart 2.x (no InstructionsTable), pass nil to
	// ParseDispatchTable which will use the first_code_id fallback.
	// For Dart 3.x, InstrTable is required.
	if ctx.InstrTable == nil && ctx.Info.Version.CodeTextOffsetDelta {
		// Dart 2.x: use TextOffset fallback (first_code_id based).
		raw, err := cluster.ParseDispatchTable(ctx.Info.IsolateData.Data, ctx.Result, ctx.Info.Version, nil)
		if err != nil {
			return nil, err
		}
		return resolveDispatchEntries(ctx, raw), nil
	}
	if ctx.InstrTable == nil {
		return nil, fmt.Errorf("dispatch table: no InstructionsTable available for this snapshot")
	}

	raw, err := cluster.ParseDispatchTable(ctx.Info.IsolateData.Data, ctx.Result, ctx.Info.Version, ctx.InstrTable)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	return resolveDispatchEntries(ctx, raw), nil
}

// resolveDispatchEntries converts raw DispatchTableEntry slice to resolved
// entries with function names. TARGET 3: also handles 2.x fallback entries
// that have CodeRef/OwnerRef instead of ClusterIndex.
func resolveDispatchEntries(ctx *Context, raw []cluster.DispatchTableEntry) []ResolvedDispatchEntry {
	// byClusterIndex covers DispatchCode targets (real Dart functions).
	// byStubIndex covers DispatchStub targets.
	byClusterIndex := make(map[int]string, len(ctx.Ranges))
	byStubIndex := make(map[int]string, len(ctx.Ranges))
	for _, r := range ctx.Ranges {
		funcStart := uint64(r.PCOffset) - ctx.CodeOff
		funcVA := ctx.CodeVA + funcStart
		name := ctx.SymbolNames[funcVA]
		if r.RefID < 0 {
			byStubIndex[r.Index] = name
		} else {
			byClusterIndex[r.Index] = name
		}
	}

	// TARGET 3: For 2.x fallback, build refID → function name map.
	byCodeRef := make(map[int]string, len(ctx.Ranges))
	for _, r := range ctx.Ranges {
		if r.RefID >= 0 {
			funcStart := uint64(r.PCOffset) - ctx.CodeOff
			funcVA := ctx.CodeVA + funcStart
			byCodeRef[r.RefID] = ctx.SymbolNames[funcVA]
		}
	}

	resolved := make([]ResolvedDispatchEntry, len(raw))
	for i, e := range raw {
		re := ResolvedDispatchEntry{Index: e.Index, Kind: e.Kind}
		switch e.Kind {
		case cluster.DispatchCode:
			if e.CodeRef > 0 {
				// TARGET 3: 2.x fallback — resolve by CodeRef.
				re.Name = byCodeRef[e.CodeRef]
			}
			if re.Name == "" {
				re.Name = byClusterIndex[e.ClusterIndex]
			}
		case cluster.DispatchStub:
			re.Name = byStubIndex[e.StubIndex]
		}
		resolved[i] = re
	}
	return resolved
}
