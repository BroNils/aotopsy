package naming

import (
	"aotopsy/internal/cluster"
	"aotopsy/internal/snapshot"
)

// BuildDiscardedFunctionSymbols names Instructions that have NO owning Code
// object in the snapshot -- Dart AOT release builds discard most Function's
// Code wrapper by default (Code::IsDiscarded, gated on
// FLAG_dwarf_stack_traces_mode, which Flutter enables for release builds) to
// shrink the snapshot, keeping only the raw instructions. This is the SAME
// population `cluster.ResolveStubRanges` calls "stubs" (InstructionsTable
// indices 0..FirstEntryWithCode-1) -- confirmed via dart-lang/sdk's
// FunctionSerializationCluster::WriteFill/GetCodeAndEntryPointByIndex
// (runtime/vm/app_snapshot.cc) that this is NOT a small, fixed set of VM
// runtime stubs at all: a real sample showed ~93000 such entries, i.e. most
// ordinary Dart functions in a real release build. Confirmed by name
// resolution succeeding on real production and test Dart samples after wiring
// this in (previously displayed as opaque `stub_<hex>`/`sub_<hex>`).
//
// The name is recoverable WITHOUT any Code object or external DWARF/symbols
// file: every Function object retains a `code_index` scalar (serialized
// unconditionally in FullAOT mode, right after Function's normal ref
// fields -- already captured by this project as NamedObject.CodeIndex, see
// internal/cluster/fill.go) that indexes into the SAME global numbering
// scheme Dart's own Deserializer::GetCodeAndEntryPointByIndex uses at
// runtime for stack-trace symbolication:
//
//	idx := code_index - 1          // slot 0 is reserved for LazyCompile
//	if idx < table.FirstEntryWithCode {
//	    // discarded: idx is a direct index into the InstructionsTable's
//	    // own PCOffset array (NOT the Code cluster).
//	} else {
//	    // has a real Code object; idx - FirstEntryWithCode is the
//	    // Code cluster index (the case ResolveCodeRanges already handles).
//	}
//
// `base` (non-root-unit/deferred-loading-unit code_index bias) is assumed
// 0 -- correct for a normal, non-split (`--split-debug-info`/deferred
// component) APK, which is what every real sample analyzed by this project
// so far is. A future deferred-loading-unit sample would need to thread
// `num_base_objects` through; not attempted since no such sample exists to
// verify against (this project's own "don't guess wrong" rule).
//
// This ALSO reveals a real, pre-existing bug in cmd/aotopsy/refinfo.go's
// `-find-owner-of-code-ref` (already flagged in ARCHITECTURE.md as
// "buggy for some Dart versions" without a root cause): it compares
// `no.CodeIndex == target.ClusterIndex` directly, but the real relationship
// requires subtracting both the reserved LazyCompile slot AND
// FirstEntryWithCode first, exactly as coded here.
func BuildDiscardedFunctionSymbols(named []cluster.NamedObject, ct *snapshot.CIDTable, table *cluster.InstructionsTable, pl *PoolLookups, codeVA, codeOff uint64, codeIndexOneBased bool) map[uint64]string {
	out := make(map[uint64]string)
	if table == nil || ct == nil || pl == nil {
		return out
	}
	firstEntryWithCode := int(table.FirstEntryWithCode)
	for i := range named {
		no := &named[i]
		if no.CID != ct.Function || no.CodeIndex <= 0 {
			continue
		}
		// code_index is 1-based for Dart >=2.16 (0=LazyCompile stub).
		// For <=2.15, code_index is 0-based (direct index).
		idx := no.CodeIndex
		if codeIndexOneBased {
			idx = no.CodeIndex - 1 // slot 0 reserved for LazyCompile
		}
		if idx < 0 || idx >= firstEntryWithCode || idx >= len(table.Entries) {
			continue // not a discarded entry (or out of range) -- already handled by the normal Code cluster path
		}
		name := pl.ResolveName(no)
		if name == "" {
			continue
		}
		if owner := pl.ResolveOwnerName(no); owner != "" {
			name = owner + "." + name
		}
		// X-4: Prefix constructors with "new ", mirroring BuildPoolLookups'
		// handling of non-discarded Codes (helpers.go). Without this, a
		// discarded constructor's instructions render as "MyClass.myMethod"
		// instead of "new MyClass.myMethod", making it indistinguishable from
		// an ordinary method — the exact gap measured in the session handoff:
		// 520 Function objects have kind=constructor, but only 306 own a Code
		// directly (handled by BuildPoolLookups); the remaining 214 have
		// discarded Code and were named here without the "new " prefix.
		if no.IsConstructor() && name != "" {
			name = "new " + name
		}
		funcVA := codeVA + uint64(table.Entries[idx].PCOffset) - codeOff
		out[funcVA] = name
	}
	return out
}
