package analysis

import (
	"fmt"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/naming"
	"aotopsy/internal/snapshot"
)

// SymbolNameSet is the VA-keyed naming of every code range in a snapshot.
type SymbolNameSet struct {
	// Names maps a function's start VA to its display name, covering every
	// CodeRange: Dart functions, isolate and VM stubs, and discarded-code
	// functions.
	Names map[uint64]string
	// VMForm carries the VM's own spelling for the addresses where it
	// differs from the display name -- currently type-testing stubs. Not an
	// output; the symtab differential compares against whichever notation a
	// given ELF dialect uses. Sparse.
	VMForm map[uint64]string
	// Sizes maps a function's start VA to its byte size.
	Sizes map[uint64]uint32
}

// BuildSymbolNames names every code range once, for every caller.
//
// This existed three times -- LoadContext, RunDisasmStage and
// RunDisasmStageX86 -- with the copies' own comments pointing at each other
// ("mirrors LoadContext's pattern", "Same pattern as RunDisasmStage and
// LoadContext"). Triplicated naming means a name recovered in one place is
// missing in the other two, and that is exactly what happened to the isolate
// stubs: teaching LoadContext about them left the pipeline still emitting
// `sub_<pcOffset>` into functions.jsonl, call_edges.jsonl and the signal
// graph.
//
// isolateData may be nil, in which case isolate stubs are not named. Every
// other input is required.
func BuildSymbolNames(
	ranges []cluster.CodeRange,
	image cluster.CodeImage,
	pl *naming.PoolLookups,
	clResult *cluster.Result,
	info *snapshot.Info,
	table *cluster.InstructionsTable,
	fmtOpts dartfmt.Options,
	isolateData []byte,
) SymbolNameSet {
	out := SymbolNameSet{
		Names:  make(map[uint64]string, len(ranges)),
		VMForm: make(map[uint64]string),
		Sizes:  make(map[uint64]uint32, len(ranges)),
	}

	// Isolate stubs: their Code objects have no owner, so the only place
	// their name survives is the ObjectStore field list in the roots
	// section. See naming.BuildIsolateStubSymbols.
	var isoStubs map[int]string
	if len(isolateData) > 0 {
		if err := cluster.ReadObjectStoreRefs(isolateData, clResult, info.Version); err != nil {
			clResult.ObjectStoreRefs = nil
		}
		isoStubs = naming.BuildIsolateStubSymbols(clResult, info.Version.DartVersion)
	}

	// A type-testing stub's Code has the tested Type as its owner
	// (type_testing_stubs.cc, `code.set_owner(type)`).
	ttsOwnerByCodeRef := make(map[int]int, len(clResult.Codes))
	for _, ce := range clResult.Codes {
		if ce.OwnerRef >= 0 {
			ttsOwnerByCodeRef[ce.RefID] = ce.OwnerRef
		}
	}

	for _, r := range ranges {
		va, ok := image.FuncVA(r)
		if !ok {
			continue
		}
		out.Sizes[va] = r.Size
		if r.RefID < 0 {
			out.Names[va] = fmt.Sprintf("stub_%x", r.PCOffset)
			continue
		}
		if n, ok := isoStubs[r.RefID]; ok {
			out.Names[va] = n
			continue
		}
		out.Names[va] = naming.QualifiedCodeName(r.RefID, pl, r.PCOffset)
		if owner, ok := ttsOwnerByCodeRef[r.RefID]; ok {
			if vm := pl.TypeTestingStubSDKNames[owner]; vm != "" {
				out.VMForm[va] = vm
			}
		}
	}
	for va, name := range naming.BuildVMStubSymbols(info, fmtOpts) {
		out.Names[va] = name
	}
	for va, name := range naming.BuildDiscardedFunctionSymbols(
		clResult.Named, info.Version.CIDs, table, pl,
		image.CodeVA, image.CodeOff, info.Version.CodeIndexOneBased) {
		out.Names[va] = name
	}
	return out
}
