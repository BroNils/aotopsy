package naming

// This file merges vmstubs.go, discardedfuncs.go, typeteststubs.go, and ttscall.go
// into a single stubs.go for reduced file count.

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/vmtables"
)

// BuildVMStubSymbols parses the VM-isolate snapshot region (info.VmData,
// a separate stream from the app's own isolate snapshot -- see
// ARCHITECTURE.md's "Stub naming" section) and returns a VA->name map for
// stub Code objects with a known name (vmtables.VMStubNames). The VM
// isolate's Code cluster order matches VM_STUB_CODE_LIST's macro
// expansion order exactly (verified against two real compiled samples:
// index 0 is always a ~12-byte function, consistent with the trivially
// small GetCStackPointer), so result.Codes[i] (in its ORIGINAL,
// creation-order slice position -- NOT cluster.ResolveCodeRanges' output,
// which is sorted by PCOffset instead) is named names[i].
//
// Returns an empty map (never nil) on any failure or unverified version --
// this is a best-effort convenience layered on top of the existing
// stub_<hex>/sub_<hex> fallback, not a required pipeline step.
func BuildVMStubSymbols(info *snapshot.Info, opts dartfmt.Options) map[uint64]string {
	debug := os.Getenv("AOTOPSY_DEBUG_VMSTUBS") != ""
	out := make(map[uint64]string)
	names := vmtables.VMStubNamesInImageOrder(info.Version.DartVersion)
	if names == nil || len(info.VmData.Data) == 0 || info.VmHeader == nil || len(info.VmInstructions.Data) == 0 {
		if debug {
			fmt.Fprintf(os.Stderr, "vmstubs: names=%v vmDataLen=%d vmHeader=%v vmInstrLen=%d\n", names != nil, len(info.VmData.Data), info.VmHeader != nil, len(info.VmInstructions.Data))
		}
		return out
	}

	clusterStart, err := cluster.FindClusterDataStart(info.VmData.Data)
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "vmstubs: FindClusterDataStart: %v\n", err)
		}
		return out
	}
	result, err := cluster.ScanClusters(info.VmData.Data, clusterStart, info.Version, true, opts)
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "vmstubs: ScanClusters: %v\n", err)
		}
		return out
	}
	if err := cluster.ReadFill(info.VmData.Data, result, info.Version, true, 0); err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "vmstubs: ReadFill: %v\n", err)
		}
		return out
	}
	table, err := cluster.ParseInstructionsTable(info.VmData.Data, &result.Header, info.Version, info.VmHeader)
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "vmstubs: ParseInstructionsTable: %v\n", err)
		}
		return out
	}
	ranges, err := cluster.ResolveCodeRanges(result.Codes, table)
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "vmstubs: ResolveCodeRanges: %v\n", err)
		}
		return out
	}
	_, codeOff, payloadLen, err := snapshot.CodeRegion(info.VmInstructions.Data)
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "vmstubs: CodeRegion: %v\n", err)
		}
		return out
	}
	if debug {
		fmt.Fprintf(os.Stderr, "vmstubs: codes=%d ranges=%d names=%d\n", len(result.Codes), len(ranges), len(names))
	}
	codeEndOffset := uint32(codeOff) + uint32(payloadLen) //nolint:gosec // codeOff/payloadLen are offsets within one already-loaded snapshot payload, always well under 2^32
	cluster.SetLastRangeSize(ranges, codeEndOffset)
	codeVA := info.VmInstructions.VA + codeOff

	// Zip names against ranges sorted by ADDRESS, not by Code-cluster index.
	//
	// This used to walk result.Codes in cluster order and assign names[i],
	// which put VM_STUB_CODE_LIST entry 0 (`JumpToFrame`) at the lowest
	// address. The symbol table of a 3.12.2 build says `JumpToFrame` is at
	// the HIGHEST: the image is laid out in reverse, and the 9
	// type-testing stubs sit in the middle rather than in an unnamed tail.
	// Every name was wrong. See vmtables.VMStubNamesInImageOrder for the
	// derivation and the ground truth it came from.
	sorted := make([]cluster.CodeRange, len(ranges))
	copy(sorted, ranges)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PCOffset < sorted[j].PCOffset })

	if len(sorted) != len(names) && debug {
		// A mismatch means the composed list and the image disagree about
		// how many stubs exist, so the zip is offset and every name after
		// the divergence is wrong. Report it rather than emit them.
		fmt.Fprintf(os.Stderr, "vmstubs: %d ranges but %d composed names -- refusing to name\n",
			len(sorted), len(names))
	}
	if len(sorted) != len(names) {
		return out
	}

	for i, r := range sorted {
		funcVA := codeVA + uint64(r.PCOffset) - codeOff
		out[funcVA] = names[i]
	}
	return out
}

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
		// FP-5: Deferred loading unit support would subtract a base bias
		// here, but NumBaseObjects from the cluster header is NOT that bias —
		// it is the count of VM-isolate base objects already accounted for in
		// ref numbering. The deferred loading unit bias comes from a separate
		// Deserializer field not available in the cluster header. Until a
		// deferred loading unit sample exists, this remains a no-op.
		if idx < 0 || idx >= firstEntryWithCode || idx >= len(table.Entries) {
			continue // not a discarded entry (or out of range) -- already handled by the normal Code cluster path
		}
		name := pl.ResolveName(no)
		if name == "" {
			name = pl.ResolveVMName(no)
		}
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

// Type-testing stubs.
//
// A Code whose owner is neither a Function nor a Class looked like corrupt
// data, and the residue was large: after every other naming path had run,
// 409 of 8045 Codes on the 3.9.2 ARM64 sample still had no name, and 100 %
// of them failed the same way -- no Function claimed their cluster index,
// and Code.OwnerRef pointed at an object that is not in RefToNamed.
//
// Measured rather than guessed, the OwnerRefs split cleanly in two:
//
//	324  point at a Type (CID 49), each at a DIFFERENT one
//	 85  all share ref 1, which is Object::null() in every version
//
// The first group is not corruption. dart-lang/sdk, verified at tag 3.9.2:
//
//	runtime/vm/type_testing_stubs.cc
//	  const char* name = namer_.StubNameForType(type);
//	  ...
//	  code.set_owner(type);              // <- the owner IS the type
//
// So these are type-testing stubs, and the SDK names them
// `TypeTestingStub_<library url>_<Class>[__<type argument>...]`
// (TypeTestingStubNamer::WriteStubNameForTypeTo). They were rendering as
// `sub_<pcOffset>`.
//
// The second group is a Code with a genuinely null owner. Nothing in the
// isolate snapshot names it, so it stays a placeholder -- an honest one.
//
// KNOWN LIMITATION, measured before shipping rather than discovered after.
// Naming these requires Type -> type_class_id, which only lands in
// Result.Types for the v3.x flags-packed encoding. On versions where
// type_class_id is its own ref (VersionProfile.TypeClassIdIsRef, v2.10-2.15)
// it is not resolved anywhere in this pipeline, and the failure is silent
// and total rather than partial: a real Dart 2.12.0 sample resolved 251 of
// 251 type-owned Codes to a real-looking name, but to a SINGLE distinct
// class ("TypeParameters") for all 251. That is worse than no name -- it
// invents 251 confident, wrong labels -- so this is switched off there and
// those Codes keep the `sub_` placeholder. The same 3.x samples resolve 260
// and 271 distinct classes out of 324 and 339, which is what working looks
// like.

// buildTypeTestingStubNames maps a Type's reference ID to the display name
// for the stub that tests it. Returns nil when the Dart version cannot
// resolve a Type to its class, in which case callers simply find nothing.
func buildTypeTestingStubNames(result *cluster.Result, l *PoolLookups, ct *snapshot.CIDTable, typeClassIDIsRef bool) map[int]string {
	// typeClassIdIsRef (Dart 2.10-2.15): Type.type_class_id is a Smi ref,
	// not a scalar packed into the "flags" word. resolveTypeClassIDs
	// (called in BuildTypeContext) fills ClassID from MintValues, but on
	// a real 2.12.0 sample ALL 251 type-owned Codes resolved to the SAME
	// class ("TypeParameters") — 251 confident wrong labels is worse than
	// 251 honest sub_ placeholders, so naming stays OFF for these versions.
	if typeClassIDIsRef {
		return nil
	}
	if len(result.Types) == 0 {
		return nil
	}
	classNames := make(map[int32]string)
	for i := range result.Classes {
		ci := result.Classes[i]
		no, ok := l.RefToNamed[ci.RefID]
		if !ok {
			continue
		}
		name := l.ResolveName(no)
		if name == "" {
			name = l.ResolveVMName(no)
		}
		if name != "" {
			classNames[ci.ClassID] = name
		}
	}
	out := make(map[int]string, len(result.Types))
	for _, t := range result.Types {
		name, ok := classNames[t.ClassID]
		if !ok && ct != nil {
			// Predefined/builtin classes have no snapshot-side Class record
			// name; the SDK's own table covers them.
			name = cluster.CidNameV(int(t.ClassID), ct)
		}
		if name == "" {
			continue
		}
		out[t.RefID] = fmt.Sprintf("TypeTestingStub_%s", name)
	}
	return out
}

// Indirect calls that invoke a type-testing stub.
//
// dart-lang/sdk, verified at tag 3.12.2,
// runtime/vm/compiler/backend/flow_graph_compiler_x64.cc:
//
//	void FlowGraphCompiler::GenerateIndirectTTSCall(Assembler* assembler,
//	                                                Register reg_to_call,
//	                                                intptr_t sub_type_cache_index) {
//	  __ LoadWordFromPoolIndex(TypeTestABI::kSubtypeTestCacheReg,
//	                           sub_type_cache_index);
//	  __ Call(compiler::FieldAddress(
//	      reg_to_call,
//	      compiler::target::AbstractType::type_test_stub_entry_point_offset()));
//	}
//
// `reg_to_call` holds the AbstractType, so the callee is that type's testing
// stub -- the same stub named in typeteststubs.go.
//
// On the 3.12.2 x86_64 sample every one of the 1128 `CALL [reg+disp]` sites
// uses the SAME displacement, 0x7, because both shapes that reach an entry
// point through a field are at offset 8 with the heap tag subtracted:
// Code::entry_point_offset and AbstractType::type_test_stub_entry_point_offset.
// The displacement therefore says nothing about which of the two it is; only
// what the register holds does. Of those 1128:
//
//	405  the register came from a pool <vm:Code>   -- a VM stub, still unnamed
//	111  the register came from a pool Type        -- resolved here
//	491  the register came from an object field    -- a runtime type, so there
//	                                                  is no static answer
//	121  no provenance recovered
//
// Only the 111 are resolvable without inventing anything, and this handles
// exactly those.

// viaPoolIndex matches the provenance annotation the disassembler attaches to
// a register loaded from the object pool: "pp[123]" or "pp[123] <Type>".
var viaPoolIndex = regexp.MustCompile(`^pp\[(\d+)\]`)

// BuildTTSCallTargets maps an object-pool INDEX to the type-testing stub name
// for the type in that slot, for slots that hold a Type at all. Returns nil
// when no type-testing stub names are available, so callers resolve nothing
// rather than guessing.
func BuildTTSCallTargets(pool []cluster.PoolEntry, pl *PoolLookups) map[int]string {
	if pl == nil || len(pl.TypeTestingStubNames) == 0 {
		return nil
	}
	out := make(map[int]string)
	for _, pe := range pool {
		if pe.Kind != cluster.PoolTagged {
			continue
		}
		if name, ok := pl.TypeTestingStubNames[pe.RefID]; ok {
			out[pe.Index] = name
		}
	}
	return out
}

// TtsCallTarget returns the type-testing stub a call site invokes, given the
// provenance annotation of the called register, or "" when the site is not
// one of these.
func TtsCallTarget(via string, byPoolIndex map[int]string) string {
	if len(byPoolIndex) == 0 {
		return ""
	}
	m := viaPoolIndex.FindStringSubmatch(via)
	if m == nil {
		return ""
	}
	idx, err := strconv.Atoi(m[1])
	if err != nil {
		return ""
	}
	return byPoolIndex[idx]
}
