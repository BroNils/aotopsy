// Package funcdiff compares source-identity-shaped Dart Function descriptors
// between two libapp.so builds using parsed AOT snapshot metadata, and reports
// raw instruction-byte equality separately. Descriptor matches are not claims
// that Dart source semantics are equivalent, and byte differences are not
// claims that Dart source semantics changed.
package funcdiff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/naming"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/strutil"
)

// FuncDescriptor is the source-identity-shaped bucket for one or more Dart
// Function objects. It is intentionally structured instead of a formatted key:
// library URI, owner, declaration name, Function kind and enclosing closure
// ancestry have different semantics and must not alias because one component
// happens to contain a display delimiter.
//
// RefID/CodeIndex are deliberately absent because they are snapshot-local. A
// descriptor is still not guaranteed unique: PRODUCT AOT does not preserve a
// source token position for every supported version, so sibling anonymous
// closures can legitimately collide. FuncSet is therefore a MULTISET.
type FuncDescriptor struct {
	LibraryURI string `json:"library_uri"`
	Owner      string `json:"owner"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Enclosing  string `json:"enclosing,omitempty"`
}

func (d FuncDescriptor) String() string {
	s := fmt.Sprintf("%s::%s::%s [kind=%s]", d.LibraryURI, d.Owner, d.Name, d.Kind)
	if d.Enclosing != "" {
		s += " [enclosing=" + d.Enclosing + "]"
	}
	return s
}

// FuncInfo holds one resolved Function occurrence plus raw instruction evidence.
//
// CodeSize used to be CodeEntry.PayloadInfo, which is not a size. The SDK
// writes it as
//
//	payload_info = (unchecked_offset << 1) | has_monomorphic_entrypoint
//
// (app_snapshot.cc, serializer around line 8488 / deserializer 9625), so
// it is the unchecked-entry offset with a flag in the low bit -- a codegen
// property. Treating it as body identity confuses entry layout with actual
// instruction bytes. The real size comes from the instructions table, and
// InstrHash distinguishes same-length byte sequences.
//
// Note what InstrHash is and is not. It is a hash of the instruction
// bytes, so it flags any byte difference -- including one caused purely by
// object-pool renumbering between builds, since pool indices are encoded
// in the instructions. It answers "are these bytes identical", not "did
// the source change". Treat a hash difference as "worth looking at", not
// as proof of a semantic edit.
type FuncInfo struct {
	RefID     int
	CodeSize  int64  // instruction bytes, from cluster.CodeRange.Size
	InstrHash string // SHA-256 of those bytes; "" when the code is unavailable
}

// FuncSet preserves every Function object. A descriptor can map to multiple
// entries and DiffDescriptors performs deterministic multiset matching.
type FuncSet map[FuncDescriptor][]FuncInfo

// IdentityStats makes descriptor coverage explicit. Strict snapshot parsing can
// still leave individual Functions without enough source identity metadata for
// a cross-build comparison; silently dropping them would make added/removed
// totals look more authoritative than they are.
type IdentityStats struct {
	FunctionObjects         int `json:"function_objects"`
	ResolvedFunctions       int `json:"resolved_functions"`
	DescriptorBuckets       int `json:"descriptor_buckets"`
	CollisionBuckets        int `json:"collision_buckets"`
	CollisionFunctions      int `json:"collision_functions"`
	WithInstructionBytes    int `json:"with_instruction_bytes"`
	WithoutInstructionBytes int `json:"without_instruction_bytes"`
	SkippedUnstableKind     int `json:"skipped_unstable_kind"`
	SkippedOwner            int `json:"skipped_owner"`
	SkippedName             int `json:"skipped_name"`
	SkippedLibrary          int `json:"skipped_library"`
	SkippedClosureParent    int `json:"skipped_closure_parent"`
}

type BuildResult struct {
	Functions FuncSet
	Stats     IdentityStats
}

// stableDescriptorName removes Dart's process/build-local private-library key
// from names that are already namespaced by the descriptor's library URL.
// Keeping the key makes the same private declaration look added+removed across
// two builds even though its source identity did not change.
func stableDescriptorName(s string) string {
	return strutil.ScrubDartPrivateKeys(s)
}

// Build assembles descriptor -> FuncInfo for every Function NamedObject whose
// source identity can be resolved completely. VM snapshot strings are only
// consulted through PoolLookups.StringForRef, which enforces the isolate's
// base-object boundary and string CID check. Missing owner/library/name data is
// therefore skipped rather than collapsed into a plausible shared descriptor.
//
// ranges and code may be nil: the descriptor set is still built, with
// CodeSize 0 and no hash. Matched descriptors then remain byte-indeterminate;
// identity added/removed accounting still works.
func Build(result *cluster.Result, pl *naming.PoolLookups, profile *snapshot.VersionProfile,
	table *cluster.InstructionsTable, ranges []cluster.CodeRange, code []byte, codeOff uint64) BuildResult {
	out := make(FuncSet)
	var stats IdentityStats
	if result == nil || pl == nil || profile == nil || profile.CIDs == nil {
		return BuildResult{Functions: out, Stats: stats}
	}
	ct := profile.CIDs

	// Function RefID -> the code range that implements it.
	type codeInfo struct {
		size int64
		hash string
	}
	classByRef := make(map[int]*cluster.ClassInfo, len(result.Classes))
	for i := range result.Classes {
		classByRef[result.Classes[i].RefID] = &result.Classes[i]
	}
	closureParents, closureNeedsParent := buildClosureParentIdentities(result, pl, ct)
	im := cluster.CodeImage{Code: code, CodeOff: codeOff}
	rangeByRef, rangeRefAmbiguous := indexRangesByRef(ranges)
	rangeByCluster, rangeClusterAmbiguous := indexRangesByCluster(ranges)
	codeEvidence := func(no *cluster.NamedObject) codeInfo {
		if no == nil {
			return codeInfo{}
		}
		var r cluster.CodeRange
		var ok bool
		if profile.CodeIndexOneBased {
			if table == nil || no.CodeIndex <= 0 {
				return codeInfo{}
			}
			// >=2.16 SDK: CodeIndexToClusterIndex(code_index) is exactly
			// code_index - 1 - first_entry_with_code. A negative result is a
			// stub/discarded-code slot and has no Code object/range to hash.
			clusterIndex := no.CodeIndex - 1 - int(table.FirstEntryWithCode)
			if clusterIndex < 0 || rangeClusterAmbiguous[clusterIndex] {
				return codeInfo{}
			}
			r, ok = rangeByCluster[clusterIndex]
		} else {
			// <=2.15 SDK: Function.code_ is serialized as a normal reference;
			// d->ReadUnsigned() is passed to d->Ref(code_index). The value is an
			// absolute snapshot Code ref ID, never a Code-cluster index.
			if no.CodeIndex <= cluster.RefNull || rangeRefAmbiguous[no.CodeIndex] {
				return codeInfo{}
			}
			r, ok = rangeByRef[no.CodeIndex]
		}
		if !ok || r.RefID < 0 {
			return codeInfo{}
		}
		ci := codeInfo{size: int64(r.Size)}
		if fnCode, _, exact := im.SliceExact(r); exact {
			sum := sha256.Sum256(fnCode)
			ci.hash = hex.EncodeToString(sum[:])
		}
		return ci
	}
	for i := range result.Named {
		no := &result.Named[i]
		if no.CID != ct.Function {
			continue
		}
		stats.FunctionObjects++
		if no.FuncKind == cluster.FunctionKindUnknown || no.FuncKind == cluster.FunctionKindOther {
			stats.SkippedUnstableKind++
			continue
		}
		ownerName, effectiveClass, ok := functionOwnerIdentity(no, pl, ct)
		if !ok {
			stats.SkippedOwner++
			continue
		}
		name := pl.ResolveObjectName(no.RefID)
		if name == "" {
			stats.SkippedName++
			continue // truly unnamed/anonymous objects have no stable diff identity
		}
		name = stableDescriptorName(name)

		libraryURL := functionLibraryURL(effectiveClass, classByRef, pl, ct)
		if libraryURL == "" {
			// The library URI is part of semantic identity. Inventing an
			// <unknown-library> bucket aliases unrelated declarations and, on
			// unified snapshots, also admits the VM's synthetic UnknownDartCode
			// Function (owner=void, name=<optimized out>).
			stats.SkippedLibrary++
			continue
		}
		kind := no.FuncKind.String()
		parent := stableDescriptorName(closureParents[no.RefID])
		if closureNeedsParent[no.RefID] && parent == "" {
			// ClosureData says this Function has a distinct enclosing Function,
			// but that identity could not be recovered. Dropping the qualifier
			// would merge otherwise unrelated anonymous closures.
			stats.SkippedClosureParent++
			continue
		}
		desc := FuncDescriptor{LibraryURI: libraryURL, Owner: ownerName, Name: name, Kind: kind, Enclosing: parent}
		ci := codeEvidence(no)
		out[desc] = append(out[desc], FuncInfo{
			RefID:     no.RefID,
			CodeSize:  ci.size,
			InstrHash: ci.hash,
		})
		stats.ResolvedFunctions++
		if ci.hash != "" {
			stats.WithInstructionBytes++
		} else {
			stats.WithoutInstructionBytes++
		}
	}
	for d := range out {
		sortFuncInfos(out[d])
		stats.DescriptorBuckets++
		if len(out[d]) > 1 {
			stats.CollisionBuckets++
			stats.CollisionFunctions += len(out[d])
		}
	}
	return BuildResult{Functions: out, Stats: stats}
}

func indexRangesByRef(ranges []cluster.CodeRange) (map[int]cluster.CodeRange, map[int]bool) {
	out := make(map[int]cluster.CodeRange, len(ranges))
	ambiguous := make(map[int]bool)
	for i := range ranges {
		r := ranges[i]
		if r.RefID <= cluster.RefNull {
			continue
		}
		if _, exists := out[r.RefID]; exists {
			ambiguous[r.RefID] = true
			continue
		}
		out[r.RefID] = r
	}
	for ref := range ambiguous {
		delete(out, ref)
	}
	return out, ambiguous
}

func indexRangesByCluster(ranges []cluster.CodeRange) (map[int]cluster.CodeRange, map[int]bool) {
	out := make(map[int]cluster.CodeRange, len(ranges))
	ambiguous := make(map[int]bool)
	for i := range ranges {
		r := ranges[i]
		if r.RefID < 0 || r.Index < 0 {
			continue
		}
		if _, exists := out[r.Index]; exists {
			ambiguous[r.Index] = true
			continue
		}
		out[r.Index] = r
	}
	for idx := range ambiguous {
		delete(out, idx)
	}
	return out, ambiguous
}

func functionLibraryURL(effectiveClass int, classByRef map[int]*cluster.ClassInfo, pl *naming.PoolLookups, ct *snapshot.CIDTable) string {
	if pl == nil || effectiveClass <= cluster.RefNull {
		return ""
	}
	ci := classByRef[effectiveClass]
	if ci == nil || ci.LibraryRefID <= cluster.RefNull {
		return ""
	}
	lib, ok := pl.NamedObjectForRef(ci.LibraryRefID)
	if !ok || lib == nil {
		return ""
	}
	if ct != nil && ct.Library != 0 && lib.CID != ct.Library {
		return ""
	}
	return pl.ResolveObjectName(lib.RefID)
}

// functionOwnerIdentity follows PatchClass wrappers to the real owning Class
// and distinguishes the VM's real top-level pseudo-class (name "::") from a
// missing owner name. Treating both as <top-level> aliases malformed Functions
// with genuine top-level declarations.
func functionOwnerIdentity(no *cluster.NamedObject, pl *naming.PoolLookups, ct *snapshot.CIDTable) (name string, classRef int, ok bool) {
	if no == nil || pl == nil || ct == nil {
		return "", 0, false
	}
	ref := no.OwnerRefID
	for depth := 0; depth <= 4; depth++ {
		owner, found := pl.NamedObjectForRef(ref)
		if !found {
			return "", 0, false
		}
		if ct.PatchClass != 0 && owner.CID == ct.PatchClass {
			ref = owner.OwnerRefID
			continue
		}
		// Function::Owner in every supported SDK accepts exactly Class or
		// PatchClass (which unwraps to Class). A named Field/Library/etc. at this
		// reference is corrupt/stale metadata, not a plausible owner identity.
		if ct.Class == 0 || owner.CID != ct.Class {
			return "", 0, false
		}
		raw := pl.ResolveObjectName(ref)
		if raw == "" {
			return "", 0, false
		}
		if raw == "::" {
			return "<top-level>", ref, true
		}
		return stableDescriptorName(raw), ref, true
	}
	return "", 0, false
}

// buildClosureParentIdentities mirrors the SDK's recursive Function::PrintName
// ancestry for non-implicit closures, while resolving every object/string
// through the guarded helpers above. PRODUCT Full-AOT does not preserve a real
// token position on every supported release, so ancestry is the strongest
// cross-build qualifier available without inventing source coordinates.
func buildClosureParentIdentities(result *cluster.Result, pl *naming.PoolLookups, ct *snapshot.CIDTable) (map[int]string, map[int]bool) {
	if result == nil || pl == nil || ct == nil {
		return nil, nil
	}
	parentByData := make(map[int]int, len(result.ClosureData))
	for i := range result.ClosureData {
		cd := &result.ClosureData[i]
		if cd.ParentFunctionRef > cluster.RefNull {
			parentByData[cd.RefID] = cd.ParentFunctionRef
		}
	}
	parentByFunction := make(map[int]int)
	requiresParent := make(map[int]bool)
	for i := range result.Named {
		no := &result.Named[i]
		if no.CID != ct.Function || no.FuncKind != cluster.FunctionKindClosure {
			continue
		}
		// A real local closure is backed by ClosureData.parent_function in every
		// supported SDK. Missing/malformed ClosureData is therefore missing
		// identity evidence, not permission to collapse to an unqualified name.
		requiresParent[no.RefID] = true
		if no.DataRefID <= cluster.RefNull {
			continue
		}
		parentRef, found := parentByData[no.DataRefID]
		if !found || parentRef <= cluster.RefNull || parentRef == no.RefID {
			continue
		}
		parentByFunction[no.RefID] = parentRef
	}

	// render returns the SDK-style qualified local-function identity for ref.
	// The recursion bound is defensive against malformed ClosureData cycles.
	var render func(ref int, visiting map[int]bool, depth int) (string, bool)
	render = func(ref int, visiting map[int]bool, depth int) (string, bool) {
		if depth > 64 || visiting[ref] {
			return "", false
		}
		fn, found := pl.NamedObjectForRef(ref)
		if !found || fn == nil || fn.CID != ct.Function {
			return "", false
		}
		name := stableDescriptorName(pl.ResolveObjectName(ref))
		if name == "" || fn.FuncKind == cluster.FunctionKindUnknown {
			return "", false
		}
		visiting[ref] = true
		defer delete(visiting, ref)

		if fn.FuncKind == cluster.FunctionKindClosure {
			parentRef, ok := parentByFunction[ref]
			if !ok {
				return "", false
			}
			parentName, ok := render(parentRef, visiting, depth+1)
			if !ok {
				return "", false
			}
			return parentName + "." + name, true
		}

		ownerName, _, ok := functionOwnerIdentity(fn, pl, ct)
		if !ok {
			return "", false
		}
		if fn.IsConstructor() {
			if ownerName == "<top-level>" {
				return "new " + name, true
			}
			return ownerName + ".new " + name, true
		}
		if ownerName == "<top-level>" {
			return name, true
		}
		return ownerName + "." + name, true
	}

	out := make(map[int]string)
	for fnRef, parentRef := range parentByFunction {
		if rendered, ok := render(parentRef, make(map[int]bool), 0); ok {
			out[fnRef] = rendered
		}
	}
	if len(out) == 0 {
		out = nil
	}
	if len(requiresParent) == 0 {
		requiresParent = nil
	}
	return out, requiresParent
}

// LoadedSet is one fully parsed build. Machine is retained because raw
// instruction hashes are meaningful only within one ISA.
type LoadedSet struct {
	Descriptors FuncSet
	Identity    IdentityStats
	DartVersion string
	Machine     string
}

// Load runs aotopsy's standard fast-path parse (elfx -> snapshot -> cluster
// scan+fill, isolate + VM snapshot) and builds the descriptor set for one
// libapp.so build. A present-but-unparseable VM snapshot is fatal here: VM base
// object names contribute to descriptor identity, so silently dropping them
// manufactures removals/renames.
func Load(libPath string) (*LoadedSet, error) {
	// A function diff cannot safely use a partially recovered object graph:
	// placeholders and truncated clusters turn parser damage into plausible
	// additions/removals. Fail at the first structural error instead.
	sc, err := analysis.LoadSnapshot(libPath, dartfmt.Options{Mode: dartfmt.ModeStrict})
	if err != nil {
		return nil, fmt.Errorf("funcdiff: %s: %w", libPath, err)
	}
	defer func() { _ = sc.Close() }()
	if err := requireCompleteVM(sc); err != nil {
		return nil, fmt.Errorf("funcdiff: %s: %w", libPath, err)
	}

	built := Build(sc.Result, sc.Pool, sc.Info.Version, sc.Table, sc.Ranges, sc.Code, sc.CodeOff)
	return &LoadedSet{
		Descriptors: built.Functions,
		Identity:    built.Stats,
		DartVersion: sc.Info.Version.DartVersion,
		Machine:     sc.EF.Machine().String(),
	}, nil
}

func requireCompleteVM(sc *analysis.SnapshotContext) error {
	if sc == nil || sc.Info == nil {
		return fmt.Errorf("incomplete snapshot context")
	}
	// Dart 3.13+ deliberately has one unified snapshot and therefore no
	// separate VM result. Legacy snapshots always need the VM snapshot here:
	// base-object strings from it are part of FuncDescriptor identity.
	if sc.Info.UnifiedSnapshot {
		return nil
	}
	if sc.Info.VmHeader == nil {
		return fmt.Errorf("incomplete VM snapshot: legacy VM header is unavailable")
	}
	if sc.VMError != nil {
		return fmt.Errorf("incomplete VM snapshot: %w", sc.VMError)
	}
	if sc.VMResult == nil {
		return fmt.Errorf("incomplete VM snapshot: no VM cluster result was produced")
	}
	return nil
}

// Report separates source-identity-shaped matching from machine instruction
// bytes. An instruction byte difference is never called a semantic/source
// change: pool numbering, relocation/layout, compiler flags and codegen can all
// alter bytes while Dart source behavior remains equivalent.
type Report struct {
	OldPath                            string        `json:"old_path"`
	NewPath                            string        `json:"new_path"`
	OldVersion                         string        `json:"old_dart_version"`
	NewVersion                         string        `json:"new_dart_version"`
	SameDartVersion                    bool          `json:"same_dart_version"`
	OldMachine                         string        `json:"old_machine"`
	NewMachine                         string        `json:"new_machine"`
	InstructionBytesComparable         bool          `json:"instruction_bytes_comparable"`
	InstructionBytesIncomparableReason string        `json:"instruction_bytes_incomparable_reason,omitempty"`
	OldIdentity                        IdentityStats `json:"old_identity"`
	NewIdentity                        IdentityStats `json:"new_identity"`
	MatchedIdentityTotal               int           `json:"matched_identity_total"`
	IdentityAddedTotal                 int           `json:"identity_added_total"`
	IdentityRemovedTotal               int           `json:"identity_removed_total"`
	InstructionBytesEqualTotal         int           `json:"instruction_bytes_equal_total"`
	InstructionBytesDifferentTotal     int           `json:"instruction_bytes_different_total"`
	InstructionBytesIndeterminateTotal int           `json:"instruction_bytes_indeterminate_total"`
	IdentityAdded                      []DiffEntry   `json:"identity_added"`
	IdentityRemoved                    []DiffEntry   `json:"identity_removed"`
	InstructionBytesDifferent          []DiffEntry   `json:"instruction_bytes_different,omitempty"`
	InstructionBytesIndeterminate      []DiffEntry   `json:"instruction_bytes_indeterminate,omitempty"`
	Truncated                          bool          `json:"truncated"`
}

// DiffEntry aggregates multiplicity under one stable semantic descriptor.
// Count is a number of Function objects, not distinct descriptor strings.
type DiffEntry struct {
	Descriptor FuncDescriptor `json:"descriptor"`
	Count      int            `json:"count"`
}

// Diff loads both builds and computes descriptor-multiset identity differences
// plus equal/different/indeterminate instruction-byte status for matched identity.
func Diff(oldPath, newPath string, topN int) (*Report, error) {
	oldBuild, err := Load(oldPath)
	if err != nil {
		return nil, err
	}
	newBuild, err := Load(newPath)
	if err != nil {
		return nil, err
	}

	bytesComparable := oldBuild.Machine == newBuild.Machine
	rep := diffDescriptors(oldBuild.Descriptors, newBuild.Descriptors, topN, bytesComparable)
	rep.OldPath = oldPath
	rep.NewPath = newPath
	rep.OldVersion = oldBuild.DartVersion
	rep.NewVersion = newBuild.DartVersion
	rep.SameDartVersion = oldBuild.DartVersion != "" && oldBuild.DartVersion == newBuild.DartVersion
	rep.OldMachine = oldBuild.Machine
	rep.NewMachine = newBuild.Machine
	rep.OldIdentity = oldBuild.Identity
	rep.NewIdentity = newBuild.Identity
	rep.InstructionBytesComparable = bytesComparable
	if !bytesComparable {
		rep.InstructionBytesIncomparableReason = fmt.Sprintf("instruction bytes use different machines (%s vs %s)", oldBuild.Machine, newBuild.Machine)
	}
	return rep, nil
}

// DiffDescriptors computes differences between two in-memory function descriptor sets.
func DiffDescriptors(oldDescs, newDescs FuncSet, topN int) *Report {
	rep := diffDescriptors(oldDescs, newDescs, topN, true)
	rep.InstructionBytesComparable = true
	return rep
}

func diffDescriptors(oldDescs, newDescs FuncSet, topN int, compareInstructionBytes bool) *Report {
	var added, removed, different, indeterminate []DiffEntry
	matched, addedTotal, removedTotal, equalTotal, differentTotal, indeterminateTotal := 0, 0, 0, 0, 0, 0
	keys := make(map[FuncDescriptor]struct{}, len(oldDescs)+len(newDescs))
	for d := range oldDescs {
		keys[d] = struct{}{}
	}
	for d := range newDescs {
		keys[d] = struct{}{}
	}
	ordered := make([]FuncDescriptor, 0, len(keys))
	for d := range keys {
		ordered = append(ordered, d)
	}
	sort.Slice(ordered, func(i, j int) bool { return funcDescriptorLess(ordered[i], ordered[j]) })

	for _, d := range ordered {
		oldList := append([]FuncInfo(nil), oldDescs[d]...)
		newList := append([]FuncInfo(nil), newDescs[d]...)
		sortFuncInfos(oldList)
		sortFuncInfos(newList)
		descriptorCollision := len(oldList) > 1 || len(newList) > 1
		if !compareInstructionBytes {
			pairs := min(len(oldList), len(newList))
			matched += pairs
			if pairs > 0 {
				indeterminate = append(indeterminate, DiffEntry{Descriptor: d, Count: pairs})
				indeterminateTotal += pairs
			}
			if n := len(newList) - pairs; n > 0 {
				added = append(added, DiffEntry{Descriptor: d, Count: n})
				addedTotal += n
			}
			if n := len(oldList) - pairs; n > 0 {
				removed = append(removed, DiffEntry{Descriptor: d, Count: n})
				removedTotal += n
			}
			continue
		}

		// First consume equal, PRESENT hashes globally. Missing hashes are not
		// evidence of equality and must never steal a known exact match.
		oldUsed := make([]bool, len(oldList))
		newUsed := make([]bool, len(newList))
		for oi := range oldList {
			if oldList[oi].InstrHash == "" {
				continue
			}
			for ni := range newList {
				if newUsed[ni] || newList[ni].InstrHash == "" ||
					oldList[oi].InstrHash != newList[ni].InstrHash ||
					oldList[oi].CodeSize != newList[ni].CodeSize {
					continue
				}
				oldUsed[oi], newUsed[ni] = true, true
				matched++
				equalTotal++
				break
			}
		}

		var oldRemain, newRemain []FuncInfo
		for i := range oldList {
			if !oldUsed[i] {
				oldRemain = append(oldRemain, oldList[i])
			}
		}
		for i := range newList {
			if !newUsed[i] {
				newRemain = append(newRemain, newList[i])
			}
		}

		pairs := min(len(oldRemain), len(newRemain))
		if pairs > 0 {
			matched += pairs
			if descriptorCollision {
				// A descriptor bucket with multiplicity >1 has no per-object
				// per-object identity. Exact equal hashes above can safely consume
				// byte-equal occurrences, but two remaining unequal hashes do NOT
				// prove one Function corresponds to the other: an old anonymous
				// closure may have been removed while a new sibling was added.
				// Pairing them as a byte difference would manufacture correspondence
				// from a collision. Keep the unavoidable multiset intersection as
				// identity-matched but mark its byte relationship indeterminate.
				indeterminate = append(indeterminate, DiffEntry{Descriptor: d, Count: pairs})
				indeterminateTotal += pairs
			} else if compareFuncInfo(oldRemain[0], newRemain[0]) == instructionBytesDifferent {
				different = append(different, DiffEntry{Descriptor: d, Count: 1})
				differentTotal++
			} else {
				indeterminate = append(indeterminate, DiffEntry{Descriptor: d, Count: 1})
				indeterminateTotal++
			}
		}
		if n := len(newRemain) - pairs; n > 0 {
			added = append(added, DiffEntry{Descriptor: d, Count: n})
			addedTotal += n
		}
		if n := len(oldRemain) - pairs; n > 0 {
			removed = append(removed, DiffEntry{Descriptor: d, Count: n})
			removedTotal += n
		}
	}

	rep := &Report{
		OldIdentity:                        summarizeFuncSet(oldDescs),
		NewIdentity:                        summarizeFuncSet(newDescs),
		MatchedIdentityTotal:               matched,
		IdentityAddedTotal:                 addedTotal,
		IdentityRemovedTotal:               removedTotal,
		InstructionBytesEqualTotal:         equalTotal,
		InstructionBytesDifferentTotal:     differentTotal,
		InstructionBytesIndeterminateTotal: indeterminateTotal,
		InstructionBytesComparable:         compareInstructionBytes,
	}
	if topN > 0 && len(added) > topN {
		rep.IdentityAdded = added[:topN]
		rep.Truncated = true
	} else {
		rep.IdentityAdded = added
	}
	if topN > 0 && len(removed) > topN {
		rep.IdentityRemoved = removed[:topN]
		rep.Truncated = true
	} else {
		rep.IdentityRemoved = removed
	}
	if topN > 0 && len(different) > topN {
		rep.InstructionBytesDifferent = different[:topN]
		rep.Truncated = true
	} else {
		rep.InstructionBytesDifferent = different
	}
	if topN > 0 && len(indeterminate) > topN {
		rep.InstructionBytesIndeterminate = indeterminate[:topN]
		rep.Truncated = true
	} else {
		rep.InstructionBytesIndeterminate = indeterminate
	}
	return rep
}

func summarizeFuncSet(s FuncSet) IdentityStats {
	stats := IdentityStats{
		FunctionObjects:   funcSetCount(s),
		ResolvedFunctions: funcSetCount(s),
		DescriptorBuckets: len(s),
	}
	for _, list := range s {
		if len(list) > 1 {
			stats.CollisionBuckets++
			stats.CollisionFunctions += len(list)
		}
		for _, info := range list {
			if info.InstrHash != "" {
				stats.WithInstructionBytes++
			} else {
				stats.WithoutInstructionBytes++
			}
		}
	}
	return stats
}

func funcDescriptorLess(a, b FuncDescriptor) bool {
	if a.LibraryURI != b.LibraryURI {
		return a.LibraryURI < b.LibraryURI
	}
	if a.Owner != b.Owner {
		return a.Owner < b.Owner
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return a.Enclosing < b.Enclosing
}

func funcSetCount(s FuncSet) int {
	total := 0
	for _, list := range s {
		total += len(list)
	}
	return total
}

func sortFuncInfos(v []FuncInfo) {
	sort.Slice(v, func(i, j int) bool {
		if (v[i].InstrHash != "") != (v[j].InstrHash != "") {
			return v[i].InstrHash != "" // known evidence first
		}
		if v[i].InstrHash != v[j].InstrHash {
			return v[i].InstrHash < v[j].InstrHash
		}
		if v[i].CodeSize != v[j].CodeSize {
			return v[i].CodeSize < v[j].CodeSize
		}
		return v[i].RefID < v[j].RefID
	})
}

type codeComparison uint8

const (
	instructionBytesDifferent codeComparison = iota
	instructionBytesIndeterminate
)

// compareFuncInfo classifies an already-unmatched pair. Equal non-empty hashes
// have been consumed before this function. Two present unequal hashes prove a
// byte difference. Two present unequal sizes also prove a byte difference. Any
// comparison involving missing evidence where size does not prove a difference
// is indeterminate.
func compareFuncInfo(a, b FuncInfo) codeComparison {
	if a.InstrHash != "" && b.InstrHash != "" {
		return instructionBytesDifferent
	}
	if a.CodeSize > 0 && b.CodeSize > 0 && a.CodeSize != b.CodeSize {
		return instructionBytesDifferent
	}
	return instructionBytesIndeterminate
}
