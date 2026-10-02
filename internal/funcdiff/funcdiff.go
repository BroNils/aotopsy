// Package funcdiff diffs the set of Dart functions between two libapp.so
// builds (e.g. before/after a code change, or two app versions), reusing
// aotopsy's own real Dart-AOT snapshot cluster deserializer for function
// identity -- unlike flutterdec's pipeline/runners_diff.rs (Rust), which
// has to fall back to a heuristic library-URI/owner-class model because
// flutterdec-core has no real cluster parser of its own. Ported concept,
// better ground truth.
package funcdiff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/naming"
	"aotopsy/internal/snapshot"
)

// FuncDescriptor is the stable semantic bucket for one or more Dart Function
// objects. It deliberately excludes RefID/CodeIndex because those are snapshot-
// local numbering and are not stable across builds. Multiple Function objects
// may legitimately share a descriptor (e.g. repeated anonymous closures), so
// FuncSet stores a MULTISET per descriptor instead of silently keep-first.
type FuncDescriptor string

// FuncInfo holds a function's identity and what it takes to tell whether
// its code changed.
//
// CodeSize used to be CodeEntry.PayloadInfo, which is not a size. The SDK
// writes it as
//
//	payload_info = (unchecked_offset << 1) | has_monomorphic_entrypoint
//
// (app_snapshot.cc, serializer around line 8488 / deserializer 9625), so
// it is the unchecked-entry offset with a flag in the low bit -- a codegen
// property. Diffing on it reports a function as changed when only its
// entry layout moved, and as unchanged when its body was rewritten to the
// same unchecked offset.
//
// Measured: diffing dart-3.12.2-arm64 against dart-3.12.2-f3440-arm64 --
// the same app built against a different Flutter -- payload_info reported
// 0 of 6430 common functions as changed. It is a small number that repeats
// across functions, so the "changed" column was structurally always empty.
//
// The real size comes from the instructions table, and InstrHash covers
// the case the size cannot: a body rewritten to the same length. With
// both, the same pair reports 5051 changed.
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

// Dart private keys are not decimal-only. The VM treats '@' as the separator
// and consumes everything up to the next '.' or '&' when comparing names
// without a private key (String::EqualsIgnoringPrivateKey).
var privateLibraryKeyRE = regexp.MustCompile(`@[^.&]+`)

// stableDescriptorName removes Dart's process/build-local private-library key
// from names that are already namespaced by the descriptor's library URL.
// Keeping the key makes the same private declaration look added+removed across
// two builds even though its source identity did not change.
func stableDescriptorName(s string) string {
	return privateLibraryKeyRE.ReplaceAllString(s, "")
}

// Build assembles descriptor -> FuncInfo for every Function NamedObject whose
// source identity can be resolved completely. VM snapshot strings are only
// consulted through PoolLookups.StringForRef, which enforces the isolate's
// base-object boundary and string CID check. Missing owner/library/name data is
// therefore skipped rather than collapsed into a plausible shared descriptor.
//
// ranges and code may be nil: the descriptor set is still built, with
// CodeSize 0 and no hash. Common descriptors then remain indeterminate rather
// than being guessed changed/unchanged; added/removed identity still works.
func Build(result *cluster.Result, pl *naming.PoolLookups, profile *snapshot.VersionProfile,
	table *cluster.InstructionsTable, ranges []cluster.CodeRange, code []byte, codeOff uint64) FuncSet {
	out := make(FuncSet)
	if result == nil || pl == nil || profile == nil || profile.CIDs == nil {
		return out
	}
	ct := profile.CIDs

	// Function RefID -> the code range that implements it.
	type codeInfo struct {
		size int64
		hash string
	}
	byOwner := make(map[int]codeInfo, len(ranges))
	classByRef := make(map[int]*cluster.ClassInfo, len(result.Classes))
	for i := range result.Classes {
		classByRef[result.Classes[i].RefID] = &result.Classes[i]
	}
	closureParents, closureNeedsParent := buildClosureParentIdentities(result, pl, ct)
	im := cluster.CodeImage{Code: code, CodeOff: codeOff}
	firstEntryWithCode := -1
	if table != nil {
		firstEntryWithCode = int(table.FirstEntryWithCode)
	}
	byCodeIndex := naming.CodeIndexToFunc(result, ct, profile.CodeIndexOneBased, firstEntryWithCode)
	codeByRef := make(map[int]cluster.CodeEntry, len(result.Codes))
	for i := range result.Codes {
		c := result.Codes[i]
		if c.RefID > cluster.RefNull {
			codeByRef[c.RefID] = c
		}
	}
	for i := range ranges {
		r := &ranges[i]
		// Stub/trampoline ranges reuse the same small Index values as real Code
		// cluster entries. They have no Function owner and must not participate in
		// the CodeIndex cross-reference below.
		if r.RefID < 0 {
			continue
		}
		ownerRef := r.OwnerRef
		if ce, ok := codeByRef[r.RefID]; ok {
			if owner, ok := naming.ResolveCodeOwner(ce, pl.RefToNamed, byCodeIndex, ct); ok && owner != nil {
				ownerRef = owner.RefID
			}
		}
		if ownerRef < 0 {
			continue
		}
		ci := codeInfo{size: int64(r.Size)}
		// SliceExact, not Slice: a clamped read would hash fewer bytes
		// than the function has and produce a digest that differs from
		// every other build for a reason unrelated to the code.
		if fnCode, _, ok := im.SliceExact(*r); ok {
			sum := sha256.Sum256(fnCode)
			ci.hash = hex.EncodeToString(sum[:])
		}
		byOwner[ownerRef] = ci
	}
	for i := range result.Named {
		no := &result.Named[i]
		if no.CID != ct.Function {
			continue
		}
		if no.FuncKind == cluster.FunctionKindUnknown {
			continue
		}
		ownerName, effectiveClass, ok := functionOwnerIdentity(no, pl, ct)
		if !ok {
			continue
		}
		name := stableObjectName(pl, no)
		if name == "" {
			continue // truly unnamed/anonymous objects have no stable diff identity
		}
		name = stableDescriptorName(name)

		libraryURL := functionLibraryURL(effectiveClass, classByRef, pl, ct)
		if libraryURL == "" {
			// The library URI is part of semantic identity. Inventing an
			// <unknown-library> bucket aliases unrelated declarations and, on
			// unified snapshots, also admits the VM's synthetic UnknownDartCode
			// Function (owner=void, name=<optimized out>).
			continue
		}
		kind := no.FuncKind.String()
		parent := stableDescriptorName(closureParents[no.RefID])
		if closureNeedsParent[no.RefID] && parent == "" {
			// ClosureData says this Function has a distinct enclosing Function,
			// but that identity could not be recovered. Dropping the qualifier
			// would merge otherwise unrelated anonymous closures.
			continue
		}
		desc := FuncDescriptor(fmt.Sprintf("%s::%s::%s [kind=%s]", libraryURL, ownerName, name, kind))
		if parent != "" {
			desc += FuncDescriptor(" [parent=" + parent + "]")
		}
		ci := byOwner[no.RefID]
		out[desc] = append(out[desc], FuncInfo{
			RefID:     no.RefID,
			CodeSize:  ci.size,
			InstrHash: ci.hash,
		})
	}
	for d := range out {
		sortFuncInfos(out[d])
	}
	return out
}

func functionLibraryURL(effectiveClass int, classByRef map[int]*cluster.ClassInfo, pl *naming.PoolLookups, ct *snapshot.CIDTable) string {
	if pl == nil || effectiveClass <= cluster.RefNull {
		return ""
	}
	ci := classByRef[effectiveClass]
	if ci == nil || ci.LibraryRefID <= cluster.RefNull {
		return ""
	}
	lib, ok := stableNamedForRef(pl, ci.LibraryRefID)
	if !ok || lib == nil {
		return ""
	}
	if ct != nil && ct.Library != 0 && lib.CID != ct.Library {
		return ""
	}
	return stableObjectName(pl, lib)
}

// stableNamedForRef resolves an object reference in the same namespace rules
// as snapshot references themselves: isolate objects first, VM objects only in
// the base-object prefix. VmRefToNamed keys are not globally unique with app
// refs and must not be used as an unconditional fallback.
func stableNamedForRef(pl *naming.PoolLookups, ref int) (*cluster.NamedObject, bool) {
	if pl == nil || ref <= cluster.RefNull {
		return nil, false
	}
	if no, ok := pl.RefToNamed[ref]; ok && no != nil {
		return no, true
	}
	if ref < pl.BaseObjLimit && pl.VmRefToNamed != nil {
		if no, ok := pl.VmRefToNamed[ref]; ok && no != nil {
			return no, true
		}
	}
	return nil, false
}

// stableObjectName resolves a NamedObject's string with the same guarded VM
// fallback used everywhere PoolLookups exposes a raw reference. In particular,
// do not call ResolveVMName directly here: it cannot tell whether NameRefID is
// in the VM base-object domain.
func stableObjectName(pl *naming.PoolLookups, no *cluster.NamedObject) string {
	if pl == nil || no == nil {
		return ""
	}
	if s, ok := pl.StringForRef(no.NameRefID); ok {
		return s
	}
	return ""
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
		owner, found := stableNamedForRef(pl, ref)
		if !found {
			return "", 0, false
		}
		if ct.PatchClass != 0 && owner.CID == ct.PatchClass {
			ref = owner.OwnerRefID
			continue
		}
		raw := stableObjectName(pl, owner)
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

// buildClosureParentIdentities mirrors naming.BuildClosureParents but resolves
// every object/string through the guarded helpers above. FuncDescriptor uses
// the enclosing function to disambiguate anonymous closures, so an unsafe VM
// fallback here is just as capable of creating a false match as one on the
// closure's own name.
func buildClosureParentIdentities(result *cluster.Result, pl *naming.PoolLookups, ct *snapshot.CIDTable) (map[int]string, map[int]bool) {
	if result == nil || pl == nil || ct == nil || len(result.ClosureData) == 0 {
		return nil, nil
	}
	parentByData := make(map[int]int, len(result.ClosureData))
	for i := range result.ClosureData {
		cd := &result.ClosureData[i]
		if cd.ParentFunctionRef > cluster.RefNull {
			parentByData[cd.RefID] = cd.ParentFunctionRef
		}
	}
	if len(parentByData) == 0 {
		return nil, nil
	}

	out := make(map[int]string)
	requiresParent := make(map[int]bool)
	for i := range result.Named {
		no := &result.Named[i]
		if no.CID != ct.Function || no.DataRefID <= cluster.RefNull || no.IsImplicitClosure() {
			continue
		}
		parentRef, found := parentByData[no.DataRefID]
		if !found || parentRef == no.RefID {
			continue
		}
		requiresParent[no.RefID] = true
		parent, found := stableNamedForRef(pl, parentRef)
		if !found || parent.CID != ct.Function {
			continue
		}
		parentName := stableObjectName(pl, parent)
		if parentName == "" {
			continue
		}
		if parent.IsConstructor() {
			parentName = "new " + parentName
		} else if ownerName, _, ownerOK := functionOwnerIdentity(parent, pl, ct); ownerOK && ownerName != "<top-level>" {
			parentName = ownerName + "." + parentName
		}
		out[no.RefID] = parentName
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

	return &LoadedSet{
		Descriptors: Build(sc.Result, sc.Pool, sc.Info.Version, sc.Table, sc.Ranges, sc.Code, sc.CodeOff),
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

// Report is the result of diffing two builds' function descriptor sets.
type Report struct {
	OldPath            string      `json:"old_path"`
	NewPath            string      `json:"new_path"`
	OldVersion         string      `json:"old_dart_version"`
	NewVersion         string      `json:"new_dart_version"`
	OldMachine         string      `json:"old_machine"`
	NewMachine         string      `json:"new_machine"`
	CodeComparable     bool        `json:"code_comparable"`
	IncomparableReason string      `json:"incomparable_reason,omitempty"`
	OldCount           int         `json:"old_count"`
	NewCount           int         `json:"new_count"`
	CommonCount        int         `json:"common_count"`
	AddedTotal         int         `json:"added_total"`
	RemovedTotal       int         `json:"removed_total"`
	ChangedTotal       int         `json:"changed_total"`
	IndeterminateTotal int         `json:"indeterminate_total"`
	Added              []DiffEntry `json:"added"`
	Removed            []DiffEntry `json:"removed"`
	Changed            []DiffEntry `json:"changed,omitempty"`
	Indeterminate      []DiffEntry `json:"indeterminate,omitempty"`
	Truncated          bool        `json:"truncated"`
}

// DiffEntry aggregates multiplicity under one stable semantic descriptor.
// Count is a number of Function objects, not distinct descriptor strings.
type DiffEntry struct {
	Descriptor string `json:"descriptor"`
	Count      int    `json:"count"`
}

// Diff loads both builds and computes added/removed/common function identity
// plus changed/indeterminate code status for common functions.
func Diff(oldPath, newPath string, topN int) (*Report, error) {
	oldBuild, err := Load(oldPath)
	if err != nil {
		return nil, err
	}
	newBuild, err := Load(newPath)
	if err != nil {
		return nil, err
	}

	codeComparable := oldBuild.Machine == newBuild.Machine
	rep := diffDescriptors(oldBuild.Descriptors, newBuild.Descriptors, topN, codeComparable)
	rep.OldPath = oldPath
	rep.NewPath = newPath
	rep.OldVersion = oldBuild.DartVersion
	rep.NewVersion = newBuild.DartVersion
	rep.OldMachine = oldBuild.Machine
	rep.NewMachine = newBuild.Machine
	rep.CodeComparable = codeComparable
	if !codeComparable {
		rep.IncomparableReason = fmt.Sprintf("instruction bytes use different machines (%s vs %s)", oldBuild.Machine, newBuild.Machine)
	}
	return rep, nil
}

// DiffDescriptors computes differences between two in-memory function descriptor sets.
func DiffDescriptors(oldDescs, newDescs FuncSet, topN int) *Report {
	rep := diffDescriptors(oldDescs, newDescs, topN, true)
	rep.CodeComparable = true
	return rep
}

func diffDescriptors(oldDescs, newDescs FuncSet, topN int, compareCode bool) *Report {
	var added, removed, changed, indeterminate []DiffEntry
	common, addedTotal, removedTotal, changedTotal, indeterminateTotal := 0, 0, 0, 0, 0
	keys := make(map[FuncDescriptor]struct{}, len(oldDescs)+len(newDescs))
	for d := range oldDescs {
		keys[d] = struct{}{}
	}
	for d := range newDescs {
		keys[d] = struct{}{}
	}
	ordered := make([]string, 0, len(keys))
	for d := range keys {
		ordered = append(ordered, string(d))
	}
	sort.Strings(ordered)

	for _, ds := range ordered {
		d := FuncDescriptor(ds)
		oldList := append([]FuncInfo(nil), oldDescs[d]...)
		newList := append([]FuncInfo(nil), newDescs[d]...)
		sortFuncInfos(oldList)
		sortFuncInfos(newList)
		descriptorCollision := len(oldList) > 1 || len(newList) > 1
		if !compareCode {
			pairs := min(len(oldList), len(newList))
			common += pairs
			if pairs > 0 {
				indeterminate = append(indeterminate, DiffEntry{Descriptor: ds, Count: pairs})
				indeterminateTotal += pairs
			}
			if n := len(newList) - pairs; n > 0 {
				added = append(added, DiffEntry{Descriptor: ds, Count: n})
				addedTotal += n
			}
			if n := len(oldList) - pairs; n > 0 {
				removed = append(removed, DiffEntry{Descriptor: ds, Count: n})
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
				common++
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
			common += pairs
			if descriptorCollision {
				// A descriptor bucket with multiplicity >1 has no per-object
				// semantic identity. Exact equal hashes above can safely consume
				// unchanged occurrences, but two remaining unequal hashes do NOT
				// prove one Function changed into the other: an old anonymous
				// closure may have been removed while a new sibling was added.
				// Calling that pair "changed" manufactures a rename/change from a
				// collision. Keep the unavoidable multiset intersection as common
				// but mark its code relationship indeterminate.
				indeterminate = append(indeterminate, DiffEntry{Descriptor: ds, Count: pairs})
				indeterminateTotal += pairs
			} else if compareFuncInfo(oldRemain[0], newRemain[0]) == codeChanged {
				changed = append(changed, DiffEntry{Descriptor: ds, Count: 1})
				changedTotal++
			} else {
				indeterminate = append(indeterminate, DiffEntry{Descriptor: ds, Count: 1})
				indeterminateTotal++
			}
		}
		if n := len(newRemain) - pairs; n > 0 {
			added = append(added, DiffEntry{Descriptor: ds, Count: n})
			addedTotal += n
		}
		if n := len(oldRemain) - pairs; n > 0 {
			removed = append(removed, DiffEntry{Descriptor: ds, Count: n})
			removedTotal += n
		}
	}

	rep := &Report{
		OldCount:           funcSetCount(oldDescs),
		NewCount:           funcSetCount(newDescs),
		CommonCount:        common,
		AddedTotal:         addedTotal,
		RemovedTotal:       removedTotal,
		ChangedTotal:       changedTotal,
		IndeterminateTotal: indeterminateTotal,
		CodeComparable:     compareCode,
	}
	if topN > 0 && len(added) > topN {
		rep.Added = added[:topN]
		rep.Truncated = true
	} else {
		rep.Added = added
	}
	if topN > 0 && len(removed) > topN {
		rep.Removed = removed[:topN]
		rep.Truncated = true
	} else {
		rep.Removed = removed
	}
	if topN > 0 && len(changed) > topN {
		rep.Changed = changed[:topN]
		rep.Truncated = true
	} else {
		rep.Changed = changed
	}
	if topN > 0 && len(indeterminate) > topN {
		rep.Indeterminate = indeterminate[:topN]
		rep.Truncated = true
	} else {
		rep.Indeterminate = indeterminate
	}
	return rep
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
	codeChanged codeComparison = iota
	codeIndeterminate
)

// compareFuncInfo classifies an already-unmatched pair. Equal non-empty hashes
// have been consumed before this function. Two present unequal hashes prove a
// byte change. Two present unequal sizes also prove a change. Any comparison
// involving missing byte evidence where size does not prove a difference is
// indeterminate, never silently "unchanged".
func compareFuncInfo(a, b FuncInfo) codeComparison {
	if a.InstrHash != "" && b.InstrHash != "" {
		return codeChanged
	}
	if a.CodeSize > 0 && b.CodeSize > 0 && a.CodeSize != b.CodeSize {
		return codeChanged
	}
	return codeIndeterminate
}
