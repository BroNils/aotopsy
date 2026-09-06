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
	"sort"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/naming"
	"aotopsy/internal/snapshot"
)

// FuncDescriptor is the canonical identity of one function, analogous to
// flutterdec's "<library_uri>::<owner_class>::<name>" descriptor string.
// aotopsy does not currently track a per-class library URI, so the
// descriptor here is "<owner_class>::<name>" -- still a meaningful,
// collision-resistant identity for diffing, just without the library-URI
// segment flutterdec's descriptor has.
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

// Build assembles descriptor -> FuncInfo for every Function NamedObject in
// a loaded snapshot, one hop through PatchClass (mirroring
// cmd/aotopsy/refinfo.go's listToplevelFunctions owner-resolution),
// with the VM base-object string table as a fallback for synthetic "::"
// top-level-scope class names.
//
// ranges and code may be nil: the descriptor set is still built, with
// CodeSize 0 and no hash, and Diff then reports only added/removed. That
// is the honest degradation -- reporting "changed" from payload_info was
// not.
func Build(result *cluster.Result, pl *naming.PoolLookups, ct *snapshot.CIDTable,
	ranges []cluster.CodeRange, code []byte, codeOff uint64) map[FuncDescriptor]FuncInfo {
	out := make(map[FuncDescriptor]FuncInfo)

	// Function RefID -> the code range that implements it.
	type codeInfo struct {
		size int64
		hash string
	}
	byOwner := make(map[int]codeInfo, len(ranges))
	im := cluster.CodeImage{Code: code, CodeOff: codeOff}
	for i := range ranges {
		r := &ranges[i]
		if r.OwnerRef < 0 {
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
		byOwner[r.OwnerRef] = ci
	}
	for i := range result.Named {
		no := &result.Named[i]
		if no.CID != ct.Function {
			continue
		}
		ownerName := resolveEffectiveOwnerName(no, pl, ct)
		name := pl.ResolveName(no)
		if name == "" {
			continue // unnamed/anonymous closures aren't stable diff targets
		}
		desc := FuncDescriptor(ownerName + "::" + name)
		if _, exists := out[desc]; !exists {
			ci := byOwner[no.RefID]
			out[desc] = FuncInfo{
				RefID:     no.RefID,
				CodeSize:  ci.size,
				InstrHash: ci.hash,
			}
		}
	}
	return out
}

func resolveEffectiveOwnerName(no *cluster.NamedObject, pl *naming.PoolLookups, ct *snapshot.CIDTable) string {
	effectiveClass := no.OwnerRefID
	if ct != nil && ct.PatchClass != 0 {
		if owner, ok := pl.RefToNamed[no.OwnerRefID]; ok && owner.CID == ct.PatchClass {
			effectiveClass = owner.OwnerRefID
		}
	}
	classObj, ok := pl.RefToNamed[effectiveClass]
	if !ok && pl.VmRefToNamed != nil {
		classObj, ok = pl.VmRefToNamed[effectiveClass]
	}
	if !ok {
		return ""
	}
	name := pl.ResolveName(classObj)
	if name == "" {
		name = pl.ResolveVMName(classObj)
	}
	return name
}

// Load runs aotopsy's standard fast-path parse (elfx -> snapshot ->
// cluster scan+fill, isolate + VM snapshot) and builds the descriptor set
// for one libapp.so build.
func Load(libPath string) (descriptors map[FuncDescriptor]FuncInfo, dartVersion string, err error) {
	sc, err := analysis.LoadSnapshot(libPath, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
	if err != nil {
		return nil, "", fmt.Errorf("funcdiff: %s: %w", libPath, err)
	}
	defer func() { _ = sc.Close() }()

	descriptors = Build(sc.Result, sc.Pool, sc.Info.Version.CIDs, sc.Ranges, sc.Code, sc.CodeOff)
	return descriptors, sc.Info.Version.DartVersion, nil
}

// PackageCounts is unused for now (no per-class library-URI tracking to
// bucket by package) -- kept as a documented gap versus flutterdec's
// collect_diff_package_counts, which buckets by dart:/package: URI.

// Report is the result of diffing two builds' function descriptor sets.
type Report struct {
	OldPath      string   `json:"old_path"`
	NewPath      string   `json:"new_path"`
	OldVersion   string   `json:"old_dart_version"`
	NewVersion   string   `json:"new_dart_version"`
	OldCount     int      `json:"old_count"`
	NewCount     int      `json:"new_count"`
	CommonCount  int      `json:"common_count"`
	AddedTotal   int      `json:"added_total"`
	RemovedTotal int      `json:"removed_total"`
	ChangedTotal int      `json:"changed_total"`
	Added        []string `json:"added"`
	Removed      []string `json:"removed"`
	Changed      []string `json:"changed,omitempty"`
	Truncated    bool     `json:"truncated"`
}

// Diff loads both builds and computes the added/removed/common/changed
// function descriptor sets.
func Diff(oldPath, newPath string, topN int) (*Report, error) {
	oldDescs, oldVer, err := Load(oldPath)
	if err != nil {
		return nil, err
	}
	newDescs, newVer, err := Load(newPath)
	if err != nil {
		return nil, err
	}

	rep := DiffDescriptors(oldDescs, newDescs, topN)
	rep.OldPath = oldPath
	rep.NewPath = newPath
	rep.OldVersion = oldVer
	rep.NewVersion = newVer
	return rep, nil
}

// DiffDescriptors computes differences between two in-memory function descriptor sets.
func DiffDescriptors(oldDescs, newDescs map[FuncDescriptor]FuncInfo, topN int) *Report {
	var added, removed, changed []string
	common := 0
	for d, newInfo := range newDescs {
		if oldInfo, ok := oldDescs[d]; !ok {
			added = append(added, string(d))
		} else {
			common++
			// Prefer the hash: a body rewritten to the same length is a
			// change the size alone cannot see. Fall back to the size when
			// either side has no code (Build was given no instructions
			// image), and report nothing when neither is available rather
			// than guessing.
			switch {
			case oldInfo.InstrHash != "" && newInfo.InstrHash != "":
				if oldInfo.InstrHash != newInfo.InstrHash {
					changed = append(changed, string(d))
				}
			case oldInfo.CodeSize != 0 || newInfo.CodeSize != 0:
				if oldInfo.CodeSize != newInfo.CodeSize {
					changed = append(changed, string(d))
				}
			}
		}
	}
	for d := range oldDescs {
		if _, ok := newDescs[d]; !ok {
			removed = append(removed, string(d))
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)

	rep := &Report{
		OldCount:     len(oldDescs),
		NewCount:     len(newDescs),
		CommonCount:  common,
		AddedTotal:   len(added),
		RemovedTotal: len(removed),
		ChangedTotal: len(changed),
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
	return rep
}
