// Package funcdiff diffs the set of Dart functions between two libapp.so
// builds (e.g. before/after a code change, or two app versions), reusing
// aotopsy's own real Dart-AOT snapshot cluster deserializer for function
// identity -- unlike flutterdec's pipeline/runners_diff.rs (Rust), which
// has to fall back to a heuristic library-URI/owner-class model because
// flutterdec-core has no real cluster parser of its own. Ported concept,
// better ground truth.
package funcdiff

import (
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

// FuncInfo holds a function's descriptor and code size for change detection.
type FuncInfo struct {
	RefID    int
	CodeSize int64 // PayloadInfo from CodeEntry (proxy for instruction count)
}

// Build assembles descriptor -> FuncInfo for every Function NamedObject in
// a loaded snapshot, one hop through PatchClass (mirroring
// cmd/aotopsy/refinfo.go's listToplevelFunctions owner-resolution),
// with the VM base-object string table as a fallback for synthetic "::"
// top-level-scope class names.
func Build(result *cluster.Result, pl *naming.PoolLookups, ct *snapshot.CIDTable) map[FuncDescriptor]FuncInfo {
	out := make(map[FuncDescriptor]FuncInfo)
	// Build Function RefID → code size map from CodeEntry.OwnerRef.
	codeSizeByOwner := make(map[int]int64)
	for i := range result.Codes {
		ce := &result.Codes[i]
		if ce.OwnerRef >= 0 {
			codeSizeByOwner[ce.OwnerRef] = ce.PayloadInfo
		}
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
			out[desc] = FuncInfo{
				RefID:    no.RefID,
				CodeSize: codeSizeByOwner[no.RefID],
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

	descriptors = Build(sc.Result, sc.Pool, sc.Info.Version.CIDs)
	return descriptors, sc.Info.Version.DartVersion, nil
}

// PackageCounts is unused for now (no per-class library-URI tracking to
// bucket by package) -- kept as a documented gap versus flutterdec's
// collect_diff_package_counts, which buckets by dart:/package: URI.

// Report is the result of diffing two builds' function descriptor sets.
type Report struct {
	OldPath     string   `json:"old_path"`
	NewPath     string   `json:"new_path"`
	OldVersion  string   `json:"old_dart_version"`
	NewVersion  string   `json:"new_dart_version"`
	OldCount    int      `json:"old_count"`
	NewCount    int      `json:"new_count"`
	CommonCount int      `json:"common_count"`
	AddedTotal  int      `json:"added_total"`
	RemovedTotal int     `json:"removed_total"`
	ChangedTotal int     `json:"changed_total"`
	Added       []string `json:"added"`
	Removed     []string `json:"removed"`
	Changed     []string `json:"changed,omitempty"`
	Truncated   bool     `json:"truncated"`
}

// Diff loads both builds and computes the added/removed/common/changed
// function descriptor sets. A function is "changed" when it exists in both
// builds but has a different code size (PayloadInfo), indicating the
// compiler emitted different instructions for the same named function.
func Diff(oldPath, newPath string, topN int) (*Report, error) {
	oldDescs, oldVer, err := Load(oldPath)
	if err != nil {
		return nil, err
	}
	newDescs, newVer, err := Load(newPath)
	if err != nil {
		return nil, err
	}

	var added, removed, changed []string
	common := 0
	for d, newInfo := range newDescs {
		if oldInfo, ok := oldDescs[d]; !ok {
			added = append(added, string(d))
		} else {
			common++
			if oldInfo.CodeSize != newInfo.CodeSize {
				changed = append(changed, string(d))
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
		OldPath:      oldPath,
		NewPath:      newPath,
		OldVersion:   oldVer,
		NewVersion:   newVer,
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
	return rep, nil
}
