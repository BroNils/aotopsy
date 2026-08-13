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

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/pipeline"
	"aotopsy/internal/snapshot"
)

// FuncDescriptor is the canonical identity of one function, analogous to
// flutterdec's "<library_uri>::<owner_class>::<name>" descriptor string.
// aotopsy does not currently track a per-class library URI, so the
// descriptor here is "<owner_class>::<name>" -- still a meaningful,
// collision-resistant identity for diffing, just without the library-URI
// segment flutterdec's descriptor has.
type FuncDescriptor string

// Build assembles descriptor -> ref ID for every Function NamedObject in
// a loaded snapshot, one hop through PatchClass (mirroring
// cmd/aotopsy/refinfo.go's listToplevelFunctions owner-resolution),
// with the VM base-object string table as a fallback for synthetic "::"
// top-level-scope class names.
func Build(result *cluster.Result, pl *pipeline.PoolLookups, ct *snapshot.CIDTable) map[FuncDescriptor]int {
	out := make(map[FuncDescriptor]int)
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
			out[desc] = no.RefID
		}
	}
	return out
}

func resolveEffectiveOwnerName(no *cluster.NamedObject, pl *pipeline.PoolLookups, ct *snapshot.CIDTable) string {
	effectiveClass := no.OwnerRefID
	if owner, ok := pl.RefToNamed[no.OwnerRefID]; ok && owner.CID == ct.PatchClass {
		effectiveClass = owner.OwnerRefID
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
func Load(libPath string) (descriptors map[FuncDescriptor]int, dartVersion string, err error) {
	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}

	ef, err := elfx.Open(libPath)
	if err != nil {
		return nil, "", fmt.Errorf("funcdiff: open %s: %w", libPath, err)
	}
	defer func() { _ = ef.Close() }()

	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		return nil, "", fmt.Errorf("funcdiff: extract %s: %w", libPath, err)
	}

	data := info.IsolateData.Data
	clusterStart, err := cluster.FindClusterDataStart(data)
	if err != nil {
		return nil, "", fmt.Errorf("funcdiff: cluster start %s: %w", libPath, err)
	}
	result, err := cluster.ScanClusters(data, clusterStart, info.Version, false, opts)
	if err != nil {
		return nil, "", fmt.Errorf("funcdiff: scan %s: %w", libPath, err)
	}
	if err := cluster.ReadFill(data, result, info.Version, false, info.IsolateHeader.TotalSize); err != nil {
		return nil, "", fmt.Errorf("funcdiff: fill %s: %w", libPath, err)
	}

	var vmResult *cluster.Result
	vmData := info.VmData.Data
	if len(vmData) >= 64 && info.VmHeader != nil {
		if vmStart, err := cluster.FindClusterDataStart(vmData); err == nil {
			if vmRes, err := cluster.ScanClusters(vmData, vmStart, info.Version, true, opts); err == nil {
				_ = cluster.ReadFill(vmData, vmRes, info.Version, true, info.VmHeader.TotalSize)
				vmResult = vmRes
			}
		}
	}

	pl := pipeline.BuildPoolLookups(result, info.Version.CIDs, vmResult, info.Version.CodeIndexOneBased, info.Version.DartVersion, info.Version.TypeClassIdIsRef)
	descriptors = Build(result, pl, info.Version.CIDs)
	return descriptors, info.Version.DartVersion, nil
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
	Added        []string `json:"added"`
	Removed      []string `json:"removed"`
	Truncated    bool     `json:"truncated"`
}

// Diff loads both builds and computes the added/removed/common function
// descriptor sets (plain set difference/intersection -- flutterdec's
// run_diff does no fuzzy matching either, and neither do we).
func Diff(oldPath, newPath string, topN int) (*Report, error) {
	oldDescs, oldVer, err := Load(oldPath)
	if err != nil {
		return nil, err
	}
	newDescs, newVer, err := Load(newPath)
	if err != nil {
		return nil, err
	}

	var added, removed []string
	common := 0
	for d := range newDescs {
		if _, ok := oldDescs[d]; !ok {
			added = append(added, string(d))
		} else {
			common++
		}
	}
	for d := range oldDescs {
		if _, ok := newDescs[d]; !ok {
			removed = append(removed, string(d))
		}
	}
	sort.Strings(added)
	sort.Strings(removed)

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
	return rep, nil
}
