package analysis

import (
	"sort"

	"aotopsy/internal/cluster"
	"aotopsy/internal/sdk"
)

// NativeCapability is one VM native the snapshot can reach.
type NativeCapability struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	RefID    int    `json:"ref_id"`
}

// BuildNativeCapabilities lists the VM native functions a snapshot can
// reach, classified by what reaching them means.
//
// These names sit in the object pool as ordinary strings -- Ffi_dl_open,
// File_Open, Socket_CreateConnect, Process_Start -- and they are the most
// durable behavioural evidence a stripped binary offers: the VM resolves
// natives by name at runtime, so obfuscation cannot touch them.
//
// They are deliberately NOT read from string_refs. Nothing in generated
// Dart code loads them -- measured: zero of the 105 native names in
// dart-3.9.2-arm64 appear in string_refs.jsonl, because it is the VM that
// resolves them, not the app. Classifying them through the reference path
// would therefore report nothing at all, which is exactly what it did
// before this existed.
//
// The result is a property of the binary rather than of any function, so
// it gets its own artifact instead of a category on a signal-graph node.
// Both snapshots are scanned. Most native names live in the VM snapshot's
// string pool, not the isolate's: reading only the isolate found 20 of the
// 105 that a raw `strings` sweep shows.
func BuildNativeCapabilities(isolate, vm *cluster.Result) []NativeCapability {
	seen := make(map[string]bool, 128)
	var out []NativeCapability
	for _, res := range []*cluster.Result{vm, isolate} {
		if res == nil {
			continue
		}
		for _, ps := range res.Strings {
			if seen[ps.Value] {
				continue
			}
			cat, ok := sdk.DartNativeCategory(ps.Value)
			if !ok {
				continue
			}
			seen[ps.Value] = true
			out = append(out, NativeCapability{Name: ps.Value, Category: cat, RefID: ps.RefID})
		}
	}
	// Deterministic order: the artifact is hashed by the golden gate, and
	// cluster.Result's string order is stable but the dedup map is not.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})
	return out
}
