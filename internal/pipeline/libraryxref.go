package pipeline

import (
	"sort"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/naming"
)

// Library cross-referencing: the consumer for the Script/Library capture,
// covering the gap-analysis §6 row "No library → functions xref — Group
// functions by OwnerName; emit library_functions.jsonl".
//
// Note this groups by the owning LIBRARY's url, not by the Script url. They are
// usually the same string for single-file libraries but diverge for a library
// assembled from `part` files: several Scripts, one Library. Grouping by
// Library is what callers asking "what code belongs to package:foo" want.

// LibraryResolver maps a Function (or Class) ref to its owning library URL.
//
// This hoists logic that previously existed only as closures inside
// cmd/aotopsy/decompile_native_cmd.go (effectiveOwnerClassRef /
// libraryURLForClassRef), so the pipeline and the decompiler command resolve
// libraries the same way instead of maintaining two copies.
type LibraryResolver struct {
	pl         *naming.PoolLookups
	classByRef map[int]cluster.ClassInfo
}

// NewLibraryResolver builds the class-ref index needed for library lookups.
func NewLibraryResolver(result *cluster.Result, pl *naming.PoolLookups) *LibraryResolver {
	byRef := make(map[int]cluster.ClassInfo, len(result.Classes))
	for _, ci := range result.Classes {
		byRef[ci.RefID] = ci
	}
	return &LibraryResolver{pl: pl, classByRef: byRef}
}

// EffectiveClassRef resolves a Function's owner to a real Class ref, hopping
// through a PatchClass when Dart wrapped the owner (mixin application, patched
// library). This is the documented PatchClass hop from ARCHITECTURE.md.
func (r *LibraryResolver) EffectiveClassRef(ownerRefID int) int {
	if r.pl == nil || r.pl.CT == nil {
		return ownerRefID
	}
	if owner, ok := r.pl.RefToNamed[ownerRefID]; ok && owner.CID == r.pl.CT.PatchClass {
		return owner.OwnerRefID
	}
	return ownerRefID
}

// LibraryURLForClassRef returns the library URL owning a class, or "".
func (r *LibraryResolver) LibraryURLForClassRef(classRef int) string {
	ci, ok := r.classByRef[classRef]
	if !ok || ci.LibraryRefID < 0 {
		return ""
	}
	libObj, ok := r.pl.RefToNamed[ci.LibraryRefID]
	if !ok {
		return ""
	}
	if url := r.pl.ResolveName(libObj); url != "" {
		return url
	}
	return r.pl.ResolveVMName(libObj)
}

// IsFrameworkLibraryURL reports whether a URL belongs to the SDK or Flutter
// rather than to application or third-party code.
func IsFrameworkLibraryURL(url string) bool {
	return strings.HasPrefix(url, "dart:") || strings.HasPrefix(url, "package:flutter")
}

// LibraryFunctionsRecord is one line in library_functions.jsonl.
type LibraryFunctionsRecord struct {
	URL string `json:"url"`
	// IsFramework marks dart:* / package:flutter* libraries, so consumers can
	// isolate application code without re-deriving the rule.
	IsFramework bool `json:"is_framework,omitempty"`
	ClassCount  int  `json:"class_count"`
	FuncCount   int  `json:"func_count"`
	// Functions are qualified "Owner.name" where an owner is known, sorted.
	Functions []string `json:"functions,omitempty"`
	// Classes are the class names owned by this library, sorted.
	Classes []string `json:"classes,omitempty"`
}

// BuildLibraryFunctions groups every Function and Class in the snapshot by its
// owning library URL.
//
// It works off the cluster/fill capture rather than the disassembly output, so
// it covers functions that were never disassembled (discarded Code, abstract
// methods) too. Functions whose library cannot be resolved are collected under
// the empty URL and reported as such rather than dropped, so the counts always
// add up to the number of Function objects present.
func BuildLibraryFunctions(result *cluster.Result, pl *naming.PoolLookups) []LibraryFunctionsRecord {
	if pl == nil || pl.CT == nil {
		return nil
	}
	res := NewLibraryResolver(result, pl)

	type bucket struct {
		funcs   []string
		classes []string
	}
	buckets := map[string]*bucket{}
	get := func(url string) *bucket {
		b, ok := buckets[url]
		if !ok {
			b = &bucket{}
			buckets[url] = b
		}
		return b
	}

	for i := range result.Named {
		no := &result.Named[i]
		switch no.CID {
		case pl.CT.Function:
			classRef := res.EffectiveClassRef(no.OwnerRefID)
			url := res.LibraryURLForClassRef(classRef)
			name := pl.ResolveName(no)
			if name == "" {
				name = pl.ResolveVMName(no)
			}
			if ownerName := ownerDisplayName(pl, classRef); ownerName != "" && name != "" {
				name = ownerName + "." + name
			}
			get(url).funcs = append(get(url).funcs, name)
		case pl.CT.Class:
			url := res.LibraryURLForClassRef(no.RefID)
			if name := pl.ResolveName(no); name != "" {
				get(url).classes = append(get(url).classes, name)
			}
		}
	}

	records := make([]LibraryFunctionsRecord, 0, len(buckets))
	for url, b := range buckets {
		sort.Strings(b.funcs)
		sort.Strings(b.classes)
		records = append(records, LibraryFunctionsRecord{
			URL:         url,
			IsFramework: IsFrameworkLibraryURL(url),
			ClassCount:  len(b.classes),
			FuncCount:   len(b.funcs),
			Functions:   b.funcs,
			Classes:     b.classes,
		})
	}
	// Deterministic order: unresolved ("") last, then by URL.
	sort.Slice(records, func(i, j int) bool {
		if (records[i].URL == "") != (records[j].URL == "") {
			return records[j].URL == ""
		}
		return records[i].URL < records[j].URL
	})
	return records
}

// ownerDisplayName resolves a class ref to its name for qualification.
func ownerDisplayName(pl *naming.PoolLookups, classRef int) string {
	no, ok := pl.RefToNamed[classRef]
	if !ok {
		return ""
	}
	if name := pl.ResolveName(no); name != "" {
		return name
	}
	return pl.ResolveVMName(no)
}
