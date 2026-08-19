package snapshot

import "strconv"

// VM-isolate base objects: the objects the deserializer assigns reference IDs
// to before reading anything, so they are never written into the snapshot.
//
// dart-lang/sdk's AddBaseObjects (runtime/vm/app_snapshot.cc, and
// runtime/vm/clustered_snapshot.cc before 2.13) calls
//
//	s->AddBaseObject(Object::null(), "Null", "null");
//	...
//	s->AddBaseObject(Bool::True().ptr(),  "bool", "true");
//	s->AddBaseObject(Bool::False().ptr(), "bool", "false");
//
// in a fixed order, and the third argument is the SDK's own display name.
// Reference IDs are assigned in that order starting at 1, so an object pool
// entry pointing at ref N is exactly the Nth entry of this list.
//
// The list is NOT stable across versions, and not in a way that can be
// guessed. Every minor from 2.12 to 3.12 was read from the SDK; the index of
// `true` alone is 9, then 10, then 11, then back to 10:
//
//	2.12-2.18  true=9   transition_sentinel, zero_array
//	2.19       true=9   zero_array -> empty_instantiations_cache_array
//	3.0-3.1    true=10  optimized_out added
//	3.2-3.4    true=11  empty_subtype_test_cache_array added
//	3.5-3.12   true=10  transition_sentinel removed
//
// So this is a table, not a formula, and a version outside it returns nil
// rather than a guess -- the caller then leaves the pool entry unnamed, which
// is what it did before this existed.
//
// TestBaseObjectNamesMatchSDK re-derives every row straight from the SDK and
// fails if a row drifts.

// baseObjectLayout is one contiguous run of Dart versions that share a base
// object list.
type baseObjectLayout struct {
	// minMajor/minMinor and maxMajor/maxMinor are inclusive bounds.
	minMajor, minMinor int
	maxMajor, maxMinor int
	names              []string
}

// The first 13 entries of each layout. Only the leading run matters: pool
// entries beyond it fall back to the existing name resolution, and carrying
// the full list would mean tracking entries no pool has been seen to
// reference.
var baseObjectLayouts = []baseObjectLayout{
	{2, 12, 2, 18, []string{
		"null", "sentinel", "transition_sentinel", "<empty_array>", "<zero_array>",
		"<dynamic type>", "<void type>", "[]", "true", "false",
		"<extractor parameter types>", "<extractor parameter names>", "<empty>",
	}},
	{2, 19, 2, 19, []string{
		"null", "sentinel", "transition_sentinel", "<empty_array>",
		"<empty_instantiations_cache_array>", "<dynamic type>", "<void type>", "[]",
		"true", "false",
		"<synthetic getter parameter types>", "<synthetic getter parameter names>", "<empty>",
	}},
	{3, 0, 3, 1, []string{
		"null", "sentinel", "transition_sentinel", "<optimized out>", "<empty_array>",
		"<empty_instantiations_cache_array>", "<dynamic type>", "<void type>", "[]",
		"true", "false",
		"<synthetic getter parameter types>", "<synthetic getter parameter names>",
	}},
	{3, 2, 3, 4, []string{
		"null", "sentinel", "transition_sentinel", "<optimized out>", "<empty_array>",
		"<empty_instantiations_cache_array>", "<empty_subtype_test_cache_array>",
		"<dynamic type>", "<void type>", "[]", "true", "false",
		"<synthetic getter parameter types>",
	}},
	{3, 5, 3, 12, []string{
		"null", "sentinel", "<optimized out>", "<empty_array>",
		"<empty_instantiations_cache_array>", "<empty_subtype_test_cache_array>",
		"<dynamic type>", "<void type>", "[]", "true", "false",
		"<synthetic getter parameter types>", "<synthetic getter parameter names>",
	}},
	// 3.13.0: fundamental change. AddBaseObjects no longer reads from
	// vm_isolate_snapshot_object_table (which carried ~12 entries including
	// empty_array, dynamic/void types, etc). Instead, for snapshots that
	// include code (kFullAOT), exactly 7 hardcoded Roots entries are added
	// as base objects. The empty_array etc are now pushed to early clusters
	// (PushRoots), not AddBaseObject. Verified via gh api to
	// dart-lang/sdk app_snapshot.cc @3.13.0: ProgramSerializationRoots::
	// AddBaseObjects and ProgramDeserializationRoots::AddBaseObjects both
	// add the same 7 in the same order. Roots::null_obj is ref 1, false is
	// ref 2, true is ref 3 — note true/false are SWAPPED vs 3.12.2 where
	// true=ref 9, false=ref 10.
	{3, 13, 3, 13, []string{
		"null", "false", "true", "sentinel", "unknown constant",
		"non constant", "<optimized out>",
	}},
}

// BaseObjectNames returns the SDK's display names for the VM-isolate base
// objects of a Dart version, indexed from 0 so entry i is reference ID i+1.
//
// Returns nil when the version is unknown or outside the verified range. The
// caller must treat that as "no name available" and must not fall back to a
// nearby version's list: the index of `true` moved four times between 2.12
// and 3.12, so a neighbouring list can name the wrong object.
func BaseObjectNames(dartVersion string) []string {
	major, minor, ok := parseMajorMinor(dartVersion)
	if !ok {
		return nil
	}
	for _, l := range baseObjectLayouts {
		if versionAtLeast(major, minor, l.minMajor, l.minMinor) &&
			versionAtMost(major, minor, l.maxMajor, l.maxMinor) {
			return l.names
		}
	}
	return nil
}

// BaseObjectName returns the display name for a base object reference ID
// (1-based), or "" when there is none.
func BaseObjectName(dartVersion string, refID int) string {
	names := BaseObjectNames(dartVersion)
	if refID < 1 || refID > len(names) {
		return ""
	}
	return names[refID-1]
}

func parseMajorMinor(v string) (major, minor int, ok bool) {
	i := 0
	for i < len(v) && v[i] >= '0' && v[i] <= '9' {
		i++
	}
	if i == 0 || i >= len(v) || v[i] != '.' {
		return 0, 0, false
	}
	major, err := strconv.Atoi(v[:i])
	if err != nil {
		return 0, 0, false
	}
	j := i + 1
	for j < len(v) && v[j] >= '0' && v[j] <= '9' {
		j++
	}
	if j == i+1 {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(v[i+1 : j])
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func versionAtLeast(major, minor, atLeastMajor, atLeastMinor int) bool {
	return major > atLeastMajor || (major == atLeastMajor && minor >= atLeastMinor)
}

func versionAtMost(major, minor, atMostMajor, atMostMinor int) bool {
	return major < atMostMajor || (major == atMostMajor && minor <= atMostMinor)
}
