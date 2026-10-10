package cluster

import (
	"fmt"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

// ReadObjectStoreRefs fills Result.ObjectStoreRefs from the isolate roots
// section, without parsing anything after it.
//
// It reads exactly the prefix ParseDispatchTable reads before the dispatch
// table itself -- the 3.13.0+ roots prefix, then ObjectStoreAOTFieldCount
// plain refs -- so the two cannot disagree about where the object store
// starts. ParseDispatchTable calls this rather than duplicating the walk.
//
// Separate from ParseDispatchTable because the names come far earlier than the
// dispatch table does: LoadContext builds every function's display name, and
// the isolate stubs need theirs there, long before type tracking runs.
//
// Refuses unverified profiles or roots positions: an unnamed stub is preferable
// to guessed identity, but semantic callers also need to know why names are
// unavailable rather than silently continuing from a fabricated profile.
func ReadObjectStoreRefs(data []byte, result *Result, profile *snapshot.VersionProfile) error {
	if result == nil {
		return fmt.Errorf("object store roots: nil cluster result")
	}
	if !snapshot.IsExactSupportedProfile(profile) {
		return fmt.Errorf("object store roots: exact supported snapshot profile required")
	}
	if result.ObjectStoreRefs != nil {
		return nil // already read
	}
	if result.FillEnd <= 0 {
		return fmt.Errorf("object store roots: ReadFill must run first (FillEnd unset)")
	}
	if profile.ObjectStoreAOTFieldCount <= 0 {
		return fmt.Errorf("object store roots: ObjectStoreAOTFieldCount not verified for Dart %s", profile.DartVersion)
	}
	s, err := dartfmt.NewStreamAt(data, result.FillEnd)
	if err != nil {
		return fmt.Errorf("object store roots: stream start: %w", err)
	}
	return readObjectStoreRefsFromStream(s, result, profile)
}

// readObjectStoreRefsFromStream consumes the complete roots prefix through the
// ObjectStore range from the caller's current stream position. Both the early
// name-resolution path and ParseDispatchTable use this exact helper so a future
// Dart roots-layout change cannot advance one path but not the other.
func readObjectStoreRefsFromStream(s *dartfmt.Stream, result *Result, profile *snapshot.VersionProfile) error {
	for i := 0; i < profile.RootsPrefixRefCount; i++ {
		if _, err := readRef(s, profile.FillRefUnsigned); err != nil {
			return fmt.Errorf("object store roots: prefix ref %d/%d: %w", i, profile.RootsPrefixRefCount, err)
		}
	}
	refs := make([]int, 0, profile.ObjectStoreAOTFieldCount)
	for i := 0; i < profile.ObjectStoreAOTFieldCount; i++ {
		r, err := readRef(s, profile.FillRefUnsigned)
		if err != nil {
			return fmt.Errorf("object store roots: field %d/%d: %w", i, profile.ObjectStoreAOTFieldCount, err)
		}
		refs = append(refs, int(r))
	}
	if result.ObjectStoreRefs == nil {
		result.ObjectStoreRefs = refs
	}
	return nil
}
