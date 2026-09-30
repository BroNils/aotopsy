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
// No-op (nil error) when the version's ObjectStoreAOTFieldCount is unverified
// or ReadFill has not run: an unnamed stub is the honest outcome, a guessed
// stream position is not.
func ReadObjectStoreRefs(data []byte, result *Result, profile *snapshot.VersionProfile) error {
	if result == nil || profile == nil {
		return nil
	}
	if result.ObjectStoreRefs != nil {
		return nil // already read
	}
	if result.FillEnd <= 0 || profile.ObjectStoreAOTFieldCount <= 0 {
		return nil
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
