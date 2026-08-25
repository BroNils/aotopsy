package cluster

import (
	"fmt"
	"os"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

var debugDT = os.Getenv("DEFLUTTER_DEBUG_DT") != ""

// DispatchTableEntryKind classifies what a DispatchTableEntry points at.
type DispatchTableEntryKind int

const (
	// DispatchNull: this slot points at the null-error stub -- i.e. no
	// override exists for this class+selector combination (encoded as a
	// literal 0 in the stream).
	DispatchNull DispatchTableEntryKind = iota
	// DispatchCode: this slot points at a real Code object. ClusterIndex
	// is in the SAME numbering domain as CodeEntry.ClusterIndex and
	// Function.CodeIndex (see pipeline.CodeIndexToFunc) -- resolvable to
	// a real function name via either.
	DispatchCode
	// DispatchStub: this slot points at a stub/trampoline slot in the
	// InstructionsTable (e.g. a NoSuchMethod dispatcher or other shared
	// VM-internal stub) rather than a Dart Function. StubIndex is the
	// ABSOLUTE table slot, matching ResolveStubRanges' Index domain
	// (0..FirstEntryWithCode-1) -- a DIFFERENT numbering domain than
	// ClusterIndex, deliberately kept separate rather than conflated.
	DispatchStub
)

// DispatchTableEntry is one resolved slot of the AOT snapshot's
// DispatchTable -- the mechanism `EmitDispatchTableCall` uses for
// megamorphic/polymorphic instance dispatch (`class_id + selector_offset`
// -> call target), which carries NO name in the instruction stream
// itself (see ARCHITECTURE.md's "DispatchTable parsing" section for the
// full investigation this implements).
type DispatchTableEntry struct {
	Index        int // slot index within the dispatch table
	Kind         DispatchTableEntryKind
	ClusterIndex int // valid when Kind == DispatchCode
	StubIndex    int // valid when Kind == DispatchStub
	CodeRef      int // ref ID of Code object (TARGET 3: for 2.x fallback)
	OwnerRef     int // owner ref ID of Code object (TARGET 3: for 2.x fallback)
}

// dispatch table RLE encoding constants, verified directly against
// dart-lang/sdk's runtime/vm/app_snapshot.cc (kDispatchTableSpecialEncodingBits
// = 6, unchanged across every version checked: 3.7.0, 3.10.0/3.10.7).
const (
	dispatchTableRecentCount = 1 << 6
	dispatchTableRecentMask  = (1 << 6) - 1
	dispatchTableMaxRepeat   = (1 << 6) - 1
	dispatchTableIndexBase   = dispatchTableMaxRepeat + 1
)

// ParseDispatchTable reads the isolate snapshot's roots section
// (immediately following the last cluster's fill data, at
// result.FillEnd -- see ReadFill's doc comment) and decodes the real
// DispatchTable, when this Dart version's exact byte-for-byte layout of
// everything BEFORE the dispatch table has been verified (see
// snapshot.VersionProfile.ObjectStoreAOTFieldCount's doc comment).
//
// This replays, in order (matching dart-lang/sdk's
// ProgramDeserializationRoots::ReadRoots exactly, runtime/vm/
// app_snapshot.cc):
//  1. ObjectStore fields: ObjectStoreAOTFieldCount plain ReadRef() calls
//     (ObjectStore::from() through to_snapshot(kFullAOT) inclusive).
//  2. initial_field_table: ReadUnsigned(n) + n * ReadRef().
//  3. shared_initial_field_table: ReadUnsigned(n) + n * ReadRef().
//  4. The dispatch table itself: ReadUnsigned(length) +
//     ReadUnsigned(first_code_id) + an RLE-encoded array of `length`
//     intptr_t-sized signed values (dartfmt.Stream.ReadTagged64),
//     decoded per dart-lang/sdk's Deserializer::ReadDispatchTable.
//
// Verified end-to-end against two real, independently-version-checked
// binaries (Dart 3.7.0 sample and Dart 3.10.7/sample_310): every single
// non-repeat-continuation entry classified cleanly as DispatchNull,
// DispatchCode (matching a real Code/Function), or DispatchStub
// (matching a real InstructionsTable stub slot) -- zero entries fell
// into none of those three buckets on either binary.
//
// Returns an error (not a guess) if ObjectStoreAOTFieldCount is 0
// (unverified for this Dart version) or result.FillEnd is unset (0,
// meaning ReadFill was never run).
func ParseDispatchTable(data []byte, result *Result, profile *snapshot.VersionProfile, table *InstructionsTable) ([]DispatchTableEntry, error) {

	if result.FillEnd <= 0 {
		return nil, fmt.Errorf("dispatch table: ReadFill must run first (FillEnd unset)")
	}
	if profile.ObjectStoreAOTFieldCount <= 0 {
		return nil, fmt.Errorf("dispatch table: ObjectStoreAOTFieldCount not verified for Dart %s -- refusing to guess the roots-section layout", profile.DartVersion)
	}

	// TARGET 3: For Dart 2.x (no InstructionsTable), use first_code_id
	// fallback. The SDK's ReadDispatchTable reads first_code_id from the
	// stream and resolves code via Ref(first_code_id + cluster_index).
	// We build a refID → CodeEntry lookup from result.Codes.
	useTextOffsetFallback := table == nil
	if useTextOffsetFallback {
		if len(result.Codes) == 0 {
			return nil, fmt.Errorf("dispatch table: no Codes available for Dart %s TextOffset fallback", profile.DartVersion)
		}
		// Build refID → ClusterIndex map from result.Codes.
		// first_code_id is the ref ID of the first Code object.
		// cluster_index = encoded - kDispatchTableIndexBase.
		// Code object ref = first_code_id + cluster_index.
		// We need to map ref → owner function name.
		// This will be done after reading first_code_id below.
	}

	s := dartfmt.NewStreamAt(data, result.FillEnd)
	fillRefUnsigned := profile.FillRefUnsigned

	// 0. The Roots prefix, from 3.13.0 on: VM bootstrap objects and the
	// predefined class table, read before anything else. Zero on every
	// earlier version. See snapshot.VersionProfile.RootsPrefixRefCount for
	// the SDK derivation and for what breaks when it is skipped.
	for i := 0; i < profile.RootsPrefixRefCount; i++ {
		if _, err := readRef(s, fillRefUnsigned); err != nil {
			return nil, fmt.Errorf("dispatch table: roots prefix ref %d/%d: %w", i, profile.RootsPrefixRefCount, err)
		}
	}

	// 1. ObjectStore fields -- plain refs, contents intentionally
	// discarded: ParseDispatchTable only needs to advance the stream by
	// the correct number of bytes, not interpret what each field means.
	for i := 0; i < profile.ObjectStoreAOTFieldCount; i++ {
		if _, err := readRef(s, fillRefUnsigned); err != nil {
			return nil, fmt.Errorf("dispatch table: object_store field %d/%d: %w", i, profile.ObjectStoreAOTFieldCount, err)
		}
	}

	// 2. initial_field_table, 3. shared_initial_field_table.
	//
	// Which of these the roots section contains is a per-version fact, and
	// there are three distinct shapes -- verified by reading
	// ProgramDeserializationRoots::ReadRoots at twelve dart-lang/sdk tags:
	//
	//	<= 2.17.6   ObjectStore refs, then straight to ReadDispatchTable
	//	>= 2.18.0   ... initial_field_table, then ReadDispatchTable
	//	>= 3.5.0    ... initial_field_table, shared_initial_field_table, ...
	//	>= 3.13.0   a Roots prefix comes FIRST, ahead of the ObjectStore refs
	//	            -- see RootsPrefixRefCount, handled above as step 0.
	//
	// (2.10-2.15 predate the class entirely; they fall under the first case.)
	//
	// This used to be one gate on CodeTextOffsetDelta, which puts the boundary
	// at 2.15/2.16 and reads BOTH tables above it. That is wrong for every
	// version from 2.16 through 3.4.3: on 2.17.6 it invents two tables that
	// are not there, and on 3.1.0 one. Either way the stream desynchronises
	// and the dispatch table is unreadable, which silently disables the whole
	// type-inference stage -- no typetrack_report.json and every BLR edge left
	// unresolved. It went unnoticed because the only samples this was ever run
	// against were 3.7.0 and 3.10.7, where reading both is correct.
	readInitial := dartVersionAtLeast(profile.DartVersion, "2.18.0")
	readShared := dartVersionAtLeast(profile.DartVersion, "3.5.0")
	tables := make([]string, 0, 2)
	if readInitial {
		tables = append(tables, "initial_field_table")
	}
	if readShared {
		tables = append(tables, "shared_initial_field_table")
	}
	for _, name := range tables {
		n, err := s.ReadUnsigned()
		if debugDT {
			fmt.Fprintf(os.Stderr, "DEBUG DT: %s count=%d pos=%d\n", name, n, s.Position())
		}
		if err != nil {
			return nil, fmt.Errorf("dispatch table: %s count: %w", name, err)
		}
		for i := int64(0); i < n; i++ {
			if _, err := readRef(s, fillRefUnsigned); err != nil {
				return nil, fmt.Errorf("dispatch table: %s entry %d/%d: %w", name, i, n, err)
			}
		}
	}

	// 4. The dispatch table itself.
	length, err := s.ReadUnsigned()
	if err != nil {
		return nil, fmt.Errorf("dispatch table: length: %w", err)
	}
	if length == 0 {
		return nil, nil
	}
	// P5-3 (D-027): Cap length against data size to prevent OOM on
	// malformed input. Each dispatch table entry requires at least 1
	// byte in the encoded stream, so length can't exceed len(data)*8.
	maxLen := int64(len(data)) * 8
	if length > maxLen {
		return nil, fmt.Errorf("dispatch table: length %d exceeds data bounds %d (corrupt snapshot?)", length, maxLen)
	}
	firstCodeID, err := s.ReadUnsigned()
	if err != nil {
		return nil, fmt.Errorf("dispatch table: first_code_id: %w", err)
	}

	// TARGET 3: For Dart 2.x (TextOffset fallback), build refID → Code
	// lookup. first_code_id is the ref ID of the first Code object.
	// cluster_index = encoded - kDispatchTableIndexBase.
	// Code ref = first_code_id + cluster_index.
	var codeByRef map[int]*CodeEntry
	if useTextOffsetFallback {
		codeByRef = make(map[int]*CodeEntry, len(result.Codes))
		for i := range result.Codes {
			codeByRef[result.Codes[i].RefID] = &result.Codes[i]
		}
	}

	firstEntryWithCode := 0
	if table != nil {
		firstEntryWithCode = int(table.FirstEntryWithCode)
	}
	var recent [dispatchTableRecentCount]DispatchTableEntry
	recentIndex := 0
	var value DispatchTableEntry
	repeatCount := int64(0)

	entries := make([]DispatchTableEntry, 0, length)
	for i := int64(0); i < length; i++ {
		if repeatCount > 0 {
			e := value
			e.Index = int(i)
			entries = append(entries, e)
			repeatCount--
			continue
		}

		encoded, err := s.ReadTagged64()
		if err != nil {
			return entries, fmt.Errorf("dispatch table: entry %d/%d: %w", i, length, err)
		}
		switch {
		case encoded == 0:
			value = DispatchTableEntry{Kind: DispatchNull}
		case encoded < 0:
			r := ^encoded // bitwise complement, matches dart-lang/sdk's `~encoded`
			if r < 0 || r >= dispatchTableRecentCount {
				return entries, fmt.Errorf("dispatch table: entry %d: bad recent index %d", i, r)
			}
			value = recent[r]
		case encoded <= dispatchTableMaxRepeat:
			// Repeat marker: value is left UNCHANGED (repeats the
			// previous entry's value); repeatCount governs how many
			// MORE entries after this one also get it.
			repeatCount = encoded - 1
		default:
			// code_index encoding is version-dependent:
			// Dart >=2.16: code_index is 1-based (0=LazyCompile stub),
			//   so absoluteSlot = codeIndex - 1.
			// Dart <=2.15: code_index is 0-based (direct cluster index),
			//   so absoluteSlot = codeIndex (no subtract).
			// Confirmed via gh api at tags 2.14.0 (no -1) vs 2.16.0+ (-1).
			// Comparing against FirstEntryWithCode tells apart a real
			// Code target (ClusterIndex, relative to FirstEntryWithCode)
			// from a stub target (StubIndex, absolute).
			codeIndex := int(encoded) - dispatchTableIndexBase
			absoluteSlot := codeIndex
			if profile.CodeIndexOneBased {
				absoluteSlot = codeIndex - 1
			}

			if useTextOffsetFallback {
				// TARGET 3: Dart 2.x TextOffset fallback.
				// Code ref = first_code_id + cluster_index.
				// No FirstEntryWithCode — all entries are code entries
				// (stubs are encoded as 0 or negative).
				codeRef := int(firstCodeID) + absoluteSlot
				if ce, ok := codeByRef[codeRef]; ok {
					value = DispatchTableEntry{Kind: DispatchCode, ClusterIndex: absoluteSlot, CodeRef: ce.RefID, OwnerRef: ce.OwnerRef}
				} else {
					value = DispatchTableEntry{Kind: DispatchCode, ClusterIndex: absoluteSlot}
				}
			} else if absoluteSlot < firstEntryWithCode {
				value = DispatchTableEntry{Kind: DispatchStub, StubIndex: absoluteSlot}
			} else {
				value = DispatchTableEntry{Kind: DispatchCode, ClusterIndex: absoluteSlot - firstEntryWithCode}
			}
			// recent buffer update: version-dependent.
			// Dart >=2.16: update ONLY for code-index entries (inside
			// the else block in the SDK's ReadDispatchTable).
			// Dart <=2.15: ALSO update only for code-index entries —
			// verified directly against dart-lang/sdk source at tags
			// 2.12.0, 2.14.0, 2.15.0, 2.16.0, 3.9.2: in ALL versions
			// the recent update is inside the code-index else block only.
			// (The previous claim that pre-2.16 updated for ALL entry
			// types was factually wrong — corrected in audit C-2.)
			recent[recentIndex] = value
			recentIndex = (recentIndex + 1) & dispatchTableRecentMask
		}

		e := value
		e.Index = int(i)
		entries = append(entries, e)
	}
	return entries, nil
}
