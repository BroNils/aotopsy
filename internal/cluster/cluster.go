// Package cluster parses Dart AOT clustered snapshot data to recover
// object references, string values, function names, and code mappings.
package cluster

import (
	"fmt"
	"os"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/snapshot"
)

var debugAlloc = os.Getenv("DEFLUTTER_DEBUG_ALLOC") != ""

// Header holds the clustered snapshot section header fields.
type Header struct {
	NumBaseObjects             int64
	NumObjects                 int64
	NumCanonicalClusters       int64 // v2.12-2.13 only (SplitCanonical); 0 otherwise
	NumClusters                int64
	InitialFieldTableLen       int64 // v2.x only; 0 for v3.x
	InstructionsTableLen       int64
	InstructionTableDataOffset int64
}

// ClusterMeta describes one cluster read from the alloc section.
type ClusterMeta struct {
	Index       int
	CID         int
	IsCanonical bool
	IsImmutable bool
	Count       int64 // number of objects allocated
	StartRef    int   // first ref index assigned during alloc
	StopRef     int   // one past last ref index
	StartOffset int   // byte offset where this cluster's tag was read
	EndOffset   int   // byte offset after this cluster's alloc data

	// Instance-specific: set only for AllocInstance clusters.
	// next_field_offset_in_words from alloc; used by fill parser
	// to determine how many pointer fields each instance has.
	NextFieldOffsetInWords int32

	// Code-specific: main (non-deferred) count from alloc.
	// In fill, main codes read ReadUnsigned(payload_info) + refs,
	// deferred codes read only refs.
	MainCount int64

	// Code-specific: set of discarded code indices (DiscardedBit set in state_bits).
	// v2.14+: discarded codes in fill skip all refs; only ReadInstructions is called.
	DiscardedCodes map[int64]bool

	// Per-object lengths from alloc, for variable-length fill clusters.
	// Set for Array, WeakArray, Context, TypeArguments, ExceptionHandlers,
	// TypedData, ObjectPool, ContextScope, Record.
	Lengths []int64

	// Class-specific: predefined class CIDs from alloc phase.
	PredefCIDs []int64
}

// ParsedString holds a recovered string value and its ref index.
type ParsedString struct {
	RefID     int
	Value     string
	IsOneByte bool
}

// CodeEntry holds a Code object's ref, owner ref, and instruction metadata.
type CodeEntry struct {
	RefID                int
	OwnerRef             int   // ref ID of the owning Function/Closure/FfiTrampolineData
	ClusterIndex         int   // implicit instructions_index_ (main codes only; -1 for deferred)
	PayloadInfo          int64 // raw payload_info from fill (0 for deferred)
	TextOffset           int64 // text_offset_delta from fill (v2.10-v2.15 only; 0 otherwise)
	ExceptionHandlersRef int   // ref ID of ExceptionHandlers object (ref index 1); -1 if not captured
	PcDescriptorsRef     int   // ref ID of PcDescriptors object (ref index 2); -1 if not captured
	CodeSourceMapRef     int   // ref ID of CodeSourceMap object (ref index 5, AOT); -1 if not captured
	InlinedFuncsRef      int   // ref ID of inlined_id_to_function Array (ref index 4); -1 if not captured
}

// PoolEntryKind distinguishes ObjectPool entry types.
type PoolEntryKind uint8

const (
	PoolTagged    PoolEntryKind = iota // tagged object ref
	PoolImmediate                      // raw int64
	PoolNative                         // native function (no snapshot data)
	PoolEmpty                          // non-snapshotable (v3.x behavior != 0)
)

// PoolEntry is one entry in the isolate ObjectPool.
type PoolEntry struct {
	Index int
	Kind  PoolEntryKind
	RefID int   // valid when Kind == PoolTagged
	Imm   int64 // valid when Kind == PoolImmediate
}

// Result holds all parsed cluster data.
type Result struct {
	Header     Header
	Clusters   []ClusterMeta
	Strings    []ParsedString
	Named      []NamedObject  // named objects extracted from fill (Function, Class, Library, etc.)
	FuncTypes  []FuncTypeInfo // FunctionType parameter counts extracted from fill
	Classes    []ClassInfo    // class layout data extracted from fill
	Types      []TypeInfo     // Type objects' resolved type_class_id, extracted from fill (v3.x only)
	Fields     []FieldInfo    // field layout data extracted from fill
	Codes      []CodeEntry    // Code objects with owner refs, extracted from fill
	Arrays     []ArrayInfo    // Array/ImmutableArray elements, extracted from fill
	Pool       []PoolEntry    // ObjectPool entries extracted from fill
	MintValues map[int]int64  // Mint/Smi ref→int64 value from alloc phase
	FillStart  int            // byte offset where the fill section begins
	FillEnd    int            // byte offset right after the last cluster's fill data (set by ReadFill; 0 if not run). See ParseDispatchTable.
	Diags      []dartfmt.Diag

	// Captured object data (previously skipped):
	Instances         []InstanceInfo         // Instance field values
	Contexts          []ContextInfo          // Context captured variables (empty in AOT — runtime-allocated)
	TypeArguments     []TypeArgumentsInfo    // TypeArguments type refs
	ExceptionHandlers []ExceptionHandlerInfo // Exception handler tables
	ICData            []ICDataInfo           // ICData call-site→class→target mappings (empty in AOT — JIT-only)
	Scripts           []ScriptInfo           // Script URLs + line/col metadata
	LoadingUnits      []LoadingUnitInfo      // Loading unit / deferred library metadata
	KernelProgramInfo []KernelProgramInfoRef // KernelProgramInfo refs (empty in AOT — not serialized)

	// ClosureData: alternative to Context for closure resolution in AOT.
	// ClosureData objects ARE serialized in AOT (unlike Context objects).
	// Each ClosureData has parent_function and closure refs, enabling
	// closure → parent function mapping without runtime Context data.
	ClosureData []ClosureDataInfo

	// PcDescriptors holds decoded PcDescriptors streams, keyed by ref ID via
	// PcDescriptorsInfo.RefID and reached from CodeEntry.PcDescriptorsRef.
	// Their try_index values are the only source for try/catch region extents.
	PcDescriptors []PcDescriptorsInfo

	// CodeSourceMaps holds decoded CodeSourceMap streams, reached from
	// CodeEntry.CodeSourceMapRef. Gives PC -> inlined-function stack and raw
	// token position; see CodeSourceMapInfo for why that is not file:line.
	CodeSourceMaps []CodeSourceMapInfo

	// CompressedStackMaps holds raw CompressedStackMaps payloads (not decoded
	// yet — no consumer exists). Captured for completeness so future
	// decompilation quality improvements can access which registers are live
	// at safepoints without re-parsing the snapshot.
	CompressedStackMaps []CompressedStackMapsInfo

	// TypeParameters holds TypeParameters objects: a function's or class's own
	// generic parameter declarations. Consumed via FuncTypeInfo.TypeParamsRefID
	// to reconstruct `<T>` in decompiler signatures (gap §2.3).
	TypeParameters []TypeParametersInfo
}

// ScanClusters reads the clustered snapshot header and cluster tags from
// snapshot data. clusterStart is the offset within data where the clustered
// section begins (after the snapshot header's null-terminated features string).
// If profile is nil, the v3.x format is assumed. isVM indicates whether this
// is the VM snapshot (affects canonical set handling for strings).
func ScanClusters(data []byte, clusterStart int, profile *snapshot.VersionProfile, isVM bool, opts dartfmt.Options) (*Result, error) {
	if clusterStart >= len(data) {
		return nil, fmt.Errorf("cluster: start offset %d beyond data length %d", clusterStart, len(data))
	}
	if profile == nil {
		profile = snapshot.DetectVersion("")
	}

	s := dartfmt.NewStreamAt(data, clusterStart)
	maxSteps := opts.EffectiveMaxSteps()

	var diags dartfmt.Diags
	result := &Result{}

	// Read header values (count depends on version).
	// Header counts use WriteUnsigned in all versions (even 2.10/2.13).
	var err error
	result.Header.NumBaseObjects, err = s.ReadUnsigned()
	if err != nil {
		return nil, fmt.Errorf("cluster header: num_base_objects: %w", err)
	}
	result.Header.NumObjects, err = s.ReadUnsigned()
	if err != nil {
		return nil, fmt.Errorf("cluster header: num_objects: %w", err)
	}
	// Header field evolution:
	//   2.10      (HF=4): base, objects, clusters, field_table_len
	//   2.12-2.13 (HF=5, SplitCanonical): base, objects, canonical_clusters, clusters, field_table_len
	//   2.14-2.16 (HF=5): base, objects, clusters, field_table_len, instr_table_len
	//   2.17      (HF=6): base, objects, clusters, field_table_len, instr_table_len, instr_table_rodata
	//   2.18+     (HF=5): base, objects, clusters, instr_table_len, instr_table_rodata
	if profile.SplitCanonical {
		// v2.12-2.13: field 3 = num_canonical_clusters, field 4 = num_clusters
		result.Header.NumCanonicalClusters, err = s.ReadUnsigned()
		if err != nil {
			return nil, fmt.Errorf("cluster header: num_canonical_clusters: %w", err)
		}
		result.Header.NumClusters, err = s.ReadUnsigned()
		if err != nil {
			return nil, fmt.Errorf("cluster header: num_clusters: %w", err)
		}
	} else {
		result.Header.NumClusters, err = s.ReadUnsigned()
		if err != nil {
			return nil, fmt.Errorf("cluster header: num_clusters: %w", err)
		}
	}
	if profile.FillRefUnsigned {
		result.Header.InitialFieldTableLen, err = s.ReadUnsigned()
		if err != nil {
			return nil, fmt.Errorf("cluster header: initial_field_table_len: %w", err)
		}
	}
	if profile.HeaderFields >= 5 && !profile.SplitCanonical {
		result.Header.InstructionsTableLen, err = s.ReadUnsigned()
		if err != nil {
			return nil, fmt.Errorf("cluster header: instructions_table_len: %w", err)
		}
	}
	if (profile.HeaderFields >= 6 || !profile.FillRefUnsigned) && !profile.SplitCanonical && !profile.PreCanonicalSplit {
		result.Header.InstructionTableDataOffset, err = s.ReadUnsigned()
		if err != nil {
			return nil, fmt.Errorf("cluster header: instruction_table_data_offset: %w", err)
		}
	}

	// Total clusters = canonical + non-canonical for split format.
	nc := int(result.Header.NumCanonicalClusters + result.Header.NumClusters)
	if nc > maxSteps {
		return nil, fmt.Errorf("cluster: num_clusters %d exceeds max_steps %d", nc, maxSteps)
	}
	if debugAlloc {
		fmt.Fprintf(os.Stderr, "HEADER: base=%d objs=%d canonical=%d clusters=%d nc=%d field_table=%d instr_table=%d instr_offset=%d\n",
			result.Header.NumBaseObjects, result.Header.NumObjects,
			result.Header.NumCanonicalClusters, result.Header.NumClusters, nc,
			result.Header.InitialFieldTableLen, result.Header.InstructionsTableLen,
			result.Header.InstructionTableDataOffset)
	}

	// Read cluster tags from alloc section.
	result.Clusters = make([]ClusterMeta, 0, nc)
	ct := profile.CIDs
	nextRef := int(result.Header.NumBaseObjects) + 1
	for i := 0; i < nc; i++ {
		tagPos := s.Position()

		var cid int
		var canonical, immutable bool

		switch profile.Tags {
		case snapshot.TagStyleCidShift1:
			// v2.14+ / early v3.x: Read<uint64_t>((cid << 1) | canonical).
			cidAndCanonical, err := s.ReadTagged64()
			if err != nil {
				diags.Addf(uint64(tagPos), dartfmt.DiagTruncated,
					"cluster %d/%d: tags: %v", i, nc, err)
				break
			}
			cid, canonical = DecodeTagsOld(cidAndCanonical)
		case snapshot.TagStyleObjectHeader:
			// v3.4.3+: Read<uint32_t>(ClassIdTag | CanonicalBit | ImmutableBit).
			tags, err := s.ReadTagged32()
			if err != nil {
				diags.Addf(uint64(tagPos), dartfmt.DiagTruncated,
					"cluster %d/%d: tags: %v", i, nc, err)
				break
			}
			cid, canonical, immutable = DecodeTags(tags)
		case snapshot.TagStyleCidInt32:
			// v2.10-2.13: Read<int32_t>(cid). Signed VLE (endMarker=192), value = CID directly.
			// Canonical determined by cluster loop position (first NumCanonicalClusters are canonical).
			rawCid, err := s.ReadTagged64()
			if err != nil {
				diags.Addf(uint64(tagPos), dartfmt.DiagTruncated,
					"cluster %d/%d: tags: %v", i, nc, err)
				break
			}
			cid = int(rawCid)
			// In split-canonical format, clusters before NumCanonicalClusters are canonical.
			if profile.SplitCanonical {
				canonical = i < int(result.Header.NumCanonicalClusters)
			}
		}
		// Check if we broke out of the switch due to error.
		if s.Position() == tagPos {
			break
		}

		cm := ClusterMeta{
			Index:       i,
			CID:         cid,
			IsCanonical: canonical,
			IsImmutable: immutable,
			StartRef:    nextRef,
			StartOffset: tagPos,
		}

		// Skip alloc data for this cluster using version-aware CID dispatch.
		// Mint clusters are handled separately to capture ref→value mapping.
		var count int64
		var err error
		if ClassifyAlloc(cid, ct) == AllocMint {
			var mintVals []int64
			count, mintVals, err = readMintAlloc(s, profile.PreCanonicalSplit, maxSteps)
			if result.MintValues == nil {
				result.MintValues = make(map[int]int64)
			}
			for j, v := range mintVals {
				result.MintValues[nextRef+j] = v
			}
		} else {
			count, err = skipAllocV(s, &cm, canonical, ct, isVM, profile, &diags, maxSteps)
		}
		if err != nil {
			name := CidNameV(cid, ct)
			if name == "" {
				name = fmt.Sprintf("CID_%d", cid)
			}
			if debugAlloc {
				ak := ClassifyAlloc(cid, ct)
				fmt.Fprintf(os.Stderr, "ALLOC[%3d] CID=%-4d %-24s kind=%-2d count=%-6d pos=0x%06x ERR: %v\n",
					i, cid, name, ak, count, s.Position(), err)
			}
			diags.Addf(uint64(s.Position()), dartfmt.DiagTruncated,
				"cluster %d (CID %d %s): alloc skip: %v", i, cid, name, err)
			cm.EndOffset = s.Position()
			cm.StopRef = nextRef + int(count)
			result.Clusters = append(result.Clusters, cm)
			break
		}
		cm.Count = count
		cm.StopRef = nextRef + int(count)
		cm.EndOffset = s.Position()
		nextRef = cm.StopRef
		result.Clusters = append(result.Clusters, cm)

		if debugAlloc {
			name := CidNameV(cid, ct)
			if name == "" {
				name = fmt.Sprintf("CID_%d", cid)
			}
			ak := ClassifyAlloc(cid, ct)
			fmt.Fprintf(os.Stderr, "ALLOC[%3d] CID=%-4d %-24s kind=%-2d count=%-6d tag=0x%06x end=0x%06x refs=%d-%d\n",
				i, cid, name, ak, count, cm.StartOffset, cm.EndOffset, cm.StartRef, cm.StopRef)
		}
	}

	result.FillStart = s.Position()
	if debugAlloc {
		fmt.Fprintf(os.Stderr, "ALLOC: nc=%d, FillStart=0x%06x totalRefs=%d expectedObjs=%d deficit=%d\n",
			nc, result.FillStart, nextRef-1, result.Header.NumObjects, result.Header.NumObjects-int64(nextRef-1))
	}
	result.Diags = diags.Items()
	return result, nil
}

// FindClusterDataStart returns the byte offset where clustered data begins
// within a snapshot data region. This is after: magic(4) + length(8) + kind(8) +
// hash(32) + features(null-terminated).
func FindClusterDataStart(data []byte) (int, error) {
	const minHeader = 0x35 // magic + length + kind + hash
	if len(data) < minHeader {
		return 0, fmt.Errorf("cluster: data too short (%d < %d)", len(data), minHeader)
	}

	// Features string starts at offset 0x34, null-terminated.
	featStart := 0x34
	for i := featStart; i < len(data); i++ {
		if data[i] == 0 {
			return i + 1, nil // byte after null terminator
		}
		if i-featStart > 1024 {
			return 0, fmt.Errorf("cluster: features string too long (no null terminator within 1024 bytes)")
		}
	}
	return 0, fmt.Errorf("cluster: unterminated features string")
}

// skipAllocV dispatches alloc skipping using version-aware CID classification.
// isVM indicates the VM snapshot, where String canonical sets are absent.
// cm is used to store extra metadata (e.g. NextFieldOffsetInWords for Instance clusters).
func skipAllocV(s *dartfmt.Stream, cm *ClusterMeta, isCanonical bool, ct *snapshot.CIDTable, isVM bool, profile *snapshot.VersionProfile, diags *dartfmt.Diags, maxSteps int) (int64, error) {
	cid := cm.CID
	kind := ClassifyAlloc(cid, ct)
	// v2.12 and earlier (NoCanonicalSetData): canonical sets are rebuilt in memory
	// during PostLoad, never written to the stream. CanonicalSetDeserializationCluster
	// (BuildCanonicalSetFromLayout) was introduced in 2.13 — verified absent from
	// dart-lang/sdk runtime/vm/clustered_snapshot.cc at the 2.12.0 tag. Treat every
	// cluster as non-canonical for alloc-stream purposes on such profiles, even
	// though the tag's canonical bit/position is still meaningful for InitializeHeader.
	canonicalSetInStream := isCanonical && !profile.NoCanonicalSetData
	switch kind {
	case AllocSimple:
		return skipFixedAllocSimple(s, maxSteps)
	case AllocCanonicalSet:
		if profile.PreCanonicalSplit {
			// v2.10: Type and TypeParameter have internal canonical/non-canonical
			// split: two counts (canonical_count, non_canonical_count) with no
			// canonical set hash table data.
			return skipDualCountAlloc(s, maxSteps)
		}
		// In Dart 2.13 (SplitCanonical), BuildCanonicalSetFromLayout only writes
		// first_element for Type (kAllCanonicalObjectsAreIncludedIntoSet=false).
		// All other canonical set types have first_element hardcoded to 0 and NOT
		// in the stream. In 2.14+, first_element is always in the stream.
		readFirstElement := true
		if profile.SplitCanonical {
			readFirstElement = (cid == ct.Type)
		}
		return skipFixedWithCanonicalSet(s, canonicalSetInStream, readFirstElement, maxSteps)
	case AllocString:
		// In AOT without compressed-pointers, strings use ROData format:
		// count + per-item offset delta (not per-string length).
		// SplitCanonical (2.13) always uses ROData for strings.
		// For other versions, check CompressedPointers flag.
		if profile.SplitCanonical || !profile.CompressedPointers {
			// Only the abstract kStringCid has canonical set data in ROData.
			// OneByteString/TwoByteString via ROData have no canonical set,
			// even when the cluster is canonical (cid_ != kStringCid in C++).
			hasCanonicalSet := canonicalSetInStream && cid == ct.String
			// Pass cm to record offset deltas for later string extraction.
			return skipRODataAlloc(s, cm, hasCanonicalSet, !profile.SplitCanonical, maxSteps)
		}
		// VM snapshot strings never have canonical set data.
		return skipStringAlloc(s, isCanonical && !isVM, maxSteps)
	case AllocMint:
		// Handled in the alloc loop via readMintAlloc (captures ref→value mapping).
		// This path should not be reached.
		return 0, fmt.Errorf("AllocMint should be handled before skipAllocV")
	case AllocArray:
		return skipArrayAlloc(s, cm, maxSteps)
	case AllocWeakArray:
		return skipWeakArrayAlloc(s, cm, maxSteps)
	case AllocTypeArguments:
		// TypeArguments uses kAllCanonicalObjectsAreIncludedIntoSet=true.
		// In 2.13 (SplitCanonical), first_element is NOT in stream.
		// In 2.14+, first_element is always in stream.
		return skipTypeArgumentsAlloc(s, cm, canonicalSetInStream, !profile.SplitCanonical, maxSteps)
	case AllocClass:
		return skipClassAlloc(s, cm, ct, maxSteps)
	case AllocCode:
		// In Dart ≤2.13, Code alloc has no per-object state_bits (they are in fill).
		// In 2.14+, state_bits moved to alloc phase.
		stateBitsInAlloc := profile.Tags != snapshot.TagStyleCidInt32
		return skipCodeAlloc(s, cm, stateBitsInAlloc, maxSteps)
	case AllocObjectPool:
		return skipObjectPoolAlloc(s, cm, maxSteps)
	case AllocROData:
		// ROData for PcDescriptors/CodeSourceMap/CompressedStackMaps is never
		// canonical, so the readFirstElement value doesn't matter.
		//
		// cm is passed (it used to be nil, "no string extraction") purely to
		// RECORD the per-object offset deltas in cm.Lengths. Without them
		// extractRODataPcDescriptors has no way to locate objects in the data
		// image, which is why PcDescriptors decoded to nothing on
		// non-compressed-pointer builds. Recording deltas does not change how
		// much of the stream is consumed.
		return skipRODataAlloc(s, cm, canonicalSetInStream, !profile.SplitCanonical, maxSteps)
	case AllocExceptionHandlers:
		return skipExceptionHandlersAlloc(s, cm, maxSteps)
	case AllocContext:
		return skipContextAlloc(s, cm, maxSteps)
	case AllocContextScope:
		return skipContextScopeAlloc(s, cm, maxSteps)
	case AllocRecord:
		return skipRecordAlloc(s, cm, maxSteps)
	case AllocTypedData:
		return skipTypedDataAlloc(s, cm, maxSteps)
	case AllocInstance:
		return skipInstanceAllocV(s, cm, maxSteps)
	case AllocEmpty:
		// WeakSerializationReference in v2.13+: WriteAlloc writes only the CID tag,
		// ReadAlloc reads nothing. In v2.10 (PreCanonicalSplit), WSR has a count.
		if profile.PreCanonicalSplit {
			return skipFixedAllocSimple(s, maxSteps)
		}
		return 0, nil
	default:
		return 0, fmt.Errorf("unknown CID %d", cid)
	}
}

// skipDualCountAlloc handles v2.10 PreCanonicalSplit clusters (Type, TypeParameter)
// where canonical and non-canonical objects are counted separately within one cluster:
// canonical_count = ReadUnsigned(), non_canonical_count = ReadUnsigned().
// No canonical set hash table data.
func skipDualCountAlloc(s *dartfmt.Stream, maxSteps int) (int64, error) {
	canonical, err := s.ReadUnsigned()
	if err != nil {
		return 0, fmt.Errorf("canonical count: %w", err)
	}
	if canonical < 0 || int(canonical) > maxSteps {
		return 0, fmt.Errorf("canonical count %d out of range", canonical)
	}
	nonCanonical, err := s.ReadUnsigned()
	if err != nil {
		return canonical, fmt.Errorf("non-canonical count: %w", err)
	}
	if nonCanonical < 0 || int(nonCanonical) > maxSteps {
		return canonical, fmt.Errorf("non-canonical count %d out of range", nonCanonical)
	}
	return canonical + nonCanonical, nil
}

// skipFixedAllocSimple skips a cluster whose alloc is just: count = ReadUnsigned().
func skipFixedAllocSimple(s *dartfmt.Stream, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("count %d out of range", count)
	}
	return count, nil
}

// skipFixedWithCanonicalSet skips a fixed-size cluster that may have canonical set data.
// Used for Type, FunctionType, RecordType, TypeParameter, ConstMap, ConstSet.
// readFirstElement controls whether BuildCanonicalSetFromLayout reads first_element
// from the stream (true for ≥2.17, true only for Type in ≤2.16).
func skipFixedWithCanonicalSet(s *dartfmt.Stream, isCanonical bool, readFirstElement bool, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("count %d out of range", count)
	}
	if isCanonical {
		if err := skipCanonicalSet(s, int(count), readFirstElement, maxSteps); err != nil {
			return count, fmt.Errorf("canonical set: %w", err)
		}
	}
	return count, nil
}

// skipCanonicalSet reads the BuildCanonicalSetFromLayout data:
//
//	table_length: ReadUnsigned()
//	first_element: ReadUnsigned()   (only if readFirstElement is true)
//	for i in 0..(count - first_element): gap = ReadUnsigned()
//
// readFirstElement controls whether first_element is present in the stream.
// In Dart ≤2.16, only Type sets kAllCanonicalObjectsAreIncludedIntoSet=false,
// meaning first_element is written/read. All other types (TypeParameter,
// FunctionType, TypeArguments, etc.) use the default true, so first_element
// is hardcoded to 0 and NOT in the stream. In Dart ≥2.17, the format was
// simplified: first_element is always in the stream for all types.
func skipCanonicalSet(s *dartfmt.Stream, count int, readFirstElement bool, maxSteps int) error {
	// Table length (hash table backing array size).
	tableLen, err := s.ReadUnsigned()
	if err != nil {
		return fmt.Errorf("table_length: %w", err)
	}
	if tableLen < 0 || int(tableLen) > maxSteps*16 {
		return fmt.Errorf("table_length %d out of range", tableLen)
	}
	// first_element: number of objects that precede the first gap.
	// Only present in stream when readFirstElement is true.
	var firstElement int64
	if readFirstElement {
		firstElement, err = s.ReadUnsigned()
		if err != nil {
			return fmt.Errorf("first_element: %w", err)
		}
		if firstElement < 0 || int(firstElement) > count {
			return fmt.Errorf("first_element %d out of range (count=%d)", firstElement, count)
		}
	}
	// Number of gap values = count - first_element.
	numGaps := count - int(firstElement)
	for i := 0; i < numGaps; i++ {
		if _, err := s.ReadUnsigned(); err != nil {
			return fmt.Errorf("gap %d/%d: %w", i, numGaps, err)
		}
	}
	return nil
}

// skipStringAlloc skips String cluster alloc:
//
//	count + per-string encoded length + canonical set (if canonical).
func skipStringAlloc(s *dartfmt.Stream, isCanonical bool, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("string count %d out of range", count)
	}
	for i := int64(0); i < count; i++ {
		// Each string alloc reads: encoded = ReadUnsigned() (length<<1 | cid_flag)
		if _, err := s.ReadUnsigned(); err != nil {
			return count, fmt.Errorf("string %d/%d alloc: %w", i, count, err)
		}
	}
	if isCanonical {
		// String canonical sets in ≥2.17 always write first_element (kAllCanonical=true
		// but format always includes it). This path is only used for non-SplitCanonical (≥2.17).
		if err := skipCanonicalSet(s, int(count), true, maxSteps); err != nil {
			return count, fmt.Errorf("string canonical set: %w", err)
		}
	}
	return count, nil
}

// readMintAlloc reads Mint cluster alloc, capturing ref→value pairs.
//
// All versions: count + per-mint Read<int64_t>() value.
// v2.10 PreCanonicalSplit: per-mint also has Read<bool>(is_canonical) before value.
func readMintAlloc(s *dartfmt.Stream, preCanonicalSplit bool, maxSteps int) (int64, []int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, nil, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, nil, fmt.Errorf("mint count %d out of range", count)
	}
	// Each mint reads its value during alloc (to determine Smi vs heap Mint).
	values := make([]int64, count)
	for i := int64(0); i < count; i++ {
		if preCanonicalSplit {
			// v2.10: Read<bool>(is_canonical) = 1 raw byte.
			if _, err := s.ReadByte(); err != nil {
				return count, values, fmt.Errorf("mint %d/%d canonical: %w", i, count, err)
			}
		}
		v, err := s.ReadTagged64()
		if err != nil {
			return count, values, fmt.Errorf("mint %d/%d value: %w", i, count, err)
		}
		values[i] = v
	}
	return count, values, nil
}

// skipArrayAlloc skips Array/ImmutableArray alloc: count + per-element length.
func skipArrayAlloc(s *dartfmt.Stream, cm *ClusterMeta, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("array count %d out of range", count)
	}
	cm.Lengths = make([]int64, count)
	for i := int64(0); i < count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return count, fmt.Errorf("array %d/%d alloc: %w", i, count, err)
		}
		cm.Lengths[i] = length
	}
	return count, nil
}

// skipTypeArgumentsAlloc skips TypeArguments alloc:
//
//	count + per-item length + canonical set (if canonical).
//
// readFirstElement: whether canonical set has first_element in stream (≥2.17: true, ≤2.16: false).
func skipTypeArgumentsAlloc(s *dartfmt.Stream, cm *ClusterMeta, isCanonical bool, readFirstElement bool, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("type_arguments count %d out of range", count)
	}
	cm.Lengths = make([]int64, count)
	for i := int64(0); i < count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return count, fmt.Errorf("type_arguments %d/%d alloc: %w", i, count, err)
		}
		cm.Lengths[i] = length
	}
	if isCanonical {
		if err := skipCanonicalSet(s, int(count), readFirstElement, maxSteps); err != nil {
			return count, fmt.Errorf("type_arguments canonical set: %w", err)
		}
	}
	return count, nil
}

// skipClassAlloc skips Class alloc:
//
//	predefined_count + per-class ReadCid(), then new_count.
//
// Some Dart SDK builds (observed in Dart 3.5.1 / Flutter forks) write an extra
// WriteUnsigned(total_class_count) before the standard predefined_count field.
// We detect this by checking whether the first value exceeds NumPredefinedCids;
// if so, we consume it and read the next value as the actual predefined_count.
//
// Stores predefined count in cm.MainCount for fill-phase use.
func skipClassAlloc(s *dartfmt.Stream, cm *ClusterMeta, ct *snapshot.CIDTable, maxSteps int) (int64, error) {
	predefined, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	// Heuristic: predefined_count must be ≤ NumPredefinedCids (174 for v3.4.3+).
	// If the value is larger, it's an extra "total class count" prefix; skip it
	// and read the real predefined_count.
	if ct != nil && int(predefined) > ct.NumPredefinedCids {
		predefined, err = s.ReadUnsigned()
		if err != nil {
			return 0, err
		}
	}
	if predefined < 0 || int(predefined) > maxSteps {
		return 0, fmt.Errorf("predefined class count %d out of range", predefined)
	}
	cm.PredefCIDs = make([]int64, predefined)
	for i := int64(0); i < predefined; i++ {
		// ReadCid() = Read<int32_t>() with kEndByteMarker=192.
		cid, err := s.ReadTagged32()
		if err != nil {
			return 0, fmt.Errorf("predefined class %d/%d cid: %w", i, predefined, err)
		}
		cm.PredefCIDs[i] = int64(cid)
	}
	newCount, err := s.ReadUnsigned()
	if err != nil {
		return predefined, err
	}
	if newCount < 0 || int(newCount) > maxSteps {
		return predefined, fmt.Errorf("new class count %d out of range", newCount)
	}
	cm.MainCount = predefined
	return predefined + newCount, nil
}

// skipCodeAlloc skips Code cluster alloc.
//
// Format depends on Dart version:
//   - 2.14+: count + per-code state_bits(int32_t), deferred_count + per-deferred state_bits(int32_t)
//   - ≤2.13: count, deferred_count (no per-object data; state_bits read during fill)
func skipCodeAlloc(s *dartfmt.Stream, cm *ClusterMeta, stateBitsInAlloc bool, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("code count %d out of range", count)
	}
	if stateBitsInAlloc {
		for i := int64(0); i < count; i++ {
			sb, err := s.ReadTagged32()
			if err != nil {
				return count, fmt.Errorf("code %d/%d state_bits: %w", i, count, err)
			}
			// DiscardedBit is bit 3 of state_bits (Dart 2.14+).
			if (sb>>3)&1 != 0 {
				if cm.DiscardedCodes == nil {
					cm.DiscardedCodes = make(map[int64]bool)
				}
				cm.DiscardedCodes[i] = true
			}
		}
	}
	cm.MainCount = count
	// Deferred code section.
	deferred, err := s.ReadUnsigned()
	if err != nil {
		return count, fmt.Errorf("deferred code count: %w", err)
	}
	if deferred < 0 || int(deferred) > maxSteps {
		return count, fmt.Errorf("deferred code count %d out of range", deferred)
	}
	if stateBitsInAlloc {
		for i := int64(0); i < deferred; i++ {
			sb, err := s.ReadTagged32()
			if err != nil {
				return count + deferred, fmt.Errorf("deferred code %d/%d state_bits: %w", i, deferred, err)
			}
			// Deferred codes should not be discarded (Dart asserts this).
			if (sb>>3)&1 != 0 {
				if cm.DiscardedCodes == nil {
					cm.DiscardedCodes = make(map[int64]bool)
				}
				cm.DiscardedCodes[count+i] = true
			}
		}
	}
	return count + deferred, nil
}

// skipObjectPoolAlloc skips ObjectPool cluster alloc: count + per-pool length.
func skipObjectPoolAlloc(s *dartfmt.Stream, cm *ClusterMeta, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("object_pool count %d out of range", count)
	}
	cm.Lengths = make([]int64, count)
	for i := int64(0); i < count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return count, fmt.Errorf("object_pool %d/%d alloc: %w", i, count, err)
		}
		cm.Lengths[i] = length
	}
	return count, nil
}

// skipRODataAlloc skips ROData cluster alloc (used in AOT for PcDescriptors,
// CodeSourceMap, CompressedStackMaps, and sometimes String).
//
//	count + per-item ReadUnsigned() (running offset delta).
//	If CID is String and canonical, also reads canonical set data.
//
// readFirstElement: whether canonical set has first_element in stream.
// If cm is non-nil, records the offset deltas in cm.Lengths for later extraction.
func skipRODataAlloc(s *dartfmt.Stream, cm *ClusterMeta, isCanonical bool, readFirstElement bool, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("rodata count %d out of range", count)
	}
	if cm != nil {
		cm.Lengths = make([]int64, count)
	}
	for i := int64(0); i < count; i++ {
		delta, err := s.ReadUnsigned()
		if err != nil {
			return count, fmt.Errorf("rodata %d/%d offset: %w", i, count, err)
		}
		if cm != nil {
			cm.Lengths[i] = delta
		}
	}
	// ROData canonical set is only for String CID, but we pass isCanonical
	// for safety — the caller knows the CID.
	if isCanonical {
		if err := skipCanonicalSet(s, int(count), readFirstElement, maxSteps); err != nil {
			return count, fmt.Errorf("rodata canonical set: %w", err)
		}
	}
	return count, nil
}

// skipExceptionHandlersAlloc skips ExceptionHandlers alloc: count + per-handler length.
func skipExceptionHandlersAlloc(s *dartfmt.Stream, cm *ClusterMeta, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("exception_handlers count %d out of range", count)
	}
	cm.Lengths = make([]int64, count)
	for i := int64(0); i < count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return count, fmt.Errorf("exception_handlers %d/%d alloc: %w", i, count, err)
		}
		cm.Lengths[i] = length
	}
	return count, nil
}

// skipContextAlloc skips Context cluster alloc: count + per-context num_variables.
func skipContextAlloc(s *dartfmt.Stream, cm *ClusterMeta, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("context count %d out of range", count)
	}
	cm.Lengths = make([]int64, count)
	for i := int64(0); i < count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return count, fmt.Errorf("context %d/%d alloc: %w", i, count, err)
		}
		cm.Lengths[i] = length
	}
	return count, nil
}

// skipContextScopeAlloc skips ContextScope cluster alloc: count + per-scope length.
func skipContextScopeAlloc(s *dartfmt.Stream, cm *ClusterMeta, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("context_scope count %d out of range", count)
	}
	cm.Lengths = make([]int64, count)
	for i := int64(0); i < count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return count, fmt.Errorf("context_scope %d/%d alloc: %w", i, count, err)
		}
		cm.Lengths[i] = length
	}
	return count, nil
}

// skipWeakArrayAlloc skips WeakArray cluster alloc: count + per-array length.
func skipWeakArrayAlloc(s *dartfmt.Stream, cm *ClusterMeta, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("weak_array count %d out of range", count)
	}
	cm.Lengths = make([]int64, count)
	for i := int64(0); i < count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return count, fmt.Errorf("weak_array %d/%d alloc: %w", i, count, err)
		}
		cm.Lengths[i] = length
	}
	return count, nil
}

// skipRecordAlloc skips Record cluster alloc: count + per-record num_fields.
func skipRecordAlloc(s *dartfmt.Stream, cm *ClusterMeta, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("record count %d out of range", count)
	}
	cm.Lengths = make([]int64, count)
	for i := int64(0); i < count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return count, fmt.Errorf("record %d/%d alloc: %w", i, count, err)
		}
		cm.Lengths[i] = length
	}
	return count, nil
}

// skipTypedDataAlloc skips TypedData cluster alloc: count + per-item length.
func skipTypedDataAlloc(s *dartfmt.Stream, cm *ClusterMeta, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("typed_data count %d out of range", count)
	}
	cm.Lengths = make([]int64, count)
	for i := int64(0); i < count; i++ {
		length, err := s.ReadUnsigned()
		if err != nil {
			return count, fmt.Errorf("typed_data %d/%d alloc: %w", i, count, err)
		}
		cm.Lengths[i] = length
	}
	return count, nil
}

// skipInstanceAllocV skips a generic Instance alloc and stores layout in cm:
//
//	count = ReadUnsigned()
//	next_field_offset = Read<int32_t>()
//	instance_size = Read<int32_t>()
func skipInstanceAllocV(s *dartfmt.Stream, cm *ClusterMeta, maxSteps int) (int64, error) {
	count, err := s.ReadUnsigned()
	if err != nil {
		return 0, err
	}
	if count < 0 || int(count) > maxSteps {
		return 0, fmt.Errorf("instance(%d) count %d out of range", cm.CID, count)
	}
	// Instance alloc reads two layout values using Read<int32_t>() (marker 192).
	nfo, err := s.ReadTagged32()
	if err != nil {
		return count, fmt.Errorf("instance(%d) next_field_offset: %w", cm.CID, err)
	}
	cm.NextFieldOffsetInWords = int32(nfo)
	if _, err := s.ReadTagged32(); err != nil {
		return count, fmt.Errorf("instance(%d) instance_size: %w", cm.CID, err)
	}
	return count, nil
}
