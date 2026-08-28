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
	CodeSourceMapRef     int   // ref ID of CodeSourceMap object (ref index 5 in 3.x AOT, ref index 6 in 2.x AOT); -1 if not captured
	InlinedFuncsRef      int   // ref ID of inlined_id_to_function Array (ref index 4 in 3.x AOT, ref index 5 in 2.x AOT); -1 if not captured
	// CompressedStackMapsRef is the ref ID of the CompressedStackMaps object.
	// In 2.x AOT (CodeNumRefs=7), compressed_stackmaps_ is a ref at index 4.
	// In 3.x AOT (CodeNumRefs=6), compressed_stackmaps_ is null (not a ref).
	// -1 if not captured or not present in this version's AOT format.
	CompressedStackMapsRef int // ref ID of CompressedStackMaps object (ref index 4 in 2.x AOT); -1 if not captured
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

	// unboxedByClassID memoizes classUnboxedBitmaps' index.
	unboxedByClassID map[int32]uint64

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
