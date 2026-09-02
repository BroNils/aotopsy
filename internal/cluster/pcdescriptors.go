package cluster

import (
	"encoding/binary"
	"fmt"
	"sort"

	"aotopsy/internal/snapshot"
)

// PcDescriptors decoding.
//
// A Code object's PcDescriptors is the only place that records WHICH try block
// is active at a given PC. ExceptionHandlers records handler entry points and
// their flags, but not the protected range, so try/catch region recovery is
// impossible without this.
//
// Everything below is transcribed from the Dart SDK @ 3.9.2:
//   - PcDescriptors::Iterator::MoveNext, runtime/vm/object.h
//   - UntaggedPcDescriptors::KindAndMetadata, runtime/vm/raw_object.h

// PcDescriptorKind mirrors UntaggedPcDescriptors::Kind. The values are a
// bitmask (each kind is a distinct bit), which is why the encoded form stores
// log2(kind) rather than the kind itself.
type PcDescriptorKind int

const (
	PcDeopt           PcDescriptorKind = 1
	PcIcCall          PcDescriptorKind = 2
	PcUnoptStaticCall PcDescriptorKind = 4
	PcRuntimeCall     PcDescriptorKind = 8
	PcOsrEntry        PcDescriptorKind = 16
	PcRewind          PcDescriptorKind = 32
	PcBSSRelocation   PcDescriptorKind = 64
	PcOther           PcDescriptorKind = 128
)

func (k PcDescriptorKind) String() string {
	switch k {
	case PcDeopt:
		return "Deopt"
	case PcIcCall:
		return "IcCall"
	case PcUnoptStaticCall:
		return "UnoptStaticCall"
	case PcRuntimeCall:
		return "RuntimeCall"
	case PcOsrEntry:
		return "OsrEntry"
	case PcRewind:
		return "Rewind"
	case PcBSSRelocation:
		return "BSSRelocation"
	case PcOther:
		return "Other"
	}
	return fmt.Sprintf("Kind(%d)", int(k))
}

// InvalidTryIndex is UntaggedPcDescriptors' "not inside a try block" sentinel.
// It is stored biased by +1, so 0 on the wire decodes to -1 here.
const InvalidTryIndex = -1

// InvalidYieldIndex mirrors UntaggedPcDescriptors::kInvalidYieldIndex.
const InvalidYieldIndex = -1

// PcDescriptorEntry is one decoded descriptor.
type PcDescriptorEntry struct {
	PCOffset   uint32 // offset from the Code's payload start (absolute after delta accumulation)
	Kind       PcDescriptorKind
	TryIndex   int // index into ExceptionHandlerInfo.Handlers, or InvalidTryIndex
	YieldIndex int
}

// PcDescriptorsInfo is one PcDescriptors object's decoded contents.
type PcDescriptorsInfo struct {
	RefID   int
	Entries []PcDescriptorEntry
}

// readSLEB128 decodes one signed LEB128 value starting at buf[pos].
//
// Dart writes these with ReadStream::ReadSLEB128 (runtime/vm/datastream.h):
// 7 payload bits per byte, low byte first, high bit set means "more bytes
// follow", and the final byte's bit 6 is the sign bit which must be extended.
func readSLEB128(buf []byte, pos int) (val int64, next int, err error) {
	const (
		moreBit = 0x80
		signBit = 0x40
		maskLow = 0x7f
	)
	var shift uint
	var b byte
	for {
		if pos >= len(buf) {
			return 0, pos, fmt.Errorf("sleb128: truncated at %d", pos)
		}
		b = buf[pos]
		pos++
		if shift < 64 {
			val |= int64(b&maskLow) << shift
		}
		shift += 7
		if b&moreBit == 0 {
			break
		}
		if shift > 70 {
			return 0, pos, fmt.Errorf("sleb128: value too long at %d", pos)
		}
	}
	// Sign-extend from the last byte's sign bit.
	if shift < 64 && b&signBit != 0 {
		val |= -1 << shift
	}
	return val, pos, nil
}

// decodeKindAndMetadata splits the packed first field of a descriptor.
//
// Bit layout from UntaggedPcDescriptors::KindAndMetadata. kLastKind == kOther
// == 128, ShiftForPowerOfTwo(128) == 7 and BitLength(7) == 3, so KindShiftBits
// is 3 bits wide; TryIndexBits is the next 10 bits; YieldIndexBits takes the
// rest. try_index and yield_index are both stored biased by +1 so that their
// -1 sentinels encode as 0 and stay in one byte for the common case.
func decodeKindAndMetadata(kam int64) (kind PcDescriptorKind, tryIndex, yieldIndex int) {
	u := uint32(kam)
	kind = PcDescriptorKind(1 << (u & 0x7))
	tryIndex = int((u>>3)&0x3FF) - 1
	yieldIndex = int(u>>13) - 1
	return kind, tryIndex, yieldIndex
}

// DecodePcDescriptors decodes a PcDescriptors payload stream.
//
// payload is the variable-length data only (already past the object header and
// the length_ word). In AOT each record is exactly two SLEB128 values:
//
//	kind_and_metadata = SLEB128
//	pc_offset        += SLEB128   // delta-encoded
//
// deopt_id and token_pos are additionally present only when
// !FLAG_precompiled_mode, i.e. in JIT snapshots; this decoder is AOT-only and
// says so rather than guessing, because reading two extra values that are not
// there would desync the whole stream.
func DecodePcDescriptors(payload []byte) ([]PcDescriptorEntry, error) {
	var entries []PcDescriptorEntry
	pos := 0
	var pc int64
	for pos < len(payload) {
		kam, next, err := readSLEB128(payload, pos)
		if err != nil {
			return entries, fmt.Errorf("pc_descriptors: kind_and_metadata: %w", err)
		}
		pos = next
		delta, next, err := readSLEB128(payload, pos)
		if err != nil {
			return entries, fmt.Errorf("pc_descriptors: pc_offset delta: %w", err)
		}
		pos = next
		pc += delta
		if pc < 0 {
			return entries, fmt.Errorf("pc_descriptors: negative pc_offset %d", pc)
		}
		kind, tryIdx, yieldIdx := decodeKindAndMetadata(kam)
		entries = append(entries, PcDescriptorEntry{
			PCOffset:   uint32(pc),
			Kind:       kind,
			TryIndex:   tryIdx,
			YieldIndex: yieldIdx,
		})
	}
	return entries, nil
}

// extractRODataPcDescriptors decodes every PcDescriptors object in one ROData
// cluster.
//
// This path serves non-compressed-pointer builds (Dart < 2.18); 2.18+ routes
// PcDescriptors through FillInlineBytes instead. Verified on dart212_sample
// (Dart 2.12.0): 116 objects, 959 descriptors, 927 carrying a try index.
//
// Two things had to be true for it to work, and neither was at first:
//   - skipRODataAlloc must receive a non-nil cm so the per-object offset
//     deltas land in cm.Lengths. The AllocROData branch used to pass nil.
//   - The per-cluster reset of runningOffset is CORRECT: the FIRST delta of a
//     cluster is absolute from the data-image start (measured on dart212:
//     TwoByteString starts at 23159, PcDescriptors at 23191), so clusters do
//     not need a shared running offset.
//
// Addressing mirrors extractRODataStrings exactly (same cluster, same image),
// so the delta/alignment reasoning is not repeated here -- see that function.
//
// Object layout in the data image:
//
//	[objPos+0  .. +8)   tags   (or tags:4 + hash:4 under compressed pointers)
//	[objPos+8  .. +16)  length_
//	[objPos+16 .. )     length_ bytes of delta-encoded descriptor stream
//
// length_ is a raw uword, NOT a Smi, and it is a BYTE count. Both are load
// bearing and both are easy to get wrong:
//   - raw: UntaggedPcDescriptors declares `uword length_`, unlike
//     UntaggedString's Smi length_ which extractRODataStrings has to shift.
//   - bytes: the field's own comment says "Number of descriptors", but that is
//     stale. PcDescriptors::UnroundedSize(len) == HeaderSize() + len and
//     PcDescriptors::New(data, size) takes the encoded size, and the identical
//     field on UntaggedCodeSourceMap is documented "Length in bytes".
func extractRODataPcDescriptors(data []byte, cm *ClusterMeta, dataImageObjStart int64, profile *snapshot.VersionProfile, isVM bool) []PcDescriptorsInfo {
	if profile.CIDs == nil {
		return nil
	}
	var out []PcDescriptorsInfo
	for _, p := range extractRODataPayloads(data, cm, profile.CIDs.PcDescriptors, dataImageObjStart, profile) {
		entries, err := DecodePcDescriptors(p.Payload)
		if len(entries) > 0 || err == nil {
			out = append(out, PcDescriptorsInfo{RefID: p.RefID, Entries: entries})
		}
	}
	return out
}

// extractRODataCodeSourceMaps is the CodeSourceMap sibling of
// extractRODataPcDescriptors.
//
// It exists because CodeSourceMap follows the same compression-dependent split:
// FillInlineBytes on compressed-pointer builds (2.18+), ROData otherwise. An
// earlier revision wired CSM capture into the inline-bytes path ONLY, so Dart
// < 2.18 decoded PcDescriptors but zero CodeSourceMaps -- an asymmetry with no
// justification, since the ROData mechanism was already working next to it.
func extractRODataCodeSourceMaps(data []byte, cm *ClusterMeta, dataImageObjStart int64, profile *snapshot.VersionProfile, isVM bool) []CodeSourceMapInfo {
	if profile.CIDs == nil {
		return nil
	}
	var out []CodeSourceMapInfo
	for _, p := range extractRODataPayloads(data, cm, profile.CIDs.CodeSourceMap, dataImageObjStart, profile) {
		entries, err := DecodeCodeSourceMap(p.Payload)
		if len(entries) > 0 || err == nil {
			out = append(out, CodeSourceMapInfo{RefID: p.RefID, Entries: entries})
		}
	}
	return out
}

// rodataPayload is one variable-length ROData object's bytes plus its ref ID.
type rodataPayload struct {
	RefID   int
	Payload []byte
}

// extractRODataPayloads locates every object of wantCID in one ROData cluster
// and returns its variable-length data.
//
// Shared by PcDescriptors and CodeSourceMap because their in-image layout is
// identical: both are UntaggedObject + a uword length_ + that many bytes.
func extractRODataPayloads(data []byte, cm *ClusterMeta, wantCID int, dataImageObjStart int64, profile *snapshot.VersionProfile) []rodataPayload {
	if len(cm.Lengths) == 0 || dataImageObjStart <= 0 || wantCID == 0 {
		return nil
	}

	// ROData running_offset delta is encoded in units of kObjectAlignment
	// (RODataDeserializationCluster::ReadAlloc: running_offset += ReadUnsigned()
	// << kObjectAlignmentLog2). kObjectAlignmentLog2 = 4 (kObjectAlignment = 16).
	// This is the SAME delta stride used by extractRODataStrings in fill.go;
	// the two functions must agree (they share the same ROData image layout).
	// Previously this used dataImageAlignment(profile) (16 or 64), which is the
	// IMAGE BASE alignment, not the delta stride — a conflation that only
	// happened to work when dataImageAlignment == 16 (i.e. Dart <= 2.18).
	alignShift := uint(4)

	// No per-snapshot header adjustment: with the correct image-base alignment
	// (kObjectStartAlignment, applied in dataImageObjStart) and the correct delta
	// stride (kObjectAlignment=16, alignShift=4 above), the cumulative
	// running_offset lands exactly on each object header for BOTH the VM and the
	// isolate data images. Verified against real cid=94 OneByteString headers in
	// both (same fix as extractRODataStrings in fill.go).
	// Both images -- VM and isolate -- land on their object headers with no
	// per-snapshot fudge, which is why there is no isVM parameter here any
	// more. It survived the alignment fix as `_ = isVM` "for API
	// compatibility"; nothing outside this file calls the function, so the
	// only thing that compatibility preserved was the illusion that the
	// distinction still mattered.
	headerAdjust := int64(0)

	runningOffset := int64(0)
	ref := cm.StartRef
	var out []rodataPayload

	for i := 0; i < len(cm.Lengths); i++ {
		runningOffset += cm.Lengths[i] << alignShift
		objPos := dataImageObjStart + runningOffset + headerAdjust

		if objPos < 0 || objPos+16 > int64(len(data)) {
			ref++
			continue
		}

		// Confirm the object really is what we want before trusting the length
		// word: an ROData cluster can hold other object kinds.
		tags := binary.LittleEndian.Uint64(data[objPos : objPos+8])
		var cid int
		if profile.PreV32Format {
			cid = int((uint32(tags) >> 16) & 0xFFFF)
		} else {
			cid = int((uint32(tags) >> 12) & ((1 << 20) - 1))
		}
		if cid != wantCID {
			ref++
			continue
		}

		length := int64(binary.LittleEndian.Uint64(data[objPos+8 : objPos+16]))
		// These streams are at least a couple of bytes and realistically far
		// under 1 MiB; anything else means we are not looking at what we think.
		if length <= 0 || length > 1<<20 || objPos+16+length > int64(len(data)) {
			ref++
			continue
		}

		out = append(out, rodataPayload{RefID: ref, Payload: data[objPos+16 : objPos+16+length]})
		ref++
	}
	return out
}

// ExpandOuterTryRegions adds the enclosing try blocks implied by nesting.
//
// PcDescriptors only records the INNERMOST active try_index at each pc, and
// descriptors exist only at call sites. So when a nested try's body contains
// every descriptor, the outer try leaves no trace of its own and
// BuildTryRegions reports one region where the source has two. Measured:
// compare_sample's nestedTryCatch yields 2 handlers but 1 region on 3.9.2,
// while the identical source on dart212 yields 2 regions because that build has
// one more descriptor.
//
// The recovery is definitional, not a guess: if a pc is inside try N and
// handler[N].outer_try_index is M, then that pc is inside try M as well. So
// every region for N implies a region for M over at least the same range. This
// walks the outer chain and unions the ranges.
//
// It cannot recover an outer try that extends BEYOND its inner one -- that part
// is still bounded by descriptor density -- so outer ranges remain lower bounds.
func ExpandOuterTryRegions(regions []TryRegion, handlers []ExceptionHandlerEntry) []TryRegion {
	if len(regions) == 0 || len(handlers) == 0 {
		return regions
	}
	// Every original region is preserved verbatim; expansion only ADDS. An
	// earlier version unioned ranges per try index instead, which silently
	// merged the several disjoint regions BuildTryRegions can legitimately
	// produce for one try index (a try re-entered at separate pc ranges) --
	// measured as 5 regions collapsing to 3 on compare_sample.
	out := make([]TryRegion, 0, len(regions))
	seen := make(map[TryRegion]bool, len(regions))
	addRegion := func(r TryRegion) {
		if r.EndPC <= r.StartPC || seen[r] {
			return
		}
		seen[r] = true
		out = append(out, r)
	}
	for _, r := range regions {
		addRegion(r)
	}

	for _, r := range regions {
		idx := r.TryIndex
		// Walk outward. The visited set guards against a malformed chain
		// pointing back at itself, which would otherwise loop forever.
		visited := map[int]bool{idx: true}
		for {
			if idx < 0 || idx >= len(handlers) {
				break
			}
			outer := int(handlers[idx].OuterTryIndex)
			if outer < 0 || outer >= len(handlers) || visited[outer] {
				break
			}
			visited[outer] = true
			addRegion(TryRegion{StartPC: r.StartPC, EndPC: r.EndPC, TryIndex: outer})
			idx = outer
		}
	}
	// Innermost (smallest) first, then by address, for deterministic output.
	sort.Slice(out, func(i, j int) bool {
		si := out[i].EndPC - out[i].StartPC
		sj := out[j].EndPC - out[j].StartPC
		if si != sj {
			return si < sj
		}
		if out[i].StartPC != out[j].StartPC {
			return out[i].StartPC < out[j].StartPC
		}
		return out[i].TryIndex < out[j].TryIndex
	})
	return out
}

// TryRegion is a contiguous PC range covered by one try block.
type TryRegion struct {
	// StartPC is inclusive, EndPC exclusive; both are offsets from the Code's
	// payload start, in the same space as CodeRange PC offsets.
	StartPC uint32
	EndPC   uint32
	// TryIndex indexes ExceptionHandlerInfo.Handlers.
	TryIndex int
}

// BuildTryRegions turns descriptors into merged try regions.
//
// Descriptors are point annotations, not ranges: the try_index recorded at one
// descriptor holds until the next descriptor changes it. So a region runs from
// the first descriptor carrying a given try_index up to the next descriptor
// with a different one. Adjacent descriptors sharing a try_index merge.
//
// endPC bounds the last region (the function's size), since the final
// descriptor has no successor to delimit it.
//
// Descriptors with try_index == InvalidTryIndex produce no region: those PCs
// are outside any try block.
func BuildTryRegions(entries []PcDescriptorEntry, endPC uint32) []TryRegion {
	if len(entries) == 0 {
		return nil
	}
	sorted := make([]PcDescriptorEntry, len(entries))
	copy(sorted, entries)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].PCOffset < sorted[j].PCOffset })

	var regions []TryRegion
	for i := 0; i < len(sorted); i++ {
		if sorted[i].TryIndex == InvalidTryIndex {
			continue
		}
		start := sorted[i].PCOffset
		// Extend while the try index stays the same.
		j := i
		for j+1 < len(sorted) && sorted[j+1].TryIndex == sorted[i].TryIndex {
			j++
		}
		end := endPC
		if j+1 < len(sorted) {
			end = sorted[j+1].PCOffset
		}
		if end > start {
			regions = append(regions, TryRegion{StartPC: start, EndPC: end, TryIndex: sorted[i].TryIndex})
		}
		i = j
	}

	// Merge regions that are adjacent and share a try index. The scan above
	// can emit two touching regions when an unrelated descriptor with the same
	// try index appears after a gap of InvalidTryIndex entries.
	merged := regions[:0:len(regions)]
	for _, r := range regions {
		if n := len(merged); n > 0 && merged[n-1].TryIndex == r.TryIndex && merged[n-1].EndPC >= r.StartPC {
			if r.EndPC > merged[n-1].EndPC {
				merged[n-1].EndPC = r.EndPC
			}
			continue
		}
		merged = append(merged, r)
	}
	return merged
}
