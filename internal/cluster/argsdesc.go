package cluster

import "aotopsy/internal/snapshot"

// ArgumentsDescriptor references that need no heap object.
//
// The VM pre-allocates a small set of fixed-shape descriptors
// (ArgumentsDescriptor::Init, dart_entry.cc) and the serializer hands them the
// FIRST reference ids of every snapshot, in order, right after the fixed
// "base objects" (Serializer::AddBaseObjects, app_snapshot.cc /
// clustered_snapshot.cc, loop over cached_args_descriptors_). A call site whose
// descriptor is one of them therefore points at a small reference id instead of
// at an Array in the snapshot, which is why a descriptor reference is not found
// among the decoded Arrays (measured: all 7..23 distinct UnlinkedCall
// descriptors of the 3.9.2 / 3.12.2 / 3.1.0 / 2.12.0 / 2.10.0 samples are such
// ids).
//
// Shape (NewNonCached(type_args_len, i, i, ...)): cached descriptor i has
// kTypeArgsLenIndex = type_args_len and kCountIndex = kPositionalCountIndex = i,
// no named arguments. Layout:
//
//	<= 3.8.1  32 entries: type_args_len 0, count 0..31       (kCachedDescriptorCount = 32)
//	>= 3.9.2  35 entries: type_args_len 0, count 0..31, then
//	                      type_args_len 1, count 0..2        (kMaxNumArgumentsForCachedDescriptor = {31, 2})
//
// The first cached reference id is 1 + the number of base objects added before
// the loop. Counted in the SDK source (read at every md5 bucket):
//
//	2.10.0           24 base objects (8 Bytecode objects)  -> first id 25
//	2.12.0..2.17.6   18                                    -> first id 19
//	2.18.0, 2.19.0   19 (async exception handlers added)   -> first id 20
//	3.0.5, 3.1.0     20 (zero_array replaced, optimized_out added) -> first id 21
//	3.2.5..3.4.3     21 (+ empty_subtype_test_cache_array)  -> first id 22
//	3.5.0..3.12.2    20 (transition_sentinel removed)       -> first id 21
//	>= 3.13.0        AOT base objects are only the 7 Roots  -> no cached ids
//
// Verified against real snapshots: the descriptor ids of the corpus samples are
// exactly 1..N above the first id for every version listed above.

// ArgsDescriptorShape is the part of an ArgumentsDescriptor that a cached
// descriptor determines: the length of the type-argument vector and the number
// of passed arguments (the receiver included, type arguments excluded).
type ArgsDescriptorShape struct {
	TypeArgsLen int
	Count       int
}

// firstCachedArgsDescriptorRef returns the reference id of
// cached_args_descriptors_[0] for an exact supported Dart version.
func firstCachedArgsDescriptorRef(dartVersion string) (int, bool) {
	switch {
	case snapshot.VersionAtLeast(dartVersion, "3.13.0"):
		return 0, false
	case snapshot.VersionAtLeast(dartVersion, "3.5.0"):
		return 21, true
	case snapshot.VersionAtLeast(dartVersion, "3.2.5"):
		return 22, true
	case snapshot.VersionAtLeast(dartVersion, "3.0.5"):
		return 21, true
	case snapshot.VersionAtLeast(dartVersion, "2.18.0"):
		return 20, true
	case snapshot.VersionAtLeast(dartVersion, "2.12.0"):
		return 19, true
	default:
		return 25, true
	}
}

// cachedArgsDescriptor decodes ref when it is one of the VM's pre-allocated
// ArgumentsDescriptors. ok is false for every other reference: those are real
// Arrays in the snapshot (named arguments, larger counts) whose Smi elements
// this does not decode.
func cachedArgsDescriptor(dartVersion string, ref int) (ArgsDescriptorShape, bool) {
	first, ok := firstCachedArgsDescriptorRef(dartVersion)
	if !ok || ref < first {
		return ArgsDescriptorShape{}, false
	}
	i := ref - first
	if i < 32 {
		return ArgsDescriptorShape{TypeArgsLen: 0, Count: i}, true
	}
	if snapshot.VersionAtLeast(dartVersion, "3.9.2") && i < 35 {
		return ArgsDescriptorShape{TypeArgsLen: 1, Count: i - 32}, true
	}
	return ArgsDescriptorShape{}, false
}

// NamedArgument is one named argument of an ArgumentsDescriptor: the String
// ref of its name and the position it occupies among the passed arguments.
type NamedArgument struct {
	NameRef  int
	Position int
}

// ArgsDescriptor is a decoded ArgumentsDescriptor array. Layout (identical in
// every supported version, object.h ArgumentsDescriptor; audited in
// .tmp/review/AUDIT-2026-10.md): [type_args_len, count, size_with_type_args,
// positional_count, (name, position)*, null].
type ArgsDescriptor struct {
	TypeArgsLen int
	Count       int // passed arguments, receiver included, type arguments excluded
	Size        int // slots including the type-argument vector
	Positional  int
	Named       []NamedArgument
}

// ArgsDescriptorDecoder decodes the args_descriptor ref of a call site. A ref
// is either one of the VM's pre-allocated descriptors (cachedArgsDescriptor) or
// an Array in the snapshot whose elements are Smi objects (Mint/Smi clusters
// carry their values in Result.MintValues) and the shared null.
type ArgsDescriptorDecoder struct {
	version string
	arrays  map[int][]int
	smis    map[int]int64
}

// NewArgsDescriptorDecoder indexes the snapshot's Arrays and Smi values once.
func NewArgsDescriptorDecoder(r *Result, dartVersion string) *ArgsDescriptorDecoder {
	d := &ArgsDescriptorDecoder{version: dartVersion, arrays: make(map[int][]int, len(r.Arrays)), smis: r.MintValues}
	for _, a := range r.Arrays {
		d.arrays[a.RefID] = a.ElementRefIDs
	}
	return d
}

// Decode returns the descriptor behind ref, or ok=false when ref is neither a
// cached descriptor nor an Array of the expected shape.
func (d *ArgsDescriptorDecoder) Decode(ref int) (ArgsDescriptor, bool) {
	if s, ok := cachedArgsDescriptor(d.version, ref); ok {
		return ArgsDescriptor{TypeArgsLen: s.TypeArgsLen, Count: s.Count, Size: s.Count, Positional: s.Count}, true
	}
	elems, ok := d.arrays[ref]
	if !ok || len(elems) < 5 || len(elems)%2 == 0 {
		return ArgsDescriptor{}, false
	}
	smi := func(i int) (int, bool) {
		v, ok := d.smis[elems[i]]
		return int(v), ok
	}
	var out ArgsDescriptor
	var ok1, ok2, ok3, ok4 bool
	out.TypeArgsLen, ok1 = smi(0)
	out.Count, ok2 = smi(1)
	out.Size, ok3 = smi(2)
	out.Positional, ok4 = smi(3)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return ArgsDescriptor{}, false
	}
	for i := 4; i+1 < len(elems)-1; i += 2 {
		pos, ok := smi(i + 1)
		if !ok {
			return ArgsDescriptor{}, false
		}
		out.Named = append(out.Named, NamedArgument{NameRef: elems[i], Position: pos})
	}
	return out, true
}
