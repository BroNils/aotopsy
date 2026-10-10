package cluster

import "testing"

// Reference ids measured on real snapshots (UnlinkedCall.args_descriptor of the
// corpus samples): the ids are first+count for a one-argument call upward.
func TestCachedArgsDescriptorMatchesMeasuredSnapshots(t *testing.T) {
	for _, tc := range []struct {
		version string
		ref     int
		want    ArgsDescriptorShape
	}{
		{"3.9.2", 22, ArgsDescriptorShape{0, 1}},
		{"3.9.2", 24, ArgsDescriptorShape{0, 3}},
		{"3.12.2", 23, ArgsDescriptorShape{0, 2}},
		{"3.1.0", 22, ArgsDescriptorShape{0, 1}},
		{"3.1.0", 24, ArgsDescriptorShape{0, 3}},
		{"2.12.0", 20, ArgsDescriptorShape{0, 1}},
		{"2.12.0", 23, ArgsDescriptorShape{0, 4}},
		{"2.10.0", 26, ArgsDescriptorShape{0, 1}},
		{"2.10.0", 29, ArgsDescriptorShape{0, 4}},
	} {
		got, ok := cachedArgsDescriptor(tc.version, tc.ref)
		if !ok || got != tc.want {
			t.Errorf("%s ref %d = %+v ok=%v, want %+v", tc.version, tc.ref, got, ok, tc.want)
		}
	}
}

// The first cached id moves with the base-object list of each SDK bucket.
func TestCachedArgsDescriptorFirstIDPerVersionBucket(t *testing.T) {
	for version, first := range map[string]int{
		"2.10.0": 25, "2.12.0": 19, "2.13.0": 19, "2.14.0": 19, "2.15.0": 19, "2.16.0": 19, "2.17.6": 19,
		"2.18.0": 20, "2.19.0": 20, "3.0.5": 21, "3.1.0": 21, "3.2.5": 22, "3.3.0": 22, "3.4.3": 22,
		"3.5.0": 21, "3.6.2": 21, "3.7.0": 21, "3.8.1": 21, "3.9.2": 21, "3.10.7": 21, "3.11.0": 21, "3.12.2": 21,
	} {
		got, ok := cachedArgsDescriptor(version, first)
		if !ok || got.Count != 0 || got.TypeArgsLen != 0 {
			t.Errorf("%s: first id %d = %+v ok=%v, want count 0", version, first, got, ok)
		}
		if _, ok := cachedArgsDescriptor(version, first-1); ok {
			t.Errorf("%s: id %d (a base object before the cache) decoded", version, first-1)
		}
	}
}

func TestCachedArgsDescriptorCacheSizeAndTypeArgs(t *testing.T) {
	// <= 3.8.1: 32 entries, no type-argument descriptors.
	if _, ok := cachedArgsDescriptor("3.8.1", 21+31); !ok {
		t.Error("3.8.1: last count-31 descriptor not decoded")
	}
	if _, ok := cachedArgsDescriptor("3.8.1", 21+32); ok {
		t.Error("3.8.1 has no type-argument descriptors")
	}
	// >= 3.9.2: three more with type_args_len 1.
	got, ok := cachedArgsDescriptor("3.9.2", 21+32)
	if !ok || got != (ArgsDescriptorShape{1, 0}) {
		t.Errorf("3.9.2 first type-argument descriptor = %+v ok=%v", got, ok)
	}
	if _, ok := cachedArgsDescriptor("3.9.2", 21+35); ok {
		t.Error("3.9.2: id past the 35 cached entries decoded")
	}
	// 3.13.0: the AOT base objects are the 7 Roots; nothing is cached.
	if _, ok := cachedArgsDescriptor("3.13.0", 21); ok {
		t.Error("3.13.0 has no cached descriptor ids")
	}
}

// A snapshot Array descriptor (3.13.0 shape measured on a real sample:
// [Smi 0, Smi 1, Smi 1, Smi 1, null]) and one with a named argument.
func TestArgsDescriptorDecoderDecodesSnapshotArrays(t *testing.T) {
	const null = 1
	r := &Result{
		MintValues: map[int]int64{8: 0, 100: 2, 101: 3, 102: 5},
		Arrays: []ArrayInfo{
			{RefID: 500, ElementRefIDs: []int{8, 100, 100, 100, null}},
			// call(a, b, {x}): count 3, size 3, positional 2, named x at position 2.
			{RefID: 501, ElementRefIDs: []int{8, 101, 101, 100, 900, 100, null}},
			{RefID: 502, ElementRefIDs: []int{8, 100, 100, null}},      // even length
			{RefID: 503, ElementRefIDs: []int{8, 777, 100, 100, null}}, // count is not a Smi
		},
	}
	d := NewArgsDescriptorDecoder(r, "3.13.0")
	got, ok := d.Decode(500)
	if !ok || got.Count != 2 || got.Size != 2 || got.Positional != 2 || got.TypeArgsLen != 0 || len(got.Named) != 0 {
		t.Fatalf("plain descriptor = %+v ok=%v", got, ok)
	}
	got, ok = d.Decode(501)
	if !ok || got.Count != 3 || got.Positional != 2 || len(got.Named) != 1 || got.Named[0] != (NamedArgument{NameRef: 900, Position: 2}) {
		t.Fatalf("named descriptor = %+v ok=%v", got, ok)
	}
	// Not a descriptor: wrong length, unknown ref, element that is not a Smi.
	for _, ref := range []int{999, 502, 503} {
		if _, ok := d.Decode(ref); ok {
			t.Errorf("ref %d decoded", ref)
		}
	}
}

func TestArgsDescriptorDecoderUsesCachedDescriptors(t *testing.T) {
	d := NewArgsDescriptorDecoder(&Result{}, "3.9.2")
	got, ok := d.Decode(23)
	if !ok || got.Count != 2 || got.Positional != 2 {
		t.Fatalf("cached descriptor = %+v ok=%v", got, ok)
	}
}
