package pipeline

import (
	"os"
	"testing"

	"aotopsy/internal/cluster"
)

// TestInstanceFieldOffsets_ConfigData verifies Instance field capture against
// exact ground truth in compare_sample/lib/ground_truth.dart:
//
//	class ConfigData {
//	  final String name;
//	  final int version;
//	  final bool enabled;
//	  const ConfigData({required this.name, required this.version,
//	                    required this.enabled});
//	}
//	const cfg1 = ConfigData(name: 'test', version: 42, enabled: true);
//	const cfg2 = ConfigData(name: 'prod', version: 1,  enabled: false);
//
// ConfigData is the sharpest possible fixture for the offset math, because its
// layout contains every case the old implementation got wrong:
//
//   - Dart reports nextFieldOffsetInWords = 6, so with 2 header words under
//     compressed pointers there are 4 field SLOTS (offsets 8/12/16/20) for only
//     3 declared fields.
//   - `version` is an unboxed int64, which occupies TWO compressed-pointer
//     slots (12 and 16) and produces NO ref. Anything that infers a field's
//     offset from its index in the ref list is therefore off by two for every
//     field after it.
//   - ConfigData has ZERO Field objects in the snapshot (AOT drops them for
//     final fields of const-only classes), so the old approach of sorting the
//     class's declared field offsets and zipping had nothing to sort at all.
//
// So the expectation is exactly two captured refs, at offsets 8 and 20.
func TestInstanceFieldOffsets_ConfigData(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_ARM64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_ARM64 not set")
	}
	res := clusterOnly(t, libPath)

	// Find ConfigData's class ID via its ClassInfo name.
	var configCID int32 = -1
	for _, ci := range res.Classes {
		if ci.NameRefID < 0 {
			continue
		}
		for _, ps := range res.Strings {
			if ps.RefID == ci.NameRefID && ps.Value == "ConfigData" {
				configCID = ci.ClassID
			}
		}
		if configCID >= 0 {
			break
		}
	}
	if configCID < 0 {
		t.Skip("ConfigData not in this sample (stale binary? see AGENTS.md " +
			"-- the extracted_* libapp.so files predate ground_truth.dart)")
	}

	var insts []cluster.InstanceInfo
	for _, ii := range res.Instances {
		if int32(ii.CID) == configCID {
			insts = append(insts, ii)
		}
	}
	if len(insts) != 2 {
		t.Fatalf("found %d ConfigData instances, want 2 (cfg1 and cfg2)", len(insts))
	}

	strByRef := map[int]string{}
	for _, ps := range res.Strings {
		strByRef[ps.RefID] = ps.Value
	}

	var names []string
	for _, ii := range insts {
		if ii.HeaderWords != 2 {
			t.Errorf("HeaderWords = %d, want 2 (compressed pointers: tags + hash)", ii.HeaderWords)
		}
		if ii.NumFieldSlots != 4 {
			t.Errorf("NumFieldSlots = %d, want 4 (nextFieldOffsetInWords 6 - 2 header words)",
				ii.NumFieldSlots)
		}
		if len(ii.Fields) != 2 {
			t.Fatalf("captured %d refs, want 2: `version` is an unboxed int64 and "+
				"produces none. Got %+v", len(ii.Fields), ii.Fields)
		}
		// name at offset 8, enabled at offset 20 -- offsets 12 and 16 are the
		// two halves of the unboxed int64 and must be absent.
		if got := ii.Fields[0].ByteOffset; got != 8 {
			t.Errorf("first field offset = %d, want 8", got)
		}
		if got := ii.Fields[1].ByteOffset; got != 20 {
			t.Errorf("second field offset = %d, want 20 (offsets 12/16 hold the "+
				"unboxed int64 and must not appear)", got)
		}
		if s, ok := strByRef[ii.Fields[0].Ref]; ok {
			names = append(names, s)
		}
	}

	// The String values must be the ones in the source, proving the offset-8
	// ref really is `name` and not some neighbouring slot.
	want := map[string]bool{"test": true, "prod": true}
	if len(names) != 2 {
		t.Fatalf("resolved %d of 2 name strings; offset 8 may not be `name`. got %v", len(names), names)
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("name = %q, want one of test/prod (from the source's cfg1/cfg2)", n)
		}
	}
	if names[0] == names[1] {
		t.Errorf("both instances have name %q; cfg1 and cfg2 differ in the source", names[0])
	}

	// enabled: true for cfg1, false for cfg2 -- two DIFFERENT canonical base
	// object refs. Equal refs would mean we captured the same slot twice.
	if insts[0].Fields[1].Ref == insts[1].Fields[1].Ref {
		t.Errorf("both instances share enabled ref %d; the source sets true vs false",
			insts[0].Fields[1].Ref)
	}
	for _, ii := range insts {
		if ii.Fields[1].Ref <= cluster.RefNull {
			t.Errorf("enabled ref = %d, want a real base object (true/false)", ii.Fields[1].Ref)
		}
	}
}

// TestInstanceFieldRefsNeverExceedSlots is a corpus-wide invariant: a class
// cannot have more captured pointer fields than it has field slots. It catches
// stream misalignment in readFillInstance, which would otherwise show up only
// as subtly wrong types much later.
func TestInstanceFieldRefsNeverExceedSlots(t *testing.T) {
	for _, env := range []string{"AOTOPSY_TEST_SAMPLE_ARM64", "AOTOPSY_TEST_SAMPLE_312_X64",
		"AOTOPSY_TEST_SAMPLE_DART212", "AOTOPSY_TEST_SAMPLE_LARGE"} {
		libPath := os.Getenv(env)
		if libPath == "" {
			continue
		}
		t.Run(env, func(t *testing.T) {
			res := clusterOnly(t, libPath)
			if len(res.Instances) == 0 {
				t.Skip("no instances captured")
			}
			wordSizes := map[int]bool{4: true, 8: true}
			for _, ii := range res.Instances {
				if len(ii.Fields) > ii.NumFieldSlots {
					t.Fatalf("instance ref %d (cid %d): %d refs > %d slots",
						ii.RefID, ii.CID, len(ii.Fields), ii.NumFieldSlots)
				}
				if !wordSizes[ii.HeaderWords*4] && ii.HeaderWords != 1 && ii.HeaderWords != 2 {
					t.Fatalf("instance ref %d: HeaderWords = %d", ii.RefID, ii.HeaderWords)
				}
				var prev int32 = -1
				for _, f := range ii.Fields {
					if f.ByteOffset <= prev {
						t.Fatalf("instance ref %d: offsets not strictly increasing (%d after %d)",
							ii.RefID, f.ByteOffset, prev)
					}
					// Offsets must land inside the object.
					maxOff := int32((ii.HeaderWords + ii.NumFieldSlots) * 4)
					if ii.HeaderWords == 1 {
						maxOff = int32((ii.HeaderWords + ii.NumFieldSlots) * 8)
					}
					if f.ByteOffset >= maxOff {
						t.Fatalf("instance ref %d: offset %d beyond object end %d",
							ii.RefID, f.ByteOffset, maxOff)
					}
					prev = f.ByteOffset
				}
			}
			t.Logf("%d instances checked", len(res.Instances))
		})
	}
}
