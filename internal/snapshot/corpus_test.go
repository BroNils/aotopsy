package snapshot_test

import (
	"strings"
	"testing"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/samplecorpus"
	"aotopsy/internal/snapshot"
)

// Corpus-wide snapshot tests.
//
// What these replace pinned a literal MD5 per sample:
//
//	if info.VmHeader.SnapshotHash != "1441d6b13b8623fa7fbf61433abebd31" { ... }
//
// with the sample identified only by an app codename. samples/ is gitignored,
// the codenames drifted onto other binaries (see internal/samplecorpus), and
// the assertion then reported "unexpected hash" -- which reads as a snapshot
// parsing bug and was in fact a fixture pointing at a different app.
//
// The hash needs no literal. It IS the version identity: DetectVersion maps a
// snapshot hash to a Dart version through knownHashes. So the assertion worth
// making is that the hash in this binary resolves to the version the file name
// claims, which pins the same mapping and cannot rot into a magic number.
func eachSample(t *testing.T, fn func(t *testing.T, s samplecorpus.Sample, info *snapshot.Info)) {
	t.Helper()
	for _, entry := range samplecorpus.Registry {
		entry := entry
		t.Run(entry.FileName(), func(t *testing.T) {
			path := samplecorpus.Path(entry.FileName())
			if path == "" {
				t.Skip(samplecorpus.MissingMessage(entry))
			}
			ef, err := elfx.Open(path)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			t.Cleanup(func() { _ = ef.Close() })
			info, err := snapshot.Extract(ef, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if info.Version == nil || info.Version.DartVersion != entry.DartVersion {
				got := ""
				if info.Version != nil {
					got = info.Version.DartVersion
				}
				t.Fatal(samplecorpus.VersionMismatch(entry, got))
			}
			fn(t, entry, info)
		})
	}
}

// TestCorpusExtract checks that every sample yields the regions and headers
// the rest of the pipeline depends on.
func TestCorpusExtract(t *testing.T) {
	eachSample(t, func(t *testing.T, s samplecorpus.Sample, info *snapshot.Info) {
		// Dart 3.13.0 merged the four snapshot symbols into two and the VM and
		// isolate snapshots into one blob, so there are no separate VM regions
		// to find. Requiring them would be requiring the sample to be older.
		if !info.UnifiedSnapshot {
			if info.VmData.VA == 0 {
				t.Error("VmData VA is 0")
			}
			if info.VmInstructions.VA == 0 {
				t.Error("VmInstructions VA is 0")
			}
			if info.VmHeader == nil {
				t.Fatal("VmHeader is nil")
			}
			if info.VmData.SHA256 == "" {
				t.Error("VmData SHA256 is empty")
			}
		}
		if info.IsolateData.VA == 0 {
			t.Error("IsolateData VA is 0")
		}
		if info.IsolateInstructions.VA == 0 {
			t.Error("IsolateInstructions VA is 0")
		}
		if info.IsolateHeader == nil {
			t.Fatal("IsolateHeader is nil")
		}

		hdr := info.IsolateHeader
		if !info.UnifiedSnapshot {
			hdr = info.VmHeader
		}
		if hdr.SnapshotHash == "" {
			t.Fatal("snapshot hash is empty")
		}
		if hdr.Features == "" {
			t.Error("features string is empty")
		}

		// The hash-to-version mapping, without a literal hash: this is what
		// the per-sample MD5 constants were really pinning.
		detected := snapshot.DetectVersion(hdr.SnapshotHash)
		if detected == nil || detected.DartVersion != s.DartVersion {
			got := "<unknown hash>"
			if detected != nil && detected.DartVersion != "" {
				got = detected.DartVersion
			}
			t.Errorf("snapshot hash %s resolves to %s, want %s\n"+
				"  Either knownHashes lost this entry, or the sample is not what it claims.",
				hdr.SnapshotHash, got, s.DartVersion)
		}

		t.Logf("Dart %s %s: hash=%s features=%s", s.DartVersion, s.Arch,
			hdr.SnapshotHash, summariseFeatures(hdr))
	})
}

// TestCorpusVersionProfileFlags checks each sample's detected profile against
// the profile the registry says it should get.
//
// The list this replaces spelled out HeaderFields/FillRefUnsigned/PreV32Format
// per sample by hand, which is the profile table copied into a test -- so it
// could only fail when a fixture stopped being the version it claimed, and it
// then reported that as flags being swapped.
func TestCorpusVersionProfileFlags(t *testing.T) {
	eachSample(t, func(t *testing.T, s samplecorpus.Sample, info *snapshot.Info) {
		want := snapshot.ProfileForVersion(s.DartVersion)
		if want == nil {
			t.Fatalf("no profile for Dart %s", s.DartVersion)
		}
		if !want.Supported {
			t.Fatalf("Dart %s has a profile but Supported is false", s.DartVersion)
		}
		got := info.Version
		if got.HeaderFields != want.HeaderFields {
			t.Errorf("HeaderFields = %d, profile says %d", got.HeaderFields, want.HeaderFields)
		}
		if got.FillRefUnsigned != want.FillRefUnsigned {
			t.Errorf("FillRefUnsigned = %v, profile says %v", got.FillRefUnsigned, want.FillRefUnsigned)
		}
		if got.PreV32Format != want.PreV32Format {
			t.Errorf("PreV32Format = %v, profile says %v", got.PreV32Format, want.PreV32Format)
		}
		if got.Tags != want.Tags {
			t.Errorf("Tags = %v, profile says %v", got.Tags, want.Tags)
		}
		if got.CIDs != want.CIDs {
			t.Error("CIDs table is not the profile's table")
		}
	})
}

func summariseFeatures(h *snapshot.Header) string {
	var on []string
	for _, f := range []string{"null-safety", "compressed-pointers", "product", "release", "debug"} {
		if h.HasFeature(f) {
			on = append(on, f)
		}
	}
	if len(on) == 0 {
		return "(none of the tracked features)"
	}
	return strings.Join(on, ",")
}
