package samplecorpus_test

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"aotopsy/internal/samplecorpus"
	"aotopsy/internal/snapshot"
)

// TestCorpusCoverage reports which snapshot FORMAT FAMILIES the sample corpus
// actually exercises.
//
// Counting supported versions overstates coverage badly. A version profile is
// mostly a restatement of the format its release used, so versions sharing a
// cluster-tag encoding stand or fall together -- and conversely, a family with
// no sample has never had its tag decoding run against a real binary, however
// many profiles it contains.
//
// At the time this was written the split was:
//
//	TagStyleCidInt32       3 profiles, 1 sample  (2.12.0)
//	TagStyleCidShift1     10 profiles, 0 samples <-- entire family unproven
//	TagStyleObjectHeader  10 profiles, 6 samples
//
// The ten TagStyleCidShift1 profiles (Dart 2.14.0-3.2.5) had never been run
// against a real binary. The two fixtures that were supposed to cover it --
// documented as 2.17.6 and 3.1.0 -- had silently become symlinks to 3.9.2 and
// 3.11.0 builds, so the family looked covered and was not.
//
// A checkout with no samples/ directory skips, because CI does not carry the
// corpus. Once a corpus is present it is expected to be complete: missing or
// extra binaries and identity mismatches are fixture drift and fail here.
func TestCorpusCoverage(t *testing.T) {
	if err := samplecorpus.ValidateRegistry(); err != nil {
		t.Fatalf("registry invariant: %v", err)
	}
	if err := samplecorpus.RequireCompleteCorpus(); err != nil {
		if errors.Is(err, samplecorpus.ErrNoCorpus) {
			t.Skip("no samples/ directory in this checkout")
		}
		t.Fatalf("corpus completeness: %v", err)
	}
	type family struct {
		profiles []string
		samples  []string
	}
	fams := map[string]*family{}

	for _, v := range snapshot.SupportedVersions() {
		p := snapshot.ProfileForVersion(v)
		if p == nil {
			t.Errorf("SupportedVersions lists %s but ProfileForVersion returns nil", v)
			continue
		}
		name := p.Tags.String()
		f := fams[name]
		if f == nil {
			f = &family{}
			fams[name] = f
		}
		f.profiles = append(f.profiles, v)
	}

	present := 0
	for _, s := range samplecorpus.Registry {
		_, err := samplecorpus.RequireSample(s.FileName())
		if err != nil {
			t.Fatalf("resolve %s: %v", s.FileName(), err)
		}
		present++
		p := snapshot.ProfileForVersion(s.DartVersion)
		if p == nil {
			t.Errorf("sample %s is a version with no profile", s.FileName())
			continue
		}
		f := fams[p.Tags.String()]
		if f != nil {
			f.samples = append(f.samples, s.FileName())
		}
	}

	names := make([]string, 0, len(fams))
	for n := range fams {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("snapshot format coverage:\n")
	uncovered := 0
	for _, n := range names {
		f := fams[n]
		state := fmt.Sprintf("%d sample(s)", len(f.samples))
		if len(f.samples) == 0 {
			state = "NO SAMPLE -- tag decoding never run against a real binary"
			uncovered++
		}
		fmt.Fprintf(&b, "  %-22s %2d profiles (%s .. %s)  %s\n",
			n, len(f.profiles), f.profiles[0], f.profiles[len(f.profiles)-1], state)
	}
	fmt.Fprintf(&b, "  samples present: %d of %d registered\n", present, len(samplecorpus.Registry))
	t.Log(b.String())

	if uncovered > 0 {
		t.Logf("%d format famil(y/ies) have no sample at all. That is a real "+
			"coverage hole, not a test failure -- it is closed by adding a binary, "+
			"not by changing code.", uncovered)
	}
}

func TestRegistryMatchesIndependentManifest(t *testing.T) {
	if err := samplecorpus.ValidateRegistry(); err != nil {
		t.Fatal(err)
	}
	if got := len(samplecorpus.ExpectedFiles()); got != samplecorpus.ExpectedSampleCount {
		t.Fatalf("manifest count = %d, want %d", got, samplecorpus.ExpectedSampleCount)
	}
}

func TestValidateRegistryRejectsDuplicateRegistration(t *testing.T) {
	original := samplecorpus.Registry
	samplecorpus.Registry = append(append([]samplecorpus.Sample(nil), original...), original[0])
	t.Cleanup(func() { samplecorpus.Registry = original })

	if err := samplecorpus.ValidateRegistry(); err == nil || !strings.Contains(err.Error(), "duplicate Registry filename") {
		t.Fatalf("ValidateRegistry error = %v, want duplicate filename error", err)
	}
}

func TestValidateRegistryRejectsMissingRegistration(t *testing.T) {
	original := samplecorpus.Registry
	samplecorpus.Registry = append([]samplecorpus.Sample(nil), original[1:]...)
	t.Cleanup(func() { samplecorpus.Registry = original })

	if err := samplecorpus.ValidateRegistry(); err == nil || !strings.Contains(err.Error(), "absent from Registry") {
		t.Fatalf("ValidateRegistry error = %v, want missing registration error", err)
	}
}

func TestValidateRegistryRejectsBrokenTwinContract(t *testing.T) {
	original := samplecorpus.Registry
	mutated := append([]samplecorpus.Sample(nil), original...)
	for i := range mutated {
		if mutated[i].TwinOf != "" {
			mutated[i].TwinOf = "dart-3.10.7-arm64.so"
			samplecorpus.Registry = mutated
			t.Cleanup(func() { samplecorpus.Registry = original })
			if err := samplecorpus.ValidateRegistry(); err == nil || !strings.Contains(err.Error(), "not source/version/arch-identical") {
				t.Fatalf("ValidateRegistry error = %v, want false-twin identity error", err)
			}
			return
		}
	}
	t.Fatal("registry has no declared ground-truth twin to corrupt")
}

func TestValidateRegistryRejectsUnknownSourceSet(t *testing.T) {
	original := samplecorpus.Registry
	mutated := append([]samplecorpus.Sample(nil), original...)
	mutated[0].SourceSet = "ad_hoc_unverified_source"
	samplecorpus.Registry = mutated
	t.Cleanup(func() { samplecorpus.Registry = original })

	if err := samplecorpus.ValidateRegistry(); err == nil || !strings.Contains(err.Error(), "unknown source set") {
		t.Fatalf("ValidateRegistry error = %v, want unknown source-set error", err)
	}
}

func TestDifferentialSourceSetsExcludeSymbolOracles(t *testing.T) {
	for setName, members := range samplecorpus.DifferentialSourceSets() {
		if len(members) < 2 {
			t.Fatalf("source set %q has only %d differential member(s)", setName, len(members))
		}
		for _, s := range members {
			if s.SymbolOracle {
				t.Fatalf("source set %q includes symbol oracle %s in differential population", setName, s.FileName())
			}
		}
	}
}
