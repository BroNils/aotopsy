package samplecorpus_test

import (
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
// This test reports rather than fails. A missing sample is not something the
// code can fix, and a permanently-red test is precisely the failure mode this
// package exists to end. It fails only on something actionable: a registry
// entry whose file is present but is not the version its name claims.
func TestCorpusCoverage(t *testing.T) {
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
		path := samplecorpus.Path(s.FileName())
		if path == "" {
			continue
		}
		present++
		got := detectVersion(t, path)
		if got != s.DartVersion {
			// Actionable, and the whole point of the naming scheme.
			t.Error(samplecorpus.VersionMismatch(s, got))
			continue
		}
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
	for _, s := range samplecorpus.Registry {
		if samplecorpus.Path(s.FileName()) == "" {
			fmt.Fprintf(&b, "  missing: %-22s %s\n", s.FileName(), s.Note)
		}
	}
	t.Log(b.String())

	if uncovered > 0 {
		t.Logf("%d format famil(y/ies) have no sample at all. That is a real "+
			"coverage hole, not a test failure -- it is closed by adding a binary, "+
			"not by changing code.", uncovered)
	}
}

func detectVersion(t *testing.T, path string) string {
	t.Helper()
	info, err := samplecorpus.Extract(path)
	if err != nil {
		t.Errorf("open %s: %v", path, err)
		return ""
	}
	if info == nil || info.Version == nil {
		return ""
	}
	return info.Version.DartVersion
}
