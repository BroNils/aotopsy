package cluster

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/samplecorpus"
	"aotopsy/internal/snapshot"
)

// Corpus-wide cluster tests.
//
// These used to be one hardcoded function per sample --
// TestScanClusters_EvilPatched_VM, TestScanClusters_BlutterLce_Isolate, and so
// on -- with the expected counts inline. Two things were wrong with that.
//
// Adding a sample meant editing four test files, so nobody did, and six of the
// corpus's binaries were never touched by any test.
//
// Worse, the counts were tied to binaries identified only by an app codename.
// samples/ is gitignored, the codenames drifted onto whatever each machine had
// (see internal/samplecorpus), and the counts then failed against innocent
// parsing code. Five test files sat permanently red.
//
// So: the tests are driven by samplecorpus.Registry, and every per-binary
// number lives in a committed record keyed by the input's SHA-256 -- the same
// arrangement internal/pipeline's golden test uses, for the same reason. A
// different local binary skips rather than fails, because a different input is
// not a regression. A MISSING record fails, because self-recording baselines
// cannot catch anything.
//
//	AOTOPSY_UPDATE_CORPUS=1 go test ./internal/cluster/ -run Corpus

// corpusRecord is one sample's recorded cluster-layer facts.
type corpusRecord struct {
	Sample      string `json:"sample"`
	InputSHA256 string `json:"input_sha256"`
	DartVersion string `json:"dart_version"`

	// Unified is Dart 3.13.0+, where one blob replaces the VM/isolate pair
	// and there is no separate VM snapshot to scan.
	Unified bool `json:"unified_snapshot"`

	VMClusters      int64 `json:"vm_clusters,omitempty"`
	IsolateClusters int64 `json:"isolate_clusters"`

	// HasInstructionsTable is false on the versions that predate it
	// (CodeTextOffsetDelta, Dart 2.10-2.15), where code ranges come from
	// per-Code text-offset deltas instead. The instr_table_* fields below
	// are meaningless when this is false.
	HasInstructionsTable bool `json:"has_instructions_table"`

	Strings int `json:"strings"`
	Named   int `json:"named"`
	Codes   int `json:"codes"`

	InstrTableLength       uint32 `json:"instr_table_length"`
	InstrTableFirstWithPCs uint32 `json:"instr_table_first_entry_with_code"`
	InstrTableCodeEntries  int    `json:"instr_table_code_entries"`
	CodeRanges             int    `json:"code_ranges"`
}

// corpusSample is a registry entry resolved to an on-disk file.
type corpusSample struct {
	samplecorpus.Sample
	path string
	info *snapshot.Info
}

// eachCorpusSample runs fn as a subtest for every registry entry present on
// this machine, after checking the file really is the version its name claims.
func eachCorpusSample(t *testing.T, fn func(t *testing.T, s corpusSample)) {
	t.Helper()
	present := 0
	for _, entry := range samplecorpus.Registry {
		entry := entry
		t.Run(entry.FileName(), func(t *testing.T) {
			path := samplecorpus.Path(entry.FileName())
			if path == "" {
				t.Skip(samplecorpus.MissingMessage(entry))
			}
			present++
			info := openSample(t, path)
			if info.Version == nil || info.Version.DartVersion != entry.DartVersion {
				got := ""
				if info.Version != nil {
					got = info.Version.DartVersion
				}
				t.Fatal(samplecorpus.VersionMismatch(entry, got))
			}
			fn(t, corpusSample{Sample: entry, path: path, info: info})
		})
	}
	if present == 0 {
		t.Log("no corpus sample present on this machine (or all filtered out by " +
			"-run); nothing was verified")
	}
}

// openSample keeps the ELF mapped for the lifetime of the subtest, unlike
// samplecorpus.Extract which closes it -- the cluster layer reads the mapped
// snapshot data, not just the headers.
func openSample(t *testing.T, path string) *snapshot.Info {
	t.Helper()
	ef, err := elfx.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = ef.Close() })
	info, err := snapshot.Extract(ef, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
	if err != nil {
		t.Fatalf("extract %s: %v", path, err)
	}
	return info
}

// TestCorpusClusterFacts is the drift sentinel for the whole cluster layer.
//
// Any ref-count mistake in any cluster shows up here, because a wrong ref
// count desynchronises the stream and every later count moves with it. That
// property is why exact numbers are worth recording at all.
func TestCorpusClusterFacts(t *testing.T) {
	update := os.Getenv("AOTOPSY_UPDATE_CORPUS") != ""
	eachCorpusSample(t, func(t *testing.T, s corpusSample) {
		got := measureSample(t, s)

		recPath := filepath.Join("testdata", "corpus", s.FileName()+".json")
		var want corpusRecord
		have := false
		if data, err := os.ReadFile(recPath); err == nil {
			if err := json.Unmarshal(data, &want); err != nil {
				t.Fatalf("parse %s: %v", recPath, err)
			}
			have = true
		}

		if update {
			writeCorpusRecord(t, recPath, got)
			return
		}
		if !have {
			t.Fatalf("no corpus record at %s\n"+
				"  Records are committed, so a missing one means a newly added sample.\n"+
				"  Record it deliberately, then read the diff before committing:\n"+
				"    AOTOPSY_UPDATE_CORPUS=1 go test ./internal/cluster/ -run Corpus", recPath)
		}
		if want.InputSHA256 != got.InputSHA256 {
			t.Skipf("samples/%s is a different binary than the record\n"+
				"  record: %s\n  actual: %s\n"+
				"  (a different input of the same Dart version is not a regression)",
				s.FileName(), want.InputSHA256, got.InputSHA256)
		}
		compareCorpusRecords(t, want, got)
	})
}

func measureSample(t *testing.T, s corpusSample) corpusRecord {
	t.Helper()
	rec := corpusRecord{
		Sample:      s.FileName(),
		InputSHA256: fileSHA256(t, s.path),
		DartVersion: s.info.Version.DartVersion,
		Unified:     s.info.UnifiedSnapshot,
	}

	// The VM snapshot only exists as a separate blob before 3.13.0.
	if !s.info.UnifiedSnapshot && len(s.info.VmData.Data) > 64 {
		vm := scanData(t, s.info, s.info.VmData.Data, true)
		rec.VMClusters = declaredClusters(vm)
		if int64(len(vm.Clusters)) != rec.VMClusters {
			t.Errorf("VM: decoded %d clusters, header declares %d",
				len(vm.Clusters), rec.VMClusters)
		}
	}

	data := s.info.IsolateData.Data
	iso := scanData(t, s.info, data, false)
	rec.IsolateClusters = declaredClusters(iso)
	if int64(len(iso.Clusters)) != rec.IsolateClusters {
		t.Errorf("isolate: decoded %d clusters, header declares %d",
			len(iso.Clusters), rec.IsolateClusters)
	}

	// snapshotSize must be the isolate header's TotalSize, not 0 and not
	// len(data): it is what locates the ROData image. Passing 0 silently
	// disables every ROData-backed capture, which on a compressed-pointer
	// build looks fine (strings are inline there) and on an uncompressed one
	// records zero strings -- the first recording of the 2.12 sample said
	// "strings": 0 for exactly this reason.
	var isoSize int64
	if s.info.IsolateHeader != nil {
		isoSize = s.info.IsolateHeader.TotalSize
	}
	if err := ReadFill(data, iso, s.info.Version, false, isoSize); err != nil {
		t.Fatalf("ReadFill: %v", err)
	}
	rec.Strings, rec.Named, rec.Codes = len(iso.Strings), len(iso.Named), len(iso.Codes)

	// Dart 2.10-2.15 have no instructions table at all: code ranges come from
	// per-Code text-offset deltas. snapshot_loader.go treats exactly this
	// combination as the legitimate no-table case, and so does this test --
	// asserting a table here would just be asserting that the sample is 3.x.
	table, err := ParseInstructionsTable(data, &iso.Header, s.info.Version, s.info.IsolateHeader)
	if err != nil {
		if iso.Header.InstructionTableDataOffset == 0 && s.info.Version.CodeTextOffsetDelta {
			rec.CodeRanges = len(ResolveCodeRangesFromTextOffset(iso.Codes))
			return rec
		}
		t.Fatalf("ParseInstructionsTable: %v", err)
	}
	rec.HasInstructionsTable = true
	if int(table.Length) != len(table.Entries) {
		t.Errorf("instructions table: Length = %d but %d entries",
			table.Length, len(table.Entries))
	}
	if table.FirstEntryWithCode < table.Length {
		if first := table.Entries[table.FirstEntryWithCode]; first.PCOffset == 0 {
			t.Error("first entry with code has PCOffset = 0")
		}
	}
	rec.InstrTableLength = table.Length
	rec.InstrTableFirstWithPCs = table.FirstEntryWithCode
	rec.InstrTableCodeEntries = int(table.Length) - int(table.FirstEntryWithCode)

	ranges, err := ResolveCodeRanges(iso.Codes, table)
	if err != nil {
		t.Fatalf("ResolveCodeRanges: %v", err)
	}
	rec.CodeRanges = len(ranges)
	for i := 0; i < len(ranges)-1; i++ {
		if ranges[i].Size == 0 {
			t.Errorf("range[%d] (ref %d) has size 0", i, ranges[i].RefID)
			break
		}
	}
	for i := 1; i < len(ranges); i++ {
		if ranges[i].PCOffset <= ranges[i-1].PCOffset {
			t.Errorf("ranges not sorted by PCOffset at %d: %d <= %d",
				i, ranges[i].PCOffset, ranges[i-1].PCOffset)
			break
		}
	}
	return rec
}

func compareCorpusRecords(t *testing.T, want, got corpusRecord) {
	t.Helper()
	type field struct {
		name       string
		want, got  int64
		suppressed bool
	}
	noTable := !want.HasInstructionsTable
	fields := []field{
		{"vm_clusters", want.VMClusters, got.VMClusters, want.Unified},
		{"isolate_clusters", want.IsolateClusters, got.IsolateClusters, false},
		{"strings", int64(want.Strings), int64(got.Strings), false},
		{"named", int64(want.Named), int64(got.Named), false},
		{"codes", int64(want.Codes), int64(got.Codes), false},
		{"instr_table_length", int64(want.InstrTableLength), int64(got.InstrTableLength), noTable},
		{"instr_table_first_entry_with_code", int64(want.InstrTableFirstWithPCs), int64(got.InstrTableFirstWithPCs), noTable},
		{"instr_table_code_entries", int64(want.InstrTableCodeEntries), int64(got.InstrTableCodeEntries), noTable},
		{"code_ranges", int64(want.CodeRanges), int64(got.CodeRanges), false},
	}
	for _, f := range fields {
		if f.suppressed || f.want == f.got {
			continue
		}
		t.Errorf("%s = %d, want %d\n"+
			"  A count that moved means the cluster stream desynchronised, which is\n"+
			"  almost always a ref count that is wrong for this Dart version.\n"+
			"  If the change is intended: AOTOPSY_UPDATE_CORPUS=1 and review the diff.",
			f.name, f.got, f.want)
	}
	if want.Unified != got.Unified {
		t.Errorf("unified_snapshot = %v, want %v", got.Unified, want.Unified)
	}
	if want.HasInstructionsTable != got.HasInstructionsTable {
		t.Errorf("has_instructions_table = %v, want %v -- the snapshot changed "+
			"which code-range mechanism it uses", got.HasInstructionsTable, want.HasInstructionsTable)
	}
}

func writeCorpusRecord(t *testing.T, path string, rec corpusRecord) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("recorded %s", path)
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

// TestCorpusHeaderFieldCount checks each sample's header shape against its own
// version profile, rather than against a number written next to one binary.
//
// The two tests this replaces pinned HeaderFields=6 for a 2.17.6 sample and 5
// for a 3.10.7 one. Stated that way the assertion is really "the profile says
// 6" repeated by hand, so it could only ever fail when the fixture stopped
// being 2.17.6 -- which is exactly what happened, and it reported the problem
// as a header bug.
func TestCorpusHeaderFieldCount(t *testing.T) {
	eachCorpusSample(t, func(t *testing.T, s corpusSample) {
		profile := snapshot.ProfileForVersion(s.DartVersion)
		if profile == nil {
			t.Fatalf("no profile for Dart %s", s.DartVersion)
		}
		if s.info.Version.HeaderFields != profile.HeaderFields {
			t.Errorf("HeaderFields = %d, profile for %s says %d",
				s.info.Version.HeaderFields, s.DartVersion, profile.HeaderFields)
		}

		iso := scanData(t, s.info, s.info.IsolateData.Data, false)
		// Whether the header carries initial_field_table_len is NOT a function
		// of the field count: 2.12 and 2.18 both have five fields and only 2.12
		// has it. The parser keys off FillRefUnsigned (true for 2.10-2.17), and
		// so does this. Deriving it from HeaderFields instead was wrong and
		// this test caught it on the 2.12 sample -- a sample the tests this
		// replaces never ran at all.
		if profile.FillRefUnsigned {
			if iso.Header.InitialFieldTableLen == 0 {
				t.Errorf("InitialFieldTableLen = 0, but Dart %s writes it "+
					"(FillRefUnsigned)", s.DartVersion)
			}
		} else if iso.Header.InitialFieldTableLen != 0 {
			t.Errorf("InitialFieldTableLen = %d, want 0 for Dart %s "+
				"(no field table in the header)", iso.Header.InitialFieldTableLen, s.DartVersion)
		}
	})
}

// TestCorpusPatchClassRefCount is the format-boundary sentinel: PatchClass has
// three refs up to Dart 3.1 and two after, and getting it wrong desynchronises
// every cluster that follows.
//
// The expectation is derived from the profile's PreV32Format flag rather than
// hardcoded per sample, so this covers whatever samples exist instead of the
// three that were listed by name. That matters here more than anywhere else:
// the two samples meant to cover the PreV32Format=true side had both drifted
// onto PreV32Format=false binaries, so the boundary this test exists to guard
// was being checked from one side only.
func TestCorpusPatchClassRefCount(t *testing.T) {
	sawPre, sawPost := false, false
	eachCorpusSample(t, func(t *testing.T, s corpusSample) {
		want := 2
		if s.info.Version.PreV32Format {
			want = 3
			sawPre = true
		} else {
			sawPost = true
		}
		patchCID := s.info.Version.CIDs.PatchClass
		spec := GetFillSpec(patchCID, &ClusterMeta{CID: patchCID}, s.info.Version)
		if spec.NumRefs != want {
			t.Errorf("PatchClass NumRefs = %d, want %d (Dart %s, PreV32Format=%v)",
				spec.NumRefs, want, s.DartVersion, s.info.Version.PreV32Format)
		}
	})
	if !sawPre || !sawPost {
		t.Logf("boundary covered from one side only (PreV32Format=true seen: %v, "+
			"false seen: %v) -- a sample on the missing side would make this a real "+
			"two-sided sentinel", sawPre, sawPost)
	}
}

// declaredClusters is the cluster count the header declares.
//
// On SplitCanonical versions (Dart 2.12-2.13) the header carries the canonical
// and non-canonical counts separately and the real total is their sum --
// ScanClusters allocates for exactly that sum. Comparing against NumClusters
// alone reports a 2.12 snapshot as having decoded 267 clusters where the
// header "says" 29, which is a bug in the reader of the header, not in the
// scanner.
func declaredClusters(r *Result) int64 {
	return r.Header.NumCanonicalClusters + r.Header.NumClusters
}

// scanData is scanSnapshot without the t.Fatal on a short buffer, so callers
// can decide whether an absent VM blob is expected.
func scanData(t *testing.T, info *snapshot.Info, data []byte, isVM bool) *Result {
	t.Helper()
	cs, err := FindClusterDataStart(data)
	if err != nil {
		t.Fatalf("FindClusterDataStart: %v", err)
	}
	result, err := ScanClusters(data, cs, info.Version, isVM, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
	if err != nil {
		t.Fatalf("ScanClusters: %v", err)
	}
	return result
}
