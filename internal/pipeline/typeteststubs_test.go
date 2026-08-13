package pipeline

import (
	"os"
	"strings"
	"testing"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/snapshot"
)

// loadForNaming is the cluster-only path (ELF -> snapshot -> alloc -> fill),
// with the VM isolate too, because half the naming paths consult it and a nil
// vmResult silently changes what the numbers mean. Measuring this gap with
// vmResult nil is exactly the mistake that produced a first, wrong reading of
// it: 877 Codes looked like "owner resolved, name empty" when the real figure
// with the VM strings present is 0.
func loadForNaming(t *testing.T, libPath string) (*cluster.Result, *cluster.Result, *snapshot.VersionProfile) {
	t.Helper()
	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}
	ef, err := elfx.Open(libPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = ef.Close() }()
	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if info.Version == nil || !info.Version.Supported {
		t.Skipf("unsupported snapshot in %s", libPath)
	}
	data := info.IsolateData.Data
	start, err := cluster.FindClusterDataStart(data)
	if err != nil {
		t.Fatalf("cluster start: %v", err)
	}
	res, err := cluster.ScanClusters(data, start, info.Version, false, opts)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var size int64
	if info.IsolateHeader != nil {
		size = info.IsolateHeader.TotalSize
	}
	if err := cluster.ReadFill(data, res, info.Version, false, size); err != nil {
		t.Fatalf("fill: %v", err)
	}
	var vmRes *cluster.Result
	if vmData := info.VmData.Data; len(vmData) >= 64 && info.VmHeader != nil {
		if vmStart, err := cluster.FindClusterDataStart(vmData); err == nil {
			if r, err := cluster.ScanClusters(vmData, vmStart, info.Version, true, opts); err == nil {
				_ = cluster.ReadFill(vmData, r, info.Version, true, info.VmHeader.TotalSize)
				vmRes = r
			}
		}
	}
	if vmRes == nil {
		t.Fatal("no VM snapshot; every name count below would be misleading")
	}
	return res, vmRes, info.Version
}

// A type-testing stub's owner is the Type it tests, not a Function
// (type_testing_stubs.cc `code.set_owner(type)`, verified at tag 3.9.2), so
// it fails both the CodeIndex cross-reference and the RefToNamed lookup and
// used to render as `sub_<pcOffset>`. On the 3.9.2 ARM64 sample that was 324
// of the 409 remaining unnamed Codes.
func TestTypeTestingStubsAreNamed(t *testing.T) {
	for _, env := range []string{"AOTOPSY_TEST_SAMPLE_ARM64", "AOTOPSY_TEST_SAMPLE_312_X64"} {
		libPath := os.Getenv(env)
		if libPath == "" {
			t.Skipf("%s not set", env)
		}
		t.Run(env, func(t *testing.T) {
			res, vmRes, profile := loadForNaming(t, libPath)
			pl := BuildPoolLookups(res, profile.CIDs, vmRes, profile.CodeIndexOneBased,
				profile.DartVersion, profile.TypeClassIdIsRef)

			var stubs, distinct = 0, map[string]bool{}
			for _, ce := range res.Codes {
				name := pl.CodeNames[ce.RefID].FuncName
				if strings.HasPrefix(name, "TypeTestingStub_") {
					stubs++
					distinct[name] = true
				}
			}
			if stubs < 200 {
				t.Errorf("only %d type-testing stubs named; both 3.x samples have >300", stubs)
			}
			// Collapsing to one class is the specific way this fails --
			// see the 2.12 case below -- so a healthy spread is the check
			// that matters, not the raw count.
			if len(distinct) < stubs/2 {
				t.Errorf("%d stubs but only %d distinct names; the Type->class resolution has collapsed",
					stubs, len(distinct))
			}
			t.Logf("%d type-testing stubs, %d distinct types", stubs, len(distinct))
		})
	}
}

// On versions where Type.type_class_id is its own ref (2.10-2.15) nothing in
// this pipeline resolves it, and the failure is total rather than partial: a
// real Dart 2.12.0 sample resolved 251 of 251 type-owned Codes to a
// real-looking name -- all to the SAME class. 251 confident wrong labels is
// worse than 251 honest `sub_` placeholders, so the feature stays off there.
//
// This pins the gate. If Type->ClassID is ever implemented for 2.x, this test
// fails and the gate can be removed on purpose rather than by accident.
func TestTypeTestingStubNamingIsOffWhereTypesCannotResolve(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_DART212")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_DART212 not set")
	}
	res, vmRes, profile := loadForNaming(t, libPath)
	if !profile.TypeClassIdIsRef {
		t.Fatalf("sample no longer has TypeClassIdIsRef; this test guards the wrong thing now")
	}
	pl := BuildPoolLookups(res, profile.CIDs, vmRes, profile.CodeIndexOneBased,
		profile.DartVersion, profile.TypeClassIdIsRef)
	for _, ce := range res.Codes {
		if strings.HasPrefix(pl.CodeNames[ce.RefID].FuncName, "TypeTestingStub_") {
			t.Fatalf("named a type-testing stub on a version that cannot resolve a Type to its class: %q",
				pl.CodeNames[ce.RefID].FuncName)
		}
	}
}

// buildTypeTestingStubNames must refuse rather than guess, on the same
// principle as the pool-index arithmetic: a wrong label propagates into every
// call site that references the stub.
func TestTypeTestingStubNamesRefuseWhenUnresolvable(t *testing.T) {
	res := &cluster.Result{
		Types: []cluster.TypeInfo{{RefID: 100, ClassID: 4242}},
	}
	pl := &PoolLookups{RefToNamed: map[int]*cluster.NamedObject{}, RefToStr: map[int]string{}}
	if got := buildTypeTestingStubNames(res, pl, nil, false); len(got) != 0 {
		t.Errorf("named an unresolvable class: %v", got)
	}
	// And the version gate wins even when the data would resolve.
	if got := buildTypeTestingStubNames(res, pl, nil, true); got != nil {
		t.Errorf("TypeClassIdIsRef must disable naming entirely, got %v", got)
	}
}
