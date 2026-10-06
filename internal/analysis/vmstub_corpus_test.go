package analysis

import (
	"debug/elf"
	"errors"
	"regexp"
	"sort"
	"strings"
	"testing"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/samplecorpus"
	"aotopsy/internal/vmtables"
)

var (
	// Up to 2.14 the stub slot of the pair is a tagged Code reference (measured:
	// from 2.15 it is a reset entry point, so there is nothing to name).
	stubOracleSample = regexp.MustCompile(`^dart-2\.(10|12|13|14)\.0(-prenn)?-arm64\.so$`)
	stubSymbolSample = regexp.MustCompile(`^dart-2\.1[3-6]\.0-gt-(arm64|x64)\.so$`)
)

// On 2.10.0..2.14.0 the stub slot of a switchable-call pair is a tagged Code
// reference to a VM stub, and WHICH stub is known from the call itself: the
// slot paired with an UnlinkedCall is StubCode::SwitchableCallMiss, the one
// paired with a MegamorphicCache is StubCode::MegamorphicCall
// (EmitInstanceCallAOT / EmitMegamorphicInstanceCall). The pool display of that
// slot must say so. (Before the fix it printed `Subtype5TestCache` /
// `TopTypeTypeTest` on 2.12.0: the Code cluster is in image order, the name
// table was applied in emission order.)
func TestVMStubPairSlotsAreNamedByTheirStub(t *testing.T) {
	checked := 0
	for _, name := range samplecorpus.ExpectedFiles() {
		if !stubOracleSample.MatchString(name) {
			continue
		}
		path, err := samplecorpus.RequireSample(name)
		if errors.Is(err, samplecorpus.ErrNoCorpus) {
			t.Skip("no sample corpus")
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sc, err := LoadSnapshot(path, dartfmt.Options{Mode: dartfmt.ModeBestEffort})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if sc.VMResult == nil {
			_ = sc.Close()
			continue
		}
		vmCode := map[int]bool{}
		for _, c := range sc.VMResult.Codes {
			vmCode[c.RefID] = true
		}
		poolByIndex := map[int]int{} // tagged pool index -> ref
		for _, pe := range sc.Result.Pool {
			if pe.Kind == 0 {
				poolByIndex[pe.Index] = pe.RefID
			}
		}
		kind := map[int]bool{} // call-site ref -> megamorphic
		for _, c := range sc.Result.CallSites {
			kind[c.RefID] = c.Megamorphic
		}
		for _, pe := range sc.Result.Pool {
			mega, ok := kind[pe.RefID]
			if !ok {
				continue
			}
			// The pair is {call site, stub} up to 3.9.2. Later versions reset the
			// stub slot to an entry point instead of a Code reference.
			ref, tagged := poolByIndex[pe.Index+1]
			if !tagged || !vmCode[ref] {
				continue
			}
			stub := sc.PoolDisplay[pe.Index+1]
			want := "SwitchableCallMiss"
			if mega {
				want = "MegamorphicCall"
			}
			checked++
			if stub != want {
				t.Fatalf("%s: stub slot %d of a %s pair displays %q, want %q", name, pe.Index+1,
					map[bool]string{false: "UnlinkedCall", true: "MegamorphicCache"}[mega], stub, want)
			}
		}
		_ = sc.Close()
	}
	if checked == 0 {
		t.Skip("no tagged-stub pair slots in the registered samples")
	}
}

// Ground truth: the `-gt-` builds keep their symbol table, and the VM stubs are
// `Precompiled_Stub_<Name>` FUNC symbols. In ascending address order they must be
// vmtables.VMStubNamesInImageOrder (UnknownDartCode has no symbol; isolate-only
// stubs such as AllocateClosure are not in the VM list and are skipped).
func TestVMStubOrderMatchesSymbolTable(t *testing.T) {
	ran := 0
	for _, name := range samplecorpus.ExpectedFiles() {
		if !stubSymbolSample.MatchString(name) {
			continue
		}
		path, err := samplecorpus.RequireSample(name)
		if errors.Is(err, samplecorpus.ErrNoCorpus) {
			t.Skip("no sample corpus")
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		version := strings.TrimPrefix(strings.SplitN(name, "-gt-", 2)[0], "dart-")
		f, err := elf.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		syms, err := f.Symbols()
		_ = f.Close()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		type sym struct {
			addr uint64
			name string
		}
		var stubs []sym
		for _, s := range syms {
			if elf.ST_TYPE(s.Info) == elf.STT_FUNC && strings.HasPrefix(s.Name, "Precompiled_Stub_") {
				stubs = append(stubs, sym{s.Value, strings.TrimPrefix(s.Name, "Precompiled_Stub_")})
			}
		}
		sort.Slice(stubs, func(i, j int) bool { return stubs[i].addr < stubs[j].addr })
		table := vmtables.VMStubNamesInImageOrder(version)
		inTable := map[string]bool{}
		for _, n := range table {
			inTable[n] = true
		}
		var got []string
		for _, s := range stubs {
			if inTable[s.name] {
				got = append(got, s.name)
			}
		}
		var want []string
		have := map[string]bool{}
		for _, s := range stubs {
			have[s.name] = true
		}
		for _, n := range table {
			if have[n] {
				want = append(want, n)
			}
		}
		if len(got) < len(table)-2 {
			t.Fatalf("%s: only %d of %d table names have a symbol", name, len(got), len(table))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%s: ascending stub symbols diverge from VMStubNamesInImageOrder at %d: symbol=%q table=%q",
					name, i, got[i], want[i])
			}
		}
		ran++
	}
	if ran == 0 {
		t.Skip("no -gt- samples registered")
	}
}
