package analysis

import (
	"errors"
	"regexp"
	"testing"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/samplecorpus"
)

var hierarchySample = regexp.MustCompile(`^dart-\d+\.\d+\.\d+(-prenn)?-arm64\.so$`)

func TestClassHierarchyOnCorpus(t *testing.T) {
	ran := 0
	for _, name := range samplecorpus.ExpectedFiles() {
		if !hierarchySample.MatchString(name) {
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
		h := cluster.NewClassHierarchy(sc.Result, sc.VMResult)
		cidByName := map[string]int{}
		classes := sc.Result.Classes
		if sc.VMResult != nil {
			classes = append(append([]cluster.ClassInfo{}, sc.VMResult.Classes...), classes...)
		}
		abstract, withIfaces, edges := 0, 0, 0
		for _, c := range classes {
			s, ok := sc.Pool.StringForRef(c.NameRefID)
			if !ok {
				s, ok = sc.Pool.VmRefToStr[c.NameRefID] // core classes live in the VM snapshot
			}
			if ok {
				s = reLibMangle.ReplaceAllString(s, "") // `_Smi@0150898` -> `_Smi`
				if _, dup := cidByName[s]; !dup {
					cidByName[s] = int(c.ClassID)
				}
			}
			if c.IsAbstract() {
				abstract++
			}
			if c.InterfacesRefID > cluster.RefNull {
				withIfaces++
			}
		}
		for _, p := range h.Parents {
			edges += len(p)
		}
		t.Logf("%-32s classes=%d abstract=%d withInterfaceArray=%d edges=%d unresolved=%d", name, len(classes), abstract, withIfaces, edges, h.Unresolved)
		if h.Unresolved != 0 {
			t.Errorf("%s: %d super/interface type refs did not resolve to a class", name, h.Unresolved)
		}
		missing := 0
		// Facts of the Dart core library (sdk/lib), true in every supported version.
		for _, f := range []struct{ sub, super string }{
			{"_OneByteString", "String"},  // String is implemented through _StringBase
			{"String", "Comparable"},      // abstract final class String implements Comparable<String>, Pattern
			{"_GrowableList", "List"},     // class _GrowableList<T> extends ListBase<T>; ListBase implements List
			{"_GrowableList", "Iterable"}, // List extends Iterable (via implements chain)
			{"_Double", "num"},            // class _Double extends double; double extends num
			{"_Smi", "num"},
		} {
			sub, ok1 := cidByName[f.sub]
			super, ok2 := cidByName[f.super]
			if !ok1 || !ok2 {
				missing++
				continue
			}
			if !h.IsSubclassOrImplementor(sub, super) {
				t.Errorf("%s: %s is not a subtype of %s in the captured hierarchy", name, f.sub, f.super)
			}
		}
		for abstractName, want := range map[string]bool{"List": true, "Iterable": true, "_GrowableList": false, "_OneByteString": false} {
			if cid, ok := cidByName[abstractName]; ok && h.Abstract[cid] != want {
				t.Errorf("%s: %s abstract=%v, want %v", name, abstractName, h.Abstract[cid], want)
			}
		}
		if missing > 1 {
			t.Errorf("%s: %d of the 6 core subtype facts could not be looked up by name (assertions would be vacuous)", name, missing)
		}
		_ = sc.Close()
		ran++
	}
	if ran == 0 {
		t.Skip("no arm64 samples registered")
	}
}
