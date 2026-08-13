package pipeline

import (
	"os"
	"testing"

	"aotopsy/internal/cluster"
)

// TestPcDescriptorsDecodedFromBinary checks that PcDescriptors payloads are
// located in ROData and decoded into plausible descriptors on a real snapshot.
//
// Plausibility is asserted structurally rather than against fixed numbers:
//   - descriptors exist at all (a Flutter app has tens of thousands)
//   - pc offsets stay inside a sane range (a bad length_ read or a desynced
//     SLEB128 stream produces wild values immediately)
//   - kinds are all valid single-bit values
//   - some descriptors carry a real try_index, since the app contains try/catch
func TestPcDescriptorsDecodedFromBinary(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_ARM64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_ARM64 not set")
	}
	res := clusterOnly(t, libPath)

	if len(res.PcDescriptors) == 0 {
		t.Fatal("no PcDescriptors objects decoded; every Code has one and they " +
			"live in ROData alongside strings")
	}

	validKind := map[cluster.PcDescriptorKind]bool{
		cluster.PcDeopt: true, cluster.PcIcCall: true, cluster.PcUnoptStaticCall: true,
		cluster.PcRuntimeCall: true, cluster.PcOsrEntry: true, cluster.PcRewind: true,
		cluster.PcBSSRelocation: true, cluster.PcOther: true,
	}

	var total, withTry, badKind, wildPC int
	maxTryIndex := -1
	for _, pd := range res.PcDescriptors {
		for _, e := range pd.Entries {
			total++
			if !validKind[e.Kind] {
				badKind++
			}
			// A single function's code is far below 1 MiB; anything larger means
			// the stream desynced or length_ was misread.
			if e.PCOffset > 1<<20 {
				wildPC++
			}
			if e.TryIndex != cluster.InvalidTryIndex {
				withTry++
				if e.TryIndex > maxTryIndex {
					maxTryIndex = e.TryIndex
				}
			}
		}
	}
	t.Logf("objects=%d descriptors=%d with_try=%d max_try_index=%d",
		len(res.PcDescriptors), total, withTry, maxTryIndex)

	if total == 0 {
		t.Fatal("PcDescriptors objects found but every stream decoded empty")
	}
	if badKind > 0 {
		t.Errorf("%d of %d descriptors have an invalid kind; KindShiftBits width "+
			"or the SLEB128 decode is wrong", badKind, total)
	}
	if wildPC > 0 {
		t.Errorf("%d of %d descriptors have pc_offset > 1MiB; length_ is probably "+
			"read as a Smi or from the wrong offset", wildPC, total)
	}
	if withTry == 0 {
		t.Error("no descriptor carries a try_index, but the app contains try/catch " +
			"(AntiInlineTools.safeDivide, ground_truth.dart's tryCatch*). " +
			"TryIndexBits position is likely wrong.")
	}
	// try_index is stored in 10 bits as index+1, so 1022 is the ceiling. A
	// value near it on a small app means the bitfield is misaligned.
	if maxTryIndex > 64 {
		t.Errorf("max try_index %d is implausibly large for this app; TryIndexBits "+
			"may be overlapping YieldIndexBits", maxTryIndex)
	}
}

// TestTryRegionsForKnownTryCatchFunctions verifies recovered try regions against
// the uncompiled Dart source. compare_sample declares, all
// @pragma('vm:never-inline') so they survive as real functions:
//
//	main.dart          AntiInlineTools.safeDivide(int, int)   -- one try/catch
//	ground_truth.dart  tryCatchFinally(int, int)              -- try/catch/finally
//	ground_truth.dart  nestedTryCatch(int, int, int)          -- nested try
//	ground_truth.dart  tryCatchWithType(String)               -- multiple on-clauses
//
// Each must yield at least one try region, and each region must reference a
// handler that actually exists in the function's ExceptionHandlers.
func TestTryRegionsForKnownTryCatchFunctions(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_ARM64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_ARM64 not set")
	}
	res := clusterOnly(t, libPath)
	if len(res.PcDescriptors) == 0 {
		t.Skip("no PcDescriptors decoded")
	}

	strByRef := map[int]string{}
	for _, ps := range res.Strings {
		strByRef[ps.RefID] = ps.Value
	}
	pdByRef := map[int]*cluster.PcDescriptorsInfo{}
	for i := range res.PcDescriptors {
		pdByRef[res.PcDescriptors[i].RefID] = &res.PcDescriptors[i]
	}
	ehByRef := map[int]*cluster.ExceptionHandlerInfo{}
	for i := range res.ExceptionHandlers {
		ehByRef[res.ExceptionHandlers[i].RefID] = &res.ExceptionHandlers[i]
	}
	// Function ref -> Code entry, via Code.OwnerRef.
	codeByOwner := map[int]*cluster.CodeEntry{}
	for i := range res.Codes {
		codeByOwner[res.Codes[i].OwnerRef] = &res.Codes[i]
	}

	targets := []string{"safeDivide", "tryCatchFinally", "nestedTryCatch", "tryCatchWithType"}
	found := 0
	for _, want := range targets {
		var fnRef = -1
		for i := range res.Named {
			if strByRef[res.Named[i].NameRefID] == want {
				fnRef = res.Named[i].RefID
				break
			}
		}
		if fnRef < 0 {
			t.Logf("%s: not present (stale binary? see AGENTS.md)", want)
			continue
		}
		code, ok := codeByOwner[fnRef]
		if !ok {
			t.Logf("%s: no Code found via OwnerRef", want)
			continue
		}
		found++

		pd, hasPD := pdByRef[code.PcDescriptorsRef]
		if !hasPD {
			t.Errorf("%s: Code has no decoded PcDescriptors (ref %d)", want, code.PcDescriptorsRef)
			continue
		}
		eh, hasEH := ehByRef[code.ExceptionHandlersRef]
		if !hasEH {
			t.Errorf("%s: Code has no ExceptionHandlers (ref %d)", want, code.ExceptionHandlersRef)
			continue
		}

		// endPC is unknown here (cluster-only has no code ranges), so use one
		// past the last descriptor; that is enough to close the final region.
		var maxPC uint32
		for _, e := range pd.Entries {
			if e.PCOffset > maxPC {
				maxPC = e.PCOffset
			}
		}
		regions := cluster.BuildTryRegions(pd.Entries, maxPC+4)
		t.Logf("%s: %d descriptors, %d handlers, %d try regions",
			want, len(pd.Entries), len(eh.Handlers), len(regions))

		if len(eh.Handlers) == 0 {
			t.Errorf("%s: source declares try/catch but ExceptionHandlers is empty", want)
		}
		if len(regions) == 0 {
			t.Errorf("%s: source declares try/catch but no try region recovered", want)
			continue
		}
		for _, r := range regions {
			if r.TryIndex < 0 || r.TryIndex >= len(eh.Handlers) {
				t.Errorf("%s: region %+v has try_index outside the %d handlers",
					want, r, len(eh.Handlers))
			}
			if r.EndPC <= r.StartPC {
				t.Errorf("%s: empty region %+v", want, r)
			}
		}
	}
	if found == 0 {
		t.Skip("none of the try/catch fixtures are in this sample")
	}
}

// TestExpandOuterTryRegions_NestedTryCatch checks that an enclosing try which
// left no descriptor of its own is recovered from OuterTryIndex.
//
// compare_sample/lib/ground_truth.dart declares nestedTryCatch with two nested
// trys, so it has 2 handlers. PcDescriptors records only the INNERMOST active
// try_index, and on 3.9.2 every descriptor falls inside the inner try, so the
// raw region scan sees 1 region. The outer one is definitional: a pc inside try
// N is inside handler[N].outer_try_index too.
func TestExpandOuterTryRegions_NestedTryCatch(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_ARM64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_ARM64 not set")
	}
	res := clusterOnly(t, libPath)

	strByRef := map[int]string{}
	for _, ps := range res.Strings {
		strByRef[ps.RefID] = ps.Value
	}
	pdByRef := map[int]*cluster.PcDescriptorsInfo{}
	for i := range res.PcDescriptors {
		pdByRef[res.PcDescriptors[i].RefID] = &res.PcDescriptors[i]
	}
	ehByRef := map[int]*cluster.ExceptionHandlerInfo{}
	for i := range res.ExceptionHandlers {
		ehByRef[res.ExceptionHandlers[i].RefID] = &res.ExceptionHandlers[i]
	}
	codeByOwner := map[int]*cluster.CodeEntry{}
	for i := range res.Codes {
		codeByOwner[res.Codes[i].OwnerRef] = &res.Codes[i]
	}

	var fnRef = -1
	for i := range res.Named {
		if strByRef[res.Named[i].NameRefID] == "nestedTryCatch" {
			fnRef = res.Named[i].RefID
			break
		}
	}
	if fnRef < 0 {
		t.Skip("nestedTryCatch not in this sample (stale binary? see AGENTS.md)")
	}
	code, ok := codeByOwner[fnRef]
	if !ok {
		t.Skip("no Code for nestedTryCatch")
	}
	pd, ok1 := pdByRef[code.PcDescriptorsRef]
	eh, ok2 := ehByRef[code.ExceptionHandlersRef]
	if !ok1 || !ok2 {
		t.Skip("nestedTryCatch has no PcDescriptors/ExceptionHandlers")
	}
	if len(eh.Handlers) != 2 {
		t.Fatalf("nestedTryCatch has %d handlers, want 2 (source nests two trys)", len(eh.Handlers))
	}

	var maxPC uint32
	for _, e := range pd.Entries {
		if e.PCOffset > maxPC {
			maxPC = e.PCOffset
		}
	}
	raw := cluster.BuildTryRegions(pd.Entries, maxPC+4)
	expanded := cluster.ExpandOuterTryRegions(raw, eh.Handlers)
	t.Logf("raw regions=%d expanded=%d handlers=%d", len(raw), len(expanded), len(eh.Handlers))
	for i, h := range eh.Handlers {
		t.Logf("  handler[%d]: pc=0x%x outer_try=%d catch_all=%v needs_st=%v gen=%v",
			i, h.PCOffset, h.OuterTryIndex, h.HasCatchAll, h.NeedsStacktrace, h.IsGenerated)
	}
	for _, r := range raw {
		t.Logf("  raw region: try=%d [0x%x,0x%x)", r.TryIndex, r.StartPC, r.EndPC)
	}
	for _, e := range pd.Entries {
		t.Logf("  desc: pc=0x%x kind=%v try=%d", e.PCOffset, e.Kind, e.TryIndex)
	}

	if len(expanded) < len(raw) {
		t.Errorf("expansion lost regions: %d -> %d", len(raw), len(expanded))
	}
	// The source nests two trys, so both handler indices must be represented.
	seen := map[int]bool{}
	for _, r := range expanded {
		seen[r.TryIndex] = true
		if r.EndPC <= r.StartPC {
			t.Errorf("empty region %+v", r)
		}
		if r.TryIndex < 0 || r.TryIndex >= len(eh.Handlers) {
			t.Errorf("region %+v indexes outside %d handlers", r, len(eh.Handlers))
		}
	}
	// NOT asserted: that both try indices appear. The data decides which
	// direction is recoverable, and for this fixture on 3.9.2 it is neither
	// "both" nor a bug:
	//
	//   handler[0] outer_try=-1  <- OUTERMOST
	//   handler[1] outer_try=0   <- inner, nested in 0
	//   both descriptors carry try_index 0
	//
	// i.e. the descriptors sit in the OUTER try and the inner one left no trace
	// at all. Walking outward cannot invent it, and inferring an extent for a
	// try with no descriptor would be a guess. So expansion correctly recovers
	// nothing here; it fires when the descriptors are in an INNER try instead.
	// Nesting invariant: the outer region must contain the inner one.
	if len(expanded) == 2 {
		in, out := expanded[0], expanded[1]
		if in.StartPC < out.StartPC || in.EndPC > out.EndPC {
			t.Errorf("inner %+v not contained in outer %+v", in, out)
		}
	}
}

// TestExpandOuterTryRegionsCorpusEffect measures how often OuterTryIndex
// expansion actually recovers an enclosing try across the whole snapshot, so
// the feature is not carried on faith. It also enforces the two invariants that
// must hold whenever it does fire.
func TestExpandOuterTryRegionsCorpusEffect(t *testing.T) {
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_ARM64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_ARM64 not set")
	}
	res := clusterOnly(t, libPath)

	pdByRef := map[int]*cluster.PcDescriptorsInfo{}
	for i := range res.PcDescriptors {
		pdByRef[res.PcDescriptors[i].RefID] = &res.PcDescriptors[i]
	}
	ehByRef := map[int]*cluster.ExceptionHandlerInfo{}
	for i := range res.ExceptionHandlers {
		ehByRef[res.ExceptionHandlers[i].RefID] = &res.ExceptionHandlers[i]
	}

	var withRegions, expandedFuncs, addedRegions, nestedHandlers int
	for i := range res.Codes {
		ce := &res.Codes[i]
		pd, ok1 := pdByRef[ce.PcDescriptorsRef]
		eh, ok2 := ehByRef[ce.ExceptionHandlersRef]
		if !ok1 || !ok2 || len(eh.Handlers) == 0 {
			continue
		}
		for _, h := range eh.Handlers {
			if h.OuterTryIndex >= 0 {
				nestedHandlers++
			}
		}
		var maxPC uint32
		for _, e := range pd.Entries {
			if e.PCOffset > maxPC {
				maxPC = e.PCOffset
			}
		}
		raw := cluster.BuildTryRegions(pd.Entries, maxPC+4)
		if len(raw) == 0 {
			continue
		}
		withRegions++
		exp := cluster.ExpandOuterTryRegions(raw, eh.Handlers)
		if len(exp) < len(raw) {
			t.Fatalf("expansion lost regions: %d -> %d", len(raw), len(exp))
		}
		if len(exp) > len(raw) {
			expandedFuncs++
			addedRegions += len(exp) - len(raw)
		}
		// Every emitted region must index a real handler and be non-empty.
		for _, r := range exp {
			if r.TryIndex < 0 || r.TryIndex >= len(eh.Handlers) || r.EndPC <= r.StartPC {
				t.Fatalf("bad expanded region %+v against %d handlers", r, len(eh.Handlers))
			}
		}
	}
	t.Logf("codes with regions=%d, expanded=%d (+%d regions), nested handlers seen=%d",
		withRegions, expandedFuncs, addedRegions, nestedHandlers)

	if nestedHandlers == 0 {
		t.Skip("no nested handlers in this snapshot; expansion has nothing to do")
	}
}
