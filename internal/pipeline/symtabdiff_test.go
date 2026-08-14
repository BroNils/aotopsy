package pipeline

import (
	"os"
	"strings"
	"testing"

	"aotopsy/internal/elfx"
)

func TestNormalizeRecoveredName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Duration.compareTo_80", "Duration.compareTo"},
		{"Duration.dyn:*_210", "Duration.*"},
		{"FocusManager.get:instance_5bc", "FocusManager.instance"},
		{"FocusManager.set:instance_5bc", "FocusManager.instance"},
		{"_ViewState@141024595.didChangeViewFocus_3c0", "_ViewState.didChangeViewFocus"},
		{"new _GrowableList@0150898.of_1d8", "new _GrowableList.of"},
		// An unnamed constructor's Function name ends in a bare dot.
		{"new _GrowableList@0150898._1960", "new _GrowableList"},
		// A bare top-level function has no owner part.
		{"main_1a2b", "main"},
		{"dyn:main_1a2b", "main"},
		// Nothing to strip.
		{"Duration.compareTo", "Duration.compareTo"},
	}
	for _, c := range cases {
		if got := NormalizeRecoveredName(c.in); got != c.want {
			t.Errorf("NormalizeRecoveredName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeSymbolName(t *testing.T) {
	cases := []struct{ in, want string }{
		// We name VM stubs bare, so the ELF's `stub ` prefix is folded away.
		{"stub CheckIsolateFieldAccess", "CheckIsolateFieldAccess"},
		// The ELF's phrasing for a type-testing stub is our name said
		// differently -- confirmed by both naming the same addresses.
		{"assert type is HitTestTarget", "TypeTestingStub_HitTestTarget"},
		{"new Duration", "new_Duration"},
		{"_ViewState@141024595.didChangeViewFocus", "_ViewState.didChangeViewFocus"},
		{"  Duration.compareTo  ", "Duration.compareTo"},
	}
	for _, c := range cases {
		if got := NormalizeSymbolName(c.in); got != c.want {
			t.Errorf("NormalizeSymbolName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A stripped build must be a no-op, not a failure: that is the normal
// production case and most of this project's corpus.
func TestCompareNamesToSymbolsOnStrippedBuild(t *testing.T) {
	c := CompareNamesToSymbols(map[uint64]string{0x1000: "Foo.bar_10"}, nil)
	if c.Compared != 0 || len(c.Disagreement) != 0 {
		t.Errorf("stripped build should compare nothing, got %+v", c)
	}
	if c.AgreementRate() != 1 {
		t.Errorf("AgreementRate on an empty comparison = %v, want 1", c.AgreementRate())
	}
}

func TestCompareNamesToSymbolsCountsBothSides(t *testing.T) {
	recovered := map[uint64]string{
		0x1000: "Duration.compareTo_80", // agrees after normalisation
		0x2000: "Duration.dyn:*_210",    // agrees after normalisation
		0x3000: "Foo.wrong_30",          // disagrees
		0x4000: "OnlyOurs.thing_40",     // no symbol at this VA
	}
	symbols := map[uint64]string{
		0x1000: "Duration.compareTo",
		0x2000: "Duration.*",
		0x3000: "Foo.right",
		0x5000: "OnlySymbols.thing",
	}
	c := CompareNamesToSymbols(recovered, symbols)
	if c.Compared != 3 || c.Agree != 2 {
		t.Errorf("Compared=%d Agree=%d, want 3 and 2", c.Compared, c.Agree)
	}
	if c.OnlyOurs != 1 || c.OnlySymbols != 1 {
		t.Errorf("OnlyOurs=%d OnlySymbols=%d, want 1 and 1", c.OnlyOurs, c.OnlySymbols)
	}
	if len(c.Disagreement) != 1 || c.Disagreement[0].VA != 0x3000 {
		t.Errorf("disagreements = %+v, want just 0x3000", c.Disagreement)
	}
}

// TestRecoveredNamesAgreeWithSymbolTable is the differential gate.
//
// Golden files compare a hash of what this pipeline produced last time, so
// they detect change but cannot detect wrongness. On a build that kept a
// `.symtab` the linker already recorded every function's real Dart name, and
// that is ground truth from outside the project.
//
//	AOTOPSY_VALIDATE_SYMTAB=/path/to/libapp.so[,another.so] \
//	  go test ./internal/pipeline/ -run RecoveredNamesAgreeWithSymbolTable -v
//
// Opt-in because it needs a symbol-bearing sample, which most real builds are
// not. The floor is deliberately a floor and not an exact figure: names
// legitimately improve, and a gate that fails on improvement gets disabled.
//
// Measured 59.5% on Dart 3.12.2, both architectures. That is not a target to
// drive to 100%: most of the remainder is the two sides describing the same
// function differently, and in several of those OUR name carries more:
//
//	ours _GrowableList.addAll        elf List.addAll
//	     the implementation          the interface
//	ours TypeTestingStub_Iterable    elf assert type is Iterable<X0>
//	                                 elf keeps type arguments and nullability
//	ours _MixinApplication164&...    elf DirectionalFocusTraversalPolicyMixin
//	     the mixin application       the mixin
//
// What IS a real gap and shows up here: `Duration_1d8` against
// `new Duration`, one of the ~925 constructors whose Function is absent from
// the isolate's Named set. The gate is how that gets counted.
func TestRecoveredNamesAgreeWithSymbolTable(t *testing.T) {
	list := os.Getenv("AOTOPSY_VALIDATE_SYMTAB")
	if list == "" {
		t.Skip("AOTOPSY_VALIDATE_SYMTAB not set")
	}
	// Below the measured 59.5%, with room for legitimate movement. Raise it
	// when the constructor gap closes; do not raise it to whatever today's
	// number happens to be.
	const floor = 0.55

	for _, path := range strings.Split(list, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		t.Run(path, func(t *testing.T) {
			ef, err := elfx.Open(path)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			symbols := ef.FuncSymbols()
			_ = ef.Close()
			if len(symbols) == 0 {
				t.Skipf("%s is stripped: no .symtab to compare against", path)
			}

			ctx, err := LoadContext(path)
			if err != nil {
				t.Fatalf("load context: %v", err)
			}
			defer func() { _ = ctx.Close() }()

			c := CompareNamesToSymbols(ctx.SymbolNames, symbols)
			t.Logf("%d compared, %d agree (%.1f%%), %d disagree, %d ours-only, %d symbols-only",
				c.Compared, c.Agree, 100*c.AgreementRate(), len(c.Disagreement), c.OnlyOurs, c.OnlySymbols)
			for i, d := range c.Disagreement {
				if i >= 15 {
					t.Logf("... and %d more", len(c.Disagreement)-15)
					break
				}
				t.Logf("  0x%x ours=%q elf=%q", d.VA, d.Ours, d.ELF)
			}
			if c.AgreementRate() < floor {
				t.Errorf("agreement %.1f%% is below the %.0f%% floor -- the naming layer regressed "+
					"against ground truth, not just against its own last output",
					100*c.AgreementRate(), 100*floor)
			}
		})
	}
}
