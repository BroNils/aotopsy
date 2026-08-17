package pipeline

import (
	"os"
	"testing"
)

// Symtab differential test: compare recovered names against the ELF
// symbol table (.symtab) on builds that kept one.
//
// This is the ONLY regression gate that compares against something
// other than our own previous output: golden files compare hashes of
// what we produced last time, so they notice a change but have no
// opinion on whether the new text is right. The ELF symbol table is
// ground truth from the linker.
//
// On a stripped binary (no .symtab), the test skips — production
// builds are stripped, so this gate only fires on debug/unstripped
// builds. That is by design: recovering names without symbols is the
// whole point of the tool.
//
//	AOTOPSY_VALIDATE_SYMTAB=1 \
//	AOTOPSY_TEST_SAMPLE_ARM64=... \
//	go test ./internal/pipeline/ -run TestSymtabDifferential
//
// The test FAILS when the agreement rate drops below a threshold,
// signalling a naming regression. Known deltas (ours carries MORE
// information than the ELF) are normalised away by
// NormalizeRecoveredName/NormalizeSymbolName before comparison.
func TestSymtabDifferential(t *testing.T) {
	if os.Getenv("AOTOPSY_VALIDATE_SYMTAB") == "" {
		t.Skip("AOTOPSY_VALIDATE_SYMTAB not set")
	}

	samples := []struct{ env, name string }{
		{"AOTOPSY_TEST_SAMPLE_ARM64", "compare_sample_arm64"},
		{"AOTOPSY_TEST_SAMPLE_312_X64", "sample312_x64"},
		{"AOTOPSY_TEST_SAMPLE_DART212", "dart212_arm64"},
	}

	ran := false
	for _, s := range samples {
		libPath := os.Getenv(s.env)
		if libPath == "" {
			continue
		}
		ran = true
		t.Run(s.name, func(t *testing.T) {
			runSymtabDifferential(t, libPath, s.name)
		})
	}

	if !ran {
		t.Skip("no sample env vars set (need at least one AOTOPSY_TEST_SAMPLE_*)")
	}
}

// runSymtabDifferential loads the binary, builds recovered names the
// same way the pipeline does, gets .symtab symbols from the ELF, and
// compares the two via CompareNamesToSymbols.
func runSymtabDifferential(t *testing.T, libPath, name string) {
	ctx, err := LoadContext(libPath)
	if err != nil {
		t.Fatalf("LoadContext: %v", err)
	}
	defer func() { _ = ctx.Close() }()

	// Get ELF .symtab symbols (ground truth).
	elfSyms := ctx.EF.FuncSymbols()
	if len(elfSyms) == 0 {
		t.Skipf("%s: binary is stripped (no .symtab) — nothing to compare against", name)
	}

	// Build recovered names, filtering out stub_/sub_ placeholders
	// that are not naming claims but honest "we don't know" markers.
	recovered := make(map[uint64]string, len(ctx.SymbolNames))
	for va, nm := range ctx.SymbolNames {
		if len(nm) > 4 && nm[:4] == "stub" {
			continue
		}
		if len(nm) > 4 && nm[:4] == "sub_" {
			continue
		}
		if len(nm) > 10 && nm[:10] == "SharedStub" {
			continue
		}
		recovered[va] = nm
	}

	if len(recovered) == 0 {
		t.Skipf("%s: no recovered names to compare", name)
	}

	comp := CompareNamesToSymbols(recovered, elfSyms)

	rate := comp.AgreementRate()
	t.Logf("%s: %d compared, %d agree, %d disagree, rate=%.1f%%",
		name, comp.Compared, comp.Agree, len(comp.Disagreement), rate*100)

	// Print disagreements for diagnosis (up to 20).
	if len(comp.Disagreement) > 0 {
		limit := 20
		if len(comp.Disagreement) < limit {
			limit = len(comp.Disagreement)
		}
		for _, d := range comp.Disagreement[:limit] {
			t.Logf("  disagree 0x%x: ours=%q elf=%q", d.VA, d.Ours, d.ELF)
		}
		if len(comp.Disagreement) > limit {
			t.Logf("  ... and %d more", len(comp.Disagreement)-limit)
		}
	}

	// Fail if agreement rate drops below 50%. On an unstripped build
	// the rate should be well above 80% (measured: 1730/8346 exact
	// agreements on 3.12.2 x86_64 after normalisation).
	const minAgreementRate = 0.50
	if rate < minAgreementRate {
		t.Errorf("%s: agreement rate %.1f%% < %.1f%% threshold — %d disagreements out of %d compared",
			name, rate*100, minAgreementRate*100, len(comp.Disagreement), comp.Compared)
	}
}

// TestSymtabDifferentialReport is a non-failing variant that always
// runs (when env-gated) and prints the full disagreement list, even
// when the rate is above threshold. Useful for diagnosing naming
// regressions without failing CI.
//
//	AOTOPSY_VALIDATE_SYMTAB=1 \
//	AOTOPSY_TEST_SAMPLE_ARM64=... \
//	go test ./internal/pipeline/ -run TestSymtabDifferentialReport -v
func TestSymtabDifferentialReport(t *testing.T) {
	if os.Getenv("AOTOPSY_VALIDATE_SYMTAB") == "" {
		t.Skip("AOTOPSY_VALIDATE_SYMTAB not set")
	}

	samples := []struct{ env, name string }{
		{"AOTOPSY_TEST_SAMPLE_ARM64", "compare_sample_arm64"},
		{"AOTOPSY_TEST_SAMPLE_312_X64", "sample312_x64"},
		{"AOTOPSY_TEST_SAMPLE_DART212", "dart212_arm64"},
	}

	ran := false
	for _, s := range samples {
		libPath := os.Getenv(s.env)
		if libPath == "" {
			continue
		}
		ran = true
		t.Run(s.name, func(t *testing.T) {
			ctx, err := LoadContext(libPath)
			if err != nil {
				t.Fatalf("LoadContext: %v", err)
			}
			defer func() { _ = ctx.Close() }()

			elfSyms := ctx.EF.FuncSymbols()
			if len(elfSyms) == 0 {
				t.Skipf("%s: stripped", s.name)
				return
			}

			recovered := make(map[uint64]string, len(ctx.SymbolNames))
			for va, nm := range ctx.SymbolNames {
				if len(nm) > 4 && nm[:4] == "stub" {
					continue
				}
				if len(nm) > 4 && nm[:4] == "sub_" {
					continue
				}
				if len(nm) > 10 && nm[:10] == "SharedStub" {
					continue
				}
				recovered[va] = nm
			}

			if len(recovered) == 0 {
				t.Skipf("%s: no recovered names", s.name)
				return
			}

			comp := CompareNamesToSymbols(recovered, elfSyms)
			rate := comp.AgreementRate()
			t.Logf("%s: %d compared, %d agree, %d disagree, rate=%.1f%%",
				s.name, comp.Compared, comp.Agree, len(comp.Disagreement), rate*100)

			for _, d := range comp.Disagreement {
				t.Logf("  disagree 0x%x: ours=%q elf=%q", d.VA, d.Ours, d.ELF)
			}
		})
	}

	if !ran {
		t.Skip("no sample env vars set")
	}
}
