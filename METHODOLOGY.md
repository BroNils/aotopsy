# Methodology — How AOTopsy Measures Itself

AOTopsy's accuracy claims are **measured against external ground truth, not
asserted**. This document defines every metric, how it is computed, and how to
reproduce it, so the method — not just the numbers — can be audited.

## Governing principle (§2, anti-fabrication)

The tool never reports a guessed name, type, or call target as fact. When a value
is not recoverable it is emitted honestly (`indirectCall`, `dynamicCall`,
`<unknown>`, `dynamic`, `stub_…`, `sub_…`). A metric that rewarded plausible-but-
wrong output would defeat the purpose, so the metrics below are built to punish
guessing, not honesty.

## Ground truth

The external oracle is each build's own ELF **`.symtab`**. Unstripped Dart builds
carry a symbol table mapping virtual address → original function name. AOTopsy
recovers names from the snapshot alone (no symbol table); comparing the two, by
virtual address, is a true differential against an independent source.

Production Flutter builds are stripped and carry no `.symtab` — those samples
*skip* the name comparison (there is nothing to compare against), so the accuracy
numbers come only from builds where an independent ground truth exists.

## Metrics

### 1. Name-recovery agreement — `BENCHMARK.md`
- **Computed by:** `CompareNamesToSymbols(recovered, elfSyms)` in
  `TestSymtabDifferential`; scored by `AgreementRate()`.
- **Honest denominator:** `stub_` / `sub_` / `SharedStub` outputs are *"we don't
  know"* markers, not name claims, and are **excluded** from the comparison.
  Counting them as disagreements would punish honesty; counting them as agreements
  would reward guessing. Both are wrong, so they are removed.
- **Gate floor:** 0.81 (`minAgreementRate`). Current: 90.2% overall across 44
  ground-truth builds, 81.3% worst band, up to Dart 3.13.0 (92.8%).
- **Reproduce:** `make bench`.

### 2. Decompiler syntactic validity
- **Computed by:** `decompiler.ValidateSource(src)` (a violation list; empty =
  valid Dart) over emitted pseudocode.
- **Gate:** `TestDecompileQualityCorpus` (F1), floor 0.95 on a golden subset.
- **Property:** `TestDecompilerOutputInvariants` sweeps thousands of functions
  per sample on both architectures. Current: 100% valid.
- **Cross-checked against the real frontend:** the `export-dart` output is run
  through the actual Dart analyzer (`dart analyze`). `ValidateSource` is a fast
  Go-side approximation; the analyzer is the authority. This cross-check drove the
  declaration-name / stack-slot / placeholder fixes so recovered Dart parses (only
  abstracted-body `undefined_identifier`s remain — the reconstruction floor).

### 3. Fabrication rate
- **Definition:** any output that invents information the binary does not contain
  — a synthesized lambda body (`(item) => …` where no closure body was recovered),
  or an `<Array>` placeholder rewritten to a concrete `[]`.
- **Computed by:** exact marker detection in F1 and in the invariant property
  sweep. **Required value: 0.** Measured 0 across the full sweep.

### 4. Structural invariants
- Balanced braces per emitted function (checked over the full sweep; the class of
  bug the SSA phi / dead-code fixes protect). Required: every function balanced.

### 5. Format coverage — `COVERAGE.md`
- **Computed by:** `TestCoverageCensus` parses every corpus sample present locally,
  end-to-end (ELF → snapshot → cluster alloc+fill → instructions → disasm). A
  format AOTopsy did not model would raise `unknown CID` and fail.
- Current: 93 sample builds across 23 Dart versions, both architectures, 0 failures,
  up to Dart 3.13.0. The Dart 3.13 49-cluster set is verified handled against
  `runtime/vm/app_snapshot.cc@3.13.2`.
- **Reproduce:** `make coverage`.

### 6. Emitter reachability — `TestDecompileCorpus`
- **Computed by:** every registered sample is run through the emitter and its
  average CFG coverage measured (`VerifyCFG`: blocks emitted / blocks in the
  lifted CFG). Below 95% fails.
- Current: 93/93 samples, Dart 2.10.0–3.13.0 on both architectures, all at
  99.9%–100%.
- **Why it exists:** the golden gate covers pipeline *artifacts*, and pseudocode
  is not one of them — it is written only under `--decompile`. The emitter
  therefore had no corpus-wide coverage at all, and six samples could crash the
  decompiler outright with the whole suite green. Coverage is the right measure
  here because the failure it catches is silent omission: a block that is in the
  binary and not in the output.

## Gates vs measurement harnesses

**Permanent gates** (must stay green; run in the normal suite / CI):
- `TestSymtabDifferential` — the external ground-truth gate (floor 0.81).
- `TestDecompileQualityCorpus` — Dart validity + fabrication (F1).
- `TestGoldenPipelineOutput`, `TestCrossVersionDifferential`, `funckind_sdk_test.go`,
  `blr_signal_regression_test.go`.
- `TestDecompileCorpus` — emitter reachability over the whole corpus.
- SDK drift gates re-derive each committed VM table from `dart-lang/sdk` at its
  pinned tag: `TestThreadStubOffsetsMatchSDK`, `TestStubNamesMatchSDK`,
  `TestRuntimeEntriesMatchSDK`, `TestThreadFieldNamesMatchSDK`,
  `TestRegisterABIMatchSDK`, and the CID-table gate. What they guard against is
  not a missing name — that renders as an unnamed `THR.fNN` and says so — but a
  *wrong* one: a version aliased to a neighbour's table after the SDK inserted a
  field gets every later offset named after its neighbour, with the confidence of
  a correct answer. Four tables were in that state before the field gate existed.
- `Fuzz*` targets run their seed corpus under normal `go test`.

**Measurement harnesses** (env-gated, not gates; drive the published scoreboards):
- `TestDecompileFidelityCensus` (`AOTOPSY_FIDELITY=1`) — residual-defect census.
- `TestCoverageCensus` (`AOTOPSY_COVERAGE=1`) — `COVERAGE.md`.
- `TestDecompilerOutputInvariants` (`AOTOPSY_PROPERTY=1`) — full-set invariants.
- The `BENCHROW` rows in `TestSymtabDifferential` — `BENCHMARK.md`.

Ground-truth SDK facts (register roles, offsets, cluster layouts) are verified the
same way throughout: Grep MCP to locate, then `gh api repos/dart-lang/sdk/…@<tag>`
to read the exact version — never from memory.

## Limits of this method (honestly)
- Ground-truth twins are real builds we **cannot redistribute**, so the accuracy
  gates run locally, not in public CI (CI validates build, vet, `gofmt`,
  `staticcheck`, shuffled unit tests, a coverage floor, and the fuzz seed corpus
  across the platform matrix). `samples/` is gitignored, so sample-driven tests
  skip there — but only when the corpus is absent entirely; a corpus that is
  present and missing a registered sample fails.
- We do **not** yet measure re-executability (recompile the recovered Dart to AOT
  and diff): recovered output is often abstracted and will not recompile verbatim.
  A twin-scoped recompile-and-diff spike is future work.
- The floors documented in the README's *Limitations & Scope* (AOT-dropped field
  names, polymorphic dispatch) bound what any metric here can reach.
