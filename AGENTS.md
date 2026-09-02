# AGENTS.md — AOTopsy

## ⚠️ MANDATORY: read `AGENTS-local.md` too

If `AGENTS-local.md` exists in the repo root, it MUST be read before working.
It contains local info (sample binary paths, env vars) not documented here.
Sample `libapp.so` and `ground_truth.dart` are not in the repo — they live in
`~/dev/` (see AGENTS-local.md).

That file is **intentionally not in git** (`.gitignore`); its role is like
`.env`: it holds paths and env vars for one machine, which would be wrong on
another. So a fresh clone won't have it — that's normal, not missing.
If it doesn't exist yet, create your own with sample paths and integration
test env vars for your machine.

## ⚠️ Host memory limits — read before running anything heavy

This repo's analysis pipeline is memory-intensive. The specific host RAM,
swap, and `ulimit` values for your machine are in **`AGENTS-local.md`** — read
that file before running any heavy test or pipeline. The universal rules:

- **One heavy thing at a time, in the foreground.** `go test` in this repo
  runs full `Run()` pipelines of its own.
- **Never run the full pipeline on a big real app** (e.g. a 129k-function
  libapp.so). Use the cluster-only harness (`clusterOnly` in
  `internal/analysis/loadingunit_test.go`): ELF → snapshot → alloc → fill,
  skipping disassembly.
- `aotopsy _debug decompile-native --all` on a real app is the single most
  dangerous command here — see its own `--max` help text.

## Build & Test

Do NOT use `./...` — it traverses `runtime_test/` (thousands of non-Go files) causing slow stat and OOM. Use:

```bash
go build ./cmd/... ./internal/... ./tools/...
go test ./cmd/... ./internal/... ./tools/...
```

Build just the binary: `go build -o aotopsy ./cmd/aotopsy/`

## Project Structure

```mermaid
flowchart TD
    CLI_ENTRY[cmd/aotopsy<br/>CLI entry point]
    subgraph "internal/"
        ANALYSIS[analysis<br/>pipeline orchestration & snapshot loader]
        SDK[sdk<br/>Dart VM facts, registers, predicates]
        VMT[vmtables<br/>versioned tables]
        THRAUDIT[thraudit<br/>audit & classification]
        ARM64[arch/arm64<br/>bitmask decoders]
        NAMING[naming<br/>pool lookups & stub resolution]
        ELFX[elfx<br/>ELF validation]
        SNAP[snapshot<br/>version profiles]
        DART[dartfmt<br/>wire encoding]
        CLUST[cluster<br/>snapshot deserialization]
        DISASM[disasm<br/>ARM64 + x86_64 decode]
        CG[callgraph<br/>DOT rendering]
        SIG[signal<br/>behavioral classification]
        REND[render<br/>HTML/DOT/SVG]
        OUT[output<br/>JSONL & SARIF 2.1.0]
        DEC[decompiler<br/>pseudocode]
        TT[typetrack<br/>type inference & receiver recovery]
        FP[fingerprint<br/>version ID]
        FD[funcdiff<br/>function diffing]
        SM[symbolmap<br/>symbol resolution]
        FFI[ffitrace<br/>dart:ffi tracing]
        SX[strxref<br/>string cross-ref]
        SU[strutil<br/>shared utilities & metadata]
        JU[jsonutil<br/>JSONL streams]
        FRIDA[frida<br/>script generator]
        CLI[cli<br/>ANSI colors]
    end
    TOOLS[tools/<br/>THR extractor]
    GHIDRA[ghidra_scripts/<br/>Python]
    IDA[ida_scripts/<br/>Python]

    CLI_ENTRY --> ANALYSIS
    CLI_ENTRY --> DEC
    CLI_ENTRY --> DISASM
    ANALYSIS --> ELFX
    ANALYSIS --> SNAP
    ANALYSIS --> CLUST
    ANALYSIS --> DISASM
    ANALYSIS --> SIG
    ANALYSIS --> TT
    ANALYSIS --> NAMING
    ANALYSIS --> OUT
    CLUST --> SNAP
    DISASM --> DART
    DISASM --> ARM64
    DISASM --> SDK
    DISASM --> VMT
    DEC --> DISASM
    DEC --> SDK
    DEC --> ARM64
    TT --> DISASM
    TT --> CLUST
    TT --> SDK
    TT --> ARM64
    FFI --> ANALYSIS
    FFI --> DEC
    FFI --> NAMING
    SX --> ANALYSIS
    SX --> DEC
    FD --> CLUST
    FD --> NAMING
    SM --> DISASM
    FP --> ELFX
    CG --> DISASM
    REND --> CG
    REND --> SIG
```

- `cmd/aotopsy/` — CLI entry point, command handlers
- `internal/` — library packages (24 packages, see ARCHITECTURE.md)
- `ghidra_scripts/` — Ghidra integration (Python)
- `ida_scripts/` — IDA integration (Python)

## Integration Tests

Sample-driven tests resolve their input from `internal/samplecorpus`, which walks
up from the working directory to a `samples/` directory. Put the binaries there
(symlinks are fine) and they run; there is nothing to set.

This replaced five `AOTOPSY_TEST_SAMPLE_*` environment variables. Nobody sets
five environment variables, so roughly 25 test functions across a dozen files —
including the golden gate — had been skipping silently while `go test
./internal/...` reported ok.

Missing samples are treated two different ways, and the difference matters:

- **No `samples/` directory at all** → skip. `samples/` is gitignored, so a fresh
  clone and every CI runner legitimately has no corpus and nothing to assert
  against.
- **`samples/` present but a registered sample absent** → fail. The corpus has
  drifted from the registry, and that is the state the suite spent months in.

`samplecorpus.Available()` is what separates the two. Collapsing them into one
silent skip is the bug the registry was meant to fix; collapsing them into one
hard failure took 34 tests red on every CI runner.

### ⚠️ A Flutter build tree holds SEVERAL libapp.so — most are stale

A Flutter build tree contains multiple `libapp.so` files with different hashes,
and the `extracted_*` APK outputs are often stale (predate the current source).
**Which paths are stale vs valid on your machine is documented in
`AGENTS-local.md`** — always link `samples/` at `merged_native_libs`, not
`extracted_*`. Before trusting a negative result (`--find X` returning 0
matches), confirm the symbol is in the file: `strings -n 6 libapp.so | grep -x X`.

`internal/samplecorpus` exists because this went wrong once already: fixtures
were named after the app they came from, `samples/` is gitignored, and the names
drifted onto other binaries. A sample now declares its Dart version and
architecture in its file name, and `TestCorpusVersionsMatch` fails if the binary
disagrees with what the name claims.

## Key Conventions

- `commands.go`'s command registry (`primaryCommands`/`debugCommands`) is the source of truth for command dispatch — always check it
- `PoolLookups` (`naming.PoolLookups`) is the central name-resolution surface
- PatchClass hop: `OwnerRefID` may point at a PatchClass (CID 6), not the real Class
- `DetectVersion` returns a copy to prevent data races
- `LiftState.Clone` shares Locals by reference (intentional for cross-branch visibility)

## File Editing Rules

**ALWAYS use the harness file tools (`read`, `edit`, `write`) for modifying files.**

- **NEVER use `sed`, `perl -i`, `awk`, or shell-based text substitution** to edit source files. These are prone to errors with CRLF/LF mismatches, escaping issues, and partial matches. The harness `edit` tool is guarded — it validates `old_string` uniqueness and preserves exact whitespace.
- **NEVER use `python3 -c` with inline `open()/replace()` to edit files** for the same reason. If a bulk change is truly needed, use `write` to rewrite the entire file (after `read`ing it first).
- **NEVER use `python3 << 'PYEOF'` heredoc scripts to edit files** — this caused syntax errors (brace mismatch, CRLF issues, non-unique matches). The edit tool validates uniqueness and preserves exact whitespace. Heredoc python scripts bypass all safety checks.
- Shell commands (`exec`) are for running builds, tests, git, and one-off diagnostics — NOT for file content modification.
- If `edit` fails with "String not found", read the file again to get the exact current content (tabs, spaces, line endings) before retrying. Do NOT fall back to `sed` or python scripts.

**Line endings are LF everywhere**, pinned by `.gitattributes` (`*.go text
eol=lf`). 34 files were previously committed with CRLF, which is why this section
warns about CRLF/LF mismatches — that hazard is now removed at the source, and
`gofmt -w` is safe on any file. Do not reintroduce CRLF: it puts the CI `gofmt`
gate permanently red, which is exactly why that gate could not exist before.

## CI

`.github/workflows/ci.yml` runs, on every push and PR:

- `gofmt -l` over `cmd/ internal/ tools/` — must be empty.
- `staticcheck ./...` — must be clean. Fix findings; do not suppress them. A gate
  whose baseline is a list of exceptions is not a gate.
- `go build`, `go vet`, `go test -shuffle=on` on ubuntu, macos and windows.
- race + coverage, with a floor (currently 18%, measured 20.0% without the
  corpus). Raise it when it is comfortably clear; never lower it to make a red
  build green.

CI has no `samples/`, so sample-driven tests skip there — see Integration Tests
for why "no corpus" and "incomplete corpus" behave differently.

**Why this rule exists (do not work around it):** every harness (Claude Code,
Devin, Codex, etc.) has its own edit/write tool that works like git — it
requires an exact `old_string`, rejects duplicate matches, and fails hard if
the context has changed. That is the safety guard. `sed`/`python replace()`
has no guard at all: if the string appears twice it replaces both, if the
file has changed it still writes, and CRLF/escape silently corrupt.

- This applies to ALL ways of invoking python/sed, including `python3 - <<'PY'`
  that reads a file then `open(...,'w').write(...)`. That form looks clean
  but still writes without verification — forbidden.
- Bulk edit is not an excuse: break into multiple `edit` calls, or `read`
  the whole file then `write` it.
- Python/sed MAY be used for things that do not write source files:
  computing, parsing output, analyzing JSONL/JSON results, writing helper
  scripts in `/tmp`. The boundary is clear — do not touch files inside the repo.
- Formatter (`gofmt -w`) is still allowed: it is a language tool whose job is
  to rewrite files deterministically, not ad-hoc text substitution.

**This has been violated before and it was expensive.** During the decompiler
porting session, `python3 - <<'PY'` was used for dozens of edits. Two of them
**silently did nothing**: `lift.go` and `arm64.go` were CRLF, while the
`replace()` pattern was written with `\n`, so `replace` returned the same
string and the file was rewritten with no change. No error, no warning. The
only sign something was wrong was a feature not firing (`x22` stayed 13600
when it should be 0) — caught only because the number happened to be checked.
The `edit` tool would have failed hard there because `old_string` didn't
match. That is the point.

Rule of thumb: if tempted to write `python3 - <<'PY'` containing
`open(...,'w')`, stop. Use `edit` multiple times, or `read` + `write`.

**And CRLF is not a reason to avoid `edit`.** A later session hesitated to
touch `ir.go`/`lift.go`/`emit.go`/`arm64.go` (all CRLF), then measured:
`edit` inserts a multi-line block (written with `\n`) and the file stays
**436/436 lines CRLF** — the insertion is normalized to match the file. So
the CRLF danger is specific to python/sed, not a property of the file. Note:
`gofmt -l` flags all CRLF files as "not formatted" (`call.go`,
`tryregion_test.go`, etc. have been that way since the start) — that is
baseline noise, not your edit's fault, and **do not** run `gofmt -w` to
"fix" it because it converts the entire file to LF.

## Engineering Philosophy

- **Do not take the easiest path.** If the correct fix requires a large
  refactor or signature change, do it. Example: `transferInstruction`
  signature was changed to pass `prevRaw` — this was key to the UBFX fix.
  "Changing the signature would require many changes" → DO IT ANYWAY.
- **Do not declare a "limitation" you haven't tried.** P7 async detection
  was declared "future work" when the fix (Future.delayed detection) was
  straightforward. Never declare something impossible without first
  attempting it.
- **Do not settle for "approximate" or "good enough"** when a real fix is
  achievable. The kHeapObjectTag off-by-one fix seemed trivial but unlocked
  11550 field hits from 11.
- **Root cause analysis must be deep.** Use gh search + gh api to the SDK
  source to verify every assumption. Do not guess. Example:
  ObjectStoreAOTFieldCount was wrong because it only counted RW fields,
  when there are also CW, FW, LAZY_CORE, LAZY_FFI, etc.
- **"Data limitation" is not the end of research.** If BLR is low, find
  alternative resolution paths (PP-loaded Code, THR stubs, object field
  calls). Do not stop at "dispatch table too small".

### Proven work order: check SDK → count → trace → change

This is not a preference. In this codebase **reading code produces
hypotheses, not findings** — measured on one investigation: four conclusions
from reading code, all four wrong; the answer came from a `println` that
wasn't even firing.

1. **Check data availability in the SDK before planning.** Two major plans
   were canceled before a single line was written, because the field simply
   doesn't exist in a release AOT snapshot: `allocation_stub_` (outside
   `to_snapshot(kFullAOT)`) and `var_descriptors` (`NOT_IN_PRODUCT`). Both
   would have been days wasted if started directly.
2. **Count ALL failure modes before choosing one.** Working example: 1335
   unnamed ranges were split into 910 "owner found, name empty" + 425 "owner
   not found", then measured that 910 of 910 could be resolved via the VM
   string table. The fix became a certainty, not a guess — and the result
   was exactly the predicted number.
3. **Trace with tests that replay the original instructions** before
   changing code. The "CMP kills the register it compares" bug was found
   this way, in one pass, after four rounds of reasoning failed.

### Cross-architecture counters are not necessarily comparable

Before concluding from a number difference, make sure both sides measure
the same population. Three real traps:

- `add_class_hits` 58x lower on x86_64 — **by design**:
  `flow_graph_compiler_x64.cc` folds slot arithmetic into the `CALL`
  addressing mode, while ARM64 emits `AddImmediate` first.
- `header_hits` 3x lower — ARM64 counts typed *and* untyped branches,
  x86 only typed.
- Golden with identical `wc -l` — 93 records inside changed.

A ratio computed from the wrong population also misleads: "70% of
narrowing sites are groundless" turned out to be 4%, because it was
computed from the `CMP` distribution in disassembly, not from sites that
actually fire.

### Do not send changes without measured results

A factually correct change with zero output impact is better canceled than
sent. A correctness fix that removes an unfounded claim is still worth
sending even if output hasn't changed — but **say so honestly** that it
doesn't buy anything.

## Known limits (do not claim solved)

- **Dispatch resolution on Dart 2.x was low** (2.12: 129 single-callee out
  of 5504 BLR, vs 3.9.2: 2378 out of 5354). Three bugs were found and fixed:
  1. `buildPoolClassByIndex` only checked isolate `RefCID`, not VM `VmRefCID`
     — pool entries referencing VM objects (Type, Class) were silently
     dropped. `pool_hits` went from 0 to 172119.
  2. `CalleeExitTypes` was populated once after the fixed-point loop, not
     inside it — BL return value propagation was completely dead. `BL has
     exit type` went from 0 to 834124.
  3. `handleDispatchTableLoad` dropped the `SelectorOnly` flag when
     propagating `KnownDispatchIndex` through `LDR [X21, Xm, LSL #3]`. The
     common 2.x pattern (`SUB X0, X0, #imm → LDR X30, [X21, X0, LSL #3] →
     BLR X30`) set `SelectorOnly=true` at the SUB, but the LDR replaced it
     with `KnownDispatch(selectorOffset)` which has `SelectorOnly=false`.
     `resolveBLR` then tried a direct slot lookup at a negative selector
     offset (always fails) instead of the selector scan fallback. Fix:
     preserve `SelectorOnly` through the LDR. `blr.polymorphic` went from
     41 to 2997, `unresolved` from 5334 to 2378. Total resolved: 3.1% → 56.8%.

  The earlier "chicken-and-egg genuine" conclusion was wrong — the root
  cause was not 2.x stack-based receiver passing, but a type tracker bug.
  2.x does pass the receiver via the stack (`DartCallingConvention` does
  not exist in `constants_arm64.h` at 2.12.0, first appears at 3.4.3),
  but the selector scan fallback does not need the receiver class — it
  scans all dispatch table entries at a given selector offset.
  Seeding `this` from a frame slot was tried and discarded for a different
  reason: the declaring class is not the exact runtime class, while direct
  slot lookup needs the exact one. The selector scan does not have this
  limitation.

## Two gates that must stay green

Both exist because of bugs that slipped through for months: the object pool
index was off by two slots, while the regression test only checked loose
ranges ("50-300 signal", "20000-50000 edge"). The total looked reasonable,
every line was wrong.

### 1. Golden output (`internal/analysis/golden_test.go`)

SHA-256 per output file is compared against records in
`internal/analysis/testdata/golden/`. The key is the input binary's SHA-256,
so pointing at a different `libapp.so` will SKIP (not fail).

```bash
go test ./internal/analysis/ -run Golden                    # verify
AOTOPSY_UPDATE_GOLDEN=1 go test ./internal/analysis/ -run Golden   # re-record
```

If it fails: **do not re-record immediately**. First find what changed;
re-record only after the change is understood and intentional.

Note that this gate compares **content**, not line count. A `B.AL` fix
slipped past a manual "same line count" check but was caught here:
`call_edges.jsonl` stayed 40502 lines while 93 of them got new `via`
annotations. To judge a golden diff, compare per-record (key → value), not
`wc -l`.

`TestGoldenOutputIsDeterministic` runs the pipeline twice and demands
byte-identical output — golden is meaningless if the output itself wobbles.
Any `for k := range someMap` writing to shared state, or `sort.Slice` with
a non-total key, will be caught here.

### 2. SDK drift (`tools/extract_thr.go`)

Thread offset tables and `ObjectStoreAOTFieldCount` cannot be validated by
any local test: a wrong offset produces a plausible-looking annotation
(`THR.allocate_object_stub`) but points at a different field. The only
truth is the SDK header that generated it.

```bash
go run tools/extract_thr.go -check              # THR tables vs SDK
go run tools/extract_thr.go -check-objectstore  # ObjectStore field count vs SDK
go run tools/extract_thr.go -write              # rewrite tables from SDK
AOTOPSY_TEST_SDK=1 go test ./internal/disasm/ -run MatchSDK   # both, as a test
```

THR tables in `internal/disasm/thrfields*.go` are generated code: change
via `-write`, do not hand-edit. Fields the SDK genuinely doesn't export
(`empty_array`, `dynamic_type`, etc. — see `handDerivedFields`) are listed
explicitly in the tool, not silently tolerated.

## Source of Truth: SDK Verification

Two-step technique for verifying against Dart SDK source:

1. **Grep MCP (`searchGitHub` by Vercel)**: Fast literal/regex search across millions of GitHub repos (`https://mcp.grep.app`).
   - Use ONLY `query` + `repo` (e.g. `repo: "dart-lang/sdk"`). Do **NOT** pass `path` —
     leaving it off returns wider results across the whole repo and surfaces more
     knowledge (related call sites, other files, cross-arch counterparts) you would
     otherwise miss by narrowing. This is intended: cast wide, then narrow with `gh api`.
   - Pass literal code/symbol in `query` (e.g. `"CheckStackOverflowInstr"`, `"NULL_REG"`).
   - ⚠️ **NEVER** put `repo:...` or `path:...` inside `query` — `query` matches literal text in files.
2. **`gh api` @ version tag**: Once the path is found, fetch exact uncompressed source lines:
   `gh api -H "Accept: application/vnd.github.raw" "repos/dart-lang/sdk/contents/<path>?ref=<tag>"`

Both are necessary: Grep MCP finds the file/line fast, `gh api` gives versioned ground truth. Never rely on training memory.

### Critical lessons learned

- **ObjectStoreAOTFieldCount**: Must count ALL field macros (RW + CW + FW + LAZY_CORE + LAZY_ISOLATE + LAZY_FFI + LAZY_INTERNAL + LAZY_ASYNC + ARW_AR + ARW_RELAXED), not just RW. Counting only RW → wrong stream position → dispatch table parsed from wrong position → BLR=0.
- **from() differs between versions**: 2.12.0 ObjectStore::from() = &object_class_, 3.9.2 = &list_class_. IsolateObjectStore::from() is different and NOT used for serialization.
- **Class ID extraction differs**: 2.x uses LDURH (16-bit, kClassIdTagPos=16), 3.x uses LDUR+UBFX (64-bit, kClassIdTagPos=12).
- **Dispatch pattern differs**: 2.x uses cid_reg in-place (SUB X0, X0, #imm), 3.x uses LR as temp (SUB X30, X0, #imm).
