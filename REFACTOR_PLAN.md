# AOTopsy — Master Plan: Refactor + Roadmap Consolidation

> **Status**: RENCANA — belum dieksekusi. Working tree clean di commit `243a4c7`.
> **Filosofi**: Destruktif. Tidak ada backward compat. Kode lama mengikuti kode baru.
> **Tujuan**: Mudah dipahami, reusable, tidak ribet, terarah.

---

## 0. Context — What Already Happened

Sesi sebelumnya menulis `docs/REFACTOR_PLAN.md` (629 baris) dengan 3 phase. **Phase 1 dan 2 sudah dieksekusi** — package-package berikut sudah ada:

| Old Plan Item | Status | Evidence |
|---|---|---|
| 1.1 vmtables extraction | ✅ DONE | `internal/vmtables/` exists (5 files, 8,114 lines) |
| 1.2 arch → sdk merge | ✅ DONE | `internal/sdk/` has x86_decode.go + x86_helpers.go |
| 1.3 thraudit extraction | ✅ DONE | `internal/thraudit/` exists |
| 1.4 split decompile_native_cmd | ✅ DONE | Split into 4 files (cmd, loop, output, from_main) |
| 2.1 naming extraction | ✅ DONE | `internal/naming/` exists (8 files) |
| 2.2 decompiler/stmt | ✅ DONE | `internal/decompiler/stmt/` exists (15 files) |
| 2.3 decompiler/compare | ✅ DONE | `internal/decompiler/compare/` exists (7 files) |
| 2.4 frida extraction | ✅ DONE | `internal/frida/` exists (5 files) |

**Yang tersisa dari old plan** (Phase 3, belum dieksekusi):
- 3.1 Slim `pipeline/` to pure orchestration
- 3.2 `cmd/aotopsy/` naming conventions
- 3.3 ARM64/x86_64 naming convention consistency
- 3.4 Consolidate `context.go` / `snapshot_loader.go`
- 3.5 Testutil consolidation

**Decompiler reconstruction (50-decompiler-reconstruction.md)**: Phases 0-10 semua DONE. D1-D12 defects semua remediated. Code review findings (A1-A7, B1-B4, C1-C3, D1-D3, E1-E2, F1-F3) semua done. rawReg −50-66%, F1 100% valid, 0 fabrication.

---

## 1. Current State (Measured 2026-08-19, verified this session)

### 1.1 Codebase Size

- 317 Go files, 80,501 lines total (excluding runtime_test/)
- 32 packages (cmd/aotopsy + 31 internal + tools)
- All gates green: golden, cross-version, SDK drift (46 tables), symtab differential (floor 0.81), decompiler quality (floor 0.95), `go test`

### 1.2 Package Sizes (source files, excluding tests)

| Package | Lines | Status |
|---|---|---|
| `decompiler` | 11,015 | Core + stmt/ + compare/ sub-packages. Arch mixing in parent. |
| `cluster` | 8,997 | Well-structured. Snapshot deserialization. |
| `pipeline` | 8,891 | **STILL God Package** — orchestration + captured records + symtabdiff + xref + class layouts + exports + firbuild + context |
| `vmtables` | 8,114 | MIXED: generated tables + hand-written logic. Stays in place. |
| `cmd/aotopsy` | 7,490 | **STILL 46 flat files** — business logic mixed with CLI |
| `typetrack` | 6,116 | Well-structured. Type inference. |
| `decompiler/stmt` | 4,044 | Well-structured. Statement tree + passes. |
| `disasm` | 3,333 | ARM64-centric naming. Data tables already moved out. |
| `signal` | 3,242 | Well-structured. Behavioral classification. |
| `render` | 2,813 | Well-structured. DOT/HTML output. |
| `naming` | 2,710 | **Kitchen sink** — name resolution + utilities (ReadJSONL, WriteDartMeta, IsInterestingCallee) |
| `snapshot` | 2,546 | Well-structured. Version profiles + header parsing. |
| `frida` | 1,456 | Well-structured. Frida integration. |
| `decompiler/compare` | 1,308 | Well-structured. Comparison tools. |
| `sdk` | 1,153 | Well-structured. SDK constants + x86 helpers. |
| Others | ~3,500 | elfx, samplecorpus, thraudit, dartfmt, ffitrace, arm64dec, symbolmap, output, callgraph, fingerprint, strutil, strxref, funcdiff, lattice, cli, sdktest |

### 1.3 Remaining Structural Problems

1. **`cmd/aotopsy`** — 46 files, 7,490 lines, all `package main`. Business logic (reachability BFS, decompile loop, library classification, Ghidra/IDA launchers, find-libapp, inventory, parity) bercampur dengan CLI plumbing. Tidak bisa di-test atau di-reuse.

2. **`pipeline`** — Masih God Package. `Context` struct punya 20+ field melayani decompiler, ffitrace, strxref, dispatch table, arg-reg masks. `symtabdiff.go` (522 lines, 3 ELF dialect name comparison), `captured_records.go` (363 lines, 10+ record types), `firbuild_helpers.go`, `r2_fingerprint_export.go`, `libraryxref.go`, `class_layouts.go` — semua di pipeline, bukan orchestration.

3. **`naming`** — Kitchen sink. `ReadJSONL`/`WriteJSONLFile` (generic JSONL I/O), `WriteDartMeta`, `ExtractAsmComments`, `IsInterestingCallee`, `MakeLogf`/`MakeStagef` — utility functions yang bukan naming.

4. **Duplikasi** — `X86DecodedInst` di 3 package, `canonReg` di 3 package, `dartVersionAtLeast` di 2 package, `poolLookups` type alias di 4 file cmd.

5. **`lattice`** — 91 lines, package terpisah yang hanya dipakai `callgraph`. Tidak perlu package sendiri.

6. **`output` → `signal` dependency** — SARIF output bergantung pada signal analysis. Output formatting seharusnya analysis-agnostic.

### 1.4 What's Deprecated / Stale (from roadmap docs)

| Item | Source | Why Stale |
|---|---|---|
| Old ROADMAP §3.5 "name pool entries that hold Code" (321 bare) | 20-invariants | Stale in 3.x — 0 empty-display slots at 3.12.2. Honest-floor verdict reached. |
| `blr.monomorphic` as objective function | 20-invariants | Counts confidence, not correctness. Never use as optimization target. |
| Full SSA rewrite (G3) | ssa-evaluation.md | DEFERRED — phi materialization tried, 0% gain, reverted. Idiom work has better ROI. |
| Call-return type propagation (C) | 30-aot-limits | Tried, implemented, measured INERT, reverted. |
| `<Array>` → `[]` fold | 50-decompiler A1 | Fabricates value. Removed. Placeholder kept honest. |
| `null + N` → `N` fold | 50-decompiler A2 | x22 is null POINTER not 0. Removed. |
| Lambda body synthesis | 50-decompiler A3 | Pure guess. Removed. Honest anon-closure reference kept. |
| `docs/REFACTOR_PLAN.md` (old) | docs/ | Phase 1-2 already executed. Phase 3 remaining items absorbed into this plan. |

### 1.5 What's Already Implemented (from roadmap docs)

| Feature | Source | Status |
|---|---|---|
| Decompiler phases 0-10 | 50-decompiler | All DONE. D1-D12 remediated. |
| canonReg value-graph | 50-decompiler §5 | DONE. rawReg −50-66%. |
| Accessor field-name recovery | 30-aot-limits §2.1 | DONE. rawField −11-22%. 554-1396 names/binary. |
| Two-FuncIR-builder consolidation | 50-decompiler §3 | DONE. Context.FuncIRFor now enriched. |
| 3.13.0 roots section fix | 40-snapshot-format-kb | DONE. dispatch_table 31→29636. |
| VM stub image-order reversal fix | stuborder.go | DONE. All 164 names corrected. |
| Closure parent mapping | naming/typeparams.go | DONE. BuildClosureParents. |
| Named parameter names | naming/typeparams.go | DONE. NamedParamNames. |
| Async state machine linearizer | stmt/async_linearizer.go | DONE. |
| For-in recovery | stmt/stmt_for_in.go | DONE. |
| Collection idiom (Set/List literal) | stmt/stmt_idioms.go | DONE. |
| Null-aware `?.`/`??`/`??=` | stmt/stmt_idioms.go | DONE. |
| Cascade `..` | stmt/stmt_idioms.go | DONE. |
| String interpolation | stmt/stmt_idioms.go | DONE. |
| Closure inlining | stmt/stmt_closure.go | DONE. |
| Project synthesizer + export-dart | project_synthesizer.go | DONE. |
| Typed declarations | stmt/stmt_types.go | DONE. |
| Copy propagation + CSE | stmt/stmt_dataflow.go | DONE. |
| Expression tree + constant folding | stmt/expr.go | DONE. |
| Statement tree (replaces regex passes) | stmt/stmt.go | DONE. |
| 3.13 cluster addition (Bytecode etc.) | 40-snapshot-format-kb §6 | Known, needs implementation (A1 below). |

---

## 2. vmtables: Generate More or Keep As-Is?

### 2.1 Current Composition

| File | Lines | Generated? | What's Hand-Written |
|---|---|---|---|
| `thrfields_x64.go` | 3,446 | ✅ by `extract_thr.go -write` | `init()` merge calls (mirror ARM64) |
| `thrfields.go` | 3,202 | Partially by `extract_thr.go -write` | `THRFieldsWithProfile` selection, `mergeRuntimeEntries`, `init()`, runtime entry name lists, LEAF entry lists, non-compressed variant tables |
| `stubnames.go` | 854 | ❌ entirely hand-written | VM_STUB_CODE_LIST expansion per version (20+ versions) |
| `threadstubs.go` | 286 | ❌ entirely hand-written | CACHED_VM_STUBS_ADDRESSES_LIST offsets per version |
| `stuborder.go` | 118 | ❌ entirely hand-written | TTS insertion logic (Subtype7TestCache anchor), image-order reversal |

### 2.2 Can extract_thr.go Generate More?

| Table | Source in SDK | Can extract_thr.go parse it? | Verdict |
|---|---|---|---|
| Runtime entry name lists | `runtime_entry_list.h` — `RUNTIME_ENTRY_LIST(V)` + `LEAF_RUNTIME_ENTRY_LIST(V)` macros | Yes — macro expansion is parseable (list of `V(Name)` entries) | **SHOULD GENERATE** — adds SDK drift coverage |
| `threadstubs.go` offsets | `runtime_offsets_extracted.h` — `Thread_*_entry_point_offset` constants | Yes — already extracted for full THR table; just filter for the CACHED_VM_STUBS subset | **SHOULD GENERATE** — filter existing extraction |
| `stubnames.go` lists | `stub_code_list.h` — `VM_STUB_CODE_LIST(V)` macro | Yes — but needs per-version diff (stubs added/removed across versions) | **SHOULD GENERATE** — parse macro at each tag, diff |
| `stuborder.go` TTS logic | `stub_code_list.h` — `VM_TYPE_TESTING_STUB_CODE_LIST(V)` position within `VM_STUB_CODE_LIST` | Partially — the Subtype7TestCache anchor is structural (macro call position), not a constant | **KEEP HAND-WRITTEN** — structural composition, not data |
| `THRFieldsWithProfile` selection | N/A — this is application logic (which table to pick) | No — this is our code, not SDK data | **KEEP HAND-WRITTEN** |
| `mergeRuntimeEntries` | N/A — computes names for offsets SDK doesn't export | No — this is derivation logic | **KEEP HAND-WRITTEN** |

### 2.3 Decision

**Improve `extract_thr.go` to also generate:**
1. Runtime entry name lists (from `runtime_entry_list.h` at each tag)
2. `threadstubs.go` offset tables (filter `runtime_offsets_extracted.h` for `*_entry_point_offset` fields in the CACHED_VM_STUBS_ADDRESSES_LIST)
3. `stubnames.go` per-version lists (parse `VM_STUB_CODE_LIST` macro at each tag)

**Keep hand-written:**
- `stuborder.go` — TTS insertion is structural, not data
- `THRFieldsWithProfile` — selection logic
- `mergeRuntimeEntries` — derivation logic
- `init()` calls — wiring

**Benefit**: SDK drift gate (`-check`) would then cover stubnames + threadstubs + runtime entries, catching version drift in those tables too. Currently only `thrfields*.go` tables are checked.

**Risk**: LOW — extract_thr.go already parses SDK headers via `gh api`. Adding `runtime_entry_list.h` and `stub_code_list.h` parsing is incremental. The `-write` mode would rewrite the generated portions; hand-written portions stay untouched.

---

## 3. Consolidated Refactor Plan

### Phase A: Extract Business Logic from `cmd/aotopsy` (HIGHEST IMPACT)

**Goal**: `cmd/aotopsy` becomes thin CLI handlers. All business logic in library packages.

**Steps**:

1. Move `range_finder.go` → `cluster/range.go` (29 lines, pure cluster logic)
2. Move Ghidra helpers (`decompile.go` findGhidra, probeGhidraHome, etc.) → `analysis/ghidra.go`
3. Move IDA helpers (`ida.go` findPython, findIDAScript) → `analysis/ida.go`
4. Move `artifacts.go` (copyGhidraArtifacts, copyIDAArtifacts) → `analysis/artifacts.go`
5. Move `find_libapp.go` logic → `analysis/findlibapp.go`
6. Move `inventory.go` logic → `analysis/inventory.go`
7. Move `reflutter_import.go` logic → `analysis/reflutter.go`
8. Move `parity.go` logic → `analysis/parity.go`
9. Move `refinfo.go` logic → `analysis/refinfo.go`
10. Move `x64refs.go` logic → `analysis/x64refs.go`
11. Move `graph.go` logic → `analysis/graph.go`
12. Move `strings.go`/`clusters.go`/`objects.go` logic → `analysis/`
13. Move `thr_audit.go` logic → `analysis/thraudit.go`
14. Move `cmd_export_dart.go` sanitization → `strutil/` or `decompiler/`
15. Move `decompile_native_*.go` logic → `analysis/decompile*.go` + `analysis/reachability.go`
16. Move `callTargetsOf` → `decompiler/call.go`
17. Delete `pool.go` (type alias, 1 line)
18. Move `disasm_test.go` → `internal/analysis/`
19. `resolve.go` helpers (defaultOutDir, resolvePositionalLib, reorderPositionalArg) stay in `cmd/aotopsy/` (CLI helpers)

**Verification**: `go build ./cmd/... ./internal/... ./tools/...` + `go test`

### Phase B: Slim `naming` — Extract Utilities

**Goal**: `naming` only contains name resolution.

1. Create `internal/jsonutil/` with `ReadJSONL`/`WriteJSONLFile` (generic JSONL I/O)
2. Move `WriteDartMeta`/`ExtractAsmComments`/`FlutterMetaComment` → `analysis/meta.go`
3. Move `IsInterestingCallee` → `signal/classify.go`
4. Move `MakeLogf`/`MakeStagef` → `cli/`
5. Move `DisasmIndexEntry` → `analysis/types.go`
6. Delete `SanitizeFilename` wrapper (already delegates to `strutil`)
7. Split `helpers.go` into `pool.go` (PoolLookups, BuildPoolLookups, ResolvePoolDisplay) + `codeowner.go` (ResolveCodeOwner, CodeIndexToFunc, QualifiedCodeName)
8. Merge `vmstubs.go` + `discardedfuncs.go` + `typeteststubs.go` + `ttscall.go` → `stubs.go`

**Verification**: `naming` imports reduced from 7 to 3-4 internal packages.

### Phase C: Rename `pipeline` → `analysis` + Split Context

**Goal**: Pipeline is orchestration-only. Context is not a God Object.

1. Rename `internal/pipeline/` → `internal/analysis/`
2. Split `Context` → `AnalysisContext` (slim: EF, Info, Result, Ranges, Pool, Code, etc.) + `DecompileEnrichment` (lazy-built: FieldNameResolver, ReceiverClassByCode, etc.)
3. Move `symtabdiff.go` → stays in `analysis/` (name comparison, used by pipeline)
4. Move `captured_records.go` → stays in `analysis/` (captured data, used by pipeline)
5. `ffitrace`, `strxref`, `frida`, `funcdiff` import `analysis` and use `AnalysisContext`
6. Update all imports (`pipeline.LoadContext` → `analysis.LoadContext`, etc.)

**Verification**: `go build` + `go test` + golden + SDK drift

### Phase D: Arch File Naming + Merge

1. Rename `disasm/disasm.go` → `disasm/arm64.go`
2. Rename `disasm/dataflow.go` → `disasm/dataflow_arm64.go`
3. Move `disasm/pipeline.go` types → `analysis/types.go` or `core/types.go`
4. Merge `decompiler/arm64.go` + `lift_arm64ops.go` → `lift_arm64.go`
5. Merge `decompiler/x86.go` + `lift_x86.go` → `lift_x86.go`
6. Merge `decompiler/compact.go` + `compact_extra.go` → `compact.go`
7. Move `arm64dec/` → `arch/arm64/` (update `tools/extract_thr.go` if needed — it doesn't reference arm64dec)
8. Update all imports

### Phase E: Merge `lattice` into `callgraph`

1. Move `lattice/graph.go` + `lattice/cfg.go` → `callgraph/graph.go`
2. Move `lattice/render/` → `callgraph/render/`
3. Update imports in `pipeline`/`analysis` and `callgraph`
4. Delete `internal/lattice/`

### Phase F: Remove `output` → `signal` Dependency

1. Define `output.Finding` interface or generic record type
2. `signal.SignalFinding` satisfies the interface
3. `WriteSARIF` accepts generic type
4. Remove `signal` import from `output`

### Phase G: Improve `extract_thr.go` — Generate More vmtables

1. Add `runtime_entry_list.h` parsing to extract runtime entry names per version
2. Add `stub_code_list.h` parsing to generate `stubnames.go` per-version lists
3. Filter `runtime_offsets_extracted.h` for `*_entry_point_offset` to generate `threadstubs.go` tables
4. Add `-check-stubs` and `-check-runtime-entries` verification modes
5. Update `-write` to rewrite generated portions of `stubnames.go` and `threadstubs.go`
6. Keep `stuborder.go`, `THRFieldsWithProfile`, `mergeRuntimeEntries`, `init()` hand-written

**Verification**: `go run tools/extract_thr.go -check` + new `-check-stubs` pass

### Phase H: Dedup + Cleanup

1. Remove duplicate `X86DecodedInst` → use `arch/x86.DecodedInst` (or `sdk.X86Decoded`) everywhere
2. Remove duplicate `canonReg` → use `sdk.X86CanonReg` everywhere
3. Consolidate `dartVersionAtLeast` / `VersionAtLeast` → one in `snapshot/`
4. Remove deprecated command handling code (the `Deprecated` field in command registry — old aliases like `disasm`, `dump`, `strings`, `graph`, `clusters`, `render`, `thr-audit`, etc.)
5. Remove `ReadFillStrings` (marked deprecated in `cluster/fill_strings.go`)
6. Run `gofmt -w` on all files (but NOT to "fix" CRLF — see AGENTS.md)

### Phase I: Open Roadmap Items (from 70-public-reliability-roadmap.md)

These are NOT structural refactor — they are feature/reliability work. Listed here for consolidation.

**Workstream A — Format currency:**
- A1 (P1): Recognize/parse/skip 4 new clusters in Dart 3.13 (Bytecode, ApiError, UnwindError, LocalVarDescriptors). **Status: Known, needs implementation.**
- A2 (P2): Add 3.13.2 ground-truth twin to corpus
- A3 (P2): Confirm Function bit-flag shift (IsRedirectingFactory → IsDynamicallyCallable)
- A4 (P3): 3.14 forward-watch

**Workstream B — Published accuracy:**
- B1 (P0): Publish version-twin symtab differential as public benchmark
- B2 (P0): Adopt field-standard metric names (syntax-validity, fabrication rate, coverage)
- B3 (P1): `make bench` one-command harness
- B4 (P1): Honest coverage census
- B5 (P2): Recompile-and-diff spike

**Workstream C — Supply chain:**
- C1 (P0): GitHub Actions matrix CI
- C2 (P0): GoReleaser + cosign signing
- C3-C7: Provenance, SBOM, coverage badge, verification instructions

**Workstream D — Robustness:**
- D1 (P1): Go native fuzz the snapshot parser
- D2 (P1): Differential as CI invariant
- D3 (P1): Property-based output invariants

**Workstream E — Reach:**
- E1 (P2): arm32 + iOS arm64 coverage
- E2 (P2): Static + Frida complementary workflow docs

**Workstream F — Trust surface:**
- F1 (P0): Fix dead upstream link (zboralski/unflutter → KristijanZic/unflutter)
- F2 (P0): Honest Limitations & Scope page
- F3 (P0): Copy-pasteable quickstart with bundled sample

**Workstream G — Decompiler fidelity:**
- G1 (P2): Idiom-by-idiom rawReg reduction (ongoing)
- G2 (P2): Amplify accessor field-name recovery, publish count
- G3 (P3): Full SSA — **DEFERRED** per ssa-evaluation.md

---

## 4. Execution Order

```
Phase A: Extract cmd/aotopsy business logic → analysis/     (HIGHEST IMPACT)
Phase B: Slim naming — extract utilities
Phase C: Rename pipeline → analysis, split Context           (HIGH RISK)
Phase D: Arch file naming + merge
Phase E: Merge lattice → callgraph
Phase F: Remove output → signal dependency
Phase G: Improve extract_thr.go — generate more vmtables
Phase H: Dedup + cleanup
Phase I: Open roadmap items (feature work, not refactor)
```

**Critical path**: A → C (A extracts to analysis/, C renames pipeline to analysis/)

**Can be parallelized**: B, D, E, F are independent of each other (all depend on A being done for import paths).

**Phase G** is independent of A-F (it's tooling improvement).

**Phase H** should be last (cleanup after all moves).

**Phase I** is separate workstream — not blocking refactor, listed for consolidation.

---

## 5. What Does NOT Change

- **`internal/vmtables/`** — stays in place. MIXED generated + hand-written. `tools/extract_thr.go` has hardcoded paths to `thrfields*.go` and `snapshot/version.go`. Phase G improves generation but doesn't move files.
- **`internal/cluster/`** — well-structured. Only `range_finder.go` logic moves in.
- **`internal/dartfmt/`** — already clean, 2 files.
- **`internal/snapshot/`** — well-structured. `version.go` path referenced by `extract_thr.go` — must not move.
- **`internal/typetrack/`** — well-structured. Only import path updates.
- **`internal/signal/`** — well-structured. `IsInterestingCallee` moves in.
- **`internal/render/`** — well-structured.
- **`internal/frida/`** — well-structured (extracted in prior session).
- **`internal/thraudit/`** — well-structured (extracted in prior session).
- **`internal/decompiler/stmt/`** — well-structured (extracted in prior session).
- **`internal/decompiler/compare/`** — well-structured (extracted in prior session).
- **`internal/sdk/`** — well-structured. x86 helpers already merged in.
- **`internal/arm64dec/`** — moves to `arch/arm64/` in Phase D.
- **`internal/cli/`** — minimal. `MakeLogf`/`MakeStagef` move in.
- **`internal/strutil/`** — minimal.
- **`internal/sdktest/`** — minimal.
- **`internal/samplecorpus/`** — minimal.
- **`tools/extract_thr.go`** — standalone. Phase G improves it. Hardcoded paths to vmtables + snapshot must be respected.
- **`ghidra_scripts/`**, **`ida_scripts/`** — Python, not Go.

---

## 6. Verification Gates

After each phase:

1. **Build**: `go build ./cmd/... ./internal/... ./tools/...`
2. **Tests**: `go test ./cmd/... ./internal/... ./tools/...`
3. **Golden**: `go test ./internal/analysis/ -run Golden` (or SKIP if no sample)
4. **SDK drift**: `go run tools/extract_thr.go -check` (+ `-check-stubs` after Phase G)
5. **Determinism**: `go test ./internal/analysis/ -run Deterministic`

---

## 7. Expected Outcome

### Before
- 32 packages, 80,501 lines
- `cmd/aotopsy`: 46 files, 7,490 lines, all `package main`
- `pipeline`: 8,891 lines, God Package with God Object (`Context`)
- `naming`: 2,710 lines, kitchen sink with 7 internal deps
- `lattice`: 91 lines, unnecessary separate package
- Duplicate types: `X86DecodedInst` × 3, `canonReg` × 3, `dartVersionAtLeast` × 2
- vmtables: only `thrfields*.go` covered by SDK drift gate

### After
- ~30 packages, ~79,000 lines (reduction from dedup)
- `cmd/aotopsy`: ~5 files, ~500 lines (main + commands + helpers)
- `cmd/aotopsy/handlers/`: ~20 files, ~2,000 lines (thin CLI handlers)
- `analysis`: ~8,000 lines (was pipeline, slimmed Context, orchestration + stage files)
- `naming`: ~1,500 lines (slimmed, 3-4 internal deps)
- `callgraph`: ~400 lines (absorbed lattice)
- `arch/arm64/`: ~400 lines (was arm64dec)
- `jsonutil/`: ~50 lines (extracted from naming)
- Duplicate types: eliminated
- vmtables: `thrfields*.go` + `stubnames.go` + `threadstubs.go` + runtime entry lists all covered by SDK drift gate

---

## 8. Deprecated Items — Do Not Re-Plan

These are settled verdicts from the roadmap docs. Do not re-open:

1. **`blr.unresolved` as "pool naming" problem** — honest floor reached. Remainder is true polymorphic dispatch + dynamic Code/Closure objects. AOT limit.
2. **`blr.monomorphic` as objective function** — counts confidence, not correctness.
3. **Full SSA rewrite (G3)** — deferred. Phi tried, 0% gain, reverted. Idiom work has better ROI.
4. **Call-return type propagation** — tried, inert, reverted.
5. **`<Array>` → `[]` fold** — fabricates value. Removed.
6. **`null + N` → `N` fold** — x22 is null POINTER. Removed.
7. **Lambda body synthesis** — pure guess. Removed.
8. **Last-component mixin fold in real output** — wrong 23% of time. Comparison-only.
9. **Float guess from bit pattern** — gated on slot CID, not bit pattern.
10. **`allocation_stub_` recovery** — outside `to_snapshot(kFullAOT)`. Impossible.
11. **`var_descriptors` recovery** — behind `NOT_IN_PRODUCT`. Impossible.
12. **ICData contents** — empty in AOT PRODUCT. Impossible.
13. **Recompilation for verification** — `CompileFunction` calls `FATAL()` under `DART_PRECOMPILED_RUNTIME`. Use `VerifyCFG` instead.
14. **`num_fixed_parameters` since 2.14** — removed by SDK in two steps. Recover from code (receiver slot), not snapshot.
