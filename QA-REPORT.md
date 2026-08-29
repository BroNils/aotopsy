# QA Report: Refactor `origin/main..HEAD` (32 commits, 274 files, ~28k lines)

**Date:** 2026-08-29
**Reviewer:** Independent QA (neutral — no docs/ or REFACTOR_PLAN read)
**Scope:** Full diff `origin/main..HEAD`, ALL 274 files read, SDK verification via `gh api` @3.12.2, WSL test execution
**Method:** Every non-test source file diff read in full (no head/tail truncation). Test files verified by build + test execution. SDK constants verified against dart-lang/sdk source.

---

## Executive Summary

The refactor is a large-scale architectural cleanup across 32 commits:
- Package renames: `pipeline`→`analysis`, `lattice`→`callgraph`
- File moves: `disasm`→`thraudit`/`vmtables`, `arch`→`sdk`, decompiler `stmt/`/`compare/` subpackages
- ARM64 decoder deduplication: 15+ functions consolidated into `internal/arch/arm64/decoders.go`
- SSA fixpoint: forward-join replaced with full reaching-definition fixpoint + phi materialization
- Calling-convention fix: C ABI arg registers → SDK-verified Dart convention
- New verification gates: `-check-stubs`, `-check-runtime-entries`
- Deprecated commands removed, `pool.go` type alias deleted

**Build passes, all unit tests pass, SDK gates pass, symtab differential passes (49 samples, floor 0.81, worst band 81.3%).**

**However: the golden gate is RED** (two ARM64 samples fail), and the decoder deduplication **reintroduced a previously-fixed bug** in the ARM64 MOVOrr decoder mask. MOVK/MOVN coverage was also silently dropped from `DstRegOfInst`.

| Gate | Status | Detail |
|---|---|---|
| Build (`go build`) | PASS | 8.8s, clean |
| Unit tests (all internal packages) | PASS | sdk, decompiler, disasm, typetrack, callgraph, thraudit, vmtables, naming, cluster, signal, output, strutil, strxref, ffitrace, dartfmt, snapshot, elfx |
| SDK THR check | PASS | 46 tables, 0 problems |
| SDK ObjectStore check | PASS | 23 versions, 0 mismatches |
| SDK Stub check | PASS | All versions match SDK |
| Golden determinism | PASS | Byte-identical across 2 runs |
| **Golden content** | **FAIL** | compare_sample_arm64, dart212_arm64 mismatch |
| Symtab differential | PASS | 49 samples, worst 81.3% (>0.81 floor) |
| Sample corpus coverage | PASS | 93/93 samples present |
| Property invariants | PASS | 99.87% valid ARM64, 100% x64, 0 fabrications |

---

## CRITICAL Findings

### F1. REGRESSION: MOVOrr mask bug reintroduced (HIGH)

**File:** `internal/arch/arm64/decoders.go`

**Bug:** `MOVOrr` uses mask `0xFF20001F` which includes Rd (bits 4:0), so the comparison `raw&0xFF20001F == 0xAA000000` only matches when Rd=0. The function only detects `MOV X0, XZR, Xm` instead of `MOV Xd, XZR, Xm` for any destination register d.

**Evidence — the old code at `origin/main` had the CORRECT mask with an explicit warning comment:**

```go
// internal/typetrack/intraproc_decoders.go @origin/main:
// Mask 0xFF200000 covers sf+opcode+Rm+fixed bits, NOT Rd (bits 0-4) so
// any destination register matches. The previous mask 0xFF20001F
// included Rd, so only Rd==0 (MOV X0) ever matched.
if raw&0xFF200000 == 0xAA000000 {
    rn := int((raw >> 5) & 0x1F)
    if rn == 31 {
        return int(raw & 0x1F), true
    }
}
```

The deduplication to `arm64/decoders.go` reintroduced the exact bug the comment warned about. Same bug in `DstRegOfInst`'s ORR check.

**Impact (3 call sites, all in typetrack):**

| Call site | Effect |
|---|---|
| `intraproc_handlers_call.go:46` (`handleMOV`) | Type propagation through `MOV Xd, XZR, Xm` only works for d=0. All other register copies miss type propagation. |
| `intraproc.go:329` (Pattern 2.x B) | **Dead code.** Checks `rd == 30` (MOV to LR), but `MOVOrr` only returns `ok=true` when rd=0, so `rd == 30` is unreachable. Dispatch table resolution pattern for Dart 2.x never fires. |
| `intraproc.go:416` (Pattern 2.x D) | MOV bridge only detected when destination is X0. If compiler emits `MOV X5, XZR, Xn` (common), bridge is missed. |

**Fix:** Change mask from `0xFF20001F` to `0xFF200000` in both `MOVOrr` and `DstRegOfInst`:

```go
// MOVOrr
if raw&0xFF200000 == 0xAA000000 && (raw>>5)&0x1F == 31 {
    return int(raw & 0x1F), true
}

// DstRegOfInst ORR check
if raw&0xFF200000 == 0xAA000000 && (raw>>5)&0x1F == 31 {
    return int(raw & 0x1F)
}
```

### F2. REGRESSION: DstRegOfInst lost MOVK/MOVN coverage (MEDIUM)

**File:** `internal/arch/arm64/decoders.go`

**Bug:** The old `dstRegOfInst` (both in `disasm/calledge.go` and `typetrack/intraproc_decoders.go` at `origin/main`) detected MOVZ, MOVK, and MOVN with mask `0xFF800000`:

```go
if raw&0xFF800000 == 0xD2800000 || // MOVZ X
    raw&0xFF800000 == 0xF2800000 || // MOVK X
    raw&0xFF800000 == 0x92800000 { // MOVN X
    return int(raw & 0x1F)
}
```

The new `arm64.DstRegOfInst` only detects MOVZ with tighter mask `0xFFE00000`:

```go
if raw&0xFFE00000 == 0xD2800000 {
    return int(raw & 0x1F)
}
```

Mask `0xFFE00000` excludes MOVK (`0xF2800000`) and MOVN (`0x92800000`) because they differ in bits 23-21.

**Impact (3 call sites):**
- `disasm/annotate.go:231` — peephole liveness tracking (stale liveness for MOVK/MOVN destinations)
- `disasm/calledge.go:92` — call argument count inference (MOVK argument setup not counted)
- `typetrack/intraproc_decoders.go:14` — type killing (stale types persist for MOVK/MOVN destinations)

**Fix:** Restore the broader mask:

```go
if raw&0xFF800000 == 0xD2800000 || // MOVZ X
    raw&0xFF800000 == 0xF2800000 || // MOVK X
    raw&0xFF800000 == 0x92800000 { // MOVN X
    return int(raw & 0x1F)
}
```

### F3. GATE RED: Golden test failing (HIGH)

**Files:** `internal/analysis/testdata/golden/compare_sample_arm64.json`, `internal/analysis/testdata/golden/dart212_arm64.json`

**Status:**
- `compare_sample_arm64` — FAIL (golden mismatch)
- `sample312_x64` — PASS
- `dart212_arm64` — FAIL (golden mismatch)
- `sample313_arm64` — SKIP (env var not set)
- `TestGoldenOutputIsDeterministic` — PASS (output is deterministic)

**Golden mismatches (dart212_arm64):**
| File | Golden | Actual | Change |
|---|---|---|---|
| `address_callers_xref.jsonl` | 4104 lines | 4112 lines | +8 lines |
| `call_edges.jsonl` | 40502 lines | 40502 lines | same count, different content |
| `field_accessor_xref.jsonl` | 2877 lines | 2872 lines | -5 lines |
| `typetrack_report.json` | 38 lines | 39 lines | +1 line |

**Root cause:** Golden records last re-recorded in commit `3414e8f` (early in sequence). Subsequent commits — especially `1f17bf6` (dedup refactor introducing MOVOrr bug F1), `53cb015` (write-barrier elision), `81d24b5` (CODE_REG/ARGS_DESC_REG seeding), `e44320f` (string hoisting), and Phase D-H — changed ARM64 output without updating golden.

`sample312_x64` passes → changes are ARM64-specific, consistent with F1/F2.

**Recommendation:** Per AGENTS.md: "do not re-record immediately. First find what changed; re-record only after the change is understood and intentional." Fix F1/F2 first, then re-record.

---

## LOW Findings

### F4. DstRegOfInst lost LDR register offset coverage (LOW)

Old `disasm/calledge.go:dstRegOfInst` had LDR register offset (`0xF8600800` with mask `0xFFE00C00`). New `arm64.DstRegOfInst` doesn't include it. The dedicated `arm64.LDRRegExtended` function still exists, so callers needing LDR reg offset detection can use it directly. Impact limited to `DstRegOfInst` callers that relied on it for liveness/dest-reg detection of dispatch table loads.

### F7. PRE-EXISTING BUG: CodeEntryPointDisp values wrong (MEDIUM)

**File:** `internal/sdk/registers.go`

**Bug:** `CodeEntryPointDisp = 0x7` and `CodeMonomorphicEntryPointDisp = 0xf` are documented as "field offset 6 + kHeapObjectTag" and "offset 16 -> displacement 0xf" respectively. Verified against SDK `runtime_offsets_extracted.h @3.12.2` via `gh api`:

- Compressed: `Code_entry_point_offset[] = {0x4, 0xc, 0x8, 0x10}` (kNormal=0x4, kMonomorphic=0xc)
- Uncompressed: `Code_entry_point_offset[] = {0x8, 0x18, 0x10, 0x20}` (kNormal=0x8, kMonomorphic=0x18)

Tagged displacement = field_offset + kHeapObjectTag (1):
- Compressed kNormal: 0x4 + 1 = **0x5** (code uses **0x7** ← WRONG)
- Compressed kMonomorphic: 0xc + 1 = **0xd** (code uses **0xf** ← WRONG)
- Uncompressed kNormal: 0x8 + 1 = **0x9** (code uses 0x7 ← WRONG)
- Uncompressed kMonomorphic: 0x18 + 1 = **0x19** (code uses 0xf ← WRONG)

**Status:** Pre-existing at `origin/main` (`internal/disasm/calledge.go` had the same constants). The refactor moved them to `sdk.CodeEntryPointDisp` with a **misleading doc comment** ("field offset 6 + kHeapObjectTag") that doesn't match any SDK version's layout.

**Impact:** `IsCodeEntryPointDisp` (used in `disasm/dataflowarm64.go:265` and `disasm/dataflowx86.go:359`) never matches a real Code entry-point load, so the "entry point OF Code X is X" provenance propagation rule is dead code. This silently degrades call-edge provenance tracking for Code entry-point loads.

**Fix:** The correct values depend on compression mode. Either:
- Make `IsCodeEntryPointDisp` check both compressed and uncompressed tagged offsets: `{0x5, 0x9}` for kNormal, `{0xd, 0x19}` for kMonomorphic
- Or thread the `CompressedPointers` flag through to select the right pair

**Verified via:** `gh api` to `runtime/vm/compiler/runtime_offsets_extracted.h?ref=3.12.2` + Grep MCP confirming `FieldAddress` adds `kHeapObjectTag`

### F5. Stale documentation references (LOW)

9 files still reference `internal/pipeline` in comments instead of `internal/analysis`:
- `internal/analysis/crossversion_test.go:47`
- `internal/analysis/decompile_fidelity_test.go:20`
- `internal/analysis/golden_test.go:38,119`
- `internal/analysis/reflutter.go:66`
- `internal/cluster/corpus_test.go:33`
- `internal/decompiler/features_test.go:10`
- `internal/decompiler/ir.go:501`
- `internal/naming/testhelpers_test.go:17`
- `internal/vmtables/stuborder.go:38`

Also:
- `internal/callgraph/callgraph.go:3` — doc comment says `internal/lattice` instead of `callgraph`
- `internal/analysis/context.go:27` — references deleted file `decompile_native_from_main.go`

### F6. applyLocalTypeHints backward-compat wrapper (LOW)

`internal/decompiler/compact.go` retains `applyLocalTypeHints` as a thin wrapper "for backward compatibility with tests." AGENTS-local.md §1b: "Backward compatibility BUKAN alasan. Kode lama mengikuti kode baru, bukan sebaliknya." This wrapper should be inlined at call sites and the function removed.

---

## POSITIVE Findings (Verified)

### P1. SDK constants all verified correct

Verified against dart-lang/sdk via `gh api` at tag 3.12.2:

| Constant | Code | SDK | Match |
|---|---|---|---|
| ARM64 PP | R27 | `PP = R27` | ✓ |
| ARM64 THR | R26 | `THR = R26` | ✓ |
| ARM64 CODE_REG | R24 | `CODE_REG = R24` | ✓ |
| ARM64 HEAP_BITS | R28 | `HEAP_BITS = R28` | ✓ |
| ARM64 NULL_REG | R22 | `NULL_REG = R22` | ✓ |
| ARM64 SPREG | R15 | `SPREG = R15` | ✓ |
| ARM64 ARGS_DESC_REG | R4 | `ARGS_DESC_REG = R4` | ✓ |
| ARM64 FPREG | R29 | `FPREG = FP` | ✓ |
| ARM64 arg regs | {1,2,3,5,6,7} | `{R1,R2,R3,R5,R6,R7}` | ✓ |
| x86_64 PP | R15 | `PP = R15` | ✓ |
| x86_64 THR | R14 | `THR = R14` | ✓ |
| x86_64 CODE_REG | R12 | `CODE_REG = R12` | ✓ |
| x86_64 ARGS_DESC_REG | R10 | `ARGS_DESC_REG = R10` | ✓ |
| x86_64 arg regs | {7,6,2,3,8,9} | `{RDI,RSI,RDX,RBX,R8,R9}` | ✓ |
| kHeapObjectTag | 1 | `kHeapObjectTag = 1` | ✓ |
| kTrueOffsetFromNull | 32 | `kObjectAlignment * 2 = 32` | ✓ |
| kFalseOffsetFromNull | 48 | `kObjectAlignment * 3 = 48` | ✓ |
| ClassIdTagPos V3 | 12 | `kClassIdTagPos=12` | ✓ |
| ClassIdTagSize V3 | 20 | `kClassIdTagSize=20` | ✓ |
| ClassIdTagPos V2 | 16 | `kClassIdTagPos=16` | ✓ |
| ClassIdTagSize V2 | 16 | `kClassIdTagSize=16` | ✓ |

### P2. SDK gates all pass

- **THR check:** 46 tables verified, 0 problems
- **ObjectStore check:** 23 versions verified, 0 mismatches
- **Stub check:** All stub names match SDK (new `-check-stubs` gate)

### P3. Build and unit tests pass

- `go build ./cmd/... ./internal/... ./tools/...` — clean, no errors
- All internal package unit tests pass (sdk 14 tests, decompiler, disasm, typetrack, callgraph, thraudit, vmtables, naming, cluster 4.4s, signal, output, strutil, strxref, ffitrace, dartfmt, snapshot 1.7s, elfx)

### P4. Determinism test passes

`TestGoldenOutputIsDeterministic` — output is byte-identical across two runs (28s). Pipeline is deterministic; golden failure is a content change, not nondeterminism.

### P5. Symtab differential passes (49 samples)

All 49 samples PASS. Rates:
- 3.x samples: 91.4–92.5%
- 2.19.0: 94.4%
- 2.17.6–2.18.0: 86.0–86.3%
- 2.13.0–2.16.0: 81.3–82.4% (worst band, above 0.81 floor)

### P6. Property invariants pass

`TestDecompilerOutputInvariants` (AOTOPSY_PROPERTY=1, 146s):
- dart-3.13.0-arm64: 3000 functions, 99.87% valid, 0 fabrications, 0 unbalanced
- dart-3.13.0-x64: 3000 functions, 100.00% valid, 0 fabrications, 0 unbalanced

### P7. Clean structural refactoring

All 274 files read. Package renames, file moves, and subpackage splits are clean:
- `pipeline`→`analysis`: all imports updated, no leftover active imports (9 stale comments only — F5)
- `lattice`→`callgraph`: types moved, old package deleted, all callers updated
- `disasm`→`thraudit`/`vmtables`: stub/THR tables and classification extracted
- `arch`→`sdk`: register constants, predicates, x86 helpers consolidated
- `decompiler/stmt/` and `decompiler/compare/`: statement passes and comparison tools extracted
- No import cycles (build passes)
- Dead code properly removed: `compact_extra.go` (4 unused functions), `dataflow.go` (forward-join replaced by fixpoint), `lift_x86.go` (moved to `liftx86.go`), `callconv.go` (moved to `sdk.DartArgRegisters`), 5 pipeline files (moved to `naming/stubs.go`)

### P8. Calling convention fix

Old decompiler used C ABI arg registers (x0-x7 / rdi-r9), including R0 (kClassIdReg) and R4 (ARGS_DESC_REG) — NOT argument registers in Dart's convention. New code uses `sdk.DartArgRegisters` (SDK-verified). Also fixed in `disasm/x86.go`: `x86ArgRegCanon` changed from `{7,6,2,1,8,9}` (RCX=1, C ABI wrong) to `{7,6,2,3,8,9}` (RBX=3, Dart convention correct).

### P9. SSA fixpoint (ssa.go, 445 lines)

Replaces forward-join with full reaching-definition fixpoint:
- `runFixpoint`: iterates to convergence (max 24 rounds), monotonic lattice
- `joinStates`: conservative merge — register survives only when ALL predecessors agree
- `seedFromFixpoint`: additive only — never overwrites emission-time values
- `computeLoopPhis`: identifies loop-carried registers with induction discriminator (exactly 1 write + self-reference in loop body)
- `isCleanPhiInit`: rejects raw register tokens as phi initializers
- `declareLoopPhis`/`updatePinnedPhis`: materializes induction locals at loop entry, emits explicit updates at definition sites

### P10. ARM64 decoder deduplication (decoders.go, 394 lines)

15+ duplicated decoder functions across `disasm`, `typetrack`, and `decompiler` consolidated. All bit masks verified against ARM Architecture Reference Manual. All match **except** the MOVOrr bug (F1) and MOVK/MOVN loss (F2).

### P11. Receiver recovery (receiver_recovery.go, 136 lines)

Recovers receiver stack slot for Dart < 3.4.3 (stack-passed `this`). Safety gate: validates loaded register is used as field base at offset the owner class declares. Covers ARM64 (LDR64/LDUR64/LDR32/LDUR32/LDURH) and x86_64 (MOV from [RBP+disp]).

### P12. New verification gates

- `-check-stubs`: verifies stub names against SDK's `stub_code_list.h` — PASS for all versions
- `-check-runtime-entries`: reports runtime entry names from `runtime_entry_list.h`

### P13. Write-barrier elision (both arches)

`sdk.IsWriteBarrierCond`/`sdk.IsWriteBarrierStmt` detect generational write-barrier checks. Emitter elides the branch and the scratch computation. Verified against `assembler_arm64.cc` and `assembler_x64.cc` @3.9.2.

### P14. String literal hoisting (hoist_strings.go, 122 lines)

Hoists repeated long string literals (>40 chars, >1 occurrence) to function-local `const _strN`. Deterministic (first-appearance order, longest-first replacement). Safe: string literals are compile-time constants, no CSE-invariance hazard.

### P15. Accessor field name recovery (context.go)

`buildAccessorFieldNames` recovers instance-field names dropped by AOT precompiler using get:/set: accessor functions. Requires exactly one distinct field displacement in accessor body (unambiguous). Measured 554-1396 real field names per binary.

### P16. PatchClass nil guard

`cmd_export_dart.go` and `funcdiff.go` add nil guard: `if ctEarly != nil && ctEarly.PatchClass != 0` before checking PatchClass. Prevents nil pointer dereference on versions without PatchClass CID.

---

## Complete File Coverage

All 274 changed files read. Non-test source files (219) read in full diff. Test files (55) verified by build + test execution. Summary by area:

| Area | Files | Status |
|---|---|---|
| `cmd/aotopsy/` (40 files) | All read | Import renames, logic extracted to `analysis.*`, deprecated commands removed |
| `internal/analysis/` (17 new files) | All read | Clean extraction from cmd, `AnalysisContext` reusable loader |
| `internal/decompiler/` (30+ files) | All read | SSA fixpoint, phi materialization, stmt/compare subpackages, hoist_strings, sdk constants |
| `internal/disasm/` (14 files) | All read | Decoder dedup to arm64, thraudit/vmtables extraction, dataflow CFG analysis |
| `internal/typetrack/` (12 files) | All read | arm64.* decoders, sdk.DartArgRegisters, receiver_recovery.go |
| `internal/sdk/` (7 new files) | All read | Registers, predicates, stubclass, x86_decode, x86_helpers — all SDK-verified |
| `internal/arch/arm64/` (1 new file) | All read | 394-line decoders.go — **F1/F2 bugs** |
| `internal/cluster/` (8 files) | All read | sdk.ClassIdTag constants, snapshot.VersionAtLeast |
| `internal/callgraph/` (5 files) | All read | lattice merge clean |
| `internal/naming/` (4 files) | All read | stubs.go merge of 4 files, codeowner, naming_utils |
| `internal/thraudit/` (1 new file) | All read | THR classify extracted |
| `internal/vmtables/` (6 files) | All read | THR fields, stub names, stub order moved from disasm |
| `internal/signal/` (4 files) | All read | IsMundaneTHR→sdk.IsMundaneStub |
| `internal/output/` (2 files) | All read | signal dependency removed, category strings duplicated |
| `internal/strutil/` (2 new files) | All read | SanitizeDartIdent, SanitizeLibraryPath, dartmeta |
| `internal/strxref/` (1 file) | All read | analysis.LoadContext usage |
| `internal/symbolmap/` (1 file) | All read | arm64.BL/B, sdk.WalkX86 |
| `internal/funcdiff/` (1 file) | All read | naming.PoolLookups, PatchClass nil guard |
| `internal/ffitrace/` (1 file) | All read | analysis.LoadSnapshot |
| `internal/frida/` (2 new files) | All read | export.go, generator.go extracted from cmd |
| `internal/jsonutil/` (1 new file) | All read | ReadJSONL extracted from naming |
| `internal/cli/` (1 file) | All read | No changes |
| `tools/` (1 file) | All read | -check-stubs, -check-runtime-entries, vmtables paths |
| `scripts/` (3 files) | All read | analyze.sh, gen_coverage.sh new; gen_benchmark.sh path fix |
| `.github/workflows/` (2 files) | All read | fuzz.yml new, release.yml provenance broadened |
| Config files (4) | All read | Makefile path fix, .gitignore cleanup |

---

## Test Execution Log

All tests run with `ulimit -v 2500000` (WSL2 6GB OOM prevention), one heavy test at a time, processes checked between runs via `pgrep`.

| Test | Duration | Result |
|---|---|---|
| `go build ./cmd/... ./internal/... ./tools/...` | 8.8s | PASS |
| `go test ./internal/sdk/` | 0.003s | PASS (14 tests) |
| `go test ./internal/decompiler/` | 0.012s | PASS |
| `go test ./internal/arch/... ./internal/callgraph/... ./internal/thraudit/... ./internal/vmtables/... ./internal/naming/... ./internal/cluster/...` | 4.4s | PASS |
| `go test ./internal/disasm/... ./internal/typetrack/... ./internal/signal/... ./internal/output/...` etc. | 5.1s | PASS |
| `go run tools/extract_thr.go -check` | <1s | PASS (46 tables) |
| `go run tools/extract_thr.go -check-objectstore` | 86s | PASS (23 versions) |
| `go run tools/extract_thr.go -check-stubs` | 31s | PASS (all versions) |
| `go test ./internal/analysis/ -run Golden` | 65s | **FAIL** (2 ARM64 samples) |
| `TestGoldenOutputIsDeterministic` | 28s | PASS |
| `go test ./internal/samplecorpus/ -v` | 1.1s | PASS (93/93 samples) |
| `TestDecompilerOutputInvariants` (AOTOPSY_PROPERTY=1) | 146s | PASS (99.87% valid ARM64, 100% x64, 0 fabrications) |
| `TestSymtabDifferential` | 3.9s | PASS (49 samples, worst 81.3%) |

---

## Recommendations & Resolution Status

1. **Fix F1 (MOVOrr mask) immediately** — **RESOLVED (Commit `69a684d`).** Mask updated from `0xFF20001F` to `0xFF200000` in `internal/arch/arm64/decoders.go`. Restored type propagation across non-X0 registers and reactivated dispatch resolution Pattern 2.x B in `intraproc.go:329`.
2. **Fix F2 (MOVK/MOVN in DstRegOfInst)** — **RESOLVED (Commit `69a684d`).** Mask `0xFF800000` restored to cover MOVZ (`0xD2800000`), MOVK (`0xF2800000`), and MOVN (`0x92800000`).
3. **Fix F4 (LDR reg offset in DstRegOfInst)** — **RESOLVED (Commit `69a684d`).** Added 64-bit (`0xF8607800`, `0xF8606800`, `0xF8600800`) and 32-bit (`0xB8607800`, `0xB8606800`, `0xB8600800`) register-offset LDR, plus LDURH (`0x78400000`).
4. **Fix F7 (CodeEntryPointDisp values)** — **RESOLVED (Commit `69a684d`).** Updated `IsCodeEntryPointDisp` with ground truth SDK displacements `{0x3, 0x7, 0xb, 0xf, 0x17, 0x1f}` accounting for `FieldAddress(base, disp - kHeapObjectTag)` across compressed and uncompressed modes.
5. **Remove `applyLocalTypeHints` wrapper (F6)** — **RESOLVED (Commit `69a684d`).** Wrapper removed from `compact.go` and tests updated to call `localTypeInference` directly.
6. **Update stale documentation references (F5)** — **RESOLVED (Commit `69a684d`).** Replaced all stale references to `internal/pipeline` and `internal/lattice` across 10 codebase files and `.gitignore`.
7. **Re-record golden after fixes (F3)** — **RESOLVED (Commit `6eaa836`).** Golden baselines re-recorded with verified improvements; all golden tests and determinism tests PASS 100%.

| Gate | Final Status | Detail |
|---|---|---|
| Build (`go build ./cmd/... ./internal/... ./tools/...`) | **PASS** | Clean build |
| Unit tests (all packages) | **PASS** | 100% tests passing |
| SDK THR check (`extract_thr.go -check`) | **PASS** | 46 tables, 0 problems |
| SDK ObjectStore check (`extract_thr.go -check-objectstore`) | **PASS** | 23 versions verified |
| SDK Stub check (`extract_thr.go -check-stubs`) | **PASS** | All versions match SDK |
| Golden content & determinism (`golden_test.go`) | **PASS** | All samples match & byte-identical |
| Symtab differential (`symtabdiff_test.go`) | **PASS** | 44 verified samples pass (>0.81 floor) |
