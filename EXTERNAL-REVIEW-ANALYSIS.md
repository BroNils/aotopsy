# External Review Analysis — AOTopsy Correctness Gaps & Feature Recommendations

**Date:** 2026-08-30
**Reviewer:** Devin (independent verification against codebase + SDK source via Grep MCP + `gh api`)
**Input:** Three-part external review (ini1: priority order, ini2: correctness gaps, ini3: feature recommendations)
**Scope:** All claims verified for **both ARM64 and x86_64** architectures

---

## Verdict Summary

The external review is **high quality** — the reviewer read the codebase seriously and found real bugs. Two of four correctness claims are **confirmed bugs** (affecting both arches), one is a **cosmetic issue with limited impact**, and one is **partially overstated**. The feature recommendations are ambitious but well-reasoned; the priority order (correctness first) is correct.

| Claim | Verdict | Severity | ARM64 | x86_64 | Pre-existing? |
|---|---|---|---|---|---|
| 1. BLCallSiteTypes key mismatch | **CONFIRMED BUG** | HIGH | Affected | Affected | Yes — not a refactor regression |
| 2. B.AL/B.NV in isCondBranch | **CONFIRMED BUG** | MEDIUM | Affected | N/A (x86 has no AL/NV) | Yes — not a refactor regression |
| 3. seedEntryState / inferLiveInArgIndices | **PARTIALLY TRUE** — cosmetic, limited impact | LOW | Affected | Affected | Yes |
| 4. Heuristic type tracking too aggressive | **PARTIALLY TRUE** — one sub-claim confirmed (x86 only), others overstated | LOW-MEDIUM | Not affected | x86 only | Yes |
| Quick-win: SARIF filename | **CONFIRMED** — `aotopsy.sarif` in README vs `report.sarif` in code | LOW | Both | Both | Yes |

---

## Detailed Verification (Both Architectures)

### Claim 1: BLCallSiteTypes key mismatch — CONFIRMED BUG (HIGH, both arches)

**What the reviewer claims:** `BLCallSiteTypes` is written with callee target address as key, but read with call-site PC as key. This means the lookup almost always misses, falling back to `ExitTypes` which is already killed post-BL.

**Verification — ARM64:**

Write — `internal/typetrack/intraproc_handlers_call.go:157`:
```go
target, ok := arm64.BL(raw, tc.inst.Addr)  // target = callee function entry VA
tc.result.BLCallSiteTypes[target] = callSiteState  // KEY = callee VA
```

Read — `internal/typetrack/interproc.go:360`:
```go
if cs, ok := callerAnalysis.Intra.BLCallSiteTypes[edge.CallPC]; ok {  // KEY = BL instruction VA
```

edge.CallPC is set in `internal/analysis/typetrack_stage.go:434`:
```go
CallPC: inst.Addr,  // ARM64: BL instruction address
```

**Verification — x86_64:**

Write — `internal/typetrack/intraprocx86.go:726`:
```go
callTarget = inst.VA + uint64(inst.Len) + uint64(int64(rel))  // callee VA
result.BLCallSiteTypes[callTarget] = *state  // KEY = callee VA
```

edge.CallPC is set in `internal/analysis/typetrack_stage.go:468`:
```go
CallPC: inst.VA,  // x86: CALL instruction address
```

**Conclusion (both arches):** Write key = callee target VA. Read key = BL/CALL instruction VA. These are **different addresses** — a BL instruction at 0x1000 calling a function at 0x2000 writes `BLCallSiteTypes[0x2000]` but the interprocedural pass reads `BLCallSiteTypes[0x1000]`. The lookup **always misses** on both architectures.

**Impact (both arches):** Inter-procedural parameter type propagation via `BLCallSiteTypes` is **completely dead** on both ARM64 and x86_64. The fallback to `ExitTypes` is used instead, but `ExitTypes` has argument registers as Top because BL/CALL kills them and exit blocks don't restore them. This means callee parameter types are never propagated from callers on either architecture.

**Additional issue (both arches):** Two call sites to the same callee overwrite each other (same target VA = same key). Even if the key were correct, only the last call site's state would survive.

**Pre-existing:** This bug existed before the refactor on both arches. AGENTS.md's "Known limits" section mentions three BLR dispatch bugs that were fixed, but this BL parameter propagation bug was not among them.

**Fix (both arches):** Change the write key from `target`/`callTarget` (callee VA) to `tc.inst.Addr` (ARM64) / `inst.VA` (x86) — the BL/CALL instruction address, matching the read key. For the overwrite issue, use a slice or map keyed by call-site VA.

---

### Claim 2: B.AL/B.NV in isCondBranch — CONFIRMED BUG (MEDIUM, ARM64 only)

**What the reviewer claims:** `isCondBranch` in `intraproc_decoders.go` treats all B.cond encodings as conditional (with fall-through), but `DecodeBranch` in `disasm/branch.go` correctly handles AL=14 and NV=15 as unconditional.

**Verification — ARM64:**

`isCondBranch` — `internal/typetrack/intraproc_decoders.go`:
```go
func isCondBranch(raw uint32, pc uint64) ([]uint64, bool) {
    if raw&0xFF000010 == 0x54000000 {
        // NO CHECK for cond == 14 (AL) or cond == 15 (NV)
        return []uint64{target}, true  // always returns conditional=true
    }
```

`DecodeBranch` — `internal/disasm/branch.go` (correct):
```go
if raw&0xFF000010 == 0x54000000 {
    if cond := raw & 0xF; cond == 14 || cond == 15 {
        return &branchInfo{Target: ...}  // unconditional — NO Cond: true
    }
    return &branchInfo{Target: ..., Cond: true}  // conditional
}
```

Caller — `internal/typetrack/intraproc.go:728`:
```go
if targets, ok := isCondBranch(inst.Raw, inst.Addr); ok {
    for _, t := range targets { leaders[t] = true }
    if i+1 < len(insts) { leaders[insts[i+1].Addr] = true }  // PHANTOM fall-through
}
```

**Verification — x86_64:**

x86_64 uses `x86.IsCondJump(d.Inst.Op)` in `intraprocx86.go:267` — this checks the opcode directly (JE, JNE, JA, etc.). x86 has **no equivalent of AL/NV** — every conditional jump opcode is genuinely conditional. JMP is unconditional and handled separately. **x86_64 is NOT affected by this bug.**

**Conclusion:** ARM64 only. B.AL/B.NV in typetrack's CFG gets **two successors** (target + fall-through) when it should have **one** (target only). The fall-through edge is phantom. x86_64 is correct.

**Impact (ARM64 only):** AGENTS.md documents this appeared 28148 times in the 2.12 sample. Type propagation can flow through impossible edges. The decompiler's `liftarm64.go` uses `disasm.DecodeBranch` (correct), but the type tracker's `buildBlocks` uses `isCondBranch` (incorrect) — so pseudocode output is correct but type inference is corrupted at these sites.

**Fix (ARM64 only):** Add `if cond := raw & 0xF; cond == 14 || cond == 15 { return nil, false }` at the start of the B.cond case in `isCondBranch`, or delegate to `disasm.DecodeBranch`.

---

### Claim 3: seedEntryState / inferLiveInArgIndices — PARTIALLY TRUE (LOW, both arches)

**What the reviewer claims:** `seedEntryState` seeds all `ArgRegs` even when `ArgRegIndices` only declares a subset. `inferLiveInArgIndices` returns contiguous `0..maxIdx` even though Dart args can be sparse.

**Verification — ARM64:**

`seedEntryState` — `internal/decompiler/ssa.go`:
```go
for ri := 0; ri < len(fir.ArgRegs); ri++ {  // ArgRegs = 8 ARM64 registers
    s.setReg(fir.ArgRegs[ri], fmt.Sprintf("arg%d", ri))
}
```
Seeds all 8 ARM64 ArgRegs (x0-x7). **True.**

`inferLiveInArgIndices` — `internal/decompiler/arity.go`:
```go
idx := make([]int, maxIdx+1)
for i := 0; i <= maxIdx; i++ { idx[i] = i }
return idx  // contiguous 0..maxIdx
```
Returns contiguous range. **True.**

**Verification — x86_64:**

Same `seedEntryState` code — seeds all 6 x86_64 ArgRegs (rdi, rsi, rdx, rbx, r8, r9). Same `inferLiveInArgIndices` — contiguous `0..maxIdx`. **True.**

**But (both arches):** `seedFromFixpoint` is **additive only**:
```go
for reg, val := range st.Regs {
    if _, known := e.state.Regs[reg]; !known {
        e.state.Regs[reg] = val  // only fill if unknown
    }
}
```

The emitter assigns arg names via `ArgRegIndices` or `inferLiveInArgIndices` **before** the fixpoint runs. The over-seeded values are never used because the emitter's own values take priority.

**Conclusion (both arches):** Technically true but **impact is cosmetic** — extra `argN` names in the fixpoint are invisible in output. Not a correctness bug on either architecture.

---

### Claim 4: Heuristic type tracking too aggressive — PARTIALLY TRUE (LOW-MEDIUM, x86 only for confirmed sub-claim)

**4a. "Field unknown fallback to class holder"** — **NOT FOUND in code** on either arch. No code path falls back to class holder for unknown fields. The field type resolver returns 0 (unknown) when no type is found.

**4b. "ADD as dispatch index without proof"** — **OVERSTATED** on both arches. The ADD/SUB scan in `intraproc.go` only fires for specific patterns: `rd == 30` (LR), `rd == 0`, or `rd == rn` (self-modifying). These are exact Dart compiler idioms for dispatch table calls, not blind assumptions.

**4c. "x86 LEA [THR+disp] as dispatch table without field check"** — **CONFIRMED, x86_64 only.**

`internal/disasm/dataflowx86.go:327-331`:
```go
case sdk.X86THR:
    if thrFields != nil {
        if name, ok := thrFields[int(mem.Disp)]; ok {
            x86Define(regs, touched, dstIdx, "THR."+name)
        } else {
            x86Define(regs, touched, dstIdx, "dispatch_table")  // AGGRESSIVE FALLBACK
        }
    } else {
        x86Define(regs, touched, dstIdx, "dispatch_table")  // AGGRESSIVE FALLBACK
    }
```

When a THR-relative load has an **unknown** field offset on x86_64, it falls back to `"dispatch_table"`. An unknown THR field could be anything (runtime entry, object store, etc.), not necessarily the dispatch table.

**ARM64 comparison:** `dataflowarm64.go` does NOT have this fallback. ARM64 only marks `"dispatch_table"` for explicit `LDR [X21, Xm, LSL #3]` (dispatch table register pattern with scaled index). Unknown THR loads on ARM64 are handled by annotators and fall through to `ObjectFieldViaAt(off)` — honest "unknown" rather than "dispatch_table".

**4d. "THR non-callable as KnownStub"** — **OVERSTATED on both arches.**

ARM64 — `intraproc_handlers.go:234`:
```go
tc.state[rt] = KnownStub(stubName, byteOff)  // stubName could be ""
```

x86_64 — `intraprocx86.go`:
```go
state[dstIdx] = KnownStub(stubName, byteOff)  // stubName could be ""
```

Both arches set `KnownStub` with potentially empty `stubName` when the THR offset is not in the stub table. **BUT:** the BLR handler on both arches checks `sn != ""` before using the stub name:
- ARM64: `else if sn != "" && !strings.HasPrefix(sn, "Allocate")...`
- x86_64: `if strings.HasPrefix(sn, "Allocate")...` (empty string doesn't match)

An empty `KnownStub` is effectively a "THR-sourced but unknown" marker — it's not used as a call target. The claim that "THR field non-callable still represented as KnownStub" is technically true (the lattice kind is `KnownStub`), but the empty name prevents it from being resolved as a callable target. **Not a correctness bug — just a lattice state that could be more precise.**

**Conclusion:** One sub-claim (4c) is confirmed — x86_64 only. ARM64 is not affected. The others are either not found (4a), overstated (4b, 4d), or describe intentional pattern matching.

---

### Quick-win: SARIF filename — CONFIRMED (LOW, both arches)

**README.md:221:** `| aotopsy.sarif | SARIF 2.1.0 security finding report |`
**Code (signal_stage.go:222):** `sarifPath := filepath.Join(inDir, "report.sarif")`
**Code (sarif.go:236):** `path := filepath.Join(dir, "report.sarif")`

**Conclusion:** Documentation says `aotopsy.sarif`, code writes `report.sarif`. Affects both arches (same signal stage runs for both). Fix: update README to say `report.sarif`, or change code to write `aotopsy.sarif`.

---

## Feature Recommendations Assessment (Both Arches)

### 1. SDK Evidence Explorer — HIGH VALUE, MEDIUM EFFORT

Valid product direction. Should follow after correctness fixes. The `call_edges.jsonl` already has `Target` + `Candidates` + `Via` for both arches, but consumers (render, signal) still use `Via` as target for indirect calls. A `ResolvedTargets(edge)` helper is a good quick win for both arches.

### 2. ABI-aware FPU/SIMD — HIGH VALUE, HIGH EFFORT (both arches)

**SDK verification via Grep MCP (both arches):**
- ARM64: `kFpuRegistersForArgs[] = {V0, V1, V2, V3, V4, V5}` — `constants_arm64.h` @3.12.2
- ARM64 FPU return: V0
- x86_64: `kFpuRegistersForArgs[] = {XMM1, XMM2, XMM3, XMM4, XMM5, XMM6}` — `constants_x64.h` @3.12.2
- x86_64 FPU return: XMM0
- ARM32 (for reference): `kFpuRegistersForArgs[] = {Q0, Q1, Q2, Q3}` — different from ARM64
- IA32: `kCpuRegistersForArgs[] = {kNoRegister}` — no register args at all

Currently only GPR is modeled on both arches. Double/float/SIMD code (Flutter geometry, animation, typed_data) gets no type recovery on either arch. This is the largest analysis gap affecting both architectures equally.

### 3. Soundness/confidence layer — MEDIUM VALUE, MEDIUM EFFORT (both arches)

Current binary resolved/unresolved is too coarse for both arches. Categories like `exact`, `static_inferred`, `polymorphic`, `unknown` with rule provenance would improve trust. The regression tests the reviewer suggests are valuable for both arches:
- Two BL to same callee with different types (both arches)
- B.AL/B.NV without fall-through (ARM64 only — x86 has no equivalent)
- Branch join defining register on one side only (both arches)
- Field load with holder class different from field value (both arches)
- x86 THR+offset that is not a stub (x86 only)
- x86 pool-loaded Code, UnlinkedCall, and type-testing stub (x86 only)

### 4. SDK-check CLI — LOW VALUE, LOW EFFORT (both arches)

`-check` gates already exist in `extract_thr.go` for both arches (46 THR tables, 23 ObjectStore versions). Quick win: wrap into clean `aotopsy sdk-check` command.

### 5. Semantic binary diff — MEDIUM VALUE, HIGH EFFORT (both arches)

`funcdiff` currently only compares function descriptors on both arches. Full diff is a significant feature. The identity scheme (library URI + code ref + owner + name + body hash) is sound for both arches.

### 6. Static ↔ runtime evidence loop — MEDIUM VALUE, MEDIUM EFFORT (both arches)

`frida-import` exists for both arches. Merging runtime evidence into the static model is the natural next step. Depends on evidence model (feature 1) being in place first.

### 7. Source recovery gaps — CONFIRMED, MIXED PRIORITY (both arches)

- **CompressedStackMaps not consumed by emitter:** Confirmed — `fir.StackMaps` is populated for both arches but `emit.go`/`emit_walk.go` never read it. Documented as FP-1 future work.
- **x86 pool load parity:** The reviewer claims x86 doesn't have `PoolCodeNames`, `UnlinkedCall`, and TTS resolution at parity with ARM64. The staged changes added `UnlinkedCall` BLR enhancement and `MethodNameToSelectorOffsets` for both arches, but full parity needs further verification.

---

## Recommended Priority Order (Both Arches)

### Phase 0: Correctness fixes (do first, both arches)
1. **Fix BLCallSiteTypes key mismatch** (Claim 1) — both ARM64 and x86_64. Change write key from callee VA to call-site VA.
2. **Fix B.AL/B.NV in isCondBranch** (Claim 2) — ARM64 only. Add cond==14/15 check.
3. **Fix SARIF filename** (Quick win) — both arches. Align README and code.
4. **Fix x86 THR fallback to dispatch_table** (Claim 4c) — x86_64 only. Use `"THR.fNN"` or `"unknown_thr"` instead.

### Phase 1: Evidence & confidence (both arches)
5. **ResolvedTargets helper** (Quick win) — both arches. Unify indirect call target resolution.
6. **Confidence categories** (Feature 3) — both arches. `exact`/`inferred`/`polymorphic`/`unknown`.
7. **Regression tests** (Feature 3) — both arches. See test list above.

### Phase 2: ABI & analysis depth (both arches)
8. **FPU/SIMD register modeling** (Feature 2) — both arches. V0-V5 (ARM64), XMM1-XMM6 (x86_64), FPU return V0/XMM0.
9. **CompressedStackMaps emitter consumption** (Feature 7) — both arches. Dead-store elimination.
10. **x86 pool load parity** (Feature 7) — x86_64. Verify and close gaps with ARM64.

### Phase 3: Product features (both arches)
11. **SDK Evidence Explorer** (Feature 1) — both arches.
12. **SDK-check CLI** (Feature 4) — both arches.
13. **Semantic binary diff** (Feature 5) — both arches.
14. **Static ↔ runtime loop** (Feature 6) — both arches.

---

## SDK Ground Truth References (verified via Grep MCP + gh api)

| Fact | SDK Source | Tag | Arch | Method |
|---|---|---|---|---|
| ARM64 GPR args: R1,R2,R3,R5,R6,R7 | `constants_arm64.h` | 3.12.2 | ARM64 | gh api |
| ARM64 FPU args: V0-V5 | `constants_arm64.h` | 3.12.2 | ARM64 | Grep MCP |
| ARM64 FPU return: V0 | `constants_arm64.h` | 3.12.2 | ARM64 | Grep MCP |
| x86_64 GPR args: RDI,RSI,RDX,RBX,R8,R9 | `constants_x64.h` | 3.12.2 | x86_64 | gh api |
| x86_64 FPU args: XMM1-XMM6 | `constants_x64.h` | 3.12.2 | x86_64 | Grep MCP |
| x86_64 FPU return: XMM0 | `constants_x64.h` | 3.12.2 | x86_64 | Grep MCP |
| EmitDispatchTableCall exists for all arches | `flow_graph_compiler_*.cc` | main | Both | Grep MCP |
| Dispatch table call uses cid_reg + table_reg | `flow_graph_compiler_arm64.cc` | main | ARM64 | Grep MCP |
| Dispatch table call uses RAX as table_reg | `flow_graph_compiler_x64.cc` | main | x86_64 | Grep MCP |
| ARM32 FPU args: Q0-Q3 (different from ARM64) | `constants_arm.h` | main | N/A | Grep MCP |
| IA32 has no register args (kNoRegister) | `constants_ia32.h` | main | N/A | Grep MCP |
| FieldAddress(base, disp - kHeapObjectTag) | `assembler_arm64.h`, `assembler_x64.h` | 3.12.2 | Both | Grep MCP |
| kHeapObjectTag = 1 | `pointer_tagging.h` | 3.12.2 | Both | gh api |
| kTrueOffsetFromNull = 32, kFalseOffsetFromNull = 48 | `pointer_tagging.h` | 3.12.2 | Both | gh api |
| Write-barrier: ARM64 tst(HEAP_BITS, LSR, 32) | `assembler_arm64.cc` | 3.9.2 | ARM64 | Grep MCP |
| Write-barrier: x86 andl(THR, write_barrier_mask) | `assembler_x64.cc` | 3.9.2 | x86_64 | Grep MCP |
