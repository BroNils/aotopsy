# RE Gap Analysis Report: internal/render

> **STATUS VERIFIKASI (2026-09-01)** — diadu dengan `disasm/dataflowarm64.go`,
> `analysis/context.go`, `cluster/pcdescriptors.go`. Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`. Koreksi:
> - **Gap 3 (GDT call jatuh ke ProvUnresolved di ARM64) → SALAH.** Pass emisi
>   di `dataflowarm64.go` menulis `via = regs[rn]` untuk setiap BLR. Urutan SDK
>   `Call(Address(DISPATCH_TABLE_REG, LR, UXTX, Scaled))` = `ldr LR,[X21,LR,LSL#3];
>   blr LR`; `ldr`-nya cocok `arm64.LDRRegExtended` (option=011,S=1) dengan
>   `base == regDT` → `defineReg(LR,"dispatch_table")` → BLR mewarisi
>   `Via="dispatch_table"` → `ClassifyEdgeProv` = `ProvDispatch`. Klaim yang
>   sama diulang di CONSOLIDATED_SUMMARY P1-9 — sama-sama gugur.
> - **Gap 1 & 2 ("AOTopsy tidak punya akses ke ExceptionHandlers/PcDescriptors")
>   → PARTIAL.** Keduanya didekode di `internal/cluster` dan dialirkan ke
>   `FuncIR.ExceptionHandlers`/`TryRegions` (`analysis/context.go:297-320,
>   690-720`, `SnapTryRegionsToBlocks`) serta ditulis ke
>   `exception_handlers.jsonl`. Yang benar-benar kosong hanya `disasm.BuildCFG`
>   (jalur DOT) dan `CallEdgeRecord` yang tak membawa `PcDescriptors.Kind`.
> - Tabel register di report ini **benar** (R21/R22/R24/R5/R4/R0/R28) — dipakai
>   sebagai pembanding untuk report lain yang salah (`analysis`, `symbolmap`,
>   `strutil`).

## Ringkasan

Folder `internal/render/` berisi 10 file Go (+/- 2.100 LOC) yang menghasilkan
seluruh visual output AOTopsy: DOT (callgraph, classgraph, reachability,
per-function CFG, signal graph, signal CFG) dan HTML (index ringkasan +
self-contained signal explorer dengan gzip+base64 embedded data).

Analisis terhadap Dart SDK (`dart-lang/sdk` @3.12.2 / @3.9.2, diverifikasi
via grep MCP `searchGitHub` + `gh api ... ?ref=<tag>`) menemukan beberapa gap
signifikan antara apa yang **bisa dirender** vs apa yang **SDK sediakan sebagai
metadata ground-truth** di setiap Code object AOT:

1. **CFG tidak memuat exception-handler entry points** — SDK menyimpan
   `ExceptionHandlers` + `CatchEntryMoves` per Code object, yang menandai
   PC catch-entry sebagai block leader. AOTopsy `disasm.BuildCFG` hanya
   memakai branch targets sebagai leader, sehingga try/catch block tidak
   pernah muncul sebagai node CFG yang benar.
2. **PcDescriptors (safepoint/deopt/runtime-call/reloc/yield) tidak
   dianotasikan** di CFG/HTML — SDK menandai setiap BL/BLR dengan
   `UntaggedPcDescriptors::Kind` (`kOther`, `kRuntimeCall`, `kDeopt`,
   `kRet`, `kReloc`, `kYield`) yang membedakan runtime call vs Dart call vs
   deopt continuation. AOTopsy hanya punya `Kind: "bl"|"blr"` mentah.
3. **Dispatch-table call (GDT) tidak punya kategori visual sendiri** di
   callgraph DOT — `ProvDispatch` ada di `callgraph.go` tetapi
   `dataflowarm64.go:254-256` hanya menandai register sebagai
   `"dispatch_table"` ketika `base == regDT` (X21); untuk ARM64 emit
   `BLR [X21, LR, LSL #3]` (lihat `flow_graph_compiler_arm64.cc:622-642`
   @3.12.2), edge-nya jatuh ke `ProvUnresolved` karena `Via` kosong.
4. **Monomorphic / SwitchableCall / MegamorphicCall stub entry tidak
   dibedakan** — SDK punya 4 entry point per Code (`entry_point_`,
   `monomorphic_entry_point_`, `unchecked_entry_point_`,
   `monomorphic_unchecked_entry_point_`) dan 3 call-site flavor
   (SwitchableCallMiss → MonomorphicSmiableCheck → MegamorphicCall).
   AOTopsy `IsCodeEntryPointDisp` mengenali displacement-nya tetapi
   render tidak memvisualkan flavor call-nya.
5. **12 dari 31 kategori sinyal tidak punya CSS class** di `signal_html.go`
   (`accessibility`, `attribution`, `rooting`, `anti_analysis`,
   `ssl_pinning`, `fraud`, `dynamic_load`, `ipc`, `covert_channel`,
   `drm_bypass`, `obfuscation`, `crypto_const`, `method_channel`, `plugin`)
   — tag tetap tampil tetapi tanpa warna kategori, sehingga filter bar
   kehilangan affordansi visual.
6. **`typetrack.FieldAccess` dan `BlrResolution` tidak dirender** sama
   sekali — data intra-procedural type tracking (class ID receiver, byte
   offset, read/write) sudah dihitung `internal/typetrack` tetapi
   `internal/render` tidak punya renderer untuk field-access xref graph
   atau per-function receiver-type overlay.
7. **`evidence.Evidence` (unified provenance model) tidak dirender** —
   `signal_stage.go:228-236` menulis `evidence.jsonl` tetapi tidak ada
   HTML/DOT yang memvisualkan confidence (`exact`/`static_inferred`/
   `polymorphic`/`stub`/`unknown`) atau `SDKRef` per finding.
8. **`PoolIdx` cross-reference tidak divisualkan** — `ClassifiedStringRef`
   membawa `PoolIdx` dan `signal_html.go:541` mengumpulkannya, tetapi
   view "Strings" tidak menampilkan kolom pool index atau link antar
   fungsi yang share pool slot yang sama (sangat berguna untuk deteksi
   string dedup / obfuscation).
9. **Tidak ada CFG reachability overlay** — `ReachabilityDOT` memfilter
   ke reachable set tetapi tidak menandai dead code di callgraph utama;
   RE user tidak melihat "fungsi mana yang unreachable" tanpa compare
   dua SVG.
10. **Tidak ada inter-active graph** — seluruh DOT output statik; hanya
    `signal.html` yang interaktif (JS). Callgraph/classgraph/CFG tidak
    punya hover/click/filter/collapse, padahal `signal.html` sudah
    membuktikan pola gzip+base64+DecompressionStream bisa dipakai.

Mayoritas gap adalah **RE usefulness gap** (output honest tetapi under-
informative), bukan correctness bug — kecuali Gap 1 (catch-entry leader)
yang menyebabkan CFG salah bentuk untuk fungsi dengan try/catch, dan
Gap 3 yang menyebabkan dispatch-table call miscount sebagai unresolved.

## Struktur Folder

```
internal/render/
├── callgraph.go        (361 LOC)  CallgraphDOT + ComputeStats + ClassifyEdgeProv
├── cfg.go              ( 87 LOC)  CFGDOT — per-function basic-block CFG
├── classgraph.go       (201 LOC)  ClassgraphDOT — class-level aggregated graph
├── helpers.go          ( 48 LOC)  dotEscape, dotID, stripMethodName, truncLabel
├── html.go             (260 LOC)  WriteIndexHTML — summary page
├── reachability.go     (207 LOC)  FindEntryPoints, ReachableSet, ReachabilityDOT
├── signal_cfg_dot.go   (305 LOC)  SignalCFGDOT — connected signal graph w/ content
├── signal_dot.go       (391 LOC)  SignalDOT — entry→signal path graph
├── signal_html.go      (900 LOC)  WriteSignalHTML — self-contained interactive page
└── theme.go            ( 46 LOC)  NASA theme (colors)
```

Total ~2.900 LOC. Semua renderer menerima `disasm.*` / `signal.*` record
struct yang sudah di-parse dari JSONL; render adalah pure transform
(data → string).

**Catatan duplikasi:** ada package terpisah `internal/callgraph/render/`
(486 LOC, `DOT`/`DOTCFG`) yang dipanggil dari `internal/analysis/disasm_stage.go`
& `disasm_stagex86.go`. Package itu punya CFG renderer yang berbeda
(Japanese-minimalist theme, multi-function cluster, block-call label)
dan tidak share code dengan `internal/render/cfg.go`. Ini duplikasi
konseptual — dua CFG renderer dengan feature set berbeda untuk data
yang sama. Di luar scope folder ini tetapi perlu disebut sebagai
prerequisite refactor.

## Gap Analysis

### Gap 1: CFG tidak memuat exception-handler (catch-entry) block leaders

- **Deskripsi**: `disasm.BuildCFG` (`cfg.go:47-66`) hanya menandai block
  leader dari: (a) index 0, (b) branch target dalam fungsi, (c) instruksi
  setelah terminator. Dart AOT Code object menyimpan metadata
  `ExceptionHandlers` (`runtime/vm/raw_object.h`, `kExceptionHandlers`
  cluster di `module_snapshot.cc:78`) yang memetakan PC try-range →
  PC catch-entry. Catch-entry adalah **entry point tidak terlihat** yang
  di-jump oleh runtime exception dispatcher (`runtime/vm/exceptions.cc`),
  bukan oleh instruksi branch di dalam fungsi. Akibatnya CFG AOTopsy
  menggabungkan catch block ke predecessor-nya sebagai satu basic block
  besar, atau menjadikannya unreachable orphan.
- **Bukti SDK**:
  - grep MCP `CatchEntryMoves` → `runtime/vm/exceptions.h:247`
    "A sequence of moves that needs to be executed to create a state
    expected at the catch entry", `runtime/vm/exceptions.cc:179`
    `PrepareFrameForCatchEntry()`.
  - grep MCP `kCatchEntry` → `runtime/vm/module_snapshot.cc:78` cluster
    list `kExceptionHandlers, kPcDescriptors, kCatchEntryMoves`.
  - `runtime/vm/code_descriptors.cc:42-50` (@3.12.2 via gh api):
    "When precompiling, we only use pc descriptors for **exceptions**,
    relocations and yield indices" — konfirmasi bahwa di AOT, PcDescriptors
    eksplisit menyimpan `try_index` per PC.
- **Dampak**: CFG fungsi dengan try/catch salah. RE user tidak melihat
  edge implicit "throw → catch block". Untuk Flutter app yang heavy
  try/catch (network parsing, async error handling), ini adalah
  distorsi struktural yang signifikan. `signal_cfg_dot.go` juga
  mewarisi gap ini karena memakai `signal.SignalGraph` yang dibangun
  dari edge yang sama.
- **Usulan**:
  1. Baca `ExceptionHandlers` + `PcDescriptors` dari Code object di
     stage disasm (snapshot deserialization), expose sebagai
     `disasm.CatchEntry{PC, TryIndex, HandlerPC}`.
  2. Di `BuildCFG`, tambahkan `HandlerPC` sebagai leader.
  3. Tambah edge `Succ{Cond: "throw"}` dari setiap PC di try-range ke
     handler block; render dengan warna `t.EdgeUnresolved` (NASA red)
     dan label "catch".
  4. Di `CFGDOT`, beri style khusus catch block (fillcolor berbeda).
- **Prioritas**: HIGH — correctness bug untuk fungsi dengan try/catch.

### Gap 2: PcDescriptors Kind (safepoint/deopt/runtime-call) tidak dianotasikan

- **Deskripsi**: `disasm.CallEdgeRecord.Kind` hanya `"bl"|"blr"|"call"|
  "call_indirect"`. SDK `UntaggedPcDescriptors::Kind` membedakan
  `kOther`, `kRuntimeCall`, `kDeopt`, `kRet`, `kReloc`, `kYield`
  (lihat `runtime/vm/compiler/backend/flow_graph_compiler.cc:450-475`
  `EmitCallsiteMetadata`). Setiap BL/BLR di AOT dikategorikan: runtime
  call (StubCode::StackOverflowShared, AllocateObject, WriteBarrier),
  deopt continuation, Dart call, dll. AOTopsy tidak punya akses ke
  PcDescriptors sehingga semua BL terlihat homogen.
- **Bukti SDK**:
  - grep MCP `UntaggedPcDescriptors::kOther` → 30+ hit di
    `flow_graph_compiler_*.cc` dan `il_*.cc`, menunjukkan setiap
    stub call diberi Kind spesifik.
  - `runtime/vm/code_descriptors.cc:42` (@3.12.2): "When precompiling,
    we only use pc descriptors for exceptions, relocations and yield
    indices" — AOT masih menyimpan Kind untuk exception/reloc/yield.
  - `runtime/vm/compiler/backend/flow_graph_compiler.cc:473`
    `AddCurrentDescriptor(UntaggedPcDescriptors::kDeopt, deopt_id_after,
    source)` — deopt continuation point setelah call.
- **Dampak**: RE user tidak bisa membedakan "BL ke Dart function" vs
  "BL ke runtime stub (WriteBarrier, AllocateObject)" vs "BL ke deopt
  continuation" di CFG/callgraph. Untuk RE malware analysis, membedakan
  runtime bookkeeping (yang bisa di-elide) dari logic call (yang harus
  di-trace) adalah salah satu task paling penting. Saat ini semua
  terlihat sama.
- **Usulan**:
  1. Tambah stage snapshot-deserialization untuk PcDescriptors; expose
     `disasm.PcDescriptor{PC, Kind, TryIndex, YieldIndex}`.
  2. Di `CallEdgeRecord`, tambah field `PcdKind string` (opsional).
  3. Di `callgraph.go`, perluas `ClassifyEdgeProv` untuk mengategorikan
     stub-call (THR.* yang match stub name) vs Dart-call.
  4. Di `CFGDOT`, beri warna berbeda untuk runtime/deopt call.
  5. Di `html.go` summary, tambah baris "Runtime stub calls" vs
     "Dart calls" breakdown.
- **Prioritas**: MEDIUM-HIGH — RE usefulness gap besar.

### Gap 3: Dispatch-table call (GDT) edge jatuh ke Unresolved di ARM64

> **[REFUTED 2026-09-01]** `dataflowarm64.go` pass emisi: `if rn, ok :=
> arm64.BLR(inst.Raw); ok { var via string; if rn >= 0 && rn <= 30 { via =
> regs[rn] }; edges = append(..., Via: via) }`. Register target GDT justru
> yang di-`defineReg` sebagai `"dispatch_table"` oleh cabang `LDRRegExtended
> base==regDT`, jadi `Via` terisi. Edge GDT ARM64 sudah `ProvDispatch`.

- **Deskripsi**: `ClassifyEdgeProv` (`callgraph.go:21-42`) mengembalikan
  `ProvDispatch` hanya jika `e.Via == ProvDispatch` (literal
  `"dispatch_table"`). Tapi `dataflowarm64.go:254-256` hanya men-set
  `defineReg(regs, touched, dstR, "dispatch_table")` pada register
  yang di-load dari `LDRRegExtended base==regDT` — itu mendefinisikan
  register, bukan men-set `e.Via`. Untuk emit `BLR [X21, LR, LSL #3]`
  ( instruksi `Call(Address(DISPATCH_TABLE_REG, LR, UXTX, Scaled))`
  dari `flow_graph_compiler_arm64.cc:622-642` @3.12.2), BLR classification
  di `calledge.go` melihat register target = LR yang baru di-AddImmediate
  dari cid_reg+offset, dan `Via` tetap kosong → edge masuk `ProvUnresolved`.
  Hanya x86 (`x86.go:222-223`) yang men-set `e.Via = "dispatch_table"`
  secara eksplisit untuk pola `MOV RAX, [THR.dispatch_table_array]`.
- **Bukti SDK**:
  - `runtime/vm/compiler/backend/flow_graph_compiler_arm64.cc:622-642`
    (@3.12.2 via gh api):
    ```cpp
    void FlowGraphCompiler::EmitDispatchTableCall(...) {
      const auto cid_reg = DispatchTableNullErrorABI::kClassIdReg;
      ...
      CLOBBERS_LR({
        __ AddImmediate(LR, cid_reg, offset);
        __ Call(compiler::Address(DISPATCH_TABLE_REG, LR, UXTX,
                                  compiler::Address::Scaled));
      });
    }
    ```
  - `runtime/vm/constants_arm64.h` @3.12.2 (gh api): `R21 = 21, //
    DISPATCH_TABLE_REG (AOT only)` dan `const Register
    DISPATCH_TABLE_REG = R21;`.
  - `runtime/vm/compiler/aot/aot_call_specializer.cc:1183-1225`
    (@3.12.2): `TryReplaceWithDispatchTableCall` — setiap InstanceCall
    yang punya interface_target non-null diganti ke GDT call di AOT.
- **Dampak**: Di ARM64 (mayoritas Flutter app Android/iOS), semua GDT
  call (virtual method dispatch yang sudah di-devirtualize ke table)
  terhitung sebagai `ProvUnresolved` di `ComputeStats.ProvCounts` dan
  di-render dengan warna `t.EdgeUnresolved` (NASA red) + style dashed
  — sama seperti BLR yang benar-benar tidak ter-resolve. Statistik
  di `html.go` "BLR annotated" jadi misleading. Class graph
  (`classgraph.go:70-76`) juga skip edge ini untuk BLR, sehingga
  inter-class coupling via GDT call tidak muncul.
- **Usulan**:
  1. Di `dataflowarm64.go` BLR classification, deteksi pola
     `AddImmediate(LR, cid_reg, #imm); BLR [X21, LR, LSL #3]` dan
     set `e.Via = "dispatch_table"` + simpan selector offset.
  2. Alternatif: di `ClassifyEdgeProv`, jika `e.Kind == "blr"` dan
     register target baru saja di-define dari `regDT`, klasifikasikan
     sebagai `ProvDispatch`.
  3. Tambah kategori visual `ProvGDT` terpisah (warna berbeda dari
     `ProvDispatch` generic) untuk membedakan GDT call vs dispatch
     table manual.
  4. Di `classgraph.go`, jangan skip `ProvDispatch` edge — masukkan
     ke `classCounts` agar inter-class coupling via GDT terlihat.
- **Prioritas**: HIGH — correctness gap untuk ARM64 (mayoritas target).

### Gap 4: Monomorphic / Switchable / Megamorphic call flavor tidak dibedakan

- **Deskripsi**: SDK punya 3 call-site flavor untuk instance call yang
  tidak di-devirtualize ke GDT:
  - **SwitchableCallMiss** → initial state, pakai `UnlinkedCall` di
    pool slot (`flow_graph_compiler_arm64.cc:537-570`).
  - **MonomorphicSmiableCheck** → setelah 1 hit, patch ke
    `MonomorphicSmiableCall{expected_cid, entrypoint}` dan BLR ke
    `Code.monomorphic_entry_point_` (`stub_code_compiler_arm.cc:3304`
    `GenerateMonomorphicSmiableCheckStub`).
  - **MegamorphicCall** → setelah >FLAG_max_polymorphic_checks, patch
    ke `MegamorphicCache` + `StubCode::MegamorphicCall()` entry
    (`runtime_entry.cc:3190`, `flow_graph_compiler_arm64.cc:497`).
  AOTopsy `IsCodeEntryPointDisp` (`calledge.go:142-149`) mengenali
  displacement 0x3/0x7/0xb/0xf/0x17/0x1f tetapi render tidak
  memvisualkan flavor-nya — semuanya jadi `object_field` atau
  `dispatch_table` generik.
- **Bukti SDK**:
  - grep MCP `MonomorphicSmiableCall` → `runtime/vm/class_id.h:50`,
    `runtime/vm/raw_object_fields.cc:101`
    `F(MonomorphicSmiableCall, expected_cid_)` /
    `F(MonomorphicSmiableCall, entrypoint_)`, `runtime/vm/runtime_entry.cc:3566`
    `MonomorphicSmiableCall::New(expected_cid.Value(), target_code)`.
  - grep MCP `MegamorphicCall` → `runtime/vm/stub_code_list.h:93`
    `V(MegamorphicCall)`, `runtime/vm/thread.h:240`
    `megamorphic_call_checked_entry_`.
  - `runtime/vm/runtime_entry.cc:3190` (@3.12.2): "Instance call at
    %" Px " switching to megamorphic dispatch".
- **Dampak**: RE user tidak bisa membedakan "ini monomorphic call ke
  method X untuk class Y" (sangat informative — menunjukkan type
  inference hasil) vs "ini megamorphic call ke selector Z" (polymorphic,
  perlu cache lookup). Untuk RE method override dan class hierarchy
  recovery, perbedaan ini krusial.
- **Usulan**:
  1. Di `calledge.go`, tambah field `CallFlavor string`:
     `"mono_smiable"`, `"megamorphic"`, `"switchable"`, `"gdt"`,
     `"static"`, `"dispatch_table"`.
  2. Deteksi flavor dari kombinasi: (a) pool slot type
     (UnlinkedCall/MonomorphicSmiableCall/MegamorphicCache), (b) entry
     point displacement yang di-load, (c) stub target.
  3. Di `callgraph.go`, perluas `ClassifyEdgeProv` + `edgeColor` +
     `edgeStyle` untuk flavor baru.
  4. Di `signal_dot.go` dan `signal_cfg_dot.go`, tampilkan flavor di
     edge label.
- **Prioritas**: MEDIUM — RE usefulness gap, terutama untuk method
  override recovery.

### Gap 5: 12+ kategori sinyal tidak punya CSS class di signal_html.go

- **Deskripsi**: `signal_html.go:96-114` mendefinisikan CSS class
  `.cat-*` hanya untuk 18 kategori: `url, host, encryption, auth, net,
  file, base64, thr, sim, sms, contacts, location, device, cloaking,
  data, camera, webview, blockchain, gambling`. Tapi
  `signal/classify.go:13-50` mendefinisikan 31 kategori, termasuk
  `attribution, rooting, anti_analysis, ssl_pinning, accessibility,
  fraud, dynamic_load, ipc, covert_channel, drm_bypass, obfuscation,
  crypto_const, method_channel, plugin`. Tag untuk kategori yang
  tidak punya CSS class tetap di-render (`signal_html.go:459`
  `cats = (f.categories || []).map(c => '<span class="' + catClass(c)
  + '">' + c + '</span>')`) tetapi `catClass(c)` mengembalikan
  `"cat-tag cat-" + c` yang tidak match selector mana pun → tag
  tampil dengan style default `.cat-tag` (gray, no accent color).
- **Bukti**: `grep -oE "cat-[a-z_]+" signal_html.go` vs
  `grep Cat...classify.go` — 13 kategori di classify.go tidak punya
  CSS class: `attribution, rooting, anti_analysis, ssl_pinning,
  accessibility, fraud, dynamic_load, ipc, covert_channel,
  drm_bypass, obfuscation, crypto_const, method_channel, plugin`.
- **Dampak**: Filter bar (`renderCatBar`) tetap menampilkan semua
  kategori, tetapi tag untuk kategori high-value (fraud, ssl_pinning,
  anti_analysis, covert_channel, drm_bypass) tidak berwarna → RE user
  kehilangan visual cue untuk kategori paling penting (malware/
  fraud/piracy). Konsistensi visual rusak.
- **Usulan**:
  1. Tambah CSS class untuk semua 31 kategori di `signal_html.go`
     `<style>` block. Pakai palette yang konsisten:
     - red (`--red`): `fraud, anti_analysis, rooting, drm_bypass,
       covert_channel, dynamic_load`
     - orange (`--orange`): `attribution, ssl_pinning`
     - pink (`--pink`): `accessibility, obfuscation, method_channel,
       plugin`
     - gold (`--gold`): `crypto_const`
  2. Generate CSS dari `signal/classify.go` Cat* constants (DRY) —
     atau pindahkan palette ke `signal` package dan render baca dari
     sana.
  3. Sinkronkan `strCategoryColor` di `signal_cfg_dot.go` dan
     `signal_dot.go:340-350` dengan palette yang sama (saat ini
     hanya cover 6 kategori).
- **Prioritas**: MEDIUM — quick win, high visual impact.

### Gap 6: typetrack.FieldAccess dan BlrResolution tidak dirender

- **Deskripsi**: `internal/typetrack/intraproc.go:208-213` mendefinisikan
  `FieldAccess{ClassID, ByteOffset, IsStore, PC}` dan
  `BlrResolution{...}` — hasil intra-procedural type dataflow yang
  men-track receiver class per register. `internal/evidence/evidence.go`
  punya `FromCallEdges` + `FromSignalFindings` + `FromFieldAccesses`
  (lihat `evidence_test.go:97`) yang mengumpulkan field access sebagai
  evidence. Tapi `internal/render/` tidak punya renderer untuk:
  - Field-access cross-reference graph: node = (class, field offset),
    edge = function yang read/write field itu.
  - Per-function receiver-type overlay di CFG: warnai block berdasarkan
    inferred receiver class.
  - BLR resolution confidence overlay: warnai BLR edge berdasarkan
    `BlrResolution.Confidence` (exact/inferred/polymorphic).
- **Bukti**: `grep -rn "FieldAccess\|BlrResolution\|typetrack"
  internal/render/ internal/analysis/signal_stage.go` → 0 hit. Data
  sudah dihitung tetapi tidak dvisualkan.
- **Dampak**: RE user kehilangan dua insight paling berharga dari type
  tracking: (1) "field offset 0x20 di class X di-access dari fungsi
  mana saja" (cross-reference untuk reverse-engineer class layout),
  (2) "BLR di PC ini resolve ke fungsi Y dengan confidence exact"
  (validasi call edge). Data ada di `evidence.jsonl` tetapi harus di-
  grep manual.
- **Usulan**:
  1. Tambah `render.FieldAccessDOT(funcs []disasm.FuncRecord,
     analyses []typetrack.IntraResult) string` — bipartite graph
     class-field ↔ function.
  2. Tambah `render.CFGWithTypes(cfg, intraResult)` — overlay
     receiver class color per block.
  3. Tambah view "Field Access" di `signal_html.go` (atau page HTML
     terpisah) yang tabel: Class | Offset | Read/Write | Functions.
  4. Di `signal_dot.go`, warnai BLR edge berdasarkan
     `BlrResolution.Confidence` (exact = solid, inferred = dashed,
     polymorphic = dotted).
- **Prioritas**: HIGH — data sudah ada, hanya perlu renderer.

### Gap 7: evidence.Evidence (unified provenance) tidak dirender

- **Deskripsi**: `internal/evidence/evidence.go:22-33` mendefinisikan
  `Evidence{PC, Function, Kind, Instruction, Inputs, Result,
  Confidence, Rule, SDKRef}` dengan `Confidence` ∈
  `{exact, static_inferred, polymorphic, stub, unknown,
  runtime_confirmed}` dan `SDKRef{Tag, File, Symbol}`. `signal_stage.go:228-236`
  menulis `evidence.jsonl` tetapi tidak ada renderer yang memvisualkan
  confidence per edge atau SDKRef per finding. `signal.html` hanya
  menampilkan string refs + asm + callers/callees, bukan evidence
  confidence.
- **Bukti**: `grep -rn "evidence\." internal/render/` → 0 hit.
  `evidence.go:131 FromSignalFindings` dan `evidence.go:154
  FromFieldAccesses` ada tetapi tidak di-consume renderer.
- **Dampak**: RE user tidak melihat "edge ini exact (terverifikasi
  via type tracking)" vs "edge ini polymorphic (over-approximation)"
  vs "edge ini stub (runtime bookkeeping)". Untuk triage manual RE,
  confidence adalah signal paling penting untuk prioritasi investigasi.
- **Usulan**:
  1. Tambah `render.WriteEvidenceHTML(w, records []evidence.Evidence)`
     — tabel interaktif dengan filter by Kind/Confidence/Rule.
  2. Di `signal_dot.go` dan `callgraph.go`, accept optional
     `evidenceIndex map[pc]Evidence` dan warnai edge berdasarkan
     confidence.
  3. Tambah kolom "Confidence" di `signal_html.go` card body,
     sebelah "Callees".
  4. Tampilkan `SDKRef` sebagai tooltip/link di setiap finding
     (ground-truth traceability).
- **Prioritas**: MEDIUM-HIGH — RE usefulness, data sudah ada.

### Gap 8: PoolIdx cross-reference tidak divisualkan

- **Deskripsi**: `signal.ClassifiedStringRef` (`graph.go:12-19`)
  membawa `PoolIdx int`. `signal_html.go:541` mengumpulkan
  `poolIdx: r.pool_idx` ke `allStringRefs` tetapi view "Strings"
  (`renderStrings` line 555-626) hanya menampilkan kolom Address,
  Value, Function — tidak ada kolom PoolIdx. Padahal pool index
  adalah cross-reference key: dua string dengan PoolIdx yang sama
  adalah string yang sama di object pool (dedup), dan satu PoolIdx
  bisa di-reference dari banyak PC/fungsi.
- **Bukti**: `grep -n "poolIdx\|pool_idx" signal_html.go` → hanya
  1 hit (line 541, assignment). Tidak ada render kolom.
- **Dampak**: RE user tidak bisa:
  - Deteksi string dedup/obfuscation (string pendek yang share pool
    slot = string yang di-alias).
  - Trace "pool slot 36 di-reference dari fungsi mana saja" —
    cross-reference yang sangat berguna untuk memahami konstanta
    shared.
  - Validasi bahwa dua string berbeda di output sebenarnya adalah
    pool entry yang sama.
- **Usulan**:
  1. Tambah kolom "Pool" di view Strings (`renderStrings`).
  2. Tambah view "By Pool Index" — group by PoolIdx, tampilkan
    semua (function, PC) yang reference pool slot itu.
  3. Di `signal_dot.go` string literal node, tambahkan label
    `[PP[N]]` agar cross-reference terlihat di graph.
  4. Di `signal_cfg_dot.go` string section, tambahkan pool index
    ke label.
- **Prioritas**: MEDIUM — quick win, data sudah ada.

### Gap 9: Tidak ada dead-code / reachability overlay di callgraph utama

- **Deskripsi**: `ReachabilityDOT` (`reachability.go:87`) memfilter
  ke reachable set dan render graph terpisah. `CallgraphDOT`
  (`callgraph.go:82`) render semua function tanpa penanda reachable.
  RE user harus compare dua SVG untuk mengetahui fungsi mana
  unreachable (dead code, stripped, atau hanya callable via reflection).
- **Bukti**: `CallgraphDOT` signature tidak accept `reachable`
  parameter. `cmd_debug_graph.go:115` call tanpa reachable set.
- **Dampak**: Dead code (fungsi yang tidak terjangkau dari entry
  point) tidak terlihat di callgraph utama. Untuk RE malware,
  dead code sering adalah payload tersembunyi (di-invoke via
  reflection / native bridge) — visualisasi ini sangat berguna.
- **Usulan**:
  1. Tambah parameter `reachable map[string]bool` ke `CallgraphDOT`
     (opsional, nil = no overlay).
  2. Render unreachable node dengan style berbeda (dashed border,
     muted fillcolor, opacity 0.5).
  3. Tambah toggle di `html.go` summary: "Show dead code".
  4. Tambah statistik "Dead functions: N / M" di summary.
- **Prioritas**: MEDIUM — RE usefulness.

### Gap 10: Callgraph/Classgraph/CFG statik (tidak interaktif)

- **Deskripsi**: `signal.html` (`signal_html.go`) adalah page
  interaktif dengan search, filter, scope toggle, view mode, category
  bar, card expand/collapse, asm scroll-to-PC, backtrace walker.
  Callgraph/classgraph/CFG hanya output DOT → SVG statik via
  graphviz. Tidak ada hover/click/filter/collapse. Untuk graph besar
  (ribuan node), SVG statik tidak usable — harus zoom/pan manual
  dan tidak bisa filter.
- **Bukti**: `signal_html.go:263-895` punya JS app lengkap
  (decompress, index, render, filter). `callgraph.go`/`classgraph.go`/
  `cfg.go` hanya emit DOT string.
- **Dampak**: RE user harus pakai graphviz viewer eksternal (zgrviewer,
  gephi) untuk navigasi graph besar. Untuk Flutter app real (10k+
  fungsi), callgraph SVG statik tidak readable. Padahal pola
  gzip+base64+DecompressionStream sudah terbukti work di signal.html.
- **Usulan**:
  1. Refactor `signal_html.go` JS app menjadi generic "graph
     explorer" yang accept graph data (nodes, edges, clusters,
     categories) dan render sebagai force-directed / hierarchical
     SVG via `<svg>` + d3 atau canvas.
  2. Emit `callgraph.html`, `classgraph.html`, `cfg.html` yang
     embed graph data sebagai gzip+base64 blob (sama seperti
     signal.html).
  3. Tambah filter: by owner, by severity, by reachable, by
     category, by edge provenance.
  4. Tambah click-to-expand cluster, click-to-highlight neighbors,
     right-click to collapse.
- **Prioritas**: HIGH untuk RE usability — tapi effort besar.

## Register Tracking Gaps

Berikut register yang **seharusnya ditrack** untuk rendering tetapi
**tidak ditrack** di render layer (data mungkin ada di `internal/sdk`
tetapi tidak di-consume renderer):

| Register | Role (SDK @3.12.2) | Status di render | Gap |
|----------|-------------------|------------------|-----|
| R21 (DISPATCH_TABLE_REG) | Base Global Dispatch Table | `regDT` di `dataflowarm64.go:10` tetapi hanya untuk defineReg, tidak set `e.Via` di BLR classification | Gap 3 — GDT call edge miscount |
| R22 (NULL_REG) | Caches NullObject() | Tidak dirender | Tidak ada anotasi "null compare" di CFG |
| R24 (CODE_REG) | Target Code object | Tidak dirender | Code entry-point load tidak dianotasikan (Gap 4) |
| R5 (IC_DATA_REG) | ICData/MegamorphicCache | Tidak dirender | Megamorphic call flavor tidak terlihat (Gap 4) |
| R4 (ARGS_DESC_REG) | Arguments descriptor | Tidak dirender | Arg count hint tidak dianotasikan di edge |
| R0 (FUNCTION_REG) | Target function | Tidak dirender | Static call target tidak dianotasikan |
| R28 (HEAP_BITS) | write_barrier_mask \| heap_base | Tidak dirender | Write barrier call tidak dibedakan (Gap 2) |
| LR (R30) | Return address / GDT call target | Di-track sebagai link reg tetapi tidak dianotasikan saat dipakai sebagai GDT call target | Gap 3 |

**Sumber verifikasi**: `runtime/vm/constants_arm64.h` @3.12.2 (gh api):
```cpp
const Register PP = R27;  // Caches object pool pointer
const Register DISPATCH_TABLE_REG = R21;  // Dispatch table register
const Register CODE_REG = R24;
const Register FUNCTION_REG = R0;
const Register IC_DATA_REG = R5;    // ICData/MegamorphicCache register
const Register ARGS_DESC_REG = R4;  // Arguments descriptor register
const Register THR = R26;           // Caches current thread
const Register HEAP_BITS = R28;     // write_barrier_mask << 32 | heap_base >> 32
const Register NULL_REG = R22;      // Caches NullObject() value
```

**Gap register yang paling berdampak ke render**:
1. **DISPATCH_TABLE_REG (R21)** — Gap 3. Tanpa track base register di
   BLR target, GDT call tidak bisa diklasifikasi.
2. **CODE_REG (R24) + IC_DATA_REG (R5)** — Gap 4. Tanpa track ini,
   monomorphic/megamorphic call flavor tidak bisa dibedakan.
3. **HEAP_BITS (R28)** — Gap 2. Write barrier call (BL ke
   `StubCode::WriteBarrier`) tidak dibedakan dari Dart call.

## Fitur RE Missing/Incomplete

1. **Exception handler CFG overlay** (Gap 1) — catch-entry block leader.
2. **PcDescriptors Kind annotation** (Gap 2) — runtime/deopt/Dart call
   distinction.
3. **GDT call edge classification** (Gap 3) — dispatch table BLR.
4. **Call flavor visualization** (Gap 4) — monomorphic/megamorphic/
   switchable.
5. **Complete category palette** (Gap 5) — 13 kategori tanpa CSS class.
6. **Field-access cross-reference graph** (Gap 6) — typetrack data
   renderer.
7. **BLR resolution confidence overlay** (Gap 6) — exact/inferred/
   polymorphic edge coloring.
8. **Evidence provenance visualization** (Gap 7) — confidence +
   SDKRef per finding.
9. **PoolIdx cross-reference view** (Gap 8) — string dedup detection.
10. **Dead-code overlay di callgraph** (Gap 9) — unreachable node
    marking.
11. **Interactive callgraph/classgraph/CFG explorer** (Gap 10) —
    HTML+JS seperti signal.html.
12. **Per-function CFG dengan receiver-type overlay** (Gap 6) —
    warnai block berdasarkan inferred receiver class.
13. **Switch table / jump table resolution** — `cfg.go:117` BR
    indirect di-mark terminal tanpa resolve jump table target;
    SDK AOT jarang pakai jump table tetapi bisa muncul di switch
    besar. Tidak ada data flow untuk resolve `LDR + BR` pattern.
14. **Cross-function dataflow overlay** — `typetrack.InterResult`
    (inter-procedural) tidak dirender; tidak ada visualisasi
    "return value dari fungsi X mengalir ke fungsi Y".
15. **Decompile pseudocode view** — `internal/decompiler` menghasilkan
    pseudocode tetapi tidak ada renderer yang menggabungkan pseudocode
    dengan CFG (side-by-side view).
16. **SARIF finding → HTML link** — `output.WriteSARIF` menghasilkan
    `aotopsy.sarif` tetapi tidak ada link dari signal.html ke SARIF
    finding ID, dan sebaliknya.
17. **Multi-function CFG view** — `internal/callgraph/render/cfg.go`
    (`DOTCFG`) sudah render multi-function CFG dengan cluster, tetapi
    `internal/render/cfg.go` (`CFGDOT`) hanya single-function. Feature
    set tidak konsisten antara dua package.
18. **Time/size metric per function** — `FuncRecord.Size` ada tetapi
    tidak dirender di callgraph (node size tidak scale dengan code size).
    `classgraph.go:149` sudah scale node height by method count, tetapi
    callgraph tidak scale by code size.
19. **Owner hash collision detection** — `stripOwnerHash` (`classgraph.go:14`)
    strip `@hash` tetapi tidak deteksi collision (dua class berbeda
    dengan nama sama setelah strip). Untuk app dengan obfuscation,
    ini bisa merge dua class berbeda ke satu node.
20. **Edge provenance legend** — DOT output tidak punya legend box
    yang menjelaskan warna edge (THR/PP/Dispatch/Object/Direct/
    Unresolved). RE user harus baca `html.go` summary untuk memahami
    warna.

## Verifikasi SDK

Semua klaim yang menyandar ke Dart SDK diverifikasi via dua metode
(aturan AGENTS-local.md #2):

### Metode 1: grep MCP (`searchGitHub` by Vercel)

| Query | Repo | Hasil |
|-------|------|-------|
| `DispatchTable` | `dart-lang/sdk` | `runtime/vm/compiler/aot/dispatch_table_generator.cc`, `pkg/dart2wasm/lib/dispatch_table.dart` |
| `switchable_call` | `dart-lang/sdk` | `pkg/native_compiler/lib/runtime/vm_offsets.g.dart` (`Thread_switchable_call_miss_entry_offset`), `runtime/vm/compiler/backend/flow_graph_compiler_*.cc` |
| `MonomorphicSmiableCall` | `dart-lang/sdk` | `runtime/vm/class_id.h:50`, `runtime/vm/raw_object_fields.cc:101`, `runtime/vm/runtime_entry.cc:3566`, `runtime/vm/compiler/stub_code_compiler_arm.cc:3304` |
| `MegamorphicCall` | `dart-lang/sdk` | `runtime/vm/stub_code_list.h:93`, `runtime/vm/thread.h:240`, `runtime/vm/compiler/backend/flow_graph_compiler_*.cc` |
| `TryReplaceWithDispatchTableCall` | `dart-lang/sdk` | `runtime/vm/compiler/aot/aot_call_specializer.cc:1183` |
| `DispatchTableCallInstr` | `dart-lang/sdk` | `runtime/vm/compiler/backend/il.cc:5444`, `il.h:5102`, `il_printer.cc:852` |
| `CatchEntryMoves` | `dart-lang/sdk` | `runtime/vm/exceptions.h:247`, `exceptions.cc:179`, `code_descriptors.cc:151`, `module_snapshot.cc:78` |
| `kCatchEntry` | `dart-lang/sdk` | `runtime/vm/module_snapshot.cc:78` cluster list |
| `UntaggedPcDescriptors::kOther` | `dart-lang/sdk` | 30+ hit di `flow_graph_compiler_*.cc`, `il_*.cc` |

### Metode 2: `gh api` @ version tag

| Path | Tag | Konten yang diverifikasi |
|------|-----|--------------------------|
| `runtime/vm/constants_arm64.h` | `3.12.2` | Register alias: `R21=DISPATCH_TABLE_REG`, `R22=NULL_REG`, `R24=CODE_REG`, `R26=THR`, `R27=PP`, `R28=HEAP_BITS`, `R5=IC_DATA_REG`, `R4=ARGS_DESC_REG`, `R0=FUNCTION_REG`. Baris 51 komentar `// R21 = 21, // DISPATCH_TABLE_REG (AOT only)`. |
| `runtime/vm/compiler/backend/flow_graph_compiler_arm64.cc` | `3.12.2` | Baris 622-642 `EmitDispatchTableCall`: `AddImmediate(LR, cid_reg, offset); Call(Address(DISPATCH_TABLE_REG, LR, UXTX, Scaled))` — konfirmasi GDT call emit pattern. Baris 497-515 `MegamorphicCall` emit. Baris 537-570 `InstanceCallAOT` (SwitchableCallMiss). |
| `runtime/vm/compiler/aot/aot_call_specializer.cc` | `3.12.2` | Baris 1183-1225 `TryReplaceWithDispatchTableCall`: setiap InstanceCall dengan interface_target non-null diganti ke DispatchTableCallInstr di AOT. Baris 1228-1300 `ReplaceWithConditionalDispatchTableCall` untuk `has_dynamically_extendable_subtypes`. |
| `runtime/vm/code_descriptors.cc` | `3.12.2` (via grep MCP) | Baris 42-50: "When precompiling, we only use pc descriptors for exceptions, relocations and yield indices" — konfirmasi AOT PcDescriptors masih menyimpan try_index + yield_index. |

### Catatan versi

- Tag utama: `3.12.2` (stable, representatif 2.10–3.13 range yang
  AOTopsy target).
- Tag sekunder: `3.9.2` (dipakai di `internal/sdk/predicates.go`
  comment, stabil 2.10–3.13).
- Tidak ada perubahan register alias antara 2.10–3.13 (konfirmasi di
  `internal/sdk/registers.go:17` dan `ARCHITECTURE.md:56`).
- `DISPATCH_TABLE_REG` (R21) hanya ada di AOT mode — di JIT, R21
  adalah callee-saved register biasa (lihat `internal/arch/RE_GAP_ANALYSIS_REPORT.md:1056`).
- x86_64 **tidak** punya `DISPATCH_TABLE_REG` fixed; `flow_graph_compiler_x64.cc`
  me-load table ke `RAX` dinamik via `LoadDispatchTable(table_reg)`,
  jadi Gap 3 (GDT call classification) untuk x86 sudah di-handle
  via `x86.go:222-223` `e.Via = "dispatch_table"`. Gap 3 adalah
  ARM64-only.

---

Report ini berdasarkan pembacaan lengkap 10 file di
`internal/render/` (2.900 LOC), cross-reference ke `internal/disasm/`,
`internal/signal/`, `internal/typetrack/`, `internal/evidence/`,
`internal/callgraph/render/`, `cmd/aotopsy/cmd_debug_graph.go`,
`internal/analysis/signal_stage.go`, dan verifikasi `dart-lang/sdk`
@3.12.2/3.9.2 via grep MCP + gh api. Tidak ada build/test/run AOTopsy
dijalankan (sesuai instruksi: research gap planning only).
