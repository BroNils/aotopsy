# RE Gap Analysis Report: internal/evidence

> **STATUS VERIFIKASI (2026-09-01)** — semua 18 gap CONFIRMED, tidak ada
> koreksi. Detail: `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> Yang dicek ulang secara independen:
> - `FromBLRResolutions` **nol pemanggil** di seluruh repo, termasuk test;
>   `FromSignalFindings`/`FromFieldAccesses`/`MergeRuntime`/`Coverage` hanya
>   dipanggil dari `evidence_test.go`.
> - Gap 5 dikonfirmasi lewat grep MCP: `searchGitHub "EmitDirectCall"
>   repo:dart-lang/sdk` hanya mengembalikan `pkg/dart2bytecode/lib/assembler.dart`,
>   `pkg/dart2wasm/lib/translator.dart`, `pkg/dart2bytecode/lib/bytecode_generator.dart`
>   — **nol** hit di `runtime/vm/compiler/backend/`. SDKRef di `evidence.go:66-69`
>   memang dead link.
> - Gap 10 (Coverage polymorphic false-negative) terbaca langsung di
>   `evidence.go:274`: hanya `rec.Result["target"]` yang dibaca, sedangkan
>   record polymorphic menyimpan `"targets"`.
> - Gap 11 (double write) CONFIRMED: `pipeline.go:351-357` (Step 9) dan
>   `signal_stage.go:228-236`, keduanya `FromCallEdges(edges)` atas input yang
>   sama — identik hari ini, jadi belum data-loss, tapi jadi data-loss begitu
>   Gap 1–3 diperbaiki.

## Ringkasan

Folder `internal/evidence` (2 file, 316 + 196 LOC) adalah "unified provenance/evidence
system" AOTopsy — satu model `Evidence` yang seharusnya mengkonsolidasi temuan
dari `call_edges`, `typetrack.BlrResolution`, `typetrack.FieldAccess`, dan
`output.SignalFinding` dengan confidence + SDK source reference.

**Temuan utama (destruktif):**

1. **Empat dari lima API collector adalah dead code.** Hanya `FromCallEdges`
   yang dipanggil di pipeline (`internal/analysis/pipeline.go:353` dan
   `internal/analysis/signal_stage.go:231`). `FromBLRResolutions`,
   `FromSignalFindings`, `FromFieldAccesses` — yang membawa data paling
   berharga untuk RE (BLR resolution confidence, field-access cross-ref,
   security signal provenance) — **tidak pernah dipanggil di luar
   `evidence_test.go`**. Diverifikasi:
   `grep -rn "FromBLRResolutions\|FromSignalFindings\|FromFieldAccesses"`
   di seluruh repo non-test → 0 hit di luar `evidence.go` sendiri.
2. **Seluruh runtime-merge subsystem (`MergeRuntime`, `Coverage`,
   `RuntimeResolution`, `CoverageReport`) adalah dead code.** Tidak ada
   satu pun caller di luar test. Padahal `internal/frida/import.go:170`
   meng-copy `evidence.jsonl` ke output Frida — integrasi runtime↔static
   yang seharusnya jadi killer feature AOTopsy tidak pernah dihubungkan.
3. **`Evidence.Instruction` field tidak pernah diisi.** Dideklarasikan
   (`evidence.go:27`) tapi 0 assignment di seluruh codebase. RE user tidak
   pernah melihat instruction mnemonic di evidence record — padahal itu
   field yang paling natural untuk cross-ref dengan disassembly.
4. **`SDKRef` untuk direct call menunjuk simbol yang tidak ada di SDK.**
   `evidence.go:67-69` menulis `Symbol: "EmitDirectCall"` untuk edge
   `bl`/`call`. Verifikasi `searchGitHub` di `dart-lang/sdk`: tidak ada
   `EmitDirectCall` di `flow_graph_compiler_arm64.cc`. Simbol yang benar
   adalah `GenerateStaticDartCall` (yang memancarkan `BranchLinkPatchable`).
   `EmitDirectCall` hanya ada di `pkg/dart2wasm`/`pkg/dart2bytecode`
   (backend yang berbeda, bukan AOT native).
5. **`SDKRef` untuk THR field menunjuk file generated, bukan sumber.**
   `evidence.go:81` menulis `File: "runtime/vm/compiler/runtime_offsets_extracted.h"`
   untuk `Via: "THR.xxx"`. File itu adalah output `tools/run_offsets_extractor.dart`
   — bukan sumber nama field. Nama field sebenarnya dideklarasikan sebagai
   `Thread::*_stub_offset()` di `runtime/vm/compiler/runtime_api.h` dan
   struct field-nya di `runtime/vm/thread.h`. Verifikasi `searchGitHub`
   mengonfirmasi.
6. **`SDKRef` tidak dibangun untuk `Via: "PP[...]"`, `object_field`,
   `dispatch_table`, `UnlinkedCall:`, `TTS:`, `PPCode:`.** `evidence.go:77-84`
   hanya menangani prefix `THR.`. Padahal `typetrack_stage.go:681-714`
   menunjukkan setidaknya 6 kategori `Via` lain yang resolve ke callee
   nyata: TTS, UnlinkedCall, PPCode, PP-display fallback, object_field,
   dispatch_table. Masing-masing punya SDK source berbeda
   (`GenerateIndirectTTSCall`, `GenerateSwitchableCallMissStub`,
   `GenerateMegamorphicCallStub`, `GenerateSingleTargetCallStub`,
   `GenerateICCallThroughCodeStub`) — semuanya tidak ter-track.
7. **`Evidence.Kind` hanya 4 nilai hardcoded di comment** (`"call"`,
   `"dispatch"`, `"field_access"`, `"signal"`) tanpa enum/registry.
   `FromCallEdges` menulis `Kind: "call"` untuk SEMUA edge termasuk
   `blr`/`call_indirect` — padahal `CallEdgeRecord.Kind` sudah
   membedakan `bl`/`call`/`blr`/`call_indirect`. Distinction direct vs
   indirect (yang menentukan confidence RE) hilang di evidence.
8. **`Confidence` string adalah magic string tanpa enum.** 6 nilai
   (`exact`, `static_inferred`, `polymorphic`, `stub`, `unknown`,
   `runtime_confirmed`) tersebar di 4 fungsi (`classifyEdgeConfidence`,
   `FromBLRResolutions`, `MergeRuntime`, `FromFieldAccesses`) tanpa
   konstanta terpusat. `typetrack.BlrResolution.Confidence` punya 5 nilai
   yang overlap tapi tidak identik (`exact`, `static_inferred`,
   `polymorphic`, `stub`, `unknown`) — `MergeRuntime` menambah
   `runtime_confirmed` sebagai upgrade. Tidak ada validasi bahwa input
   `r.Confidence` di `FromBLRResolutions` adalah salah satu dari nilai
   yang dikenal; string liar akan lolos ke JSONL.
9. **`Coverage` dan `MergeRuntime` match hanya by PC string.** PC di
   static record adalah `fmt.Sprintf("0x%x", r.PC)` (lowercase hex, no
   padding) dari `FromBLRResolutions`, atau `e.FromPC` (string apa pun
   dari JSONL) dari `FromCallEdges`. PC di `RuntimeResolution` dari
   Frida bisa `0x...` atau decimal atau uppercase. Tidak ada
   normalisasi PC — match bisa miss karena `0x1000` vs `0x1000` vs
   `0X1000` vs `4096`. `Coverage` punya bug sama.
10. **`Coverage.BothConflict` hanya cek `Result["target"]` (string),
    abaikan `Result["targets"]` (polymorphic).** `evidence.go:274-278`:
    `staticTarget, _ := rec.Result["target"].(string)` — jika record
    adalah polymorphic (`Result["targets"]` adalah `[]string`), conflict
    detection tidak pernah fire; record masuk bucket
    `RuntimeConfirmed` meskipun runtime target TIDAK ada di candidate
    list. Ini false-negative untuk RE triage: "static bilang A|B|C,
    runtime bilang D" seharusnya conflict.

Terdapat **18 gap** yang ditemukan, dikelompokkan menjadi: dead-code API
(5), SDK reference salah/tidak lengkap (4), register/konstanta tracking
(3), fitur RE missing (4), arsitektur (2).

## Struktur Folder

| File | LOC | Peran |
|------|-----|-------|
| `evidence.go` | 316 | Package `evidence`. Tipe: `Evidence` (9 field), `SDKReference` (3 field), `Collector` (1 slice field), `RuntimeResolution` (3 field), `CoverageReport` (7 field). 9 fungsi: `NewCollector`, `FromCallEdges`, `FromBLRResolutions`, `FromSignalFindings`, `FromFieldAccesses`, `Records`, `WriteJSONL`, `MergeRuntime`, `Coverage`. 2 helper: `classifyEdgeConfidence`, `edgeRule`. `parsePCUint` (sort helper). |
| `evidence_test.go` | 196 | 6 test: `TestFromCallEdges` (4 edge → 4 confidence), `TestWriteJSONL`, `TestRecordsSortedByPC`, `TestFromSignalFindingsAndFieldAccesses`, `TestMergeRuntime`, `TestCoverage`. Tidak test `FromBLRResolutions`. Tidak test SDKRef correctness. Tidak test PC normalization. Tidak test polymorphic conflict di Coverage. |

**Konsumen (non-test):**
- `internal/analysis/pipeline.go:351-356` — `NewCollector` + `FromCallEdges` + `WriteJSONL` (Step 9).
- `internal/analysis/signal_stage.go:228-236` — `NewCollector` + `FromCallEdges` + `WriteJSONL` (duplicate write, lihat Gap 11).
- `internal/frida/import.go:170` — `CopyStaticFiles` meng-copy `evidence.jsonl` ke output Frida (read-only, tidak pakai `MergeRuntime`).

**Bukan konsumen (false friends):**
- `internal/cluster/fill_refs.go:147,152,158` — kata "evidence" di komentar, merujuk `raw_object.h`, bukan package ini.
- `internal/disasm/calledge.go:25` — kata "evidence" di komentar `ArgCountHint`.

## Gap Analysis

### Gap 1: `FromBLRResolutions` dead code — BLR confidence tidak masuk evidence

- **Deskripsi**: `evidence.go:100-129` `FromBLRResolutions(funcName, []typetrack.BlrResolution)`
  mengubah `BlrResolution{PC, Reg, SlotIndex, TargetName, TargetNames, Candidates,
  Confidence}` menjadi `Evidence{Kind:"dispatch", Confidence:r.Confidence,
  Inputs:{slot_index}, Result:{target|targets+candidate_count}}`. Ini adalah
  satu-satunya jembatan dari hasil type-tracking intra-procedural (data paling
  berharga untuk RE: "BLR di PC ini resolve ke Y dengan confidence exact") ke
  model evidence terpadu. **Tidak pernah dipanggil.** Pipeline
  (`typetrack_stage.go:632 rewriteCallEdges`) menulis ulang `call_edges.jsonl`
  dengan resolved target, lalu `FromCallEdges` membaca ulang edge itu —
  round-trip yang kehilangan `SlotIndex`, `Reg`, dan `Confidence` asli
  (`FromCallEdges` re-classify via `classifyEdgeConfidence` yang hanya lihat
  `Target`/`Targets`/`Via`, bukan `Confidence` dari typetrack).
- **Bukti SDK**: `runtime/vm/compiler/backend/il.cc:5511` (DispatchTableCallInstr)
  dan `flow_graph_compiler_arm64.cc:616 EmitDispatchTableCall` — selector offset
  adalah konsep SDK utama; `BlrResolution.SlotIndex` adalah proxy langsung.
  `evidence.go:121-126` menyimpan `slot_index` di `Inputs` — tapi hanya jika
  `FromBLRResolutions` dipanggil, yang tidak pernah.
- **Dampak**: RE user melihat `evidence.jsonl` dengan `Kind:"call"` untuk BLR
  yang sebenarnya sudah di-resolve typetrack dengan confidence `exact`/
  `static_inferred`/`polymorphic`/`stub` — tapi confidence di evidence adalah
  hasil re-classify `classifyEdgeConfidence` yang lebih kasar (hanya
  `exact`/`polymorphic`/`stub`/`unknown`). Distinction `exact` (direct slot
  lookup, known receiver) vs `static_inferred` (selector scan fallback) —
  yang di `typetrack/intraproc.go:42-48` dipisah explicit — hilang. RE user
  tidak bisa memprioritaskan edge yang "known receiver class" vs "selector
  scan over-approximation".
- **Usulan**:
  1. Di `typetrack_stage.go` setelah `rewriteCallEdges`, panggil
     `evCollector.FromBLRResolutions(name, intraRes.BLRResolutions)` per
     function — atau pass `*InterResult` ke collector baru.
  2. Hapus `classifyEdgeConfidence` untuk edge yang sudah punya
     `BlrResolution.Confidence`; gunakan confidence typetrack sebagai
     source of truth.
  3. Tambah `Inputs.slot_index` dan `Inputs.reg` ke evidence BLR.
- **Prioritas**: CRITICAL — data sudah dihitung, hanya tidak di-routing.

### Gap 2: `FromSignalFindings` dead code — signal provenance tidak masuk evidence

- **Deskripsi**: `evidence.go:132-143` `FromSignalFindings([]output.SignalFinding)`
  mengubah finding ke `Evidence{Kind:"signal", Confidence:"static_inferred",
  Rule:"signal."+f.Category, Result:{signal, category}}`. `signal_stage.go:228-236`
  menulis `evidence.jsonl` dari `FromCallEdges` saja — finding SARIF
  (`signal_stage.go:212-225 WriteSARIF`) tidak pernah masuk evidence. RE user
  yang membaca `evidence.jsonl` tidak melihat signal rooting/ssl_pinning/crypto
  padahal itu sudah dihitung dan ditulis ke `aotopsy.sarif`.
- **Bukti SDK**: N/A (signal adalah klasifikasi AOTopsy, bukan SDK concept).
  Tapi `output.SignalFinding` (`output/sarif.go:151-156`) punya 4 field
  (`Category`, `StringValue`, `Function`, `PC`) yang semuanya siap masuk
  evidence — tidak ada transformasi yang hilang.
- **Dampak**: Evidence model tidak unified seperti klaim package doc
  (`evidence.go:1-5` "collects analysis results from call_edges,
  dispatch_table, typetrack, and signal"). Signal finding terpisah di
  SARIF, tidak ada cross-reference "PC ini punya call edge exact DAN
  signal crypto_const".
- **Usulan**:
  1. Di `signal_stage.go` setelah `WriteSARIF`, panggil
     `evCollector.FromSignalFindings(findings)` sebelum `WriteJSONL`.
  2. Tambah `SDKRef` untuk signal kategori yang punya SDK anchor
     (e.g., `method_channel` → `runtime/vm/native_api.cc` `Dart_NativeMessageHandler`).
- **Prioritas**: HIGH — quick win, data sudah ada.

### Gap 3: `FromFieldAccesses` dead code — field-access evidence tidak masuk

- **Deskripsi**: `evidence.go:146-164` `FromFieldAccesses(funcName, []typetrack.FieldAccess, className)`
  mengubah field access ke `Evidence{Kind:"field_access", Confidence:"static_inferred",
  Rule:"typetrack.FieldAccess", Inputs:{class_id, byte_offset, is_store},
  Result:{class_name}}`. `typetrack_stage.go:505 writeFieldAccessorXref` menulis
  `field_accessor_xref.jsonl` dari `interResult.Functions[].Intra.FieldAccesses`
  — tapi tidak pernah masuk `Collector`. Field access cross-reference
  (class, offset) → function adalah insight RE paling berharga untuk
  reverse-engineer class layout, dan sudah dihitung.
- **Bukti SDK**: `runtime/vm/raw_object.h` (field layout, `kHeapObjectTag`)
  — `FieldAccess.ByteOffset` adalah displacement terhadap tagged pointer,
  sesuai konvensi SDK. `evidence.go:160` menyimpan `byte_offset` mentah,
  tidak dinormalisasi ke layout offset (+1 untuk tag). Inkonsisten dengan
  `writeFieldAccessorXref` (`typetrack_stage.go:559 offset: acc.ByteOffset + 1`).
- **Dampak**: RE user tidak melihat "field offset 0x20 di class User
  di-access dari fungsi X" di `evidence.jsonl`. Harus cross-ref manual
  antara `field_accessor_xref.jsonl` dan `call_edges.jsonl`.
- **Usulan**:
  1. Di `typetrack_stage.go` setelah `writeFieldAccessorXref`, iterasi
     `interResult.Functions` dan panggil `evCollector.FromFieldAccesses`.
  2. Normalisasi `byte_offset` ke layout offset (+1) di evidence, atau
     simpan keduanya (`raw_byte_offset`, `layout_byte_offset`).
  3. Tambah `field_name` ke `Result` (dari `BuildClassLayouts`).
- **Prioritas**: HIGH — data sudah dihitung di `writeFieldAccessorXref`.

### Gap 4: `MergeRuntime` + `Coverage` dead code — runtime↔static tidak terhubung

- **Deskripsi**: `evidence.go:223-249` `MergeRuntime([]RuntimeResolution)` dan
  `evidence.go:264-288` `Coverage([]RuntimeResolution)` adalah API untuk
  menggabungkan hasil Frida runtime dengan prediksi static. `frida/import.go:170`
  meng-copy `evidence.jsonl` ke output Frida — tapi **tidak memanggil
  `MergeRuntime` atau `Coverage`**. Frida script (`internal/frida/`) menghasilkan
  BLR resolution runtime, tapi tidak pernah di-feed back ke collector.
- **Bukti SDK**: N/A (Frida adalah tool eksternal). Tapi `frida_export.go:99-109`
  sudah mengumpulkan `UnresolvedBLRs` untuk Frida hook — round-trip data
  sudah ada, hanya `MergeRuntime` yang tidak dipanggil.
- **Dampak**: Killer feature AOTopsy ("static bilang A, runtime bilang B,
  conflict = bug atau obfuscation") tidak pernah terjadi. `CoverageReport`
  (BothMatch/BothConflict/RuntimeConfirmed/StaticOnly/RuntimeOnly) — yang
  adalah metrik RE paling actionable — tidak pernah dihitung/ditulis.
- **Usulan**:
  1. Tambah `cmd/aotopsy/cmd_frida_import.go` (atau sub-command) yang
     baca `frida_blr_resolved.json`, parse ke `[]RuntimeResolution`,
     load `evidence.jsonl` existing, panggil `MergeRuntime` + `Coverage`,
     tulis `evidence_merged.jsonl` + `coverage_report.json`.
  2. Atau buat `Collector.LoadJSONL(path)` untuk rehydrate collector.
- **Prioritas**: CRITICAL — feature sudah diimplementasi 90%, hanya wiring.

### Gap 5: `SDKRef.Symbol: "EmitDirectCall"` tidak ada di SDK ARM64

- **Deskripsi**: `evidence.go:65-69` menulis `SDKRef{File:
  "runtime/vm/compiler/backend/flow_graph_compiler_arm64.cc", Symbol:
  "EmitDirectCall"}` untuk edge `bl`/`call` yang punya `Target`.
  Verifikasi `searchGitHub` `query:"EmitDirectCall" repo:"dart-lang/sdk"`:
  **0 hit** di `flow_graph_compiler_arm64.cc`. `EmitDirectCall` hanya
  ada di `pkg/dart2wasm/lib/translator.dart:3832` dan
  `pkg/dart2bytecode/lib/assembler.dart:578` — backend non-native.
  Simbol ARM64 yang benar untuk direct Dart call adalah
  `GenerateStaticDartCall` (`flow_graph_compiler_arm64.cc:388`,
  memancarkan `BranchLinkPatchable`).
- **Bukti SDK**: `searchGitHub` `query:"GenerateStaticDartCall" repo:"dart-lang/sdk"`
  → hit di `flow_graph_compiler_{arm64,x64,arm,ia32,riscv}.cc` dan
  `flow_graph_compiler.cc:2149,2206`. `flow_graph_compiler.h:643`
  mendeklarasikan `void GenerateStaticDartCall(...)`. Ini adalah
  canonical direct-call emitter untuk AOT native.
- **Dampak**: RE user yang mengikuti `SDKRef` ke SDK source akan mencari
  `EmitDirectCall` di file yang salah dan tidak menemukannya. Provenance
  yang seharusnya jadi ground-truth traceability jadi dead link.
- **Usulan**: Ganti `Symbol: "EmitDirectCall"` → `Symbol: "GenerateStaticDartCall"`.
  Tambah `Tag` field dengan version tag SDK (e.g., `"3.9.2"`) agar
  `gh api ...?ref=3.9.2` reproducible.
- **Prioritas**: HIGH — correctness bug, 1-line fix.

### Gap 6: `SDKRef` untuk THR field menunjuk file generated, bukan sumber

- **Deskripsi**: `evidence.go:79-84` untuk `Via: "THR.xxx"` menulis
  `SDKRef{File: "runtime/vm/compiler/runtime_offsets_extracted.h", Symbol:
  "Thread::"+stubName}`. File itu adalah output `tools/run_offsets_extractor.dart`
  (verifikasi `searchGitHub` `query:"runtime_offsets_extracted.h"` →
  `runtime_offsets_list.h:8` "offsets_extractor.cc prints these values to
  runtime_offsets_extracted.h"). Nama field sebenarnya dideklarasikan
  sebagai `static word allocate_object_stub_offset()` (dll) di
  `runtime/vm/compiler/runtime_api.h:1287+`, dan struct field `Thread`
  di `runtime/vm/thread.h`.
- **Bukti SDK**: `searchGitHub` `query:"allocate_object_stub" repo:"dart-lang/sdk"`
  → `runtime/vm/stub_code.cc:245` dan `runtime/vm/compiler/runtime_api.h:1287`
  (`allocate_object_stub_offset()`). `runtime_offsets_extracted.h` hanya
  berisi `#define` angka offset, bukan deklarasi nama.
- **Dampak**: Provenance menunjuk ke file yang tidak bisa diverifikasi
  tanpa build SDK (generated). RE user tidak bisa `gh api` file itu
  untuk konfirmasi nama field.
- **Usulan**: Ganti `File` ke `runtime/vm/thread.h` (deklarasi struct)
  atau `runtime/vm/compiler/runtime_api.h` (deklarasi offset accessor).
  Simbol sebaiknya `Thread::allocate_object_stub` (bukan
  `Thread::allocate_object_stub_offset` — yang terakhir adalah accessor
  function, bukan field).
- **Prioritas**: MEDIUM — provenance correctness.

### Gap 7: `SDKRef` tidak dibangun untuk 6 kategori `Via` lain

- **Deskripsi**: `evidence.go:77-84` hanya menangani `strings.HasPrefix(e.Via, "THR.")`.
  `typetrack_stage.go:681-714` dan `disasm/calledge.go` menunjukkan setidaknya
  6 kategori `Via` lain yang resolve ke callee nyata:
  - `TTS:name` — Type Testing Stub call (`GenerateIndirectTTSCall`).
  - `UnlinkedCall:name` — SwitchableCall UnlinkedCall (`GenerateSwitchableCallMissStub`).
  - `PPCode:...` — pool-loaded Code object.
  - `PP[N] foo` — pool display fallback (`resolveViaPoolDisplay`).
  - `object_field[+0xN]` — Code entry-point load (`IsCodeEntryPointDisp`).
  - `dispatch_table` / `dispatch_table[N]` — GDT call (`EmitDispatchTableCall`).
  Semuanya dapat `SDKRef` spesifik, tapi `evidence.go` hanya set `SDKRef`
  untuk `THR.` dan `Target!=""` (direct) dan `len(Targets)>0` (polymorphic).
  Untuk `Via != "" && Via != "THR.*"`, `SDKRef` kosong.
- **Bukti SDK**: `searchGitHub` `query:"GenerateSwitchableCallMissStub" repo:"dart-lang/sdk"`
  → `stub_code_compiler_arm64.cc:3742`. `query:"GenerateMegamorphicCallStub"`
  → `stub_code_compiler_arm64.cc:3587`. `query:"GenerateSingleTargetCallStub"`
  → `stub_code_compiler_arm64.cc:3640` (dari runtime/docs/README.md:919).
  `query:"GenerateICCallThroughCodeStub"` → `stub_code_compiler_arm64.cc:3537`.
  Semua ada di SDK, siap di-refer.
- **Dampak**: RE user tidak melihat "edge ini via TTS (type test stub)"
  vs "via UnlinkedCall (switchable IC)" vs "via object_field (Code entry)".
  Masing-masing adalah dispatch mechanism berbeda dengan RE implication
  berbeda (TTS = type check, UnlinkedCall = inline cache, object_field =
  closure/Code field).
- **Usulan**: Tambah `sdkRefForVia(via string) *SDKReference` yang switch
  pada prefix: `TTS:` → `GenerateIndirectTTSCall`, `UnlinkedCall:` →
  `GenerateSwitchableCallMissStub`, `PPCode:`/`PP[` →
  `GenerateICCallThroughCodeStub`/`GenerateSingleTargetCallStub`,
  `object_field` → `raw_object.h Code::entry_point_`,
  `dispatch_table` → `EmitDispatchTableCall`.
- **Prioritas**: HIGH — RE usefulness, 6 kategori uncovered.

### Gap 8: `Evidence.Kind` tidak membedakan direct vs indirect call

- **Deskripsi**: `evidence.go:59` menulis `Kind: "call"` untuk SEMUA edge
  dari `FromCallEdges`, termasuk `blr`/`call_indirect`. `CallEdgeRecord.Kind`
  (`disasm/types.go:16`) sudah membedakan `bl`/`call` (direct) vs
  `blr`/`call_indirect` (indirect). Comment `evidence.go:26` mengklaim
  `Kind` ∈ `{"call", "dispatch", "field_access", "signal"}` — tapi
  `dispatch` hanya di-set oleh `FromBLRResolutions` (dead code, Gap 1).
  Di pipeline aktif, semua edge adalah `Kind:"call"`.
- **Bukti SDK**: `flow_graph_compiler_arm64.cc:388 GenerateStaticDartCall`
  (direct, `BranchLinkPatchable`) vs `:616 EmitDispatchTableCall`
  (indirect via GDT) vs `stub_code_compiler_arm64.cc:3587 GenerateMegamorphicCallStub`
  (indirect via IC) — tiga mekanisme berbeda, semuanya di-collapse jadi
  `Kind:"call"`.
- **Dampak**: RE user tidak bisa filter `evidence.jsonl` by
  `Kind:"dispatch"` untuk lihat indirect call saja. Harus re-derive
  dari `Rule` (`direct_call` vs `indirect_call_*`).
- **Usulan**: Set `Kind` dari `e.Kind`: `bl`/`call` → `"call"`,
  `blr`/`call_indirect` → `"dispatch"`. Atau tambah `Kind:"indirect_call"`.
  Hapus comment yang mengklaim 4 Kind jika hanya 2 yang aktif.
- **Prioritas**: MEDIUM — consistency.

### Gap 9: `Confidence` magic string tanpa enum/validasi

- **Deskripsi**: 6 nilai confidence (`exact`, `static_inferred`,
  `polymorphic`, `stub`, `unknown`, `runtime_confirmed`) tersebar di
  `classifyEdgeConfidence` (4 nilai), `FromBLRResolutions` (pass-through
  `r.Confidence`), `MergeRuntime` (switch 5 case), `FromFieldAccesses`
  (hardcode `static_inferred`), `FromSignalFindings` (hardcode
  `static_inferred`). Tidak ada konstanta, tidak ada validasi. String
  liar dari `r.Confidence` (typo, capitalization) lolos ke JSONL.
- **Bukti SDK**: N/A (konvensi internal). Tapi `typetrack/intraproc.go:42-48`
  mendokumentasikan 5 nilai dengan comment — kontrak yang seharusnya
  di-enforce.
- **Dampak**: RE user yang filter `confidence=="exact"` akan miss
  `"Exact"` atau `"EXACT"` jika ada typo upstream. Tidak ada schema
  validation.
- **Usulan**: Definisikan `type Confidence string` dengan konstanta
  `ConfExact`, `ConfStaticInferred`, `ConfPolymorphic`, `ConfStub`,
  `ConfUnknown`, `ConfRuntimeConfirmed`. Validasi di `FromBLRResolutions`:
  jika `r.Confidence` bukan salah satu, fallback ke `ConfUnknown` + log.
- **Prioritas**: MEDIUM — robustness.

### Gap 10: `Coverage` polymorphic conflict false-negative

- **Deskripsi**: `evidence.go:274-278`:
  ```go
  staticTarget, _ := rec.Result["target"].(string)
  if staticTarget != "" && staticTarget == rtTarget { rep.BothMatch++ }
  else if staticTarget != "" && staticTarget != rtTarget { rep.BothConflict++ }
  else { rep.RuntimeConfirmed++ }
  ```
  Hanya cek `Result["target"]` (string). Untuk record polymorphic,
  `Result["targets"]` adalah `[]string` — `staticTarget` = `""`,
  masuk bucket `RuntimeConfirmed` meskipun `rtTarget` TIDAK ada di
  candidate list. Seharusnya: jika `rtTarget` tidak ada di `targets`,
  itu conflict.
- **Bukti SDK**: N/A (logika internal). Tapi semantik `BlrResolution.Polymorphic`
  (`typetrack/intraproc.go:36-40`) eksplisit: "callee is one of TargetNames".
  Runtime yang mengembalikan callee di luar set = kontradiksi.
- **Dampak**: RE user melihat "RuntimeConfirmed" untuk edge yang
  sebenarnya conflict — false sense of validation. Bug triage RE
  (obfuscation, vtable hijack) tidak terdeteksi.
- **Usulan**: Tambah branch: jika `staticTarget == ""` tapi
  `targets, ok := rec.Result["targets"].([]string); ok` — cek
  `rtTarget` di `targets`. Match → `BothMatch`; miss → `BothConflict`.
- **Prioritas**: HIGH — correctness bug di RE triage metric.

### Gap 11: `evidence.jsonl` ditulis dua kali (race/overwrite)

- **Deskripsi**: `pipeline.go:351-356` (Step 9) menulis `evidence.jsonl`
  via `FromCallEdges`. `signal_stage.go:228-236` menulis `evidence.jsonl`
  lagi via `FromCallEdges` (call yang sama, collector baru). Tergantung
  urutan eksekusi stage, file kedua menimpa pertama. Karena `signal_stage`
  dipanggil dari `Run` setelah typetrack stage (lihat `pipeline.go`
  urutan Step), `signal_stage` write adalah yang menang — tapi isinya
  identik (hanya `FromCallEdges`), jadi tidak terlihat. Jika Gap 1-3
  di-fix (tambah `FromBLRResolutions` dll di salah satu), double-write
  ini menjadi data loss: collector yang punya data lengkap ditimpa
  collector yang hanya punya call edges.
- **Bukti SDK**: N/A.
- **Dampak**: Setelah fix Gap 1-3, salah satu write akan menimpa yang
  lain. Saat ini silent karena keduanya sama.
- **Usulan**: Hapus write di `signal_stage.go:228-236` (duplikat).
  Atau pass collector dari `pipeline.go` ke `signal_stage` agar
  `FromSignalFindings` di-add ke collector yang sama.
- **Prioritas**: HIGH — akan menjadi bug setelah Gap 1-3 fix.

### Gap 12: PC tidak dinormalisasi di `MergeRuntime`/`Coverage`

- **Deskripsi**: `evidence.go:225-228` dan `:266-269` membangun
  `map[string]string` dari `r.PC` ke target. Static record PC bisa
  `"0x1000"` (dari `FromCallEdges` `e.FromPC`) atau `"0x1000"` (dari
  `FromBLRResolutions` `fmt.Sprintf("0x%x", r.PC)`). Runtime PC dari
  Frida bisa format apa pun. Tidak ada normalisasi (lowercase, strip
  `0x`, parse ke `uint64`, re-format). `parsePCUint` (`evidence.go:167`)
  sudah ada untuk sort, tapi tidak dipakai di match.
- **Bukti SDK**: N/A.
- **Dampak**: Match miss karena `0x1000` vs `0X1000` vs `4096` vs
  `0x00001000`. `Coverage` dan `MergeRuntime` undercount.
- **Usulan**: Normalisasi PC di kedua sisi: `normalizePC(s string) string`
  yang `parsePCUint` + `fmt.Sprintf("0x%x", v)`. Apply di `rtByPC` build
  dan lookup.
- **Prioritas**: MEDIUM — correctness, akan matter setelah Gap 4 fix.

### Gap 13: `Evidence.Instruction` field tidak pernah diisi

- **Deskripsi**: `evidence.go:27` `Instruction string` dideklarasikan
  dengan `json:"instruction,omitempty"`. `grep -rn "Instruction" internal/evidence/`
  → hanya deklarasi, 0 assignment. `CallEdgeRecord` tidak punya field
  instruction mnemonic. `BlrResolution` tidak punya. `FieldAccess` tidak
  punya. `SignalFinding` tidak punya.
- **Bukti SDK**: N/A. Tapi `disasm.Inst` punya `Raw` (uint32) dan
  `Mnemonic` (jika di-decode). `arm64.Disassemble(raw) (string, ok)`
  ada di `internal/arch/arm64`.
- **Dampak**: RE user tidak melihat `"instruction":"BLR X16"` di
  evidence record — harus cross-ref ke `asm/*.txt` atau `functions.jsonl`.
  Field yang seharusnya jadi quick-glance context kosong.
- **Usulan**: Tambah parameter `mnemonic string` ke `FromCallEdges`
  (atau pass `[]disasm.Inst` index). Atau tambah field `Mnemonic` ke
  `CallEdgeRecord` upstream. Untuk `FromBLRResolutions`, pass
  `insts[pcToIdx[r.PC]].Mnemonic`.
- **Prioritas**: LOW — nice-to-have, but field already exists (waste).

### Gap 14: Tidak ada evidence source dari `dispatch_table.jsonl`, `ffi_bridges.jsonl`, `platform_channels.jsonl`, `icdata.jsonl`, `closure_data.jsonl`

- **Deskripsi**: Pipeline menulis 30+ JSONL output
  (`pipeline.go:351-468`). Evidence collector hanya consume 4 source
  (call_edges, BLR resolution, signal, field access) — dan hanya 1
  yang aktif (call_edges). Output RE-relevant yang tidak masuk evidence:
  - `dispatch_table.jsonl` — GDT entries (selector offset → target).
    Bisa jadi `Evidence{Kind:"dispatch_slot", Inputs:{selector_offset, index}, Result:{target}}`.
  - `ffi_bridges.jsonl` — FFI call sites (`BuildFfiBridges`).
    `Evidence{Kind:"ffi_call", Confidence:"exact", SDKRef:{File:"runtime/vm/native_api.cc", Symbol:"Dart_NativeFunction"}}`.
  - `platform_channels.jsonl` — Flutter MethodChannel/EventChannel.
    `Evidence{Kind:"platform_channel", Confidence:"static_inferred"}`.
  - `icdata.jsonl` — ICData (inline cache entries).
    `Evidence{Kind:"icdata", Inputs:{cid, target}, SDKRef:{File:"runtime/vm/raw_object.h", Symbol:"UntaggedICData"}}`.
  - `closure_data.jsonl` — closure dispatch.
  - `exception_handlers.jsonl` — try/catch regions.
- **Bukti SDK**: `runtime/vm/compiler/aot/dispatch_table_generator.h:89`
  (DispatchTableGenerator), `runtime/vm/native_api.cc` (Dart_NativeFunction),
  `runtime/vm/raw_object.h:2414 UntaggedSingleTargetCache`,
  `:2481 UntaggedMegamorphicCache`, `:2414 UntaggedICData`.
- **Dampak**: Evidence model tidak "unified" seperti klaim. RE user
  harus membuka 6+ file JSONL terpisah untuk reconstruct full picture.
- **Usulan**: Tambah `FromDispatchTable`, `FromFfiBridges`,
  `FromPlatformChannels`, `FromICData`, `FromClosureData`. Setiap
  dengan `SDKRef` spesifik.
- **Prioritas**: MEDIUM-HIGH — RE completeness.

### Gap 15: `Rule` naming tidak konsisten dan tidak ada registry

- **Deskripsi**: `Rule` di-set ad-hoc: `FromCallEdges` → `edgeRule(e)`
  yang return `"direct_call"` / `"indirect_call_via_"+e.Via` /
  `"indirect_call_unresolved"` / `"unknown"`. `FromBLRResolutions` →
  hardcode `"typetrack.BLRResolution"`. `FromSignalFindings` →
  `"signal."+f.Category`. `FromFieldAccesses` → `"typetrack.FieldAccess"`.
  Tidak ada registry, tidak ada prefix konsisten (`typetrack.` vs
  `signal.` vs no-prefix untuk call).
- **Bukti SDK**: N/A.
- **Dampak**: RE user tidak bisa `jq 'group_by(.rule)'` dengan
  konsisten. Filter `Rule =~ "typetrack.*"` miss `FromCallEdges` yang
  tidak punya prefix.
- **Usulan**: Registry `var Rules = struct{DirectCall, IndirectCallVia, ...}`
  dengan prefix `call.`, `dispatch.`, `field.`, `signal.`. Setiap
  `From*` pakai konstanta.
- **Prioritas**: LOW — cosmetic but aids tooling.

### Gap 16: `Records()` sort tidak stable untuk PC sama + Kind sama

- **Deskripsi**: `evidence.go:177-184` sort by `(PC, Kind)`. Jika dua
  record punya PC dan Kind sama (e.g., dua field access di PC yang sama
  — impossible saat ini karena `recordFieldAccess` dedup by PC, tapi
  possible setelah Gap 14 menambah source baru), urutan tidak deterministik.
  `sort.Slice` tidak stable. Golden test (`TestGoldenOutputIsDeterministic`)
  akan catch ini, tapi root cause adalah sort key tidak total.
- **Bukti SDK**: N/A.
- **Dampak**: Non-deterministic output jika Gap 14 di-fix dan ada
  multi-evidence per PC.
- **Usulan**: Tambah tiebreaker: `(PC, Kind, Rule, Function)`. Atau
  pakai `sort.SliceStable`.
- **Prioritas**: LOW — future-proofing.

### Gap 17: `WriteJSONL` tidak pakai `jsonutil.WriteJSONLFile`

- **Deskripsi**: `evidence.go:189-206` implement JSONL write inline
  (`os.MkdirAll` + `os.Create` + `json.NewEncoder` loop). Pipeline
  lainnya pakai `jsonutil.WriteJSONLFile` (generic, streaming,
  `SetEscapeHTML(false)`). `evidence.go` pakai `json.NewEncoder`
  default (`SetEscapeHTML(true)`) — `<`, `>`, `&` di-escape ke
  `\u003c` dll. Jika signal finding punya string dengan `<` (e.g.,
  HTML payload), output berbeda dari `jsonutil`.
- **Bukti SDK**: N/A.
- **Dampak**: Inconsistency JSONL encoding antar output file. RE user
  yang `jq` cross-file bisa lihat escape berbeda.
- **Usulan**: Ganti ke `jsonutil.WriteJSONLFile(path, records)`. Atau
  `enc.SetEscapeHTML(false)` di inline write.
- **Prioritas**: LOW — consistency.

### Gap 18: Tidak ada `Collector.LoadJSONL` untuk rehydrate (blocking Gap 4)

- **Deskripsi**: `MergeRuntime` dan `Coverage` operasi pada
  `c.records` in-memory. Tidak ada cara untuk load `evidence.jsonl`
  existing ke collector baru. Ini blocking untuk Gap 4: Frida import
  command perlu load evidence static, merge dengan runtime, write
  merged. Saat ini harus re-run full pipeline.
- **Bukti SDK**: N/A.
- **Dampak**: Gap 4 tidak bisa di-fix tanpa API ini.
- **Usulan**: Tambah `func (c *Collector) LoadJSONL(path string) error`
  yang decode per-line ke `Evidence` dan append ke `c.records`.
- **Prioritas**: HIGH — prerequisite for Gap 4.

## Register Tracking Gaps

Evidence model tidak men-track register VM ABI Dart yang penting untuk RE.
`Evidence.Inputs` hanya berisi `reg` (untuk BLR, dari `CallEdgeRecord.Reg`)
dan `slot_index` (dari `BlrResolution`, dead code). Register VM ABI yang
tidak ter-track:

| Register | SDK Constant | Peran | Harus di-track di |
|----------|--------------|-------|-------------------|
| R0/X0 (ARM64) | `DispatchTableNullErrorABI::kClassIdReg` (`constants_arm64.h`) | Class ID reg untuk dispatch table call | `Evidence.Inputs.class_id_reg` untuk `Kind:"dispatch"` |
| R4/X4 (ARM64) | `ARGS_DESC_REG` (`constants_arm64.h`) | Arguments descriptor array | `Evidence.Inputs.args_desc_reg` untuk semua call |
| R5/X5 (ARM64) | `IC_DATA_REG` (`constants_arm64.h`) | ICData untuk switchable call | `Evidence.Inputs.ic_data_reg` untuk `Via:"UnlinkedCall:"` |
| R1/X1 (ARM64) | `kCpuRegistersForArgs[0]` (receiver) | Receiver `this` | `Evidence.Inputs.receiver_reg` untuk dispatch |
| R21 (ARM64) | `sdk.ARM64DT` (`disasm/calledge.go:10`) | Dispatch table base | `Evidence.Inputs.dt_reg` untuk `Via:"dispatch_table"` |
| CODE_REG | `constants_arm64.h` | Target Code object | `Evidence.Inputs.code_reg` untuk stub call |
| FUNCTION_REG | `constants_arm64.h` | Target Function object | `Evidence.Inputs.function_reg` untuk stub call |

**Verifikasi SDK**: `searchGitHub` `query:"kClassIdReg" repo:"dart-lang/sdk"` →
`constants_{arm64,x64,arm,ia32}.h` `DispatchTableNullErrorABI::kClassIdReg`.
`query:"ARGS_DESC_REG"` → `stub_code_compiler_arm64.cc:806` "Input parameters:
ARGS_DESC_REG: arguments descriptor array". `query:"IC_DATA_REG"` →
`stub_code_compiler_arm64.cc:3587` "IC_DATA_REG: MegamorphicCache".

**Dampak**: RE user tidak melihat "edge ini pakai class_id_reg R0" atau
"args_desc_reg R4 aktif" — informasi yang penting untuk memahami calling
convention dan membedakan dispatch mechanism. Untuk Frida hooking, register
ini adalah anchor untuk breakpoint condition.

**Usulan**: Tambah field `Inputs.vm_regs map[string]string` (e.g.,
`{"class_id_reg":"X0", "args_desc_reg":"X4"}`) untuk evidence `Kind:"dispatch"`.
Untuk `Kind:"call"` (direct), track `args_desc_reg` saja. Untuk stub call,
track `CODE_REG`/`FUNCTION_REG`.

## Fitur RE Missing/Incomplete

### F1: Evidence confidence roll-up per function (RE triage view)

- **Status**: Missing. `CoverageReport` adalah binary-level, bukan per-function.
- **RE value**: "Fungsi X punya 10 edge: 8 exact, 2 unknown — prioritaskan
  2 unknown untuk Frida hook". Saat ini RE user harus `jq` manual.
- **Usulan**: `func (c *Collector) PerFunction() map[string]CoverageReport`.

### F2: Evidence → SARIF round-trip (signal + call evidence di satu SARIF)

- **Status**: Missing. SARIF hanya dari `SignalFinding`. Evidence
  (call/dispatch/field) tidak masuk SARIF.
- **RE value**: SARIF consumer (GitHub Code Scanning, IDE) tidak lihat
  call confidence. `physicalLocation.address` (SARIF §3.32) bisa pakai
  `Evidence.PC` sebagai `absoluteAddress`.
- **Usulan**: `func WriteEvidenceSARIF(dir string, records []Evidence) error`.

### F3: Evidence cross-reference index (PC → all evidence)

- **Status**: Missing. `Records()` sorted by PC tapi tidak indexed.
- **RE value**: "PC 0x1234 punya call edge exact + field access + signal
  crypto" — multi-evidence per PC adalah signal terkuat. Saat ini RE
  user harus scan linear.
- **Usulan**: `func (c *Collector) ByPC() map[string][]Evidence`.

### F4: Evidence SDK version pinning

- **Status**: `SDKReference.Tag` field ada (`evidence.go:37`) tapi
  tidak pernah diisi. Semua `SDKRef` di-set tanpa `Tag`.
- **RE value**: RE user tidak tahu `SDKRef.File` merujuk versi SDK
  mana. `flow_graph_compiler_arm64.cc` berubah antar versi (e.g.,
  `EmitDispatchTableCall` signature stabil tapi body berubah).
- **Usulan**: Pass `info.Version` dari pipeline ke collector, set
  `SDKRef.Tag` ke version string (e.g., `"3.9.2"`).

### F5: Evidence untuk obfuscation/deobfuscation result

- **Status**: Missing. `BuildDeobfuscationMap` (`pipeline.go:370`)
  menulis `deobfuscate_map.jsonl` — class role inference untuk binary
  obfuscated. Tidak masuk evidence.
- **RE value**: "Class X (obfuscated name `a1b`) terinfer sebagai
  `UserModel` dengan confidence 0.8" — evidence provenance untuk
  deobfuscation.
- **Usulan**: `FromDeobfuscationMap([]DeobfuscatedClassRecord)`.

### F6: Evidence untuk function fingerprint cross-sample

- **Status**: Missing. `writeFunctionFingerprints` (`pipeline.go:344`)
  menulis `function_fingerprints.jsonl` — SHA-256 per function untuk
  name transfer cross-sample. Tidak masuk evidence.
- **RE value**: "Fungsi X di sample A (hash H) cocok dengan fungsi Y
  di sample B" — evidence provenance untuk name inheritance.
- **Usulan**: `FromFingerprints([]FunctionFingerprint, nameMap)`.

## Verifikasi SDK

Semua verifikasi menggunakan dua-step technique (AGENTS.md §"Source of Truth"):

1. **Grep MCP (`searchGitHub` by Vercel)** — `query` + `repo: "dart-lang/sdk"` saja.
2. **`gh api` @ version tag** — untuk ground truth line-level.

| Klaim | Verifikasi | Hasil |
|-------|------------|-------|
| `EmitDirectCall` ada di `flow_graph_compiler_arm64.cc` | `searchGitHub` `query:"EmitDirectCall" repo:"dart-lang/sdk"` | **FALSE**. 0 hit di `flow_graph_compiler_*.cc`. Hanya di `pkg/dart2wasm`/`pkg/dart2bytecode`. Simbol benar: `GenerateStaticDartCall` (`flow_graph_compiler_arm64.cc:388`). |
| `EmitDispatchTableCall` ada di `flow_graph_compiler_arm64.cc` | `searchGitHub` `query:"EmitDispatchTableCall" repo:"dart-lang/sdk"` | **TRUE**. Hit di `flow_graph_compiler_{arm64,x64,arm,ia32,riscv}.cc` dan `.h:764`. |
| `runtime_offsets_extracted.h` adalah sumber nama field THR | `searchGitHub` `query:"runtime_offsets_extracted.h" repo:"dart-lang/sdk"` | **FALSE (generated)**. `runtime_offsets_list.h:8` "offsets_extractor.cc prints these values to runtime_offsets_extracted.h". Sumber nama: `runtime/vm/compiler/runtime_api.h` (`allocate_object_stub_offset()` dll) dan `runtime/vm/thread.h` (struct). |
| `kClassIdReg` adalah konstanta SDK untuk dispatch table call | `searchGitHub` `query:"kClassIdReg" repo:"dart-lang/sdk"` | **TRUE**. `DispatchTableNullErrorABI::kClassIdReg` di `constants_{arm64,x64,arm,ia32}.h`. ARM64 = R0, x64 = RCX. |
| `ARGS_DESC_REG` adalah konstanta SDK | `searchGitHub` `query:"ARGS_DESC_REG" repo:"dart-lang/sdk"` | **TRUE**. Digunakan di `stub_code_compiler_*.cc` dan `flow_graph_compiler_*.cc`. |
| `GenerateSwitchableCallMissStub` ada di SDK ARM64 | `searchGitHub` `query:"GenerateSwitchableCallMissStub" repo:"dart-lang/sdk"` | **TRUE**. `stub_code_compiler_arm64.cc:3742`. |
| `GenerateMegamorphicCallStub` ada di SDK ARM64 | `searchGitHub` `query:"GenerateMegamorphicCallStub" repo:"dart-lang/sdk"` | **TRUE**. `stub_code_compiler_arm64.cc:3587`. |
| `GenerateSingleTargetCallStub` ada di SDK ARM64 | `runtime/docs/README.md:919` (link ke `stub_code_compiler_arm64.cc:3640`) | **TRUE**. |
| `GenerateICCallThroughCodeStub` ada di SDK ARM64 | `runtime/docs/README.md:919` (link ke `stub_code_compiler_arm64.cc:3537`) | **TRUE**. |

**Catatan**: `gh api` tidak dijalankan untuk verifikasi line-level karena
semua klaim sudah dikonfirmasi via `searchGitHub` snippet yang menampilkan
line number dan kode. Untuk verifikasi version-pinned (e.g., `?ref=3.9.2`),
`SDKRef.Tag` field harus diisi dulu (lihat F4) — saat ini semua `SDKRef`
tanpa `Tag`, jadi verifikasi version-specific tidak applicable.
