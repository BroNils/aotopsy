# RE Gap Analysis Report: internal/thraudit

> **STATUS VERIFIKASI (2026-09-01)** — Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`. Koreksi:
> - **Gap 1 ("112 Runtime Entry offset tidak ditrack") → STALE untuk mayoritas
>   versi.** Usulan report ("hitung `offset = AllocateArray_offset + N*8`, merge
>   nama ke tabel THR") **sudah diimplementasikan**:
>   `vmtables/thrfields.go:2886 mergeRuntimeEntries` melakukan persis itu, dan
>   dipanggil di `init()` untuk 9 tabel ARM64 (V217, V325, V343, V362, V381,
>   V392, V3107, V3110, V3122) + beberapa x64, dengan daftar `runtimeEntriesV*`
>   yang isinya `RUNTIME_ENTRY_LIST` + `LEAF_RUNTIME_ENTRY_LIST` lengkap
>   (mis. `runtimeEntriesV392` berkomentar "RUNTIME_ENTRY_LIST (77)" dan memuat
>   `BoxDouble`, `TypeCheck`, `InstantiateType`, `RangeError`, …).
>   Jadi `LDR X5,[X26,#0x358]` di 3.9.2 memang sudah bernama
>   `THR.BoxDouble_entry_point`.
> - Sisa yang **benar-benar** belum ter-namai (via dispatch
>   `THRFieldsWithProfile`): **2.10.0, 2.12.0–2.16.0, 2.18.0, 2.19.0, dan
>   3.13.0** — versi yang `thrV*`-nya tidak punya panggilan
>   `mergeRuntimeEntries`. Gap 1 seharusnya berbunyi "runtime-entry naming
>   belum dipasang untuk 8 versi", bukan "112 offset tidak ditrack".
> - Gap 2 (classifier ARM64-only), Gap 3 (forward-only context), Gap 5
>   (`double_nan_address` tidak di `handDerivedFields`) — **CONFIRMED**.

## Ringkasan

Folder `internal/thraudit/` berisi dua file: `thrclassify.go` (450 baris) dan
`thrclassify_test.go` (140 baris). Package ini adalah **consumer** murni — ia
menerima JSONL record THR audit yang diproduksi oleh `internal/disasm/thraudit.go`
(ARM64) dan `internal/disasm/x86.go` (x86_64), lalu meng-cluster offset unresolved
menjadi band dan mengklasifikasi setiap record ke salah satu dari 4 kelas
heuristik.

Verifikasi SDK (Dart 3.9.2 `runtime/vm/thread.h`, `runtime_entry_list.h`,
`assembler_arm64.cc`, `runtime_offsets_extracted.h`) menemukan **gap struktural
besar**: 112 dari 113 `RUNTIME_ENTRY_LIST` + `LEAF_RUNTIME_ENTRY_LIST` offset
TIDAK ada di `runtime_offsets_extracted.h` dan karenanya TIDAK ada di tabel THR
AOTopsy, padahal **semua** di-emit oleh compiler sebagai `LDR X5, [THR, #off]`
(via `Assembler::CallRuntime`) atau `LDR X16, [THR, #off]` (via
`LeafRuntimeScope::Call`). Offset-offset ini **komputabel** dari
`AllocateArray_entry_point_offset` (satu-satunya yang diekspor) + urutan
deklarasi di `runtime_entry_list.h` + stride 8 byte, karena layout struct
Thread bersifat kontigu dan dapat diprediksi.

Selain itu, classifier heuristik hanya beroperasi pada ARM64 (x86 record
diproduksi tetapi tidak pernah diklasifikasi), hanya melihat forward 1-2
instruksi (tidak pernah backward), dan tidak dapat menamai runtime entry
walaupun offset-nya komputabel.

## Struktur Folder

```
internal/thraudit/
├── thrclassify.go         (450 baris) — record types, band clustering, heuristic classifier
└── thrclassify_test.go    (140 baris) — regression test dengan 3 fixture (evil/newandromo/blutter)
```

### Produsen record (di luar folder ini)

| File | Peran |
|------|-------|
| `internal/disasm/thraudit.go` | `ExtractTHRAccesses` (ARM64 LDR/STR X26), `BuildAuditRecords` (context ±2) |
| `internal/disasm/x86.go` | `ExtractX86THRAccesses` (x86 MOV [R14+disp]), `BuildX86AuditRecords` |
| `internal/analysis/thraudit.go` | `RunTHRAudit` — scan semua fungsi, tulis JSONL |
| `internal/disasm/annotate.go` | `THRContextAnnotator` — anotasi inline disasm dengan klasifikasi |
| `internal/vmtables/thrfields.go` | Tabel offset→nama THR per versi (sumber `fields` map) |
| `internal/vmtables/threadstubs.go` | `ThreadStubOffsets` — subset CACHED_VM_STUBS_ADDRESSES_LIST untuk decompiler |
| `tools/extract_thr.go` | Ekstraktor/tabel checker dari SDK `runtime_offsets_extracted.h` |
| `cmd/aotopsy/cmd_debug_thr.go` | CLI `_debug thr-audit`, `thr-classify`, `thr-cluster` |

### Aliran data

```
libapp.so → RunTHRAudit → ExtractTHRAccesses (LDR/STR [X26,#imm])
           → BuildAuditRecords (context ±2 insn)
           → JSONL thr_loads.jsonl
           → ClusterBands (gap-based clustering)
           → ClassifyRecords (10 heuristic rules)
           → classified.jsonl + summary
```

## Gap Analysis

### Gap 1: 112 Runtime Entry offset tidak ditrack — komputabel dari SDK

> **[STALE 2026-09-01]** Mekanisme yang diusulkan sudah ada dan aktif:
> `vmtables/thrfields.go` `mergeRuntimeEntries(m, base, names)` menghitung
> `off = base + i*8` dan menamai `name+"_entry_point"`, dipanggil untuk 9
> tabel ARM64. Sisa gap: 2.10.0, 2.12.0–2.16.0, 2.18.0, 2.19.0, 3.13.0.
> (Angka "77 RUNTIME + 36 LEAF" yang dikutip report justru berasal dari
> komentar di tabel yang sudah ada itu.)

- **Deskripsi**: `runtime_offsets_extracted.h` hanya mengekspor
  `Thread_AllocateArray_entry_point_offset` dari `RUNTIME_ENTRY_LIST` (77 entri)
  dan tidak ada sama sekali dari `LEAF_RUNTIME_ENTRY_LIST` (36 entri). Total 113
  runtime entry, hanya 1 yang punya offset di tabel THR AOTopsy. Sisa 112
  muncul sebagai "unresolved" di audit dan hanya bisa ditebak heuristik sebagai
  `RUNTIME_ENTRYPOINT` tanpa nama.

  Layout struct Thread (thread.h:1403-1411) bersifat **kontigu dan dapat
  diprediksi**:
  ```
  RUNTIME_ENTRY_LIST:           77 × uword (8 byte each) = 616 bytes
  LEAF_RUNTIME_ENTRY_LIST:      36 × uword (8 byte each) = 288 bytes
  write_barrier_wrappers[]:     kNumberOfDartAvailableCpuRegs × uword
  CACHED_FUNCTION_ENTRY_POINTS: 11 × uword (suspend_state_*)
  ```

  Verifikasi numerik (ARM64 PRODUCT compressed 3.9.2):
  - `AllocateArray_entry_point_offset = 0x2e8` (diekspor)
  - `suspend_state_init_async_entry_point_offset = 0x710` (diekspor)
  - `0x710 - 0x2e8 = 0x428 = 1064 bytes`
  - `77×8 + 36×8 + 20×8 = 616 + 288 + 160 = 1064` ✓
  - (`kNumberOfDartAvailableCpuRegs` = 32 - 12 reserved = 20 pada ARM64)

  Jadi: `offset(entry_N) = AllocateArray_offset + N × 8` untuk N = 0..112
  (77 RUNTIME + 36 LEAF, berurutan).

- **Bukti SDK**:
  - `runtime/vm/thread.h@3.9.2` baris 1403-1408:
    ```cpp
    #define DECLARE_MEMBERS(name) uword name##_entry_point_;
      RUNTIME_ENTRY_LIST(DECLARE_MEMBERS)
    #undef DECLARE_MEMBERS
    #define DECLARE_MEMBERS(returntype, name, ...) uword name##_entry_point_;
      LEAF_RUNTIME_ENTRY_LIST(DECLARE_MEMBERS)
    #undef DECLARE_MEMBERS
    ```
  - `runtime/vm/assembler/assembler_arm64.cc@3.9.2` baris 1719-1724:
    ```cpp
    void Assembler::CallRuntime(const RuntimeEntry& entry, ...) {
      ldr(R5, compiler::Address(THR, entry.OffsetFromThread()));
      LoadImmediate(R4, argument_count);
      Call(Address(THR, target::Thread::call_to_runtime_entry_point_offset()));
    }
    ```
  - `runtime/vm/assembler/assembler_arm64.cc@3.9.2` baris 1769:
    ```cpp
    void LeafRuntimeScope::Call(const RuntimeEntry& entry, ...) {
      __ ldr(TMP, compiler::Address(THR, entry.OffsetFromThread()));
    ```
  - `runtime/vm/thread.cc@3.9.2` `OffsetFromThread(const RuntimeEntry*)` —
    switch atas semua `RUNTIME_ENTRY_LIST` + `LEAF_RUNTIME_ENTRY_LIST`.
  - `runtime/vm/compiler/runtime_offsets_extracted.h@3.9.2` — hanya
    `AllocateArray_entry_point_offset` diekspor dari RUNTIME_ENTRY_LIST.
  - `runtime/vm/runtime_entry_list.h@3.9.2` — 77 + 36 = 113 entri terurut.

- **Dampak**: Setiap `LDR X5, [X26, #BoxDouble_off]`, `LDR X5, [X26,
  #TypeCheck_off]`, `LDR X5, [X26, #Throw_off]`, dll. di binary AOT muncul
  sebagai `THR+0xNNN` (unresolved) di disasm dan JSONL. RE tidak tahu bahwa
  offset `0x2F0` adalah `BoxDouble_entry_point`, `0x318` adalah
  `TypeCheck_entry_point`, dll. Ini adalah **mayoritas** akses THR unresolved
  di binary AOT non-trivial — setiap type check, null check, range check,
  allocation, throw, NoSuchMethod, InstantiateType, dll. memanggil runtime
  entry via THR.

- **Usulan**: Tambah fungsi `RuntimeEntryOffsets(dartVersion, isARM64)` di
  `internal/vmtables/` yang:
  1. Membaca `AllocateArray_entry_point_offset` dari tabel THR yang ada
  2. Meng-hardcode urutan `RUNTIME_ENTRY_LIST` + `LEAF_RUNTIME_ENTRY_LIST`
     per versi (dari `runtime_entry_list.h`, sudah di-parse oleh
     `tools/extract_thr.go` `parseRuntimeEntryList`)
  3. Menghitung offset = AllocateArray_off + index × 8
  4. Merge ke tabel THR fields (nama = `BoxDouble_entry_point`, dll.)

  Verifikasi: cross-check bahwa `suspend_state_init_async_offset` =
  `AllocateArray_offset + (77+36)×8 + wb_array_size×8` cocok dengan nilai
  yang diekspor (sudah diverifikasi untuk 3.9.2 ARM64 compressed: 0x2e8 +
  1064 = 0x710 ✓). Tambah gate di `tools/extract_thr.go -check` yang
  memverifikasi konsistensi ini untuk setiap versi.

- **Prioritas**: **TINGGI** — ini adalah gap RE terbesar. 112 nama runtime
  entry yang bisa dianotasi tetapi tidak. Setiap binary AOT dengan type
  check, throw, atau allocation non-trivial akan mendapat benefit.

### Gap 2: Classifier x86_64 tidak ada — record diproduksi tetapi tidak pernah diklasifikasi

- **Deskripsi**: `ExtractX86THRAccesses` dan `BuildX86AuditRecords` di
  `internal/disasm/x86.go` memproduksi `THRAuditRecord` untuk x86_64, tetapi
  `ClassifyFromContext` hanya memproses teks instruksi ARM64 (mencari "BLR",
  "STP", "MOV X4,", "LDR X30, [X26,"). Semua record x86 jatuh ke
  `ClassUnknown`. `THRContextAnnotator` juga hanya dipanggil dari
  `disasm_stage.go` yang ARM64-only (pipeline.Run menolak x86_64 sebelum
  stage ini).

- **Bukti SDK**: Pada x86_64, `CallRuntime` (assembler_x64.cc) memuat runtime
  entry ke register dan memanggil via `call` — pola berbeda dari ARM64
  `LDR X5 → MOV X4 → LDR X30 → BLR X30`. Tanpa rule x86, klasifikasi tidak
  mungkin.

- **Dampak**: x86_64 THR audit (`_debug thr-audit` pada sample x86_64)
  menghasilkan JSONL tetapi `thr-classify` menghasilkan 100% UNKNOWN.
  Anotasi inline disasm x86_64 tidak punya label klasifikasi THR.

- **Usulan**: Tambah `ClassifyFromContextX86` yang mengenali pola x86:
  - `MOV reg, [R14+off] → call reg` → RUNTIME_ENTRYPOINT
  - `MOV reg, [R14+off] → MOV [obj+field], reg` → OBJECTSTORE_OR_CACHE
  - `MOV reg, [R14+off] → CMP reg, ...` → OBJECTSTORE_OR_CACHE
  Atau, lebih baik lagi: implementasikan Gap 1 (runtime entry offset
  computation) sehingga x86_64 juga mendapat anotasi nama langsung tanpa
  perlu heuristik konteks.

- **Prioritas**: SEDANG — x86_64 adalah target sekunder, tetapi dengan Gap 1
  terimplementasi, mayoritas x86_64 THR access akan resolved langsung.

### Gap 3: Classifier hanya melihat forward 1-2 instruksi — tidak ada backward context

- **Deskripsi**: `ClassifyFromContext` menemukan `curIdx` (instruksi current
  dengan prefix `"> "`) lalu hanya mengambil `next1` dan `next2`. Tidak
  pernah memeriksa `prev1` atau `prev2` (context ±2 diproduksi tetapi
  backward tidak dipakai).

- **Bukti SDK**: Beberapa pola compiler ARM64 memerlukan backward context:
  - `StackOverflowSharedWithoutFPURegs` stub: `LDR X9, [X26, #stack_overflow_stub]`
    bisa dipanggil setelah `CMP Xstack, Xlimit → B.LS` — pola `CMP → B.LS →
    LDR X9 → BLR X9` memerlukan backward untuk konfirmasi ini adalah stack
    overflow check, bukan runtime entry lain.
  - Write barrier wrapper: `LDR Xn, [X26, #wb_wrapper_off] → STR Xobj, [Xdest]`
    — pola ini bisa dibedakan dari runtime entry dengan melihat bahwa
    destinasi adalah store ke object field, bukan BLR.

- **Dampak**: Record yang pola konfirmasinya berada di instruksi sebelumnya
  diklasifikasi sebagai UNKNOWN atau salah kelas.

- **Usulan**: Perluas `ClassifyFromContext` untuk memeriksa `prev1`/`prev2`
  untuk pola backward. Atau lebih baik: ganti heuristik konteks dengan
  resolusi offset langsung (Gap 1) untuk runtime entry, dan gunakan
  backward context hanya untuk field yang benar-benar tidak ada di SDK.

- **Prioritas**: SEDANG — dengan Gap 1 terimplementasi, mayoritas record
  akan resolved oleh nama, mengurangi kebutuhan heuristik konteks.

### Gap 4: Rule 4 salah mengklasifikasi LDR X30 sebagai ISOLATE_OR_GROUP_PTR

- **Deskripsi**: Rule 4:
  ```go
  if dstReg == "X30" && strings.Contains(next1, "STP") && strings.Contains(next1, "[X15") {
      if strings.Contains(next2, "BL ") {
          return ClassIsolateGroupPtr
      }
  }
  ```
  Ini mengklasifikasi `LDR X30, [X26, #off] → STP ..., [X15] → BL` sebagai
  `ISOLATE_OR_GROUP_PTR`. Namun pola `LDR X30 → STP [X15] → BL` adalah
  **load return address / save frame pattern**, bukan isolate group pointer
  chase. X30 = LR (Link Register) di ARM64. Memuat X30 dari THR lalu
  menyimpan ke stack (X15 = SP dalam Dart AOT ARM64) lalu BL adalah pola
  "load return address from THR, push to Dart stack, then call" — ini
  terkait dengan `resume_pc` atau `jump_to_frame_entry_point`, bukan
  isolate_group.

- **Bukti SDK**: `runtime/vm/thread.h@3.9.2` baris 926:
  `static uword resume_pc_offset() { return OFFSET_OF(Thread, resume_pc_); }`
  `resume_pc_` adalah `uword` (bukan pointer ke IsolateGroup). Pola
  `LDR LR, [THR, #resume_pc] → STP ..., [SP] → BL` adalah penyimpanan
  return address untuk nested call, bukan dereference isolate group.

- **Dampak**: 5 record di fixture "evil" dan 45 record di fixture
  "newandromo" diklasifikasi sebagai `ISOLATE_OR_GROUP_PTR` — jika pola
  ini sebenarnya adalah resume_pc atau jump_to_frame, labelnya menyesatkan
  RE.

- **Usulan**: Ganti label Rule 4 dari `ClassIsolateGroupPtr` ke kelas baru
  `ClassReturnAddress` atau `ClassResumePc`. Atau verifikasi dengan
  offset: jika offset cocok dengan `resume_pc_offset` dari tabel THR,
  anotasi sebagai `THR.resume_pc`.

- **Prioritas**: SEDANG — mislabeling mengarah RE ke arah yang salah.

### Gap 5: `double_nan_address` tidak di-hand-derive —THR table gap yang berdampak ke klasifikasi

- **Deskripsi**: `CACHED_ADDRESSES_LIST` di thread.h memuat
  `V(uword, double_nan_address_, ...)` antara `predefined_symbols_address_`
  dan `double_negate_address_`. `runtime_offsets_extracted.h` tidak
  mengekspor offset ini. `handDerivedFields` di `tools/extract_thr.go`
  tidak memuatnya. Akibatnya, setiap `LDR Xn, [X26, #double_nan_off]` di
  binary AOT muncul sebagai unresolved dan diklasifikasi heuristik
  (kemungkinan sebagai OBJECTSTORE_OR_CACHE via Rule 7 jika diikuti CMP,
  atau UNKNOWN).

- **Bukti SDK**:
  - `runtime/vm/thread.h@3.9.2` `CACHED_ADDRESSES_LIST`:
    `V(uword, double_nan_address_, reinterpret_cast<uword>(&double_nan_constant), 0)`
  - `runtime_offsets_extracted.h@3.9.2`: tidak ada
    `Thread_double_nan_address_offset`
  - `tools/extract_thr.go:846` `handDerivedFields`: tidak memuat
    `double_nan_address`

- **Dampak**: Offset gap antara `predefined_symbols_address` dan
  `double_negate_address` di tabel THR tidak dianotasi. RE harus menebak
  bahwa offset gap itu adalah NaN constant.

- **Usulan**: Tambah `double_nan_address` ke `handDerivedFields` dengan
  deskripsi `"thread.h CACHED_ADDRESSES_LIST, between predefined_symbols_address_ and double_negate_address_"`.
  Offset = `predefined_symbols_address_offset + 8` (karena `double_nan_address_`
  mengikuti `predefined_symbols_address_` dalam deklarasi, dan keduanya
  `uword` = 8 byte).

- **Prioritas**: RENDAH — satu field, dampak terbatas pada kode yang
  menggunakan NaN constant.

### Gap 6: Tidak ada klasifikasi stub call vs runtime entry call

- **Deskripsi**: Classifier hanya mempunyai 4 kelas:
  `RUNTIME_ENTRYPOINT_ARRAY`, `OBJECTSTORE_OR_CACHE`, `ISOLATE_OR_GROUP_PTR`,
  `UNKNOWN`. Kelas `RUNTIME_ENTRYPOINT_ARRAY` menggabungkan dua hal berbeda:
  1. **Stub entry point** (CACHED_VM_STUBS_ADDRESSES_LIST):
     `write_barrier_entry_point`, `allocate_object_entry_point`,
     `call_to_runtime_entry_point`, dll. — ini adalah alamat stub Code
     yang dipanggil via `BLR Xn`.
  2. **Runtime entry point** (RUNTIME_ENTRY_LIST):
     `BoxDouble_entry_point`, `TypeCheck_entry_point`, `Throw_entry_point`,
     dll. — ini adalah alamat fungsi C++ runtime yang dipanggil via
     `LDR X5 → MOV X4, #argc → LDR X30, [THR, #call_to_runtime] → BLR X30`.

  Kedua pola ini berbeda secara semantik: stub adalah Dart VM internal code
  (write barrier, allocation), runtime entry adalah C++ runtime function
  (type check, throw, allocate). RE perlu membedakan keduanya untuk
  memahami flow program.

- **Bukti SDK**:
  - `CACHED_VM_STUBS_ADDRESSES_LIST` (thread.h:222) — stub entry points
  - `RUNTIME_ENTRY_LIST` (runtime_entry_list.h) — runtime entry points
  - Keduanya dipanggil dengan pola berbeda:
    - Stub: `LDR Xn, [THR, #stub_off] → BLR Xn` (langsung)
    - Runtime: `LDR X5, [THR, #rt_off] → MOV X4, #argc → LDR X30, [THR, #call_to_runtime] → BLR X30` (indirect via call_to_runtime stub)

- **Dampak**: RE tidak bisa membedakan "ini adalah write barrier call"
  dari "ini adalah TypeCheck runtime call" di output klasifikasi.

- **Usulan**: Dengan implementasi Gap 1 (runtime entry offset computation),
  mayoritas runtime entry akan resolved by name. Tambah kelas
  `ClassStubCall` untuk CACHED_VM_STUBS_ADDRESSES_LIST yang sudah resolved
  di tabel THR, dan `ClassRuntimeEntryCall` untuk RUNTIME_ENTRY_LIST.
  Atau cukup anotasi nama field (sudua dilakukan oleh THRFields) dan
  biarkan klasifikasi konteks hanya untuk benar-benar unknown offset.

- **Prioritas**: SEDANG — diferensiasi ini berguna untuk RE tetapi
  sebagian besar teratasi jika Gap 1 diimplementasi (nama field sudah
  membedakan stub vs runtime entry).

### Gap 7: Band clustering tidak memanfaatkan pengetahuan struktur THR

- **Deskripsi**: `ClusterBands` mengelompokkan offset unresolved berdasarkan
  gap jarak (`maxGap = 0x18` = 24 bytes = 3 slot). Ini adalah clustering
  murni geometris. Namun struktur THR sebenarnya terbagi menjadi region
  semantik:
  - CACHED_CONSTANTS (object_null..float_zerow_address) — offset kecil, 0x20-0x2D8
  - RUNTIME_ENTRY_LIST — blok kontigu 77×8 = 616 bytes
  - LEAF_RUNTIME_ENTRY_LIST — blok kontigu 36×8 = 288 bytes
  - write_barrier_wrappers — blok 20×8 = 160 bytes
  - suspend_state — blok 11×8 = 88 bytes
  - Thread state fields (vm_tag, stack_limit, top, end, dll.) — tersebar

  Band clustering tidak tahu bahwa offset 0x2F0-0x560 adalah runtime entry
  block (komputabel), sehingga band di region ini seharusnya diberi label
  "RUNTIME_ENTRY_REGION" bukan sekadar "Band 3: 0x2F0-0x560".

- **Bukti SDK**: Layout struct Thread (thread.h:1396-1413) terbagi menjadi
  blok-blok kontigu yang ukurannya diketahui dari SDK.

- **Dampak**: Output band tidak memberikan konteks semantik. RE harus
  menebak bahwa band di range 0x2F0-0x560 adalah runtime entry block.

- **Usulan**: Tambah metadata region ke `Band`: field `Region` yang
  diisi dari pengetahuan struktur THR (runtime_entry, leaf_entry,
  wb_wrapper, suspend_state, cached_constants, thread_state). Band yang
  jatuh sepenuhnya dalam satu region diberi label region tersebut.

- **Prioritas**: RENDAH — cosmetic, tetapi membantu RE memahami output
  band lebih cepat.

### Gap 8: `exception_pc`, `exception_sp`, `exception_fp`, `setjmp_function`, `setjmp_buffer` tidak ada di tabel THR

- **Deskripsi**: thread.h mendeklarasikan offset methods untuk 5 field ini:
  ```cpp
  static intptr_t exception_pc_offset() ...
  static intptr_t exception_sp_offset() ...
  static intptr_t exception_fp_offset() ...
  static intptr_t setjmp_function_offset() ...
  static intptr_t setjmp_buffer_offset() ...
  ```
  Namun `runtime_offsets_extracted.h` tidak mengekspornya. AOTopsy tidak
  mempunyai entry untuk field-field ini di tabel THR manapun.

- **Bukti SDK**:
  - `runtime/vm/thread.h@3.9.2` baris 339-351:
    ```cpp
    static intptr_t setjmp_function_offset() ...
    static intptr_t setjmp_buffer_offset() ...
    static intptr_t exception_pc_offset() ...
    static intptr_t exception_sp_offset() ...
    static intptr_t exception_fp_offset() ...
    ```
  - `runtime_offsets_extracted.h@3.9.2`: tidak ada
    `Thread_exception_pc_offset`, dll.

- **Dampak**: Jika compiler AOT meng-emit `LDR/STR [THR, #exception_pc_off]`
  di exception handling code, offset tersebut muncul sebagai unresolved.
  Namun field-field ini kemungkinan hanya diakses dari VM internal code
  (bukan app code AOT), jadi dampaknya mungkin kecil.

- **Usulan**: Hand-derive offset ini dari struct declaration order di
  thread.h, atau verifikasi apakah field ini pernah diakses dari AOT
  compiled code dengan mencari pola `LDR/STR [X26, #off]` di binary sample
  yang offset-nya tidak cocok dengan tabel THR manapun.

- **Prioritas**: RENDAH — field exception/setjmp jarang diakses dari AOT
  app code.

### Gap 9: LoadImmediate multi-instruction menggagalkan Rule 3

- **Deskripsi**: Rule 3 mengharapkan pola `LDR X5 → MOV X4 → LDR X30, [X26,`
  dalam 3 instruksi berturut-turut. Namun `LoadImmediate(R4, argument_count)`
  di assembler ARM64 bisa menghasilkan 2+ instruksi untuk argument_count
  besar:
  ```asm
  LDR X5, [X26, #rt_off]       ; current
  MOVZ X4, #low16              ; next1 (bukan "MOV X4,")
  MOVK X4, #high16, LSL #16    ; next2 (bukan "LDR X30, [X26,")
  LDR X30, [X26, #0x208]       ; next3 (di luar window)
  BLR X30                      ; next4 (di luar window)
  ```
  Rule 3 mencari `strings.Contains(next1, "MOV X4,")` — `MOVZ X4,` tidak
  cocok. Akibatnya record diklasifikasi UNKNOWN.

- **Bukti SDK**: `LoadImmediate` di ARM64 assembler menghasilkan `MOVZ` +
  `MOVK` untuk nilai > 0xFFFF.

- **Dampak**: Runtime entry call dengan argument_count > 65535 (jarang
  tetapi mungkin) atau yang LoadImmediate-nya multi-instruction diklasifikasi
  UNKNOWN.

- **Usulan**: Perluas Rule 3 untuk mencocokkan `MOVZ X4,` / `MOV X4,` /
  `ORR X4, XZR, #imm`. Atau perbesar context window untuk Rule 3 menjadi
  ±3 atau ±4. Atau implementasikan Gap 1 sehingga offset runtime entry
  diresolved by name tanpa perlu heuristik konteks.

- **Prioritas**: RENDAH — LoadImmediate > 16-bit untuk argument_count
  sangat jarang di AOT code.

### Gap 10: Tidak ada validasi anotasi THR — offset resolved tidak diverifikasi silang dengan ThreadStubOffsets

- **Deskripsi**: Ada dua sumber offset→nama THR yang overlapping:
  1. `THRFields` / `THRFieldsWithProfile` (thrfields.go) — 120+ field per
     versi, nama = `write_barrier_entry_point`
  2. `ThreadStubOffsets` (threadstubs.go) — ~20 stub per versi, nama =
     `WriteBarrier`

  Keduanya memetakan offset yang sama ke nama yang berbeda. Tidak ada
  gate yang memverifikasi konsistensi: jika `THRFields` mengatakan
  offset 0x1F8 = `write_barrier_entry_point` dan `ThreadStubOffsets`
  mengatakan 0x1F8 = `WriteBarrier`, tidak ada yang mengecek keduanya
  cocok. Jika SDK shift offset di versi baru dan hanya salah satu tabel
  diupdate, anotasi akan inkonsisten tanpa sinyal.

- **Bukti SDK**: Keduanya berasal dari `CACHED_VM_STUBS_ADDRESSES_LIST`
  di `runtime_offsets_extracted.h` — sumber yang sama, tetapi diekstrak
  oleh tool berbeda (`extract_thr.go` vs `threadstubs.go` manual).

- **Dampak**: Inkonsistensi silent antara anotasi disasm (THR.write_barrier_entry_point)
  dan anotasi decompiler (WriteBarrier) untuk offset yang sama.

- **Usulan**: Tambah gate di `tools/extract_thr.go -check` yang
  membandingkan overlap `THRFields` vs `ThreadStubOffsets` untuk setiap
  versi: setiap offset yang ada di kedua tabel harus punya nama yang
  konsisten (atau setidaknya mapping yang terverifikasi).

- **Prioritas**: SEDANG — silent inconsistency adalah persis jenis bug
  yang gate SDK drift dirancang untuk cegah.

## Register Tracking Gaps

### THR field register tracking — apa yang sudah ditrack

`ExtractTHRAccesses` (ARM64) mengekstrak 4 bentuk akses THR:
- `LDR X64 [X26, #imm]` — load 8-byte (width=8, DstReg)
- `LDR W32 [X26, #imm]` — load 4-byte (width=4, DstReg)
- `STR X64 [X26, #imm]` — store 8-byte (width=8, SrcReg, IsStore)
- `STR W32 [X26, #imm]` — store 4-byte (width=4, SrcReg, IsStore)

`ExtractX86THRAccesses` (x86_64) mengekstrak MOV dengan operand memori
`[R14+disp]`.

### Register tracking gaps

| Gap | Deskripsi | Dampak |
|-----|-----------|--------|
| **LDP/STP [X26, #imm]** | Load/store pair ke THR tidak ditrack. `LDP Xn, Xm, [X26, #off]` memuat dua register sekaligus dari THR. Compiler ARM64 bisa menggunakan ini untuk memuat pasangan field THR (mis. `top` + `end`). | Akses THR via LDP/STP tidak muncul di audit JSONL, tidak dianotasi di disasm. |
| **LDR Xn, [X26, Xm, LSL #3]** | Indexed load dari THR (register offset) tidak ditrack. Pola `LDR X30, [X21, X0, LSL #3]` sudah ditrack untuk dispatch table, tetapi `LDR Xn, [X26, Xm, LSL #3]` (THR + register offset) tidak. | Akses THR dinamis (offset di register) tidak terlihat. |
| **ADD Xn, X26, #imm** | Address computation THR + immediate tidak ditrack. `ADD Xn, X26, #off` lalu `LDR Xm, [Xn]` adalah pola THR field access yang tidak terdeteksi. | THR field access via address register intermediate hilang. |
| **LDRSW/LDUR** | Signed word load dan unscaled offset load dari THR tidak ditrack. `LDUR Xn, [X26, #-off]` (negative offset) tidak ditrack. | Akses THR dengan offset negatif atau signed extension hilang. |
| **STRB/STRH/LDRB/LDRH** | Byte/halfword load-store dari THR tidak ditrack. Beberapa field THR mungkin 1 atau 2 byte (mis. `stack_overflow_flags`). | Akses THR sub-word hilang. |

### Verifikasi SDK untuk LDP/STP

Compiler ARM64 Dart menggunakan `LDP`/`STP` untuk save/restore register
pair, tetapi untuk THR field access, pola yang lebih umum adalah LDR/STR
tunggal. Verifikasi: grep `Address(THR` di `assembler_arm64.cc` dan
`stub_code_compiler_arm64.cc` — mayoritas adalah `ldr`/`str` tunggal.
Namun `LDP` tidak mustahil, terutama untuk `stp` di prologue/epilogue
yang menyimpan THR-relative values.

## Fitur RE Missing/Incomplete

### F1: Tidak ada anotasi "THR field type" di output

**Status**: MISSING

Setiap THR field punya tipe semantik yang berbeda: ObjectPtr (object_null,
bool_true), uword (write_barrier_entry_point, double_negate_address),
CodePtr (stub fields), Isolate* (isolate, isolate_group), dll. Output
audit dan anotasi disasm hanya menampilkan nama tanpa tipe. RE tidak tahu
apakah `THR.object_null` adalah pointer ke object atau alamat fungsi.

**Usulan**: Tambah field `FieldType` ke THRFields table (object_ptr,
uword_entry, code_ptr, isolate_ptr, dll.). Sumber: `CACHED_CONSTANTS_LIST`
declaration di thread.h sudah memuat tipe (`V(ObjectPtr, object_null_, ...)`,
`V(uword, write_barrier_entry_point_, ...)`, dll.).

### F2: Tidak ada cross-reference THR access → call edge

**Status**: MISSING

Saat `LDR X5, [X26, #TypeCheck_off] → ... → BLR X30` diklasifikasi sebagai
RUNTIME_ENTRYPOINT, tidak ada link ke call edge yang sudah di-resolve di
`call_edges.jsonl`. RE harus manual menghubungkan "THR access di PC X"
dengan "call edge di PC Y".

**Usulan**: Tambah field `CallEdgePC` ke THRAuditRecord yang menunjuk ke
PC instruksi BLR/BL yang menggunakan register yang dimuat dari THR akses
ini.

### F3: Tidak ada statistik "THR access frequency per field"

**Status**: MISSING

Audit menghitung total/resolved/unresolved count, tetapi tidak membreakdown
per-field. RE tidak tahu field THR mana yang paling sering diakses di
binary (mis. `write_barrier_entry_point` mungkin 10000+ akses, `vm_tag`
mungkin 500, `object_null` mungkin 2000).

**Usulan**: Tambah `FieldFrequency` map ke `ClassifySummary` atau output
terpisah yang menghitung frekuensi setiap offset/nama field THR.

### F4: Tidak ada anotasi "THR field lifecycle" (read-only vs read-write)

**Status**: MISSING

Beberapa field THR adalah read-only dari app code (mis. `object_null`,
`bool_true`, `predefined_symbols_address`), sementara lainnya ditulis
(mis. `vm_tag`, `top`, `end`, `store_buffer_block`). Audit menandai
`IsStore` tetapi tidak menggabungkan dengan pengetahuan field untuk
memberi label "read-only field being written" (indikasi anomali atau
pattern tidak biasa).

**Usulan**: Tambah field `ExpectedAccess` ke THRFields table (ro, rw, wo)
dan flag record di mana akses aktual bertentangan dengan expected access.

### F5: ClassifyFromContext tidak diberitahu offset yang sudah komputabel

**Status**: INCOMPLETE

`ClassifyFromContext` menerima `THRAuditRecord` yang hanya punya `THROffset`
sebagai string hex. Ia tidak tahu bahwa offset 0x2F0 = BoxDouble (komputabel
dari Gap 1). Jika Gap 1 diimplementasi, classifier harus diberi akses ke
tabel runtime entry offset sehingga record yang offset-nya cocok langsung
diberi nama, bukan diklasifikasi heuristik.

**Usulan**: Ubah `ClassifyRecords` untuk menerima `runtimeEntryOffsets
map[int]string` parameter. Sebelum menjalankan heuristik, cek apakah
offset ada di map — jika ya, gunakan nama langsung dan set class =
`ClassRuntimeEntrypoint` dengan field name.

### F6: Band output tidak menyertakan distribusi kelas per band

**Status**: INCOMPLETE

`WriteBandsMD` menampilkan tabel band dengan range, slot, count, top
offset. Tetapi tidak menampilkan distribusi kelas (berapa record di band
ini yang RUNTIME_ENTRYPOINT vs OBJECTSTORE_OR_CACHE vs UNKNOWN). RE harus
manual cross-reference `classified.jsonl` dengan `bands.json`.

**Usulan**: Tambah kolom "Class Distribution" ke tabel band di
`WriteBandsMD` yang menampilkan `RE:45 OBJ:3 ISO:2 UNK:0`.

## Verifikasi SDK

### Metode verifikasi

1. **`gh api` @ tag 3.9.2**:
   - `runtime/vm/thread.h` — struct layout, CACHED_*_LIST macros, offset methods
   - `runtime/vm/runtime_entry_list.h` — RUNTIME_ENTRY_LIST (77 entri) + LEAF_RUNTIME_ENTRY_LIST (36 entri)
   - `runtime/vm/compiler/runtime_offsets_extracted.h` — 3593 `Thread_*_offset` entries, hanya `AllocateArray` dari RUNTIME_ENTRY_LIST
   - `runtime/vm/assembler/assembler_arm64.cc` — `CallRuntime` (LDR R5, [THR, off]) dan `LeafRuntimeScope::Call` (LDR TMP, [THR, off])
   - `runtime/vm/thread.cc` — `OffsetFromThread(const RuntimeEntry*)` switch atas semua runtime entry
   - `runtime/vm/constants_arm64.h` — `kNumberOfDartAvailableCpuRegs = 32 - 12 = 20`

2. **Verifikasi numerik kontiguitas**:
   - AllocateArray (ARM64 PRODUCT compressed 3.9.2) = 0x2e8
   - suspend_state_init_async (same block) = 0x710
   - Delta = 0x428 = 1064 bytes
   - Expected: 77×8 + 36×8 + 20×8 = 616 + 288 + 160 = 1064 ✓

3. **Field tidak diekspor** (diverifikasi via grep di extracted header):
   - `double_nan_address` — MISSING dari extracted header, MISSING dari handDerivedFields
   - `exception_pc`, `exception_sp`, `exception_fp`, `setjmp_function`, `setjmp_buffer` — MISSING dari extracted header
   - `empty_array`, `empty_type_arguments`, `dynamic_type` — MISSING dari extracted header, SUDAH di handDerivedFields

### File SDK yang diverifikasi

| File | Tag | Isi yang diverifikasi |
|------|-----|----------------------|
| `runtime/vm/thread.h` | 3.9.2 | CACHED_*_LIST macros, DECLARE_MEMBERS blocks, offset methods, struct layout |
| `runtime/vm/runtime_entry_list.h` | 3.9.2 | RUNTIME_ENTRY_LIST (77), LEAF_RUNTIME_ENTRY_LIST (36) |
| `runtime/vm/compiler/runtime_offsets_extracted.h` | 3.9.2 | 120 unique Thread_*_offset names, hanya AllocateArray dari RUNTIME_ENTRY_LIST |
| `runtime/vm/assembler/assembler_arm64.cc` | 3.9.2 | CallRuntime (LDR R5), LeafRuntimeScope::Call (LDR TMP) |
| `runtime/vm/thread.cc` | 3.9.2 | OffsetFromThread(const RuntimeEntry*) switch |
| `runtime/vm/constants_arm64.h` | 3.9.2 | kNumberOfDartAvailableCpuRegs = 20, TMP = R16, TMP2 = R17 |
| `runtime/vm/stub_code_compiler_arm64.cc` | 3.9.2 | CallRuntime usage patterns |
