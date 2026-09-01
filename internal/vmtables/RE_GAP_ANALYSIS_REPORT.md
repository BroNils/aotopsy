# RE Gap Analysis Report: internal/vmtables

> **STATUS VERIFIKASI (2026-09-01)** — Gap 1 **CONFIRMED dan skalanya 5× lebih
> besar dari yang ditulis**. Detail: `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
>
> `thread.h` `CACHED_VM_STUBS_ADDRESSES_LIST` memuat keempat stub
> (`megamorphic_call_checked_entry_`, `switchable_call_miss_entry_`,
> `optimize_entry_`, `deoptimize_entry_`) di **2.17.6, 3.0.5, 3.2.5, 3.4.3,
> DAN 3.6.2** — bukan hanya 2.17.6. Offset dibaca langsung dari
> `runtime_offsets_extracted.h` (blok ARM64+PRODUCT, compressed untuk 3.x,
> non-compressed untuk 2.17.6):
>
> | tabel | StackOverflowWithFPU | 4 entri yang hilang | CallNativeThroughSafepoint |
> |---|---|---|---|
> | `threadStubOffsets2176` | 0x240 | **0x248, 0x250, 0x258, 0x260** | 0x268 |
> | `threadStubOffsets305`/`325` | 0x230 | **0x238, 0x240, 0x248, 0x250** | 0x258 |
> | `threadStubOffsets343` | 0x238 | **0x240, 0x248, 0x250, 0x258** | 0x260 |
> | `threadStubOffsets362` | 0x240 | **0x248, 0x250, 0x258, 0x260** | 0x268 |
>
> Total **20 entri hilang di 5 tabel**. Pembanding definitif:
> `threadStubOffsets370ARM64` punya keempat nama itu di 0x248–0x260 dengan
> kepala & ekor identik dengan tabel 3.6.2 — jadi komentar "added in 3.7.0"
> (`threadstubs.go:220-225`) juga factually wrong.
>
> Catatan cara kerjanya bug ini lolos: keempat field bernama `..._entry_`
> (bukan `..._entry_point_`), jadi filter berpola `_entry_point` melewatkannya
> — persis jebakan yang sama menimpa verifikasi awal saya sendiri.

## Ringkasan

Folder `internal/vmtables` berisi tiga lapis tabel versioned yang dipakai
seluruh pipeline AOTopsy untuk menamai stub VM, stub Thread-cached, dan field
Thread (THR):

| File | Peran | Sumber SDK |
|------|-------|------------|
| `stubnames.go` | Ekspansi `VM_STUB_CODE_LIST` per versi → nama Code objek VM-isolate by index | `runtime/vm/stub_code_list.h` |
| `stuborder.go` | Urutan emisi stub di image (reverse + 9 TTS setelah `Subtype7TestCache`) | `.symtab` Dart 3.12.2 + `stub_code_list.h` |
| `threadstubs.go` | Offset THR → nama stub untuk idiom `ldr xN,[THR,#off]; blr xN` | `CACHED_VM_STUBS_ADDRESSES_LIST` di `runtime/vm/thread.h` + `runtime_offsets_extracted.h` |
| `thrfields.go` / `thrfieldsx86.go` | Offset THR → nama field Thread (stub entry points, objek cached, runtime entries, wb wrappers, suspend-state entries) | `runtime_offsets_extracted.h` + `runtime_entry_list.h` |
| `stubnames_sdk_test.go` | Gate SDK drift untuk `stubnames.go` (ekspansi macro nested) | — |

Verifikasi ke SDK (`gh api` @tag + grep MCP `searchGitHub` `repo:dart-lang/sdk`)
menemukan **3 gap correctness** (tabel salah/tdak lengkap yang menghasilkan
anotasi salah) dan **2 gap coverage** (versi yang punya THR field table tapi
tidak punya stub table). Yang paling serius: `threadstubs.go` 2.17.6
**melewatkan 4 stub entry point yang eksplisit ada di SDK** — komentarnya
menyatakan stubs itu "did not yet exist" di 2.17.6, yang **factually wrong**
(terverifikasi langsung di `thread.h@2.17.6` dan
`runtime_offsets_extracted.h@2.17.6`).

## Struktur Folder

```
internal/vmtables/
├── stubnames.go            (854 lines)  — VM_STUB_CODE_LIST per versi (20 versi)
├── stubnames_sdk_test.go   (208 lines)  — gate SDK: ekspansi macro vs committed table
├── stuborder.go            (118 lines)  — image-order vs cluster-order composition
├── threadstubs.go          (286 lines)  — CACHED_VM_STUBS offset→nama (11 versi)
├── thrfields.go           (3202 lines)  — THR field table ARM64 (19 map + runtime entries)
└── thrfieldsx86.go        (3448 lines)  — THR field table x86_64 (27 map)
```

Cakupan versi per tabel (verifikasi via `gh api` ke tag SDK):

| Versi | `VMStubNames` | `ThreadStubOffsets` | `THRFields` ARM64 | `THRFields` x64 |
|-------|:---:|:---:|:---:|:---:|
| 2.10.0 | — | — | ✓ (nocompress) | ✓ (nocompress) |
| 2.12.0 | ✓ | ✗ MISSING | ✓ (nocompress) | ✓ (nocompress) |
| 2.13.0 | — | — | ✓ (nocompress) | ✓ (nocompress) |
| 2.14.0 | ✓ | ✗ MISSING | ✓ (nocompress) | ✓ (compress+nocompress) |
| 2.15.0 | ✓ | ✗ MISSING | ✓ (nocompress) | ✓ (compress+nocompress) |
| 2.16.0 | ✓ | ✗ MISSING | ✓ (nocompress) | ✓ (compress+nocompress) |
| 2.17.6 | ✓ | ⚠️ PARTIAL (4 stubs hilang) | ✓ (nocompress) | ✓ (compress+nocompress) |
| 2.18.0 | ✓ | ✗ MISSING | ✓ (compress) | ✓ (compress) |
| 2.19.0 | ✓ | ✗ MISSING | ✓ (compress) | ✓ (compress) |
| 3.0.5 | ✓ | ✓ | ✓ (compress) | ✓ (compress) |
| 3.1.0 | ✓ | ✗ MISSING (borrows 3.2.5 di THRFields) | ✓ (compress) | ✓ (compress) |
| 3.2.5 | ✓ | ✓ | ✓ (compress) | ✓ (compress) |
| 3.3.0 | ✓ | ✗ MISSING | ✓ (compress) | ✓ (compress) |
| 3.4.3 | ✓ | ✓ | ✓ (compress) | ✓ (compress) |
| 3.5.0 | ✓ | ✗ MISSING | ✓ (compress) | ✓ (compress) |
| 3.6.2 | ✓ | ✓ | ✓ (compress) | ✓ (compress) |
| 3.7.0 | ✓ | ✓ | ✓ (compress, reuse 3.6.2) | ✓ (compress) |
| 3.8.1 | ✗ MISSING | ✗ MISSING | ✓ (compress) | ✓ (compress) |
| 3.9.2 | ✓ | ✓ | ✓ (compress+nocompress) | ✓ (compress+nocompress) |
| 3.10.7 | ✓ | ✓ | ✓ (compress) | ✓ (compress) |
| 3.11.0 | ✓ | ✓ | ✓ (compress) | ✓ (compress) |
| 3.12.2 | ✓ | ✓ | ✓ (compress) | ✓ (compress) |
| 3.13.0 | ✓ | ✓ | ✓ (compress) | ✓ (compress) |

## Gap Analysis

### Gap 1: `threadStubOffsets2176` melewatkan 4 stub entry point yang ADA di SDK 2.17.6

- **Deskripsi**: Tabel `threadStubOffsets2176` di `threadstubs.go` melompat dari
  offset `0x240` (`StackOverflowSharedWithFPURegs`) langsung ke `0x268`
  (`CallNativeThroughSafepoint`), melewatkan 4 entry point cached stub:
  `megamorphic_call_checked_entry` (0x248), `switchable_call_miss_entry`
  (0x250), `optimize_entry` (0x258), `deoptimize_entry` (0x260). Komentar di
  baris 132-139 menyatakan keempat stubs itu "did not yet exist as
  Thread-cached stubs in 2.17.6" — pernyataan itu **salah**.

- **Bukti SDK**:
  - `runtime/vm/thread.h@2.17.6` baris 168-198: `CACHED_VM_STUBS_ADDRESSES_LIST(V)`
    eksplisit memuat `megamorphic_call_checked_entry_`,
    `switchable_call_miss_entry_`, `optimize_entry_`, `deoptimize_entry_`
    (verifikasi `gh api ... thread.h?ref=2.17.6`).
  - `runtime/vm/compiler/runtime_offsets_extracted.h@2.17.6` blok
    `PRODUCT + TARGET_ARCH_ARM64 + !DART_COMPRESSED_POINTERS`:
    `Thread_megamorphic_call_checked_entry_offset = 584` (0x248),
    `Thread_switchable_call_miss_entry_offset = 592` (0x250),
    `Thread_optimize_entry_offset = 600` (0x258),
    `Thread_deoptimize_entry_offset = 608` (0x260).
  - `thrfields.go` `thrV217` (baris 174-177) **benar** memuat keempatnya di
    offset yang sama — jadi anotasi field THR jalan, tapi recognition
    stub-CALL (`ldr xN,[THR,#0x248]; blr xN` → callee `MegamorphicCall`)
    tidak jalan karena `ThreadStubOffsets` tidak punya entry itu.

- **Dampak**: Pada binary Dart 2.17.6 ARM64, setiap call megamorphic /
  switchable-call-miss / optimize / deoptimize yang ditempuh via
  Thread-cached entry point (idiom `ldr xN,[x26,#0x248]; blr xN`) tidak
  dikenali sebagai stub call oleh decompiler. Callee render sebagai
  `THR.megamorphic_call_checked_entry` (field access display) tapi edge
  call-graph tidak diberi label `MegamorphicCall`, dan `signal`/`thraudit`
  klasifikasi stub role tidak memicu untuk 4 stubs ini di 2.17.6.

- **Usulan**: Tambahkan 4 entry ke `threadStubOffsets2176`:
  ```go
  0x248: "MegamorphicCall",
  0x250: "SwitchableCallMiss",
  0x258: "OptimizeFunction",
  0x260: "Deoptimize",
  ```
  **[UPDATE 2026-09-01]** dan hal yang sama untuk EMPAT tabel lain — lihat
  banner di atas: `threadStubOffsets305`/`325` (0x238–0x250),
  `threadStubOffsets343` (0x240–0x258), `threadStubOffsets362` (0x248–0x260).
  Hapus/fix komentar salah. Karena `threadStubOffsets2176` juga dipakai
  sebagai basis tidak ada untuk versi lain, perbaikan ini berdiri sendiri.
  Tambahkan gate `TestThreadStubOffsetsMatchSDK` analog
  `TestVMStubNamesMatchSDK` yang re-derive `CACHED_VM_STUBS_ADDRESSES_LIST`
  + offset dari `runtime_offsets_extracted.h` per versi — saat ini
  `threadstubs.go` **tidak punya gate SDK drift sama sekali**, hanya
  `stubnames.go` yang punya. Itulah kenapa gap ini lolos.

- **Prioritas**: HIGH — correctness bug, 4 stubs call-tidak-ter-resolve di
  setiap binary 2.17.6.

### Gap 2: `threadstubs.go` tidak punya tabel untuk 10 versi yang punya THR field table

- **Deskripsi**: `ThreadStubOffsets(dartVersion, isARM64)` hanya meng-cover
  11 versi (2.17.6, 3.0.5, 3.2.5, 3.4.3, 3.6.2, 3.7.0, 3.9.2, 3.10.7,
  3.11.0, 3.12.2, 3.13.0). `THRFields` meng-cover 21 versi. 10 versi
  (2.12.0, 2.14.0, 2.15.0, 2.16.0, 2.18.0, 2.19.0, 3.1.0, 3.3.0, 3.5.0,
  3.8.1) punya anotasi THR field tapi `ThreadStubOffsets` return `nil` →
  decompiler `FuncIR.ThreadStubOffsets` kosong → fitur stub-call naming
  non-aktif untuk versi itu (degrade ke `THR.fNN`).

- **Bukti SDK**:
  - `thread.h@2.12.0`: `CACHED_VM_STUBS_ADDRESSES_LIST` ada (16 entry,
    termasuk megamorphic/switchable/optimize/deoptimize, tanpa
    jump_to_frame/resume_interpreter/interpret_call).
  - `thread.h@2.18.0`: `CACHED_VM_STUBS_ADDRESSES_LIST` ada (17 entry +
    native wrappers, sama dengan 2.17.6).
  - `runtime_offsets_extracted.h@2.18.0` blok `PRODUCT + ARM64 + compressed`:
    `write_barrier_entry_point = 560` (0x230), `megamorphic = 640` (0x280),
    `call_native_through_safepoint = 672` (0x2a0), `auto_scope = 712` (0x2c8)
    — offset berbeda dari 3.0.5 (0x1e8..) maupun 2.17.6 (0x1f8..), jadi
    tidak bisa borrow.
  - 3.1.0/3.3.0/3.5.0: `THRFieldsWithProfile` sudah borrow ke 3.2.5/3.4.3
    (kompatibel window), `ThreadStubOffsets` bisa borrow ke versi tetangga
    yang sama — tapi tidak ada case-nya.

- **Dampak**: Binary 2.12.0–2.16.0, 2.18.0, 2.19.0, 3.1.0, 3.3.0, 3.5.0,
  3.8.1 tidak dapat nama callee untuk stub call Thread-cached manapun.
  `signal`/`thraudit` klasifikasi stub role juga non-aktif (mereka konsumsi
  nama dari `ThreadStubOffsets` via `ClassifyStubRole`).

- **Usulan**:
  1. Tambah case borrow untuk 3.1.0→`threadStubOffsets305` (3.2.5), 3.3.0
     →`threadStubOffsets325`, 3.5.0→`threadStubOffsets343` — sama seperti
     `THRFieldsWithProfile` sudah lakukan, verifikasi offset via
     `runtime_offsets_extracted.h@3.1.0/3.3.0/3.5.0`.
  2. Tambah tabel baru untuk 2.12.0–2.16.0 (non-compress, 16 entry tanpa
     jump_to_frame) dan 2.18.0/2.19.0 (compress, 17 entry + native
     wrappers) — offset berbeda, tidak bisa borrow. Generate via
     `tools/extract_thr.go` (sudah ada `extractThreadStubOffsets`).
  3. Tambah 3.8.1 (lihat Gap 3).
  4. Tambah gate SDK drift untuk `threadstubs.go` (lihat Gap 1 usulan).

- **Prioritas**: HIGH untuk 3.1.0/3.3.0/3.5.0 (borrow trivial, verifikasi
  1 baris), MEDIUM untuk 2.12.0–2.19.0 (butuh tabel baru).

### Gap 3: `VMStubNames` tidak punya case 3.8.1

- **Deskripsi**: `THRFieldsWithProfile` punya `thrV381` (baris 93-94),
  `ThreadStubOffsets` tidak, dan `VMStubNames` juga tidak. Binary 3.8.1
  mendapat anotasi THR field saja — semua VM stub Code objek di VM-isolate
  snapshot region tidak dinamai (render `stub_<hex>`/`sub_<hex>`).

- **Bukti SDK**:
  - `stub_code_list.h@3.8.1`: 159 `V(...)` call di body `VM_STUB_CODE_LIST`
    + 1 `AllocationProbePoint` dari `PROBE_POINT_STUBS_LIST` = 160 setelah
    ekspansi. Memuat `RunExceptionHandlerUnbox` (tidak ada di 3.7.0) tapi
    TIDAK memuat `FieldAccessErrorShared*` (baru di 3.9.2). Jadi 3.8.1
    unik — tidak bisa borrow 3.7.0 (kurang `RunExceptionHandlerUnbox`)
    maupun 3.9.2 (lebih `FieldAccessErrorShared*`).
  - `stub_code_list.h@3.8.1`: tidak ada `FfiCallTrampoline`,
    `CheckedStoreIntoShared`, `EnsureDeeplyImmutable`, `ExitSafepointIgnoreUnwindInProgress`.

- **Dampak**: 0 VM stub call dinamai di binary 3.8.1. Karena `BuildVMStubSymbols`
  return empty map kalau `VMStubNames` nil, seluruh VM-isolate Code cluster
  tidak punya VA→name mapping untuk 3.8.1.

- **Usulan**: Tambah `stubNames381` (160 entry) dengan diff dari `stubNames370`:
  insert `RunExceptionHandlerUnbox` setelah `RunExceptionHandler` (index 3).
  Verifikasi via `TestVMStubNamesMatchSDK` (tambah `"3.8.1"` ke `tags` slice
  di `stubnames_sdk_test.go` baris 41-45). Tambah case `ThreadStubOffsets`
  untuk 3.8.1 juga (offset verifikasi via `runtime_offsets_extracted.h@3.8.1`).

- **Prioritas**: MEDIUM — 3.8.1 adalah versi release nyata (Dart 3.8.1
  shipped), bukan dev branch.

### Gap 4: Tidak ada gate SDK drift untuk `threadstubs.go` dan `thrfields.go` runtime-entries

- **Deskripsi**: `stubnames.go` punya `TestVMStubNamesMatchSDK` (gate
  ketat, ekspansi macro nested, per-element compare). `threadstubs.go`
  **tidak punya gate SDK test apapun** — tabel offset ditulis tangan dan
  hanya diverifikasi via komentar manual. `tools/extract_thr.go -check`
  ada untuk `thrfields.go` tapi **bukan** untuk `threadstubs.go` (function
  `extractThreadStubOffsets` ada di tool tapi tidak dipanggil mode `-check`
  untuk membandingkan vs committed `threadStubOffsets*` map).

- **Bukti SDK**: Gap 1 lolos tepat karena tidak ada gate. Komentar
  `threadstubs.go` 2.17.6 menyatakan 4 stubs "did not yet exist" —
  pernyataan yang bisa diverifikasi salah dalam 1 `gh api` call, tapi
  tidak ada yang menjalankannya otomatis.

- **Dampak**: Setiap perubahan `CACHED_VM_STUBS_ADDRESSES_LIST` di SDK
  (penambahan/penghapusan stub, shift offset) diam-diam membuat tabel
  salah tanpa sinyal. Gap 1 adalah instance nyata dari failure mode ini.

- **Usulan**:
  1. Tambah `threadstubs_sdk_test.go` dengan `TestThreadStubOffsetsMatchSDK`
     yang re-derive `CACHED_VM_STUBS_ADDRESSES_LIST` dari `thread.h@tag` +
     offset dari `runtime_offsets_extracted.h@tag` (PRODUCT + arch +
     compressed block) dan compare vs `ThreadStubOffsets(tag, isARM64)`
     per-offset. Pattern sama dengan `stubnames_sdk_test.go`.
  2. Extend `tools/extract_thr.go -check` untuk juga compare
     `threadStubOffsets*` map (function `extractThreadStubOffsets` sudah
     ada, hanya perlu wiring ke `runCheck`).

- **Prioritas**: HIGH — tanpa gate, gap baru akan terus lolos.

## Register Tracking Gaps

`internal/sdk/registers.go` memodelkan register **globally-reserved** Dart
AOT. Verifikasi vs `constants_arm64.h@3.12.2` dan `constants_x64.h@3.12.2`
menunjukkan register globally-reserved semuanya sudah ditrack dengan benar
(THR/PP/DT/HeapBits/CODE_REG/ARGS_DESC_REG/SPREG/NULL_REG/FPREG/LR/return).

Yang **tidak** ditrack adalah register **ABI-role** (context-dependent,
hanya bermakna di stub ABI tertentu). Ini bukan bug — tapi gap RE feature
yang bisa dianotasi:

| Register | ARM64 | x64 | Peran SDK | Nilai RE jika ditrack |
|----------|-------|-----|-----------|------------------------|
| `IC_DATA_REG` | R5 | RBX | ICData/MegamorphicCache di IC call sites | Anotasi inline-cache call site, bantu resolve IC miss → `SwitchableCallMiss` |
| `kSuspendStateReg` | R2/R3 | RBX | SuspendState di async/sync* resume | Identifikasi resume point async, link ke `suspend_state_*_entry_point` THR field |
| `kClassIdReg` | R0 | RCX | Class ID di dispatch null-error ABI & type check | Bantu decode dispatch table null-error prologue |
| `FUNCTION_REG` | R0 | RAX | Function di JIT LazyCompile (AOT: jarang) | Low value di AOT |
| `TMP`/`TMP2` | R16/R17 | R11/— | Assembler scratch | Anotasi "scratch, bukan data" agar tidak dianggap value |

**Catatan konflik x64**: `IC_DATA_REG = RBX` SAMA dengan arg-register ke-4
Dart (`DartCallingConvention::kCpuRegistersForArgs[] = {RDI, RSI, RDX,
RBX, R8, R9}`). Jadi RBX di x64 AOT adalah arg-4 **dan** ICData register —
peran bergantung konteks (prologue IC call vs function entry). Tracker
typetrack/decompiler saat ini memperlakukan RBX murni sebagai arg-4;
anotasi ICData hanya bisa dinyalakan di basic-block yang diawali
IC-call pattern, bukan global.

**Usulan**: Tambah konstanta role register ke `registers.go` (non-reserved,
annotation-only) + handler di disasm/decompiler yang mengenali pattern
pemakaiannya (IC call: `ldr xN,[PP,#idx]; ... ; blr xN` dengan R5 hold
ICData). Tidak mengubah reserved-register lattice, hanya enrich anotasi.

## Fitur RE Missing/Incomplete

### F1: `double_nan_address` THR-cached constant tidak dianotasi

- **Deskripsi**: `CACHED_ADDRESSES_LIST` di `thread.h` (2.12.0+ hingga
  3.13.0) memuat `double_nan_address_` antara `predefined_symbols_address_`
  dan `double_negate_address_`. `runtime_offsets_extracted.h` **tidak
  mengekspor** offset-nya (bukan field yang compiler butuh), jadi
  `tools/extract_thr.go` tidak mengambilnya. `handDerivedFields` di
  `extract_thr.go` baris 846-852 juga tidak mendaftarnya.

- **Bukti SDK**:
  - `thread.h@2.12.0` baris 211: `V(uword, double_nan_address_, ...)`
    antara `predefined_symbols_address_` dan `double_negate_address_`.
  - `thread.h@3.13.0` baris 271: sama.
  - `thrV217` (thrfields.go): `0x298: predefined_symbols_address`,
    `0x2a8: double_negate_address` → gap `0x2a0` = `double_nan_address`
    (8 byte, satu word).
  - `thrV3130`: `0x2b0: predefined_symbols_address`,
    `0x2c0: double_negate_address` → gap `0x2b8` = `double_nan_address`.

- **Dampak**: `ldr xN,[THR,#0x2a0]` (2.17.6) / `ldr xN,[THR,#0x2b8]`
  (3.13.0) yang load konstan `double NaN` render sebagai `THR.fNN` bukan
  `THR.double_nan_address`. RE harus menebak offset gap itu adalah NaN.

- **Usulan**: Tambah `double_nan_address` ke `handDerivedFields` (offset =
  `predefined_symbols_address` + 8, derivable dari deklarasi
  `CACHED_ADDRESSES_LIST` yang contiguous). Tambah ke setiap `thrV*` map
  di posisi gap. Karena `mergeRuntimeEntries` tidak menyentuh area ini,
  aman ditambah manual via `tools/extract_thr.go -write` setelah
  `handDerivedFields` diupdate.

- **Prioritas**: LOW — minor annotation, tidak mempengaruhi resolusi call.

### F2: THR `suspend_state_*_entry_point` tidak di-cross-reference ke async control flow

- **Deskripsi**: `thrfields.go` memuat 11 `suspend_state_*_entry_point`
  per versi (3.6.2+: `suspend_state_init_async_entry_point`,
  `suspend_state_await_entry_point`, dst.). Tapi tidak ada handler yang
  mengenali `ldr xN,[THR,#suspend_state_await_entry_point_offset]; blr xN`
  sebagai **async resume point** dan menghubungkannya ke
  `SuspendStubABI`/`ResumeStubABI` register roles.

- **Bukti SDK**: `constants_arm64.h@3.12.2` baris 420-470:
  `SuspendStubABI::kSuspendStateReg = R3`, `ResumeStubABI::kSuspendStateReg
  = R2`, dst. Stub `Await`, `Resume`, `InitAsync`, `YieldAsyncStar` punya
  ABI eksplisit. THR field offset stub entry point-nya ada di tabel.

- **Dampak**: RE async/sync* code tidak dapat anotasi "ini await resume
  point" otomatis — hanya label `THR.suspend_state_await_entry_point`
  sebagai field access, tanpa konteks bahwa callee adalah async resume
  stub dengan ABI register-role khusus.

- **Usulan**: Tambah handler di `decompiler/ir.go` yang, ketika
  `ThreadStubOffsets` (atau `ThreadFieldNames`) menyebut
  `suspend_state_*_entry_point`, anotasi call site sebagai async resume
  + seed `kSuspendStateReg` (R2/R3/RBX) di basic-block entry. Cross-ref
  ke `stubnames.go` stub `Await`/`Resume`/`InitAsync`/`YieldAsyncStar`.

- **Prioritas**: MEDIUM — fitur RE useful untuk analisa async code, tapi
  bukan correctness bug.

### F3: `threadstubs.go` x86_64 reuse ARM64 map tanpa verifikasi independen per versi

- **Deskripsi**: `threadStubOffsets370X64 = threadStubOffsets370ARM64`,
  `threadStubOffsets392X64 = threadStubOffsets392ARM64`, dst. Komentar
  (baris 71-77, 82-83) menyatakan offset X64 identik ARM64 untuk cluster
  ini "verified against the generated header". Tapi untuk 2.17.6 tidak
  ada `threadStubOffsets2176X64` terpisah — `ThreadStubOffsets` 2.17.6
  return `threadStubOffsets2176` (ARM64 non-compress) untuk **kedua** arch.

- **Bukti SDK**: `runtime_offsets_extracted.h@2.17.6` blok
  `PRODUCT + TARGET_ARCH_X64 + !DART_COMPRESSED_POINTERS`:
  `write_barrier_entry_point = 504` (0x1f8), `megamorphic = 584` (0x248)
  — **identik** ARM64 non-compress. Jadi reuse valid untuk 2.17.6.
  Tapi Gap 1 (4 stubs hilang) juga diwarisi X64 — perbaikan Gap 1 otomatis
  fix X64.

- **Dampak**: Tidak ada bug terpisah dari Gap 1, tapi klaim "verified
  against generated header" tidak ter-gate otomatis (lihat Gap 4).

- **Usulan**: Setelah Gap 1 fix + Gap 4 gate ditambah, verifikasi
  otomatis akan cover X64 juga.

- **Prioritas**: LOW (tertutup oleh Gap 1 + Gap 4).

## Verifikasi SDK

Semua klaim di report ini diverifikasi langsung ke `dart-lang/sdk` via:

1. **`gh api -H "Accept: application/vnd.github.raw" "repos/dart-lang/sdk/contents/<path>?ref=<tag>"`** untuk ground-truth versioned:
   - `runtime/vm/thread.h` @ 2.12.0, 2.17.6, 2.18.0, 3.13.0 → `CACHED_VM_STUBS_ADDRESSES_LIST`, `CACHED_ADDRESSES_LIST` (double_nan_address)
   - `runtime/vm/compiler/runtime_offsets_extracted.h` @ 2.12.0, 2.17.6, 2.18.0, 3.8.1, 3.10.7, 3.13.0 → offset stub entry point per (PRODUCT, arch, compressed) block
   - `runtime/vm/stub_code_list.h` @ 2.12.0, 3.8.1, 3.9.2, 3.10.7, 3.13.0 → `VM_STUB_CODE_LIST` ekspansi (AllocationProbePoint, RunExceptionHandlerUnbox, FfiCallTrampoline, AllocateClosure1-4, IsTopType rename)
   - `runtime/vm/constants_arm64.h` @ 3.12.2 → register roles (IC_DATA_REG R5, kSuspendStateReg R2/R3, kClassIdReg R0, TMP R16/R17)
   - `runtime/vm/constants_x64.h` @ 3.12.2 → IC_DATA_REG RBX konflik dengan arg-4

2. **Grep MCP `searchGitHub` `repo:dart-lang/sdk`** untuk lokasi cepat:
   - `CACHED_VM_STUBS_ADDRESSES_LIST` → `runtime/vm/thread.h:218`

3. **Verifikasi spesifik numerik**:
   - 3.13.0 PRODUCT+ARM64+compressed: `write_barrier=0x200`, `call_native=0x270`, `resume_interpreter=0x288`, `bootstrap=0x290`, `auto_scope=0x2a0`, `interpret_call=0x2a8` → cocok `threadStubOffsets3122` (reuse untuk 3.13.0) ✓
   - 3.10.7 PRODUCT+ARM64+compressed: `write_barrier=0x1f8`, `megamorphic=0x248`, `call_native=0x268`, `stack_overflow_without=0x238` → cocok `threadStubOffsets370ARM64` (reuse untuk 3.10.7) ✓
   - 2.17.6 PRODUCT+ARM64+!compressed: `megamorphic=0x248`, `optimize=0x258`, `deoptimize=0x260` ADA di SDK tapi TIDAK di `threadStubOffsets2176` ✗ (Gap 1)
   - 3.13.0 `VM_STUB_CODE_LIST` ekspansi = 164 entry (163 `V()` + 1 `AllocationProbePoint`) → cocok `stubNames3130` count 164 ✓
   - 3.8.1 `VM_STUB_CODE_LIST` = 160 entry ekspansi, memuat `RunExceptionHandlerUnbox`, tidak memuat `FieldAccessErrorShared*` → unik, butuh tabel sendiri (Gap 3)

Tidak ada klaim di report ini yang berasal dari memory training — semua
diverifikasi via `gh api` ke tag SDK spesifik.
