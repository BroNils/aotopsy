# RE Gap Analysis Report: internal/sdktest

> **STATUS VERIFIKASI (2026-09-01)** — semua gap CONFIRMED. Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> **Temuan "runtimeEntriesV3130 missing" TERVERIFIKASI dan aktif:**
> `thrfields.go:2858-2869` memanggil `mergeRuntimeEntries` untuk V217, V325,
> V343, V362, V381, V392, V3107, V3110, V3122 — **tidak ada V3130**. `thrV3130`
> punya `AllocateArray_entry_point` di 0x2f0 seperti `thrV3122`, tapi 0x2f8 dst.
> kosong; dari 141 entri hanya 31 yang `*_entry_point`, dan melompat dari 0x688
> (suspend-state) ke 0x720 (`DeoptimizeCopyFrame`).
>
> **Peringatan untuk perbaikannya (tidak disebut report):** jangan pakai ulang
> `runtimeEntriesV3122`. Diverifikasi `gh api` + `diff` atas
> `runtime/vm/runtime_entry_list.h`:
> ```
> 3.12.2 RUNTIME_ENTRY_LIST : 83 entri
> 3.13.0 RUNTIME_ENTRY_LIST : 85 entri
>    +V(TypeError                      <- disisipkan di posisi 46 (TENGAH)
>    +V(AllocateBytecodeCoverageArray  <- ditambahkan di akhir
> ```
> Karena `TypeError` disisipkan di tengah, memakai ulang tabel 3.12.2 akan
> menggeser **setiap** nama setelah indeks 45 sebesar 8 byte. Kondisi sekarang
> (tanpa merge) adalah kegagalan **aman** (offset tak bernama), bukan nama
> salah — pertimbangkan itu saat memprioritaskan.
>
> Gap 2 (tidak ada gate untuk `threadStubOffsets*`) terbukti bukan teori: itulah
> sebabnya 20 entri stub hilang di 5 tabel lolos — lihat banner di
> `internal/vmtables/RE_GAP_ANALYSIS_REPORT.md`.

## Ringkasan

`internal/sdktest/` adalah package helper setebal 60 baris (`sdktest.go`) yang
menyediakan tiga primitif — `SkipIfNoSDK()`, `HasGH()`, `GHFileAtTag(path, tag)`
— dipakai oleh empat "SDK drift gate" test di package lain
(`internal/disasm`, `internal/vmtables`, `internal/snapshot`,
`internal/cluster`). Filosofinya benar: tabel version-keyed di AOTopsy
(THR fields, base objects, FunctionKind, stub names) tidak bisa divalidasi
secara lokal karena "salah offset tetap menghasilkan output yang
plausible-looking" — satu-satunya ground truth adalah source Dart SDK yang
menjadi asal tabel itu. Helper ini mengambil source tersebut via `gh api`.

Namun cakupan verifikasi saat ini **sempit dan tidak simetris**:

1. **Hanya 4 dari ~10 tabel version-keyed yang punya SDK drift gate.**
   CID tables (`cidsV210`..`cidsV3130`, 17 tabel di `internal/snapshot/version.go`),
   `threadStubOffsets*` (`internal/vmtables/threadstubs.go`, 11 tabel),
   `runtimeEntriesV*` / `leafEntriesV*` (`internal/vmtables/thrfields.go`, ~12
   tabel) — semua ini di-*claim* "SDK-verified" di komentar tetapi **tidak punya
   test yang re-derive dari SDK**. `extract_thr.go -check-runtime-entries`
   bahkan eksplisit "report-only mode" (lihat `runCheckRuntimeEntries`, baris
   358-379): tidak ada committed table yang dibandingkan.
2. **`GHFileAtTag` tidak menambah header `Accept: application/vnd.github.raw`**,
   padahal `extract_thr.go`'s `fetchHeader`/`fetchSDKFile` (baris 174-193)
   menambahkannya. Akibatnya helper ini menerima JSON base64 envelope (lalu
   di-decode manual), sedangkan tool di `tools/` menerima raw langsung. Ini
   bukan bug fungsional, tapi **inkonsistensi API** yang membuat dua jalur
   fetch berbeda untuk file SDK yang sama — sumber latent bug jika GitHub
   mengubah default content negotiation.
3. **Tidak ada caching.** Setiap test re-fetch file SDK yang sama berkali-kali
   (mis. `runtime/vm/stub_code_list.h` di-fetch oleh `TestVMStubNamesMatchSDK`
   untuk 19 tag, dan juga oleh `extract_thr.go -check-stubs` untuk tag yang
   sama). `extract_thr.go` punya cache per-tag (`headers := map[string]string{}`,
   baris 953/1304), tapi `sdktest.GHFileAtTag` tidak — sehingga test SDK drift
   gate yang iterate 19 tag melakukan 19 HTTP round-trip ke GitHub API
   (rate-limited 60 req/jam untuk unauth).
4. **Tidak ada helper untuk macro expansion bersama.** Setiap test menulis
   parser macro-nya sendiri: `stubnames_sdk_test.go` punya
   `parseStubMacros`/`expandStubMacro`, `funckind_sdk_test.go` punya
   `sdkFunctionKinds`, `baseobjects_sdk_test.go` punya `addBaseObjectRe`/
   `quotedRe`. `extract_thr.go` punya `extractMacroBlock`/`parseMacroEntries`
   yang lebih general (mendukung `V(Type, name)` multi-arg). **Tiga parser
   berbeda untuk format macro yang sama** — jika SDK menambah bentuk macro
   baru, tiga tempat harus di-fix independen.
5. **`SkipIfNoSDK` tidak memeriksa `HasGH`** — namun setiap caller tetap
   memanggil keduanya secara berurutan. Pola boilerplate 4-baris ini
   ter-duplicate di 8 tempat (4 test file × 2 fungsi). Helper yang menggabung
   keduanya akan menyederhanakan dan mencegah lupa.

Dampak RE: tabel yang tidak ter-verifikasi adalah persis kelas bug yang
AGENTS.md "Two gates that must stay green" peringatkan — "a wrong offset
produces a plausible-looking annotation that is simply wrong". Tanpa gate,
drift seperti yang sudah menimpa 2.10/2.18 FunctionKind (setter dilabel
constructor) dan 3.1.0/3.5.0 stub names (67-156 nama shifted) akan terjadi
lagi pada CID table / threadStubOffsets / runtimeEntries tanpa sinyal.

## Struktur Folder

```
internal/sdktest/
└── sdktest.go   (60 baris) — package sdktest
```

Tiga export:
- `SkipIfNoSDK() bool` — true jika `AOTOPSY_TEST_SDK` unset (test harus skip).
- `HasGH() bool` — true jika `gh` CLI di PATH.
- `GHFileAtTag(path, tag string) (string, error)` — fetch file dari
  `dart-lang/sdk` di git `tag` via `gh api repos/dart-lang/sdk/contents/<path>?ref=<tag>`,
  decode base64 JSON envelope, return raw content.

Tidak ada test file di folder ini sendiri (`sdktest_test.go` tidak ada).
Helper diuji secara tidak langsung oleh 4 consumer test.

Consumer (ditemukan via grep `sdktest\.`):
| File | Test | Tabel yang diverifikasi | File SDK | Tag yang diperiksa |
|------|------|------------------------|----------|-------------------|
| `internal/disasm/thrfields_sdk_test.go` | `TestTHRTablesMatchSDK` | `thrV*` (THR fields) | `runtime/vm/compiler/runtime_offsets_extracted.h` | via `extract_thr.go -check` (semua `allTargets`) |
| `internal/disasm/thrfields_sdk_test.go` | `TestObjectStoreFieldCountsMatchSDK` | `ObjectStoreAOTFieldCount` | `runtime/vm/object_store.h` | via `extract_thr.go -check-objectstore` (semua version profile) |
| `internal/vmtables/stubnames_sdk_test.go` | `TestVMStubNamesMatchSDK` | `stubNames*` (VM stub names) | `runtime/vm/stub_code_list.h` | 19 tag eksplisit |
| `internal/snapshot/baseobjects_sdk_test.go` | `TestBaseObjectNamesMatchSDK` | `baseObjectLayouts` | `runtime/vm/app_snapshot.cc` / `clustered_snapshot.cc` | 11 tag probe |
| `internal/cluster/funckind_sdk_test.go` | `TestFunctionKindLayoutsMatchSDK` | `funcKindLayouts` | `runtime/vm/raw_object.h` (`FOR_EACH_RAW_FUNCTION_KIND`) | semua key `funcKindLayouts` |

Tabel version-keyed yang **TIDAK** punya SDK drift gate:
- `cidsV210`..`cidsV3130` (17 CID tables, `internal/snapshot/version.go:477-955`)
- `threadStubOffsets*` (11 tabel, `internal/vmtables/threadstubs.go:46-245`)
- `runtimeEntriesV*` / `leafEntriesV*` (~12 tabel, `internal/vmtables/thrfields.go:2396-2855`)
- `RootsPrefixRefCount` (hanya di `extract_thr.go -check-roots`, report-only
  untuk class-table count, dan hanya tag 3.13.0 — lihat Gap 4)
- `vmTypeTestingStubNames` (`internal/vmtables/stuborder.go:44-54`) — di-claim
  "Stable across every supported version" tapi tidak ada test yang memverifikasi
  claim itu terhadap SDK untuk semua tag.

## Gap Analysis

### Gap 1: Tabel CID (`cidsV*`) tidak punya SDK drift gate

- **Deskripsi**: `internal/snapshot/version.go` menyimpan 17 CID table
  (`cidsV210`, `cidsV212`, ..., `cidsV3130`) yang memetakan nama kelas
  predefined ke integer Class ID. Setiap tabel di-claim "verified directly
  against dart-lang/sdk class_id.h at tag X" di komentar (mis. baris 508:
  "v2.12.0 CIDs: verified directly against dart-lang/sdk class_id.h at tag
  2.12.0"), tetapi **tidak ada test yang re-derive CID dari
  `runtime/vm/class_id.h` dan membandingkannya**. `extract_thr.go` punya
  `countClassIDEntries` (baris 498-515) dan `runCheckRoots` (baris 391-486)
  yang menyentuh `class_id.h`, tapi hanya untuk menghitung `kNumPredefinedCids`
  secara tidak langsung (dan eksplicit menyerah: "kNumPredefinedCids cannot
  be reliably extracted from class_id.h because the enum body is a macro
  expansion that nests 5+ levels deep", baris 437-445).
- **Bukti SDK**: `runtime/vm/class_id.h` berisi `enum ClassId` dengan macro
  `CLASS_LIST` → `CLASS_LIST_NO_OBJECT` → `CLASS_LIST_NO_OBJECT_NOR_STRING_NOR_ARRAY_NOR_MAP`
  → ... bersarang 5+ level. Setiap `kXxxCid` adalah predefined CID. CID berubah
  antar versi (mis. `RecordCid` baru di 2.19, `LinkedHashBaseCid` ditambah
  setelah `CLASS_LIST` di 3.13.0 — lihat komentar `version.go:1004`).
  `CIDTable` struct (`version.go:262-358`) punya 50+ field CID yang harus
  benar per versi; satu CID salah → cluster dispatch salah → stream desync.
- **Dampak**: CID table adalah dasar dari `ClassifyAlloc` (`internal/cluster/cid.go:162`)
  dan seluruh cluster dispatch. CID yang salah menyebabkan cluster
  salah-identifikasi, mirip dengan bug `ObjectStoreAOTFieldCount` yang
  "desynchronises the stream right before the dispatch table" (komentar
  `extract_thr.go:1127-1129`). Karena tidak ada gate, drift CID tidak akan
  terdeteksi sampai seseorang mencoba parse snapshot versi itu dan gagal
  dengan gejala samar.
- **Usulan**: Tambah `internal/snapshot/cids_sdk_test.go` dengan test
  `TestCIDTablesMatchSDK` yang, untuk setiap key di `versionProfiles`,
  fetch `runtime/vm/class_id.h` di tag itu, ekspansi macro `CLASS_LIST`
  (atau hitung `k*Cid` enum value secara rekursif / via preprocessor
  emulator), dan bandingkan setiap field `CIDTable` (String, Mint, Array,
  ..., Record, LocalVarDescriptors, ApiError, UnwindError) terhadap CID
  yang di-derive. Reuse helper macro-expansion dari `sdktest` (lihat Gap 6).
  Untuk macro bersarang yang sulit, fallback: verifikasi setidaknya
  `kNumPredefinedCids` (yang `extract_thr.go` sudah hitung via
  `countClassIDEntries`) dan setiap CID yang `CIDTable` ekspos —
  jika `kStringCid` di tabel != `kStringCid` di SDK, fail.
- **Prioritas**: TINGGI — CID table adalah tabel version-keyed terbesar
  yang TIDAK terverifikasi, dan dampak drift-nya fatal (stream desync).

### Gap 2: Tabel `threadStubOffsets*` tidak punya SDK drift gate

- **Deskripsi**: `internal/vmtables/threadstubs.go` menyimpan 11 tabel
  offset Thread-relatif untuk VM stub entry points (`WriteBarrier`,
  `AllocateObject`, `CallNativeThroughSafepoint`, dll.) per versi
  (`threadStubOffsets370ARM64`, `threadStubOffsets392ARM64`, ...,
  `threadStubOffsets362`). Komentar panjang di file ini meng-claim
  "verified against dart-lang/sdk's generated runtime_offsets_extracted.h"
  untuk setiap tabel, tetapi **tidak ada test yang re-derive tabel ini
  dari SDK**. `extract_thr.go -check` memverifikasi THR fields secara
  umum (yang include `*_entry_point_offset`), tapi `threadStubOffsets`
  adalah SUBSET kurasi yang dipilih untuk "extremely hot VM runtime
  stubs" — tidak ada gate yang memastikan subset itu konsisten dengan
  SDK untuk setiap versi yang `ThreadStubOffsets()` claim support.
- **Bukti SDK**: `runtime/vm/thread.h` baris 218+ mendefinisikan
  `CACHED_VM_STUBS_ADDRESSES_LIST(V)` (diverifikasi via grep MCP):
  ```
  #define CACHED_VM_STUBS_ADDRESSES_LIST(V)
    V(uword, write_barrier_entry_point_, StubCode::WriteBarrier().EntryPoint(), 0)
    V(uword, array_write_barrier_entry_point_, ..., 0)
    V(uword, call_to_runtime_entry_point_, ..., 0)
    ...
  ```
  Entry ini muncul di `runtime_offsets_extracted.h` sebagai
  `Thread_<name>_offset`. `extract_thr.go`'s `extractThreadStubOffsets`
  (baris 272-290) sudah memfilter field berakhiran `_entry_point_offset`
  — tapi fungsi itu **tidak dipanggil oleh `runCheck`** (baris 1295-1376
  hanya pakai `extractTHRFields` dan bandingkan ke `committed` map).
  `threadStubOffsets*` di `threadstubs.go` adalah map terpisah
  (`map[int64]string`) yang tidak di-parse oleh `parseCommittedTables`
  (yang hanya cari `var thrV...`).
- **Dampak**: `ThreadStubOffsets` dipakai oleh `internal/decompiler/call.go:354`,
  `internal/decompiler/lift.go:711`, `internal/decompiler/liftarm64.go:298`,
  `internal/analysis/typetrack_stage.go:291` untuk menamai indirect call
  `ldr xN,[x26,#off]; blr xN` sebagai `THR.WriteBarrier` dll. Offset salah
  → nama stub salah → RE analyst misled tentang apa yang dipanggil.
  Komentar `threadstubs.go:79-83` sendiri mencatat bahwa 3.9.2 shift +0x8
  vs 3.7.0 dan 3.10.9 shift balik -0x8 — perubahan non-monoton yang
  musti diverifikasi, bukan diasumsikan.
- **Usulan**: Tambah `internal/vmtables/threadstubs_sdk_test.go` dengan
  test `TestThreadStubOffsetsMatchSDK` yang untuk setiap case di
  `ThreadStubOffsets()` (2.17.6, 3.0.5, 3.2.5, 3.4.3, 3.6.2, 3.7.0,
  3.9.2, 3.10.7, 3.11.0, 3.12.2, 3.13.0), fetch
  `runtime/vm/compiler/runtime_offsets_extracted.h` di tag itu, ekstrak
  field `Thread_<name>_entry_point_offset` untuk arch ARM64 + PRODUCT +
  compressed (kombinasi yang `threadstubs.go` pakai), dan bandingkan
  setiap offset di `threadStubOffsets*` terhadap SDK. Field yang tidak
  di-export SDK (mis. `ResumeInterpreter` yang pakai
  `SuspendStubABI::kResumePcDistance` adjustment — lihat komentar
  `threadstubs.go:64`) masuk daftar `handDerivedStubFields` eksplisit
  seperti `handDerivedFields` di `extract_thr.go:846-852`.
- **Prioritas**: TINGGI — tabel ini aktif dipakai di decompiler lift
  pipeline; drift = mis-named call edge.

### Gap 3: Tabel `runtimeEntriesV*` / `leafEntriesV*` tidak diverifikasi (report-only)

- **Deskripsi**: `internal/vmtables/thrfields.go:2396-2855` menyimpan
  ~12 tabel nama runtime entry per versi (`runtimeEntriesV217`,
  `runtimeEntriesV325`, `runtimeEntriesV343`, ..., `runtimeEntriesV3122`,
  `leafEntriesV3107`, `leafEntriesV3115`, `leafEntriesV3122`). Tabel ini
  di-merge ke THR map via `mergeRuntimeEntries` (baris 2858-2869) untuk
  menamai offset `Thread_<name>_entry_point_offset` yang tidak di-export
  SDK. `extract_thr.go` punya `runCheckRuntimeEntries` (baris 358-379)
  yang fetch `runtime_entry_list.h` dan parse `RUNTIME_ENTRY_LIST` /
  `LEAF_RUNTIME_ENTRY_LIST` — **tapi eksplisit "report-only mode"**:
  "We don't have committed runtime entry tables yet — just report.
  Future: compare against committed tables when they exist." (baris
  374-376). Tabel committed ada (`runtimeEntriesV*`), tapi gate tidak
  pernah dihubungkan.
- **Bukti SDK**: `runtime/vm/runtime_entry_list.h` (diverifikasi via
  `gh api` @3.13.0) berisi `RUNTIME_ENTRY_LIST(V)` dengan 81 entri
  (`AllocateArray`..`AllocateBytecodeCoverageArray`) dan
  `LEAF_RUNTIME_ENTRY_LIST(V)` dengan ~35 entri
  (`DeoptimizeCopyFrame`..`MemoryMove`). Jumlah dan urutan berubah
  per versi (mis. `AllocateRecord`/`AllocateSmallRecord`/`AllocateSuspendState`
  baru di 3.2.5; `ResumeFrame` baru; `StackOverflow` rename jadi
  `InterruptOrStackOverflow`; `NonBoolTypeError` di 2.17.6 hilang
  di 3.x). Komentar `thrfields.go:2395` "v2.17.6: 55 RUNTIME + 31 LEAF"
  vs `thrfields.go:2430` "v3.2.5: 64 RUNTIME + 36 LEAF" mencatat
  perubahan ini — tapi tidak ada gate yang memastikan angka itu benar.
- **Dampak**: `runtimeEntriesV*` menamai offset THR yang di-load oleh
  `ldr xN,[x26,#off]; blr xN` sebagai `THR.AllocateArray_entry_point`
  dll. Nama salah (mis. `StackOverflow` vs `InterruptOrStackOverflow`
  di versi yang rename) → annotation misleading. Lebih buruk: jika
  urutan shift (entry ditambah/dihapus di tengah list), semua nama
  setelah titik itu shift by ±8 byte — sama persis failure mode
  `stubNames` yang "silently shifts every subsequent name by one".
- **Usulan**: Ubah `runCheckRuntimeEntries` dari report-only menjadi
  compare mode: parse `runtimeEntriesV*` dari `thrfields.go` via AST
  (sama seperti `parseCommittedTables`), bandingkan elemen-elemen
  terhadap `parseRuntimeEntryList(header)` dari SDK per tag. Tambah
  test `TestRuntimeEntriesMatchSDK` di `internal/vmtables/` yang
  invoke `extract_thr.go -check-runtime-entries` (sudah ada flag-nya,
  baris 1391; tinggal ubah `runCheckRuntimeEntries` return mismatch
  count). Atau, lebih bersih: pindahkan parsing `runtime_entry_list.h`
  ke `sdktest` helper dan tulis test langsung tanpa shell-out ke
  `extract_thr.go`.
- **Prioritas**: TINGGI — tabel aktif dipakai via `mergeRuntimeEntries`
  ke THR map yang dipakai decompiler; gate report-only = tidak ada gate.

### Gap 4: `RootsPrefixRefCount` hanya diverifikasi untuk 3.13.0, dan class-table count di-back-calculate dari total

- **Deskripsi**: `RootsPrefixRefCount` (field `VersionProfile` di
  `internal/snapshot/version.go:257`) hanya di-set untuk 3.13.0
  (`RootsPrefixRefCount: 1518`, baris 1015). `extract_thr.go`'s
  `runCheckRoots` (baris 391-486) hanya iterate `allTargets` untuk
  `t.tag == "3.13.0"` (baris 395-396) — versi lain yang mungkin akan
  pakai `RootsPrefixRefCount` di masa depan tidak diperiksa. Lebih
  buruk: `kNumPredefinedCids` "cannot be reliably extracted from
  class_id.h" (baris 437-445), sehingga `classTableCount` dihitung
  dengan **back-calculation dari total yang diketahui**:
  `classTableCount = committed - rawCount - handleCount - apiCount`
  (baris 462). Ini adalah verifikasi sirkular: total di-claim 1518,
  lalu classTableCount di-derive dari total, lalu total di-recompute
  dari komponen — yang tentu saja cocok karena classTableCount dibuat
  agar cocok. Verifikasi yang sebenarnya hanya berlaku untuk
  `rawCount`/`handleCount`/`apiCount`/`numSymbols`/`numStubEntries`.
- **Bukti SDK**: `runtime/vm/roots.h` (diverifikasi via `gh api` @3.13.0)
  mendefinisikan `RAW_ROOTS_LIST`, `HANDLE_ROOTS_LIST`,
  `API_HANDLE_ROOTS_LIST` (3 macro terpisah). `runtime/vm/symbol_list.h`
  punya `kNumPredefinedSymbols`. `runtime/vm/stub_code_list.h` punya
  `kNumStubEntries`. `runtime/vm/class_id.h` punya `kNumPredefinedCids`
  via enum. Masalahnya: `class_id.h`'s enum body bersarang 5+ level
  (CLASS_LIST → ...), sehingga regex `k\w+Cid\s*,` (`countClassIDEntries`,
  baris 513) menghitung enum entry tapi **mungkin melewatkan entry yang
  di-generate via macro expansion yang tidak expand ke `kXCid,` literal**.
- **Dampak**: `RootsPrefixRefCount` dipakai oleh
  `internal/cluster/dispatchtable.go:122` untuk skip N root refs sebelum
  dispatch table. Salah → dispatch table parse dari posisi salah →
  "BLR resolution drops to zero with no other symptom" (komentar
  `extract_thr.go:1127-1129`). Verifikasi sirkular untuk class-table
  count berarti jika `kNumPredefinedCids` berubah di SDK 3.14+, total
  1518 tidak akan cocok tapi gate tidak akan memberi sinyal yang
  actionable (hanya "MISMATCH" tanpa tahu komponen mana yang salah).
- **Usulan**:
  1. Ekspansi `runCheckRoots` ke semua tag yang punya
     `RootsPrefixRefCount` di `versionProfile` (saat ini hanya 3.13.0,
     tapi future-proof).
  2. Ganti back-calculation dengan ekstraksi langsung `kNumPredefinedCids`
     dari `class_id.h`. Opsi: (a) jalankan `gcc -E` secara lokal pada
     `class_id.h` dengan include path SDK (berat, tapi ground truth);
     (b) tulis preprocessor emulator Go yang handle `#define` + `#if`
     nesting (sudah ada prototype di `extractTHRFields`'s stack frame,
     baris 600-680 — bisa di-refactor); (c) hitung `k*Cid` enum value
     dengan parser yang aware terhadap macro expansion level (regex
     `k\w+Cid\s*,` saat ini undercount karena macro intermediate tidak
     expand).
  3. Verifikasi setiap komponen (`rawRoots`, `handleRoots`, `apiHandleRoots`,
     `numSymbols`, `numStubEntries`) secara independen, dan hanya
     kemudian jumlahkan ke total — jangan back-calculate.
- **Prioritas**: SEDANG — saat ini hanya 3.13.0 yang pakai field ini,
  tapi drift di sini fatal dan verifikasi sirkular adalah false sense
  of security.

### Gap 5: `vmTypeTestingStubNames` di-claim "stable across every supported version" tapi tidak diverifikasi

- **Deskripsi**: `internal/vmtables/stuborder.go:44-54` hardcode 9 nama
  type-testing stub (`DefaultTypeTest`, `DefaultNullableTypeTest`, ...,
  `LazySpecializeNullableTypeTest`) dengan komentar "Stable across every
  supported version." `TestVMStubNamesMatchSDK` (baris 62-65) memang
  ekstrak `VM_TYPE_TESTING_STUB_CODE_LIST` dari SDK dan membandingkan
  ke `composed` (yang include TTS via `composeVMStubEmissionOrder`), tapi
  **tidak membandingkan langsung ke `vmTypeTestingStubNames`** —
  perbandingan ke `full` (VM_STUB_CODE_LIST + TTS composed) tidak
  mengisolasi TTS list itu sendiri. Jika SDK menambah/mengubah entri TTS
  di satu versi, `vmTypeTestingStubNames` hardcoded bisa drift tanpa
  sinyal khusus.
- **Bukti SDK**: `runtime/vm/stub_code_list.h` mendefinisikan
  `VM_TYPE_TESTING_STUB_CODE_LIST(V)` terpisah dari
  `VM_STUB_CODE_LIST(V)`. Grep MCP menunjukkan keduanya di file yang
  sama. Test sudah ekstrak keduanya (`tts, err := expandStubMacro(macros,
  "VM_TYPE_TESTING_STUB_CODE_LIST")`, baris 62) — tinggal membandingkan
  `tts` ke `vmTypeTestingStubNames` langsung.
- **Dampak**: `vmTypeTestingStubNames` dipakai oleh
  `composeVMStubEmissionOrder` (baris 102-117) untuk menyisipkan 9 nama
  TTS setelah `Subtype7TestCache` anchor. Jika TTS list berubah (mis.
  `LazySpecializeTypeTest` rename atau tambah `NullableLazySpecializeTypeTest`),
  urutan composed salah → `VMStubNamesInClusterOrder` dan
  `VMStubNamesInImageOrder` salah → semua VM stub name setelah anchor
  shift.
- **Usulan**: Tambah assertion di `TestVMStubNamesMatchSDK` (atau test
  terpisah `TestVMTypeTestingStubNamesStable`) yang untuk setiap tag,
  bandingkan `tts` (hasil expand `VM_TYPE_TESTING_STUB_CODE_LIST`) ke
  `vmTypeTestingStubNames` element-wise. Jika ada versi di mana list
  berubah, test fail dengan pesan yang jelas — dan saat itu
  `vmTypeTestingStubNames` harus diubah jadi per-version map, bukan
  hardcoded global.
- **Prioritas**: SEDANG — claim "stable" adalah asumsi yang harus
  diverifikasi, bukan diasumsikan; test infrastructure sudah ada
  (cukup tambah ~5 baris assertion).

### Gap 6: Tiga parser macro berbeda untuk format yang sama

- **Deskripsi**: Tiga test file menulis parser macro C-preprocessor
  sendiri:
  - `internal/vmtables/stubnames_sdk_test.go:155-208`:
    `parseStubMacros` (regex `#define\s+(\w+)\(V\)(.*)`) + `expandStubMacro`
    (rekursif, handle nested macro via `seen` map).
  - `internal/cluster/funckind_sdk_test.go:158-189`:
    `sdkFunctionKinds` (regex `^\s*V\((\w+)\)`, scan line-by-line dari
    setelah `#define FOR_EACH_RAW_FUNCTION_KIND`, break di blank/`#define`).
  - `internal/snapshot/baseobjects_sdk_test.go:115-155`:
    `sdkBaseObjectNames` (regex `AddBaseObject\(([^;]+?)\);` + `quotedRe`
    untuk ambil argumen kedua yang quoted).
  - `tools/extract_thr.go:213-259`: `extractMacroBlock` +
    `parseMacroEntries` (handle `V(Type, name)` multi-arg, ambil
    identifier terakhir).
  Empat implementasi berbeda untuk konsep yang sama (ekstrak entri dari
  macro `V(...)`). `sdktest` package seharusnya menyediakan helper
  bersama.
- **Bukti SDK**: Semua file SDK yang diparse (`stub_code_list.h`,
  `raw_object.h`, `roots.h`, `symbol_list.h`, `class_id.h`,
  `runtime_entry_list.h`) pakai idiom macro `#define NAME(V) V(entry)
  V(entry) ...` dengan variasi: `V(Name)` single-arg,
  `V(Type, name)` multi-arg, `V(Type, name, default)` triple-arg,
  nested macro (`VM_STUB_CODE_LIST` expand `PROBE_POINT_STUBS_LIST(V)`).
- **Dampak**: Jika SDK menambah bentuk macro baru (mis. `V(Type, name,
  flag, comment)` 4-arg), empat tempat harus di-fix independen —
  kemungkinan besar satu akan tertinggal. Sudah terjadi:
  `stubnames_sdk_test.go`'s `expandStubMacro` handle nested macro,
  tapi `funckind_sdk_test.go`'s `sdkFunctionKinds` tidak (tidak perlu
  untuk `FOR_EACH_RAW_FUNCTION_KIND` yang flat, tapi jika SDK menambah
  nesting di sana, silent miss).
- **Usulan**: Pindahkan macro-expansion engine ke `internal/sdktest/`
  sebagai helper bersama:
  - `ExpandMacro(src, macroName string) ([]string, error)` — ekstrak
    body `#define MACRO(V) ...`, expand nested macro rekursif, return
    list entry (ambil identifier terakhir untuk multi-arg, matching
    `parseMacroEntries` behavior).
  - `ExpandMacroRaw(src, macroName string) ([][]string, error)` —
    return raw arg lists per entry, untuk caller yang butuh argumen
    non-terakhir (mis. `AddBaseObject` yang butuh argumen kedua quoted).
  Refactor keempat consumer untuk pakai helper ini. Hapus duplikasi.
- **Prioritas**: SEDANG — bukan bug hari ini, tapi tech debt yang
  membuat gate baru (Gap 1-3) lebih mahal untuk ditulis; refaktor ini
  akan mempermudah implementasi Gap 1-3.

### Gap 7: `GHFileAtTag` tidak konsisten dengan `fetchHeader`/`fetchSDKFile` di `extract_thr.go`

- **Deskripsi**: `sdktest.GHFileAtTag` (baris 42-60) memanggil
  `gh api repos/dart-lang/sdk/contents/<path>?ref=<tag>` **tanpa** header
  `Accept: application/vnd.github.raw`, lalu manual decode base64 JSON
  envelope (`payload.Content`). Sebaliknya, `tools/extract_thr.go`'s
  `fetchHeader` (baris 174-182) dan `fetchSDKFile` (baris 185-193)
  memanggil `gh api` **dengan** `-H "Accept: application/vnd.github.raw+json"`
  dan menerima raw content langsung (tidak perlu base64 decode).
- **Bukti SDK**: GitHub Contents API mendukung dua mode: default
  (JSON envelope dengan `content` base64-encoded) dan raw
  (`Accept: application/vnd.github.raw` → body langsung). Kedua mode
  return data yang sama setelah decode, tapi raw lebih efisien (no
  base64 overhead, no JSON parse).
- **Dampak**: Tidak ada bug fungsional hari ini, tapi:
  1. **Inkonsistensi API**: dua jalur fetch untuk file SDK yang sama
     dengan behavior berbeda — jika GitHub mengubah default content
     negotiation (mis. deprecate base64 envelope), satu jalur break
     dan yang lain tidak, sulit di-debug.
  2. **Overhead**: base64 encode + JSON envelope + base64 decode
     di client = ~33% bandwidth overhead vs raw.
  3. **Code duplication**: logika fetch SDK tersebar di dua package
     (`internal/sdktest` dan `tools/extract_thr.go`).
- **Usulan**: Standardisasi `sdktest.GHFileAtTag` untuk pakai header
  `Accept: application/vnd.github.raw+json` (matching `extract_thr.go`),
  return raw string langsung tanpa base64 decode. Refactor
  `extract_thr.go`'s `fetchHeader`/`fetchSDKFile` untuk call
  `sdktest.GHFileAtTag` (atau pindahkan fetch logic ke `sdktest` dan
  import dari `tools/`). Hapus JSON envelope parsing.
- **Prioritas**: RENDAH — cleanup konsistensi, bukan bug; tapi
  refaktor ini mengurangi surface area untuk latent bug.

### Gap 8: Tidak ada caching di `GHFileAtTag` — test SDK drift gate lambat & rentan rate-limit

- **Deskripsi**: `sdktest.GHFileAtTag` selalu melakukan `exec.Command("gh",
  "api", ...)` baru setiap dipanggil. Tidak ada cache in-process. Test
  yang iterate 19 tag (`TestVMStubNamesMatchSDK`) melakukan 19 HTTP
  round-trip ke GitHub API per test run. GitHub unauthenticated rate
  limit: 60 req/jam. `TestBaseObjectNamesMatchSDK` (11 tag) + 19 + 19
  (THR tables, via `extract_thr.go` yang punya cache sendiri) + 23
  (FunctionKind, via `funcKindLayouts` keys) = potensial 50+ req per
  `AOTOPSY_TEST_SDK=1 go test ./...` run. `extract_thr.go` punya cache
  per-tag (`headers := map[string]string{}`, baris 953/1304) —
  `sdktest` tidak.
- **Bukti SDK**: N/A (ini masalah infrastructure, bukan SDK source).
  Tapi konsekuensinya: test SDK drift gate yang seharusnya murah
  dijalankan sering (CI, pre-commit) menjadi mahal / tidak dijalankan.
- **Dampak**: Friction tinggi untuk menjalankan gate = gate jarang
  dijalankan = drift tidak tertangkap tepat waktu. Jika seseorang
  menjalankan full suite SDK test dua kali dalam satu jam, hitungan
  rate-limit GitHub habis dan test skip dengan `t.Skipf("cannot
  fetch ...: %v")` (baris 55 di `stubnames_sdk_test.go`) — silent
  skip yang terlihat seperti "tidak ada drift" padahal tidak diperiksa.
- **Usulan**: Tambah cache in-process di `sdktest`:
  ```go
  var (
      cacheMu  sync.Mutex
      cache    = map[string]string{}  // key: path+"\x00"+tag
  )
  func GHFileAtTag(path, tag string) (string, error) {
      key := path + "\x00" + tag
      cacheMu.Lock()
      if v, ok := cache[key]; ok { return v, nil }
      cacheMu.Unlock()
      // ... fetch ...
      cacheMu.Lock(); cache[key] = content; cacheMu.Unlock()
      return content, nil
  }
  ```
  Opsi tambahan: cache ke disk (`$AOTOPSY_SDK_CACHE_DIR` atau
  `~/.cache/aotopsy/sdk/<tag>/<path>`) agar test re-run berikutnya
  tidak hit network sama sekali. Ini juga memungkinkan test SDK drift
  gate berjalan offline (setelah warm cache) — berguna untuk
  air-gapped RE environment.
- **Prioritas**: SEDANG — friction tinggi = gate jarang dijalankan
  = tujuan gate (catch drift) tidak tercapai.

### Gap 9: `SkipIfNoSDK` + `HasGH` boilerplate ter-duplikasi 8 tempat

- **Deskripsi**: Setiap test SDK drift gate mulai dengan 4 baris
  boilerplate identik:
  ```go
  if sdktest.SkipIfNoSDK() {
      t.Skip("AOTOPSY_TEST_SDK not set (needs network + gh auth), skipping SDK drift check")
  }
  if !sdktest.HasGH() {
      t.Skip("gh not on PATH, skipping SDK drift check")
  }
  ```
  Muncul di 8 tempat (4 file × 2 fungsi, kecuali `stubnames_sdk_test.go`
  yang punya 1 fungsi pakai + test lain tidak). Lihat grep `SkipIfNoSDK`
  hasil 13 match. Boilerplate ini mudah salah: lupa salah satu cek,
  atau typo pesan skip.
- **Bukti SDK**: N/A (infrastruktur).
- **Dampak**: Tidak ada bug hari ini, tapi setiap gate baru (Gap 1-3)
  akan menambah 4 baris ini lagi. Jika `AOTOPSY_TEST_SDK` semantic
  berubah (mis. tambah `AOTOPSY_TEST_SDK_OFFLINE` untuk cache-only
  mode), 8+ tempat harus di-update.
- **Usulan**: Tambah helper `sdktest.SkipIfNoSDKTools(t *testing.T)`
  yang menggabungkan kedua cek:
  ```go
  func SkipIfNoSDKTools(t *testing.T) {
      t.Helper()
      if os.Getenv("AOTOPSY_TEST_SDK") == "" {
          t.Skip("AOTOPSY_TEST_SDK not set (needs network + gh auth), skipping SDK drift check")
      }
      if _, err := exec.LookPath("gh"); err != nil {
          t.Skip("gh not on PATH, skipping SDK drift check")
      }
  }
  ```
  Refactor 8 tempat untuk call helper ini. `SkipIfNoSDK` dan `HasGH`
  bisa tetap ada untuk backward-compat atau dihapus jika tidak ada
  caller lain.
- **Prioritas**: RENDAH — cleanup DRY, tapi mempermudah adopsi gate
  baru.

### Gap 10: Tidak ada test untuk `sdktest` package sendiri

- **Deskripsi**: `internal/sdktest/` tidak punya `sdktest_test.go`.
  Helper diuji secara tidak langsung oleh 4 consumer. Tidak ada test
  yang memverifikasi: (a) `GHFileAtTag` handle path dengan karakter
  khusus, (b) `GHFileAtTag` return error yang berguna jika tag tidak
  ada, (c) base64 decode handle whitespace/newline di `payload.Content`
  (saat ini di-strip via `strings.ReplaceAll(payload.Content, "\n", "")`,
  baris 55 — tapi tidak di-test), (d) `SkipIfNoSDK`/`HasGH` behavior.
- **Bukti SDK**: N/A.
- **Dampak**: Jika `gh api` response format berubah (mis. GitHub
  tambah field baru di envelope, atau ubah base64 encoding), helper
  break dan 4 consumer test semua skip dengan `t.Skipf("cannot
  fetch ...: %v")` — silent failure yang terlihat seperti "tidak ada
  drift".
- **Usulan**: Tambah `internal/sdktest/sdktest_test.go` dengan:
  - `TestGHFileAtTag_KnownFile`: fetch file kecil yang stabil (mis.
    `runtime/vm/stub_code_list.h` @3.12.2) dan assert content mengandung
    string yang diharapkan (`#define VM_STUB_CODE_LIST`).
  - `TestGHFileAtTag_UnknownTag`: fetch dengan tag tidak valid (mis.
    `nonexistent-tag-xyz`) dan assert error non-nil.
  - `TestGHFileAtTag_Base64Newlines`: unit test untuk base64 decode
    path dengan input yang mengandung newline (mock `payload.Content`).
  - `TestSkipIfNoSDK`/`TestHasGH`: set/unset env, assert behavior.
  Guard dengan `AOTOPSY_TEST_SDK` untuk test yang butuh network.
- **Prioritas**: RENDAH — defense-in-depth untuk helper yang sudah
  bekerja, tapi penting jika Gap 7-9 direfaktor (refaktor tanpa test
  = regresi risk).

## Register Tracking Gaps

"Register" di konteks AOTopsy = Thread-relatif offset (THR field) yang
di-track sebagai map `offset -> name`. Register tracking gaps:

1. **`threadStubOffsets*` (Gap 2)**: 11 tabel offset Thread-relatif untuk
   VM stub entry points tidak diverifikasi. Register yang tidak ditrack
   seharusnya ditrack: setiap `Thread_<name>_entry_point_offset` yang
   ada di `runtime_offsets_extracted.h` untuk arch/PRODUCT/compressed
   combo yang `threadstubs.go` claim support, musti diverifikasi konsisten
   dengan tabel committed.

2. **`runtimeEntriesV*` / `leafEntriesV*` (Gap 3)**: offset runtime entry
   point (`AllocateArray_entry_point`..`AllocateBytecodeCoverageArray_entry_point`
   + LEAF entries) di-merge ke THR map via `mergeRuntimeEntries` dengan
   base offset per-version, tapi nama dan urutan tidak diverifikasi.
   Register yang tidak ditrack: jika SDK menambah entry baru di tengah
   list, offset semua entry setelahnya shift by +8 — saat ini silent.

3. **`handDerivedFields` di `extract_thr.go:846-852`**: 5 field
   (`empty_array`, `empty_type_arguments`, `dynamic_type`,
   `object_sentinel`, `deferred_marking_stack_block`) di-allow sebagai
   "hand-derived" karena SDK tidak export offset-nya. Komentar
   `extract_thr.go:843-845` meng-claim field-field ini dari
   `CACHED_NON_VM_STUB_LIST` / `CACHED_VM_OBJECTS_LIST` declaration order
   di `runtime/vm/thread.h`. **Tidak ada gate yang memverifikasi
   declaration order di `thread.h` tidak berubah** — jika SDK reorder
   field-field ini, offset hand-derived salah tanpa sinyal. Grep MCP
   menemukan `CACHED_NON_VM_STUB_LIST` di `thread.h:183+`:
   ```
   V(ObjectPtr, object_null_, ...)
   V(SentinelPtr, object_sentinel_, ...)
   V(BoolPtr, bool_true_, ...)
   V(BoolPtr, bool_false_, ...)
   V(ArrayPtr, empty_array_, ...)
   ...
   V(TypePtr, dynamic_type_, ...)
   ```
   Urutan ini musti diverifikasi per tag.

4. **Write-barrier wrapper offsets (`wb_wrapper_R%d`)**:
   `extract_thr.go:724-759` meng-derive offset write-barrier wrapper
   per-register dari array `AOT_Thread_write_barrier_wrappers_thread_offset[]`
   di header. Nama di-generate sebagai `wb_wrapper_R<reg>`. Tidak ada
   gate yang memverifikasi jumlah register (array length) konsisten
   dengan `kNumberOfDartAvailableCpuRegs` (lihat `thread.cc:118`).
   Jika SDK menambah register, wrapper offset baru tidak ter-capture.

5. **THR field untuk non-PRODUCT / non-compressed variant**: `allTargets`
   di `extract_thr.go:50-159` mencakup 4 kombinasi (arm64/x64 ×
   compressed/nocompressed × product/nonproduct) untuk banyak versi,
   tapi `committedNameOverrides` (baris 860-868) hanya map 7 nama
   ARM64 v2.x. Tabel non-PRODUCT (`_nonproduct` suffix) di `thrfields.go`/
   `thrfieldsx86.go` — jika ada — tidak di-cover `allTargets` untuk
   semua versi (lihat baris 113-158: non-PRODUCT hanya sampai 3.12.2,
   tidak ada 3.13.0 non-PRODUCT). Jika sample non-PRODUCT 3.13.0 muncul,
   THR map-nya tidak ada dan tidak ada gate yang memperingatkan.

## Fitur RE Missing/Incomplete

Fitur RE useful yang missing/incomplete di `internal/sdktest/`:

1. **Helper `ExpandMacro` bersama (Gap 6)**: test infrastructure untuk
   macro expansion C-preprocessor seharusnya disediakan di `sdktest`,
   bukan di-duplikasi per consumer. Mempermudah gate baru untuk CID
   table, runtime entries, roots, symbol list.

2. **Helper `AssertMacroEntriesStable(t, macroName, expected, tags...)`**:
   helper high-level yang untuk setiap tag, fetch file SDK, expand macro,
   bandingkan ke `expected`. Mempermudah verifikasi claim "stable across
   every supported version" (Gap 5 untuk `vmTypeTestingStubNames`,
   sama untuk `kNumPredefinedSymbols` dll).

3. **Helper `GHFileAtTagCached` dengan disk cache (Gap 8)**: cache
   file SDK ke disk agar test SDK drift gate bisa berjalan offline
   (setelah warm cache). Penting untuk RE environment yang air-gapped
   atau rate-limited.

4. **Helper `SkipIfNoSDKTools(t)` gabungan (Gap 9)**: eliminasi
   boilerplate 4-baris di 8 tempat.

5. **Gate untuk `class_id.h` CID extraction (Gap 1)**: test
   infrastructure untuk ekstraksi CID dari enum `ClassId` yang
   bersarang 5+ level. Butuh preprocessor emulator Go (prototype sudah
   ada di `extractTHRFields`'s stack frame, baris 600-680) atau
   `gcc -E` shell-out. Ini enabler untuk verifikasi `kNumPredefinedCids`
   langsung (Gap 4) dan CID table gate (Gap 1).

6. **Gate untuk `RootsPrefixRefCount` semua versi (Gap 4)**:
   `runCheckRoots` seharusnya iterate semua tag yang punya
   `RootsPrefixRefCount` di `versionProfile`, bukan hardcode `3.13.0`.

7. **Gate untuk `runtime_entry_list.h` compare mode (Gap 3)**:
   ubah `runCheckRuntimeEntries` dari report-only ke compare mode, atau
   tulis test langsung di `internal/vmtables/` yang pakai `sdktest`
   helper.

8. **Gate untuk `threadstubs.go` (Gap 2)**: test yang re-derive
   `threadStubOffsets*` dari `runtime_offsets_extracted.h` per versi.

9. **Verifikasi `handDerivedFields` declaration order (Register
   Tracking Gap 3)**: test yang fetch `runtime/vm/thread.h` di setiap
   tag, parse `CACHED_NON_VM_STUB_LIST` / `CACHED_VM_OBJECTS_LIST`
   declaration order, dan bandingkan ke urutan field hand-derived di
   `extract_thr.go:846-852`.

10. **Verifikasi `kNumPredefinedCids` via preprocessor (Gap 4)**:
    enabler untuk verifikasi `RootsPrefixRefCount` non-sirkular. Bisa
    juga dipakai untuk validasi `CIDTable` field count.

11. **Test untuk `sdktest` package sendiri (Gap 10)**: defense-in-depth
    untuk helper yang sudah bekerja, terutama jika refaktor Gap 7-9
    dijalankan.

## Verifikasi SDK

Verifikasi dilakukan via dua jalur sesuai AGENTS.md "Source of Truth":

### Grep MCP (`searchGitHub` by Vercel, `repo: "dart-lang/sdk"`)

1. **`CACHED_VM_STUBS_ADDRESSES_LIST`** → `runtime/vm/thread.h:218+`:
   mengkonfirmasi macro definisi VM stub entry point yang menjadi sumber
   `threadStubOffsets*` (Gap 2). Snippet menunjukkan
   `V(uword, write_barrier_entry_point_, StubCode::WriteBarrier().EntryPoint(), 0)`
   dll. — format `V(Type, name, expr, default)` 4-arg, yang
   `parseMacroEntries` di `extract_thr.go` handle via "ambil identifier
   terakhir".

2. **`CACHED_NON_VM_STUB_LIST`** → `runtime/vm/thread.h:183+` dan
   `runtime/vm/thread.cc:1336+`: mengkonfirmasi declaration order
   `object_null_`, `object_sentinel_`, `bool_true_`, `bool_false_`,
   `empty_array_`, ..., `dynamic_type_` — sumber `handDerivedFields`
   (Register Tracking Gap 3). Urutan ini musti diverifikasi per tag.

3. **`RUNTIME_ENTRY_LIST`** → `runtime/vm/runtime_entry.h:60+`,
   `runtime/vm/runtime_entry_list.h:1+`, `runtime/vm/thread.cc:118+`,
   `runtime/vm/thread.h:830+`, `runtime/vm/tags.cc:49+`,
   `runtime/vm/compiler/runtime_api.cc:319+`: mengkonfirmasi
   `RUNTIME_ENTRY_LIST` dan `LEAF_RUNTIME_ENTRY_LIST` adalah macro
   yang di-expand di banyak tempat — sumber `runtimeEntriesV*` (Gap 3).

4. **`kClassIdTagPos`** → `runtime/vm/compiler/assembler/assembler_*.cc`
   (arm64, x64, ia32, arm, riscv): mengkonfirmasi
   `UntaggedObject::kClassIdTagPos == 12` dan
   `kClassIdTagSize == 20` di semua arch — konstanta layout object
   header yang `runtime_offsets_extracted.h` export sebagai
   `AOT_UntaggedObject_kClassIdTagPos = 0xc` (diverifikasi via gh api
   @3.13.0). Tidak ada gate yang memverifikasi konstanta layout ini
   per versi (relevant untuk `TagStyleObjectHeader` di `version.go`).

5. **`RAW_OBJECT_FIELD_LIST`** → no results (query salah, macro
   sebenarnya `FOR_EACH_RAW_OBJECT` — juga no results; macro di
   `raw_object.h` pakai nama berbeda per-field). Tidak blocking.

### `gh api` @ version tag

1. **`runtime/vm/runtime_entry_list.h?ref=3.13.0`** vs `?ref=3.12.2`:
   mengkonfirmasi `RUNTIME_ENTRY_LIST(V)` berisi **83 entri di 3.12.2**
   dan **85 entri di 3.13.0** (entri baru: `AllocateBytecodeCoverageArray`
   di awal, `TypeError` di akhir — diverifikasi via `diff` langsung).
   Bandingkan ke `runtimeEntriesV3122` (`thrfields.go:2739-2772`) yang
   claim "RUNTIME_ENTRY_LIST (83)" dan actual count 83 (diverifikasi via
   `awk | tr ',' '\n' | grep -c`): **cocok**. Komentar `runtimeEntriesV3115`
   (`thrfields.go:2796`) claim "82 RUNTIME entries" — konsisten dengan
   3.11.5 yang seharusnya 82 (3.12.2 menambah 1 entry vs 3.11.5).
   **Namun**: tidak ada `runtimeEntriesV3130` di `thrfields.go` — 3.13.0
   tidak punya tabel runtime entries committed, padahal `versionProfile`
   mendukung 3.13.0 (`version.go:1015`). `mergeRuntimeEntries(thrV3122,
   0x2f0, runtimeEntriesV3122)` (baris 2868) dipakai untuk 3.13.0 juga
   (karena `ThreadStubOffsets("3.13.0")` return `threadStubOffsets3122`,
   lihat `threadstubs.go:272-273`), tapi runtime entries 3.13.0 sebenarnya
   punya 2 entry tambahan — **ini drift yang gate Gap 3 akan tangkap**:
   jika sample 3.13.0 di-decompile, offset `AllocateBytecodeCoverageArray_entry_point`
   dan `TypeError_entry_point` tidak akan ter-namai, dan entry setelah
   `AllocateBytecodeCoverageArray` (yang shift +8) akan dapat nama salah.

2. **`runtime/vm/compiler/runtime_offsets_extracted.h?ref=3.13.0`**:
   mengkonfirmasi 225 offset `AOT_*_offset` diekspor (termasuk
   `Thread_*_offset` untuk THR fields, `ObjectStore_*_offset`,
   `Array_data_offset`, `Function_code_offset`, dll.). Hanya
   `Thread_*_offset` yang diverifikasi (`extract_thr.go -check`).
   Offset object layout lain (`Array_data_offset`,
   `Function_code_offset`, `Class_num_type_arguments_offset`, dll.)
   **tidak diverifikasi** — relevant untuk `fill_*.go` cluster fill
   logic yang baca field offset. Jika SDK shift `Array_data_offset`,
   fill Array cluster salah tanpa sinyal.

3. **`runtime/vm/roots.h?ref=3.13.0`**: mengkonfirmasi `RAW_ROOTS_LIST`,
   `HANDLE_ROOTS_LIST`, `API_HANDLE_ROOTS_LIST` terdefinisi, plus
   `kNumPredefinedSymbols`, `kNumStubEntries` reference. Mengkonfirmasi
   struktur yang `runCheckRoots` parse — tapi back-calculation
   `kNumPredefinedCids` (Gap 4) tetap tidak terverifikasi langsung.

### Temuan verifikasi yang actionable

- **`runtimeEntriesV3130` missing — drift aktif untuk 3.13.0**:
  `thrV3130` (THR field map untuk 3.13.0, `thrfields.go:3060`) ada dan
  berisi 31 entri `_entry_point`, tapi hanya entry pertama
  (`AllocateArray_entry_point` @0x2f0) dan entry suspend-state/leaf
  yang ter-namai. **82 entri runtime menengah (AllocateMint..EnsureDeeplyImmutable,
  indeks 1..82 dari RUNTIME_ENTRY_LIST) tidak ter-namai** karena
  `mergeRuntimeEntries(thrV3130, ...)` tidak dipanggil di `init()`
  (`thrfields.go:2857-2870` hanya merge untuk V217/V325/V343/V362/V381/
  V392/V3107/V3110/V3122 — tidak ada V3130). Tidak ada
  `runtimeEntriesV3130`/`leafEntriesV3130` committed. SDK 3.13.0 punya
  85 entri RUNTIME_ENTRY_LIST (`AllocateBytecodeCoverageArray` +
  `TypeError` baru vs 3.12.2's 83, diverifikasi via `diff`
  `runtime_entry_list.h@3.12.2` vs `@3.13.0`). Akibat: di sample 3.13.0,
  offset `AllocateMint_entry_point` (0x2f8) sampai
  `EnsureDeeplyImmutable_entry_point` tidak ter-namai — decompiler
  menampilkan `THR.f2f8` generik alih-alih `THR.AllocateMint_entry_point`.
  **Ini adalah contoh tepat drift yang gate Gap 3 akan tangkap.**
  Investigasi manual direkomendasikan: tambah `runtimeEntriesV3130`
  (85 entri) dan `leafEntriesV3130`, lalu tambah
  `mergeRuntimeEntries(thrV3130, 0x2f0, runtimeEntriesV3130)` di `init()`.
- **Layout konstanta tidak diverifikasi**: `AOT_UntaggedObject_kClassIdTagPos`,
  `kClassIdTagSize`, `kSizeTagPos`, `kSizeTagSize`, `kHashTagPos`,
  `UntaggedPcDescriptors_kKindBitsPos/Size`, `UntaggedClosure_kLengthBitsPos/Size`,
  dll. diekspor SDK tapi tidak ada gate. `version.go`'s `TagStyleObjectHeader`
  (baris 24-27) hardcode "CID at bits 12-31, canonical at bit 1,
  immutable at bit 6" — musti diverifikasi terhadap
  `AOT_UntaggedObject_kClassIdTagPos`/`kClassIdTagSize` per versi.
- **Object layout offset tidak diverifikasi**: 225 offset di
  `runtime_offsets_extracted.h` mencakup `Array_data_offset`,
  `Function_code_offset`, `Class_num_type_arguments_offset`,
  `Closure_length_and_flags_offset`, `Field_kind_bits_offset`, dll.
  `fill_*.go` cluster fill logic baca field-field ini; jika SDK shift,
  fill salah. Gate untuk object layout offset = enabler RE yang
  high-value.
