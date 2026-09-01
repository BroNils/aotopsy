# RE Gap Analysis Report: internal/snapshot

> **STATUS VERIFIKASI (2026-09-01)** — Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`. Koreksi:
> - **"Fitur Missing 1: ekstraksi `obfuscation_map`, Prioritas Tinggi" →
>   SALAH — datanya tidak ada di snapshot AOT.** `gh api
>   runtime/vm/object_store.h?ref=3.13.0`: `to_snapshot(kFullAOT)` return
>   `&ffi_callback_functions_` (baris 432), sementara `obfuscation_map`
>   (baris 222) dan `loading_unit_uris` (baris 223) berada **setelah** komentar
>   batas di baris 218. Keduanya tidak diserialisasi. Ini kelas kesalahan yang
>   AGENTS.md peringatkan (`allocation_stub_`, `var_descriptors`).
>   `loading_units` (baris 178) **sebelum** batas → yang ini memang tersedia,
>   jadi "Fitur Missing 2" separuh benar.
> - **Gap 1 (Kind tidak divalidasi) → CONFIRMED total.** `KindFullAOT` /
>   `KindFullAOTV313` hanya dipakai di `String()` (`snapshot.go:76`); nol
>   perbandingan `Header.Kind == KindFullAOT` di seluruh repo.
> - Gap 2–12 lain cocok dengan kode.

## Ringkasan

Folder `internal/snapshot/` adalah fondasi version profiling AOTopsy: ia
mendeteksi versi Dart dari snapshot hash, memetakan layout field per versi
(CID tables, header shape, tag style, ObjectStore field count), dan mengekstrak
region snapshot dari `libapp.so`. Analisis ini membandingkan kode AOTopsy vs
Dart SDK source (dart-lang/sdk) untuk mencari gap RE.

**Verifikasi SDK**: Semua klaim diverifikasi via `gh api` ke
`repos/dart-lang/sdk/contents/<path>?ref=<tag>` dan/atau grep MCP
(`searchGitHub` dengan `repo: "dart-lang/sdk"`). Tag yang diverifikasi:
2.10.0, 2.12.0, 2.13.0, 2.14.0, 2.15.0, 2.16.0, 2.17.6, 2.18.0, 2.19.0,
3.0.5, 3.1.0, 3.2.5, 3.3.0, 3.4.3, 3.5.0, 3.6.2, 3.7.0, 3.8.1, 3.9.2,
3.10.7, 3.11.0, 3.12.2, 3.13.0.

**Tingkat kematangan kode**: Tinggi. Penulis sudah melakukan verifikasi SDK
yang ekstensif (ObjectStoreAOTFieldCount, base object lists, CID tables,
FuncTypeParamTypesIdx). Gap yang ditemukan sebagian besar adalah fitur RE
yang belum diekstrak (bukan bug koreksi), plus beberapa gap deteksi versi
dan validasi yang berdampak pada ketahanan terhadap snapshot non-standard.

## Struktur Folder

```
internal/snapshot/
├── snapshot.go              (429 baris) — Extract(): ELF symbol resolution,
│                                          header parsing, version detection
├── version.go              (1294 baris) — VersionProfile, CIDTable,
│                                          knownHashes, versionProfiles map,
│                                          DetectVersion, ProbeTagStyle
├── image.go                 (125 baris) — Image header + InstructionsSection
│                                          parsing untuk instruction image
├── baseobjects.go           (160 baris) — VM-isolate base object name table
│                                          (per-version, first 13 entries)
├── probe.go                   (9 baris) — ProbeSnapshotMagic (scan magic bytes)
├── snapshot_test.go          (64 baris) — parseHeader unit tests + fuzz
├── version_fallback_test.go (124 baris) — DetectVersion fallback + BuildMode tests
├── corpus_test.go           (167 baris) — corpus-wide extraction tests
├── baseobjects_sdk_test.go  (155 baris) — SDK drift check untuk base objects
└── fuzz_test.go              (27 baris) — fuzz tests untuk image header parsing
```

## Gap Analysis

### Gap 1: Snapshot `Kind` diparse tapi tidak divalidasi — snapshot non-AOT diam-diam diparse

- **Deskripsi**: `parseHeader` (snapshot.go:397) membaca field `kind` (int64
  di offset 0x0c) dan menyimpannya sebagai `Header.Kind`, tapi tidak ada
  validasi bahwa kind == kFullAOT. `Extract()` tidak memeriksa `Kind` sama
  sekali. Sebuah snapshot `kFull` (0), `kFullJIT` (2), atau `kModule` (3/4)
  akan diparse sebagai AOT tanpa peringatan, padahal cluster formatnya
  berbeda (JIT Code objects memiliki fields tambahan, Module memiliki roots
  berbeda).
- **Bukti SDK**: `runtime/vm/snapshot.h` @3.12.2:
  ```cpp
  enum Kind {
    kFull,      // 0
    kFullCore,  // 1
    kFullJIT,   // 2
    kFullAOT,   // 3
    kModule,    // 4
    kNone,      // 5
    kInvalid    // 6
  };
  ```
  @3.13.0:
  ```cpp
  enum Kind {
    kFull,     // 0
    kFullJIT,  // 1
    kFullAOT,  // 2
    kModule,   // 3
    kInvalid   // 4
  };
  ```
  AOTopsy mendefinisikan `KindFullAOT = 3` (pre-3.13) dan
  `KindFullAOTV313 = 2` (3.13+), tapi tidak ada code path yang membandingkan
  `Header.Kind` dengan konstanta tersebut.
- **Dampak**: Sebuah JIT snapshot (mis. dari debug Flutter build yang
  tidak di-AOT-compile) atau Module snapshot akan diparse dengan profile
  AOT, menghasilkan output yang salah tanpa diagnostic. RE engineer tidak
  tahu bahwa inputnya bukan AOT snapshot.
- **Usulan**: Tambahkan validasi di `Extract()`: jika `Header.Kind` bukan
  `KindFullAOT` (pre-3.13) atau `KindFullAOTV313` (3.13+), emit diagnostic
  `DiagInvalid` dengan pesan "snapshot kind %d is not kFullAOT — AOTopsy
  only supports AOT snapshots". Untuk 3.13+ juga terima `KindModuleV313`
  jika Module snapshots ingin didukung di masa depan.
- **Prioritas**: Tinggi — ini adalah gate pertama yang harus mencegah
  parsing snapshot yang salah jenisnya.

### Gap 2: Features string tidak diekstrak sepenuhnya — arch, OS, sanitizer, flags hilang

- **Deskripsi**: `parseHeader` mengekstrak features string (offset 0x34,
  null-terminated), tapi `Extract()` hanya memeriksa 4 token:
  `compressed-pointers`, `product`, `release`, `debug`. SDK menulis
  banyak token lain yang berguna untuk RE: arch (`arm64`/`x64`/`arm`/
  `ia32`/`riscv32`/`riscv64`), OS (`android`/`ios`/`linux`/`macos`/
  `windows`/`fuchsia`), sanitizer (`asan`/`msan`/`tsan`), `shared_data`,
  `code_comments`, `dwarf_stack_traces`. Tidak ada dari ini yang diekstrak
  ke `Header` atau `Info`.
- **Bukti SDK**: `runtime/vm/dart.cc` @3.13.0, `Dart::FeaturesString`:
  ```cpp
  if (Snapshot::IncludesCode(kind)) {
    ADD_FLAG(asan, FLAG_target_address_sanitizer)
    ADD_FLAG(msan, FLAG_target_memory_sanitizer)
    ADD_FLAG(tsan, FLAG_target_thread_sanitizer)
    ADD_FLAG(shared_data, FLAG_experimental_shared_data)
    ADD_ISOLATE_GROUP_FLAG(code_comments, code_comments, FLAG_code_comments);
    ADD_ISOLATE_GROUP_FLAG(dwarf_stack_traces, dwarf_stack_traces,
                           FLAG_dwarf_stack_traces_mode);
  }
  // arch: ia32/x64/arm/arm64/riscv32/riscv64
  // OS: android/fuchsia/ios/macos/linux/windows
  // compressed-pointers / no-compressed-pointers
  ```
  @2.10.0 formatnya berbeda: arch+OS+ABI digabung (`arm64-sysv`,
  `arm-eabi`, `arm-ios`), dan `code-comments` menggunakan hyphen bukan
  underscore.
- **Dampak**: RE engineer kehilangan info konteks berharga:
  - **arch**: cross-check dengan ELF machine type — mismatch mendeteksi
    corrupted/wrong binary
  - **OS**: menentukan calling convention dan syscall targets
  - **sanitizer**: code dengan asan/tsan memiliki instrumentation tambahan
    yang mengubah code size dan register usage
  - **code_comments**: di !PRODUCT, Code objects memiliki 2 extra refs
    (return_address_metadata_, comments_) — AOTopsy sudah bails pada
    !PRODUCT, tapi `code_comments` flag juga aktif di PRODUCT jika
    FLAG_code_comments diset, yang juga menambah refs
  - **dwarf_stack_traces**: menunjukkan ada DWARF debug info
- **Usulan**: Tambahkan field ke `Header`:
  `Arch string`, `OS string`, `Sanitizers []string`, `CodeComments bool`,
  `DwarfStackTraces bool`, `SharedData bool`. Parse di `parseHeader` atau
  di helper terpisah. Untuk 2.10 yang formatnya berbeda (`arm64-sysv`),
  lakukan version-aware parsing atau parse generic token split.
- **Prioritas**: Sedang — info RE berguna tapi tidak menghalangi parsing.

### Gap 3: Base object names hanya melacak 13 entry pertama — refs 14+ unnamed

- **Deskripsi**: `baseObjectLayouts` (baseobjects.go:50) hanya menyimpan
  13 entry pertama dari AddBaseObjects list untuk setiap version range.
  Komentar mengatakan "Only the leading run matters: pool entries beyond
  it fall back to the existing name resolution". Tapi SDK menambahkan
  ~20+ base objects setelah entry 13 (empty_context_scope, empty_object_pool,
  empty_compressed_stackmaps, empty_descriptors, empty_var_descriptors,
  empty_exception_handlers, empty_async_exception_handlers,
  cached_args_descriptors, cached_icdata_arrays, class table entries).
- **Bukti SDK**: `runtime/vm/app_snapshot.cc` @3.12.2, `AddBaseObjects`:
  ```cpp
  s->AddBaseObject(Object::null(), "Null", "null");                    // 1
  s->AddBaseObject(Object::sentinel().ptr(), "Null", "sentinel");      // 2
  s->AddBaseObject(Object::optimized_out().ptr(), "Null", "<optimized out>"); // 3
  s->AddBaseObject(Object::empty_array().ptr(), "Array", "<empty_array>"); // 4
  s->AddBaseObject(Object::empty_instantiations_cache_array()...);      // 5
  s->AddBaseObject(Object::empty_subtype_test_cache_array()...);        // 6
  s->AddBaseObject(Object::dynamic_type()...);                         // 7
  s->AddBaseObject(Object::void_type()...);                            // 8
  s->AddBaseObject(Object::empty_type_arguments()..., "[]");           // 9
  s->AddBaseObject(Bool::True()..., "true");                           // 10
  s->AddBaseObject(Bool::False()..., "false");                         // 11
  s->AddBaseObject(Object::synthetic_getter_parameter_types()...);     // 12
  s->AddBaseObject(Object::synthetic_getter_parameter_names()...);     // 13
  s->AddBaseObject(Object::empty_context_scope()..., "<empty>");       // 14
  s->AddBaseObject(Object::empty_object_pool()..., "<empty>");         // 15
  s->AddBaseObject(Object::empty_compressed_stackmaps()..., "<empty>"); // 16
  s->AddBaseObject(Object::empty_descriptors()..., "<empty>");         // 17
  s->AddBaseObject(Object::empty_var_descriptors()..., "<empty>");     // 18
  s->AddBaseObject(Object::empty_exception_handlers()..., "<empty>");  // 19
  s->AddBaseObject(Object::empty_async_exception_handlers()...);       // 20
  // + cached_args_descriptors[kCachedDescriptorCount]
  // + cached_icdata_array[kCachedICDataArrayCount]
  // + class table entries (kFirstInternalOnlyCid..kLastInternalOnlyCid)
  ```
  @3.13.0 hanya 7 entry (IncludesCode path), yang sudah benar dilacak.
- **Dampak**: Pool entries yang mereferensikan base object ref 14+
  (empty_object_pool, empty_compressed_stackmaps, empty_descriptors, dll.)
  tidak mendapat nama. RE engineer melihat "ref 15" alih-alih
  "<empty_object_pool>". Ini adalah object-object yang SANGAT sering
  direferensikan (empty descriptors/pool adalah singleton yang dipakai
  oleh banyak Code/Function objects).
- **Usulan**: Perluas `baseObjectLayouts` untuk menyimpan SEMUA base
  objects hingga class table entries dimulai. Untuk class table entries
  (yang jumlahnya = kNumPredefinedCids - kFirstInternalOnlyCid), gunakan
  formula: ref = baseOffset + (cid - kFirstInternalOnlyCid), name =
  CIDTable lookup. Tambahkan test SDK drift yang memverifikasi count.
- **Prioritas**: Sedang — meningkatkan name resolution coverage untuk
  object pool entries yang sering muncul.

### Gap 4: Dart 2.10 tidak memiliki base object names — supported version tapi BaseObjectNames returns nil

- **Deskripsi**: `baseObjectLayouts` dimulai dari range {2, 12, 2, 18}.
  Dart 2.10.0 adalah version dengan `Supported: true` (versionProfiles
  entry), tapi `BaseObjectNames("2.10.0")` returns nil. Padahal SDK 2.10
  memiliki AddBaseObjects list sendiri yang berbeda dari 2.12+.
- **Bukti SDK**: `runtime/vm/clustered_snapshot.cc` @2.10.0:
  ```cpp
  s->AddBaseObject(Object::null(), "Null", "null");
  s->AddBaseObject(Object::sentinel().raw(), "Null", "sentinel");
  s->AddBaseObject(Object::transition_sentinel().raw(), "Null", "transition_sentinel");
  s->AddBaseObject(Object::empty_array().raw(), "Array", "<empty_array>");
  s->AddBaseObject(Object::zero_array().raw(), "Array", "<zero_array>");
  s->AddBaseObject(Object::dynamic_type().raw(), "Type", "<dynamic type>");
  s->AddBaseObject(Object::void_type().raw(), "Type", "<void type>");
  s->AddBaseObject(Object::empty_type_arguments()..., "[]");
  s->AddBaseObject(Bool::True().raw(), "bool", "true");
  s->AddBaseObject(Bool::False().raw(), "bool", "false");
  s->AddBaseObject(Object::extractor_parameter_types()...);
  s->AddBaseObject(Object::extractor_parameter_names()...);
  s->AddBaseObject(Object::empty_context_scope()..., "<empty>");
  // + empty_descriptors, empty_var_descriptors, empty_exception_handlers,
  //   implicit_*_bytecode (Bytecode entries — 2.10-specific!)
  ```
  List 2.10 memiliki `transition_sentinel`, `zero_array`,
  `extractor_parameter_types/names` (bukan `synthetic_getter_*`), dan
  entries Bytecode yang tidak ada di 2.12+.
- **Dampak**: Semua pool entries di snapshot 2.10 yang mereferensikan
  base objects (null, true, false, empty_array, dll.) tidak mendapat nama.
  Name resolution untuk 2.10 lebih buruk daripada 2.12+.
- **Usulan**: Tambahkan entry `{2, 10, 2, 10, []string{...}}` ke
  `baseObjectLayouts` dengan list lengkap dari SDK 2.10.0. Perluas
  `TestBaseObjectNamesMatchSDK` probes untuk include `2.10.0`.
- **Prioritas**: Sedang — 2.10 adalah supported version, harus memiliki
  base object names yang lengkap.

### Gap 5: Image header `kHeaderSize` hardcoded ke 16 — salah untuk versi modern (64 bytes)

- **Deskripsi**: `image.go` mendefinisikan `imageHeaderSize = 16` (2 * 8
  bytes) dan menggunakannya sebagai code start offset di fallback path
  `CodeRegion()`. Tapi SDK mendefinisikan `Image::kHeaderSize =
  kObjectStartAlignment` yang = 16 di 2.10 (kMaxObjectAlignment=16) tapi
  = 64 di 3.13.0 (kObjectStartAlignment=64). Fallback path hanya trigger
  ketika `InstructionsSectionOffset == 0 || >= len(data)` (kasus 2.10),
  jadi untuk modern binary ini tidak menyebabkan bug aktif. Tapi jika
  modern binary corrupt dan fallback trigger, code akan dibaca dari
  offset 16 alih-alih 64 — 48 bytes padding sebagai "code".
- **Bukti SDK**:
  - @2.10.0: `kMaxObjectAlignment = 16` → `kHeaderSize = 16`
    (`runtime/vm/pointer_tagging.h:67`, `runtime/vm/image_snapshot.h:70`)
  - @3.13.0: `kObjectStartAlignment = 64` → `kHeaderSize = 64`
    (`runtime/vm/pointer_tagging.h:74`, `runtime/vm/image_snapshot.h:132`)
- **Dampak**: Latent correctness bug di fallback path. Tidak aktif untuk
  binary modern yang valid, tapi akan menghasilkan output sampah untuk
  binary corrupt/edge-case.
- **Usulan**: Buat `imageHeaderSize` version-dependent, atau ambil dari
  profile. Alternatif: baca `kObjectStartAlignment` dari profile (tambah
  field `ImageHeaderSize int` ke `VersionProfile`). Atau minimal:
  dokumentasikan bahwa fallback path hanya valid untuk 2.10 dan assert
  bahwa `InstructionsSectionOffset != 0` untuk versi >= 2.12.
- **Prioritas**: Rendah — latent bug, tidak aktif untuk input valid.

### Gap 6: InstructionsSection layout hardcoded 8-byte words — 32-bit arch tidak didukung

- **Deskripsi**: `image.go` mendefinisikan `instructionsSectionFields = 40`
  (5 * 8 bytes) dan membaca semua field sebagai `binary.LittleEndian.Uint64`.
  Tapi `UntaggedInstructionsSection` menggunakan `uword`/`word` yang = 4
  bytes pada 32-bit arch (ia32, arm). Pada 32-bit, layout = 5 * 4 = 20 bytes.
- **Bukti SDK**: `runtime/vm/raw_object.h` @3.13.0:
  ```cpp
  class UntaggedInstructionsSection : public UntaggedObject {
    uword payload_length_;        // 4 or 8 bytes
    word bss_offset_;             // 4 or 8 bytes
    uword instructions_relocated_address_; // 4 or 8 bytes
    word build_id_offset_;        // 4 or 8 bytes
  };
  ```
  `uword` = `sizeof(void*)` = 4 pada 32-bit, 8 pada 64-bit.
- **Dampak**: Parsing instruction image dari 32-bit libapp.so (ia32/arm)
  akan membaca field dengan offset salah — semua nilai menjadi sampah.
  Code region extraction akan gagal atau mengembalikan range yang salah.
  AOTopsy saat ini hanya di-test pada arm64 dan x86_64 (keduanya 64-bit),
  jadi ini tidak aktif, tapi menutup pintu untuk support 32-bit.
- **Usulan**: Tambahkan parameter `wordSize int` (4 atau 8) ke
  `ParseInstructionsSection` dan `CodeRegion`. Deteksi word size dari ELF
  machine type (EM_386/EM_ARM → 4, EM_AARCH64/EM_X86_64 → 8) atau dari
  features string arch token.
- **Prioritas**: Rendah — 32-bit Flutter apps semakin langka, tapi
  dokumentasikan batasan ini secara eksplisit.

### Gap 7: `BuildIDOffset` diparse tapi tidak digunakan untuk ekstraksi build ID

- **Deskripsi**: `InstructionsSection.BuildIDOffset` (image.go:35) diparse
  dari offset 0x20 dari InstructionsSection object, tapi tidak pernah
  digunakan untuk membaca actual build ID bytes. `fingerprint.go`
  mengextract build ID via ELF note section parsing terpisah
  (`extractBuildID`), bukan via `BuildIDOffset`.
- **Bukti SDK**: `runtime/vm/raw_object.h` @3.13.0:
  ```cpp
  // The offset of the GNU build ID note section from this text section.
  word build_id_offset_;
  ```
  `build_id_offset_` adalah offset dari InstructionsSection ke GNU build
  ID note — ini adalah path SDK-native untuk menemukan build ID.
- **Dampak**: Tidak ada cross-validation antara build ID dari ELF note
  dan dari InstructionsSection. Jika ELF note section dipindah/dihapus
  oleh obfuscator tapi `build_id_offset_` masih utuh, AOTopsy tidak akan
  menemukan build ID. Sebaliknya, `build_id_offset_` bisa digunakan
  sebagai sumber alternatif.
- **Usulan**: Tambahkan method `ExtractBuildID(imageData []byte) string`
  ke `InstructionsSection` yang membaca GNU note di
  `offset + build_id_offset_`. Cross-check dengan `extractBuildID` di
  fingerprint package. Jika mismatch, emit diagnostic.
- **Prioritas**: Rendah — build ID sudah diekstrak via path lain, ini
  hanya redundancy/cross-check.

### Gap 8: `SymSnapshotBuildID` didefinisikan tapi tidak pernah digunakan

- **Deskripsi**: `snapshot.go:21` mendefinisikan
  `SymSnapshotBuildID = "_kDartSnapshotBuildId"`, tapi symbol ini tidak
  pernah di-resolve di `Extract()` atau di mana pun. `targets` list di
  `Extract()` hanya berisi 4 symbol snapshot (atau 2 untuk unified).
- **Bukti SDK**: Symbol `_kDartSnapshotBuildId` adalah ELF symbol yang
  menunjuk ke build ID string di instruction image. Ada di Flutter engine
  build output.
- **Dampak**: Build ID yang accessible via ELF symbol tidak dimanfaatkan
  sebagai fallback ketika ELF note section dan `build_id_offset_` keduanya
  gagal.
- **Usulan**: Resolve `SymSnapshotBuildID` di `Extract()` sebagai
  optional symbol. Jika ditemukan, baca string di VA tersebut dan simpan
  ke `Info.BuildID` (field baru). Cross-check dengan fingerprint package.
- **Prioritas**: Rendah — dead code, tapi symbol definition sudah ada,
  tinggal wire up.

### Gap 9: `ProbeTagStyle` CID range check terlalu longgar — `cid > 0 && cid < 200`

- **Deskripsi**: `ProbeTagStyle` (version.go:1113) menerima CID jika
  `cid > 0 && cid < 200`. Tapi `NumPredefinedCids` max adalah 176 (3.12.2)
  dan 176 (3.13.0). Range 200 terlalu longgar — sebuah random bytes yang
  decode ke CID 150-199 akan false-positive match ke profile manapun
  yang CID-nya di range tersebut.
- **Bukti SDK**: `NumPredefinedCids` per version:
  - 2.10: 156, 2.12: 148, 2.13: 148, 2.14: 152, 2.15: 154, 2.16: 154,
    2.17: 158, 2.18: 159, 2.19: 176, 3.0: 177, 3.2: 176, 3.4: 174,
    3.6-3.9: 175, 3.13: 176
  Max semua version: 177 (3.0.5).
- **Dampak**: False-positive version detection untuk snapshot dengan hash
  unknown. ProbeTagStyle bisa memilih profile yang salah jika first cluster
  tag secara kebetulan decode ke CID yang plausible.
- **Usulan**: Ganti dengan `cid > 0 && cid <= prof.CIDs.NumPredefinedCids`.
  Setiap candidate profile memiliki `NumPredefinedCids` sendiri, jadi
  bound menjadi version-specific. Tambahan: validasi bahwa CID yang
  terbaca adalah CID yang memiliki serialization cluster (bukan abstract
  base class CID seperti kObjectCid, kErrorCid, dll.).
- **Prioritas**: Sedang — meningkatkan akurasi version detection untuk
  snapshot unknown-hash.

### Gap 10: `ProbeTagStyle` hanya cek first cluster — tidak validasi konsistensi

- **Deskripsi**: `ProbeTagStyle` membaca hanya first cluster tag dan
  menerima profile pertama yang menghasilkan CID plausible. Tidak ada
  validasi bahwa cluster kedua, ketiga, dll. juga menghasilkan CID
  plausible di bawah profile yang sama. Sebuah snapshot yang first-tag-nya
  kebetulan valid di bawah dua profile (mis. 3.2.5 dan 3.4.3 yang sama-sama
  memiliki Code=18) akan pick profile yang pertama di candidate list
  (3.9.2), bukan yang benar.
- **Bukti SDK**: Cluster tags ditulis berurutan oleh serializer. Setiap
  tag harus decode ke CID yang valid DAN memiliki serialization cluster
  di version tersebut. Membaca 2-3 tag pertama dan memvalidasi semua-nya
  akan eliminasi false-positive.
- **Dampak**: Version detection bisa salah untuk snapshot unknown-hash
  yang first cluster CID-nya ambiguous. Profile yang salah → CID table
  salah → semua cluster parsing salah.
- **Usulan**: Baca 3 cluster tags pertama (skip header fields, read tag,
  skip cluster alloc section, read next tag). Validasi semua 3 CID
  plausible di bawah profile yang sama. Pilih profile dengan match
  terbanyak. Jika tie, prefer profile dengan tag style yang lebih spesifik
  (ObjectHeader > CidShift1 > CidInt32).
- **Prioritas**: Sedang — meningkatkan robustness version detection.

### Gap 11: Tidak ada deteksi versi dari features string format

- **Deskripsi**: Features string format berubah antar versi:
  - 2.10: `arm64-sysv`, `arm-eabi`, `arm-ios` (arch+OS+ABI combined),
    `code-comments` (hyphen)
  - 3.13: `arm64`, `android` (separate tokens), `code_comments` (underscore)
  AOTopsy tidak menggunakan perbedaan format ini sebagai sinyal versi
  tambahan. Untuk snapshot unknown-hash, format features string bisa
  mempersempit rentang versi.
- **Bukti SDK**:
  - @2.10.0 `dart.cc`: `buffer.AddString(" arm64-sysv")`,
    `buffer.AddString(FLAG_code_comments ? " code-comments" : ...)`
  - @3.13.0 `dart.cc`: `buffer.AddString(" arm64")`,
    `ADD_FLAG(code_comments, FLAG_code_comments)` → `code_comments`
- **Dampak**: Untuk snapshot unknown-hash, ProbeTagStyle adalah satu-satunya
  sinyal versi. Features string format yang sudah terbaca tidak dimanfaatkan
  untuk mempersempit kandidat.
- **Usulan**: Tambahkan `featuresStringFormat` detection:
  - Jika features mengandung token `*-sysv`/`*-eabi`/`*-ios` → versi ≤2.x
  - Jika features mengandung `code-comments` (hyphen) → versi ≤2.x
  - Jika features mengandung `code_comments` (underscore) → versi ≥3.x
  - Jika features mengandung `compressed-pointers` → versi ≥2.16
    (compressed pointers diperkenalkan di 2.16)
  Gunakan ini untuk memfilter candidate list di ProbeTagStyle sebelum
  mencoba tag decode.
- **Prioritas**: Sedang — sinyal versi tambahan yang gratis dari data
  yang sudah terbaca.

### Gap 12: `SnapshotKind.String()` ambiguous untuk 3.13.0+

- **Deskripsi**: `SnapshotKind.String()` (snapshot.go:68) mengembalikan
  string yang sama untuk kind=2 dan kind=3 di 3.13+:
  - kind=2 → "FullJIT/FullAOT(v3.13+)"
  - kind=3 → "FullAOT/Module(v3.13+)"
  Tapi di 3.13.0, kind=2 adalah kFullAOT dan kind=3 adalah kModule.
  Label "FullJIT/FullAOT" untuk kind=2 ambigu — user tidak tahu apakah
  ini JIT atau AOT.
- **Bukti SDK**: @3.13.0: kFull=0, kFullJIT=1, kFullAOT=2, kModule=3.
  @3.12.2: kFull=0, kFullCore=1, kFullJIT=2, kFullAOT=3.
  AOTopsy tidak punya cara untuk membedakan apakah kind=2 berarti
  kFullJIT (pre-3.13) atau kFullAOT (3.13+) tanpa info versi.
- **Dampak**: Display string membingungkan. RE engineer tidak tahu
  apakah snapshot adalah AOT atau JIT dari output saja.
- **Usulan**: Buat `SnapshotKind.String()` menerima `dartVersion` parameter,
  atau buat method `KindLabel(version string)` yang memilih label yang
  benar berdasarkan versi. Untuk 3.13+: kind=2 → "FullAOT", kind=3 →
  "Module". Untuk pre-3.13: kind=2 → "FullJIT", kind=3 → "FullAOT".
- **Prioritas**: Rendah — cosmetic, tapi membingungkan untuk user.

## Register Tracking Gaps

Paket `internal/snapshot` tidak melakukan register tracking langsung (itu
adalah tugas `internal/sdk`, `internal/disasm`, `internal/typetrack`).
Namun, ada beberapa field `VersionProfile` yang mempengaruhi register
tracking dan memiliki gap:

### Register Gap 1: `FuncTypeParamTypesIdx` tidak diverifikasi untuk 2.10.0

- **Deskripsi**: `FuncTypeParamTypesIdx` (version.go:159) didokumentasikan
  sebagai "2.10.0 was NOT checked (its raw_object.h isn't at the same
  repo path at that tag) -- left at 0 (unverified) rather than guessed."
  Nilai 0 berarti "not verified -- don't extract", jadi parameter types
  FunctionType tidak diekstrak untuk 2.10.
- **Dampak**: FunctionType parameter type names hilang untuk 2.10
  snapshots. RE engineer tidak melihat parameter types di signature
  reconstruction.
- **Usulan**: Cari `raw_object.h` di 2.10.0 dengan path alternatif
  (mungkin `runtime/vm/raw_object.h` sudah ada, atau di file berbeda).
  Verifikasi field order UntaggedFunctionType di 2.10.0 dan set
  `FuncTypeParamTypesIdx` ke nilai yang benar (kemungkinan 3, sama
  dengan 2.12-3.0.5).
- **Prioritas**: Sedang — 2.10 adalah supported version.

### Register Gap 2: Tidak ada tracking `DartCallingConvention` register per versi

- **Deskripsi**: AGENTS.md mencatat bahwa `DartCallingConvention` tidak
  ada di `constants_arm64.h` @2.12.0, first appears @3.4.3. Ini
  mempengaruhi bagaimana receiver diteruskan (register vs stack). Tapi
  `VersionProfile` tidak memiliki field untuk ini. Register tracking
  di `internal/typetrack` harus menebak berdasarkan versi.
- **Dampak**: Receiver recovery di Dart 2.x salah karena asumsi calling
  convention 3.x digunakan. AGENTS.md mencatat ini sudah diperbaiki
  via selector scan fallback, tapi field yang eksplisit tidak ada.
- **Usulan**: Tambahkan field `ReceiverOnStack bool` (true untuk ≤3.3,
  false untuk ≥3.4) ke `VersionProfile`. Set berdasarkan verifikasi
  `constants_arm64.h` per versi.
- **Prioritas**: Rendah — sudah di-work-around, tapi field eksplisit
  akan membuat code lebih jelas.

## Fitur RE Missing/Incomplete

### Fitur Missing 1: Tidak ada ekstraksi obfuscation map

> **[REFUTED 2026-09-01]** `obfuscation_map` ada di `OBJECT_STORE_FIELD_LIST`
> tetapi **setelah** batas `to_snapshot(kFullAOT)` (= `&ffi_callback_functions_`),
> jadi tidak pernah ikut diserialisasi ke roots AOT. Tidak ada yang bisa
> diekstrak. Sama untuk `loading_unit_uris`.

- **Deskripsi**: ObjectStore memiliki field `obfuscation_map` (Array)
  yang diserialisasi di snapshot. AOTopsy tidak mengekstrak atau
  menggunakan ini. Obfuscation map memetakan original names ke
  obfuscated names — critical untuk RE obfuscated apps.
- **Bukti SDK**: `runtime/vm/object_store.h` @3.13.0:
  ```cpp
  RW(Array, obfuscation_map)
  ```
  Diserialisasi sebagai bagian dari ObjectStore roots section.
- **Dampak**: RE engineer tidak bisa de-obfuscate names bahkan ketika
  obfuscation map ada di snapshot.
- **Usulan**: Setelah ObjectStore fields di-parse, ekstrak
  `obfuscation_map` entry dan simpan ke `Info.ObfuscationMap`. Build
  reverse mapping (obfuscated → original) dan apply ke function/class
  names di output stage.
- **Prioritas**: Tinggi — fitur RE yang sangat valuable untuk obfuscated
  apps.

### Fitur Missing 2: Tidak ada ekstraksi loading unit URIs

- **Deskripsi**: ObjectStore memiliki field `loading_unit_uris` (Array)
  dan `loading_units` (Array). AOTopsy tidak mengekstrak info loading
  unit. Loading units adalah split-AOT feature di mana app dibagi menjadi
  multiple `.so` files dengan deferred loading.
- **Bukti SDK**: `runtime/vm/object_store.h` @3.13.0:
  ```cpp
  RW(Array, loading_units)
  RW(Array, loading_unit_uris)
  ```
- **Dampak**: RE engineer tidak tahu apakah binary adalah loading unit
  fragment atau complete app, dan tidak tahu URI mapping untuk deferred
  libraries.
- **Usulan**: Ekstrak `loading_units` dan `loading_unit_uris` dari
  ObjectStore roots. Report ke user: jumlah loading units, URIs, dan
  apakah binary ini adalah unit 0 (base) atau fragment.
- **Prioritas**: Sedang — berguna untuk analisa split-AOT apps.

### Fitur Missing 3: Tidak ada deteksi `Snapshot::IncludesStringsInROData`

- **Deskripsi**: SDK 3.13.0 memiliki `Snapshot::IncludesStringsInROData(kind)`
  yang mengembalikan true untuk IncludesCode(kind) ketika
  `!defined(DART_COMPRESSED_POINTERS)`. Ini menentukan apakah strings
  disimpan di ROData section terpisah. AOTopsy tidak mendeteksi ini dari
  features string (`no-compressed-pointers` token).
- **Bukti SDK**: `runtime/vm/snapshot.h` @3.13.0:
  ```cpp
  static bool IncludesStringsInROData(Kind kind) {
  #if !defined(DART_COMPRESSED_POINTERS)
    return IncludesCode(kind);
  #else
    return false;
  #endif
  }
  ```
- **Dampak**: Untuk snapshot non-compressed-pointers, strings ada di
  ROData section terpisah yang AOTopsy mungkin tidak parse dengan benar.
- **Usulan**: Tambahkan field `StringsInROData bool` ke `VersionProfile`,
  set dari `!CompressedPointers && IncludesCode`. Pastikan cluster
  parser menangani ROData string section.
- **Prioritas**: Sedang — mempengaruhi string extraction untuk
  non-compressed-pointer builds.

### Fitur Missing 4: Tidak ada enumerasi semua snapshot magic occurrences

- **Deskripsi**: `ProbeSnapshotMagic` (probe.go) hanya mengembalikan
  offset occurrence pertama. Tidak ada function yang mengenumerasi semua
  occurrence. Sebuah `libapp.so` bisa memiliki multiple snapshot blobs
  (mis. loading units, atau corrupted/partial snapshots).
- **Dampak**: RE engineer tidak tahu jika ada snapshot tambahan di binary
  yang tidak ter-cover oleh ELF symbols.
- **Usulan**: Tambahkan `FindAllSnapshotMagics(data []byte) []int` yang
  mengembalikan semua offset. Cross-check dengan ELF symbol VAs — jika
  ada magic occurrence yang tidak sesuai dengan symbol manapun, report
  sebagai "orphan snapshot".
- **Prioritas**: Rendah — edge case, tapi berguna untuk analisa loading
  units.

### Fitur Missing 5: Tidak ada ekstraksi `instructions_relocated_address_`

- **Deskripsi**: `InstructionsSection.InstructionsRelocatedAddress`
  (image.go:34) diparse tapi tidak digunakan. Field ini adalah relocated
  base address dari instruction section — berguna untuk menghitung
  actual runtime address dari code offsets ketika ASLR/relocation
  diterapkan.
- **Dampak**: RE engineer harus menebak base address untuk VA calculation
  dari code offsets.
- **Usulan**: Expose `InstructionsRelocatedAddress` ke caller dan
  gunakan di disasm stage sebagai base address untuk relative offsets.
- **Prioritas**: Rendah — sebagian besar analisa AOTopsy menggunakan
  ELF VAs langsung.

### Fitur Missing 6: Tidak ada support untuk Dart 3.14+ (future versions)

- **Deskripsi**: `versionProfiles` dan `knownHashes` berhenti di 3.13.0.
  Tidak ada mekanisme untuk auto-detect versi baru dari CID table
  pattern matching. Setiap versi baru memerlukan entri manual.
- **Dampak**: Snapshot Dart 3.14+ akan fall through ke ProbeTagStyle
  fallback, yang mungkin memilih profile 3.9.2 yang salah.
- **Usulan**: Tambahkan "fuzzy matching" mode: jika hash unknown, baca
  CID table dari class_id.h di GitHub main branch dan bandingkan dengan
  CIDs yang terbaca dari snapshot. Auto-generate profile sementara.
  Alternatif: tambahkan command `aotopsy add-version <hash> <version>`
  yang fetch SDK source dan generate profile entry.
- **Prioritas**: Sedang — akan menjadi masalah ketika Dart 3.14 dirilis.

### Fitur Missing 7: `BSSOffset` diparse tapi tidak digunakan untuk BSS resolution

- **Deskripsi**: `InstructionsSection.BSSOffset` (image.go:33) diparse
  tapi tidak digunakan. BSS section berisi runtime data seperti thread
  pointer, object pool base, dan dispatch table base — critical untuk
  understanding code yang mengakses BSS.
- **Dampak**: RE engineer tidak tahu di mana BSS section berada relatif
  ke instruction image, sehingga tidak bisa resolve BSS-relative
  accesses di disasm.
- **Usulan**: Expose BSS offset ke disasm/naming stage. Gunakan untuk
  resolve `[X28, #offset]` style BSS accesses ke named fields (THR,
  object pool, dispatch table).
- **Prioritas**: Sedang — BSS resolution adalah fitur RE penting yang
  sudah ada di `internal/sdk` THR tables, tapi BSS offset dari image
  header tidak di-wire up.

## Verifikasi SDK

Berikut adalah ringkasan verifikasi yang dilakukan terhadap Dart SDK
source (dart-lang/sdk) via `gh api`:

| Verifikasi | File SDK | Tag | Hasil |
|---|---|---|---|
| Snapshot header layout (magic+length+kind) | `runtime/vm/snapshot.h` | 3.13.0, 3.12.2 | Konfirmasi: magic(4) + length(8) + kind(8) = 20 bytes. Hash+features ditulis setelahnya oleh `WriteVersionAndFeatures`. |
| Snapshot::Kind enum | `runtime/vm/snapshot.h` | 3.13.0, 3.12.2 | 3.12.2: kFull=0,kFullCore=1,kFullJIT=2,kFullAOT=3,kModule=4,kNone=5. 3.13.0: kFull=0,kFullJIT=1,kFullAOT=2,kModule=3. **AOTopsy mapping benar.** |
| FeaturesString content | `runtime/vm/dart.cc` | 3.13.0, 2.10.0 | 3.13: debug/product/release + asan/msan/tsan/shared_data + code_comments/dwarf_stack_traces + arch + OS + compressed-pointers. 2.10: format berbeda (arch-os-abi combined, code-comments hyphen). **AOTopsy hanya extract 4 token.** |
| Image::kHeaderSize | `runtime/vm/image_snapshot.h`, `pointer_tagging.h` | 3.13.0, 2.10.0 | 2.10: kMaxObjectAlignment=16. 3.13: kObjectStartAlignment=64. **AOTopsy hardcoded 16 — salah untuk 3.13 fallback path.** |
| UntaggedInstructionsSection layout | `runtime/vm/raw_object.h` | 3.13.0 | tags_ + payload_length_ + bss_offset_ + instructions_relocated_address_ + build_id_offset_ = 5 fields. **AOTopsy 40 bytes (5×8) benar untuk 64-bit, salah untuk 32-bit.** |
| AddBaseObjects (3.13.0) | `runtime/vm/app_snapshot.cc` | 3.13.0 | IncludesCode path: 7 entries (null,false,true,sentinel,unknown_constant,non_constant,optimized_out). **AOTopsy 3.13 layout benar.** |
| AddBaseObjects (3.12.2) | `runtime/vm/app_snapshot.cc` | 3.12.2 | 20+ entries sebelum cached/class-table. **AOTopsy hanya track 13.** |
| AddBaseObjects (2.10.0) | `runtime/vm/clustered_snapshot.cc` | 2.10.0 | List berbeda: transition_sentinel, zero_array, extractor_parameter_types/names, Bytecode entries. **AOTopsy tidak track 2.10 sama sekali.** |
| ObjectStoreAOTFieldCount (3.13.0) | `runtime/vm/object_store.h` | 3.13.0 | from()=list_class, to_snapshot(kFullAOT)=ffi_callback_functions. Count=171 (line-based grep). **AOTopsy 171 benar.** |
| CLASS_LIST_INTERNAL_ONLY (3.13.0) | `runtime/vm/class_id.h` | 3.13.0 | Termasuk Bytecode, Instructions, InstructionsSection, InstructionsTable, LocalVarDescriptors, ApiError, UnwindError. Bytecode cluster hanya ada jika DART_DYNAMIC_MODULES. **AOTopsy tidak track Bytecode/Instructions/InstructionsTable — OK untuk standard AOT.** |
| IsAbsentCid (3.13.0) | `runtime/vm/app_snapshot.cc` | 3.13.0 | kObjectCid, kErrorCid, kCallSiteDataCid, kAbstractTypeCid, kFinalizerBaseCid, kTypedDataBaseCid, kTypedDataCid, kExternalTypedDataCid, kTypedDataViewCid, kStringCid, kFfiStructCid adalah absent. **AOTopsy tidak track ini — OK (tidak perlu cluster dispatch).** |
| kDeltaEncodedTypedDataCid | `runtime/vm/app_snapshot.cc` | 3.13.0 | `kDeltaEncodedTypedDataCid = kNativePointer = 1`. **AOTopsy NativePointerCid=1 benar.** |
| Bytecode presence | `runtime/vm/class_id.h` | 3.4.3, 3.9.2, 3.13.0 | 3.4.3: tidak ada. 3.9.2 & 3.13.0: ada di class_id.h tapi cluster hanya jika DART_DYNAMIC_MODULES. **AOTopsy tidak track — OK untuk standard AOT.** |
| ObjectStore fields (3.13.0) | `runtime/vm/object_store.h` | 3.13.0 | obfuscation_map, loading_units, loading_unit_uris diserialisasi. **AOTopsy tidak ekstrak.** |

---

*Report ini dihasilkan dengan membaca seluruh file di
`internal/snapshot/` (10 file Go, 2554 baris total) dan verifikasi
terhadap Dart SDK source di 23 tag versi via `gh api`. Tidak ada
build/test/run AOTopsy yang dijalankan — ini adalah research report
murni untuk gap planning.*
