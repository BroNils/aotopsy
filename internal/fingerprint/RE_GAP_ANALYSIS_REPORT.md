# RE Gap Analysis Report: internal/fingerprint

> **STATUS VERIFIKASI (2026-09-01)** — semua 8 gap CONFIRMED, tidak ada
> koreksi. Detail: `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> `Report` (fingerprint.go) memang hanya `{Path, Machine, BuildID,
> FlutterVersion, DartVersion, FlutterMarkers, DartMarkers, Confidence,
> FileSize, ExecSectionSize}`, dan paket ini **tidak mengimpor
> `internal/snapshot` sama sekali** — tidak ada parse header snapshot, hash
> versi, features string, symbol presence, maupun instruction pattern.
> Kritik inti report ("fingerprinter versi Dart yang melewatkan snapshot hash
> adalah kontradiksi") tepat.

## Ringkasan

Folder `internal/fingerprint/` berisi **satu** file sumber (`fingerprint.go`,
312 baris) plus test-nya. Paket ini adalah port dari `flutterdec`'s
`engine_fingerprint.rs` (Rust) — sebuah fingerprinter *snapshot-unaware* yang
mendeteksi versi Flutter/Dart engine dengan **scan string ASCII** di seluruh
file ELF, plus ekstraksi GNU build-id dari note section.

Ini adalah masalah arsitektur terbesar: **tugas folder ini menurut
spesifikasinya adalah "fingerprinting versi Dart dari binary characteristics
(ELF structure, snapshot header, instruction patterns)", tapi kode
mengabaikan tiga dari empat sumber utama:**

1. **Snapshot header** — TIDAK diparse sama sekali. Header snapshot Dart
   (magic `0xdcdcf5f5`, hash versi 32-hex di offset `0x14`, features string
   di `0x34`, field `kind`) adalah **identifier versi yang definitif dan
   deterministik**, hadir di setiap AOT snapshot by construction, tapi
   `fingerprint.Run` tidak pernah membaca symbol `_kDartVmSnapshotData` /
   `_kDartIsolateSnapshotData` / `_kDartSnapshotData`. Seluruh logika
   version-ID yang sesungguhnya hidup di `internal/snapshot` (map
   `knownHashes`, `DetectVersion`, `ProbeTagStyle`) — `fingerprint` tidak
   mereferensikannya.
2. **Instruction patterns** — TIDAK ada. Tidak ada disassembly, tidak ada
   deteksi stub prologue, tidak ada deteksi THR register convention.
3. **ELF structure** — Hanya build-id + machine + exec-section-size +
   file-size. Tidak ada fingerprinting symbol presence (4-6 symbol snapshot
   Dart adalah sinyal versi yang kuat), section layout, atau PT_LOAD
   segment.

Satu-satunya sumber versi yang dipakai adalah **scan string ASCII** untuk
substring `"flutter engine"` / `"dart vm"` / `"dart sdk"` / `"dart:"` /
`"isolate snapshot"` / `"vm snapshot"`, lalu ekstrak semver pertama.
Pendekatan ini rapuh: bergantung pada banner engine ada di rodata, yang
bisa di-strip/obfuscate, dan `"dart:"` cocok dengan *setiap* string import
`dart:core` (noise, bukan marker versi).

**Verifikasi SDK**: Semua klaim diverifikasi via `gh api` ke
`repos/dart-lang/sdk/contents/<path>?ref=<tag>`. Tag yang diverifikasi:
2.12.0, 3.9.2, 3.12.2, 3.13.0.

**Tingkat kematangan kode**: Rendah. Kode berfungsi untuk kasus happy-path
(engine banner ada di rodata, build-id ada) tapi melewatkan mayoritas
informasi versi yang bisa diekstrak dari binary Dart AOT, dan tidak
terintegrasi dengan sistem version-detection yang sudah ada di
`internal/snapshot`.

## Struktur Folder

```
internal/fingerprint/
├── fingerprint.go        (312 baris) — Run(): build-id + marker scan + semver
├── fingerprint_test.go    (44 baris) — unit test extractSemverToken,
                                         firstSemverFromMarkers, asciiStrings
```

Hanya 2 file. Tidak ada file lain. Paket hanya diimpor oleh
`cmd/aotopsy/cmd_debug_fingerprint.go` (subcommand `_debug fingerprint`) —
**tidak terhubung ke pipeline utama** (`internal/analysis/pipeline.go`
memanggil `writeFunctionFingerprints` tapi itu adalah SHA-256 per-function
instruction bytes di package `analysis`, bukan paket ini).

## Gap Analysis

### Gap 1: Snapshot header tidak diparse — identifier versi definitif diabaikan

- **Deskripsi**: `fingerprint.Run` membuka ELF, membaca note section untuk
  GNU build-id, lalu `f.ReadAt(raw, 0)` seluruh file dan scan string ASCII.
  Ia **tidak pernah** resolve symbol snapshot Dart (`_kDartVmSnapshotData`,
  `_kDartVmSnapshotInstructions`, `_kDartIsolateSnapshotData`,
  `_kDartIsolateSnapshotInstructions`, atau `_kDartSnapshotData`/
  `_kDartSnapshotText` untuk 3.13.0+). Padahal header snapshot Dart
  menyimpan:
  - `+0x00` magic `0xdcdcf5f5` (4 byte) — konfirmasi ini snapshot Dart
  - `+0x04` length int64 — ukuran blob
  - `+0x0c` kind int64 — `0`=Full, `1`=FullCore, `2`=FullJIT, `3`=FullAOT
    (pre-3.13); `2`=FullAOT, `3`=Module (3.13+)
  - `+0x14` **snapshot hash** — 32 ASCII hex char, = `Version::SnapshotString()`,
    identifier versi Dart yang **deterministik dan exact**
  - `+0x34` features string null-terminated — build mode, arch, OS,
    compressed-pointers, null-safety, dll.

  `internal/snapshot/snapshot.go` sudah punya `parseHeader` + `DetectVersion`
  yang memetakan hash ini ke versi Dart via map `knownHashes` (47 hash → 23
  versi). `fingerprint` tidak memanggilnya.

- **Bukti SDK**:
  - `runtime/vm/snapshot.h` @3.9.2:
    ```cpp
    static constexpr int32_t kMagicValue = 0xdcdcf5f5;
    static constexpr intptr_t kMagicOffset = 0;
    static constexpr intptr_t kLengthOffset = kMagicOffset + kMagicSize; // 4
    static constexpr intptr_t kKindOffset = kLengthOffset + kLengthSize;  // 12
    static constexpr intptr_t kHeaderSize = kKindOffset + kKindSize;      // 20
    ```
  - `runtime/vm/app_snapshot.cc` @3.9.2 (`Serializer::WriteVersionAndFeatures`,
    line 8538):
    ```cpp
    const char* expected_version = Version::SnapshotString();
    WriteBytes(...expected_version, version_len);   // 32-hex hash
    char* expected_features = Dart::FeaturesString(...);
    WriteBytes(...expected_features, features_len + 1);  // null-terminated
    ```
  - `runtime/vm/version_in.cc` @3.9.2:
    ```cpp
    const char* Version::snapshot_hash_ = "{{SNAPSHOT_HASH}}"; // 32-hex, build-time
    ```
  - `runtime/include/dart_api.h` @3.9.2 (symbol names):
    ```cpp
    #define kVmSnapshotDataCSymbol "_kDartVmSnapshotData"
    #define kIsolateSnapshotDataCSymbol "_kDartIsolateSnapshotData"
    ```
  - `runtime/include/dart_api.h` @3.13.0 (unified rename):
    ```cpp
    #define kSnapshotDataCSymbol "_kDartSnapshotData"
    #define kSnapshotTextCSymbol "_kDartSnapshotText"
    ```

- **Dampak**: Untuk binary di mana engine banner string di-strip/obfuscate
  (umum pada app production yang di-shrink), `DartVersion`/`FlutterVersion`
  jadi `""` dan confidence turun ke medium/low, padahal snapshot hash
  **selalu** ada di offset `0x14` region snapshot. Sebuah fingerprinter
  versi Dart yang melewatkan snapshot hash adalah kontradiksi.

- **Usulan**: `Run` harus resolve symbol snapshot via `elfx.File.Symbol`,
  baca ≥64 byte dari region data, validasi magic, ekstrak
  `Header.SnapshotHash`, lalu panggil `snapshot.DetectVersion(hash)` (atau
  inline map `knownHashes`). Tambahkan field `SnapshotHash string`,
  `SnapshotKind string`, `SnapshotFeatures string`, `DetectedDartVersion
  string` (dari hash, bukan dari semver scan) ke `Report`. Untuk hash
  unknown, fallback ke `snapshot.ProbeTagStyle`. Ini menggabungkan
  fingerprinter dengan sumber kebenaran versi yang sudah ada.

- **Prioritas**: Tinggi — ini adalah gap inti; tanpa ini paket tidak
  layak disebut "version ID dari binary characteristics".

### Gap 2: Features string snapshot tidak diekstrak — fakta RE useful hilang

- **Deskripsi**: Features string di offset `0x34` header snapshot berisi
  token space-separated yang dikodekan di `Dart::FeaturesString`
  (`runtime/vm/dart.cc`). Token-token ini langsung RE-useful:
  - **Build mode** (`product`/`release`/`debug`) — menentukan apakah Code
    objects punya 2 extra refs (`return_address_metadata_`, `comments_`)
    yang desync fill stream. `internal/snapshot` sudah pakai ini via
    `buildModeFromFeatures`, tapi `fingerprint` tidak mengeksposnya.
  - **Arch** (`arm64`/`x64`/`arm`/`ia32`/`riscv32`/`riscv64` di 3.x;
    `arm64-sysv`/`arm-eabi`/`x64-sysv`+`hardfp`/`softfp` di 2.x) —
    konfirmasi ABI, termasuk hardfp/softfp ARM32 yang tidak terlihat dari
    ELF machine type saja.
  - **OS** (`android`/`linux`/`ios`/`macos`/`windows`/`fuchsia` di 3.x).
  - **compressed-pointers** / `no-compressed-pointers` — menentukan layout
    pointer (4 vs 8 byte), krusial untuk decoding object header.
  - **null-safety** / `no-null-safety` (2.12+) — mode null safety.
  - **code-comments** / **dwarf-stack-traces-mode** / **dedup-instructions**
    (3.x) — flag codegen.
  - **tsan** / **msan** / **asan** (3.x) — sanitizer build.

  `fingerprint.Report` tidak punya field untuk salah satu dari ini.

- **Bukti SDK**:
  - `runtime/vm/dart.cc` @3.9.2 (`FeaturesString`, line 1050-1148):
    ```cpp
    #if defined(DEBUG)      -> "debug"
    #elif defined(PRODUCT)  -> "product"
    #else                   -> "release"
    ...
    if (Snapshot::IncludesCode(kind)) {
      VM_GLOBAL_FLAG_LIST(...);  // code-comments, dwarf-stack-traces-mode, dedup-instructions
      ADD_FLAG(tsan, ...); ADD_FLAG(msan, ...); ADD_FLAG(shared_data, ...);
      ...
      buffer.AddString(" arm64"); // atau " x64", " arm", dll.
      buffer.AddString(" android"); // atau " linux", " ios", dll.
      buffer.AddString(" compressed-pointers"); // atau " no-compressed-pointers"
    }
    ```
  - `runtime/vm/dart.cc` @2.12.0 (line 1067):
    ```cpp
    if (isolate_group->null_safety()) buffer.AddString(" null-safety");
    else buffer.AddString(" no-null-safety");
    ```
    dan arch-ABI combos `arm64-sysv` / `arm-eabi` + `hardfp`/`softfp`.
  - `runtime/vm/flag_list.h` @3.9.2 (`VM_GLOBAL_FLAG_LIST`, line 59):
    ```cpp
    P(code_comments, ...)
    P(dwarf_stack_traces_mode, ...)
    R(dedup_instructions, ...)
    ```

- **Dampak**: Analis RE kehilangan fakta build configuration yang langsung
  mempengaruhi decoding (compressed pointers, build mode) dan environment
  target (OS, ABI). Info ini sudah di-parse di `internal/snapshot` tapi
  tidak diekspor via `fingerprint.Report`.

- **Usulan**: Tambahkan `SnapshotFeatures string` + `FeatureList []string`
  ke `Report`. Parse dari offset `0x34` region snapshot (sudah ada
  `snapshot.Header.Features`). Tambahkan field turunan:
  `BuildMode string`, `CompressedPointers bool`, `TargetArch string`,
  `TargetOS string`, `NullSafety bool`. Ini adalah output fingerprinting
  yang langsung actionable.

- **Prioritas**: Tinggi.

### Gap 3: Snapshot `Kind` tidak diperiksa — snapshot non-AOT diam-diam difingerprint sebagai AOT

- **Deskripsi**: `fingerprint.Run` tidak tahu apakah ELF ini benar-benar
  snapshot AOT. Sebuah `libapp.so` JIT (kind=2 `kFullJIT`) atau core
  snapshot (kind=0 `kFull`) akan difingerprint dengan confidence yang sama
  padahal cluster formatnya berbeda. Field `kind` di header snapshot
  membedakan ini secara eksplisit.

- **Bukti SDK**: `runtime/vm/snapshot.h` @3.9.2:
  ```cpp
  enum Kind { kFull, kFullCore, kFullJIT, kFullAOT, kNone, kInvalid };
  ```
  @3.13.0 (renumbered, `kFullCore`/`kNone` removed):
  ```cpp
  enum Kind { kFull, kFullJIT, kFullAOT, kModule, kInvalid };
  ```
  `Snapshot::IncludesCode(kind)` true hanya untuk `kFullJIT`/`kFullAOT`/
  `kModule`.

- **Dampak**: Fingerprinter bisa melaporkan "Dart 3.9.2" pada snapshot
  non-AOT yang tidak akan pernah bisa dianalisis pipeline AOTopsy.
  Mislabel ini menyesatkan analisis.

- **Usulan**: Baca `kind` dari header, ekspos `SnapshotKind string` di
  `Report`, dan jika kind != `kFullAOT` (atau `kFullAOT`/`kModule` di
  3.13+), turunkan confidence dan tambahkan diagnostic.

- **Prioritas**: Sedang.

### Gap 4: Symbol presence snapshot tidak difingerprint — sinyal versi 3.13+ yang kuat diabaikan

- **Deskripsi**: Dart 3.13.0 mengganti 4 symbol snapshot
  (`_kDartVmSnapshotData`, `_kDartVmSnapshotInstructions`,
  `_kDartIsolateSnapshotData`, `_kDartIsolateSnapshotInstructions`)
  dengan 2 symbol unified (`_kDartSnapshotData`, `_kDartSnapshotText`).
  Kehadiran set symbol mana pun adalah **diskriminator versi major yang
  binary-level dan tidak bergantung string**. `fingerprint.Run` tidak
  inspeksi dynamic symbol table sama sekali (hanya note section + raw
  bytes).

  Selain itu, symbol `_kDartSnapshotBuildId` (Dart-internal build id,
  terpisah dari ELF GNU build-id) didefinisikan di
  `internal/snapshot/snapshot.go:21` sebagai `SymSnapshotBuildID` tapi
  **tidak pernah dipakai** — gap yang sudah didokumentasikan di
  `internal/snapshot/RE_GAP_ANALYSIS_REPORT.md` Gap 8. Fingerprint package
  juga bisa mengeksposnya.

- **Bukti SDK**:
  - `runtime/include/dart_api.h` @3.12.2:
    ```cpp
    #define kVmSnapshotDataCSymbol "_kDartVmSnapshotData"
    #define kIsolateSnapshotDataCSymbol "_kDartIsolateSnapshotData"
    ```
  - `runtime/include/dart_api.h` @3.13.0:
    ```cpp
    #define kSnapshotDataCSymbol "_kDartSnapshotData"
    #define kSnapshotTextCSymbol "_kDartSnapshotText"
    ```
  - `runtime/include/dart_api.h` @3.9.2:
    ```cpp
    #define kSnapshotBuildIdCSymbol "_kDartSnapshotBuildId"
    ```

- **Dampak**: Untuk binary stripped sebagian di mana symbol snapshot ada
  tapi engine banner string tidak, fingerprint kehilangan diskriminator
  versi yang andal. Juga, tidak ada way untuk membedakan "ini bukan
  binary Dart AOT sama sekali" dari "ini binary Dart AOT yang stripped".

- **Usulan**: Tambahkan `SnapshotSymbols []string` ke `Report` — daftar
  symbol snapshot Dart yang ditemukan di `.dynsym`. Tambahkan flag
  `UnifiedSnapshot bool` (3.13+) jika hanya `_kDartSnapshotData`/
  `_kDartSnapshotText` yang ada. Resolve juga `_kDartSnapshotBuildId`
  dan ekspos sebagai `DartBuildID string` (terpisah dari ELF GNU
  build-id).

- **Prioritas**: Sedang.

### Gap 5: Marker scanning heuristik lemah — false positive dan false negative

- **Deskripsi**: `extractEngineMarkers` (line 192) menggunakan substring
  match case-insensitive dengan aturan:
  - `isFlutter := strings.Contains(lower, "flutter engine")`
  - `isDart := strings.Contains(lower, "dart vm") || "dart sdk" || "dart:" || "isolate snapshot" || "vm snapshot"`

  Masalah:
  1. `"dart:"` cocok dengan **setiap** string import `dart:core`,
     `dart:async`, dll. — ini bukan marker versi, ini noise. Pada binary
     dengan banyak string import Dart, `dartMarkers` akan dipenuhi entry
     `dart:core`..`dart:ffi` yang tidak punya versi.
  2. `isFlutter` hanya cocok `"flutter engine"` — melewatkan banner
     `"Flutter Engine"` yang ditulis persis begitu (case-insensitive
     match OK), tapi juga melewatkan string seperti `"flutter_version"`
     atau `"engine_revision"` yang adalah marker engine valid.
  3. Tidak ada ekstraksi terstruktur dari banner versi Dart yang
     sebenarnya, yaitu `Version::String()` = `"3.9.2 (stable) (...) on
     linux_arm64"`. Banner ini tidak mengandung substring `"dart vm"`
     atau `"dart sdk"` — jadi **tidak terdeteksi** sama sekali.
  4. Cap `len(s) > 240` dan `minLen 10` arbitrary; banner versi valid
     bisa >240 char.
  5. `firstSemverFromMarkers` mengembalikan semver pertama dari marker
     apa pun — bisa ambil semver dari string noise (mis. nomor build
     Android di string yang kebetulan cocok `"dart:"`).

- **Bukti SDK**: `runtime/vm/version_in.cc` @3.9.2:
  ```cpp
  const char* Version::str_ =
      "{{VERSION_STR}} ({{CHANNEL}}) ({{COMMIT_TIME}})"
      " on \"" kHostOperatingSystemName "_" kTargetArchitectureName "\"";
  ```
  String ini (mis. `"3.9.2 (stable) (...) on linux_arm64"`) adalah banner
  yang dicari `flutterdec`, tapi **tidak mengandung** substring `"dart
  vm"`/`"dart sdk"`/`"dart:"`/`"isolate snapshot"`/`"vm snapshot"`, jadi
  `extractEngineMarkers` tidak pernah menangkapnya. Ini false negative
  utama.

- **Dampak**: Pada binary di mana satu-satunya string versi adalah
  `Version::String()` (bukan banner `"Dart VM version: ..."`),
  `DartVersion` jadi `""`. Sebaliknya, `"dart:"` membanjiri marker list
  dengan noise.

- **Usulan**:
  1. Hapus `"dart:"` dari predicate `isDart` — terlalu broad.
  2. Tambahkan pattern spesifik untuk `Version::String()` format:
     regex `^\d+\.\d+\.\d+(-\w+)? \(\w+\) .* on \w+_\w+` (cocok
     `"3.9.2 (stable) ... on linux_arm64"`).
  3. Tambahkan pattern `"Dart VM version:"` dan `"Flutter Engine"`
     eksplisit.
  4. Pisahkan `dartMarkers` menjadi `dartVersionBanners` (string yang
     benar-benar mengandung versi) vs `dartSnapshotMarkers` (`isolate
     snapshot`/`vm snapshot`).
  5. Tingkatkan cap panjang ke ~512 atau hilangkan (banner versi bisa
     panjang).

- **Prioritas**: Sedang — tapi ini gap yang paling mudah diperbaiki dan
  paling visible.

### Gap 6: Tidak ada instruction-pattern fingerprinting

- **Deskripsi**: Tugas folder menyebut "instruction patterns" tapi
  `fingerprint.go` tidak melakukan disassembly atau pattern matching
  instruksi sama sekali. Padahal Dart VM punya signature instruksi yang
  version-specific:
  - **THR register convention**: ARM64 pakai `X26` sebagai Thread register
    pre-3.4.3; x86_64 pakai `R14`. Ini visible di prologue stub.
  - **Stub prologues**: `AllocateObject` stub, `BuildMethodExtractor` stub,
    `MegamorphicCall` stub punya urutan instruksi yang berubah antar
    versi.
  - **Object header tag bits**: `kHeapObjectTag` shift berubah antar
    versi.
  - **Dispatch table load pattern**: `LDR X30, [X21, Xm, LSL #3]` vs
    varian lain.

  `internal/sdk` dan `internal/disasm` sudah punya pengetahuan ini, tapi
  `fingerprint` tidak menggunakannya untuk fingerprinting.

- **Bukti SDK**: (tidak diverifikasi ulang di sini — ini adalah gap
  fitur, bukan klaim fakta SDK spesifik. Konvensi THR terdokumentasi di
  `runtime/vm/runtime_offsets_extracted.h` per versi, sudah dipakai
  `internal/sdk/registers.go`.)

- **Dampak**: Untuk binary di mana snapshot header tidak bisa diparse
  (corrupt, di-strip sampai symbol hilang, atau format tidak dikenali),
  fingerprinter tidak punya fallback berbasis instruksi. Juga, tidak ada
  cross-check: snapshot hash bisa cocok dengan versi X tapi instruksi
  menunjukkan versi Y (mismatch menandakan binary yang di-patch).

- **Usulan**: Tambahkan fase opsional: decode beberapa KB pertama
  `.text` section, deteksi pola prologue stub yang diketahui, dan
  ekspos `InstructionHints []string` di `Report`. Ini advanced —
  prioritas lebih rendah daripada snapshot header (Gap 1) tapi layak
  untuk robustness.

- **Prioritas**: Rendah (advanced, butuh kerja signifikan; snapshot
  header sudah menutup mayoritas kasus).

### Gap 7: Confidence level tidak mempertimbangkan snapshot hash match

- **Deskripsi**: `confidenceLevel` (line 303) hanya melihat
  `hasBuildID` dan `hasVersionHint` (semver dari marker scan). Sebuah
  binary dengan snapshot hash yang cocok ke `knownHashes` (deteksi versi
  exact, deterministik) tapi tanpa GNU build-id dan tanpa banner string
  akan dapat `ConfidenceLow` — padahal itu adalah identifikasi versi
  paling reliable yang mungkin.

- **Dampak**: Confidence menyesatkan. Analisis bisa menganggap binary
  "low confidence" padahal versinya sudah dipastikan via snapshot hash.

- **Usulan**: Jika snapshot hash match ke `knownHashes`, confidence
  wajib `ConfidenceHigh` terlepas dari build-id/marker. Tambahkan
  parameter `hashMatched bool` ke `confidenceLevel`.

- **Prioritas**: Sedang — bergantung pada Gap 1 diimplementasikan.

### Gap 8: BuildID extraction hanya GNU type 3 — note section lain diabaikan

- **Deskripsi**: `parseBuildIDNotes` (line 144) hanya mengembalikan note
  dengan `name=="GNU" && ntype==3` (`NT_GNU_BUILD_ID`). Note section lain
  diabaikan:
  - `.note.android.ident` — berisi Android NDK version info, RE-useful
    untuk toolchain fingerprinting.
  - `NT_VERSION` (type 1) — version notes umum.
  - Note owner lain (LLVM, Go, dll.).

  Untuk binary Dart AOT dari Android APK, `.note.android.ident` sering
  ada dan memberi info NDK build.

- **Dampak**: Toolchain fingerprinting (NDK version, clang version)
  hilang. Ini bukan versi Dart tapi konteks RE useful.

- **Usulan**: Generalisasi `parseBuildIDNotes` untuk mengembalikan
  `[]NoteRecord` (name, type, desc hex). Ekspos semua note di
  `Report.Notes []NoteRecord`. Tetap prioritaskan GNU build-id tapi
  jangan buang yang lain.

- **Prioritas**: Rendah.

## Register Tracking Gaps

Paket `internal/fingerprint` **tidak melakukan register tracking sama
sekali** — ia tidak menyentuh disassembly. Tidak ada pelacakan register
THR (`X26` ARM64 / `R14` x86_64), register dispatch table (`X21` ARM64),
register object pool, atau register lain yang konvensinya berubah antar
versi Dart.

Register-tracking yang relevan untuk fingerprinting versi (dan yang sudah
ada di `internal/sdk/registers.go` + `internal/disasm`):

| Register | Konvensi | Sinyal versi | Dipakai fingerprint? |
|----------|----------|--------------|----------------------|
| THR (X26/R14) | Thread pointer | Offset field berubah per versi; konvensi calling berubah di 3.4.3 (DartCallingConvention) | **Tidak** |
| PP (X21) | Object pool pointer | Stabil across versi ARM64 | **Tidak** |
| Dispatch table reg | LDR pattern | Pola `LDR X30, [X21, Xm, LSL #3]` vs varian | **Tidak** |
| CODE reg | Code object pointer | Stub prologue berubah | **Tidak** |

**Gap register**: Tidak ada satu pun register di atas ditrack. Untuk
fingerprinter versi yang claim menggunakan "instruction patterns", ini
adalah hole total. Usulan: lihat Gap 6 — tambahkan fase instruction-pattern
yang minimal mendeteksi THR register convention dari prologue stub pertama.

## Fitur RE Missing/Incomplete

Berikut fitur RE useful yang **bisa** diekstrak dari binary Dart AOT tapi
**tidak** diekstrak oleh `internal/fingerprint`:

1. **Snapshot hash → Dart version** (deterministik, exact) — **MISSING**.
   Sumber: offset `0x14` region snapshot. Sudah ada map `knownHashes` di
   `internal/snapshot/version.go` (47 hash → 23 versi).
2. **Build mode** (`product`/`release`/`debug`) — **MISSING**. Menentukan
   apakah Code objects punya extra refs. Sumber: features string token
   pertama.
3. **Compressed pointers flag** — **MISSING**. Menentukan pointer width
   (4 vs 8 byte). Sumber: features string `compressed-pointers`.
4. **Target arch dari snapshot** (`arm64`/`x64`/`arm`/...) — **MISSING**.
   Bisa berbeda dari ELF machine (cross-compile). Sumber: features string.
5. **Target OS dari snapshot** (`android`/`linux`/`ios`/...) — **MISSING**.
   Sumber: features string.
6. **Null safety mode** — **MISSING** (2.12+). Sumber: features string.
7. **Snapshot kind** (AOT vs JIT vs Module) — **MISSING**. Sumber: header
   field `kind`.
8. **Unified snapshot detection** (3.13+) — **MISSING**. Sumber: symbol
   presence (`_kDartSnapshotData` vs 4 symbol lama).
9. **Dart-internal build id** (`_kDartSnapshotBuildId`) — **MISSING**.
   Terpisah dari ELF GNU build-id.
10. **Sanitizer flags** (tsan/msan/asan) — **MISSING**. Sumber: features
    string (3.x).
11. **Code comments flag** / **dwarf stack traces** / **dedup instructions**
    — **MISSING**. Sumber: features string (3.x).
12. **ARM hardfp/softfp** (2.x ARM32) — **MISSING**. Sumber: features
    string `hardfp`/`softfp`.
13. **Instruction-pattern fallback** untuk binary stripped-header —
    **MISSING**. Stub prologue detection.
14. **Cross-check snapshot hash vs instruction hints** — **MISSING**.
    Deteksi binary yang di-patch/mismatched.
15. **Structured `Version::String()` banner extraction** — **INCOMPLETE**.
    Pattern `"3.9.2 (stable) (...) on linux_arm64"` tidak terdeteksi
    (lihat Gap 5).

## Verifikasi SDK

Semua klaim faktual tentang SDK diverifikasi via `gh api` ke
`repos/dart-lang/sdk/contents/<path>?ref=<tag>`. Ringkasan:

| Klaim | File SDK | Tag | Verifikasi |
|-------|----------|-----|------------|
| Snapshot header layout (magic/length/kind, 4+8+8=20 byte) | `runtime/vm/snapshot.h` | 3.9.2 | `kMagicValue=0xdcdcf5f5`, `kMagicOffset=0`, `kLengthOffset=4`, `kKindOffset=12`, `kHeaderSize=20` |
| Snapshot hash = `Version::SnapshotString()` (32-hex) | `runtime/vm/app_snapshot.cc` | 3.9.2 | `Serializer::WriteVersionAndFeatures` line 8538-8551 menulis `Version::SnapshotString()` lalu features+NUL |
| `snapshot_hash_` adalah placeholder build-time 32-hex | `runtime/vm/version_in.cc` | 3.9.2 | `const char* Version::snapshot_hash_ = "{{SNAPSHOT_HASH}}";` |
| Features string: `product`/`release`/`debug` + arch + OS + compressed-pointers | `runtime/vm/dart.cc` | 3.9.2, 3.13.0 | `FeaturesString` line 1050-1148 (3.9.2), `FeaturesString` line ~1-100 (3.13.0) |
| Features string 2.12: `null-safety`/`no-null-safety`, arch-ABI combos | `runtime/vm/dart.cc` | 2.12.0 | line 988-1100, `arm64-sysv`/`arm-eabi`+`hardfp`/`softfp` |
| `VM_GLOBAL_FLAG_LIST` = code-comments, dwarf-stack-traces-mode, dedup-instructions | `runtime/vm/flag_list.h` | 3.9.2 | line 59-62 |
| Symbol snapshot pre-3.13: `_kDartVmSnapshotData` + 3 lain | `runtime/include/dart_api.h` | 3.12.2 | line 4026-4046 |
| Symbol snapshot 3.13+: `_kDartSnapshotData` + `_kDartSnapshotText` | `runtime/include/dart_api.h` | 3.13.0 | line 4024-4036 |
| Symbol `_kDartSnapshotBuildId` ada | `runtime/include/dart_api.h` | 3.9.2 | line 3991-4008 |
| Snapshot Kind enum pre-3.13: kFull=0,kFullCore=1,kFullJIT=2,kFullAOT=3 | `runtime/vm/snapshot.h` | 3.9.2 | `enum Kind` |
| Snapshot Kind enum 3.13: kFull=0,kFullJIT=1,kFullAOT=2,kModule=3 (renumbered) | `runtime/vm/snapshot.h` | 3.13.0 | `enum Kind` (kFullCore/kNone removed) |
| `Version::String()` format = `"X.Y.Z (channel) (...) on OS_arch"` | `runtime/vm/version_in.cc` | 3.9.2 | `str_` template literal |

Tidak ada klaim faktual tentang SDK yang tidak diverifikasi. Klaim tentang
gap fitur (Gap 6, register tracking) didasarkan pada inspeksi kode
AOTopsy (`internal/sdk`, `internal/disasm`) dan tidak memerlukan verifikasi
SDK tambahan karena sifatnya adalah "fitur tidak ada di kode", bukan
"klaim fakta SDK".
