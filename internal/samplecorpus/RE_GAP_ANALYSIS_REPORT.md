# RE Gap Analysis Report: internal/samplecorpus

> **STATUS VERIFIKASI (2026-09-01)** — semua 11 gap CONFIRMED, tidak ada
> koreksi; report ini termasuk yang paling rapi (fakta "token `null-safety`
> hilang di Dart 3.5.0" terverifikasi dan berguna). Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> Catatan lintas-dokumen yang relevan untuk pemilik corpus: perintah
> `go test ./internal/pipeline/ …` di `AGENTS-local.md` (VERIFICATION PLAYBOOK,
> bagian differential dan OOM) **stale** — direktori `internal/pipeline/` tidak
> ada; test-test itu hidup di `internal/analysis/` (`crossversion_test.go`,
> `golden_test.go`, `decompile_quality_test.go`, `symtabdiff_test.go`,
> `loadingunit_test.go`).

## Ringkasan

Folder `internal/samplecorpus` adalah registry tunggal untuk seluruh corpus sample
binary AOTopsy. Hanya 2 file: `corpus.go` (469 baris) dan `coverage_test.go` (128
baris). Paket ini di-konsumsi oleh 9 file test lain di `internal/analysis`,
`internal/cluster`, `internal/elfx`, dan `internal/snapshot` — semua via
`samplecorpus.Registry`, `samplecorpus.Path`, `samplecorpus.Sample`,
`samplecorpus.MissingMessage`, `samplecorpus.VersionMismatch`,
`samplecorpus.SourceSets`, dan `samplecorpus.Extract`.

Filosofi paket ini sudah matang: nama file = kontrak versi, symlink-drift dideteksi
lewat `VersionMismatch`, missing sample = skip bukan fail, source-set differential
adalah satu-satunya gate yang membandingkan sibling (bukan diri-sendiri). Comment
dokumentasi sangat tebal dan akurat — banyak pelajaran historis (2.10.0 fill bug,
2.15.0 hash-vs-version drift, TagStyleCidShift1 family unproven) tercatat.

Namun analisis gap menemukan **11 gap** signifikan: register sample yang tidak
ditrack (BuildMode, CompressedPointers, OS, arch-from-features), validasi
incomplete (tidak ada gate FileName-uniqueness, tidak ada gate duplicate-input-hash
dalam source-set, `summariseFeatures` cek token `null-safety` yang tidak pernah
emit di 3.5+), dead code (`Versions()`, `Get()`, `compare()`, `triple()`), bug
silent di `Get()` (return realapp2 menyembunyikan compare_sample 3.7.0/x64),
missing GT twin untuk 4 versi (2.10.0, 2.12.0, 3.12.2, 3.13.0), dan fitur RE
corpus yang missing (corpus inventory machine-readable, feature-string validation,
cross-arch parity gate, riscv tracking).

Verifikasi SDK dilakukan via `gh api` ke `dart-lang/sdk` di tag 2.10.0, 2.17.6,
3.1.0, 3.9.2 untuk `object_store.h` dan `dart.cc` (`Dart::FeaturesString`).

## Struktur Folder

```
internal/samplecorpus/
├── corpus.go              (469 baris) — Sample struct, Registry, Extract, Path,
│                                          MissingMessage, VersionMismatch,
│                                          SourceSets, Get, Versions, compare/triple
├── coverage_test.go       (128 baris) — TestCorpusCoverage (format-family coverage),
│                                          detectVersion helper
└── RE_GAP_ANALYSIS_REPORT.md          — report ini
```

Konsumen (dari grep `samplecorpus\.`):
- `internal/analysis/coverage_census_test.go` — `Registry`, `Path`
- `internal/analysis/crossversion_test.go` — `SourceSets`, `Path`, `Sample`,
  `MissingMessage`, `VersionMismatch`
- `internal/analysis/decompile_fidelity_test.go` — `Path`
- `internal/analysis/decompile_quality_test.go` — `Path`
- `internal/analysis/property_invariants_test.go` — `Path`
- `internal/analysis/symtabdiff_test.go` — `Registry`, `Path`
- `internal/cluster/corpus_test.go` — `Registry`, `Path`, `Sample`,
  `MissingMessage`, `VersionMismatch`
- `internal/elfx/elfx_test.go` — (referensi)
- `internal/snapshot/corpus_test.go` — `Registry`, `Path`, `Sample`,
  `MissingMessage`, `VersionMismatch`

## Gap Analysis

### Gap 1: Register sample tidak track BuildMode (PRODUCT vs release/debug)

- **Deskripsi**: `Sample` struct hanya punya `DartVersion`, `Arch`, `Note`,
  `SourceSet`, `ProfileIncomplete`, `FileSuffix`, `GroundTruth`. Tidak ada field
  untuk build mode. Padahal `VersionProfile.BuildMode` (snapshot/version.go:137)
  sudah mendeteksi `BuildProduct`/`BuildRelease`/`BuildDebug` dari features string,
  dan `snapshot.Extract` (snapshot.go:312) **meng-emit warning loud** kalau non-
  PRODUCT karena "Code objects carry TWO EXTRA refs" yang desync fill stream.
  Registry tidak bisa menyatakan "sample ini harus PRODUCT" — sebuah sample yang
  tak sengaja profile-build akan pass `VersionMismatch` (hash cocok) lalu gagal
  diam-diam di cluster layer.
- **Bukti SDK**: `runtime/vm/dart.cc` @3.9.2 line 1057-1061 —
  `#if defined(DEBUG) buffer.AddString("debug"); #elif defined(PRODUCT)
  buffer.AddString("product"); #else buffer.AddString("release");`. Comment
  `VersionProfile.BuildMode` (version.go:116-137) eksplisit: non-PRODUCT Code
  fill punya 2 extra refs (`return_address_metadata_`, `comments_`) yang
  `CodeNumRefs` tidak akomodir → desync.
- **Dampak**: Sample profile-build (Flutter profile mode) bisa masuk corpus tanpa
  gate yang menolak. `TestCorpusCoverage` hanya cek version, bukan mode. Bug
  silent di cluster fill.
- **Usulan**: Tambah field `BuildMode` (atau `ExpectProduct bool`) di `Sample`;
  `coverage_test.go` assert `info.Version.BuildMode == BuildProduct` untuk
  sample non-GT. Default true (semua release APK PRODUCT).
- **Prioritas**: Tinggi — bug silent, anti-pattern "validasi incomplete"

### Gap 2: Register sample tidak track CompressedPointers

- **Deskripsi**: `Sample` tidak menyatakan apakah sample harus compressed-pointer.
  `VersionProfile.CompressedPointers` di-set dari features string (snapshot.go:286),
  bukan dari profile table. Profile 2.10-2.15 = uncompressed, 2.16+ = compressed
  (kecuali 2.14 yang uncompressed). Tidak ada gate yang memverifikasi sample
  benar-benar punya compressed-pointers sesuai harapan era versinya. Sample 2.16
  yang tak sengaja di-build dengan `--no-compressed-pointers` akan pass
  `VersionMismatch` tapi punya layout field berbeda → bug diam.
- **Bukti SDK**: `dart.cc` @3.9.2 line 1167-1169 —
  `#if defined(DART_COMPRESSED_POINTERS) buffer.AddString(" compressed-pointers");
  #else buffer.AddString(" no-compressed-pointers");`. Profile 2.16.0 di
  version.go:981 tidak set `CompressedPointers` (diambil dari features runtime).
- **Dampak**: Validasi incomplete. Sample mis-built bisa pass version check tapi
  punya object layout berbeda (compressed pointer ubah field offset semua).
- **Usulan**: Tambah `ExpectCompressedPointers *bool` di `Sample` (nil = don't
  care); gate di `coverage_test` bandingkan vs `info.Version.CompressedPointers`.
- **Prioritas**: Sedang

### Gap 3: Register sample tidak track OS / target-arch dari features string

- **Deskripsi**: Features string Dart mengandung token arch (`arm64`/`x64`/
  `riscv32`/`riscv64`/`arm`/`ia32`) dan OS (`android`/`linux`/`ios`/`macos`/
  `windows`/`fuchsia`). `Sample.Arch` hanya "arm64"/"x64" dari filename, tidak
  diverifikasi vs features string. Sample arm64 yang sebenarnya x64 build
  (mis-label) tidak tertangkap selama snapshot hash cocok. OS tidak ditrack
  sama sekali — padahal snapshot AOT meng-embed Platform.isAndroid dll sebagai
  compile-time constant, jadi sample android vs linux punya code shape berbeda.
- **Bukti SDK**: `dart.cc` @3.9.2 line 1124-1152 — `#if defined(TARGET_ARCH_ARM64)
  buffer.AddString(" arm64"); ... #elif defined(DART_TARGET_OS_ANDROID)
  buffer.AddString(" android");`. `summariseFeatures` (corpus_test.go:158) hanya
  cek `null-safety,compressed-pointers,product,release,debug` — TIDAK cek
  arch/OS token.
- **Dampak**: Mis-label arch silent. OS coverage tidak diukur (semua sample
  android? tidak ada sample iOS/windows?).
- **Usulan**: Tambah `OS string` di `Sample` (default "android"); gate cek
  `info.IsolateHeader.HasFeature(s.Arch)` dan `HasFeature(s.OS)`. Report OS
  coverage di `TestCorpusCoverage`.
- **Prioritas**: Sedang — arch mis-label adalah kelas bug sama dengan version
  mis-label yang paket ini dirancang untuk bunuh.

### Gap 4: `summariseFeatures` cek token `null-safety` yang tidak di-emit di 3.5+

- **Deskripsi**: `summariseFeatures` (snapshot/corpus_test.go:156-166) cek 5
  token: `null-safety`, `compressed-pointers`, `product`, `release`, `debug`.
  Tapi `Dart::FeaturesString` **menghapus `null-safety` di Dart 3.5.0** —
  verifikasi `gh api dart.cc @3.5.0` grep `null-safety` = 0 hit, sedangkan
  @2.17.6, @3.4.3 = 4 hit. Jadi untuk 9 dari 23 versi supported (3.5.0-3.13.0),
  `null-safety` selalu absent → `summariseFeatures` selalu report "(none of
  tracked)" atau hanya `compressed-pointers,product`. Ini bukan bug fatal (hanya
  t.Log) tapi menyesatkan: pembaca report mengira null-safety feature hilang
  padahal SDK memang tidak menulisnya lagi.
- **Bukti SDK**: `gh api ... dart.cc?ref=3.5.0` → 0 hit `null-safety`;
  `ref=3.4.3` → 4 hit. Token dihapus ketika null safety menjadi unconditional.
- **Dampak**: Report coverage menyesatkan untuk 9 versi terbaru. Tidak ada
  gate yang gagal, tapi signal noise.
- **Usulan**: Hapus `null-safety` dari list `summariseFeatures` ATAU ganti
  dengan token yang konsisten ada di semua versi: `compressed-pointers`,
  `product`/`release`/`debug`, plus arch+OS token (lihat Gap 3).
- **Prioritas**: Rendah — cosmetic, tapi melanggar prinsip "report rather than
  mislead"

### Gap 5: `Get()` punya bug silent — return realapp2 menyembunyikan compare_sample

- **Deskripsi**: `Get(dartVersion, arch string)` (corpus.go:375) return sample
  PERTAMA yang cocok di Registry. Registry di-iterate dalam deklarasi order.
  Untuk `Get("3.7.0", "x64")` return entry line 234 (`realapp2`, `FileSuffix:
  "-realapp2"`, `SourceSet: ""`) — BUKAN line 243 (`sample_dart_3.7.0 x86_64`,
  `SourceSet: comparesample`). Untuk `Get("2.12.0", "arm64")` return line 195
  (toy app, no SourceSet) bukan line 204 (prenn source-set member). `Get()`
  tidak memfilter `GroundTruth` juga — `Get("2.13.0","arm64")` return line 206
  (prenn) padahal line 315 (gt) juga match.
- **Bukti SDK**: N/A — bug logika internal.
- **Dampak**: `Get()` saat ini dead code (tidak ada caller), jadi bug tidak
  aktif. Tapi kalau ada yang pakai `Get()` untuk ambil "sample representatif
  versi X", mereka dapat realapp bukan compare_sample — anti-pattern.
- **Usulan**: Hapus `Get()` (dead code, lihat Gap 6) ATAU ubah signature jadi
  `Get(version, arch, sourceSet string)` dan filter `!GroundTruth`.
- **Prioritas**: Sedang — dead code sekarang, tapi landmine kalau diaktifkan

### Gap 6: Dead code — `Versions()`, `Get()`, `compare()`, `triple()`

- **Deskripsi**: `grep -rn "samplecorpus.Versions\|samplecorpus.Get\b"` = 0 hit
  di seluruh repo. `Versions()` (corpus.go:427) memakai `compare()` (440) dan
  `triple()` (453) yang juga private. Total ~43 baris dead code. `Versions()`
  juga redundant dengan `snapshot.SupportedVersions()` yang lebih kaya (filter
  `p.Supported`).
- **Bukti SDK**: N/A.
- **Dampak**: Maintenance burden, misleading ("ada API ini pasti dipakai").
- **Usulan**: Hapus `Versions`, `Get`, `compare`, `triple`. Kalau `Get` dibutuh
  kan nanti, re-add dengan signature yang benar (Gap 5).
- **Prioritas**: Rendah — cleanup

### Gap 7: Tidak ada gate FileName-uniqueness di Registry

- **Deskripsi**: `Sample.FileName()` = `dart-<ver><suffix>-<arch>.so`. Tidak
  ada test yang memverifikasi semua `FileName()` di Registry unik. Verifikasi
  manual saya (extract.go) menemukan 0 duplikat saat ini, tapi tidak ada gate
  yang mencegah duplikat di masa depan. Kalau 2 entry punya FileName sama,
  `Path(fileName)` return path yang sama untuk keduanya → `coverage_test`
  hitung sample dobel, `crossversion` mungkin dobel-measure.
- **Bukti SDK**: N/A.
- **Dampak**: Tidak aktif sekarang, tapi tidak ada sentinel. Anti-pattern sama
  dengan symlink-drift yang paket ini dirancang untuk bunuh.
- **Usulan**: Tambah test `TestRegistryFileNamesUnique` di coverage_test.go:
  iterate Registry, assert `seen[FileName()]++ == 1`.
- **Prioritas**: Sedang — sentinel murah, mencegah kelas bug yang sudah terjadi
  historis (drift)

### Gap 8: Tidak ada gate duplicate-input-hash dalam source-set

- **Deskripsi**: Comment corpus.go:293 menyebut "corpus records are keyed by
  input sha256". `cluster/corpus_test.go` punya `InputSHA256` field dan skip
  kalau hash beda (bukan fail). TAPI tidak ada gate yang memverifikasi: dalam
  satu `SourceSet`, tidak boleh ada 2 sample dengan input hash identik — itu
  berarti kedua "sibling" sebenarnya binary yang sama, menghapus kontrol
  differential. Ini persis regression yang comment paket ini warning-kan
  (blutter-lce.so symlink ke 3.9.2). `crossversion_test.go` tidak cek hash
  sama sekali.
- **Bukti SDK**: N/A — kontrol internal.
- **Dampak**: Differential bisa silent-invalid. `TestCrossVersionDifferential`
  bandingkan sibling yang ternyata byte-identik → semua metric "cocok" tapi
  tidak ada kontrol.
- **Usulan**: Di `crossversion_test.go` `measureCrossVersion`, simpan sha256;
  setelah loop, assert tidak ada duplikat hash dalam source-set. Atau di
  `samplecorpus.SourceSets()` tambah validasi.
- **Prioritas**: Tinggi — ini kelas bug historis yang paket ini ada untuk
  cegah, tapi gate-nya missing

### Gap 9: Missing ground-truth twin untuk 2.10.0, 2.12.0, 3.12.2, 3.13.0

- **Deskripsi**: Comment corpus.go:308-314 dokumentasikan floor GT = Flutter
  2.2.0 (Dart 2.13.0) karena `--extra-gen-snapshot-options=--no-strip` tidak
  plumbed sebelum itu. Jadi 2.10.0 dan 2.12.0 tidak punya twin (justified).
  TAPI 3.12.2 dan 3.13.0 juga tidak punya twin di Registry padahal versi modern
  — verifikasi arch.go saya: `3.12.2 GT{arm64=0 x64=0}`, `3.13.0 GT{arm64=0
  x64=0}`. `TestSymtabDifferential` (symtabdiff_test.go:36) adalah SATU-SATUNYA
  gate yang compare against ground truth (bukan diri-sendiri). Tanpa GT twin,
  3.12.2 dan 3.13.0 tidak punya ground-truth validation sama sekali — padahal
  3.13.0 adalah format baru (unified snapshot, RootsPrefixRefCount 1518) yang
  paling butuh validasi.
- **Bukti SDK**: N/A — gap corpus, bukan SDK.
- **Dampak**: 2 versi terbaru (3.12.2, 3.13.0) tidak punya ground-truth gate.
  Comment symtabdiff_test.go:33-35 bilang "Flutter releases from 3.44 on keep
  symbols in merged_native_libs" — jadi twin 3.12.2/3.13.0 SEHARUSNYA bisa
  dibuild.
- **Usulan**: Build twin `--no-strip` untuk 3.12.2 dan 3.13.0 (arm64+x64),
  tambah 4 entry `GroundTruth: true` ke Registry.
- **Prioritas**: Tinggi — 3.13.0 adalah format terbaru paling berisiko

### Gap 10: Tidak ada corpus inventory machine-readable (COVERAGE.md source)

- **Deskripsi**: `TestCorpusCoverage` (coverage_test.go) report via `t.Log` —
  human-readable text, bukan JSON/CSV. `TestCoverageCensus` (analysis/
  coverage_census_test.go) emit `COVROW` tab-separated lines tapi gated
  `AOTOPSY_COVERAGE=1` dan hanya OK/FAIL + function count. Tidak ada single
  command yang emit: per-sample `{version, arch, sourceSet, groundTruth,
  buildMode, compressedPointers, OS, inputSHA256, present, tagStyle,
  objectStoreFieldCount, headerFields}`. Inventaris seperti ini yang dibutuh
  kan untuk COVERAGE.md scoreboard dan untuk audit eksternal.
- **Bukti SDK**: N/A.
- **Dampak**: Coverage audit manual, tidak reproducible. Sulit jawab "versi
  mana yang belum punya sample real-binary-verified ObjectStoreAOTFieldCount?"
  secara programatik.
- **Usulan**: Tambah `samplecorpus.Inventory()` yang return `[]SampleRecord`
  dengan semua field; test emit JSON ke stdout saat `AOTOPSY_INVENTORY=1`.
- **Prioritas**: Sedang — infrastruktur RE

### Gap 11: RISCV32/RISCV64 arch tidak ditrack sama sekali

- **Deskripsi**: `Sample.Arch` hanya "arm64"/"x64". Features string Dart
  emit `riscv32`/`riscv64` (dart.cc:1124-1132). `fingerprint/fingerprint.go:109`
  detect `elf.EM_RISCV` tapi `internal/disasm` tidak punya decoder RISCV (grep
  0 hit). Registry tidak punya entry RISCV sama sekali. Dart AOT untuk RISCV
  ada (Flutter embedded, RPi) — celah RE untuk target itu.
- **Bukti SDK**: `dart.cc` @3.9.2 line 1130-1132 — `#elif defined(TARGET_ARCH_RISCV32)
  buffer.AddString(" riscv32"); #elif defined(TARGET_ARCH_RISCV64)
  buffer.AddString(" riscv64");`.
- **Dampak**: AOTopsy tidak bisa analisa libapp.so RISCV. Corpus tidak
  represent target itu.
- **Usulan**: Long-term: tambah RISCV disassembler. Short-term (corpus):
  dokumentasikan gap di Registry comment, jangan pura-pura support.
- **Prioritas**: Rendah (corpus) / Tinggi (disasm) — di luar scope paket ini
  tapi registry harus acknowledge

## Register Tracking Gaps

Field `Sample` saat ini:
- `DartVersion string` ✅ (tracked, validated via VersionMismatch)
- `Arch string` ✅ (tracked, dari filename; TIDAK divalidasi vs features string — Gap 3)
- `Note string` ✅ (provenance)
- `SourceSet string` ✅ (differential control)
- `ProfileIncomplete string` ✅ (documented debt)
- `FileSuffix string` ✅ (disambiguation)
- `GroundTruth bool` ✅ (unstripped twin)

Field yang SEHARUSNYA ditrack tapi tidak:
- `BuildMode` / `ExpectProduct` — Gap 1 (bug silent kalau non-PRODUCT)
- `ExpectCompressedPointers *bool` — Gap 2 (layout berbeda)
- `OS string` — Gap 3 (Platform.isAndroid compile-time constant)
- `InputSHA256 string` — Gap 8 (sentinel duplicate dalam source-set; saat ini
  hanya di corpusRecord cluster, tidak di Registry)
- `ExpectTagStyle` — bisa diturunkan dari version, tapi tidak diverifikasi vs
  binary (coverage_test cek via ProfileForVersion, tidak cek binary tag style
  match profile)

## Fitur RE Missing/Incomplete

1. **Corpus inventory JSON export** (Gap 10) — tidak ada single source of truth
   machine-readable untuk "apa yang ada di corpus".
2. **Cross-arch parity gate** — `TestCrossVersionDifferential` judge per-arch
   (crossversion_test.go:398) tapi tidak ada gate eksplisit "setiap versi
   supported harus punya sample arm64 AND x64". Verifikasi manual saya: semua
   23 versi punya paritas, tapi tidak ada sentinel.
3. **OS coverage report** — tidak ada laporan "sample android vs linux vs ios".
4. **Build-mode coverage report** — tidak ada laporan "sample PRODUCT vs
   release vs debug".
5. **Ground-truth coverage report** — tidak ada laporan "versi mana yang punya
   GT twin vs tidak". Gap 9 menemukan 4 versi tanpa twin secara manual.
6. **Source-set integrity gate** (Gap 8) — tidak ada cek duplicate-hash.
7. **Feature-string validation gate** (Gap 1, 2, 3) — tidak ada cek sample
   features match expectation.
8. **Registry self-validation** (Gap 7) — tidak ada cek FileName unik.

## Verifikasi SDK

Semua klaim SDK diverifikasi via `gh api -H "Accept: application/vnd.github.raw"
"repos/dart-lang/sdk/contents/<path>?ref=<tag>"`:

| Klaim | Path | Tag | Hasil |
|-------|------|-----|-------|
| `Dart::FeaturesString` emit `debug`/`product`/`release` first | `runtime/vm/dart.cc` | 3.9.2 | line 1057-1061 ✅ |
| Features string emit arch token (arm64/x64/riscv32/riscv64) | `runtime/vm/dart.cc` | 3.9.2 | line 1124-1132 ✅ |
| Features string emit OS token (android/linux/ios/macos/windows/fuchsia) | `runtime/vm/dart.cc` | 3.9.2 | line 1134-1152 ✅ |
| Features string emit `compressed-pointers`/`no-compressed-pointers` | `runtime/vm/dart.cc` | 3.9.2 | line 1167-1169 ✅ |
| `null-safety` token ADA di 2.17.6 | `runtime/vm/dart.cc` | 2.17.6 | line 1176-1184, 4 hit ✅ |
| `null-safety` token ADA di 3.4.3 | `runtime/vm/dart.cc` | 3.4.3 | 4 hit ✅ |
| `null-safety` token HILANG di 3.5.0 | `runtime/vm/dart.cc` | 3.5.0 | 0 hit ✅ |
| `null-safety` token HILANG di 3.9.2 | `runtime/vm/dart.cc` | 3.9.2 | 0 hit ✅ |
| `ObjectStore::from()` @3.1.0 = `&list_class_` | `runtime/vm/object_store.h` | 3.1.0 | line 586 ✅ |
| `ObjectStore::to_snapshot(kFullAOT)` @3.1.0 = `&slow_tts_stub_` | `runtime/vm/object_store.h` | 3.1.0 | line 614 ✅ |
| ObjectStoreAOTFieldCount @3.1.0 = 233 (list_class..slow_tts_stub) | `runtime/vm/object_store.h` | 3.1.0 | awk count = 233 ✅ (cocok dengan version.go:986) |
| `ObjectStore::from()` @2.10.0 = `&object_class_` | `runtime/vm/object_store.h` | 2.10.0 | line 441 ✅ |
| Non-PRODUCT Code fill 2 extra refs (`return_address_metadata_`, `comments_`) | comment version.go:127-131 | — | ✅ (sudah SDK-verified di codebase) |

Catatan: grep MCP `searchGitHub` dipakai untuk lokasi `features_string` di
`runtime/vm/service.cc:5695` (konfirmasi `Dart::FeaturesString` API surface).
Verifikasi utama via `gh api` ke tag spesifik sesuai instruksi.

---

Report ini dibuat hanya dengan membaca kode + verifikasi SDK. Tidak ada
build/test/run AOTopsy dijalankan, sesuai instruksi.
