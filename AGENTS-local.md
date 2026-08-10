# AGENTS-local.md — AOTopsy local environment

**Wajib baca file ini sebelum bekerja.** Berisi info lokal yang tidak ada di
AGENTS.md utama.

## Sample binaries location

Sample `libapp.so` dan source `ground_truth.dart` tidak ada di dalam repo
(`compare_sample/` tidak di-clone ke sini). Mereka ada di home user:

```
~/dev/compare_sample/          # Dart 3.9.2 ARM64 (main compare sample)
~/dev/sample_312/              # Dart 3.12 ARM64 + x86_64
~/dev/sample_310/              # Dart 3.10
~/dev/dart212_sample/          # Dart 2.12.0 ARM64
~/dev/gopay_samples/{310,311,312}/{arm64,x64}/  # production samples
```

### Valid libapp.so paths (per AGENTS.md stale-binary warning)

Gunakan `merged_native_libs` (bukan `extracted_*` yang stale):

```
~/dev/compare_sample/build/app/intermediates/merged_native_libs/release/mergeReleaseNativeLibs/out/lib/arm64-v8a/libapp.so
~/dev/sample_312/build/app/intermediates/merged_native_libs/release/mergeReleaseNativeLibs/out/lib/{arm64-v8a,x86_64}/libapp.so
```

**JANGAN pakai** `extracted_arm64` / `extracted_x64` — stale, tidak match
`ground_truth.dart` (lihat AGENTS.md "stale libapp.so" section).

### ground_truth.dart

```
~/dev/compare_sample/lib/ground_truth.dart
~/dev/dart212_sample/lib/ground_truth.dart
```

### Env vars untuk integration tests

```bash
export AOTOPSY_TEST_SAMPLE_ARM64=~/dev/compare_sample/build/app/intermediates/merged_native_libs/release/mergeReleaseNativeLibs/out/lib/arm64-v8a/libapp.so
export AOTOPSY_TEST_SAMPLE_312_ARM64=~/dev/sample_312/build/app/intermediates/merged_native_libs/release/mergeReleaseNativeLibs/out/lib/arm64-v8a/libapp.so
export AOTOPSY_TEST_SAMPLE_312_X64=~/dev/sample_312/build/app/intermediates/merged_native_libs/release/mergeReleaseNativeLibs/out/lib/x86_64/libapp.so
export AOTOPSY_TEST_SAMPLE_DART212=~/dev/dart212_sample/build/app/intermediates/merged_native_libs/release/out/lib/arm64-v8a/libapp.so
```

**Note:** path dart212_sample berbeda (`release/out/lib/` bukan
`release/mergeReleaseNativeLibs/out/lib/`). compare_sample & sample_312 pakai
`mergeReleaseNativeLibs/out/lib/`.

## Memory guard

Saat run aotopsy/test, selalu:
```bash
ulimit -v 2500000   # ~2.5GB, di bawah VM RAM 6GB
```
Foreground, satu hal berat sekaligus (AGENTS.md host memory rules).

### Test tanpa OOM (PENTING)

`TestDart212StringExtraction` dan test yang pakai `pipeline.Run()` = full
pipeline (disasm+typetrack+signal) → **bisa crash WSL OOM**. Sudah terjadi.

**Gunakan cluster-only harness** untuk verifikasi yang tidak butuh disassembly:
- `clusterOnly(t, libPath)` di `internal/pipeline/loadingunit_test.go` —
  ELF → snapshot → alloc → fill, SKIP disassembly. ~0.01-0.05s, aman.
- Hasil `*cluster.Result` punya: Strings, Classes, Named, FuncTypes, Fields,
  Codes, Arrays, Pool, Instances, TypeArguments, PcDescriptors, dll.
- Test yang sudah pakai ini: TypeParam, Switch, PcDesc, InstanceField, Csm,
  Partition, Dart212StringExtractionClusterOnly.

**Jangan run full-pipeline test bersamaan dengan hal berat lain.** Satu hal
sekaligus, foreground. Full `Run()` di dart212_sample PASS sendiri (5.3s) tapi
OOM jika ada proses lain.

### Verifikasi bug hunt (docs/BUG-HUNT-2026-08-09.md)

Test cluster-only untuk verifikasi bug:
```bash
ulimit -v 2500000
export AOTOPSY_TEST_SAMPLE_ARM64=~/dev/compare_sample/build/app/intermediates/merged_native_libs/release/mergeReleaseNativeLibs/out/lib/arm64-v8a/libapp.so
export AOTOPSY_TEST_SAMPLE_312_ARM64=~/dev/sample_312/build/app/intermediates/merged_native_libs/release/mergeReleaseNativeLibs/out/lib/arm64-v8a/libapp.so
export AOTOPSY_TEST_SAMPLE_312_X64=~/dev/sample_312/build/app/intermediates/merged_native_libs/release/mergeReleaseNativeLibs/out/lib/x86_64/libapp.so
export AOTOPSY_TEST_SAMPLE_DART212=~/dev/dart212_sample/build/app/intermediates/merged_native_libs/release/out/lib/arm64-v8a/libapp.so
go test ./internal/pipeline/... -run "ClusterOnly|Partition|TypeParam|Switch|PcDesc|InstanceField|Csm|Dart212" -v
```
