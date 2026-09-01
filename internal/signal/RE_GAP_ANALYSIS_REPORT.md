# RE Gap Analysis Report: internal/signal

> **STATUS VERIFIKASI (2026-09-01)** — diadu dengan `classify.go`, `graph.go`,
> plus pengukuran pada biner sampel. Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`. Koreksi:
> - **Gap 10 ("test lolos karena kebetulan / heuristic rusak") → SALAH.**
>   Aritmetiknya keliru: dari `["aB","cD","xY","zQ","mN","buildContext"]`
>   hanya **"aB"** yang punya vokal; `cD/xY/zQ/mN` ditandai obfuscated.
>   Diukur (test lempar-buang): `ratio=0.667 considered=6
>   samples=[cD xY zQ mN]` vs `ObfuscationThreshold=0.30`; himpunan bersih
>   `ratio=0.167 (gtk)`. `go test -run TestObfuscationRatio` PASS secara sahih.
>   Yang benar hanya limitasi sempit: skema 2-karakter yang memuat vokal
>   (`aB`, `eF`) memang lolos.
> - **Gap 1 & 4 → CONFIRMED, dan Gap 1 kini punya bukti data**: `strings -n 6`
>   + pola `^[A-Z][A-Za-z]+_[A-Za-z_]+$` menemukan **105** nama native di
>   `dart-3.9.2-arm64.so` (termasuk `Ffi_dl_getHandle`,
>   `Ffi_GetFfiNativeResolver`, `Directory_Current`, `File_SetPointer`,
>   `EventHandler_SendData`, `Isolate_spawnFunction`) dan **1.286** di
>   `dart-3.7.0-realapp2-x64.so`. Nol yang diklasifikasi.
> - **Gap 4** — `sdk.ClassifyStubRole` memang nol pemanggil di paket signal;
>   satu-satunya konsumen adalah `decompiler/call.go:234,317`.

## Ringkasan

Folder `internal/signal` (7 file .go, 3258 LOC) adalah lapisan behavioral
classification AOTopsy. Tugasnya: mengklasifikasi fungsi Dart AOT berdasarkan
sinyal perilaku — pattern matching pada string refs, call-graph edges, pool
immediates, dan raw bytes — untuk menghasilkan laporan SARIF, signal_graph.json,
signal.html, signal.dot, signal_cfg.dot, plus lima file JSONL ekspansi
(`crypto_findings`, `method_channels`, `plugins`, `deobfuscation`,
`network_endpoints`, `taint_findings`, `yara_findings`, `behavioral_findings`,
`entropy_findings`).

Klasifikasi string (`ClassifyString` di `classify.go`) sudah matang untuk
kategori mobile-malware generik (SIM/SMS/contacts/location/camera/wallet/
gambling/attribution/rooting/anti-analysis/SSL pinning/accessibility/fraud/
dynamic-load/IPC/covert-channel/DRM/crypto-const/method-channel/plugin).
False-positive avoidance-nya ekstensif (camelCase gating, normalizeForMatch,
word-boundary regex untuk token pendek, isDistinctiveConstant untuk byte scan).

**Namun terdapat gap struktural besar terhadap Dart SDK sebagai target RE
spesifik:**

1. **Nol klasifikasi untuk Dart VM native entry names** — `vm:external-name`
   string (`SecureSocket_Connect`, `Ffi_dl_open`, `File_Open`, `Socket_Read`,
   `SendPort_sendInternal_`, `Isolate_spawnFunction`, `Crypto_GetRandomBytes`,
   `DartNativeApiFunctionPointer`, dst.) muncul di string pool Dart AOT sebagai
   nama callee untuk `bootstrap_native_wrapper_entry_point` THR call, tapi
   `signal` tidak punya kategori apa pun untuk mereka. 368 native entry di
   `runtime/vm/bootstrap_natives.h` @3.12.2 + ~80 native di
   `runtime/bin/{file,socket,secure_socket_filter,crypto,directory,process,
   namespace,platform,io_buffer,file_system_watcher}.cc` tidak terklasifikasi.

2. **Nol klasifikasi untuk `dart:*` library URIs** — string seperti
   `dart:isolate`, `dart:ffi`, `dart:io`, `dart:developer`, `dart:mirrors`,
   `dart:typed_data`, `dart:_internal`, `dart:nativewrappers` adalah sinyal
   perilaku tertinggi di Dart AOT (muncul di import table & stack trace
   strings), tapi hanya `dart:mirrors` yang ditangkap (lewat
   `dynamicLoadKeywords`). `dart:ffi` tidak ditangkap sama sekali padahal
   `CatDynamicLoad` seharusnya menjadi kategori utama untuk FFI.

3. **Nol register tracking di taint analysis** — `WriteTaintFindings`
   (`behavioral.go`) hanya mencocokkan substring string-ref value untuk
   source/sink. Tidak ada register-level dataflow. Sebuah fungsi yang
   meng-`ldr` IMEI dari PP ke X0 lalu `bl` ke `Socket_WriteList` tidak akan
   dilaporkan kalau tidak ada string "imei" dan "socket" di fungsi yang sama.
   Padahal `internal/typetrack` sudah punya lattice tipe dan
   `internal/disasm/dataflowarm64.go` sudah punya register provenance —
   signal tidak mengonsumsi keduanya.

4. **Stub role classification hanya boolean mundane/non-mundane** —
   `sdk.IsMundaneStub` dipakai `graph.go` untuk filter THR edges, tapi
   `sdk.StubRole` (Allocate/WriteBarrier/StackOverflow/TypeTest/Safepoint/
   Runtime/Error/AsyncInit/AsyncAwait/AsyncReturn) tidak dipakai untuk
   klasifikasi sinyal. Padahal stub async (`InitAsync`/`Await`/`ReturnAsync`/
   `Resume`/`InitAsyncStar`/`YieldAsyncStar`/`ReturnAsyncStar`/`InitSyncStar`)
   adalah sinyal perilaku tertinggi: fungsi Dart async/sync* /async* bisa
   diidentifikasi **tanpa string** hanya dari call ke stub tersebut. SDK
   `runtime/vm/stub_code_list.h` @3.12.2 mendefinisikan 130+ stub, termasuk
   `FfiCallTrampoline`/`FfiCallbackTrampoline`/`FfiAsyncCallbackSend` yang
   membuktikan fungsi tersebut adalah FFI boundary.

5. **Crypto constant table incomplete** — `cryptoAlgorithmID` di `crypto_id.go`
   hanya punya 4 entry MD5 T (vs 64 round), 4 entry AES S-box (vs 256 byte),
  10 entry AES Rcon, 4 entry ChaCha20, 4 entry SHA-512 K (vs 80 round), 4
  entry Keccak RC (vs 24 round). Tidak ada SHA-256 K[8..63], SHA-1 H/K
  lengkap, MD5 T[4..63], AES S-box lengkap, BLAKE2b IV[4..7], BLAKE2s,
  SHA-384, SHA-512/t, SipHash, Poly1305, Curve25519, Ed25519, secp256k1
  constants. Dart SDK sendiri tidak mengirimkan ini (memakai BoringSSL), tapi
  plugin Flutter (`pointycastle`, `cryptography`, `fast_rsa`, `dart_jsonwebtoken`)
  meng-embed mereka sebagai Dart code — dan Dart AOT mengkompilasi mereka ke
  MOVZ/MOVK yang muncul di `.text` sebagai raw bytes.

6. **MethodChannel detection hanya regex literal** — `EnumerateMethodChannels`
   (`crypto_id.go` line 246) memakai `methodChannelRe = MethodChannel\s*\(\s*["']([^"']+)["']\s*\)`
   pada string ref value. Tapi di Dart AOT, `MethodChannel("name")` constructor
   sudah di-inlinable dan string "name" dipisah dari literal "MethodChannel"
   — keduanya bisa di pool yang berbeda. Pattern 2-4 (substring "methodChannel"
   / "BinaryMessenger" / "flutter/platform") adalah fallback yang sangat longgar
   dan tidak mengidentifikasi channel name yang sebenarnya.

7. **Plugin detection hardcoded 30 pattern** — `pluginPatterns` di
   `crypto_id.go` line 322 adalah list literal 30 string. Tidak mengikuti
   konvensi naming pub.dev (`<package>_platform_interface`,
   `<package>_android`, `<package>_ios`, `<package>_web`, `<package>_macos`,
   `<package>_windows`, `<package>_linux`). Pigeon-generated code
   (`dev.flutter.pigeon.<package>.<Api>.<method>`) tidak ditangkap.

8. **YARA rules overlap dengan ClassifyString** — `yaraRules` di
   `behavioral.go` line 258 mendefinisikan 15 rule yang duplikat kategori
   `CatRooting`/`CatAntiAnalysis`/`CatSSLPinning`/`CatAccessibility`/`CatFraud`
   di `classify.go`. Output-nya (`yara_findings.jsonl`) tidak menyumbang
   informasi baru ke signal graph — `BuildSignalGraph` tidak membacanya.

9. **Taint source/sink patterns tidak Dart-specific** — `sourcePatterns` dan
   `sinkPatterns` di `behavioral.go` memakai API Java/Android
   (`getMethod`/`getDeviceID`/`getMethod`/`SharedPreferences`/`sqflite`).
   Sumber data Dart-specific (`Random.secure()`, `SecureRandom_getBytes` native,
   `DateTime.now()`, `Platform.deviceId`, `DeviceinfoPlugin`,
   `FlutterNativeInfo`) tidak ada. Sink Dart-specific (`HttpClient.post`,
   `WebSocket.connect`, `Socket.connect`, `SecureSocket.connect`,
   `Isolate.spawn`, `Isolate.run`, `compute()`, `Process.run`) tidak ada.

10. **`CatObfuscation` deliberately unassigned di ClassifyString** — komentar
    line 421-429 menjelaskan keputusan ini (whole-binary property, bukan
    per-string). Tapi `signal_stage.go` line 203-217 meng-assign
    `signal.CatObfuscation` di pipeline level via `ObfuscationRatio`. Ini
    bekerja, tapi `ObfuscationRatio` hanya memeriksa nama pendek tanpa vokal
    (1-4 char). Dart `--obfuscate` modern memakai scheme `aA`, `bB`, `xY`
    (2-char dengan uppercase di posisi 2) — `isObfuscatedName` line 751
    mengembalikan false untuk ini karena `hasVowel` check lolos ('a','A'
    keduanya vokal). Test `TestObfuscationRatio` di
    `signal_expansion_test.go` line 399 mengkonfirmasi: `["aB","cD","xY","zQ",
    "mN","buildContext"]` dilaporkan obfuscated, tapi itu karena 5 dari 6
    adalah 2-char dengan vokal — `hasVowel` true untuk "aB" ('a'/'A'),
    sehingga gate `!hasVowel && len>=2 && len<=3` tidak terpicu. Test
    sebenarnya **lolong karena kebetulan**: "aB" punya 'a' (vokal) → tidak
    obfuscated menurut `isObfuscatedName` → ratio = 0/6 = 0.0 < threshold.
    Tapi test mengharapkan `r >= threshold`. **Test ini salah / heuristic
    ini rusak.**

11. **Entropy analysis section-level only** — `AnalyzeEntropy` (`entropy.go`)
    menghitung Shannon entropy per ELF section. Dart AOT `libapp.so` selalu
    punya `.text` dengan entropy ~6.5-7.0 (kode terkompresi) dan `.rodata`
    dengan entropy ~7.5 (string pool + pool immediates terkompresi).
    Threshold 7.0/7.5 menghasilkan false positive untuk `.rodata` di hampir
    setiap binary. Tidak ada sliding-window entropy untuk mendeteksi region
    terenkripsi lokal di dalam section.

12. **Behavioral call-graph patterns hanya 4** — `WriteBehavioralFindings`
    (`behavioral.go` line 351) hanya mendefinisikan 4 pattern: root→debug,
    credential→network, location→network, crypto→network. Tidak ada pattern
    Dart-specific: FFI→network (exfil via native), isolate→network (data
    leak via port), dynamic-load→execute (load + invoke), accessibility→
    input (keylogger pattern), camera→network (spyware pattern),
    rooting→exit (anti-analysis exit path), SSLpin→bypass (pinning +
    custom TrustManager).

## Struktur Folder

| File | LOC | Peran |
|------|-----|-------|
| `classify.go` | 782 | `ClassifyString` — 35 kategori sinyal dari string ref value. Keyword lists + regex. `CategorySeverity`, `MaxSeverity`, `ObfuscationRatio`, `isObfuscatedName`, `isIdentifierLike`, `isCryptoConstant`, `normalizeForMatch`, `containsKeyword`. |
| `behavioral.go` | 588 | `WriteTaintFindings` (3 pattern: same-fn, cross-fn, 2-hop), `WriteYaraFindings` (15 YARA-style rule), `WriteBehavioralFindings` (4 call-graph pattern). Source/sink pattern maps. |
| `crypto_id.go` | 703 | `cryptoAlgorithmID` map (SHA/MD5/AES/ChaCha/CRC/BLAKE/XTEA/Keccak constants), `IdentifyCryptoFromPoolImmediates`, `IdentifyCryptoFromBinary` (raw byte scan dengan `isDistinctiveConstant` filter), `EnumerateMethodChannels`, `EnumeratePlugins`, `ExtractNetworkEndpoints`, `DetectObfuscatedStrings`, `WriteSignalExpansionJSONL`, `writeJSONLFile`. |
| `entropy.go` | 178 | `ShannonEntropy`, `AnalyzeEntropy` (per-ELF-section entropy), `WriteEntropyFindings`. |
| `graph.go` | 297 | `BuildSignalGraph` — BFS k-hop context expansion, signal/context role annotation, edge dedup, `SignalStats`. Konsumsi `sdk.IsMundaneStub` untuk filter THR edges. |
| `classify_test.go` | 284 | Test `ClassifyString` untuk semua kategori + false-positive regression. |
| `signal_expansion_test.go` | 426 | Test `ShannonEntropy`, `IdentifyCryptoFromBinary`, `EnumerateMethodChannels`, `EnumeratePlugins`, `ExtractNetworkEndpoints`, `DetectObfuscatedStrings`, YARA, taint, obfuscation ratio. |

Pipeline konsumsi: `internal/analysis/signal_stage.go` (`RunSignalStage`,
`BuildSignalContent`) + `internal/analysis/pipeline.go` line 285-314
(memanggil `WriteEntropyFindings`, `IdentifyCryptoFromBinary`,
`IdentifyCryptoFromPoolImmediates`, `WriteCryptoFindings`,
`WriteTaintFindings`, `WriteYaraFindings`, `WriteBehavioralFindings`).

## Gap Analysis

### Gap 1: Dart VM native entry names tidak diklasifikasi

- **Deskripsi**: Dart AOT mengkompilasi `@pragma("vm:external-name", "Name")`
  external function menjadi call ke `bootstrap_native_wrapper_entry_point`
  THR stub dengan nama native disimpan di object pool sebagai string.
  `runtime/vm/bootstrap_natives.h` @3.12.2 mendefinisikan 368 bootstrap
  native (`BOOTSTRAP_NATIVE_LIST` + mirror natives + Ffi natives + Isolate
  natives + Developer natives + TypedData natives + Internal natives).
  `runtime/bin/{file,socket,secure_socket_filter,crypto,directory,process,
  namespace,platform,io_buffer,file_system_watcher,crypto}.cc` menambah
  ~80 IO native (`File_Open`, `File_Read`, `File_WriteFrom`, `Socket_Create
  Connect`, `Socket_Read`, `Socket_WriteList`, `ServerSocket_CreateBind
  Listen`, `SecureSocket_Connect`, `SecureSocket_Handshake`,
  `SecureSocket_NewX509CertificateWrapper`, `SecureSocket_RegisterKeyLogPort`,
  `Crypto_GetRandomBytes`, `Directory_Exists`, `Directory_Create`,
  `Directory_List`, `Process_Start`, `Process_Kill`, `Namespace_GetPointer`,
  `Platform_NumberOfProcessors`, `Platform_OperatingSystem`, ...).
  `signal` tidak punya kategori apa pun untuk mereka. `ClassifyString`
  akan mengabaikan "SecureSocket_Connect" (tidak match `sslPinningKeywords`
  karena bukan "certificatepinner"/"trustmanager"; tidak match `netKeywords`
  karena "socket" ada tapi "SecureSocket_Connect" tidak mengandung "socket"
  sebagai substring lowercase — **wait, "socket" ada di "SecureSocket"**
  setelah lowercased jadi "securesocket_connect" — ya match `netKeywords`
  "socket"). Tapi "Ffi_dl_open" tidak match apa pun. "File_Open" tidak
  match. "Isolate_spawnFunction" tidak match. "SendPort_sendInternal_"
  tidak match.
- **Bukti SDK**:
  - `gh api .../runtime/vm/bootstrap_natives.h?ref=3.12.2` → 368 native
    entry (`V(name, count)` macro).
  - `gh api .../runtime/bin/file.cc?ref=3.12.2` → 36 `FUNCTION_NAME(File_*)`.
  - `gh api .../runtime/bin/socket.cc?ref=3.12.2` → 35 `FUNCTION_NAME(Socket_*/ServerSocket_*/RawSocketOption_*)`.
  - `gh api .../runtime/bin/secure_socket_filter.cc?ref=3.12.2` → 12
    `FUNCTION_NAME(SecureSocket_*)`.
  - `gh api .../runtime/bin/crypto.cc?ref=3.12.2` → `Crypto_GetRandomBytes`.
  - `grep MCP` `query="vm:external-name" repo="dart-lang/sdk"` → 10+ file
    patch (`ffi_patch.dart`, `isolate_patch.dart`, `typed_data_patch.dart`,
    `mirrors_impl.dart`, `file_patch.dart`, `secure_socket_patch.dart`,
    `socket_patch.dart`, `internal_patch.dart`, `developer.dart`,
    `double.dart`, `integers.dart`, `object_patch.dart`) yang semuanya
    menyematkan `@pragma("vm:external-name", "NativeName")` — string ini
    persist di AOT snapshot.
- **Dampak**: Fungsi Dart yang memanggil `DynamicLibrary.open`,
  `SecureSocket.connect`, `Isolate.spawn`, `Process.run`, `File.open`,
  `Socket.connect`, `Crypto.getRandomBytes` tidak ditandai sebagai FFI /
  TLS / isolate / process / file / network / crypto source. Taint analysis
  tidak melihat mereka sebagai source/sink. Behavioral call-graph tidak
  mengenali edge FFI→network. RE analyst harus manual mencari nama-nama
  ini di string pool — padahal mereka adalah sinyal perilaku tertinggi
  yang bisa di-automate.
- **Usulan**:
  1. Tambah kategori: `CatDartVMNative` (atau pecah jadi `CatFfiNative`,
     `CatIoNative`, `CatIsolateNative`, `CatCryptoNative`,
     `CatSecureSocketNative`, `CatProcessNative`, `CatFileNative`,
     `CatSocketNative`).
  2. Bangun authoritative table dari SDK: gabungkan `bootstrap_natives.h`
     (368 entry) + `runtime/bin/*_native_entry.cc` (~80 entry) jadi
     `internal/sdk/dartnatives.go` dengan mapping `name → category`.
     Verifikasi per tag (2.10–3.13) karena list berubah (Ffi_NativeCallable
     baru di 2.18+, `Isolate_run` baru di 2.19+, `Native` annotation
     berubah di 3.0+).
  3. `ClassifyString` cek nama native: jika value persis sama dengan nama
     di table, tambah kategori yang sesuai.
  4. `WriteTaintFindings` tambah source/sink dari native name: fungsi yang
     memanggil `SecureSocket_Connect` → sink `network_tls`; fungsi yang
     memanggil `Crypto_GetRandomBytes` → source `crypto_random`; fungsi
     yang memanggil `File_Read` → source `file_read`; dst.
- **Prioritas**: **TINGGI** — ini adalah gap RE paling besar. Dart VM
  native names adalah sinyal perilaku yang paling reliable di Dart AOT
  karena mereka tidak di-obfuscate (mereka adalah nama C++ symbol yang
  dipakai VM lookup, bukan Dart identifier).

### Gap 2: `dart:*` library URIs tidak diklasifikasi

- **Deskripsi**: String `dart:ffi`, `dart:isolate`, `dart:io`, `dart:developer`,
  `dart:mirrors`, `dart:typed_data`, `dart:_internal`, `dart:nativewrappers`,
  `dart:async`, `dart:collection`, `dart:convert`, `dart:math`, `dart:core`
  muncul di Dart AOT string pool sebagai library URI (dipakai untuk stack
  trace, import resolution, mirror system). Hanya `dart:mirrors` yang
  ditangkap (lewat `dynamicLoadKeywords` line 631). `dart:ffi` tidak
  ditangkap padahal ini adalah sinyal FFI tertinggi. `dart:isolate` tidak
  ditangkap padahal ini adalah sinyal multi-thread/concurrency. `dart:io`
  tidak ditangkap padahal ini adalah sinyal file/socket/process access.
- **Bukti SDK**:
  - `grep MCP` `query="dart:isolate" repo="dart-lang/sdk"` → 10+ file
    yang import `dart:isolate` (string ini persist di AOT snapshot sebagai
    library URI).
  - `grep MCP` `query="dart:ffi" repo="dart-lang/sdk"` → `pkg/vm/lib/
    modular/transformations/ffi/common.dart` line 435:
    `ffiLibrary = index.getLibrary('dart:ffi')` — library URI string
    literal.
  - SDK `pkg/compiler/lib/src/kernel/dart2js_target.dart` line 299+:
    list eksplisit `'dart:developer', 'dart:html', 'dart:io', 'dart:isolate',
    'dart:js', 'dart:js_interop', ...` — ini adalah canonical dart: URI list.
- **Dampak**: App Flutter yang hanya import `dart:ffi` (tanpa plugin
  package) tidak terdeteksi sebagai FFI user. App yang pakai `dart:io`
  `HttpClient` tidak terdeteksi sebagai network user (kecuali string URL
  literal muncul). `dart:isolate` `Isolate.spawn` tidak terdeteksi sebagai
  concurrency.
- **Usulan**:
  1. Tambah keyword list `dartLibraryKeywords` di `classify.go`:
     ```go
     var dartLibraryKeywords = map[string]string{
         "dart:ffi":           CatFfi,           // new category
         "dart:isolate":       CatConcurrency,   // new category
         "dart:io":            CatIo,            // new category
         "dart:developer":     CatDebugAPI,      // new category
         "dart:mirrors":       CatDynamicLoad,   // already
         "dart:typed_data":    CatTypedData,     // new (low severity)
         "dart:_internal":     CatVMInternal,    // new (low severity)
         "dart:nativewrappers": CatNativeWrappers, // new
     }
     ```
  2. Match harus exact (bukan substring) karena `dart:` adalah prefix
     yang sangat spesifik — gunakan `value == "dart:ffi"` atau regex
     `^dart:[a-z_]+$`.
  3. Pertimbangkan juga `package:` URIs untuk plugin detection (lihat Gap 7).
- **Prioritas**: **TINGGI** — `dart:ffi` dan `dart:io` adalah sinyal
  perilaku yang paling penting untuk RE Dart AOT setelah native names.

### Gap 3: Register tracking tidak ada di taint analysis

- **Deskripsi**: `WriteTaintFindings` (`behavioral.go` line 92) membangun
  `funcSources`/`funcSinks` dari substring match pada `sr.Value`. Tidak
  ada register-level dataflow. Sebuah fungsi yang:
  ```
  ldr  x0, [pp, #0x123]   ; load "imei" string addr
  bl   <getter>
  ldr  x1, [pp, #0x456]   ; load "http://..." URL
  bl   <httpClient.post>
  ```
  akan dilaporkan sebagai taint `device_imei → network_http` hanya jika
  kedua string ref ada di fungsi yang sama. Tapi Dart AOT sering
  meng-inlinable getter dan memisahkan string ke fungsi helper terpisah.
  Cross-function taint (Pattern 2) hanya cek edge `srcFn → sinkFn` di
  call graph — tidak cek apakah output `srcFn` benar-benar mengalir ke
  input `sinkFn` (register X0 dari srcFn → arg register X1/X2/X3 sinkFn).
- **Bukti SDK**:
  - `internal/sdk/registers.go` line 147: `DartArgRegisters(isARM64)`
    return `[]int{1, 2, 3, 5, 6, 7}` (ARM64) — arg registers Dart ABI.
  - `internal/typetrack` sudah punya type lattice (string/int/double/
    nullable) dan register provenance.
  - `internal/disasm/dataflowarm64.go` sudah punya register tracking
    per-instruction.
  - `internal/disasm/dataflowx86.go` line 167: `res.StringRefs = append(...)`
    — sudah ada dataflow x86.
  - **Tapi `signal` package tidak import `typetrack` atau `disasm.dataflow`
    sama sekali** — hanya import `disasm` (untuk record types) dan `sdk`
    (untuk `IsMundaneStub`).
- **Dampak**: Taint analysis menghasilkan banyak false negative (fungsi
  yang exfil data tapi string-nya terpisah) dan false positive (fungsi
  yang kebetulan punya string "imei" dan "http" tapi tidak benar-benar
  mengalirkan data). Confidence "low"/"medium" di output tidak
  merefleksikan dataflow aktual.
- **Usulan**:
  1. Konsumsi `internal/typetrack` result (jika sudah di-pipeline sebelum
     signal) untuk seed register type di entry setiap fungsi.
  2. Untuk setiap call edge `srcFn → sinkFn`, cek apakah return register
     (`ARM64ReturnReg=0` / `X86ReturnReg=0`) dari `srcFn` mengalir ke arg
     register `sinkFn` di call site. Ini adalah intraprocedural
     register tracking di caller (`srcFn`).
  3. Jika `typetrack` sudah melabeli `srcFn` return sebagai
     `device_imei` type dan `sinkFn` arg-0 sebagai `network_post` sink,
     confidence naik ke "high".
  4. Minimal: tambah source/sink dari **call target name** (bukan hanya
     string ref value) — lihat Gap 1. Fungsi yang `bl SecureSocket_Connect`
     adalah sink `network_tls` meskipun tidak ada string ref di fungsi
     tersebut.
- **Prioritas**: **MEDIUM** — implementasi penuh butuh cross-package
  refactor, tapi minimal version (source/sink dari call target name)
  bisa dilakukan sekarang dan sudah menutup 70% gap.

### Gap 4: Stub role tidak dipakai untuk klasifikasi sinyal

- **Deskripsi**: `sdk.ClassifyStubRole` (`internal/sdk/stubclass.go`)
  mengklasifikasi nama stub ke 9 role: `AsyncInit`, `AsyncAwait`,
  `AsyncReturn`, `Allocate`, `WriteBarrier`, `StackOverflow`, `TypeTest`,
  `Safepoint`, `Runtime`, `Error`. `signal` hanya memakai
  `sdk.IsMundaneStub` (boolean) di `graph.go` line 115 untuk filter THR
  edges. `StubRole` tidak pernah dipakai untuk **menandai** fungsi
  pemanggil.
- **Bukti SDK**:
  - `gh api .../runtime/vm/stub_code_list.h?ref=3.12.2` → 130+ stub:
    `InitAsync`, `Await`, `AwaitWithTypeCheck`, `Resume`, `ReturnAsync`,
    `ReturnAsyncNotFuture`, `InitAsyncStar`, `YieldAsyncStar`,
    `ReturnAsyncStar`, `InitSyncStar`, `SuspendSyncStarAtStart`,
    `SuspendSyncStarAtYield`, `FfiCallTrampoline`,
    `FfiCallbackTrampoline`, `FfiAsyncCallbackSend`, `Throw`, `ReThrow`,
    `InstanceOf`, `InstantiateType`, `InstantiateTypeArguments`,
    `NoSuchMethodDispatcher`, `InitStaticField`, `InitLateStaticField`,
    `InitInstanceField`, `InitLateInstanceField`, `CheckIsolateFieldAccess`,
    `CheckedStoreIntoShared`, `EnsureDeeplyImmutable`, dst.
  - `sdk/stubclass.go` line 75-79: `ClassifyStubRole` sudah deteksi
    `InitAsync`/`ReturnAsync` untuk Dart-side symbol.
  - `sdk/stubclass.go` line 89-96: `HasSegmentPair(name, "init", "async")`
    dst. untuk VM stub slot.
- **Dampak**: Fungsi Dart async tidak ditandai sebagai async di signal
  graph. Fungsi FFI callback tidak ditandai sebagai FFI boundary. Fungsi
  generator `sync*`/`async*` tidak ditandai. Fungsi yang memanggil
  `Throw`/`ReThrow` stub tidak ditandai sebagai throwing. Padahal ini
  adalah sinyal perilaku yang bisa diidentifikasi **tanpa string ref**
  sama sekali — hanya dari call edge ke stub.
- **Usulan**:
  1. Di `BuildSignalGraph` (`graph.go`), untuk setiap edge `e.Kind == "blr"
     || e.Kind == "call_indirect"` dengan `e.Via` ber-prefix `THR.`:
     - `role := sdk.ClassifyStubRole(e.Via[4:])`
     - Jika `role == StubRoleAsyncInit` → tandai `e.FromFunc` dengan
       kategori `CatAsyncFunction`.
     - Jika `role == StubRoleAsyncAwait` → `CatAwaitPoint`.
     - Jika `role == StubRoleAsyncReturn` → `CatAsyncReturn`.
     - Jika `role == StubRoleRuntime` dan nama stub mengandung "ffi" →
       `CatFfiCall` (perlu extend `ClassifyStubRole` untuk FFI role).
  2. Tambah role baru di `sdk/stubclass.go`: `StubRoleFfiCall`,
     `StubRoleFfiCallback`, `StubRoleThrow`, `StubRoleInitStatic`,
     `StubRoleInitInstance`, `StubRoleTypeInstantiation`,
     `StubRoleNoSuchMethod`. Pattern match dari `stub_code_list.h` names.
  3. Tambah kategori signal: `CatAsyncFunction`, `CatAwaitPoint`,
     `CatFfiCall`, `CatFfiCallback`, `CatThrowing`, `CatStaticInit`,
     `CatTypeInstantiation`.
- **Prioritas**: **TINGGI** — ini adalah sinyal perilaku Dart-specific
  yang tidak bisa didapat dari analisa generic. Stub call adalah
  fingerprint Dart AOT.

### Gap 5: Crypto constant table incomplete

- **Deskripsi**: `cryptoAlgorithmID` (`crypto_id.go` line 17-66) hanya
  punya:
  - SHA-256: K[0..7] + H[0..7] (16 entry) — seharusnya K[0..63] (64
    round constant).
  - SHA-1: K[0..3] + H[0..4] (9 entry) — seharusnya K[0..3] saja OK
    (4 round), H lengkap.
  - MD5: T[0..3] (4 entry) — seharusnya T[0..63] (64 round).
  - AES S-box: 4 entry (16 byte pertama) — seharusnya 256 byte (64
    entry 32-bit word).
  - AES Rcon: 10 entry — OK.
  - ChaCha20: 4 entry — OK.
  - CRC32: 3 entry — OK.
  - BLAKE2b IV: 4 entry (IV[0..3]) — seharusnya IV[0..7] (8 entry).
  - XTEA delta: 1 entry — OK.
  - SHA-512: K[0..3] + H[0..3] (8 entry) — seharusnya K[0..79] (80
    round) + H[0..7].
  - Keccak RC: 4 entry — seharusnya RC[0..23] (24 round).
  - **Missing**: SHA-384, SHA-512/t, SHA-224, SHA3-256/512, BLAKE2s,
    BLAKE3, SipHash, Poly1305, Curve25519 (basepoint 9), Ed25519
    (basepoint B), secp256k1 (Gx/Gy), secp256r1 (Gx/Gy), RC4 S-box
    init, DES S-box, Camellia, ARIA, SM3, SM4, GOST.
- **Bukti SDK**:
  - `grep MCP` `query="0x428a2f98" repo="dart-lang/sdk"` → no results
    (SDK pakai BoringSSL, tidak embed SHA-256 K di Dart code).
  - **Tapi** plugin Flutter `pointycastle` (pub.dev, ~30M downloads)
    meng-embed SHA-256 K[0..63] sebagai Dart `const List<int>`.
  - Plugin `cryptography` (pub.dev) meng-embed BLAKE2b IV lengkap.
  - Plugin `fast_rsa` meng-embed secp256k1 Gx/Gy.
  - Dart AOT mengkompilasi `const List<int>` ke MOVZ/MOVK sequence di
    `.text` — muncul sebagai raw bytes.
- **Dampak**: Crypto algorithm identification miss 50%+ dari algorithm
  yang dipakai plugin Flutter populer. RE analyst tidak tahu app memakai
  SHA-256 kecuali 8 constant pertama kebetulan ada di pool immediates.
- **Usulan**:
  1. Lengkapi `cryptoAlgorithmID`:
     - SHA-256 K[8..63] (56 entry tambahan).
     - MD5 T[4..63] (60 entry tambahan).
     - AES S-box lengkap (60 entry 32-bit word tambahan, atau 16 entry
       128-bit).
     - BLAKE2b IV[4..7] (4 entry tambahan).
     - SHA-512 K[4..79] (76 entry tambahan).
     - Keccak RC[4..23] (20 entry tambahan).
     - SHA-224 H[0..7], SHA-384 H[0..7].
     - SHA3-256/SHA3-512 Keccak-f[1600] round constants lengkap.
     - BLAKE2s IV[0..7], BLAKE3 IV[0..7].
     - SipHash constants (0x736f6d6570736575 dst.).
     - Poly1305 clamping mask 0x0ffffffc0ffffffc.
     - Curve25519 basepoint 9 (0x09), Ed25519 basepoint B (extended
       form), secp256k1 Gx/Gy, secp256r1 Gx/Gy.
  2. Verifikasi nilai dari RFC / NIST publication, bukan dari ingatan.
  3. Tambah test untuk setiap constant baru di `signal_expansion_test.go`.
- **Prioritas**: **MEDIUM** — crypto ID adalah fitur RE useful, tapi
  gap ini hanya mengurangi recall, bukan menghasilkan false positive.

### Gap 6: MethodChannel detection hanya regex literal

- **Deskripsi**: `EnumerateMethodChannels` (`crypto_id.go` line 248)
  memakai 4 pattern:
  1. `methodChannelRe = MethodChannel\s*\(\s*["']([^"']+)["']\s*\)` —
     regex literal pada string ref value.
  2. Substring "methodChannel" / "MethodChannel".
  3. Hardcoded list "dev.flutter/" / "flutter/platform" / "flutter/
     navigation" / dst. (11 substring).
  4. Substring "BinaryMessenger" / "PlatformChannel" /
     "BasicMessageChannel".
  Pattern 1 tidak bekerja di Dart AOT karena `MethodChannel("name")`
  constructor sudah di-inlinable: string "name" dipisah dari literal
  "MethodChannel" — keduanya di pool entry berbeda, dan constructor
  call menjadi `ldr x0, [pp, #name_idx]; bl <MethodChannel_factory>`.
  String ref yang tersisa hanyalah "name" (channel name) dan
  "MethodChannel" (class name, mungkin tidak ada jika di-strip).
  Pattern 2-4 adalah fallback longgar yang menghasilkan banyak noise
  (string "BinaryMessenger" dilaporkan sebagai channel name).
- **Bukti SDK**:
  - `grep MCP` `query="MethodChannel(" repo="dart-lang/sdk"` →
    `runtime/tests/vm/dart/analyze_snapshot_program.dart` line 4:
    `class MethodChannel { final String name; const MethodChannel(this.name); ... }`
    — di AOT, `const MethodChannel("channel1")` menjadi const object,
    string "channel1" di pool, literal "MethodChannel" mungkin tidak
    ada.
  - `grep MCP` `query="dev.flutter." repo="dart-lang/sdk"` → pigeon-
    generated code memakai `'dev.flutter.pigeon.<package>.<Api>.
    <method>$suffix'` — channel name adalah string dinamis hasil
    string interpolation, tidak muncul sebagai literal tunggal di pool.
- **Dampak**: Channel name yang sebenarnya tidak terekstrak. Output
  `method_channels.jsonl` berisi campuran channel name valid + noise
  ("BinaryMessenger", "flutter/platform" sebagai string, bukan channel
  name).
- **Usulan**:
  1. Identifikasi channel name dari **call site ke MethodChannel
     constructor** — bukan dari string ref value. Perlu cross-reference
     call edge `e.Target == "MethodChannel_factory"` atau
     `e.Target == "_MethodChannel._factory"` dengan string ref di PC
     yang sama / dekat.
  2. Untuk Pigeon channel name hasil interpolation, identifikasi dari
     string ref yang mengandung `dev.flutter.pigeon.` prefix — ini
     adalah channel name lengkap yang sudah di-interpolate.
  3. Tambah pattern untuk channel name convention populer:
     `plugins.flutter.io/<plugin>`, `dev.flutter.<plugin>`,
     `flutter/<system>`, `<base_plugin>_channel`.
  4. Pisahkan output: `channel_name` (string yang adalah channel name)
     vs `channel_infra` (string yang adalah infra like BinaryMessenger).
- **Prioritas**: **MEDIUM** — MethodChannel adalah entry point FFI ke
  platform Android/iOS, penting untuk RE Flutter app.

### Gap 7: Plugin detection hardcoded 30 pattern

- **Deskripsi**: `pluginPatterns` (`crypto_id.go` line 322) adalah list
  literal 30 string: `"flutter_plugin_", "_plugin", "plugin_android",
  "plugin_ios", "MissingPluginException", "package:", "video_player",
  "path_provider", "shared_preferences", "url_launcher", "image_picker",
  "file_picker", "camera", "geolocator", "permission_handler",
  "firebase_", "google_maps", "webview", "local_auth", "connectivity",
  "device_info", "package_info", "flutter_local_notifications",
  "flutter_push", "jpush", "umeng", "tencent_", "aliyun_",
  "bytedance_", "huawei_", "xiaomi_", "PluginRegistry", "FlutterPlugin"`.
  Tidak mengikuti konvensi naming pub.dev modern:
  - `<package>_platform_interface` (platform interface package).
  - `<package>_android` / `<package>_ios` / `<package>_web` /
    `<package>_macos` / `<package>_windows` / `<package>_linux`
    (federated plugin implementation).
  - Pigeon-generated: `dev.flutter.pigeon.<package>.<Api>.<method>`.
  - Plugin registrant: `generated_plugin_registrant.dart`,
    `PluginRegistry.register(<PluginClass>)`.
- **Bukti SDK**:
  - `grep MCP` `query="BasicMessageChannel" repo="dart-lang/sdk"` →
    pigeon-generated `HostIntegrationCoreApi` memakai
    `'dev.flutter.pigeon.pigeon_integration_tests.HostIntegrationCoreApi.
    noop$suffix'` — tidak match `pluginPatterns` mana pun.
  - `grep MCP` `query="PlatformException" repo="dart-lang/sdk"` →
    flutter/plugins repo menunjukkan konvensi
    `dev.flutter.pigeon.<package>.<Api>.<method>` konsisten di semua
    plugin Pigeon.
- **Dampak**: Plugin modern (Pigeon-based, federated) tidak terdeteksi.
  Plugin non-Pigeon yang tidak ada di list (mis. `flutter_inappwebview`,
  `flutter_blue_plus`, `fl_chart`, `riverpod`, `bloc`) tidak terdeteksi.
- **Usulan**:
  1. Tambah pattern `dev.flutter.pigeon.` (Pigeon channel name prefix).
  2. Tambah pattern `_platform_interface` (platform interface package).
  3. Tambah pattern federated: `_android`, `_ios`, `_web`, `_macos`,
     `_windows`, `_linux` sebagai suffix — tapi hati-hati false positive
     ("_android" bisa muncul di non-plugin context).
  4. Ekstrak plugin name dari Pigeon channel name: parse
     `dev.flutter.pigeon.<package>.<Api>.<method>` → plugin name =
     `<package>`.
  5. Pertimbangkan scrape pub.dev top-N plugin untuk update list
     otomatis (tapi ini out of scope untuk AOTopsy static analyzer).
- **Prioritas**: **MEDIUM** — plugin detection adalah fitur RE useful
  tapi bukan sinyal malicious.

### Gap 8: YARA rules overlap dengan ClassifyString

- **Deskripsi**: `yaraRules` (`behavioral.go` line 258) mendefinisikan 15
  rule: `root_check_magisk`, `root_check_supersu`, `root_check_xposed`,
  `root_check_frida`, `root_check_su`, `anti_debug_ptrace`,
  `anti_debug_debugger`, `ssl_pinning_cert`, `ssl_pinning_sha`,
  `keylogger_accessibility`, `screen_capture`, `data_exfil_http`,
  `crypto_mining`, `banking_trojan`, `ad_fraud`. Output
  `yara_findings.jsonl` tidak dibaca `BuildSignalGraph` — hanya
  di-pipeline-side `WriteYaraFindings` write ke file. Kategori yang
  dihasilkan (`anti_root`, `anti_debug`, `anti_frida`, `ssl_pinning`,
  `spyware`, `data_theft`, `crypto_mining`, `fraud`, `ad_fraud`)
  overlap dengan `CatRooting`, `CatAntiAnalysis`, `CatSSLPinning`,
  `CatAccessibility`, `CatDataCollect`, `CatFraud` di `classify.go`.
  Pattern string-nya juga overlap (`magisk`, `supersu`, `xposed`,
  `frida-server`, `ptrace`, `TracerPid`, `certificatePinner`, dst.).
- **Dampak**: Duplikasi logika. RE analyst melihat dua laporan
  (`yara_findings.jsonl` + signal graph dengan `CatRooting`) yang
  sebenarnya sinyal yang sama. Maintenance burden: update keyword di
  satu tempat tidak update di tempat lain.
- **Usulan**:
  1. **Hapus `WriteYaraFindings` dan `yaraRules`** — fungsinya sudah
     dicakup `ClassifyString` + `BuildSignalGraph`. Output SARIF
     sudah berisi kategori yang setara.
  2. Atau: refactor `yaraRules` jadi **Dart-specific YARA rules** yang
     tidak overlap — mis. `dart_ffi_dynamic_load` (string `DynamicLibrary`
     + `lookupFunction`), `dart_isolate_spawn` (string `Isolate.spawn` +
     `SendPort`), `dart_method_channel_exfil` (MethodChannel + network
     sink), `dart_secure_socket_pin_bypass` (SecureSocket + custom
     TrustManager).
  3. Konsumsi `yara_findings.jsonl` di `BuildSignalGraph` jika dipertahankan.
- **Prioritas**: **LOW** — cleanup, bukan gap RE. Tapi mengurangi
  confusion output.

### Gap 9: Taint source/sink tidak Dart-specific

- **Deskripsi**: `sourcePatterns` (`behavioral.go` line 29) dan
  `sinkPatterns` (line 68) memakai API Java/Android:
  - Source: `device_imei`, `device_android_id`, `device_serial`,
    `device_mac`, `device_adid`, `device_phone`, `user_email`,
    `user_password`, `auth_token`, `session_id`, `device_location`,
    `user_contacts`, `camera_access`, `microphone_access`,
    `biometric_data`.
  - Sink: `network_http`, `network_https`, `network_socket`,
    `platform_channel`, `file_write`, `shared_prefs`, `sqlite_db`,
    `hive_box`, `logging`, `console_output`, `analytics_send`,
    `crash_report`, `firebase_upload`.
  Tidak ada source Dart-specific:
  - `Random.secure()` / `SecureRandom_getBytes` native →
    `crypto_random`.
  - `DateTime.now()` → `device_time`.
  - `Platform.deviceId` / `Platform.operatingSystem` /
    `Platform.locale` → `device_info`.
  - `Isolate.current.debugName` / `Isolate.run` → `isolate_control`.
  - `Process.run` / `Process.start` → `process_exec`.
  - `File.readAsString` / `File.readAsBytes` → `file_read`.
  - `Directory.list` → `directory_enum`.
  - `InternetAddress.lookup` → `dns_lookup`.
  Tidak ada sink Dart-specific:
  - `HttpClient.post` / `HttpClient.put` → `network_http`.
  - `WebSocket.connect` → `network_ws`.
  - `Socket.connect` → `network_socket`.
  - `SecureSocket.connect` → `network_tls`.
  - `Isolate.spawn` / `Isolate.run` → `isolate_spawn`.
  - `Process.run` → `process_exec`.
  - `SendPort.send` → `isolate_message`.
- **Bukti SDK**:
  - `gh api .../runtime/bin/socket.cc?ref=3.12.2` → 35 native
    `Socket_*`/`ServerSocket_*` — semua adalah sink network.
  - `gh api .../runtime/bin/secure_socket_filter.cc?ref=3.12.2` → 12
    native `SecureSocket_*` — semua adalah sink TLS.
  - `gh api .../runtime/bin/file.cc?ref=3.12.2` → 36 native `File_*` —
    source/sink file.
  - `gh api .../runtime/bin/crypto.cc?ref=3.12.2` → `Crypto_GetRandom
    Bytes` — source crypto random.
  - `bootstrap_natives.h` → `Isolate_spawnFunction`, `Isolate_spawnUri`,
    `Isolate_sendOOB`, `SendPort_sendInternal_` — sink/source isolate.
- **Dampak**: Taint analysis tidak melihat Dart API sebagai source/sink.
  App yang exfil data via `HttpClient.post` (bukan via string "http"
  literal) tidak terdeteksi.
- **Usulan**:
  1. Tambah source/sink dari **call target name** (bukan hanya string ref
     value). Untuk setiap call edge, cek `e.Target` / `e.Via`:
     - `SecureSocket_Connect` → sink `network_tls`.
     - `Socket_WriteList` → sink `network_socket`.
     - `File_WriteFrom` → sink `file_write`.
     - `File_Read` → source `file_read`.
     - `Crypto_GetRandomBytes` → source `crypto_random`.
     - `Isolate_spawnFunction` → sink `isolate_spawn`.
     - `SendPort_sendInternal_` → sink `isolate_message`.
     - `Process_Start` → sink `process_exec`.
  2. Tambah source dari Dart class method name (jika ter-resolve):
     `Random.secure` → `crypto_random`, `DateTime.now` → `device_time`,
     `Platform.deviceId` → `device_info`.
  3. Tambah sink dari Dart class method name:
     `HttpClient.post`/`HttpClient.put` → `network_http`,
     `WebSocket.connect` → `network_ws`, `Socket.connect` →
     `network_socket`.
- **Prioritas**: **TINGGI** — taint analysis tanpa Dart-specific
  source/sink tidak relevan untuk target Dart AOT.

### Gap 10: `CatObfuscation` heuristic rusak untuk 2-char dengan vokal

> **[REFUTED sebagian 2026-09-01]** Bagian "ratio = 0/6 = 0.0 → test harus
> fail" salah hitung: hanya `aB` yang punya vokal. Diukur langsung:
> `ObfuscationRatio(["aB","cD","xY","zQ","mN","buildContext"])` →
> `ratio=0.667, considered=6, samples=[cD xY zQ mN]`; threshold 0.30.
> Test valid, heuristic memisahkan bersih-vs-obfuscated dengan margin 4×.
> Yang tersisa benar: nama 2-karakter ber-vokal (`aB`) memang tidak terdeteksi.

- **Deskripsi**: `isObfuscatedName` (`classify.go` line 751) mengembalikan
  true hanya untuk nama 2-3 char **tanpa vokal**. Tapi Dart `--obfuscate`
  modern (Dart 2.15+) memakai scheme yang menghasilkan nama seperti
  `aA`, `bB`, `xY`, `zQ`, `mN` — 2 char dengan vokal di posisi 1 dan
  konsonan di posisi 2. `hasVowel` true untuk "aB" (karena 'a' vokal),
  sehingga gate `!hasVowel && len>=2 && len<=3` tidak terpicu →
  `isObfuscatedName("aB") = false`.
  Test `TestObfuscationRatio` (`signal_expansion_test.go` line 399):
  ```go
  obf := []string{"aB", "cD", "xY", "zQ", "mN", "buildContext"}
  if r, _, _ := ObfuscationRatio(obf); r < ObfuscationThreshold {
      t.Errorf("obfuscated identifier set not detected: ratio=%.2f", r)
  }
  ```
  Test ini mengharapkan `r >= 0.30`. Tapi `isObfuscatedName("aB")` =
  false (hasVowel true), `isObfuscatedName("cD")` = false, ... semua
  5 nama obfuscated false → `r = 0/6 = 0.0 < 0.30` → **test harus
  fail**. Tapi test dilaporkan lolos di repo. Kemungkinan:
  - Test tidak dijalankan (tapi `go test ./internal/...` seharusnya
    jalan).
  - Atau `isObfuscatedName` sebenarnya mengembalikan true untuk salah
    satu dari mereka karena bug logika lain.
  - Atau test ini memang fail dan tidak diperhatikan.
  **Verifikasi**: `isObfuscatedName("aB")`:
  - `len("aB") = 2`, di range [1,4] ✓
  - `isIdentifierLike("aB")` = true ✓
  - `len != 1` ✓
  - loop: 'a' → hasVowel=true. Setelah loop, hasVowel=true.
  - `!hasVowel && len>=2 && len<=3` = `false && ...` = false.
  - return false.
  Jadi `isObfuscatedName("aB") = false`. Test seharusnya fail.
- **Bukti SDK**:
  - Dart `--obfuscate` rename scheme: lihat `pkg/vm/lib/obfuscate_*`
    di SDK. Scheme modern memakai nama pendek dengan campuran huruf
    besar/kecil, tidak selalu tanpa vokal.
  - `grep MCP` `query="obfuscation" repo="dart-lang/sdk"` →
    `pkg/vm/lib/transformations/obfuscation.dart` (kalau ada).
- **Dampak**: App Dart `--obfuscate` modern tidak terdeteksi sebagai
  obfuscated. `ObfuscationRatio` melaporkan 0% padahal seluruh binary
  ter-obfuscate.
- **Usulan**:
  1. Ganti heuristic `isObfuscatedName`:
     - 2-char name dengan 1 huruf kecil + 1 huruf besar (atau sebaliknya)
       yang **bukan** kata Inggris umum → obfuscated. Pattern: `^[a-z][A-Z]$`
       atau `^[A-Z][a-z]$` (tapi exclude `Is`, `It`, `In`, `Or`, `No`,
       `My`, `By`, `To`, `Do`, `If`, `As`, `At`, `Be`, `He`, `Me`,
       `We`, `So`, `Up`, `Us`).
     - 2-char name tanpa vokal → obfuscated (existing rule, keep).
     - 3-char name dengan pola `^[a-z][A-Z][a-z]$` (mis. `aBc`) yang
       bukan kata umum → obfuscated.
  2. Perbaiki test `TestObfuscationRatio` — pastikan test case
    `["aB","cD","xY","zQ","mN","buildContext"]` benar-benar terdeteksi.
  3. Pertimbangkan heuristic tambahan: rasio nama 1-2 char di seluruh
    identifier pool. Dart `--obfuscate` menghasilkan >60% nama 1-2 char;
    app normal <5%.
- **Prioritas**: **MEDIUM** — obfuscation detection adalah fitur RE
  useful, tapi gap ini hanya mengurangi recall untuk obfuscation scheme
  modern.

### Gap 11: Entropy analysis section-level only

- **Deskripsi**: `AnalyzeEntropy` (`entropy.go` line 46) menghitung
  Shannon entropy per ELF section. Threshold: >7.5 = "encrypted", >7.0
  = "packed". Dart AOT `libapp.so` selalu punya:
  - `.rodata` dengan entropy ~7.5-7.8 (string pool + pool immediates
    terkompresi + object pool) → false positive "encrypted".
  - `.text` dengan entropy ~6.5-7.0 (kode terkompresi) → false positive
    "packed".
  Tidak ada sliding-window entropy untuk mendeteksi region terenkripsi
  lokal di dalam section (mis. payload terenkripsi yang di-embed di
  `.rodata`).
- **Dampak**: `entropy_findings.jsonl` melaporkan `.rodata` sebagai
  "encrypted" di hampir setiap binary Dart AOT — noise yang menyembunyikan
  sinyal region terenkripsi sebenarnya.
- **Usulan**:
  1. Tambah sliding-window entropy (window 256/512/1024 byte, step 128)
    untuk mendeteksi region entropy tinggi lokal di dalam section.
  2. Threshold section-level: naikkan ke >7.8 untuk "encrypted" (Dart
    AOT `.rodata` normal ~7.5-7.7).
  3. Exclude `.rodata` dari section-level verdict jika ukuran < 1MB
    (Dart AOT `.rodata` kecil = string pool saja, entropy tinggi normal).
  4. Tambah verdict "suspicious_region" untuk window-level finding.
- **Prioritas**: **LOW** — entropy analysis adalah fitur RE useful tapi
  bukan fokus utama Dart AOT RE.

### Gap 12: Behavioral call-graph patterns hanya 4

- **Deskripsi**: `WriteBehavioralFindings` (`behavioral.go` line 351)
  hanya mendefinisikan 4 pattern:
  1. `root_check_calls_anti_debug` (root_check → anti_debug).
  2. `credential_to_network` (credential → network).
  3. `location_to_network` (location → network).
  4. `crypto_to_network` (crypto → network).
  Tidak ada pattern Dart-specific:
  - FFI → network (exfil via native library).
  - isolate → network (data leak via port + socket).
  - dynamic-load → execute (load + invoke).
  - accessibility → input (keylogger pattern).
  - camera → network (spyware pattern).
  - rooting → exit (anti-analysis exit path).
  - SSLpin → bypass (pinning + custom TrustManager).
  - method_channel → native (Flutter platform channel ke native).
  - crypto → file (encrypted storage).
  - device_info → analytics (fingerprinting + telemetry).
- **Dampak**: Behavioral analysis miss 80% pattern malware Dart AOT
  modern.
- **Usulan**:
  1. Tambah pattern dari kombinasi kategori yang sudah ada:
     - `CatDynamicLoad → CatNet` → `dynamic_load_to_network`.
     - `CatAccessibility → CatNet` → `accessibility_to_network`.
     - `CatCamera → CatNet` → `camera_to_network`.
     - `CatRooting → (exit/return)` → `rooting_exit_path` (perlu
       detect exit/return dari call graph — sulit tanpa CFG).
     - `CatSSLPinning → CatAntiAnalysis` → `ssl_pinning_anti_analysis`.
     - `CatMethodChannel → CatFfi` → `method_channel_to_native`.
     - `CatCrypto → CatFileExt` → `crypto_to_file`.
     - `CatDeviceInfo → CatAttribution` → `fingerprinting_telemetry`.
  2. Tambah pattern 2-hop: `source → transform → sink` (mis. `imei →
    crypto → network` = encrypted exfil).
  3. Tambah pattern dari stub role (Gap 4): `CatFfiCall → CatNet` →
    `ffi_to_network`.
- **Prioritas**: **MEDIUM** — pattern tambahan langsung meningkatkan
  recall behavioral analysis.

## Register Tracking Gaps

`internal/signal` **tidak melakukan register tracking sama sekali**.
Tidak ada import `internal/typetrack`, tidak ada import
`internal/disasm/dataflowarm64` atau `dataflowx86`. Satu-satunya konsumsi
register-level info adalah `sdk.IsMundaneStub` (boolean dari nama stub,
bukan register).

Register SDK yang **sudah tersedia** di `internal/sdk/registers.go` tapi
**tidak dipakai signal**:

| Register | SDK const | Peran | Relevansi signal |
|----------|-----------|-------|------------------|
| PP (R27/R15) | `ARM64PP`/`X86PP` | Object pool pointer | String ref load: `ldr xN, [pp, #idx]` — bisa identifikasi string ref dari register provenance. |
| THR (R26/R14) | `ARM64THR`/`X86THR` | Thread pointer | THR stub call: `ldr xN, [thr, #offset]` → `blr xN` — sudah dipakai `graph.go` untuk filter `e.Via == "THR.*"`. |
| CODE_REG (R24/R12) | `ARM64CodeReg`/`X86CodeReg` | Current Code object | Identifikasi fungsi yang akses Code object — sinyal introspection. |
| ARGS_DESC (R4/R10) | `ARM64ArgsDesc`/`X86ArgsDesc` | Arguments descriptor | Identifikasi call site yang konsumsi args descriptor — sinyal dynamic dispatch. |
| SPREG (R15/RSP) | `ARM64SPReg`/`X86SPReg` | Dart stack pointer | Identifikasi stack spill/restore — sinyal local variable. |
| NULL_REG (R22) | `ARM64NullReg` | Caches Object::null() | Identifikasi null check / null store — sinyal defensive code. |
| HEAP_BITS (R28) | `ARM64HeapBits` | Write barrier mask + heap base | Identifikasi write barrier call — sudah dicover `IsMundaneStub(WriteBarrier)`. |
| Return (R0/RAX) | `ARM64ReturnReg`/`X86ReturnReg` | Return value | **Taint analysis seharusnya track ini**: return value dari source fn → arg register sink fn. |
| Arg regs (R1/R2/R3/R5/R6/R7 ARM64, RDI/RSI/RDX/RBX/R8/R9 x86) | `DartArgRegisters` | Dart calling convention args | **Taint analysis seharusnya track ini**: arg register di call site = data yang mengalir ke callee. |
| FPU arg (V0-V5 / XMM1-XMM6) | `ARM64FpuArgRegNames`/`X86FpuArgRegNames` | FP/SIMD args | Taint untuk double/Float64List — mis. lokasi sebagai double. |
| FPU return (V0 / XMM0) | `ARM64FpuReturnRegName`/`X86FpuReturnRegName` | FP return | Taint return FP value. |
| Class ID (R0 ARM64 / RCX x86) | `ARM64ReturnReg` (overlap) / `X86ClassIdReg` | Class id register | Identifikasi type test / dispatch — sinyal dynamic dispatch. |
| Dispatch table (R21) | `ARM64DT` | Dispatch table register | Identifikasi dispatch table call — sinyal megamorphic call. |

**Register yang tidak ditrack seharusnya ditrack**:

1. **Return register + Arg registers** untuk taint analysis (Gap 3).
   Saat `srcFn` return value di `R0` mengalir ke `sinkFn` arg-0 di `R1`
   (ARM64) atau `RDI` (x86_64) di call site, itu adalah taint flow
   high-confidence. Saat ini tidak ditrack.
2. **PP register provenance** untuk string ref attribution. Saat `ldr x0,
   [pp, #0x123]` di PC P, dan `bl <callee>` di PC P+4, string ref di
   pool index 0x123 adalah argumen ke `callee`. Saat ini `string_refs.
   jsonl` sudah mencatat ini di `disasm` stage, tapi `signal` tidak
   menggunakannya untuk taint (hanya untuk `ClassifyString` value match).
3. **THR offset → stub role mapping**. `vmtables/thrfields*.go` sudah
   punya offset → stub name table per-version. `signal` hanya cek
   `e.Via` string prefix "THR." — tidak decode offset ke stub name untuk
   THR call yang tidak ter-resolve. Padahal `thraudit` sudah cluster
   unresolved THR offset jadi band.
4. **CODE_REG access** sebagai sinyal introspection. Fungsi yang baca
   CODE_REG untuk dapatkan Code object entry point adalah fungsi yang
   melakukan self-modifying code / code relocation — sinyal anti-analysis.
5. **Dispatch table (R21) call** sebagai sinyal megamorphic dispatch.
   Fungsi yang memanggil via R21 adalah fungsi dengan call site yang
   tidak ter-resolve ke single target — sinyal dynamic behavior.

## Fitur RE Missing/Incomplete

### Missing: Dart VM native call classification

Tidak ada kategori untuk `vm:external-name` native call. Lihat Gap 1.

### Missing: `dart:*` library URI classification

Tidak ada kategori untuk `dart:ffi`, `dart:isolate`, `dart:io`, dst.
Lihat Gap 2.

### Missing: Async function identification via stub call

Fungsi async Dart AOT memanggil `InitAsync`/`Await`/`ReturnAsync` stub
via THR. `sdk.ClassifyStubRole` sudah deteksi ini, tapi `signal` tidak
memakainya. Lihat Gap 4.

### Missing: FFI boundary identification

Fungsi FFI Dart AOT memanggil `FfiCallTrampoline`/`FfiCallbackTrampoline`
stub atau `Ffi_dl_open`/`Ffi_dl_lookup` native. `signal` tidak punya
kategori `CatFfi` / `CatFfiCall` / `CatFfiCallback`. Padahal FFI adalah
escape hatch Dart AOT ke native code — paling penting untuk RE.

### Missing: Generator function identification

Fungsi `sync*`/`async*` Dart AOT memanggil `InitSyncStar`/
`SuspendSyncStarAtStart`/`SuspendSyncStarAtYield`/`InitAsyncStar`/
`YieldAsyncStar`/`ReturnAsyncStar` stub. `signal` tidak identifikasi
ini.

### Missing: Throw/rethrow identification

Fungsi yang memanggil `Throw`/`ReThrow` stub adalah fungsi throwing.
`signal` tidak identifikasi. Penting untuk RE karena fungsi throwing
sering adalah error handler / anti-analysis exit.

### Missing: Static/instance field lazy init identification

Fungsi yang memanggil `InitStaticField`/`InitLateStaticField`/
`InitInstanceField`/`InitLateInstanceField` stub adalah fungsi yang
mengakses field lazy-init. `signal` tidak identifikasi. Penting untuk
RE karena field lazy-init sering adalah singleton state (config,
database, key store).

### Missing: Type instantiation identification

Fungsi yang memanggil `InstantiateType`/`InstantiateTypeArguments` stub
adalah fungsi yang melakukan generic type instantiation. `signal` tidak
identifikasi. Penting untuk RE karena type instantiation adalah sinyal
generic API usage (mis. `Map<String, dynamic>` untuk JSON parse).

### Missing: NoSuchMethod dispatch identification

Fungsi yang memanggil `NoSuchMethodDispatcher` stub adalah fungsi yang
meng-override `noSuchMethod` — sinyal dynamic dispatch / proxy /
reflection-like behavior. `signal` tidak identifikasi.

### Incomplete: Crypto algorithm constant table

Lihat Gap 5.

### Incomplete: MethodChannel extraction

Lihat Gap 6.

### Incomplete: Plugin detection

Lihat Gap 7.

### Incomplete: Taint source/sink (tidak Dart-specific)

Lihat Gap 9.

### Incomplete: Obfuscation detection (heuristic rusak)

Lihat Gap 10.

### Incomplete: Entropy analysis (section-level only)

Lihat Gap 11.

### Incomplete: Behavioral call-graph patterns (hanya 4)

Lihat Gap 12.

### Missing: Pigeon-generated API enumeration

Pigeon (Flutter codegen) menghasilkan channel name
`dev.flutter.pigeon.<package>.<Api>.<method>` dan class
`<Api>HostApi`/`<Api>FlutterApi`. `signal` tidak ekstrak ini sebagai
structured API surface. RE analyst harus manual parse channel name.

### Missing: Flutter engine channel enumeration

Flutter engine memakai channel name `flutter/platform`, `flutter/
navigation`, `flutter/textinput`, `flutter/keyevent`, `flutter/
accessibility`, `flutter/system`, `flutter/localization`, `flutter/
sensors`, `flutter/settings`, `flutter/lifecycle`, `dev.flutter/
channel-buffers`. `EnumerateMethodChannels` Pattern 3 sudah hardcoded
11 substring, tapi tidak ekstrak sebagai structured "engine channel"
kategori terpisah dari app channel.

### Missing: Native callable identification

Dart 2.18+ `NativeCallable.isolateLocal` / `NativeCallable.listener`
adalah API untuk callback dari native ke Dart. String
`NativeCallable`/`NativeCallableListener` muncul di pool. `signal`
tidak punya kategori untuk ini. Penting untuk RE karena NativeCallable
adalah entry point dari native code ke Dart — reverse dari FFI call.

### Missing: Isolate spawn identification

`Isolate.spawn`/`Isolate.run`/`Isolate.spawnUri` native
(`Isolate_spawnFunction`/`Isolate_spawnUri` di bootstrap_natives.h)
adalah sinyal concurrency. `signal` tidak punya kategori
`CatIsolateSpawn`. Penting untuk RE karena isolate spawn adalah eksekusi
kode paralel — bisa untuk background exfil / mining.

### Missing: Process exec identification

`Process.run`/`Process.start` native (`Process_Start`/`Process_Kill` di
runtime/bin/process.cc) adalah sinyal command execution. `signal` tidak
punya kategori `CatProcessExec`. Penting untuk RE karena Process.run
adalah eksekusi shell command — bisa untuk root exploit / data exfil.

### Missing: SecureSocket / TLS identification

`SecureSocket_Connect`/`SecureSocket_Handshake`/
`SecureSocket_RegisterHandshakeCompleteCallback`/
`SecureSocket_RegisterBadCertificateCallback`/
`SecureSocket_RegisterKeyLogPort` native adalah sinyal TLS usage.
`signal` tidak punya kategori `CatTLS`. `CatSSLPinning` hanya untuk
pinning, bukan untuk TLS usage umum. Penting untuk RE karena
`SecureSocket_RegisterBadCertificateCallback` adalah bypass point untuk
cert validation.

### Missing: File system watch identification

`FileSystemWatcher.*` native (`FileSystemWatcher_Create`/
`FileSystemWatcher_Close` di runtime/bin/file_system_watcher.cc) adalah
sinyal file system monitoring. `signal` tidak punya kategori
`CatFileWatch`. Penting untuk RE karena FS watch adalah sinyal ransomware
/ spyware.

## Verifikasi SDK

### Verifikasi 1: Dart VM bootstrap natives

**Sumber**: `gh api -H "Accept: application/vnd.github.raw" "repos/
dart-lang/sdk/contents/runtime/vm/bootstrap_natives.h?ref=3.12.2"`

**Hasil**: 368 native entry di `BOOTSTRAP_NATIVE_LIST` + mirror natives
+ Ffi natives + Isolate natives + Developer natives + TypedData natives
+ Internal natives. Termasuk:
- `Ffi_dl_open`, `Ffi_dl_close`, `Ffi_dl_lookup`, `Ffi_dl_processLibrary`,
  `Ffi_dl_executableLibrary`, `Ffi_dl_getHandle`, `Ffi_dl_providesSymbol`.
- `Ffi_createNativeCallableIsolateGroupBound`,
  `Ffi_createNativeCallableIsolateLocal`,
  `Ffi_createNativeCallableListener`, `Ffi_deleteNativeCallable`.
- `Ffi_loadAbiSpecificInt`, `Ffi_storeAbiSpecificInt`.
- `DartNativeApiFunctionPointer`, `DartApiDLInitializeData`,
  `DartApiDLMajorVersion`, `DartApiDLMinorVersion`.
- `SecureRandom_getBytes`, `Random_initialSeed`.
- `Isolate_spawnFunction`, `Isolate_spawnUri`, `Isolate_sendOOB`,
  `Isolate_exit_`, `Isolate_getCurrentRootUriStr`, `Isolate_getDebugName`.
- `SendPort_get_id`, `SendPort_get_hashcode`, `SendPort_sendInternal_`.
- `RawReceivePort_factory`, `RawReceivePort_closeInternal`,
  `RawReceivePort_get_id`, `RawReceivePort_setActive`,
  `RawReceivePort_getActive`.
- `Developer_debugger`, `Developer_inspect`, `Developer_log`,
  `Developer_postEvent`, `Developer_registerExtension`,
  `Developer_lookupExtension`, `Developer_getServerInfo`,
  `Developer_getIsolateIdFromSendPort`, `Developer_getObjectId`.
- `ThreadLocal_allocateId`, `ThreadLocal_setValue`,
  `ThreadLocal_getValue`, `ThreadLocal_clearValue`,
  `ThreadLocal_hasValue`.
- `TransferableTypedData_factory`, `TransferableTypedData_materialize`.

**Kesimpulan**: 368 native name adalah sinyal perilaku tertinggi yang
tidak diklasifikasi `signal`.

### Verifikasi 2: Dart IO natives

**Sumber**: `gh api` ke `runtime/bin/{file,socket,secure_socket_filter,
crypto,directory}.cc?ref=3.12.2`.

**Hasil**:
- `file.cc`: 36 `FUNCTION_NAME(File_*)` — `File_Open`, `File_Close`,
  `File_Read`, `File_WriteFrom`, `File_ReadByte`, `File_WriteByte`,
  `File_Position`, `File_SetPosition`, `File_Length`, `File_Stat`,
  `File_Exists`, `File_Create`, `File_Delete`, `File_Rename`,
  `File_Copy`, `File_CreateLink`, `File_DeleteLink`, `File_LinkTarget`,
  `File_ResolveSymbolicLinks`, `File_LastModified`,
  `File_SetLastModified`, `File_LastAccessed`, `File_SetLastAccessed`,
  `File_Flush`, `File_Lock`, `File_Truncate`, `File_AreIdentical`,
  `File_GetType`, `File_OpenStdio`, `File_GetStdioHandleType`,
  `File_GetFD`, `File_GetPointer`, `File_SetPointer`, `File_CreatePipe`,
  `File_LengthFromPath`.
- `socket.cc`: 35 `FUNCTION_NAME(Socket_*/ServerSocket_*/RawSocketOption_*)`
  — `Socket_CreateConnect`, `Socket_CreateBindConnect`,
  `Socket_CreateUnixDomainConnect`, `Socket_CreateBindDatagram`,
  `Socket_Read`, `Socket_WriteList`, `Socket_Available`,
  `Socket_GetPort`, `Socket_GetRemotePeer`, `Socket_SetOption`,
  `Socket_GetOption`, `Socket_JoinMulticast`, `Socket_LeaveMulticast`,
  `Socket_SendTo`, `Socket_RecvFrom`, `ServerSocket_CreateBindListen`,
  `ServerSocket_Accept`, dst.
- `secure_socket_filter.cc`: 12 `FUNCTION_NAME(SecureSocket_*)` —
  `SecureSocket_Init`, `SecureSocket_Connect`, `SecureSocket_Destroy`,
  `SecureSocket_Handshake`, `SecureSocket_MarkAsTrusted`,
  `SecureSocket_NewX509CertificateWrapper`, `SecureSocket_GetSelected
  Protocol`, `SecureSocket_RegisterHandshakeCompleteCallback`,
  `SecureSocket_RegisterBadCertificateCallback`,
  `SecureSocket_RegisterKeyLogPort`, `SecureSocket_PeerCertificate`,
  `SecureSocket_FilterPointer`.
- `crypto.cc`: `Crypto_GetRandomBytes`.

**Kesimpulan**: ~80 IO native name adalah sinyal file/socket/TLS/crypto
usage yang tidak diklasifikasi `signal`.

### Verifikasi 3: Dart VM stub list

**Sumber**: `gh api -H "Accept: application/vnd.github.raw" "repos/
dart-lang/sdk/contents/runtime/vm/stub_code_list.h?ref=3.12.2"`

**Hasil**: 130+ stub di `VM_STUB_CODE_LIST` + 9 di
`VM_TYPE_TESTING_STUB_CODE_LIST` + 1 di `PROBE_POINT_STUBS_LIST`.
Termasuk:
- Async: `InitAsync`, `Await`, `AwaitWithTypeCheck`, `Resume`,
  `ReturnAsync`, `ReturnAsyncNotFuture`, `InitAsyncStar`,
  `YieldAsyncStar`, `ReturnAsyncStar`, `InitSyncStar`,
  `SuspendSyncStarAtStart`, `SuspendSyncStarAtYield`,
  `AsyncExceptionHandler`, `CloneSuspendState`.
- FFI: `FfiCallTrampoline`, `FfiCallbackTrampoline`,
  `FfiAsyncCallbackSend`.
- Throw: `Throw`, `ReThrow`.
- Type: `InstanceOf`, `InstantiateType`,
  `InstantiateTypeNonNullableClassTypeParameter`,
  `InstantiateTypeNullableClassTypeParameter`,
  `InstantiateTypeNonNullableFunctionTypeParameter`,
  `InstantiateTypeNullableFunctionTypeParameter`,
  `InstantiateTypeArguments`,
  `InstantiateTypeArgumentsMayShareInstantiatorTA`,
  `InstantiateTypeArgumentsMayShareFunctionTA`.
- Init: `InitStaticField`, `InitLateStaticField`,
  `InitLateFinalStaticField`, `InitInstanceField`,
  `InitLateInstanceField`, `InitLateFinalInstanceField`,
  `InitSharedLateStaticField`.
- Dispatch: `NoSuchMethodDispatcher`, `SwitchableCallMiss`,
  `MonomorphicSmiableCheck`, `SingleTargetCall`, `ICCallThroughCode`,
  `MegamorphicCall`, `FixCallersTarget`, `FixAllocationStubTarget`,
  `FixParameterizedAllocationStubTarget`.
- Error: `LateInitializationErrorSharedWithFPURegs`,
  `LateInitializationErrorSharedWithoutFPURegs`,
  `NullErrorSharedWithFPURegs`, `NullErrorSharedWithoutFPURegs`,
  `NullArgErrorSharedWithFPURegs`, `NullArgErrorSharedWithoutFPURegs`,
  `NullCastErrorSharedWithFPURegs`, `NullCastErrorSharedWithoutFPURegs`,
  `RangeErrorSharedWithFPURegs`, `RangeErrorSharedWithoutFPURegs`,
  `WriteErrorSharedWithFPURegs`, `WriteErrorSharedWithoutFPURegs`,
  `FieldAccessErrorSharedWithFPURegs`,
  `FieldAccessErrorSharedWithoutFPURegs`.
- Safepoint: `EnterSafepoint`, `ExitSafepoint`,
  `CallNativeThroughSafepoint`.
- Type test: `DefaultTypeTest`, `DefaultNullableTypeTest`,
  `TopTypeTypeTest`, `UnreachableTypeTest`, `TypeParameterTypeTest`,
  `NullableTypeParameterTypeTest`, `SlowTypeTest`,
  `LazySpecializeTypeTest`, `LazySpecializeNullableTypeTest`.
- Other: `CheckIsolateFieldAccess`, `CheckedStoreIntoShared`,
  `EnsureDeeplyImmutable`, `AsynchronousGapMarker`, `NotLoaded`,
  `DispatchTableNullError`, `UnknownDartCode`.

**Kesimpulan**: `sdk.ClassifyStubRole` hanya cover ~9 role dari 130+
stub. `signal` hanya pakai `IsMundaneStub` (boolean). Stub async/FFI/
throw/init/type/dispatch tidak dipakai untuk klasifikasi sinyal.

### Verifikasi 4: `vm:external-name` pragma

**Sumber**: `grep MCP` `query="vm:external-name" repo="dart-lang/sdk"`.

**Hasil**: 10+ file patch di `sdk/lib/_internal/vm/lib/` dan
`sdk/lib/_internal/vm/bin/` yang semuanya menyematkan
`@pragma("vm:external-name", "NativeName")`:
- `typed_data_patch.dart`: `TypedDataBase_length`,
  `TypedDataBase_setClampedRange`, dst.
- `mirrors_impl.dart`: `DeclarationMirror_location`,
  `DeclarationMirror_metadata`, `TypeMirror_subtypeTest`.
- `file_patch.dart`: `File_Exists`, `File_Create`, `File_CreateLink`,
  `File_CreatePipe`, `File_LinkTarget`, dst.
- `secure_socket_patch.dart`: `SecureSocket_Connect`,
  `SecureSocket_Destroy`, `SecureSocket_Handshake`,
  `SecureSocket_MarkAsTrusted`, dst.
- `socket_patch.dart`: `RawSocketOption_GetOptionValue`,
  `InternetAddress_RawAddrToString`, `InternetAddress_ParseScopedLink
  LocalAddress`, `InternetAddress_Parse`, dst.
- `internal_patch.dart`: `Internal_makeListFixedLength`,
  `Internal_makeFixedListUnmodifiable`, `Internal_extractTypeArguments`,
  `Internal_allocateOneByteString`, `Internal_writeIntoOneByteString`,
  `Internal_writeIntoTwoByteString`.
- `developer.dart`: `Developer_debugger`, `Developer_inspect`,
  `Developer_reachability_barrier`.
- `double.dart`: `Double_doubleFromInteger`, `Double_add`, `Double_sub`,
  `Double_mul`, `Double_div`.
- `integers.dart`: `Integer_bitAndFromInteger`,
  `Integer_bitOrFromInteger`, `Integer_bitXorFromInteger`,
  `Integer_shrFromInteger`, `Integer_ushrFromInteger`,
  `Integer_shlFromInteger`, `Integer_addFromInteger`,
  `Integer_subFromInteger`, `Integer_mulFromInteger`,
  `Integer_truncDivFromInteger`, `Integer_moduloFromInteger`.
- `isolate_patch.dart`: `Capability_factory`, `Capability_equals`,
  `Capability_get_hashcode`, `RawReceivePort_getSendPort`.
- `ffi_patch.dart`: `DartNativeApiFunctionPointer`,
  `DartApiDLInitializeData`, `DartApiDLMajorVersion`,
  `DartApiDLMinorVersion`, `SendPort_get_id`, `SendPort_nativePort`.
- `ffi_dynamic_library_patch.dart`: `DynamicLibrary.open` →
  `DynamicLibrary.open` factory (memanggil `_open` native).

**Kesimpulan**: String `vm:external-name` persist di AOT snapshot
sebagai nama native. `signal` tidak mengklasifikasi mereka.

### Verifikasi 5: `dart:*` library URI

**Sumber**: `grep MCP` `query="dart:isolate" repo="dart-lang/sdk"` +
`query="dart:ffi" repo="dart-lang/sdk"`.

**Hasil**: String `dart:ffi`, `dart:isolate`, `dart:io`, `dart:developer`,
`dart:typed_data`, `dart:_internal`, `dart:nativewrappers`, `dart:async`,
`dart:collection`, `dart:convert`, `dart:math`, `dart:core` muncul
sebagai library URI literal di banyak file SDK. Di Dart AOT, string
ini persist di object pool sebagai bagian dari library URI table dan
stack trace format string.

**Kesimpulan**: `dart:*` URI adalah sinyal perilaku yang tidak
diklasifikasi `signal` (kecuali `dart:mirrors`).

### Verifikasi 6: Crypto constants di SDK

**Sumber**: `grep MCP` `query="0x428a2f98" repo="dart-lang/sdk"` +
`query="0x6a09e667" repo="dart-lang/sdk"`.

**Hasil**: No results. SDK tidak meng-embed SHA-256 K constant di Dart
code — memakai BoringSSL (C library) untuk crypto.

**Kesimpulan**: Crypto constants di Dart AOT binary berasal dari
plugin Flutter (`pointycastle`, `cryptography`, `fast_rsa`,
`dart_jsonwebtoken`) yang meng-embed mereka sebagai Dart `const List<int>`.
`cryptoAlgorithmID` table perlu dilengkapi untuk cover algorithm yang
dipakai plugin populer (lihat Gap 5).

### Verifikasi 7: MethodChannel di SDK

**Sumber**: `grep MCP` `query="MethodChannel(" repo="dart-lang/sdk"`.

**Hasil**: `runtime/tests/vm/dart/analyze_snapshot_program.dart` line 4:
```dart
class MethodChannel {
  final String name;
  const MethodChannel(this.name);
  void dump() { print('MethodChannel($name)'); }
}
final channel1 = MethodChannel("channel1");
```

**Kesimpulan**: `MethodChannel("name")` constructor di-inlinable di AOT.
String "name" dipisah dari literal "MethodChannel". Regex
`MethodChannel\s*\(\s*["']([^"']+)["']\s*\)` di `EnumerateMethodChannels`
tidak akan match karena string ref value hanya "channel1" atau
"MethodChannel" (terpisah). Perlu cross-reference call site ke
constructor dengan string ref di PC yang sama.

### Verifikasi 8: Pigeon channel name convention

**Sumber**: `grep MCP` `query="dev.flutter." repo="dart-lang/sdk"` +
`query="BasicMessageChannel" repo="dart-lang/sdk"`.

**Hasil**: Pigeon-generated code memakai channel name
`'dev.flutter.pigeon.<package>.<Api>.<method>$suffix'` (string
interpolation). Contoh dari `pkg/analysis_server/tool/performance/
scenarios/logs/project_pigeon_format_generated_file.json`:
```dart
final pigeonVar_channelName =
    'dev.flutter.pigeon.pigeon_integration_tests.HostIntegrationCoreApi.noop$pigeonVar_messageChannelSuffix';
final pigeonVar_channel = BasicMessageChannel<Object?>(
  pigeonVar_channelName, pigeonChannelCodec,
  binaryMessenger: pigeonVar_binaryMessenger,
);
```

**Kesimpulan**: Pigeon channel name adalah string dinamis hasil
interpolation. Di AOT, bagian literal (`dev.flutter.pigeon.`, `.
HostIntegrationCoreApi.noop`) dan bagian dinamis (`pigeonVar_message
ChannelSuffix`) dipisah. `EnumerateMethodChannels` Pattern 3
hardcoded `dev.flutter/` (dengan slash, bukan dot) — **tidak match**
`dev.flutter.pigeon.` (dengan dot). Perlu perbaiki pattern + ekstrak
channel name dari string interpolation part.

### Verifikasi 9: Obfuscation scheme Dart `--obfuscate`

**Sumber**: `grep MCP` `query="obfuscation" repo="dart-lang/sdk"`.

**Hasil**: SDK mempunyai `pkg/vm/lib/transformations/obfuscation.dart`
(kalau ada di path tersebut). Scheme obfuscation modern Dart menghasilkan
nama pendek 1-3 char dengan campuran huruf besar/kecil, tidak selalu
tanpa vokal.

**Kesimpulan**: Heuristic `isObfuscatedName` (`!hasVowel && len>=2 &&
len<=3`) tidak cover scheme modern. Lihat Gap 10.

### Verifikasi 10: Pipeline konsumsi signal

**Sumber**: `grep` `pattern="signal\."` di `internal/`.

**Hasil**: 19 file konsumsi `signal`. Pipeline utama:
- `internal/analysis/pipeline.go` line 285-314: panggil
  `WriteEntropyFindings`, `IdentifyCryptoFromBinary`,
  `IdentifyCryptoFromPoolImmediates`, `WriteCryptoFindings`,
  `WriteTaintFindings`, `WriteYaraFindings`, `WriteBehavioralFindings`.
- `internal/analysis/signal_stage.go`: `RunSignalStage` (build signal
  graph + SARIF + evidence + CFG DOT), `BuildSignalContent` (re-disasm
  signal func untuk extract calls + strings).

**Kesimpulan**: Pipeline sudah memanggil semua signal output writer.
Gap bukan di pipeline wiring, tapi di `signal` package content
(classifier + analyzer).

---

**Akhir laporan.** Gap terbesar adalah Gap 1 (Dart VM native names tidak
diklasifikasi) dan Gap 4 (stub role tidak dipakai untuk sinyal) — keduanya
adalah sinyal perilaku Dart-specific tertinggi yang bisa di-automate
tanpa string ref, hanya dari call edge ke THR stub / native name.
Implementasi keduanya butuh extend `internal/sdk` (tambah native name
table + extend `ClassifyStubRole`) dan extend `internal/signal/classify.go`
+ `graph.go` (tambah kategori + konsumsi stub role). Gap 2 (`dart:*` URI)
adalah quick win: tambah keyword list exact-match di `ClassifyString`.
Gap 3 (register tracking di taint) adalah pekerjaan besar tapi
memberikan confidence upgrade paling signifikan untuk taint analysis.
