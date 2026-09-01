# RE Gap Analysis Report: internal/ffitrace

> **STATUS VERIFIKASI (2026-09-01)** — Gap 1 **CONFIRMED di tingkat SDK**.
> Detail: `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> `gh api runtime/vm/compiler/backend/il_arm64.cc?ref=3.12.2`: cabang
> `is_leaf_` menulis `vm_tag` di dalam `#if !defined(PRODUCT)` (baris
> 1422-1428 dan 1447-1451); cabang non-leaf memakai
> `ldr temp1,[THR, call_native_through_safepoint_entry_point_offset]; blr temp1`
> — transisi `vm_tag` terjadi di dalam stub, bukan di badan fungsi app.
>
> **Tambahan (report menyebut premisnya di bullet ke-3 Gap 1, tapi tidak
> menarik kesimpulannya):** `TransitionGeneratedToNative`
> (`assembler_arm64.cc:1663-1677`) menulis `vm_tag` **tanpa guard PRODUCT**,
> dan dipanggil dari badan fungsi app di `il_arm64.cc:1559` — jalur
> `NativeReturn` / FFI **callback** trampoline. Artinya di build release signal
> 2 tetap bisa menyala, tapi yang ditandainya adalah **batas FFI callback
> (Dart dipanggil dari C)**, bukan "fungsi Dart yang melakukan FFI call"
> seperti label `Kind: "native_call_site"` menyiratkan. Jadi ini **salah
> label**, bukan sekadar false-negative.

## Ringkasan

Folder `internal/ffitrace/` hanya berisi **2 file** (`ffitrace.go` 227 baris + `ffitrace_test.go` 176 baris) — paket terkecil di AOTopsy. Tugasnya: melacak dart:ffi usage di Dart AOT binary (libapp.so) secara statis, tanpa emulasi CPU. Implementasi saat ini menjalankan **2 detektor** per fungsi:

1. **Signal 1 (`findDynamicLibraryCalls`)** — scan direct call ke simbol bernama `DynamicLibrary.*` / `*lookupFunction*`, pasangkan dengan literal string pool terdekat di basic block yang sama (library path / symbol name).
2. **Signal 2 (FFICallMarker scan)** — jalankan `decompiler.EmitPseudocode` lalu cari string `"ffi_call("` di output (marker yang decompiler emit ketika register target call baru saja di-store ke `Thread.vm_tag`).

Analisis terhadap Dart SDK source (`dart-lang/sdk` @3.12.2, diverifikasi via `gh api` + grep MCP `searchGitHub`) menemukan **gap struktural yang sangat signifikan**: **Signal 2 efektif mati untuk production Flutter APK** (PRODUCT build). Penyebabnya:

- `FfiCallInstr::EmitNativeCode` (il_arm64.cc @3.12.2 line 1358) untuk path **leaf** (`is_leaf_=true`) hanya store ke `vm_tag` di bawah `#if !defined(PRODUCT)` (line 1427) — **tidak ada di release build**.
- Path **non-leaf** `FfiCallInstr` tidak store ke `vm_tag` di call site sama sekali; call site hanya `ldr temp1, [THR+CallNativeThroughSafepoint_offset]; blr temp1` (line 1463-1476), dan `vm_tag` store terjadi **di dalam stub** `CallNativeThroughSafepoint` (di VM snapshot libflutter.so, **bukan** di libapp.so yang dianalisis AOTopsy). Decompiler mengenali ini sebagai THR-stub call (`CallNativeThroughSafepoint(...)`) — **bukan** `ffi_call(` — sehingga ffitrace signal 2 miss.
- Hanya `LeafRuntimeCallInstr::EmitNativeCode` (line 1728-1732, path `@FfiNative`/`@Native` annotation dengan IsLeaf) yang store ke `vm_tag` di PRODUCT build — tetapi ini adalah subset FFI yang lebih jarang daripada pola umum `DynamicLibrary.open().lookupFunction()`.

Akibatnya, untuk real-world Flutter release APK, ffitrace hanya menemukan **lookup call site** (Signal 1) tetapi **miss seluruh actual FFI native call** (`FfiCallInstr`) — baik leaf maupun non-leaf. Ini adalah gap RE paling kritis: RE analyst kehilangan "fungsi Dart mana yang benar-benar melakukan FFI call ke native code, dengan berapa argumen, signature apa".

Gap lain: ffitrace **sama sekali tidak menggunakan** `FfiTrampolineData` snapshot metadata yang sudah di-decode oleh `internal/cluster` (`cluster.FfiTrampolineInfo` dengan `CSignatureRef`, `CallbackTargetRef`, `FfiFunctionKind`, `CallbackID`) dan sudah di-build menjadi `analysis.FfiBridgeRecord` oleh `analysis.BuildFfiBridges`. Metadata ini berisi **C-side signature** dan **callback target** yang bisa menghubungkan call site ke signature native — tetapi ffitrace tidak mengkorrelasikannya.

## Struktur Folder

- **`ffitrace.go`** (227 baris) — seluruh logika paket:
  - `Finding` struct (line 24): satu observasi FFI; field `Kind` = `"dynamic_library_call"` | `"native_call_site"`.
  - `Options` struct (line 52): `MaxScan` (default 500), `AllowUnbounded`, `Filter`.
  - `Trace` (line 98): loop utama per-CodeRange, gated by scan bound; GOMAXPROCS=2 + memory limit 1536MB backstop; panggil `findDynamicLibraryCalls` + `EmitPseudocode` scan.
  - `findDynamicLibraryCalls` (line 160): per-basic-block scan, track `OpLoadPool` literal terdekat, match `OpCall` target ke `SymbolNames`/pre-resolved name via `looksLikeFfiOpenOrLookup`.
  - `looksLikeFfiOpenOrLookup` (line 224): substring match `"dynamiclibrary"` OR `"lookupfunction"` (case-insensitive).
- **`ffitrace_test.go`** (176 baris) — 5 test: literal-arg resolution happy path, unresolved negative, indirect/unrelated ignore, default bound limit, AllowUnbounded, MaxScan override. Synthetic context dengan bare `ret` functions.

## Gap Analysis

### Gap 1: Signal 2 (`ffi_call(` marker) efektif mati di PRODUCT build — miss seluruh `FfiCallInstr` leaf & non-leaf

- **Deskripsi**: ffitrace signal 2 memindai output `EmitPseudocode` untuk `decompiler.FFICallMarker` = `"ffi_call("`. Marker ini hanya di-emit oleh `emitIndirectCall` (call.go line 289-298) ketika register target baru saja di-store ke `Thread.vm_tag` (deteksi via `applyStore` di lift.go line 922-933, mengecek `ThreadFieldNames[disp] == "vm_tag"`). Namun di SDK source, store ke `vm_tag` di app code (libapp.so) hanya terjadi untuk:
  - `FfiCallInstr` `is_leaf_=true` di bawah `#if !defined(PRODUCT)` (il_arm64.cc @3.12.2 line 1427) — **tidak ada di release**.
  - `LeafRuntimeCallInstr` (`@FfiNative` leaf) di PRODUCT (line 1728) — **ada**, tetapi ini path annotation-based yang lebih jarang.
  - `NativeEntryInstr`/`NativeReturnInstr` (callback entry/return) — ini adalah callback trampoline, bukan outbound FFI call.

  Path `FfiCallInstr` non-leaf (pola `DynamicLibrary.open().lookupFunction().call()` yang paling umum) melakukan `ldr temp1, [THR+CallNativeThroughSafepoint_entry_point_offset]; blr temp1` (line 1463-1476) — decompiler mengenali ini sebagai THR-stub call dan emit `CallNativeThroughSafepoint(...)` (call.go line 340), **bukan** `ffi_call(`. ffitrace tidak memindai marker ini.

- **Bukti SDK**:
  - `gh api repos/dart-lang/sdk/contents/runtime/vm/compiler/backend/il_arm64.cc?ref=3.12.2` line 1358-1445: `FfiCallInstr::EmitNativeCode`, path `is_leaf_` vm_tag store di `#if !defined(PRODUCT)` (line 1427).
  - Line 1463-1476: path non-leaf `ldr temp1, [THR, call_native_through_safepoint_entry_point_offset()]; blr(temp1)` — tidak ada vm_tag store di call site.
  - Line 1728-1732: `LeafRuntimeCallInstr::EmitNativeCode` — `str(target_address, [THR, vm_tag_offset]); CallCFunction(target_address)` — **tidak** di-guard `#if !defined(PRODUCT)`.
  - AOTopsy `internal/vmtables/threadstubs.go` line 61: `0x268: "CallNativeThroughSafepoint"` ada di table (3.7.0 ARM64) — decompiler pasti resolve stub ini.
  - AOTopsy `internal/decompiler/call.go` line 312-341: THR-stub load → emit `CallNativeThroughSafepoint(...)`, **bukan** `FFICallMarker`.
  - AOTopsy `internal/decompiler/lift.go` line 922-933: `applyStore` hanya set `ffiCallTargetSentinel` ketika `ThreadFieldNames[disp] == "vm_tag"`.

- **Dampak**: **Kritis**. Untuk production Flutter APK (PRODUCT build), ffitrace **miss 100%** dari `FfiCallInstr` leaf (pola `isLeaf: true` via `lookupFunction`) dan **100%** dari `FfiCallInstr` non-leaf (pola default `lookupFunction`). Hanya `LeafRuntimeCallInstr` (`@FfiNative`) yang tertangkap. RE analyst tidak mendapat daftar "fungsi Dart yang melakukan FFI call ke native" — yang adalah output utama yang dijanjikan paket ini ("which functions call out to a native library").

- **Usulan**:
  1. Tambah detektor signal 3: scan pseudocode untuk `CallNativeThroughSafepoint(` (THR-stub call yang sudah di-resolve decompiler) — ini adalah **non-leaf FfiCallInstr** di PRODUCT. Tambah `Kind: "native_call_site"` dengan sub-classifikasi `via: "call_native_through_safepoint"`.
  2. Tambah detektor signal 4 untuk leaf FFI: deteksi pola structural `mov temp_csp, CSP; mov CSP, SP; blr <branch>; mov SP, CSP; mov CSP, temp_csp` (il_arm64.cc line 1429-1445, `FfiCallInstr` is_leaf_ PRODUCT path) — ini adalah signature unik leaf-FFI yang tidak punya vm_tag store. Butuh lift-level tracking pola CSP↔SP swap di sekitar `blr`.
  3. Tambah detektor signal 5 untuk `LeafRuntimeCallInstr`: pola `EnterCFrame; mov saved_csp, CSP; mov CSP, SP; ...; str target, [THR, vm_tag]; CallCFunction target; str kDartTagId, [THR, vm_tag]; mov CSP, saved_csp; LeaveCFrame` (line 1714-1739). `CallCFunction` di ARM64 adalah `blr` — vm_tag store di sini sudah ditangkap signal 2 yang ada, tetapi anotasi kind-nya (`@FfiNative` leaf vs regular FFI) tidak dibedakan.

- **Prioritas**: **P0 — kritis**. Ini adalah gap fungsional inti paket: janji "trace FFI call boundary" tidak terpenuhi untuk release build.

### Gap 2: Tidak ada korelasi dengan `FfiTrampolineData` snapshot metadata (C signature, callback target, kind)

- **Deskripsi**: `internal/cluster/ffitrampoline.go` sudah mendefinisikan `FfiTrampolineInfo` dengan field `SignatureTypeRef` (Dart signature), `CSignatureRef` (C-side FunctionType), `CallbackTargetRef` (Dart method untuk callback), `CallbackExceptionalReturnRef`, `CallbackID`, `FfiFunctionKind` (Sync/Async/Leaf/Callback). `internal/analysis/ffi_bridges.go` sudah membangun `FfiBridgeRecord` dengan resolved `DartSignature`, `CSignature`, `CallbackTarget`. **ffitrace sama sekali tidak mengakses `ctx.Result.FfiTrampolines` atau `BuildFfiBridges`** (diverifikasi: `grep FfiTrampoline FfiBridge BuildFfiBridges` di `internal/ffitrace/*.go` → 0 hit).

  Metadata ini adalah satu-satunya sumber **C-side signature** (`c_signature_` field, `FunctionTypePtr`) di snapshot — tanpa itu, ffitrace tidak bisa memberitahu RE analyst "FFI call ini memanggil `int32_t Function(uint8_t*, uint32_t)`". Saat ini ffitrace hanya memberi symbol name string literal (jika ada) dan arg count dari pseudocode text parsing (`countArgs`), yang tidak reliable untuk typed FFI.

- **Bukti SDK**:
  - `gh api repos/dart-lang/sdk/contents/runtime/vm/raw_object.h?ref=3.12.2` line 1672-1701: `UntaggedFfiTrampolineData` punya field `signature_type_` (TypePtr), `c_signature_` (FunctionTypePtr), `callback_target_` (FunctionPtr), `callback_exceptional_return_` (InstancePtr), `callback_id_` (int32_t), `ffi_function_kind_` (uint8_t).
  - `grep MCP searchGitHub repo:dart-lang/sdk "FfiTrampolineData"` → `raw_object_fields.cc` line 203-206: `F(FfiTrampolineData, c_signature_)`, `F(FfiTrampolineData, callback_target_)`, `F(FfiTrampolineData, callback_exceptional_return_)`.
  - AOTopsy `internal/cluster/fill_refs.go` line 316-326: `FfiTrampolineInfo` sudah di-populate dari stream dengan ke-4 ref + callback_id + ffi_kind.
  - AOTopsy `internal/analysis/ffi_bridges.go` line 20-49: `BuildFfiBridges` resolve `DartSignature`/`CSignature`/`CallbackTarget` via `naming.PoolLookups`.

- **Dampak**: **Tinggi**. RE analyst kehilangan: (a) C-side type signature FFI call (mis. `Int32 Function(Pointer<Uint8>, Uint32)`), (b) identifikasi native callback (Dart function yang dipanggil dari C via `Pointer.fromFunction`/`NativeCallable`), (c) klasifikasi kind FFI (sync/async/leaf/callback), (d) callback ID untuk korelasi cross-isolate. Ini adalah info RE yang **sudah di-decode** tetapi tidak di-surface oleh ffitrace.

- **Usulan**:
  1. Di `Trace`, build `FfiBridgeRecord` sekali via `analysis.BuildFfiBridges(ctx.Result, ctx.Pool)` dan index by `RefID`.
  2. Cross-reference: untuk setiap `FfiTrampolineData` kind=Callback, resolve `CallbackTargetRef` → Function → Code → VA, dan emit Finding `Kind: "ffi_callback_target"` dengan `CSignature` + `DartSignature` + `CallbackID`.
  3. Untuk FfiCallInstr call site yang tertangkap (setelah fix Gap 1), coba resolve trampoline data terkait via pool entry `kNativeEntryData` (PoolTagged kind=4 di fill_pool.go line 68) yang ref ke FfiTrampolineData — ini menghubungkan call site ke C signature.
  4. Tambah field ke `Finding`: `CSignature string`, `DartSignature string`, `FfiKind string`, `CallbackID int32`, `CallbackTarget string`.

- **Prioritas**: **P0 — kritis**. Ini adalah fitur RE yang datanya sudah ada tetapi tidak diekstrak.

### Gap 3: `PoolNative` entry (kNativeFunction) tidak di-track — native function pointer pool slot tidak diidentifikasi

- **Deskripsi**: Object pool entry kind `kNativeFunction` (typeBits=2) diserialisasi sebagai **nothing** (fill_pool.go line 66, 99: `pe.Kind = PoolNative`, tidak baca data). `naming.ResolvePoolDisplay` (pool.go line 630-776) **tidak punya `case cluster.PoolNative:`** — entry ini tidak dapat entry di `PoolDisplay` map sama sekali. Akibatnya, ketika app code melakukan `ldr xN, [PP, #idx*8]` untuk load native function pointer dari pool, `PoolDisplay[idx]` return `false` dan ffitrace tidak bisa membedakan pool load native-function-pointer dari pool load lainnya.

  Ini signifikan karena `FfiCallInstr` me-load target native function pointer dari pool slot `kNativeFunction` (atau via `NativeFunction` object yang wrap-nya). Mengidentifikasi pool slot `PoolNative` memberi sinyal kuat "basic block ini terkait FFI native call" bahkan tanpa vm_tag detection.

- **Bukti SDK**:
  - `gh api repos/dart-lang/sdk/contents/runtime/vm/raw_object.h?ref=3.12.2`: `UntaggedDynamicLibrary` (line 3608) pakai `VISIT_NOTHING()` — `handle_` (void*) adalah inline data, **bukan** ref, jadi path library tidak di-snapshot. Ini konfirmasi bahwa ffitrace signal 1 (string literal scan) adalah satu-satunya cara recover library path — tetapi native function pointer juga tidak di-snapshot (kNativeFunction → nothing).
  - `grep MCP searchGitHub repo:dart-lang/sdk "kNativeFunction"`: pool entry type `kNativeFunction` resolved at runtime via dlsym, tidak disimpan.
  - AOTopsy `internal/cluster/fill_pool.go` line 66-67, 99-100: `case 2, 3: pe.Kind = PoolNative` — tidak baca data apa pun.
  - AOTopsy `internal/naming/pool.go` line 633-773: switch `pe.Kind` hanya handle `PoolTagged` dan `PoolImmediate` — **tidak ada `case cluster.PoolNative:`**.

- **Dampak**: **Menengah-Tinggi**. ffitrace tidak bisa: (a) identifikasi pool slot mana yang hold native function pointer, (b) memberi anotasi "pool[42] = <native function>" di output, (c) menggunakan keberadaan PoolNative load di basic block sebagai sinyal FFI call site tambahan.

- **Usulan**:
  1. Di `naming.ResolvePoolDisplay`, tambah `case cluster.PoolNative: display[pe.Index] = "<native_function>"` (atau `"<kNativeFunction>"`) sehingga pool load ke slot ini terlihat di pseudocode dan bisa di-scan ffitrace.
  2. Di ffitrace `findDynamicLibraryCalls`, track `OpLoadPool` ke slot `PoolNative` (cek `ctx.Result.Pool[idx].Kind == PoolNative` via `Enrichment.PoolByIndex`) sebagai sinyal "native function pointer load" — emit Finding `Kind: "native_function_pool_load"`.
  3. Pertimbangkan juga `kNativeFunctionWrapper` (typeBits=3, fill_pool.go line 66) yang mungkin wrap NativeFunction + FfiTrampolineData.

- **Prioritas**: **P1 — tinggi**.

### Gap 4: Heuristik literal-arg hanya scan basic block tunggal — miss cross-block & shared-bindings-object indirection

- **Deskripsi**: `findDynamicLibraryCalls` (line 160-222) hanya track `lastPoolLiteral` dalam **satu basic block** yang sama dengan call. Doc comment sendiri (line 83-85) mengakui ini tidak mengikuti "shared-bindings-object indirection" (Komponen H "Trap" note). Pola umum Dart FFI:

  ```dart
  final lib = DynamicLibrary.open("libfoo.so");      // block A: pool load "libfoo.so"
  final fn = lib.lookupFunction<Nf, Df>("symbol");    // block B/C: pool load "symbol"
  ```

  Jika `open` dan `lookupFunction` di basic block berbeda (sangat umum setelah inlining boundary / field cache), literal "libfoo.so" hilang dari scope saat `lookupFunction` call di-scan. Lebih lagi, pattern production:

  ```dart
  class _Bindings {
    static final lib = DynamicLibrary.open("libfoo.so");
    static final fn = lib.lookupFunction<...>("sym");
  }
  ```

  di mana `lib` di-cache ke field statis — `lookupFunction` call site tidak lagi punya literal "libfoo.so" di scope sama sekali (field read, bukan pool load).

- **Bukti SDK**: Pola `DynamicLibrary.open` return `DynamicLibrary` object yang di-cache ke field/variable; `lookupFunction` adalah method call di object tersebut. SDK `runtime/vm/native_api.cc` / `sdk/lib/ffi/ffi_dynamic_library.dart` — `DynamicLibrary.open` adalah native call yang return handle, `lookupFunction` resolve symbol via `dlsym` di runtime. Tidak ada koneksi static antara open dan lookup selain object flow.

- **Dampak**: **Menengah**. Banyak call site `lookupFunction` akan report `Resolved=false` (literal symbol name mungkin tertangkap di block yang sama, tetapi library path sering miss). RE analyst tidak mendapat pasangan (library, symbol) yang lengkap.

- **Usulan**:
  1. Cross-block literal tracking: extend scan ke predecessor block dalam fungsi yang sama (limited backward slice) untuk find literal pool load yang flow ke call site.
  2. Field-cache tracking: ketika `DynamicLibrary.open(...)` result di-store ke field (static atau instance), track field offset → record (field offset, library path). Saat `lookupFunction` di-call pada object loaded dari field tersebut, recover library path dari map.
  3. Cross-function: jika `open` ada di fungsi lain (lazy static initializer), gunakan `SymbolNames` + field offset untuk korelasi.
  4. Tambah field `LibraryPath string` dan `SymbolName string` terpisah di `Finding` (saat ini hanya `LiteralArg` tunggal yang ambigu antara path vs symbol).

- **Prioritas**: **P1 — tinggi**.

### Gap 5: `looksLikeFfiOpenOrLookup` terlalu sempit — miss `NativeCallable`, `Pointer.fromFunction`, `DynamicLibrary.process`, `@Native`, `@FfiNative`

- **Deskripsi**: `looksLikeFfiOpenOrLookup` (line 224-227) hanya match substring `"dynamiclibrary"` OR `"lookupfunction"`. Ini miss:
  - `NativeCallable<T>.isolateLocal` / `NativeCallable.listener` (Dart 2.18+ callback registration, menggantikan `Pointer.fromFunction` di Dart 3.x).
  - `Pointer.fromFunction` (legacy callback, masih ada di banyak app).
  - `DynamicLibrary.process()` / `DynamicLibrary.executable()` (lookup di process image sendiri — pola umum untuk self-modifying / plugin yang link static).
  - `@Native` / `@FfiNative` annotation binding (Dart 3.0+) — FFI binding via annotation, tidak melalui `DynamicLibrary.lookupFunction` sama sekali; compiler generate `LeafRuntimeCallInstr` / `FfiCallInstr` langsung dengan symbol name di kernel metadata.
  - `Native.function` / `Native.lookUp` (Dart 3.x new FFI binding API).

- **Bukti SDK**:
  - `grep MCP searchGitHub repo:dart-lang/sdk "NativeCallable"` → `sdk/lib/ffi/native_callable.dart` ada; `runtime/vm/native_entry.cc` handle `Dart_NativeCallableFunction` / `Dart_NativeCallableListenerFunction`.
  - `grep MCP searchGitHub repo:dart-lang/sdk "Pointer.fromFunction"` → `sdk/lib/ffi/ffi.dart` legacy callback API.
  - `grep MCP searchGitHub repo:dart-lang/sdk "DynamicLibrary.process"` → `sdk/lib/ffi/ffi_dynamic_library.dart`: `DynamicLibrary.process()` → `_open` dengan `nullptr` handle.
  - `@Native` annotation: `grep MCP searchGitHub repo:dart-lang/sdk "@Native"` → `sdk/lib/_internal/vm/lib/ffi_patch.dart` — binding via annotation, symbol name di `@Native<...>("symbol")` atau `@Native<...>(symbol: "name")`.

- **Dampak**: **Menengah**. App yang pakai FFI binding modern (`@Native`, `NativeCallable`) tidak terdeteksi sama sekali oleh signal 1. Callback registration (`Pointer.fromFunction`, `NativeCallable`) tidak terdeteksi — padahal ini adalah FFI boundary penting untuk RE (Dart function yang bisa dipanggil dari C).

- **Usulan**:
  1. Extend `looksLikeFfiOpenOrLookup` untuk match: `"nativecallable"`, `"pointer.fromfunction"`, `"dynamiclibrary.process"`, `"dynamiclibrary.executable"`, `"@native"`, `"ffinative"`, `"native.function"`, `"native.lookup"`.
  2. Tambah deteksi callback registration: scan untuk call ke `Pointer.fromFunction` / `NativeCallable.isolateLocal` / `NativeCallable.listener` — emit `Kind: "ffi_callback_registration"` dengan literal arg (Dart function name jika recoverable dari pool ref).
  3. Untuk `@Native` annotation binding: symbol name tidak ada di pool string (di kernel metadata, tidak di snapshot object pool). Ini perlu resolve dari Function object's `FfiCallbackId` / native name field — cross-reference dengan `FfiTrampolineData` (Gap 2).

- **Prioritas**: **P1 — tinggi**.

### Gap 6: Tidak ada klasifikasi FFI call kind (sync/async/leaf/callback) di Finding

- **Deskripsi**: `Finding.Kind` hanya `"dynamic_library_call"` | `"native_call_site"` — tidak membedakan apakah native call adalah **leaf** (no safepoint, no GC, fastest), **sync** (with safepoint), **async** (async callback), atau **callback** (Dart→C→Dart). `FfiTrampolineData.ffi_function_kind_` (uint8: 0=Sync, 1=Async, 2=Leaf, 3=Callback) sudah di-decode (`cluster.FfiKindSync` dll.) tetapi tidak di-surface.

  Klasifikasi kind penting untuk RE: leaf call tidak bisa trigger GC/safepoint (constraint kuat pada arg layout), sync call melalui safepoint stub (CallNativeThroughSafepoint), callback adalah inbound (C→Dart).

- **Bukti SDK**:
  - `gh api repos/dart-lang/sdk/contents/runtime/vm/raw_object.h?ref=3.12.2` line 1701: `uint8_t ffi_function_kind_;` dengan comment "See FfiCallbackKind."
  - `grep MCP searchGitHub repo:dart-lang/sdk "FfiCallbackKind"` / `"FfiFunctionKind"` → enum di `runtime/vm/raw_object.h` atau `runtime/vm/ffi.cc`.
  - AOTopsy `internal/cluster/ffitrampoline.go` line 19-24: `FfiKindSync=0, FfiKindAsync=1, FfiKindLeaf=2, FfiKindCallback=3` + `FfiKindString`.

- **Dampak**: **Menengah**. RE analyst tidak bisa membedakan outbound native call vs inbound callback tanpa klasifikasi kind. Leaf vs sync mempengaruhi analisis arg register dan stack alignment.

- **Usulan**: Tambah field `FfiKind string` ke `Finding` (`"leaf"` | `"sync"` | `"async"` | `"callback"` | `""`). Resolve dari `FfiTrampolineData` terkait (Gap 2) atau dari structural detection (leaf = CSP/SP swap pattern; sync = CallNativeThroughSafepoint stub; callback = NativeEntryInstr pattern).

- **Prioritas**: **P2 — menengah**.

### Gap 7: Tidak ada tracking FFI calling convention register / arg mapping (C ABI vs Dart ABI)

- **Deskripsi**: ffitrace tidak melacak register arg FFI call sama sekali. `Finding` tidak punya field arg register info. Padahal FFI call menggunakan **C ABI** (ARM64: x0-x7 + v0-v7; x86_64: rdi/rsi/rdx/rcx/r8/r9 + xmm0-7) **berbeda** dari Dart calling convention (ARM64: R1,R2,R3,R5,R6,R7 — `arm64ArgRegs` di liftarm64.go line 23). `FfiCallInstr::EmitParamMoves` (il_arm64.cc) melakukan marshalling Dart-arg-reg → C-arg-reg, dan info ini hilang.

  Register FFI-specific yang tidak di-track:
  - `kFfiAnyNonAbiRegister` (ARM64 R19, x64 R12, ia32 EBX) — register callee-saved yang dipakai FFI sebagai temp (il_arm64.cc line 1366, 1706).
  - `kFirstNonArgumentRegister` (ARM64 R9) / `kSecondNonArgumentRegister` (ARM64 R10) — FFI temp registers.
  - `target_address` register (input `TargetAddressIndex()`) — register yang hold native function pointer sebelum `blr`.
  - CSP (C stack pointer) vs SP (Dart stack pointer) swap di leaf call.

- **Bukti SDK**:
  - `gh api repos/dart-lang/sdk/contents/runtime/vm/constants_arm64.h?ref=3.12.2`: `kFfiAnyNonAbiRegister = R19`, `kFirstNonArgumentRegister = R9`, `kSecondNonArgumentRegister = R10`.
  - `gh api repos/dart-lang/sdk/contents/runtime/vm/constants_x64.h?ref=3.12.2`: `kFfiAnyNonAbiRegister = R12`.
  - `gh api repos/dart-lang/sdk/contents/runtime/vm/compiler/backend/il_arm64.cc?ref=3.12.2` line 1359: `const Register branch = locs()->in(TargetAddressIndex()).reg();` — target native function pointer register.
  - Line 1366: `R(CallingConventions::kFfiAnyNonAbiRegister) | R(R25)` di LocationSummary.

- **Dampak**: **Menengah**. Tanpa arg register tracking, ffitrace tidak bisa reconstruct "FFI call ini manggil native function dengan arg0=x0(C ABI)=R1(Dart), arg1=x1(C)=R2(Dart), ..." — yang penting untuk memahami arg marshalling dan validate C signature vs actual args.

- **Usulan**:
  1. Tambah field `TargetReg string` (register yang hold native function pointer) dan `ArgRegMap []ArgMapping` ({DartReg, CReg, PoolLiteral/Expr}) ke `Finding`.
  2. Untuk leaf FFI (CSP/SP swap pattern), track `saved_csp` register = `kFfiAnyNonAbiRegister`.
  3. Cross-reference dengan `FfiTrampolineData.c_signature_` (Gap 2) untuk validate arg count dan type.

- **Prioritas**: **P2 — menengah**.

### Gap 8: `EmitPseudocode` re-run per fungsi adalah cost double — ffitrace bayar full pseudocode emission hanya untuk string contains check

- **Deskripsi**: `Trace` (line 137) memanggil `decompiler.EmitPseudocode(fir, ...)` untuk **setiap** fungsi yang di-scan, lalu hanya `strings.Contains(art.Source, FFICallMarker)`. Ini adalah operasi mahal (full CFG walk + text emission + readability passes) yang dilakukan dua kali: sekali oleh ffitrace signal 2, dan sekali lagi jika caller lain (e.g. `decompile-native --all`) juga decompile fungsi yang sama. Doc comment Options (line 42-51) sendiri mengakui ini drove RSS ke 5.4GB.

  Sebenarnya, `CallTargetsOf` (call.go line 433) sudah ada sebagai API cheap untuk extract call targets tanpa full emission. Tapi ffitrice tidak pakai — dan `CallTargetsOf` juga tidak expose info "apakah call adalah FFI" (hanya target VA).

- **Bukti SDK**: N/A (ini adalah gap arsitektur AOTopsy internal, bukan SDK discrepancy).
- **Dampak**: **Menengah**. ffitrace dengan `AllowUnbounded` pada real app (ribuan fungsi) sangat mahal dan crash-prone. Default cap 500 berarti ffitrace hanya scan 500 fungsi pertama — **miss FFI call di fungsi setelah cap**.

- **Usulan**:
  1. Expose API baru di decompiler: `FFICallSites(fir) []FFICallSiteInfo` yang walk blocks dan return call site info (addr, target reg, kind: vm_tag/CallNativeThroughSafepoint/leaf-swap) **tanpa** full text emission.
  2. ffitrace pakai API ini instead of `EmitPseudocode` + `strings.Contains`.
  3. Ini juga memungkinkan ffitrace scan unbounded dengan cost rendah (hanya IR walk, bukan emit+compact).

- **Prioritas**: **P2 — menengah** (performa + coverage).

## Register Tracking Gaps

| Register | Peran (SDK) | Di-track ffitrace? | Sumber SDK |
|---|---|---|---|
| `vm_tag` offset (THR field) | Marker FFI/native call target store | ✅ via decompiler `ThreadFieldNames` (lift.go:924) — **tetapi hanya fire di !PRODUCT untuk FfiCallInstr leaf, dan di LeafRuntimeCallInstr** | il_arm64.cc:1427 (`#if !defined(PRODUCT)`), :1728 (PRODUCT) |
| `CallNativeThroughSafepoint_entry_point_` (THR offset 0x268 @3.7.0) | Non-leaf FfiCallInstr call site | ❌ ffitrace tidak scan marker stub ini; decompiler emit `CallNativeThroughSafepoint(...)` tetapi ffitrace hanya cari `ffi_call(` | il_arm64.cc:1463-1476; threadstubs.go:61 |
| `kFfiAnyNonAbiRegister` (R19 ARM64 / R12 x64) | FFI temp register (saved CSP) | ❌ tidak di-track | constants_arm64.h:635, constants_x64.h:677 |
| `kFirstNonArgumentRegister` (R9 ARM64) | FFI temp + branch register (FfiCallInstr target) | ❌ tidak di-track sebagai FFI-specific | constants_arm64.h:637; il_arm64.cc:1359,1438 |
| `kSecondNonArgumentRegister` (R10 ARM64) | FFI temp | ❌ tidak di-track | constants_arm64.h:637 |
| `TargetAddressIndex()` input register | Register yang hold native function pointer sebelum blr | ❌ tidak di-track | il_arm64.cc:1359 |
| CSP (C stack pointer) vs SP (Dart SPREG) | Leaf FFI swap `mov CSP, SP; blr; mov SP, CSP` | ❌ pola swap tidak di-recognize | il_arm64.cc:1429-1445; ir.go:139 (SPREG di-track tapi bukan untuk FFI pattern) |
| `exit_through_ffi_` (THR field) | Disimpan di NativeEntryInstr entry frame (callback) | ❌ tidak di-track sebagai FFI callback marker | il_arm64.cc:1619; thrfields.go:220 (`0x668: "exit_through_ffi"` ada di table tetapi tidak dipakai ffitrace) |
| `ffi_callback_code` (ObjectStore field) | Load di NativeEntryInstr untuk resolve callback Code | ❌ tidak di-track | il_arm64.cc:1660-1662 |
| C ABI arg regs (x0-x7 ARM64 / rdi-r9 x64) | Outbound FFI call arg marshalling destination | ❌ tidak di-track (decompiler track Dart ABI arg regs saja) | constants_arm64.h CallingConventions |
| FPU arg regs C ABI (v0-v7 ARM64 / xmm0-7 x64) | FFI float/double arg | ❌ tidak di-track untuk FFI | constants_arm64.h |

## Fitur RE Missing/Incomplete

1. **C-side FFI signature extraction** — `FfiTrampolineData.c_signature_` (FunctionTypePtr) sudah di-decode cluster tetapi tidak di-surface ffitrace. RE analyst tidak mendapat `Int32 Function(Pointer<Uint8>, Uint32)` untuk FFI call. (Gap 2)

2. **Native callback detection** — Dart function yang exposed ke C via `Pointer.fromFunction` / `NativeCallable` / `@FfiNative` callback. `FfiTrampolineData` kind=Callback + `CallbackTargetRef` → Function sudah ada tetapi tidak di-surface. RE analyst tidak tahu "Dart function mana yang bisa dipanggil dari native code". (Gap 2, 5)

3. **FFI call kind klasifikasi** — leaf/sync/async/callback. Mempengaruhi constraint RE (leaf = no GC, no safepoint; sync = through safepoint; callback = inbound). (Gap 6)

4. **`@Native` / `@FfiNative` annotation binding** — FFI binding modern (Dart 3.0+) yang tidak melalui `DynamicLibrary.lookupFunction`. Symbol name di kernel metadata, compiler generate `LeafRuntimeCallInstr` langsung. ffitrace sama sekali tidak detect pola ini. (Gap 5)

5. **`NativeCallable` callback registration** — pengganti `Pointer.fromFunction` di Dart 3.x. Tidak di-detect. (Gap 5)

6. **`DynamicLibrary.process()` / `executable()`** — lookup di process image sendiri (pola umum plugin static-link). `looksLikeFfiOpenOrLookup` miss. (Gap 5)

7. **(library, symbol) pair recovery** — ffitrace hanya recover satu literal (path OR symbol, ambigu). Tidak recover pasangan lengkap. Cross-block / field-cache indirection tidak di-follow. (Gap 4)

8. **Native function pool slot identification** — `PoolNative` entry tidak di-display, tidak bisa dianotasi sebagai `<native_function>` di pseudocode. (Gap 3)

9. **Arg register marshalling map** — Dart ABI → C ABI arg register mapping untuk FFI call. Penting untuk validate signature vs actual args. (Gap 7)

10. **Unbounded scan coverage** — default cap 500 fungsi berarti ffitrace miss FFI call di fungsi setelah cap. `EmitPseudocode` re-run membuat unbounded scan crash-prone. (Gap 8)

11. **FFI call site → FfiTrampolineData cross-reference** — menghubungkan call site (di app code) ke trampoline metadata (di snapshot) via pool entry `kNativeEntryData` (PoolTagged ref ke FfiTrampolineData). Tidak diimplementasi. (Gap 2)

12. **Callback ID extraction** — `FfiTrampolineData.callback_id_` (int32_t) untuk korelasi cross-isolate callback verification. Sudah di-decode tetapi tidak di-surface. (Gap 2)

## Verifikasi SDK

Semua klaim SDK diverifikasi via dua jalur:

### grep MCP `searchGitHub` (repo: dart-lang/sdk)

| Query | Hasil | File SDK |
|---|---|---|
| `FfiTrampolineData` | field `c_signature_`, `callback_target_`, `callback_exceptional_return_` di `raw_object_fields.cc:203-206`; `UntaggedFfiTrampolineData` di `raw_object.h:1672` | runtime/vm/raw_object.h, raw_object_fields.cc |
| `TransitionGeneratedToNative` | definisi di `safepoint.h:307`; pemakaian di `stub_code_compiler_arm.cc:252`, `il_arm64.cc:1559`, `il_x64.cc:505` | runtime/vm/heap/safepoint.h, compiler/stub_code_compiler_arm.cc, compiler/backend/il_arm64.cc |
| `FfiCallInstr::EmitNativeCode` | definisi di `il_arm64.cc:1358`, `il_x64.cc:1227`, `il_ia32.cc:1079`, `il_arm.cc:1627`, `il_riscv.cc:1418` | runtime/vm/compiler/backend/il_*.cc |
| `FfiCallTrampoline` | stub list di `stub_code_list.h:152`; stub code `stub_code_compiler_arm64.cc:430` (`Breakpoint()` — lihat `ffi_trampolines_arm64.S`) | runtime/vm/stub_code_list.h, compiler/stub_code_compiler_arm64.cc, ffi_trampolines_arm64.S |
| `kFfiAnyNonAbiRegister` | ARM64 R19 (`constants_arm64.h:635`), x64 R12 (`constants_x64.h:677`), ia32 EBX (`constants_ia32.h:497`), arm R4 (`constants_arm.h:758`), riscv S2 (`constants_riscv.h:632`) | runtime/vm/constants_*.h |
| `LeafRuntimeCallInstr::EmitNativeCode` | `il_arm64.cc:1708` (vm_tag store di PRODUCT, line 1728), `il_x64.cc:1543`, `il_ia32.cc:1350`, `il_riscv.cc:1785` | runtime/vm/compiler/backend/il_*.cc |
| `FfiCallbackMetadata` | `ffi_callback_metadata.h:38`, `ffi_callback_metadata.cc:27`, `runtime_entry.cc:2125` | runtime/vm/ffi_callback_metadata.{h,cc}, runtime_entry.cc |
| `NativeCallable` | `sdk/lib/ffi/native_callable.dart` | sdk/lib/ffi/ |
| `Pointer.fromFunction` | `sdk/lib/ffi/ffi.dart` | sdk/lib/ffi/ffi.dart |
| `DynamicLibrary.process` | `sdk/lib/ffi/ffi_dynamic_library.dart` | sdk/lib/ffi/ffi_dynamic_library.dart |

### `gh api` @ tag 3.12.2

| Path SDK @3.12.2 | Konten diverifikasi |
|---|---|
| `runtime/vm/raw_object.h` | `UntaggedFfiTrampolineData` (line 1672-1701): field `signature_type_`, `c_signature_`, `callback_target_`, `callback_exceptional_return_`, `callback_id_` (int32_t), `ffi_function_kind_` (uint8_t). `UntaggedDynamicLibrary` (line 3608-3615): `VISIT_NOTHING()`, `void* handle_`, `bool isClosed_`, `bool canBeClosed_` — **handle_ adalah inline void*, bukan ref, path library tidak di-snapshot**. |
| `runtime/vm/compiler/backend/il_arm64.cc` | `FfiCallInstr::EmitNativeCode` (line 1358-1556): path `is_leaf_=true` vm_tag store di `#if !defined(PRODUCT)` (line 1427); path non-leaf `ldr temp1, [THR, call_native_through_safepoint_entry_point_offset()]; blr(temp1)` (line 1463-1476) — **tidak ada vm_tag store di call site**. `LeafRuntimeCallInstr::EmitNativeCode` (line 1714-1739): `str(target_address, [THR, vm_tag_offset]); CallCFunction(target_address); str(kDartTagId, [THR, vm_tag_offset])` — **di PRODUCT, tidak di-guard #if**. `NativeEntryInstr::EmitNativeCode` (line 1581-1660): callback entry, load `exit_through_ffi_`, `ffi_callback_code` dari ObjectStore. |

### Cross-check AOTopsy internal

| File AOTopsy | Konfirmasi |
|---|---|
| `internal/cluster/ffitrampoline.go:8-16` | `FfiTrampolineInfo` struct sudah ada dengan 6 field — ffitrace tidak pakai |
| `internal/cluster/fill_refs.go:316-326` | FfiTrampolineData sudah di-decode dari snapshot stream |
| `internal/analysis/ffi_bridges.go:20-49` | `BuildFfiBridges` sudah resolve signature/callback — ffitrace tidak panggil |
| `internal/analysis/pipeline.go:400` | `BuildFfiBridges` dipanggil di pipeline (untuk export) — tetapi tidak di-surface ke ffitrace |
| `internal/vmtables/threadstubs.go:61` | `0x268: "CallNativeThroughSafepoint"` ada di table — decompiler resolve, ffitrace tidak scan |
| `internal/vmtables/thrfields.go:126,251,397,...` | `vm_tag` offset di-track per version/arch — decompiler pakai, ffitrace tidak langsung |
| `internal/decompiler/call.go:289-298` | `ffiCallTargetSentinel` → emit `ffi_call(` — hanya fire jika vm_tag store terdeteksi |
| `internal/decompiler/call.go:312-341` | THR-stub load → emit `CallNativeThroughSafepoint(...)` — ffitrace tidak scan marker ini |
| `internal/decompiler/lift.go:922-933` | `applyStore` set sentinel hanya jika `ThreadFieldNames[disp]=="vm_tag"` |
| `internal/cluster/fill_pool.go:66,99` | `PoolNative` (kNativeFunction) → `pe.Kind = PoolNative`, no data read |
| `internal/naming/pool.go:633-773` | `ResolvePoolDisplay` switch — **tidak ada `case cluster.PoolNative:`** |
| `internal/ffitrace/ffitrace.go:224-227` | `looksLikeFfiOpenOrLookup` hanya match `dynamiclibrary`/`lookupfunction` |
| `internal/ffitrace/ffitrace.go:138` | signal 2 = `strings.Contains(art.Source, FFICallMarker)` — miss CallNativeThroughSafepoint |
