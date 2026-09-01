# RE Gap Analysis Report: internal/strutil

> **STATUS VERIFIKASI (2026-09-01)** — Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`. Koreksi:
> - **Gap 9 ("stub offset map tidak di metadata; hanya THR field names yang
>   di-export") → STALE.** `pipeline.go:230` memanggil
>   `vmtables.THRFieldsWithProfile(...)` lalu meneruskannya ke
>   `strutil.WriteDartMeta(...)`, dan peta itu **memuat** nama
>   `*_entry_point` (mis. 31 entri di `thrV3130`, plus blok runtime-entry hasil
>   `mergeRuntimeEntries` untuk 9 versi). Yang benar-benar hilang hanyalah
>   **kategori** stub/entry_point/data — yaitu Gap 4, bukan offset-nya.
> - **Tabel di "Register Tracking Gaps" salah**: `HEAP_BITS x23` (seharusnya
>   **R28**); `HeapBase … rbp` juga menyesatkan. Ini kesalahan sejenis dengan
>   report `analysis` dan `symbolmap`.
> - Gap 1 (`DartReservedWords` 53 kata, `dynamic`/`Function`/`get`/`set`/
>   `interface`/`base`/`sealed`/`show`/`hide`/`on`/`when`/`augment` hilang) dan
>   Gap 2 (`ParseHexAddr` tidak menerima `0X`, tidak trim spasi, silent 0) —
>   **CONFIRMED** dari `dart_sanitize.go:25-36` dan `dartmeta.go:93-108`.

## Ringkasan

Folder `internal/strutil` (3 file non-test, ~456 LOC; 2 file test, ~173 LOC) adalah
package utilitas & metadata shared lintas-package di AOTopsy. Isinya tiga area:

1. **Sanitizers** (`strutil.go`, `dart_sanitize.go`) — `SanitizeFilename`,
   `SanitizeIdentifier`, `SanitizeR2FlagName`, `SanitizeLibraryPath`,
   `SanitizeDartIdent`, `SanitizeDartBody`, `DartReservedWords`.
2. **Metadata JSON schema** (`dartmeta.go`) — `FlutterMetaJSON`,
   `FlutterMetaFunc`, `FlutterMetaTHRField`, `FlutterMetaJSONClass`,
   `FlutterMetaField`, `FlutterMetaComment`, `DisasmIndexEntry`, plus writer
   `WriteDartMeta` dan parser `ExtractAsmComments`.
3. **Hex/address helpers** (`dartmeta.go`) — `NormalizeHexAddr`, `ParseHexAddr`,
   `FileSize`, `AsmCommentRe`.

Analisis ini membandingkan kode AOTopsy vs Dart SDK source (via grep MCP +
`gh api` @ tag 3.9.2 dan 3.12.2) dan menemukan **12 gap**: 3 bug fungsional
(keyword list incomplete, ParseHexAddr/NormalizeHexAddr inconsistency,
AsmCommentRe greedy + lewatkan format non-`0x`), 4 metadata schema gap
(THR field tanpa kategori, Class layout tanpa super/library/typeargs/unboxed,
Field tanpa kind_bits/type/initializer, Func tanpa async/return-type/kind),
3 utility yang miss (runtime register info tidak di strutil, stub/entry-point
offset tidak di metadata, ObjectStore field count tidak di metadata), dan 2
fitur RE useful yang missing (Dart operator set sanitizer, library URL scheme
coverage).

Strutil adalah "tip of the metadata iceberg" — ia define schema yang
dikonsumsi oleh `flutter_meta.json` (Ghidra/IDA import), `dart_meta.json`
(pipeline intermediate), dan `frida_metadata.json` (dynamic analysis). Karena
schema-nya under-specified, data yang SUDAH ada di `cluster.Result` /
`FuncIR` / `vmtables` tidak ter-propagate ke consumer RE, sehingga tool RE
eksternal (Ghidra, IDA, Frida, reFlutter) tidak mendapatkan info yang sebenarnya
tersedia.

## Struktur Folder

```
internal/strutil/
├── strutil.go          — SanitizeFilename, SanitizeIdentifier, SanitizeR2FlagName
│                         (128 LOC, r2 allowlist verified vs r_name_check)
├── dart_sanitize.go    — SanitizeLibraryPath, DartReservedWords, SanitizeDartIdent,
│                         SanitizeDartBody (placeholder/mixin/operator/cond sanitization)
│                         (135 LOC)
├── dartmeta.go         — FlutterMetaJSON + sub-types, WriteDartMeta,
│                         NormalizeHexAddr, ParseHexAddr, AsmCommentRe,
│                         ExtractAsmComments, FileSize, DisasmIndexEntry
│                         (193 LOC)
├── strutil_test.go     — SanitizeFilename/SanitizeIdentifier tests (78 LOC)
└── r2name_test.go      — SanitizeR2FlagName tests vs r_name_check transcription (95 LOC)
```

Konsumen (12 file, 41 call site):
- `internal/analysis/{pipeline,meta_stage,disasm_stage,disasm_stagex86,signal_stage,r2_fingerprint_export}.go`
- `internal/naming/naming_utils.go`, `internal/decompiler/emit.go`,
  `internal/decompiler/compare/r2_export.go`, `internal/render/html.go`
- `cmd/aotopsy/{cmd_debug_graph,cmd_export_dart}.go`

## Gap Analysis

### Gap 1: DartReservedWords incomplete — emit .dart tidak parse untuk 18+ keyword
- **Deskripsi**: `DartReservedWords` (dart_sanitize.go:25-36) berisi 53 keyword,
  tapi SDK scanner (`pkg/_fe_analyzer_shared/lib/src/scanner/token.dart`)
  define 73 keyword dengan `KeywordStyle` (reserved/builtIn/pseudo). Test
  `tests/language/identifier/built_in_illegal_test.dart` + diagnostic
  `BUILT_IN_IDENTIFIER_IN_DECLARATION` membuktikan bahwa **built-in identifier**
  TIDAK boleh dipakai sebagai declaration name (class/mixin/enum/typedef/
  type-parameter/extension). `SanitizeDartIdent` hanya prefix `_` untuk kata di
  `DartReservedWords`, jadi nama recovered yang collide dengan keyword missing
  akan di-emit apa adanya → file `.dart` gagal parse di analyzer.

  Keyword yang HILANG dari `DartReservedWords` (verifikasi via `gh api` @3.9.2
  `token.dart` + `built_in_illegal_test.dart`):
  - **builtIn (wajib, BUILT_IN_IDENTIFIER_IN_DECLARATION)**: `augment` (Dart 3.6+),
    `dynamic`, `Function`, `get`, `interface`, `set`
  - **pseudo (juga illegal sebagai declaration name, lihat
    `built_in_illegal_test.dart` baris `class abstract {}`)**: `base`, `hide`,
    `inout`, `native`, `of`, `on`, `out`, `patch`, `sealed`, `show`, `source`,
    `sync`, `when`

  Catatan: `async`/`await`/`yield` (pseudo) SUDAH ada di list — jadi list
  existing tidak konsisten: sebagian pseudo dimasukkan, sebagian tidak.

- **Bukti SDK**:
  - `gh api .../pkg/_fe_analyzer_shared/lib/src/scanner/token.dart?ref=3.9.2` →
    73 keyword, masing-masing ber-tag `KeywordStyle.reserved|builtIn|pseudo`.
  - `gh api .../tests/language/identifier/built_in_illegal_test.dart?ref=3.9.2` →
    `class dynamic {}`, `class get {}`, `class set {}`, `class interface {}`
    semuanya melahirkan `COMPILE_TIME_ERROR.BUILT_IN_IDENTIFIER_IN_DECLARATION`.
  - grep MCP `repo:dart-lang/sdk` `class Function {}` →
    `builtInIdentifierAsTypeName` diagnostic: "The built-in identifier 'Function'
    can't be used as a type name."
- **Dampak**: Export `.dart` (`cmd_export_dart.go` → `SanitizeDartIdent`) untuk
  method/class yang namanya recover ke `get`, `set`, `dynamic`, `Function`,
  `interface`, `base`, `sealed`, `augment`, dll. menghasilkan file yang gagal
  di-parse analyzer. Karena `get`/`set` adalah nama getter/setter yang SANGAT
  umum di Flutter framework (`get hashCode`, `set value`), collision nyata.
  `dynamic` juga sering sebagai nama field/parameter recovered.
- **Usulan**: Ganti `DartReservedWords` dengan dua set: `DartReservedWords`
  (reserved + builtIn, wajib prefix) dan `DartPseudoKeywords` (pseudo, prefix
  hanya di declaration context). Sumber otoritatif: scanner/token.dart — bukan
  hand-rolled list. Tambahkan test yang compare against keyword list yang
  di-extract dari SDK (mirip `r2NameCheck` transcription pattern di
  `r2name_test.go`). Destruktif: hapus list hand-rolled, generate dari SDK.
- **Prioritas**: HIGH — bug fungsional, emit .dart gagal parse.

### Gap 2: ParseHexAddr/NormalizeHexAddr inconsistency (0X, whitespace, sign)
- **Deskripsi**:
  - `NormalizeHexAddr` (dartmeta.go:93) handle `0x` DAN `0X` (line 94).
  - `ParseHexAddr` (dartmeta.go:105) hanya `strings.TrimPrefix(s, "0x")` —
    TIDAK trim `0X`. Input `0X652e4` → `ParseUint("X652e4",16,64)` error →
    return 0 silently.
  - `ParseHexAddr` tidak trim whitespace; `NormalizeHexAddr` juga tidak.
    `signal_stage.go:315` memanggil `ParseHexAddr(er.FromPC)` pada data dari
    JSONL yang bisa punya trailing space.
  - `ParseHexAddr` silent-failure (return 0) — caller tidak bisa bedakan
    "alamat 0" (valid) vs "parse error". `signal_stage.go:354`
    `baseAddr := ParseHexAddr(fr.PC); if baseAddr == 0 { continue }` — ini
    benar kebetulan, tapi caller lain bisa salah.
- **Bukti SDK**: N/A (ini internal consistency). Tapi format `0X` valid di
  `strconv.ParseUint` setelah prefix di-strip — SDK tidak relevan, ini bug
  murni AOTopsy.
- **Dampak**: Alamat dengan `0X` prefix (jarang tapi valid, dihasilkan oleh
  beberapa tool external) silently jadi 0. Whitespace-trailing JSONL record
  juga jadi 0. `signal_stage.go` dan `meta_stage.go` konsumen utama.
- **Usulan**: Samakan: keduanya trim `0x`/`0X` case-insensitive, trim
  whitespace, dan `ParseHexAddr` return `(uint64, error)` bukan silent 0.
  Destruktif: ubah signature. Update 2 call site di `signal_stage.go`.
- **Prioritas**: MEDIUM — silent failure, tapi `0X` jarang.

### Gap 3: AsmCommentRe greedy + lewatkan format non-`0x` / multi-`;`
- **Deskripsi**: `AsmCommentRe` (dartmeta.go:112) =
  `^(0x[0-9a-fA-F]+)\s+.*;\s+(.+)$`.
  - `.*` greedy: jika instruction text mengandung `;` (mis. inline comment di
    mnemonic), group 2 capture dari `;` TERAKHIR, bukan pertama. Format
    `output.WriteASM` (arm64.go:90) menulis `0x%08x  <bytes>  <text>  ; <ann>`
    — hanya satu `;`, jadi greedy OK untuk output AOTopsy sendiri. TAPI
    `ExtractAsmComments` dipakai juga pada file asm dari sumber lain (reFlutter,
    Ghidra export) yang formatnya bisa beda.
  - Address format: `0x[0-9a-fA-F]+` — lewatkan address tanpa `0x` prefix
    (Ghidra sering emit `000652e4  ...` tanpa `0x`). `output.WriteASM` pakai
    `0x%08x` jadi OK untuk internal, tapi kontrak fungsi tidak menyatakannya.
  - Tidak ada anchor untuk byte-column: `.*` bisa match跨 kolom bytes. Format
    internal punya kolom bytes 4×`%02x ` lalu text — regex tidak lock ke
    pola itu, jadi fragil jika format berubah.
  - `extractFileComments` skip line dengan comment `<...>` (line 157-159) untuk
    buang symbol-name comments — TAPI ini juga skip annotator yang legitimate
    mengandung `<...>` (mis. `<TypeArguments>`, `<Instance_2300>` placeholder
    yang justru BERGUNA untuk RE).
- **Bukti SDK**: N/A (format internal AOTopsy). Verifikasi format:
  `internal/disasm/arm64.go:90` `Format` → `fmt.Fprintf(&b, "0x%08x  ", ...)`.
- **Dampak**: Kehilangan comment yang legitimate (placeholder `<...>`), dan
  fragil terhadap format asm non-AOTopsy. Annotator THR/PP yang menghasilkan
  `<...>` di-skip padahal valuable.
- **Usulan**: Buat regex non-greedy `^(0x[0-9a-fA-F]+)\s+\S+\s+\S+\s+[^;]*;\s(.+)$`
  yang lock ke 4-kolom format internal. Hanya skip comment yang EXACT match
  `^<[^>]+>$` (symbol name), bukan comment yang CONTAINS `<...>`. Document
  kontrak: hanya untuk output `output.WriteASM`. Tambah test dengan sample
  line real.
- **Prioritas**: MEDIUM — kehilangan comment RE-valuable.

### Gap 4: FlutterMetaTHRField tidak punya kategori (stub/entry_point/data)
- **Deskripsi**: `FlutterMetaTHRField` (dartmeta.go:25) hanya `{Offset, Name}`.
  SDK Thread punya 120 field (verifikasi: `runtime_offsets_list.h` @3.9.2 →
  120 `FIELD(Thread, ...)`), terbagi jelas:
  - **Stub offsets** (`*_stub_offset`): `allocate_object_stub_offset`,
    `write_barrier_entry_point_offset`, `enter_safepoint_stub_offset`, dll.
    — pointer ke Code stub.
  - **Entry point offsets** (`*_entry_point_offset`): `call_to_runtime_entry_point_offset`,
    `allocate_object_entry_point_offset`, dll. — pointer ke runtime entry.
  - **Data field offsets** (`*_offset` non-stub/entry): `top_offset`,
    `stack_limit_offset`, `heap_base_offset`, `vm_tag_offset`, `bool_true_offset`,
    `object_null_offset`, `random_offset`, dll. — data word/pointer.

  `extract_thr.go:283` SUDAH tahu perbedaan ini (`strings.HasSuffix(e.name,
  "_entry_point_offset")` → stub name), tapi info kategori TIDAK disimpan di
  `FlutterMetaTHRField`. Consumer RE (Frida, Ghidra) tidak bisa bedakan "load
  THR+0x38 = stack_limit (data)" vs "BLR [THR+0x...] = call stub (code pointer)".

- **Bukti SDK**:
  - `gh api .../runtime/vm/compiler/runtime_offsets_list.h?ref=3.9.2` →
    `grep -E "FIELD\(Thread,"` = 120 field, ~40 stub/entry, ~80 data.
  - `tools/extract_thr.go:283` sudah strip `_entry_point_offset` suffix untuk
    `extractThreadStubOffsets` — kategori info ADA di extraction time, hilang
    di serialization.
- **Dampak**: Frida script (`frida/script_gen.go:108` `THR_FIELDS` map) tidak
  tahu offset mana yang code pointer (bisa di-hook) vs data (bisa di-read).
  RE yang ingin hook `allocate_object_stub` harus guess dari nama. Ghidra
  import `flutter_meta.json` tidak bisa auto-type THR field.
- **Usulan**: Tambah `Kind string` field ke `FlutterMetaJSON` THR field:
  `"stub"|"entry_point"|"data"`. Isi dari `extract_thr.go` saat generate
  `thrfields.go`. Backward-compat: `omitempty`. Destruktif: regenerate semua
  tabel THR dengan kind info (sudah ada data di extractor).
- **Prioritas**: HIGH — info RE kritis untuk Frida hooking, sudah ada di
  extraction tapi di-drop.

### Gap 5: FlutterMetaJSONClass tidak punya super/library/typeargs/unboxed bitmap
- **Deskripsi**: `FlutterMetaJSONClass` (dartmeta.go:51) =
  `{ClassName, ClassID, InstanceSize, Fields[]}`. Tapi `cluster.ClassInfo`
  (fill.go:156) punya LEBIH banyak:
  - `SuperTypeRefID` — superclass (ref ke Type object) → bisa resolve ke nama
    superclass. RE-critical untuk inheritance graph.
  - `LibraryRefID` — owning Library → bisa resolve ke library URL. RE-critical
    untuk "class ini milik package mana".
  - `TypeArgsOff` — offset field TypeArguments (reified generics). RE-critical
    untuk baca type args runtime.
  - `UnboxedFieldBitmap` — bitmap field mana yang unboxed (raw word, bukan
    ref). RE-critical untuk bedakan "field int x" vs "field Object x".

  `BuildClassLayouts` (class_layouts.go:25) SUDAH akses `ci.SuperTypeRefID`,
  `ci.LibraryRefID`, `ci.TypeArgsOff`, `ci.UnboxedFieldBitmap` — tapi TIDAK
  propagate ke `DartClassLayout`/`FlutterMetaJSONClass`. Data hilang di
  boundary `analysis` → `strutil` → JSON.

- **Bukti SDK**:
  - grep MCP `repo:dart-lang/sdk` `super_type() const` →
    `runtime/vm/object.h:1465` `TypePtr super_type() const` — superclass
    tersimpan di UntaggedClass.
  - `cluster/fill.go:156` `ClassInfo` sudah capture `SuperTypeRefID`,
    `LibraryRefID`, `TypeArgsOff`, `UnboxedFieldBitmap` dari snapshot stream.
- **Dampak**: Ghidra/IDA import `flutter_meta.json` tidak punya inheritance
  graph, tidak punya library grouping, tidak tahu field mana unboxed. RE
  harus re-derive dari disassembly. Frida tidak bisa langsung baca
  TypeArguments offset.
- **Usulan**: Tambah field ke `FlutterMetaJSONClass`:
  `SuperClass string`, `LibraryURL string`, `TypeArgsOffset int32`,
  `UnboxedFieldBitmap uint64`. Isi di `BuildClassLayouts` (data sudah ada).
  `FlutterMetaField` tambah `IsUnboxed bool` (decode dari bitmap).
  Destruktif: ubah schema JSON, bump `Version` ke "2".
- **Prioritas**: HIGH — data sudah ada di memory, di-drop di serialization.

### Gap 6: FlutterMetaField tidak punya kind_bits (static/final/const/late/...)
- **Deskripsi**: `FlutterMetaField` (dartmeta.go:59) = `{Name, ByteOffset}`.
  `cluster.FieldInfo` (fill.go:356) punya:
  - `KindBits int32` — bitfield encode: `ConstBit`, `StaticBit`, `FinalBit`,
    `IsLateBit`, `IsExtensionMemberBit`, `IsExtensionTypeMemberBit`,
    `NeedsLoadGuardBit`, `ReflectableBit`, `InitializerChangedAfterInitializationBit`
    (verifikasi: grep MCP `repo:dart-lang/sdk` `StaticBit` →
    `runtime/vm/object.h:4498` `is_static()`, `is_final()`, `is_const()`,
    `is_late()`, dll.).
  - `TypeRefID int` — declared type (ref ke Type object) → bisa resolve ke
    type name. RE-critical untuk "field ini String" vs "field ini int".
  - `InitializerRefID int` — lazy initializer Function ref → bisa resolve ke
    initializer function name. RE-critical untuk "field ini di-init gimana".
  - `HostOffset` — sudah ada (sebagai ByteOffset), TAPI static field punya
    `HostOffset = -1` (fill_scalar_handlers.go:193) — info "static" HILANG
    di `BuildClassLayouts` karena hanya field dengan `HostOffset >= 0` yang
    di-keep (class_layouts.go:37).

  `BuildClassLayouts` (class_layouts.go:36) skip field dengan
  `fi.HostOffset < 0` — yaitu SEMUA static field di-drop. Padahal static
  field RE-critical (global state, lazy init, singleton detection).

- **Bukti SDK**:
  - grep MCP `repo:dart-lang/sdk` `StaticBit` → `runtime/vm/object.h:4493`
    `bool is_static() const { return untag()->kind_bits_.Read<StaticBit>(); }`
    + `FinalBit`, `ConstBit`, `IsLateBit`, `IsExtensionMemberBit`,
    `NeedsLoadGuardBit`, `ReflectableBit`.
  - `cluster/fill.go:360` `KindBits int32` sudah capture dari `ReadTagged32`.
  - `cluster/fill_scalar_handlers.go:193` `isStatic := (state.fieldKindBits>>1)&1 != 0`
    — bit 1 = static, sudah di-decode.
- **Dampak**: Static field tidak muncul di class layout (di-drop). Field
  modifier (final/const/late/extension) tidak muncul. Field type tidak
  muncul. Initializer function tidak muncul. RE tidak bisa bedakan
  `final x = 5` vs `late x` vs `static const x`.
- **Usulan**: Tambah ke `FlutterMetaField`: `IsStatic bool`, `IsFinal bool`,
  `IsConst bool`, `IsLate bool`, `IsExtensionMember bool`, `TypeName string`,
  `InitializerName string`. Untuk static field, gunakan field_id (bukan
  byte_offset) — emit di section terpisah `StaticFields` di class. Decode
  KindBits di `BuildClassLayouts` (bit layout sudah ada di
  `fill_scalar_handlers.go:193`). Destruktif: schema change.
- **Prioritas**: HIGH — static field di-drop entirely, modifier RE-valuable.

### Gap 7: FlutterMetaFunc tidak punya async/return-type/function-kind/type-params
- **Deskripsi**: `FlutterMetaFunc` (dartmeta.go:16) =
  `{Addr, Name, Size, Owner, ParamCount}`. Tapi `decompiler.FuncIR` (ir.go:77)
  punya:
  - `IsAsync bool` (ir.go:295) — async function detection.
  - `IsAsyncStar bool` (ir.go:303) — async* generator.
  - `ReturnType string` (ir.go:327) — recovered return type ("String", "int",
    "void").
  - `TypeParamNames []string` (ir.go:264) — generic type parameter names
    (`<T>`).
  - `FunctionKind` — function kind (getter/setter/constructor/regular/method/
    closure) — sudah di-recover di naming/typetrack.

  `meta_stage.go:38` hanya copy `{Addr, Name, Size, Owner, ParamCount}` dari
  `FuncRecord` — `FuncRecord` (disasm/types.go:4) sendiri juga tidak punya
  async/return-type. Info ada di `FuncIR` (built later) tapi tidak di-merge
  ke meta.

- **Bukti SDK**: N/A (info ini AOTopsy-recovered, bukan SDK field). Tapi
  validitas info: `FuncIR.IsAsync` dideteksi via 6 path (ir.go:288-294
  comment), `ReturnType` dari typetrack inference — sudah verified.
- **Dampak**: `flutter_meta.json` consumer (Ghidra/IDA) tidak tahu fungsi
  mana async (perlu await handling), tidak tahu return type (perlu type
  annotation), tidak tahu generic. Frida tidak tahu function kind untuk
  filter hook.
- **Usulan**: Tambah ke `FlutterMetaFunc`: `IsAsync bool`, `IsAsyncStar bool`,
  `ReturnType string`, `TypeParams []string`, `FunctionKind string`. Merge
  dari `FuncIR` di `meta_stage.go` (perlu cross-reference dengan functions
  by PC). `omitempty` untuk backward-compat. Destruktif: schema change,
  meta_stage perlu akses FuncIR.
- **Prioritas**: MEDIUM — info RE-useful, sudah di-recover tapi tidak di-export.

### Gap 8: Runtime register info (THR/PP/DT/HeapBase/HeaderBit) tidak di strutil
- **Deskripsi**: `frida.FridaMetadata` (frida/export.go:4) punya
  `THRReg`, `PPReg`, `DTReg`, `HeapBaseReg`, `HeaderBitOffset`, `HeaderBitWidth`
  — info register runtime yang arch-specific. Tapi `FlutterMetaJSON`
  (strutil/dartmeta.go:31) TIDAK punya field ini. Schema metadata ter-split:
  - `dart_meta.json` (strutil) — version, ptr size, THR fields.
  - `flutter_meta.json` (strutil) — functions, comments, classes, THR fields.
  - `frida_metadata.json` (frida) — register info, dispatch table, BLR, FFI.

  RE tool yang import `flutter_meta.json` (Ghidra/IDA) tidak dapat register
  info — padahal register info RE-critical untuk interpretasi disassembly
  (THR=x26, PP=x27, DT=x21, heap_base untuk decompress).

- **Bukti SDK**:
  - grep MCP `repo:dart-lang/sdk` `Thread_reg` →
    `runtime/vm/dart/virtual_memory.cc` etc. Register assignment ada di
    `runtime/vm/compiler/backend/arm64/cpu.cc` (THR=R26, PP=R27) dan
    `pkg/native_compiler/lib/back_end/arm64/assembler.dart` (threadReg).
  - AOTopsy `internal/sdk` punya `ARM64ThreadRegStr`, `ARM64PoolRegStr`,
    `ARM64HeapBitsStr`, `X86ThreadRegStr`, `X86PoolRegStr` — sumbernya
    sudah ada.
- **Dampak**: Ghidra/IDA import tidak tahu register convention → analisis
  manual harus re-derive. Tiga file metadata untuk satu binary tidak ideal.
- **Usulan**: Pindahkan `RuntimeRegs` sub-struct ke `FlutterMetaJSON`:
  `{THRReg, PPReg, DTReg, HeapBaseReg, HeaderBitOffset, HeaderBitWidth}`.
  Isi di `meta_stage.go` dari `sdk.*` constants (sama seperti
  `frida_export.go:24-37`). `frida_metadata.json` bisa tetap punya untuk
  backward-compat, atau deprecate. Destruktif: schema change.
- **Prioritas**: MEDIUM — konsolidasi metadata, RE-valuable.

### Gap 9: Stub/entry-point offset table tidak di metadata (hanya THR field names)
- **Deskripsi**: `vmtables` punya `VMStubNames` (stubnames.go:812) —
  ordered VM_STUB_CODE_LIST expansion, dan `extractThreadStubOffsets`
  (extract_thr.go:269) yang extract `*_entry_point_offset` dari SDK. TAPI
  stub offset→name map TIDAK disimpan di `FlutterMetaJSON` / `dart_meta.json`.
  Hanya `THRFields` (data field names) yang di-export.

  Stub offset RE-critical: `BLR [THR+0x...]` sering adalah call ke stub
  (allocate_object, write_barrier, etc.). Tanpa stub offset map, RE tidak
  tahu stub mana yang di-call.

- **Bukti SDK**:
  - `tools/extract_thr.go:269` `extractThreadStubOffsets` sudah filter
    `*_entry_point_offset` dari `runtime_offsets_extracted.h`.
  - `internal/vmtables/stubnames.go:812` `VMStubNames` sudah ada list stub
    name per version.
  - grep MCP `repo:dart-lang/sdk` `Thread_runtime_entry_offset` →
    `pkg/native_compiler/lib/runtime/vm_defs.dart:84` — runtime entry offset
    di-compute dari `Thread_AllocateArray_entry_point_offset + index*wordSize`.
- **Dampak**: `flutter_meta.json` tidak punya stub offset map. Frida THR_FIELDS
  map (script_gen.go:108) hanya berisi THR field names, bukan stub offsets.
  RE tidak bisa resolve `BLR [THR+0x...]` ke stub name tanpa cross-ref manual
  ke `thrfields.go`.
- **Usulan**: Tambah `StubOffsets []FlutterMetaStubOffset` ke `FlutterMetaJSON`:
  `{Offset int, Name string, Kind string}` (kind: "vm_stub"|"runtime_entry"|
  "leaf_runtime_entry"). Isi dari `extractThreadStubOffsets` +
  `runtime_entry_list.h`. Destruktif: schema change, perlu extractor update.
- **Prioritas**: MEDIUM — RE-valuable untuk BLR resolution.

### Gap 10: ObjectStore field count/names tidak di metadata
- **Deskripsi**: `extract_thr.go:1108` `objectStoreFieldCount` sudah verify
  `ObjectStoreAOTFieldCount` per version vs `runtime/vm/object_store.h`.
  TAPI nama field ObjectStore (dan offset) tidak di-export ke metadata.
  ObjectStore root adalah entry pertama di snapshot stream, dan field-nya
  RE-critical (global object table: `true`, `false`, `null`, type-testing
  stubs, etc.).

- **Bukti SDK**:
  - `tools/extract_thr.go:1132` `gh api .../runtime/vm/object_store.h` →
    parse `OBJECT_STORE_FIELD_LIST` macro, dapatkan nama field berurutan.
  - grep MCP `repo:dart-lang/sdk` `OBJECT_STORE_FIELD_LIST` →
    `runtime/vm/object_store.h` define macro dengan R_/RW/CW/FW/ARW_RELAXED/
    LAZY_CORE/LAZY_FFI field kinds.
- **Dampak`: RE tidak tahu ObjectStore layout. Snapshot stream pertama
  (ObjectStore roots) tidak bisa di-annotate. Field `slow_tts_stub_` (yang
  adalah `to_snapshot(kFullAOT)` boundary) tidak visible.
- **Usulan**: Tambah `ObjectStoreFields []FlutterMetaObjectStoreField` ke
  `FlutterMetaJSON`: `{Index int, Name string, Kind string}` (kind dari
  macro: R/RW/CW/FW/LAZY_CORE/LAZY_FFI). Isi dari extractor yang sudah parse
  `object_store.h`. Destruktif: schema change.
- **Prioritas**: LOW — ObjectStore jarang di-access langsung dari disasm,
  lebih relevant untuk snapshot parser (sudah handle di `cluster`).

### Gap 11: SanitizeDartBody tidak handle operator set lengkap + named constructor edge
- **Deskripsi**: `opMethodReplacerDart` (dart_sanitize.go:86) handle 4 operator:
  `.[]=(`, `.[](`, `.[]=`, `.[]`. Tapi Dart punya lebih banyak operator yang
  tidak parse sebagai method call:
  - `operator ==`, `operator <`, `operator >`, `operator <=`, `operator >=`,
    `operator +`, `operator -`, `operator *`, `operator /`, `operator %`,
    `operator ~`, `operator ~/', `operator <<`, `operator >>`, `operator &`,
    `operator |`, `operator ^`, `operator []=`, `operator unary-`, `operator
    call` — verifikasi: grep MCP `repo:dart-lang/sdk` `operator ==` → banyak
    hit di `runtime/vm/object.cc`.
  - `SanitizeDartBody` line 133: `strings.ReplaceAll(body, ".(", "(")` —
    collapse `Name.(` ke `Name(`. TAPI ini juga collapse `obj.method.(` yang
    valid (named constructor `List.from(...)` → `List.from.(`? Tidak —
    `List.from(` valid). Edge case: `ClassName.` tanpa method name setelah
    dot → `ClassName(` (salah, harus skip).

- **Bukti SDK**:
  - grep MCP `repo:dart-lang/sdk` `operator unary-` →
    `runtime/vm/object.cc` banyak definisi operator.
  - Dart language spec: operator yang bisa di-overload ~20+.
- **Dampak`: Pseudocode yang emit `x.==(y)` atau `x.+(y)` tidak di-sanitize
  → tidak parse. Hanya `.[]` family yang di-handle.
- **Usulan**: Generalisasi `opMethodReplacerDart` jadi regex yang map
  `.<op>(` → `.op_<symbol>(` untuk semua operator. Atau emit `x == y` langsung
  (infix) jika memang operator call. Destruktif: rewrite sanitizer operator
  handling. Tambah test dengan semua operator.
- **Prioritas**: MEDIUM — pseudocode operator call tidak parse.

### Gap 12: SanitizeLibraryPath scheme coverage incomplete
- **Deskripsi**: `SanitizeLibraryPath` (dart_sanitize.go:10) handle 3 scheme:
  `package:`, `dart:`, `file:///`. Tapi Dart library URL bisa punya:
  - `dart-ext:` (native extension, deprecated sejak 2.15 tapi masih muncul
    di binary lama) — verifikasi: grep MCP `repo:dart-lang/sdk` `dart-ext:`
    → `pkg/front_end/lib/src/source/fragment_factory_impl.dart:941`.
  - `http:`, `https:` (web import, jarang di AOT tapi possible).
  - `data:` (data URI, jarang).
  - `org-dartlang-sdk:` (internal scheme untuk SDK libraries di beberapa
    tool).
  - `package:` dengan path bersarang (`package:flutter/src/...`) — sudah
    handle via `filepath.Clean`, tapi `:` di tengah path (setelah strip
    scheme) di-replace `/` — bisa corrupt jika ada `:` di nama file (rare).

  Juga: jika URL tidak end dengan `.dart` dan sudah punya extension lain
  (mis. `.g.dart`, `.freezed.dart`), suffix `.dart` di-append →
  `foo.g.dart.dart`. Bug: `strings.HasSuffix(url, ".dart")` check tidak
  handle multi-extension.

- **Bukti SDK**:
  - grep MCP `repo:dart-lang/sdk` `dart-ext:` → native extension scheme
    masih di-handle parser (`fragment_factory_impl.dart:941`).
  - `pkg/analyzer/lib/src/dart/analysis/library_analyzer.dart:715`
    `selectedUriStr.startsWith('dart-ext:')`.
- **Dampak`: Library URL `dart-ext:foo` → `dart-ext/foo.dart` (salah, harus
  `dart-ext/foo` atau skip). Multi-extension `.g.dart` → `.g.dart.dart`.
  Path file export salah.
- **Usulan**: Tambah `dart-ext:`, `http:`, `https:`, `data:`,
  `org-dartlang-sdk:` strip. Fix multi-extension: check `strings.HasSuffix(
  url, ".dart")` setelah clean, bukan sebelum. Tambah test dengan semua
  scheme + multi-extension. Destruktif: rewrite scheme handling.
- **Prioritas**: LOW — `dart-ext:` deprecated, multi-extension rare.

## Register Tracking Gaps

`internal/strutil` TIDAK track register secara langsung — itu domain
`internal/sdk`, `internal/disasm`, `internal/typetrack`. Tapi strutil define
metadata schema yang SEHARUSNYA carry register info untuk consumer RE, dan
saat ini TIDAK (Gap 8). Detail:

| Register | ARM64 | x86_64 | Ada di sdk? | Ada di FlutterMetaJSON? | Ada di FridaMetadata? |
|----------|-------|--------|-------------|-------------------------|------------------------|
| THR      | x26   | r14    | YES (`ARM64ThreadRegStr`) | NO | YES (`THRReg`) |
| PP       | x27   | r15    | YES (`ARM64PoolRegStr`) | NO | YES (`PPReg`) |
| DT       | x21   | rax    | hardcoded di frida_export | NO | YES (`DTReg`) |
| HeapBase | (via HEAP_BITS shift) | rbp | YES (`ARM64HeapBitsStr`) | NO | YES (`HeapBaseReg`) |
| NULL     | x22   | (pool) | YES (FuncIR.NullReg) | NO | NO |
| CODE     | x24   | r12    | YES (FuncIR.CodeReg) | NO | NO |
| ARGS_DESC| x4    | r10    | YES (FuncIR.ArgsDescReg) | NO | NO |
| HEAP_BITS| x23   | (n/a)  | YES (FuncIR.HeapBitsReg) | NO | NO |

Gap:
1. **NULL/CODE/ARGS_DESC/HEAP_BITS register tidak di FridaMetadata maupun
   FlutterMetaJSON** — padahal RE-critical untuk interpretasi disassembly
   (NULL_REG read = literal null, CODE_REG = current Code, HEAP_BITS =
   decompression marker).
2. **DTReg hardcoded** di `frida_export.go:28` (`dtReg := "rax"` / `"x21"`)
   — bukan dari `sdk` constant. Jika convention berubah (Dart version baru),
   silent wrong.
3. **HeaderBitOffset/HeaderBitWidth** di FridaMetadata tapi tidak di
   FlutterMetaJSON — Ghidra/IDA import tidak tahu class ID bit layout di
   object header.

## Fitur RE Missing/Incomplete

1. **Dart keyword list generated from SDK** — `DartReservedWords` hand-rolled,
   drift dari SDK. Harusnya generate dari `token.dart` (Gap 1).
2. **THR field category** — stub/entry_point/data (Gap 4).
3. **Class inheritance graph** — SuperClass, LibraryURL (Gap 5).
4. **Class TypeArguments offset** — untuk baca reified generics runtime (Gap 5).
5. **Unboxed field bitmap** — bedakan raw word vs ref field (Gap 5).
6. **Field modifier** — static/final/const/late/extension (Gap 6).
7. **Field declared type** — TypeName (Gap 6).
8. **Field initializer** — InitializerName (Gap 6).
9. **Static field** — di-drop entirely di BuildClassLayouts (Gap 6).
10. **Function async/return-type/kind/type-params** — sudah recover, tidak
    export (Gap 7).
11. **Runtime register info** di FlutterMetaJSON — THR/PP/DT/HeapBase/
    NULL/CODE/ARGS_DESC/HEAP_BITS (Gap 8 + Register Tracking).
12. **Stub offset map** — stub name per THR offset (Gap 9).
13. **ObjectStore field map** — nama field ObjectStore (Gap 10).
14. **Operator call sanitizer lengkap** — hanya `.[]` family (Gap 11).
15. **Library URL scheme coverage** — `dart-ext:`, multi-extension (Gap 12).
16. **AsmCommentRe lock ke format internal** — fragil, skip `<...>` comment
    yang valuable (Gap 3).
17. **ParseHexAddr error reporting** — silent 0 (Gap 2).

## Verifikasi SDK

Verifikasi dilakukan via dua channel sesuai rule:

### grep MCP (`searchGitHub` by Vercel, `repo: "dart-lang/sdk"`)
- `Thread_(\\w+)_offset` → `pkg/native_compiler/lib/runtime/vm_offsets.g.dart`
  (120+ Thread field getter), `runtime/vm/compiler/runtime_offsets_list.h`
  (FIELD(Thread, ...) list), `runtime/vm/compiler/runtime_api.h` (declaration).
- `kNonNullableBit` → `runtime/vm/object.h:8979` (TypeArguments nullability,
  context untuk bitfield pattern).
- `StaticBit` → `runtime/vm/object.h:4493-4498` (`is_static()`, `is_final()`,
  `is_const()`, `is_late()`, `is_extension_member()`, `needs_load_guard()`,
  `is_reflectable()` — Field kind_bits_ bitfield).
- `super_type() const` → `runtime/vm/object.h:1465` (Class super_type getter).
- `BUILT_IN_IDENTIFIER` → `tests/language/identifier/built_in_illegal_test.dart`
  (built-in keyword tidak boleh declaration name).
- `Keyword.ABSTRACT` → `pkg/_fe_analyzer_shared/lib/src/scanner/token.dart`
  (keyword list), `pkg/front_end/test/token_test.dart:80` (`builtInKeywords`
  set).
- `class Function {}` → `pkg/analyzer/test/src/diagnostics/built_in_identifier_as_type_name_test.dart`
  (`Function` built-in, tidak boleh type name).
- `dart-ext:` → `pkg/front_end/lib/src/source/fragment_factory_impl.dart:941`
  (native extension scheme masih di-handle).
- `operator unary-` → `runtime/vm/object.cc` (operator overload set).

### `gh api` @ version tag
- `repos/dart-lang/sdk/contents/runtime/vm/compiler/runtime_offsets_list.h?ref=3.9.2`
  → 120 `FIELD(Thread, ...)` entries (stub/entry_point/data).
- `repos/dart-lang/sdk/contents/pkg/_fe_analyzer_shared/lib/src/scanner/token.dart?ref=3.9.2`
  → 73 keyword dengan KeywordStyle (reserved/builtIn/pseudo), parsed via
  Python regex → mapping lengkap (lihat Gap 1).
- `repos/dart-lang/sdk/contents/tests/language/identifier/built_in_illegal_test.dart?ref=3.9.2`
  → konfirmasi built-in keyword illegal sebagai declaration name: abstract,
  as, dynamic, export, external, factory, get, interface, implements, import,
  mixin, library, operator, part, set, static, typedef.
- `repos/dart-lang/sdk/contents/runtime/vm/object_store.h?ref=3.9.2` (via
  `extract_thr.go:1132` reference) → OBJECT_STORE_FIELD_LIST macro dengan
  R_/RW/CW/FW/ARW_RELAXED/LAZY_CORE/LAZY_FFI field kinds.

### Catatan verifikasi
- Tidak ada `path` filter di grep MCP query (sesuai rule).
- `gh api` pakai `Accept: application/vnd.github.raw` header.
- Tag utama: 3.9.2 (ARM64 + x64, compressed + non-compressed). Cross-check
  3.12.2 untuk keyword list (Dart 3.6+ `augment` keyword) — `augment` muncul
  di token.dart @3.9.2 juga (KeywordStyle.builtIn).
