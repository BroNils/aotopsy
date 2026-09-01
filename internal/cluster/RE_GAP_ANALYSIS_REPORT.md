# RE Gap Analysis Report: internal/cluster

> **STATUS VERIFIKASI (2026-09-01)** — report ini sudah diadu dengan kode nyata
> + SDK (`gh api` @tag). Detail: `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> Koreksi untuk folder ini:
> - **Gap 1 (`is_static` misread 2.12–2.18) → SALAH.** `kKindTagSize` adalah
>   literal **5** di 2.10/2.12/2.13/2.15/2.17.6/2.18/2.19 (`object.h`, blok
>   `enum KindTagBits`), bukan turunan `BitLength(kinds)`. Jadi
>   `kModifierPos=14`, `kModifierSize=2`, `kStaticBit=**16**` di SEMUA versi
>   2.10–3.13 (dikonfirmasi juga oleh `Function_kStaticBitPos => 0x10` di
>   `pkg/native_compiler/lib/runtime/vm_offsets.g.dart`). `(kindTag>>16)&1`
>   sudah benar; tidak ada 7 versi yang rusak.
> - **Gap 3 (CSM decoder tidak dipanggil) → STALE.** Bukan di `ReadFill`, tapi
>   `DecodeCompressedStackMaps` dipanggil di `internal/analysis/context.go:386`
>   dan hasilnya masuk `fir.StackMaps` (`context.go:564-565`).
> - **Gap 5** — posisi `ModifierBits` TIDAK version-dependent: `kModifierPos=14`
>   di semua versi, jadi `(kindTag>>14)&3` cukup.

## Ringkasan

Folder `internal/cluster` (24 file non-test, ~7400 LOC) mengimplementasikan
deserialization Dart AOT clustered snapshot — membaca alloc section (cluster
tags + per-cluster alloc metadata) dan fill section (per-object field data)
untuk seluruh object types: Class, Function, Code, Field, Type, FunctionType,
TypeParameter, Closure, ClosureData, ObjectPool, Array, TypeArguments, Record,
PcDescriptors, CodeSourceMap, CompressedStackMaps, ExceptionHandlers, Instance,
dll. Output: `cluster.Result` berisi Strings, Named, FuncTypes, Classes, Types,
Fields, Codes, Arrays, Pool, Instances, PcDescriptors, CodeSourceMaps,
Closures, FfiTrampolines, dll.

Analisis ini membandingkan kode AOTopsy vs Dart SDK source (via grep MCP +
`gh api` @ version tags 2.10.0, 2.12.0, 2.13.0, 2.14.0, 2.17.6, 2.18.0, 2.19.0,
3.0.5, 3.5.0, 3.9.2, 3.12.2, 3.13.0) dan menemukan **11 gap** — 1 bug
fungsional (is_static misread untuk 2.12-2.18), 4 cluster/field yang
di-skip padahal bisa dimanfaatkan untuk RE, 3 data snapshot yang dibaca tapi
tidak diekspos ke consumer, dan 3 fitur RE useful yang incomplete.

## Struktur Folder

```
internal/cluster/
├── cluster.go              — ScanClusters: header + alloc tag loop, Result struct
├── cluster_alloc.go        — skipAllocV: per-CID alloc skip (count, lengths, canonical set)
├── cid.go                  — CID constants, ClassifyAlloc, CidNameV, DecodeTags
├── fillspec.go             — FillKind, FillSpec, GetFillSpec dispatch, per-CID spec functions
├── fill.go                 — ReadFill: main fill loop, ROData extraction, dataImageObjStart
├── fill_refs.go            — readFillRefs: generic FillRefs handler (Function, Type, Field, ICData, ...)
├── fill_class.go           — readFillClass, readFillField, skipFillDouble
├── fill_code.go            — readFillCode: Code fill (instructions + refs + state_bits)
├── fill_instance.go        — readFillInstance: Instance fill (unboxed bitmap + field refs)
├── fill_misc.go            — readFillArray, readFillExceptionHandlers, readFillContext, readFillTypeArguments, skipFillRecord, skipFillTypedData, skipFillContextScope
├── fill_pool.go            — readFillObjectPool: ObjectPool entry decode
├── fill_scalar_handlers.go — readFunctionScalar, readFuncTypeScalar, readFieldScalar, readTypeScalar, readScriptScalar, readLoadingUnitScalar, readFfiTrampolineScalar
├── fill_strings.go         — readFillStrings, extractRODataStrings
├── dispatchtable.go        — ParseDispatchTable: roots section + dispatch table RLE
├── instrtable.go           — ParseInstructionsTable, ResolveCodeRanges, ResolveStubRanges
├── pcdescriptors.go        — DecodePcDescriptors, BuildTryRegions, ExpandOuterTryRegions, extractRODataPcDescriptors
├── codesourcemap.go        — DecodeCodeSourceMap, CodeSourceMapInfo
├── compressedstackmaps.go  — DecodeCompressedStackMaps (decoder ada, tapi tidak dipanggil di fill)
├── funckind.go             — FunctionKind decode dari kind_tag_ (per-version ordinal table)
├── ffitrampoline.go        — FfiTrampolineInfo struct + FfiKindString
├── range.go                — FindRangeContainingVA
└── testdata/corpus/        — golden JSON per Dart version × arch
```

## Gap Analysis

### Gap 1: `is_static` bit misread untuk Dart 2.12-2.18 (BUG fungsional)

> **[REFUTED 2026-09-01]** Premis "KindBits = BitLength(kLastFunctionKind)"
> salah: SDK memakai literal `kKindTagSize = 5` di seluruh 2.10–2.19
> (diverifikasi `gh api runtime/vm/object.h?ref=<tag>` untuk 2.10.0, 2.12.0,
> 2.13.0, 2.15.0, 2.17.6, 2.18.0, 2.19.0), dan 3.9.2+ memakai
> `kKindBitSize = Utils::BitLength(kRecordFieldGetter)` = 5. StaticBit selalu
> di bit 16. Kode saat ini benar — jangan diubah.
> Catatan tambahan: klaim dampak "receiver seeding salah" juga tidak berlaku —
> `IsStatic` hanya dikonsumsi `naming/pool.go:216` untuk `ParamCount`;
> `FuncReceiverStackSlot` diambil dari `FixedParamsWithReceiver`.

- **Deskripsi**: `readFunctionScalar` (`fill_scalar_handlers.go:117`) membaca
  `state.isStatic = (kindTag>>16)&1 == 1` — hardcoded shift 16. Posisi
  `StaticBit` di `kind_tag_` tergantung pada width `KindBits` +
  `RecognizedBits` + `ModifierBits` (object.h @3.12.2:
  `StaticBit = BitField<..., bool, ModifierBits::kNextBit + kStaticBit>`).
  `KindBits` width = `Utils::BitLength(kLastFunctionKind)`:
  - 2.10.0: 17 kinds → 5 bits → StaticBit di bit 16 ✓
  - 2.12.0-2.18.0: 16 kinds → 4 bits → StaticBit di bit **15** ✗
  - 2.19.0+: 17 kinds → 5 bits → StaticBit di bit 16 ✓
  `RecognizedBits` = 9 bits di semua versi yang diperiksa (383-493 recognized
  methods, semua > 256). `ModifierBits` = 2 bits (`kAsyncModifierBitSize =
  BitLength(kAsyncGen=3) = 2`). Jadi untuk 2.12-2.18, bit 16 yang dibaca
  AOTopsy adalah `kConstBit` (ModifierBits::kNextBit + 1), BUKAN
  `kStaticBit`.
- **Bukti SDK**:
  - `gh api ... raw_object.h @3.12.2` line 1430-1469: `kKindBitSize =
    BitLength(kRecordFieldGetter)` — 17 kinds, 5 bits.
  - `gh api ... raw_object.h @2.12.0`: 16 kinds (no RecordFieldGetter), 4 bits.
  - `gh api ... object.h @3.12.2` line 4257: `V(Static, is_static)` adalah
    flag pertama setelah ModifierBits.
  - `gh api ... recognized_methods_list.h @2.12.0`: 386 entries →
    RecognizedBits = 9.
- **Dampak**: Untuk Dart 2.12-2.18, `NamedObject.IsStatic` salah untuk
  seluruh populasi Function. `is_static=true` dibaca sebagai `is_const=true`.
  Konsekuensi:
  1. Receiver seeding: static method tidak punya receiver, tapi AOTopsy
     mengira instance method → seed `this` dari owning class → fabricated
     type untuk static methods.
  2. `NumFixedParams` INCLUDES receiver untuk instance method — jika
     is_static salah, pengurangan implicit receiver salah.
  3. FuncKind classification tidak terpengaruh (kind bits di bit 0-4, benar).
- **Usulan**: Ganti hardcoded `>>16` dengan versi-dependent shift:
  `FuncPackedFieldsLayout` sudah ada (`fillspec.go:1159`), tapi hanya untuk
  `packed_fields_` (2.x), bukan `kind_tag_`. Tambahkan `KindTagStaticShift`
  ke `VersionProfile` atau derive dari `FuncPackedFieldsLayout`:
  - 2.10.0, 2.19.0+: shift 16
  - 2.12.0-2.18.0: shift 15
  Atau lebih robust: baca via `KindBits::bitsize() + RecognizedBits::bitsize()
  + ModifierBits::bitsize()` yang sudah diketahui per versi.
- **Prioritas**: TINGGI — bug fungsional yang menyebabkan type inference
  salah untuk 7 versi Dart (2.12-2.18), termasuk seluruh Flutter 2.0-3.3.

### Gap 2: Record cluster fill di-skip, shape & field refs tidak ditangkap

- **Deskripsi**: `skipFillRecord` (`fill_misc.go:322`) membaca `ReadUnsigned(shape)`
  + `num_fields × ReadRef(field)` tapi membuang keduanya. Tidak ada
  `RecordInfo` struct di `Result`. Padahal SDK
  (`RecordDeserializationCluster::ReadFill @3.12.2` line 5725-5738) membaca
  `shape` (yang berisi num_fields + positional/named flag + is_const info
  via `RecordShape`) dan N field refs yang bisa resolve ke Type/Instance/
  Closure object lain.
- **Bukti SDK**: `gh api ... app_snapshot.cc @3.12.2` line 5725:
  ```cpp
  const intptr_t shape = d.ReadUnsigned();
  const intptr_t num_fields = RecordShape(shape).num_fields();
  record->untag()->shape_ = Smi::New(shape);
  for (intptr_t j = 0; j < num_fields; ++j) {
    record->untag()->data()[j] = d.ReadRef();
  }
  ```
- **Dampak**: Record adalah Dart 3.0+ feature (records `(1, "a", x: 2)`).
  Tanpa capture:
  1. Record constant values tidak bisa di-resolve — RE tidak tahu record
     field values di object pool atau static fields.
  2. `RecordShape` berisi info named vs positional fields — berguna untuk
     reconstruct record type di decompiler.
  3. Field refs bisa ke Type/Closure/Instance — link graph hilang.
- **Usulan**: Tambah `RecordInfo { RefID, Shape, FieldRefs []int }` ke
  `Result`. Capture di `ReadFill` FillRecord case (ganti `skipFillRecord`
  dengan `readFillRecord`). Decode `RecordShape` (lower 16 bits = num_fields,
  bit 16+ = named flag, dll — per `object.h RecordShape`).
- **Prioritas**: SEDANG — Record adalah fitur Dart 3.0+ yang increasingly
  common; tanpa ini record constants tidak bisa di-RE.

### Gap 3: CompressedStackMaps decoder ada tapi tidak pernah dipanggil

> **[STALE 2026-09-01]** Benar bahwa `ReadFill` hanya menyimpan payload mentah,
> tapi decoder-nya **dipakai** satu lapis di atas:
> `internal/analysis/context.go:365-390` membangun `csmByRef`, mendeteksi
> `GlobalTableBit`, memanggil `cluster.DecodeCompressedStackMaps`, dan
> menyimpan hasilnya ke `Enrichment.DecodedStackMapsByCodeRef` → `fir.StackMaps`
> (`context.go:564`). Jadi dampak "decompiler tidak tahu register mana yang
> live" tidak berlaku. Yang tersisa cuma preferensi arsitektur (decode di
> cluster vs di analysis).

- **Deskripsi**: `DecodeCompressedStackMaps` (`compressedstackmaps.go:72`)
  adalah decoder lengkap untuk CSM payload (standalone, table-referencing,
  global table). Tapi `ReadFill` (`fill.go:611-618`) hanya menyimpan raw
  `Payload []byte` ke `CompressedStackMapsInfo` — tidak pernah memanggil
  decoder. `Result.CompressedStackMaps` berisi raw bytes tanpa decoded
  `StackMapEntry`.
- **Bukti SDK**: `compressedstackmaps.go` comment block line 1-31 sudah
  verifikasi format via `gh api ... raw_object.h @3.12.2`. Decoder
  `DecodeCompressedStackMaps` sudah ada dan benar.
- **Dampak**: CompressedStackMaps adalah satu-satunya sumber info register
  liveness di safepoints untuk AOT. Tanpa decode:
  1. Decompiler tidak tahu register mana yang live object pointer vs scratch
     di safepoint — bisa salah interpretasi register value.
  2. GC root scanning info hilang — tidak bisa verifikasi bahwa spill slot
     tertentu hold object reference.
  3. Info ini juga bisa bantu type inference: jika register X live sebagai
     object pointer di safepoint, kemungkinan besar itu receiver/argument
     yang relevan.
- **Usulan**: Di `ReadFill` FillInlineBytes case untuk CompressedStackMaps,
  panggil `DecodeCompressedStackMaps(p, globalTablePayload)` dan simpan
  `[]StackMapEntry` di `CompressedStackMapsInfo`. Tantangan: global table
  CSM adalah object terpisah (GlobalTableBit=true) — perlu lookup table
  global dulu sebelum decode table-referencing CSM. Tapi decoder sudah
  handle ini via parameter `globalTable []byte`.
- **Prioritas**: SEDANG — decoder sudah ada, tinggal wiring. RE value:
  register liveness untuk decompiler quality.

### Gap 4: FunctionType `packed_type_parameter_counts_` tidak dibaca

- **Deskripsi**: `specFunctionType` (`fillspec.go:489`) untuk v2.14+ membaca
  3 scalars: `OpUint8` (combined), `OpTagged32` (packed_parameter_counts),
  `OpTagged32` (packed_type_parameter_counts). Tapi `readFuncTypeScalar`
  (`fill_scalar_handlers.go:139`) hanya handle `si == 1`
  (packed_parameter_counts) — `si == 2` (packed_type_parameter_counts)
  jatuh ke `skipScalar`, valuenya dibuang.
  `packed_type_parameter_counts_` berisi `PackedNumParentTypeArguments`
  (bits 0-7) dan `PackedNumTypeParameters` (bits 8-15) — info berapa type
  parameter parent yang di-inherit + berapa type parameter sendiri.
- **Bukti SDK**: `gh api ... raw_object.h @3.12.2` line 3043-3050:
  ```cpp
  using PackedNumParentTypeArguments =
      BitField<decltype(packed_type_parameter_counts_), uint8_t>;
  using PackedNumTypeParameters =
      BitField<decltype(packed_type_parameter_counts_),
               uint8_t, PackedNumParentTypeArguments::kNextBit>;
  ```
  Dan `specFunctionType` comment line 491: "Read<uint16_t>(packed_type_parameter_counts)".
- **Dampak**: Untuk generic function seperti `void runUnaryGuarded<T>(...)`,
  AOTopsy capture `TypeParamsRefID` (ref ke TypeParameters object) yang
  sudah berisi names. Tapi `packed_type_parameter_counts_` memberi info
  berapa type parameter dari parent vs sendiri — berguna untuk reconstruct
  `<T extends Parent<S>>` dengan benar. Tanpa ini, decompiler tidak tahu
  berapa type arg parent yang di-inherit.
- **Usulan**: Tambah field `NumParentTypeArgs int` dan `NumTypeParams int`
  ke `FuncTypeInfo`. Di `readFuncTypeScalar` si==2, decode
  `packed_type_parameter_counts_` dan simpan.
- **Prioritas**: RENDAH-SEDANG — TypeParameters ref sudah capture names;
  ini info tambahan untuk precision.

### Gap 5: Function `ModifierBits` (async/sync*/async*) tidak ditangkap

- **Deskripsi**: `kind_tag_` berisi `ModifierBits` (2 bits:
  `AsyncModifier`: kNoModifier=0, kAsync=1, kSyncGen=2, kAsyncGen=3) yang
  menandai function sebagai `async`, `sync*`, `async*`, atau none.
  AOTopsy membaca `kind_tag_` tapi hanya extract `KindBits` (function kind)
  dan `StaticBit`. `ModifierBits` di-buang.
- **Bukti SDK**: `gh api ... raw_object.h @3.12.2` line 1461-1469:
  ```cpp
  enum AsyncModifier {
    kNoModifier = 0x0, kAsyncBit = 0x1, kGeneratorBit = 0x2,
    kAsync = kAsyncBit, kSyncGen = kGeneratorBit, kAsyncGen = kAsyncBit | kGeneratorBit,
  };
  ```
  Posisi: setelah KindBits + RecognizedBits (bit 14-15 untuk 3.12.2).
- **Dampak**: Decompiler tidak bisa reconstruct `async`/`sync*`/`async*`
  modifier di function signature. Untuk RE Flutter app yang heavy async
  (Future, Stream), ini info penting — `Future foo()` vs
  `Future foo() async` vs `Stream foo() sync*` punya semantics berbeda.
  AGENTS.md sendiri menyebut "P7 async detection" sebagai feature yang
  penting.
- **Usulan**: Tambah `AsyncModifier uint8` ke `NamedObject` (atau
  `FuncTypeInfo`). Decode dari `kind_tag_`:
  `modifier = (kindTag >> (KindBits_width + RecognizedBits_width)) & 0x3`.
  Posisi shift versi-dependent (sama seperti Gap 1).
- **Prioritas**: SEDANG — async modifier adalah info semantic penting untuk
  decompiler output quality.

### Gap 6: ObjectPool `SnapshotBehavior` tidak diekspos ke consumer

- **Deskripsi**: `PoolEntry` (`cluster.go:97`) hanya punya `Kind`
  (PoolTagged/PoolImmediate/PoolNative/PoolEmpty) + `RefID`/`Imm`. Tapi
  SDK `ObjectPool::SnapshotBehavior` (3 bits di entry_bits) membedakan:
  - `kResetToBootstrapNative`: runtime di-set ke CallBootstrapNative stub
  - `kResetToSwitchableCallMissEntryPoint`: runtime di-set ke
    SwitchableCallMiss entrypoint (ini adalah polymorphic call site yang
    belum di-resolve)
  - `kSetToZero`: di-zero saat deserialisasi (unused slot)
  AOTopsy lump semua ini ke `PoolEmpty`, kehilangan distinguisi.
- **Bukti SDK**: `gh api ... object_pool_builder.h @3.12.2` line 29-50:
  ```cpp
  enum SnapshotBehavior {
    kSnapshotable, kNotSnapshotable, kResetToBootstrapNative,
    kResetToSwitchableCallMissEntryPoint, kSetToZero,
  };
  ```
  `gh api ... app_snapshot.cc @3.12.2` line 3303-3325: switch pada
  snapshot_behavior menentukan runtime value.
- **Dampak**:
  1. `kResetToSwitchableCallMissEntryPoint` entries adalah call sites yang
     runtime akan di-resolve via inline cache — RE bisa identifikasi
     "polymorphic call site yang belum devirtualized" dari pool.
  2. `kResetToBootstrapNative` entries adalah native method call sites —
     RE bisa tahu ini native dispatch, bukan Dart-to-Dart.
  3. Tanpa distinguisi, consumer tidak tahu apakah `PoolEmpty` adalah
     "unused slot" vs "polymorphic call site" vs "native stub".
- **Usulan**: Tambah `SnapshotBehavior uint8` ke `PoolEntry`. Decode dari
  `entry_bits >> 5` (3 bits). Ekspos konstanta
  `PoolSnapshotable=0, PoolResetToBootstrap=2, PoolResetToSwitchableMiss=3,
  PoolSetToZero=4`.
- **Prioritas**: SEDANG — info ini langsung membantu call site
  classification & native call identification.

### Gap 7: CodeSourceMap `kChangePosition` decode salah (relative vs absolute)

- **Deskripsi**: `DecodeCodeSourceMap` (`codesourcemap.go:137`) handle
  `CSMChangePosition` dengan `tokenPos = arg` — menetapkan absolute. Tapi
  SDK `CodeSourceMapReader::GetInlinedFunctionsAt` (`code_descriptors.cc`
  @3.12.2 line 596) melakukan:
  ```cpp
  token_positions->Last() = TokenPosition::Deserialize(
      Utils::AddWithWrapAround(arg, old_token.Serialize()));
  ```
  Yaitu `tokenPos = Deserialize(arg + old_token.Serialize())` — RELATIVE
  delta dari previous token position, bukan absolute.
- **Bukti SDK**: `gh api ... code_descriptors.cc @3.12.2` line 596-601:
  ```cpp
  case CodeSourceMapOps::kChangePosition: {
    const TokenPosition& old_token = token_positions->Last();
    token_positions->Last() = TokenPosition::Deserialize(
        Utils::AddWithWrapAround(arg, old_token.Serialize()));
    break;
  }
  ```
- **Dampak**: Setelah `kChangePosition`, `CSMEntry.TokenPos` salah —
  seharusnya `prev + arg`, bukan `arg`. Untuk CSM dengan multiple
  ChangePosition ops, token position drift semakin jauh. Konsekuensi:
  1. Inline frame source position salah — tidak bisa map PC ke source
     location dengan benar.
  2. `CodeSourceMapInfo.InlineStackAt` mengembalikan `tokenPos` yang salah.
  3. Untuk non-PRODUCT build dengan line_starts, file:line recovery akan
     salah total.
  Note: comment di `codesourcemap.go:52-69` sudah bilang "PC -> file:line
  is IMPOSSIBLE for a release build" karena Script hanya serialize url.
  Tapi token position masih berguna untuk relative ordering & non-PRODUCT
  input.
- **Usulan**: Track `tokenPos` sebagai running sum. Di `CSMChangePosition`:
  `tokenPos = TokenPosition.Deserialize(tokenPos.Serialize() + arg)`.
  Initial value = `kDartCodePrologue` (-12), bukan `CSMNoPosition` (-1).
- **Prioritas**: SEDANG — bug correctness, tapi dampak praktis terbatas
  karena Script line_starts tidak ada di PRODUCT AOT. Masih penting untuk
  inline frame ordering.

### Gap 8: CodeSourceMap root function tidak di-push ke inline stack

- **Deskripsi**: `DecodeCodeSourceMap` (`codesourcemap.go:109`) mulai dengan
  `stack := []int32{}` (empty). Tapi SDK
  `CodeSourceMapReader::GetInlinedFunctionsAt` (line 590-591) mulai dengan:
  ```cpp
  function_stack->Add(&root_);
  token_positions->Add(InitialPosition());
  ```
  Root function (inline_id 0 = function itself) selalu di stack dari awal.
  AOTopsy tidak push root, jadi `CSMEntry.InlineStack` empty berarti "di
  function body" — tapi SDK menganggap stack selalu minimal [root].
- **Bukti SDK**: `gh api ... code_descriptors.cc @3.12.2` line 590-591.
  `root_` adalah `Function::Handle(zone, Function::RawCast(functions_.At(0)))`
  — function ke-0 di `inlined_id_to_function` array = function yang punya
  Code ini.
- **Dampak**: Consumer yang mengharapkan `InlineStack[0]` = root function
  (matching `CodeEntry.InlinedFuncsRef` array index 0) akan salah.
  AOTopsy return empty stack untuk "di function body", SDK return [0].
  Untuk RE, ini inconsistency: jika consumer mau tahu "function apa yang
  active di PC X", AOTopsy return [] (perlu special-case "empty = root"),
  SDK return [root_id].
- **Usulan**: Push `0` ke stack sebelum loop. Atau dokumentasikan konvensi
  AOTopsy (empty = root) dan pastikan consumer aware. Lebih robust: ikuti
  SDK, push root.
- **Prioritas**: RENDAH — cosmetic consistency, tidak break analysis.

### Gap 9: `Instance` fill — unboxed field raw value tidak ditangkap

- **Deskripsi**: `readFillInstance` (`fill_instance.go:129-136`) untuk
  unboxed field hanya `ReadTagged32` × 2 (lo + hi) dan `continue` —
  value dibuang. `InstanceInfo.Fields` hanya berisi pointer field refs.
  Padahal unboxed field berisi raw value: Smi, double, int64, float, dll.
  Untuk Instance subclass yang punya unboxed field (e.g. `Point` dengan
  `double x, y`), value tersebut hilang.
- **Bukti SDK**: `gh api ... app_snapshot.cc @3.12.2` InstanceSerializationCluster
  WriteFill: `WriteWordWith32BitWrites(value)` untuk unboxed slot.
  ReadFill: `ReadWordWith32BitReads()` untuk unboxed slot.
- **Dampak**:
  1. Instance constant values dengan unboxed field (e.g. `Duration` dengan
     int64 microseconds, `Offset` dengan double) tidak bisa di-RE.
  2. Static field yang hold Instance dengan unboxed data — value hilang.
  3. Untuk app yang punya config object dengan numeric fields, RE tidak
     bisa recover config values.
- **Usulan**: Tambah `UnboxedFields []InstanceUnboxedField` ke
  `InstanceInfo`. Capture `(ByteOffset, RawValue uint64)` untuk unboxed
  slot. Value = `ReadTagged32(lo) | ReadTagged32(hi) << 32`.
  Consumer bisa interpretasi berdasarkan field type (dari Class field
  layout + Type ref).
- **Prioritas**: SEDANG — Instance constant recovery adalah use case RE
  yang umum (config, default values, enum-like objects).

### Gap 10: `TypedData` fill — raw bytes di-skip, content hilang

- **Deskripsi**: `skipFillTypedData` (`fill_misc.go:137`) membaca
  `ReadUnsigned(length)` + `Skip(length * elemSize)` — content bytes
  dibuang. Tidak ada `TypedDataInfo` di `Result`. Padahal TypedData
  (Uint8List, Int32List, Float64List, dll) sering hold constant data:
  lookup tables, encoded strings, crypto keys, image bytes, dll.
- **Bukti SDK**: `gh api ... app_snapshot.cc @3.12.2` TypedDataDeserializationCluster
  ReadFill: `ReadBytes(cdata, length * element_size)`.
- **Dampak**:
  1. `Uint8List` constant (e.g. base64-decoded data, lookup table) tidak
     bisa di-RE.
  2. `String` yang di-encode sebagai `Uint8List` (obfuscation technique)
     tidak terdeteksi.
  3. Crypto key material yang disimpan sebagai `Uint8List` constant hilang.
- **Usulan**: Tambah `TypedDataInfo { RefID, CID, Length, Data []byte }`
  ke `Result`. Capture raw bytes di fill. Untuk large TypedData, mungkin
  batasi capture size (e.g. first 4KB) untuk avoid memory blowup.
- **Prioritas**: SEDANG — TypedData constant adalah vector obfuscation &
  data embedding yang umum di Flutter app.

### Gap 11: `Map`/`Set`/`ConstMap`/`ConstSet` fill — hanya skip refs, tidak capture key-value

- **Deskripsi**: `specMap`/`specSet` (`fillspec.go:583-596`) membaca 5 refs
  (type_arguments, hash_mask, data, used_data, deleted_keys) tapi tidak
  capture ke structured type. `readFillRefs` treat sebagai generic FillRefs
  — refs masuk `allRefs` tapi tidak ada `MapInfo`/`SetInfo` di `Result`.
  Padahal `data` ref points ke Array of key-value pairs — bisa resolve ke
  actual map entries via `ArrayInfo.ElementRefIDs`.
- **Bukti SDK**: `gh api ... raw_object.h @3.12.2` UntaggedLinkedHashBase:
  `type_arguments_, hash_mask_, data_, used_data_, deleted_keys_`.
  `data_` adalah Array berisi [key1, value1, key2, value2, ...] (interleaved).
- **Dampak**:
  1. `ConstMap` constant (e.g. `{"key": value}`) tidak bisa di-RE —
     key-value mapping hilang.
  2. Config map, enum lookup, i18n string map — semua hilang.
  3. `data` ref bisa di-resolve via `ArrayInfo`, tapi tidak ada wiring
     dari Map ref → data Array ref → entries.
- **Usulan**: Tambah `MapInfo { RefID, TypeArgsRef, DataRef }` ke `Result`.
  Capture di `readFillRefs` untuk CID Map/ConstMap/Set/ConstSet (tambah
  `isMap` flag seperti `isClosure`). Consumer resolve `DataRef` →
  `ArrayInfo.ElementRefIDs` → key-value pairs (interleaved for Map).
- **Prioritas**: SEDANG — Map/Set constant adalah data structure yang
  common di config & lookup table.

## Register Tracking Gaps

Istilah "register tracking" di konteks cluster = field/ref yang dibaca dari
stream tapi tidak ditrack (dibuang/skip). Ditemukan:

| Gap | Field yang dibuang | Dampak |
|-----|-------------------|--------|
| 1 | `StaticBit` kind_tag_ (misread untuk 2.12-2.18) | is_static salah → receiver seeding salah |
| 4 | `packed_type_parameter_counts_` FunctionType | NumParentTypeArgs/NumTypeParams hilang |
| 5 | `ModifierBits` (async/sync*/async*) kind_tag_ | Async modifier tidak bisa di-reconstruct |
| 6 | `SnapshotBehavior` ObjectPool entry_bits | Call site type (polymorphic/native/zero) hilang |
| 9 | Unboxed field raw value Instance | Numeric constant value hilang |
| 10 | TypedData raw bytes | Binary constant data hilang |
| 11 | Map/Set data ref (dibaca tapi tidak structured) | Map/Set entries tidak bisa di-resolve |

Tidak ditemukan register yang seharusnya ditrack tapi sama sekali tidak
dibaca dari stream — semua field dibaca untuk stream alignment, hanya
valuenya yang dibuang. Tidak ada cluster yang tidak dibaca (semua CID
di-handle oleh `GetFillSpec`).

## Fitur RE Missing/Incomplete

### Fitur 1: CompressedStackMaps decode tidak di-wire (Gap 3)
Decoder `DecodeCompressedStackMaps` sudah ada dan benar, tapi tidak
dipanggil di `ReadFill`. Register liveness di safepoints adalah info RE
yang valuable untuk decompiler quality — tinggal wiring.

### Fitur 2: Record shape & field refs tidak di-capture (Gap 2)
Record adalah Dart 3.0+ feature yang increasingly common. Shape encode
num_fields + named/positional + const info. Field refs bisa ke Type/
Instance/Closure. Tanpa ini, record constant tidak bisa di-RE.

### Fitur 3: Async modifier tidak di-capture (Gap 5)
`async`/`sync*`/`async*` modifier adalah semantic info yang penting untuk
decompiler output. `kind_tag_` sudah dibaca, tinggal decode `ModifierBits`.

### Fitur 4: Constant data recovery incomplete (Gap 9, 10, 11)
Instance unboxed field, TypedData bytes, Map/Set entries — semua adalah
constant data yang bisa di-RE tapi saat ini dibuang. Untuk config object,
lookup table, crypto key, obfuscated string — ini adalah target RE utama.

### Fitur 5: CodeSourceMap token position relative decode (Gap 7, 8)
Token position drift karena decode salah (absolute vs relative). Root
function tidak di-push ke inline stack. Untuk non-PRODUCT input atau
relative position ordering, ini correctness issue.

## Verifikasi SDK

Semua gap diverifikasi via:
1. **Grep MCP (`searchGitHub` by Vercel)** dengan `repo: "dart-lang/sdk"`
   untuk locate file/symbol.
2. **`gh api` @ version tag** untuk fetch exact source:
   - `runtime/vm/app_snapshot.cc` @ 2.10.0, 2.12.0, 3.12.2, 3.13.0
   - `runtime/vm/raw_object.h` @ 2.12.0, 3.12.2
   - `runtime/vm/object.h` @ 3.12.2
   - `runtime/vm/code_descriptors.cc` @ 3.12.2
   - `runtime/vm/code_descriptors.h` @ 3.12.2
   - `runtime/vm/token_position.h` @ 3.12.2
   - `runtime/vm/compiler/object_pool_builder.h` @ 3.12.2
   - `runtime/vm/compiler/method_recognizer.h` @ 2.10.0, 2.12.0, 2.14.0,
     2.17.6, 2.18.0, 2.19.0, 3.0.5, 3.5.0, 3.9.2, 3.12.2
   - `runtime/vm/compiler/recognized_methods_list.h` @ 2.10.0, 2.12.0,
     2.14.0, 2.17.6, 2.18.0, 2.19.0, 3.0.5, 3.5.0, 3.9.2, 3.12.2

Key findings yang diverifikasi:
- **Gap 1**: `KindBits` width = `BitLength(kLastKind)` — 4 bits untuk 2.12-2.18
  (16 kinds), 5 bits untuk 2.10 & 2.19+ (17 kinds). `RecognizedBits` = 9 bits
  di semua versi (383-493 recognized methods). `ModifierBits` = 2 bits.
  StaticBit position = KindBits + RecognizedBits + ModifierBits = 15 atau 16.
- **Gap 2**: `RecordDeserializationCluster::ReadFill` @3.12.2 line 5725-5738
  membaca shape + num_fields × ReadRef.
- **Gap 3**: Decoder sudah ada di `compressedstackmaps.go`, format diverifikasi
  vs `raw_object.h @3.12.2`.
- **Gap 4**: `packed_type_parameter_counts_` field di `UntaggedFunctionType`
  @3.12.2 line 3043-3050.
- **Gap 5**: `AsyncModifier` enum di `raw_object.h @3.12.2` line 1461-1469.
- **Gap 6**: `SnapshotBehavior` enum di `object_pool_builder.h @3.12.2`
  line 29-50, switch di `app_snapshot.cc @3.12.2` line 3303-3325.
- **Gap 7**: `kChangePosition` relative decode di
  `code_descriptors.cc @3.12.2` line 596-601.
- **Gap 8**: `function_stack->Add(&root_)` di
  `code_descriptors.cc @3.12.2` line 590-591.
- **Gap 9-11**: Instance/TypedData/Map fill format diverifikasi vs
  `app_snapshot.cc @3.12.2` ReadFill implementations.
