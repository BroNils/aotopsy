# RE Gap Analysis Report: internal/naming

> **STATUS VERIFIKASI (2026-09-01)** — Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> - **Gap 1 (TTS tanpa library URL + type args) → CONFIRMED**:
>   `stubs.go:303` memang `fmt.Sprintf("TypeTestingStub_%s", name)`.
> - **Gap 9 (TTS naming disabled 2.10–2.15) → PARTIAL (framing).** Yang
>   dilaporkan sebagai "BUG" sebenarnya adalah **mitigasi yang disengaja dan
>   terukur**: komentar `stubs.go:264-273` mencatat "a real Dart 2.12.0 sample
>   resolved 251 of 251 type-owned Codes to a SINGLE distinct class
>   ('TypeParameters') — 251 confident wrong labels is worse than 251 honest
>   sub_ placeholders". Jadi keputusan mematikannya benar; yang belum selesai
>   adalah **akar masalahnya** di `typetrack/lattice.go:205-214`
>   (`MintValues[ti.TypeClassIdRef]` untuk nilai yang sebenarnya Smi). Perlu
>   dicatat juga: lookup itu tampaknya **berhasil** tapi memberi nilai konstan
>   (semua 251 → satu kelas), jadi penjelasan "Smi tidak ada di MintValues"
>   belum sepenuhnya terbukti — akar masalahnya masih terbuka.

## Ringkasan

Folder `internal/naming` (7 file non-test, ~1600 LOC) adalah central name-resolution
surface AOTopsy: mengubah ref ID dari object pool, VM string table, THR stubs,
dispatch table entries, dan Code owner chains menjadi nama yang bisa dibaca RE.
`PoolLookups` adalah struktur data sentral yang dibangun sekali oleh
`BuildPoolLookups` dan dikonsumsi oleh seluruh pipeline (typetrack, xref,
refinfo, decompiler, frida export, funcdiff).

Analisis ini membandingkan kode AOTopsy vs Dart SDK source (via grep MCP +
`gh api` @ tag 3.12.2, 3.9.2, 2.12.0) dan menemukan **15 gap** — 4 bug
fungsional (TTS naming disabled di 2.x, mixin class name salah, ClosureParents
tidak verify kind, PoolNative/PoolEmpty tidak di-display), 6 jalur resolusi nama
yang miss (TTS owner bukan Type, FfiTrampoline unnamed, anonymous closure
collision, dispatcher prefix missing, SavedArgsDescriptor missing, pool display
untuk Closure), dan 5 fitur RE useful yang incomplete (library-qualified names,
Script URL source location, FunctionKind prefixes, Record/RecordType display,
PoolImmediate float interpretation).

## Struktur Folder

```
internal/naming/
├── pool.go              — PoolLookups struct, BuildPoolLookups, ResolvePoolDisplay,
│                          StringForRef, ResolveName/VMName, resolveClassName,
│                          TypeParamResolver, baseObjectName
├── stubs.go             — BuildVMStubSymbols, BuildDiscardedFunctionSymbols,
│                          buildTypeTestingStubNames, BuildTTSCallTargets, TtsCallTarget
├── elfstubname.go       — ElfStubName (last-resort ELF symbol lookup)
├── codeowner.go         — isAllocationStubOwner, CodeIndexToFunc, ResolveCodeOwner
├── typeparams.go        — BuildFuncTypeParamNames (generic <T> reconstruction),
│                          BuildClosureParents (closure → enclosing function)
├── naming_utils.go      — CodeNameInfo.Qualified, QualifiedName, FuncRelPath
└── *_test.go            — 7 test files (constructor, elfstub, helpers, typeparams,
                          ttscall, typeteststubs, testhelpers)
```

## Gap Analysis

### Gap 1: Type-testing stub names missing library URL + type arguments

- **Deskripsi**: `buildTypeTestingStubNames` (`stubs.go:264-306`) menghasilkan
  nama `TypeTestingStub_<ClassName>` saja. SDK's
  `TypeTestingStubNamer::WriteStubNameForTypeTo` (`type_testing_stubs.cc:41-96`
  @3.12.2) menghasilkan format lengkap:
  `TypeTestingStub_<library_url>_<ClassName>__<type_arg1>__<type_arg2>...`
  dengan rekursif stringify type arguments. AOTopsy tidak include library URL
  prefix dan tidak rekursif stringify type arguments. Dua TTS untuk `List<int>`
  dari `dart:core` vs `List<int>` dari `package:my_app` akan collides menjadi
  `TypeTestingStub_List` di AOTopsy, padahal SDK membedakannya.
- **Bukti SDK**: `gh api ... type_testing_stubs.cc @3.12.2` baris 41-96:
  ```cpp
  void TypeTestingStubNamer::WriteStubNameForTypeTo(...) {
    buffer->AddString("TypeTestingStub_");
    StringifyTypeTo(buffer, type);  // rekursif, include lib url + type args
  }
  // StringifyTypeTo:
  //   lib_ = klass_.library();
  //   buffer->AddString(lib_.url());  // "<library_url>_"
  //   buffer->AddString(klass_.ScrubbedNameCString());
  //   for each type_arg: buffer->AddString("__"); StringifyTypeTo(buffer, type_arg);
  ```
  AOTopsy `stubs.go:303`: `out[t.RefID] = fmt.Sprintf("TypeTestingStub_%s", name)`
  — hanya class name, tanpa library URL dan tanpa type arguments.
- **Dampak**: TTS names collide untuk same-named classes dari library berbeda.
  RE tidak bisa membedakan `TypeTestingStub_List` (dart:core) vs
  `TypeTestingStub_List` (package:other). Type argument info (e.g.,
  `List<int>` vs `List<String>`) hilang sepenuhnya — padahal ini info type
  yang useful untuk RE.
- **Usulan**: Ubah `buildTypeTestingStubNames` untuk:
  1. Resolve class's Library ref → Library url string (via `ClassInfo.LibraryRefID`
     → `RefToNamed` → `ResolveName`/`ResolveVMName`).
  2. Walk Type's `arguments` ref → TypeArguments → TypeRefs → rekursif
     stringify.
  3. Format: `TypeTestingStub_<lib_url>_<Class>__<type_arg>...`.
  4. Fallback ke format saat ini jika library/type args tidak resolvable.
- **Prioritas**: Tinggi — info type argument adalah signal RE high-value.

### Gap 2: TTS owner yang bukan Type (FunctionType, TypeParameter, RecordType) unnamed

- **Deskripsi**: `buildTypeTestingStubNames` (`stubs.go:264`) hanya iterate
  `result.Types` (CID == `ct.Type`). SDK's
  `TypeTestingStubGenerator::BuildCodeForType` (`type_testing_stubs.cc:262`)
  menerima `const AbstractType& type` — bisa Type, FunctionType, TypeParameter,
  atau RecordType. `code.set_owner(type)` di baris 303 set owner ke AbstractType
  apapun. Code dengan owner FunctionType/TypeParameter/RecordType tidak
  teridentifikasi oleh AOTopsy — fall through ke `sub_<pcOffset>`.
- **Bukti SDK**: `gh api ... type_testing_stubs.cc @3.12.2`:
  - Baris 262: `BuildCodeForType(const AbstractType& type)` — parameter adalah
    AbstractType, bukan Type.
  - Baris 303: `code.set_owner(type)` — owner adalah AbstractType apapun.
  - `StringifyTypeTo` (baris 50-95): handle `type.IsType()`,
    `type.IsTypeParameter()`, `type.IsRecordType()`, dan fallback
    `type.ToCString()` untuk lainnya.
  - `raw_object.h @3.12.2` baris 2057-2059: "If owner_ is Function::null() the
    owner is a regular stub. If owner_ is a Class the owner is the allocation
    stub for that class. Else, owner_ is a regular Dart Function." — comment
    ini TIDAK menyebut Type/AbstractType, tapi `type_testing_stubs.cc` jelas
    set owner ke AbstractType.
- **Dampak**: Code objects dengan owner FunctionType, TypeParameter, atau
  RecordType tidak bernama. Pada sample 3.9.2 ARM64, ~409 Codes unnamed setelah
  semua path — 324 adalah Type-owned (ditangani), tapi sisanya 85 mungkin
  FunctionType/TypeParameter/RecordType-owned. TTS untuk TypeParameter dan
  RecordType punya naming scheme sendiri di SDK (CanonicalNameCString, Record
  field stringify) yang tidak diimplementasi.
- **Usulan**: Extend `buildTypeTestingStubNames` untuk juga iterate
  `result.FuncTypes` (CID == FunctionType), `result.TypeParameters`
  (CID == TypeParameter), dan `result.RecordType` jika ada. Untuk masing-masing,
  gunakan naming scheme SDK:
  - TypeParameter: `TypeTestingStub_<CanonicalNameCString>` (butuh resolve
    TypeParameter's parameterized_class_id + index → canonical name).
  - RecordType: `TypeTestingStub_Record__<field_type1>__<field_type2>_<name>`.
  - FunctionType/other: `TypeTestingStub_<type.ToCString()>` (fallback).
- **Prioritas**: Medium — populasi kecil tapi naming scheme SDK berbeda.

### Gap 3: Anonymous closure token_pos disambiguation missing

- **Deskripsi**: `BuildClosureParents` (`typeparams.go:175-241`) memetakan
  closure Function ref → enclosing function name. Hasilnya: `parent.<anonymous
  closure>`. Tapi SDK's `FunctionPrintNameHelper` (`object.cc:11559-11633`
  @3.12.2) menggunakan `disambiguate_names` mode menambahkan token_pos:
  `<anonymous closure @<token_pos>>` atau `<anonymous closure @no position>`.
  AOTopsy tidak capture token_pos dan tidak menambahkannya. Multiple anonymous
  closures dalam parent function yang sama masih collides.
- **Bukti SDK**: `gh api ... object.cc @3.12.2` baris 11572-11580:
  ```cpp
  if (params.disambiguate_names &&
      fun.name() == Symbols::AnonymousClosure().ptr()) {
    if (fun.token_pos().IsReal()) {
      printer->Printf("<anonymous closure @%" Pd ">", fun.token_pos().Pos());
    } else {
      printer->Printf("<anonymous closure @no position>");
    }
  }
  ```
  AOTopsy `typeparams.go:225-228`: hanya resolve parent name, tidak tambah
  token_pos. `CodeNameInfo.Qualified` (`naming_utils.go:19-21`) menggunakan
  `EnclosingFunction + "." + FuncName` — FuncName adalah bare
  `<anonymous closure>`.
- **Dampak**: Pada sample 3.12.2, 565 anonymous closures loaded melalui pool.
  Tanpa token_pos, multiple closures dalam parent yang sama (e.g., 3 lambda
  dalam satu method) semuanya render sebagai `parent.<anonymous closure>` —
  tidak bisa dibedakan. RE tidak bisa tell call site mana invoke closure yang
  mana.
- **Usulan**: Capture `token_pos` dari Function object (butuh field baru di
  `NamedObject` atau `FuncTypeInfo` — `token_pos` adalah scalar di Function
  fill, saat ini tidak di-capture). Lalu di `BuildClosureParents` atau
  `CodeNameInfo.Qualified`, jika FuncName == `<anonymous closure>`, append
  `@<token_pos>`.
- **Prioritas**: Medium — butuh capture baru di cluster layer, tapi disambig
  high-value untuk RE.

### Gap 4: Mixin class name tidak digunakan untuk function qualification

- **Deskripsi**: `resolveClassName` (`pool.go:421-451`) mengembalikan class's
  own name. SDK's `FunctionPrintNameHelper` (`object.cc:11600-11608` @3.12.2)
  ketika `include_class_name` true: `const Class& mixin = Class::Handle(cls.Mixin());
  printer->AddString(mixin.UserVisibleNameCString())` — menggunakan MIXIN name,
  bukan class's own name, jika class punya mixin. AOTopsy tidak hop ke mixin.
- **Bukti SDK**: `gh api ... object.cc @3.12.2` baris 11600-11608:
  ```cpp
  if (params.include_class_name) {
    const Class& cls = Class::Handle(fun.Owner());
    if (!cls.IsTopLevel()) {
      const Class& mixin = Class::Handle(cls.Mixin());
      printer->AddString(params.name_visibility == Object::kUserVisibleName
                             ? mixin.UserVisibleNameCString()
                             : cls.NameCString(params.name_visibility));
      printer->AddString(".");
    }
  }
  ```
  AOTopsy `pool.go:432-443`: hanya `ResolveName(owner)` / `ResolveVMName(owner)`
  — tidak check apakah class punya mixin, tidak hop ke mixin class.
- **Dampak**: Function declared dalam mixin-applied class (e.g.,
  `class MyImpl = Object with MyMixin;`) dinamai `MyImpl.method` di AOTopsy
  padahal SDK menamai `MyMixin.method`. Symbol table mismatch — RE yang
  compare dengan ELF symbol table akan melihat disagreement untuk semua
  function di mixin-applied class.
- **Usulan**: Tambah hop ke mixin class di `resolveClassName`: jika Class punya
  mixin (butuh capture `ClassInfo.MixinRefID` — saat ini tidak di-capture,
  `ClassInfo` hanya punya `SuperTypeRefID` dan `LibraryRefID`), return mixin
  class name. Atau: baca Class's `mixin` field dari fill (ref di Class
  ReadFromTo, saat ini tidak di-capture karena `specClass` NameIdx=0, OwnerIdx=-1
  — mixin adalah ref lain di Class).
- **Prioritas**: Medium — butuh capture baru di cluster layer (Class.mixin ref).

### Gap 5: Dispatcher function prefixes missing ([invoke-field], [no-such-method], [tear-off], [tear-off-extractor])

- **Deskripsi**: SDK's `FunctionPrintNameHelper` (`object.cc:11585-11596`
  @3.12.2) ketika `disambiguate_names` menambahkan prefix:
  - `[invoke-field] ` untuk `IsInvokeFieldDispatcher`
  - `[no-such-method] ` untuk `IsNoSuchMethodDispatcher`
  - `[tear-off] ` untuk `IsImplicitClosureFunction`
  - `[tear-off-extractor] ` untuk `IsMethodExtractor`
  AOTopsy tidak emit prefix apapun. `FunctionKind` di-capture (`funckind.go`)
  tapi hanya `Constructor` dan `ImplicitClosure` yang dipakai. Kind lain
  (Getter, Setter, ImplicitGetter, ImplicitSetter) tidak dipakai untuk naming.
- **Bukti SDK**: `gh api ... object.cc @3.12.2` baris 11585-11596:
  ```cpp
  if (params.disambiguate_names) {
    if (fun.IsInvokeFieldDispatcher()) printer->AddString("[invoke-field] ");
    if (fun.IsNoSuchMethodDispatcher()) printer->AddString("[no-such-method] ");
    if (fun.IsImplicitClosureFunction()) printer->AddString("[tear-off] ");
    if (fun.IsMethodExtractor()) printer->AddString("[tear-off-extractor] ");
  }
  ```
  AOTopsy `funckind.go`: `FunctionKind` enum ada `FunctionKindGetter`,
  `FunctionKindSetter`, `FunctionKindImplicitGetter`,
  `FunctionKindImplicitSetter` — tapi `BuildPoolLookups` (`pool.go:190-196`)
  hanya check `IsConstructor()` dan `isAllocationStubOwner()`.
- **Dampak**: Dispatcher functions (NoSuchMethod, invoke-field, method
  extractor) tidak distinguishable dari regular methods. RE tidak tahu
  sebuah function adalah synthetic dispatcher vs real Dart code.
  `FunctionKindOther` (yang includes dispatchers) tidak diberi label.
- **Usulan**: Di `BuildPoolLookups`, setelah resolve nama, check `owner.FuncKind`:
  - `FunctionKindImplicitClosure`: prefix `[tear-off] ` (atau suffix).
  - Kind lain yang map ke dispatcher: prefix sesuai SDK.
  - Getter/Setter: bisa suffix ` (getter)` / ` (setter)` untuk RE clarity.
  Butuh: `FunctionKind` untuk dispatcher saat ini masuk `FunctionKindOther`
  — perlu extend enum dengan `FunctionKindInvokeFieldDispatcher`,
  `FunctionKindNoSuchMethodDispatcher`, `FunctionKindMethodExtractor`.
  Cek `FOR_EACH_RAW_FUNCTION_KIND` di SDK untuk ordinal yang benar.
- **Prioritas**: Medium — RE useful untuk identify synthetic vs real code.

### Gap 6: SavedArgumentsDescriptor disambiguation missing

- **Deskripsi**: SDK's `FunctionPrintNameHelper` (`object.cc:11625-11632`
  @3.12.2) ketika `disambiguate_names && fun.HasSavedArgumentsDescriptor()`
  menambahkan args descriptor ke nama function. Ini disambiguates overloaded
  dispatchers (e.g., `NoSuchMethodDispatcher` dengan args count berbeda).
  AOTopsy tidak capture saved_args_desc dan tidak menambahkannya.
- **Bukti SDK**: `gh api ... object.cc @3.12.2` baris 11625-11632:
  ```cpp
  if (params.disambiguate_names && fun.HasSavedArgumentsDescriptor()) {
    const auto& args_desc_array = Array::Handle(fun.saved_args_desc());
    const ArgumentsDescriptor args_desc(args_desc_array);
    args_desc.PrintTo(printer);
  }
  ```
  AOTopsy: `NamedObject` tidak punya field untuk saved_args_desc ref.
  `specFunction` tidak capture ref ini (Function ReadFromTo hanya capture
  name/owner/signature/data).
- **Dampak**: Dispatchers dengan args count berbeda collides. E.g., dua
  NoSuchMethodDispatcher untuk `foo()` vs `foo(x)` — AOTopsy namai keduanya
  sama. RE tidak bisa tell call site mana invoke dispatcher yang mana.
- **Usulan**: Capture `saved_args_desc` ref dari Function fill (butuh field
  baru di `NamedObject` dan index baru di `FunctionRefLayout`). Lalu di
  `BuildPoolLookups`, jika function adalah dispatcher, append args descriptor
  summary (e.g., `:1` untuk 1 arg, `:2_named` untuk 2 named args).
- **Prioritas**: Low — populasi kecil (dispatchers), kompleksitas tinggi.

### Gap 7: FfiTrampolineData-owned Code objects unnamed

- **Deskripsi**: `ResolveCodeOwner` (`codeowner.go:46-60`) comment mengatakan
  "finds the Function/Closure/FfiTrampolineData NamedObject that owns ce".
  Tapi `BuildPoolLookups` (`pool.go:148-224`) setelah resolve owner hanya
  memanggil `ResolveName(owner)` / `ResolveVMName(owner)`. FfiTrampolineData
  punya `NameIdx: -1` (`specFfiTrampolineData` di `fillspec.go:704-724`) —
  tidak ada name field. `ResolveName` return "". Code unnamed → `sub_<pcOffset>`.
  Padahal `FfiTrampolineInfo.CallbackTargetRef` (`ffitrampoline.go:12`) points
  ke target Function yang punya nama.
- **Bukti SDK**: `gh api ... raw_object.h @3.12.2`: `UntaggedFfiTrampolineData`
  punya fields: `signature_type`, `c_signature`, `callback_target`,
  `callback_exceptional_return`. `callback_target` adalah FunctionPtr — target
  Dart method untuk native callbacks. SDK menamai FFI trampoline berdasarkan
  callback target.
- **Dampak**: FFI callback trampoline Code objects unnamed. Pada app dengan
  FFI callbacks (e.g., native plugin integration), semua trampoline render
  sebagai `sub_<hex>`. RE tidak bisa identify FFI callback entry points.
- **Usulan**: Di `BuildPoolLookups`, jika owner CID == `ct.FfiTrampolineData`:
  1. Cari `FfiTrampolineInfo` dengan RefID == owner.RefID.
  2. Resolve `CallbackTargetRef` → Function NamedObject → name.
  3. Set `CodeNameInfo.FuncName = "ffi_callback_" + targetName`.
  4. Set `IsConstructor = false`.
  Butuh: `FfiTrampolineInfo` lookup by RefID (saat ini hanya slice di
  `result.FfiTrampolines`, tidak di-index).
- **Prioritas**: Medium — FFI increasingly common di Flutter apps.

### Gap 8: Closure objects in pool display show `<Closure>` instead of function name

- **Deskripsi**: `ResolvePoolDisplay` (`pool.go:631-776`) untuk `PoolTagged`
  entries: check `RefToNamed` → `CodeRefDisplay` → `RefCID` → `baseObjectName`
  → VM lookups. Closure objects (`specClosure` di `fillspec.go:398-405`) punya
  `NameIdx: -1, OwnerIdx: -1` — tidak di-capture ke `RefToNamed`. Closure
  falls through ke `RefCID` → `<Closure>`. Padahal `ClosureInfo.FunctionRef`
  (`fill.go:341-344`) sudah di-capture dan bisa resolve ke function name.
- **Bukti SDK**: `UntaggedClosure` ReadFromTo: `function(3)` ref points to
  wrapped Function. SDK's `Closure::function()` returns the Function, dan
  `Function::QualifiedScrubbedName()` gives the name.
- **Dampak**: Pool dump menampilkan ratusan `<Closure>` entries tanpa
  distinguishability. RE tidak bisa tell closure mana yang wrap function mana
  dari pool display saja. (typetrack sudah resolve ini via
  `PoolClosureFunctionNames` untuk BLR, tapi pool display tidak.)
- **Usulan**: Di `ResolvePoolDisplay`, sebelum fallback ke `RefCID`, check
  jika RefID adalah Closure (CID == `ct.Closure`):
  1. Cari `ClosureInfo` dengan RefID == pe.RefID.
  2. Resolve `FunctionRef` → Function NamedObject → name.
  3. Display: `Closure.<function_name>` atau `<Closure: function_name>`.
  Butuh: ClosureInfo lookup by RefID (saat ini hanya slice di
  `result.Closures`, tidak di-index di PoolLookups).
- **Prioritas**: Medium — pool display adalah RE surface utama.

### Gap 9: Type-testing stub naming disabled untuk Dart 2.10-2.15 (BUG: Smi vs Mint confusion)

- **Deskripsi**: `buildTypeTestingStubNames` (`stubs.go:271`) return nil jika
  `typeClassIDIsRef` true (Dart 2.10-2.15). Alasannya: "a real Dart 2.12.0
  sample resolved 251 of 251 type-owned Codes to a SINGLE distinct class
  ('TypeParameters')". Root cause: `resolveTypeClassIDs` (`typetrack/lattice.go:205-214`)
  lookup `MintValues[ti.TypeClassIdRef]` — tapi `type_class_id` adalah **Smi**
  (immediate value), bukan Mint (heap object). Smis tidak ada di `MintValues`.
  Lookup gagal untuk semua, tapi ada collision yang membuat semua resolve ke
  class ID yang sama.
- **Bukti SDK**: `gh api ... raw_object.h @2.12.0`: `Type` punya
  `type_class_id_` sebagai `SMI_FIELD` (bukan `POINTER_FIELD`). Smi value =
  class_id << 1 (Smi tagging). `Smi::Value(smi) = smi >> 1`. Di snapshot
  stream, `ReadRef()` untuk Smi field mengembalikan tagged Smi value langsung
  (bukan ref ID ke heap object). AOTopsy's `readRef` mengembalikan raw value
  tanpa distinguish Smi vs heap ref.
- **Dampak**: Semua TTS naming OFF untuk Dart 2.10-2.15. ~251 Codes unnamed
  pada 2.12.0 sample. Type resolution (field types, param types, dispatch)
  juga broken pada 2.x karena `TypeInfo.ClassID` stays 0.
- **Usulan**: Di `resolveTypeClassIDs`, untuk TypeClassIdRef yang adalah Smi:
  decode sebagai `ClassID = TypeClassIdRef >> 1` (Smi untagging). Distinguish
  Smi dari heap ref: Smi refs adalah nilai kecil dengan low bit 0 (Smi tag =
  0 pada 64-bit). Atau: cek jika `TypeClassIdRef < NumBaseObjects` (Smi
  canonical values adalah base objects). Verifikasi encoding Smi di snapshot
  stream vs SDK source `ReadStream::ReadRef()` @2.12.0.
- **Prioritas**: Tinggi — completely disables type info pada 2.x samples.

### Gap 10: BuildClosureParents tidak verify function adalah closure (fragile)

- **Deskripsi**: `BuildClosureParents` (`typeparams.go:192-196`) iterates ALL
  `NamedObject` dengan `CID == ct.Function` dan `DataRefID > RefNull`. Tidak
  check `FuncKind == FunctionKindClosure`. SDK's
  `Function::parent_function()` (`object.cc:8399-8404` @3.12.2) hanya return
  non-null jika `IsClosureFunction()` (kind == kClosureFunction atau
  kImplicitClosureFunction). Untuk non-closure function, `data` bisa point ke
  FieldInitializerData atau type lain — bukan ClosureData.
- **Bukti SDK**: `gh api ... object.cc @3.12.2` baris 8399-8404:
  ```cpp
  FunctionPtr Function::parent_function() const {
    if (!IsClosureFunction()) return Function::null();
    Object& obj = Object::Handle(untag()->data());
    ASSERT(!obj.IsNull());
    return ClosureData::Cast(obj).parent_function();
  }
  ```
  AOTopsy `typeparams.go:194`: hanya check `no.CID != pl.CT.Function` —
  tidak check `no.FuncKind`.
- **Dampak**: Saat ini aman secara kebetulan: `parentByData` hanya berisi
  ClosureData refs, dan non-closure function's `data` bukan ClosureData ref,
  jadi lookup miss. Tapi fragile: jika future Dart version menambah kind baru
  dengan `data` yang kebetulan adalah ClosureData ref, AOTopsy akan salah
  assign parent. Juga: untuk `FunctionKindImplicitClosure` (tear-off),
  AOTopsy skip via `IsImplicitClosure()` check di baris 206 — ini benar.
  Tapi untuk `FunctionKindRegular` dengan non-null data (e.g.,
  FieldInitializer), lookup parentByData miss diam-diam.
- **Usulan**: Tambah check `no.FuncKind == FunctionKindClosure` (non-implicit
  closure) sebelum walk `data -> ClosureData.parent_function`. Skip semua
  kind lain explicitly.
- **Prioritas**: Low — saat ini safe by accident, tapi correctness concern.

### Gap 11: PoolNative dan PoolEmpty entries tidak di-display

- **Deskripsi**: `ResolvePoolDisplay` (`pool.go:631-776`) hanya handle
  `PoolTagged` dan `PoolImmediate`. `PoolNative` (kNativeFunction /
  kNativeFunctionWrapper) dan `PoolEmpty` (kResetToBootstrapNative, dll.)
  tidak ada case — mereka tidak dapat entry di display map. Pool dump
  menampilkan "gap" di index tersebut.
- **Bukti SDK**: `fill_pool.go:66-67`: `case 2, 3: pe.Kind = PoolNative`.
  `fill_pool.go:104-105`: `case 1, 2, 3, 4: pe.Kind = PoolEmpty`.
  `pool.go:762-773`: hanya `case cluster.PoolTagged:` dan
  `case cluster.PoolImmediate:` — tidak ada case untuk PoolNative/PoolEmpty.
- **Dampak**: Pool dump tidak complete — RE tidak tahu apakah pool slot
  kosong (uninitialized) atau native function. Untuk RE, knowing slot adalah
  native function (vs unresolved ref) adalah signal berguna.
- **Usulan**: Tambah case di `ResolvePoolDisplay`:
  - `case cluster.PoolNative: display[pe.Index] = "<native_function>"`
  - `case cluster.PoolEmpty: display[pe.Index] = "<empty>"`
- **Prioritas**: Low — cosmetic, tapi pool display harus complete untuk RE.

### Gap 12: Library-qualified function names missing (RE feature)

- **Deskripsi**: Function names di AOTopsy qualified oleh owning class
  (`OwnerName.FuncName`), tapi tidak oleh owning library. SDK regular
  function names juga tidak include library qualification — jadi ini bukan
  gap vs SDK. Tapi untuk RE, library qualification useful untuk distinguish
  same-named functions dari library berbeda (e.g., `Widget.build` dari
  `package:flutter` vs `Widget.build` dari `package:other`).
- **Bukti SDK**: `FunctionPrintNameHelper` tidak include library url untuk
  regular functions. Hanya `TypeTestingStubNamer` yang include library url.
  Tapi `ClassInfo.LibraryRefID` sudah di-capture, dan `specLibrary` NameIdx=1
  (url) sudah di-capture.
- **Dampak**: RE tidak bisa tell library origin sebuah function. Untuk
  fingerprinting (framework vs app code), library info adalah signal utama.
  `libraryxref.go` sudah build library cross-reference, tapi function names
  tidak include library prefix.
- **Usulan**: Tambah optional library prefix di `CodeNameInfo`:
  `LibraryName string` (e.g., "dart:core", "package:flutter/widgets.dart").
  Di `BuildPoolLookups`, resolve `ClassInfo.LibraryRefID` → Library url.
  Display: `[dart:core] Duration.compareTo` atau separate field untuk
  programmatic access. Tidak mengubah `Qualified()` format (backward compat),
  tapi tambah field baru.
- **Prioritas**: Medium — RE fingerprinting high-value.

### Gap 13: Script URL + token_pos source location missing (RE feature)

- **Deskripsi**: SDK's stack trace format: `funcName (url:line:col)`.
  `ScriptInfo.URLRef` dan Function's `token_pos` bisa provide source location.
  AOTopsy capture Script URLs (`fill_refs.go:272-282`) tapi tidak link
  Function → Script → URL. `CodeSourceMap` memberikan PC → token_pos mapping,
  tapi tidak ada yang combine dengan Script URL untuk produce `file:line`.
- **Bukti SDK**: `gh api ... simulator_arm64.cc @3.12.2` baris 303-310:
  ```cpp
  const Script& script = Script::Handle(function.script());
  const String& url = String::Handle(script.url());
  script.GetTokenLocation(token_pos, &line, &column);
  // "%s (%s:%d:%d)", func_name, url, line, column
  ```
  AOTopsy: `ScriptInfo` punya `URLRef` tapi tidak ada Function → Script link.
  `ClassInfo` tidak punya Script ref. Function's `script()` di SDK di-resolve
  via `data` field atau via owner Class's script.
- **Dampak**: RE tidak bisa map function/PC ke source file:line. Ini adalah
  fitur paling useful untuk RE (setelah nama function) — menghubungkan binary
  ke source code. DWARF debug info provide ini tapi stripped di release.
- **Usulan**: 1. Capture Function → Script link (via `data` field untuk
  non-closure, atau via owner Class's script). 2. Resolve Script URLRef →
  string. 3. Combine dengan `CodeSourceMap` token_pos → line:col (butuh
  Script.GetTokenLocation implementation — non-trivial, butuh line starts
  array). 4. Display di disasm annotation: `; source: package:my_app/main.dart:42:5`.
- **Prioritas**: Tinggi — tapi kompleks (butuh Script line table parser).

### Gap 14: FunctionKind tidak fully utilized (getter/setter labels missing)

- **Deskripsi**: `FunctionKind` enum (`funckind.go:50-64`) punya
  `FunctionKindGetter`, `FunctionKindSetter`, `FunctionKindImplicitGetter`,
  `FunctionKindImplicitSetter`. AOTopsy hanya gunakan `FunctionKindConstructor`
  (→ "new " prefix) dan `FunctionKindImplicitClosure` (→ skip ClosureParents).
  Kind lain tidak dipakai untuk naming. SDK's `FunctionPrintNameHelper` tidak
  explicitly label getter/setter, tapi untuk RE, label ini useful untuk
  understand code structure.
- **Bukti SDK**: `FOR_EACH_RAW_FUNCTION_KIND` di `raw_object.h` includes
  `kImplicitGetterFunction`, `kImplicitSetterFunction`, `kGetterFunction`,
  `kSetterFunction`. AOTopsy capture ini di `FuncKind` tapi tidak display.
- **Dampak**: RE tidak bisa tell sebuah function adalah getter (e.g.,
  `widget.width` → `Widget.get_width` vs `Widget.width` method). Getter/setter
  adalah Dart idiom yang penting untuk understand API surface.
- **Usulan**: Di `BuildPoolLookups`, setelah resolve nama, jika FuncKind adalah
  getter/setter, tambah suffix:
  - `FunctionKindGetter` / `FunctionKindImplicitGetter`: ` (getter)`
  - `FunctionKindSetter` / `FunctionKindImplicitSetter`: ` (setter)`
  Atau: prefix dengan `get ` / `set ` matching Dart syntax: `get width`,
  `set width`.
- **Prioritas**: Low — cosmetic, tapi RE clarity.

### Gap 15: PoolImmediate tidak interpret sebagai float/double (RE feature)

- **Deskripsi**: `ResolvePoolDisplay` (`pool.go:772`) render PoolImmediate
  sebagai `0x%x` (raw hex). Comment explicitly says: "float interpretation
  belongs in the decompiler's FP-load operand path". Tapi untuk pool display
  RE, knowing sebuah immediate adalah 3.14 (double) vs 0x40091EB8 (raw hex)
  adalah signal berguna. SDK's ObjectPool immediate bisa hold double values
  yang meaningful.
- **Bukti SDK**: `fill_pool.go:59-65`: `kImmediate → Read<intptr_t>` — raw
  64-bit value. Interpretation (int vs double) tergantung instruction yang
  consume it. Tapi untuk RE pool dump, double interpretation useful sebagai
  hint.
- **Dampak**: Pool dump tidak show float values. RE harus manual decode hex
  ke double untuk identify constant seperti 3.14, 0.0, 1.0, etc.
- **Usulan**: Di `ResolvePoolDisplay` PoolImmediate case, render dual format:
  `0x%x (double: %g)` jika bits look like plausible double (e.g., exponent
  field non-zero, mantissa non-zero). Atau: tambah flag `--pool-show-floats`
  untuk opt-in. Hanya untuk display, tidak mengubah Imm field.
- **Prioritas**: Low — convenience feature untuk RE pool dump.

## Register Tracking Gaps

`internal/naming` adalah name-resolution surface, bukan disassembler — tidak
track register secara langsung. Tapi menyediakan data yang feed ke register
tracking via `typetrack`:

| Data | Status | Gap |
|------|--------|-----|
| `PoolCodeNames` (PP index → function name) | ✓ Built | — |
| `TypeTestingStubNames` (Type ref → stub name) | ✓ Built (3.x only) | Gap 9: OFF untuk 2.x |
| `PoolClosureFunctionNames` (PP index → closure function) | ✓ Built di typetrack | Gap 8: tidak di pool display |
| `PoolUnlinkedCallNames` (PP index → method name) | ✓ Built di typetrack | — |
| `PoolClassByIndex` (PP index → ClassID) | ✓ Built di typetrack | — |
| `THRFields` (THR offset → field name) | ✓ Built di vmtables | — |
| `AllocStubOffsets` (THR offset → alloc stub name) | ✓ Built di vmtables | — |
| `DispatchCodeIndexToName` (cluster index → name) | ✓ Built di typetrack | — |

Tidak ada register tracking gap baru di `internal/naming` — semua data yang
dibutuhkan typetrack sudah disediakan, kecuali TTS naming untuk 2.x (Gap 9
yang disable `TypeTestingStubNames` di 2.x).

## Fitur RE Missing/Incomplete

1. **Library-qualified function names** (Gap 12): Function names tidak
   include library origin. RE fingerprinting (framework vs app) butuh ini.

2. **Source location (file:line:col)** (Gap 13): Tidak ada mapping function/PC
   ke source file. Fitur RE paling useful setelah nama function. Butuh Script
   line table parser + Function → Script link.

3. **Type argument info di TTS names** (Gap 1): `TypeTestingStub_List` vs
   `TypeTestingStub dart:core_List__int` — type args adalah signal RE
   high-value.

4. **FunctionKind labels** (Gap 14): Getter/setter/dispatcher labels untuk
   understand code structure.

5. **Record/RecordType display** (Gap 2): Record types (Dart 3.0+) tidak
   di-display di pool. Record field types dan names bisa di-extract.

6. **Float interpretation di pool dump** (Gap 15): Pool immediate hanya show
   hex, tidak show double interpretation.

7. **Dispatcher identification** (Gap 5): NoSuchMethod/invoke-field/tear-off
   dispatcher tidak distinguishable dari real methods.

## Verifikasi SDK

Verifikasi dilakukan via:

1. **grep MCP (`searchGitHub` by Vercel)** dengan `repo: "dart-lang/sdk"`:
   - `FunctionPrintNameHelper` → `object.cc` @main, baris 11320-11640
   - `IsNonImplicitClosureFunction` → `object.h` @main, baris 3966
   - `IsClosureFunction() const` → `object.h` @main, baris 3946
   - `Function::parent_function() const` → `object.cc` @main, baris 8399
   - `QualifiedScrubbedName` → `object.cc` @main, baris 11292
   - `PrintName(NameFormattingParams` → `object.cc` @main, baris 11295
   - `code.set_owner` → `type_testing_stubs.cc` @main, baris 303
   - `IsLocalFunction` → `object.h` @main, baris 3988
   - `owner_ = Object` → `kernel_binary_flowgraph.cc` @main

2. **`gh api` @ version tag**:
   - `runtime/vm/object.cc @3.12.2` baris 11559-11640: `FunctionPrintNameHelper`
     full implementation (disambiguate_names, token_pos, mixin class,
     dispatcher prefixes, SavedArgumentsDescriptor, constructor "new ").
   - `runtime/vm/object.cc @3.12.2` baris 8399-8404: `Function::parent_function()`
     — hanya return non-null untuk `IsClosureFunction()`.
   - `runtime/vm/raw_object.h @3.12.2` baris 2050-2070: `UntaggedCode.owner`
     comment "Function, Null, or a Class" (tidak mention Type, tapi
     type_testing_stubs.cc set owner ke AbstractType).
   - `runtime/vm/type_testing_stubs.cc @3.12.2` baris 41-96:
     `WriteStubNameForTypeTo` + `StringifyTypeTo` — format lengkap dengan
     library URL, type arguments rekursif, TypeParameter, RecordType.
   - `runtime/vm/type_testing_stubs.cc @3.12.2` baris 262-303:
     `BuildCodeForType(const AbstractType& type)` — menerima AbstractType,
     bukan Type saja.
   - `runtime/vm/raw_object.h @2.12.0`: Type.type_class_id adalah SMI_FIELD
     (bukan POINTER_FIELD) — Smi, bukan Mint.

3. **Cross-reference dengan AOTopsy code**:
   - `stubs.go:264-306` vs `type_testing_stubs.cc:41-96` → Gap 1, 2
   - `pool.go:421-451` vs `object.cc:11600-11608` → Gap 4 (mixin)
   - `typeparams.go:175-241` vs `object.cc:11559-11633` → Gap 3, 5, 6
   - `pool.go:148-224` vs `ffitrampoline.go:8-16` → Gap 7
   - `pool.go:631-776` vs `fill.go:341-344` (ClosureInfo) → Gap 8
   - `typetrack/lattice.go:205-214` vs `raw_object.h @2.12.0` → Gap 9
   - `typeparams.go:192-196` vs `object.cc:8399-8404` → Gap 10
   - `pool.go:631-776` vs `fill_pool.go:66-105` → Gap 11
