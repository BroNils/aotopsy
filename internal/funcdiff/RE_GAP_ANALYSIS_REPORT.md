# RE Gap Analysis Report: internal/funcdiff

> **STATUS VERIFIKASI (2026-09-01)** — Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> - **Gap 1 (`CodeSize` = `PayloadInfo`) → CONFIRMED.** `funcdiff.go:47`
>   `codeSizeByOwner[ce.OwnerRef] = ce.PayloadInfo`; `cluster.go:73`
>   mendokumentasikannya sebagai "raw payload_info from fill"; komentar
>   `funcdiff.go:32` sendiri mengaku "proxy for instruction count".
> - **Gap 2 (descriptor tanpa library URI) → CONFIRMED**, dan sudah diakui
>   eksplisit di komentar kode (`funcdiff.go:21-27`).
> - **Gap 6 (`token_pos_` di-drop) → PARTIAL (framing).** Kutipan SDK-nya
>   tepat — guard-nya `#if defined(DART_PRECOMPILER) && !defined(PRODUCT)`,
>   jadi pemicunya adalah **gen_snapshot non-PRODUCT**. Tapi menyebutnya
>   "BUG parse" menyesatkan: snapshot non-PRODUCT **sudah dinyatakan tidak
>   didukung** dan diberi diagnostic keras di `snapshot/snapshot.go:312-318`
>   ("Code fill has 2 extra refs … will desync") — Code cluster desync jauh
>   sebelum Function. Ini bagian dari pekerjaan "dukung non-PRODUCT", bukan
>   bug berdiri sendiri. Prioritas P0 di CONSOLIDATED perlu diturunkan.

## Ringkasan

`internal/funcdiff` adalah satu-satunya komparator antar-build di AOTopsy. Ia
membandingkan dua `libapp.so` (lama vs baru) dan menghasilkan daftar fungsi
`added` / `removed` / `changed` berdasarkan descriptor string
`<owner_class>::<name>` dan proxy "ukuran kode" berupa `CodeEntry.PayloadInfo`.

Analisis ini menemukan bahwa `funcdiff` **secara fundamental under-using** data
yang sudah diparsing oleh AOTopsy, dan **salah menginterpretasikan** satu field
kunci (`PayloadInfo`) sebagai ukuran instruksi padahal ia adalah offset
entry-point. Akibatnya:

1. **Deteksi "changed" tidak reliable** — proxy ukuran kode salah semantik.
2. **Identitas fungsi tidak disambiguasi oleh library URI** — padahal
   `analysis.LibraryResolver` sudah ada dan bisa langsung dipakai, menutup
   gap yang diakui sendiri oleh komentar di `funcdiff.go`.
3. **Closure, FFI trampoline, dan field initializer function seluruhnya
   di-skip** — tiga kategori fungsi yang justru sering berubah antar versi
   app (callback FFI, listener closure, lazy field init).
4. **Tidak ada diff tingkat signature/parameter/return-type** — padahal
   `NamedObject.SignatureRefID`, `NumFixedParams`, `NumOptionalParams`,
   `FuncKind`, `IsStatic` sudah diparsing di cluster fill.
5. **Tidak ada diff tingkat instruksi / call-edge / inline-tree** — semua
   infrastruktur (`disasm`, `callgraph`, `CodeSourceMap`, `InlinedFuncsRef`)
   tersedia tapi tidak dihubungkan ke komparator.
6. **`token_pos_` (line number di AOT non-PRODUCT) di-drop** oleh
   `specFunction` — padahal SDK sengaja menyimpan line number di field itu
   untuk AOT.

Verifikasi dilakukan terhadap `dart-lang/sdk` @ tag `3.7.0` via `gh api` dan
`grep` MCP (`searchGitHub`, repo filter `dart-lang/sdk`).

## Struktur Folder

```
internal/funcdiff/
├── funcdiff.go          (198 baris)  — inti: Build, Load, Diff, DiffDescriptors
└── funcdiff_test.go     (82 baris)   — 1 unit test happy-path
```

Tidak ada sub-package. Hanya dua file. Konsumen tunggal:
`cmd/aotopsy/cmd_debug_diff.go` (`_debug funcdiff`).

Tipe/data yang dipakai:
- `cluster.Result.Named` → filter `CID == ct.Function`
- `cluster.Result.Codes` → `CodeEntry.OwnerRef` + `CodeEntry.PayloadInfo`
- `naming.PoolLookups` → `RefToNamed`, `VmRefToNamed`, `ResolveName`,
  `ResolveVMName`
- `snapshot.CIDTable` → `Function`, `PatchClass`

Tipe/data yang **tersedia di `SnapshotContext` tapi TIDAK dipakai funcdiff**:
- `sc.Ranges` (`[]cluster.CodeRange` dengan `Size` instruksi nyata)
- `sc.Table` (`*cluster.InstructionsTable`)
- `sc.Result.Classes` (untuk library URI via `ClassInfo.LibraryRefID`)
- `sc.Result.ClosureData` (`ParentFunctionRef` → identitas closure stabil)
- `sc.Result.Closures` (`FunctionRef` → closure wrapper)
- `sc.Result.FfiTrampolines`
- `sc.Result.CodeSourceMaps` (inline stack + token pos per PC)
- `sc.Result.PcDescriptors` (try/catch region)
- `sc.Result.Fields` (field layout → class-level change detection)
- `analysis.LibraryResolver` (sudah ada, langsung resolve Function→library URL)

## Gap Analysis

### Gap 1: `CodeSize` memakai `PayloadInfo` — salah semantik, deteksi "changed" tidak reliable

- **Deskripsi**: `FuncInfo.CodeSize = ce.PayloadInfo` (`funcdiff.go:47,64`).
  Komentar di `funcdiff.go:32` menyebut
  `CodeSize int64 // PayloadInfo from CodeEntry (proxy for instruction count)`.
  Namun `PayloadInfo` **bukan** instruction count dan **bukan** byte size.
  Ia adalah `payload_info` dari `CodeDeserializationCluster::ReadFill`, yang
  di-encode sebagai `(unchecked_offset << 1) | has_monomorphic_entry`
  (verified `runtime/vm/app_snapshot.cc` @3.7.0, serializer line ~8694 dan
  deserializer line ~9834). `unchecked_offset` adalah offset entry-point
  *unchecked* relatif terhadap entry-point *checked* dalam Code object yang
  sama — sebuah properti code-gen, bukan ukuran.
  Dua fungsi yang bytecode-nya berubah drastis bisa punya `PayloadInfo`
  identik (kalau `unchecked_offset` tidak berubah), dan dua fungsi yang
  bytecode-nya identik bisa punya `PayloadInfo` berbeda (kalau optimizer
  menggeser unchecked entry). Akibatnya label "changed" di report funcdiff
  bisa false-positive maupun false-negative.
- **Bukti SDK**:
  - `gh api ... runtime/vm/app_snapshot.cc?ref=3.7.0` line ~8694:
    ```cpp
    const uint32_t payload_info =
        (unchecked_offset << 1) | (Code::HasMonomorphicEntry(code) ? 0x1 : 0x0);
    WriteUnsigned(payload_info);
    ```
  - line ~9834:
    ```cpp
    const uint32_t payload_info = ReadUnsigned();
    const uint32_t unchecked_offset = payload_info >> 1;
    const bool has_monomorphic_entrypoint = (payload_info & 0x1) == 0x1;
    ```
  - AOTopsy sendiri sudah tahu ini — `cluster/fill_code.go:13` hanya
    menyebut "ReadUnsigned (payload_info)" tanpa pernah mengklaim itu size.
    `cluster/instrtable.go` justru menyediakan `ResolveCodeRanges` yang
    menghitung `CodeRange.Size` dengan mengurangkan PCOffset antar entry
    bertetangga di `InstructionsTable` — itu satu-satunya sumber size nyata.
- **Dampak**: Seluruh kategori "changed" di report funcdiff tidak dapat
  dipercaya. RE yang mengandalkan funcdiff untuk memprioritaskan fungsi
  yang "berubah" antar versi app akan salah arah.
- **Usulan**:
  1. Ganti `FuncInfo.CodeSize` dengan `CodeRange.Size` nyata dari
     `sc.Ranges` (sudah dihitung `LoadSnapshot`). Map `OwnerRef → Size`
     dari `Ranges` (field `OwnerRef` dan `Size` di `CodeRange`).
  2. Untuk Dart 2.10–2.15 (pre-InstructionsTable), pakai
     `ResolveCodeRangesFromTextOffset` (sudah ada).
  3. Sebagai sinyal tambahan yang lebih halus, hash byte instruksi di
     range `[PCOffset, PCOffset+Size)` dari `sc.Code` — ini mendeteksi
     perubahan kode yang ukurannya sama (re-order, constant pool swap).
  4. Simpan `PayloadInfo` terpisah sebagai metadata opt (monomorphic entry
     flag) bila berguna, tapi JANGAN pakai sebagai size.
- **Prioritas**: **P0 — kritis**. Ini menyangkut koreksi semantik, bukan
  fitur tambahan. Tanpa ini report "changed" menyesatkan.

### Gap 2: Descriptor tidak menyertakan library URI — collision & gap vs flutterdec

- **Deskripsi**: `FuncDescriptor = ownerClass + "::" + name` saja
  (`funcdiff.go:27,60`). Komentar eksplisit di `funcdiff.go:22-26` dan
  `:106-108` mengakui ini sebagai gap vs `flutterdec`'s
  `<library_uri>::<owner_class>::<name>`. Akibat: dua method `toString`
  di dua class berbeda di dua library berbeda hanya bisa dibedakan lewat
  owner class — tapi nama class pun bisa collide antar package
  (mis. `State`, `Widget`, `Element` sangat umum). Lebih buruk lagi:
  top-level function di file `main.dart` vs top-level function bernama
  sama di package lain akan ter-collide jadi satu descriptor.
- **Bukti SDK**: `Library` cluster (`specLibrary` di AOTopsy
  `fillspec.go:364`) membaca `url` di ref index 1 — AOTopsy SUDAH
  menangkap URL library. `ClassInfo.LibraryRefID` (`fill.go:164`) SUDAH
  diisi dari Class fill. `analysis.LibraryResolver.LibraryURLForClassRef`
  (`libraryxref.go:54`) SUDAH me-resolve Function→owner class→library URL.
  Semua bahan ada; funcdiff hanya tidak memanggilnya.
- **Dampak**:
  - False positive "common" — dua fungsi berbeda dianggap sama →
    perubahan tidak terdeteksi.
  - False positive "removed/added" — fungsi yang pindah package
    (refactor) tampak sebagai remove+add padahal hanya pindah.
  - Tidak bisa bucket diff per package (`collect_diff_package_counts`
    flutterdec) — fitur RE penting untuk "apa yang berubah di
    package:my_app vs package:flutter".
- **Usulan**:
  1. Buat descriptor 3-segment: `<library_url>::<owner_class>::<name>`.
     Gunakan `analysis.NewLibraryResolver(result, pl)` di `Build`.
  2. Tambah bucketing per-package di `Report` (dart: vs package:flutter
     vs package:<app> vs lainnya) — `IsFrameworkLibraryURL` sudah ada.
  3. Untuk top-level function (owner class adalah synthetic
     "top-level-scope" class), library URI menjadi satu-satunya
     disambiguator — wajib.
- **Prioritas**: **P0 — kritis**. Ini menyangkut identitas; tanpa ini
  diff bisa diam-diam merge dua fungsi berbeda.

### Gap 3: Closure, FFI trampoline, dan field-initializer function di-skip total

- **Deskripsi**: `funcdiff.go:52` hanya menerima `no.CID == ct.Function`.
  `funcdiff.go:58` me-skip fungsi tanpa nama ("unnamed/anonymous closures
  aren't stable diff targets"). Akibatnya tiga kategori fungsi yang
  sering berubah antar versi app hilang dari diff:
  - **Closure** (`CidClosure = 57`): handler tombol, listener stream,
    callback `then`/`catchError` — sangat sering ditambah/dihapus saat
    UI berubah.
  - **FfiTrampolineData** (`CidFfiTrampolineData = 10`): callback FFI
    (mis. plugin native) — sering berubah saat integrasi native berubah.
  - **Field initializer function** (`FuncKind == FieldInitializer`):
    fungsi yang menginisialisasi `static final` — berubah saat konstanta
    default berubah (tema, config).
- **Bukti SDK**:
  - `UntaggedFunction::Kind` (`raw_object.h` @3.7.0 line ~1237) punya
    `FieldInitializer`, `ImplicitGetter`, `ImplicitSetter`,
    `ImplicitStaticGetter`, `MethodExtractor`, `NoSuchMethodDispatcher`,
    `InvokeFieldDispatcher`, `DynamicInvocationForwarder`,
    `FfiTrampoline`, `RecordFieldGetter` — semua adalah Function dengan
    kode nyata. funcdiff hanya melihat `name != ""`, sehingga implicit
    getter/setter (yang namanya = nama field) lolos, tapi closure dan
    FfiTrampoline (CID berbeda) tidak.
  - `ClosureData` (`raw_object.h` `UntaggedClosureData`) punya
    `parent_function` — AOTopsy menangkap ini (`ClosureDataInfo.ParentFunctionRef`,
    `fill.go:331`). Ini memberi identitas stabil untuk closure:
    `<parent_func>::closure#<index_di_parent>`.
  - `Closure` object (`CidClosure=57`) punya `function` ref (index 3,
    `ClosureInfo.FunctionRef`, `fill.go:343`) — closure wrapper → Function
    yang di-wrap.
  - `FfiTrampolineData` (`FfiTrampolineInfo` di AOTopsy) punya callback
    target & signature C — identitas stabil berdasarkan callback ID.
- **Dampak**: Diff melewatkan kategori perubahan yang paling sering
  terjadi di app real (UI callback, plugin FFI, static config). RE
  yang membandingkan versi app sebelum/sesudah patch keamanan tidak
  akan melihat closure handler yang ditambah.
- **Usulan**:
  1. Untuk closure: bangun identitas `<parent_func_descriptor>::closure#<n>`
     di mana `n` adalah urutan closure di parent (dari
     `ClosureData.ParentFunctionRef` → parent Function, lalu index
     closure berdasarkan posisi di list ClosureData dengan parent yang
     sama). Stabil antar build selama urutan deklarasi tidak berubah.
  2. Untuk FfiTrampoline: descriptor `ffi::trampoline#<callback_id>`
     (callback_id sudah ditangkap AOTopsy di `FfiTrampolineInfo`).
  3. Untuk FieldInitializer: descriptor `<owner_class>::<field_name>::init`
     — resolve field via `FieldInfo.InitializerRefID`.
  4. Tambah kategori terpisah di `Report` (`AddedClosures`,
     `RemovedClosures`, dst.) agar tidak noise kanal fungsi biasa.
- **Prioritas**: **P1 — tinggi**. Kategori fungsi ini adalah sinyal
  perubahan paling kuat untuk RE app.

### Gap 4: Tidak ada diff signature/parameter/return-type/FuncKind

- **Deskripsi**: `FuncInfo` hanya bawa `RefID` dan `CodeSize`. Padahal
  `NamedObject` sudah menyimpan:
  - `SignatureRefID` → `FuncTypeInfo` (NumFixed, NumOptional,
    HasNamedOptional, ResultTypeRefID, ParamTypesArrayRefID,
    NamedParamNamesArrayRefID, TypeParamsRefID)
  - `NumFixedParams`, `NumOptionalParams` (2.x)
  - `FuncKind` (RegularFunction, GetterFunction, SetterFunction,
    Constructor, ImplicitGetter, dst.)
  - `IsStatic`, `HasKindTag`
  Semua ini sudah di-parse oleh `cluster/fill_refs.go` dan
  `cluster/fill_scalar_handlers.go`. funcdiff tidak membandingkannya
  sama sekali. Perubahan signature (menambah parameter, mengubah return
  type, mengubah `async` modifier) tidak terdeteksi kecuali kebetulan
  mengubah `PayloadInfo`.
- **Bukti SDK**:
  - `UntaggedFunction` (`raw_object.h` @3.7.0 line ~1237) punya
    `signature_` (FunctionType), `kind_tag_` (Kind + modifier async),
    `packed_fields_` (2.x: NumFixed/NumOptional).
  - `UntaggedFunctionType` (`raw_object.h` @3.7.0 line ~2851) punya
    `type_parameters`, `result_type`, `parameter_types`,
    `named_parameter_names` — semua sudah ditangkap AOTopsy
    (`FuncTypeInfo` di `fill.go:61`).
  - `FunctionDeserializationCluster::ReadFill` membaca `kind_tag_`
    (`app_snapshot.cc` @3.7.0 line ~1937) — AOTopsy menangkap ini
    (`fill_scalar_handlers.go:112-128`).
- **Dampak**: Refactor yang mengubah API (tambah parameter, ubah return
  type, ubah sync→async) tidak terdeteksi. Untuk RE yang mencoba
  memahami perubahan kontrak fungsi antar versi, funcdiff buta.
- **Usulan**:
  1. Tambah field di `FuncInfo`:
     `SignatureHash` (hash dari resolved signature: result type +
     param types + param names + named-flag + type params),
     `NumFixed`, `NumOptional`, `HasNamedOptional`, `FuncKind`,
     `IsStatic`.
  2. Di `DiffDescriptors`, tambah kategori `SignatureChanged` terpisah
     dari `CodeChanged` — signature change tanpa code change = kontrak
     API berubah; code change tanpa signature change = implementasi
     berubah. Dua sinyal RE yang berbeda.
  3. Resolve signature ke string kanonik via `FuncTypeInfo` +
     `ArrayInfo` (param types) + `Type` resolution (type_class_id).
     Aotopsy sudah punya `typetrack` package untuk ini.
- **Prioritas**: **P1 — tinggi**. Signature change = breaking API
  change, sinyal RE paling penting setelah code change.

### Gap 5: Tidak ada diff tingkat instruksi / call-edge / inline-tree

- **Deskripsi**: funcdiff berhenti di level "fungsi berubah / tidak".
  Tidak ada jawaban untuk pertanyaan RE yang lebih spesifik:
  - **Call-edge diff**: fungsi A versi lama memanggil B dan C; versi
    baru memanggil B dan D → D adalah call-site baru (mungkin fitur
    baru, atau patch keamanan). AOTopsy punya `internal/callgraph`
    (`BuildCallGraph`) dan `internal/disasm.CallEdge` tapi tidak
    ada komparator.
  - **Instruction-level diff**: dua fungsi yang CodeRange.Size-nya
    beda — apa byte yang berubah? AOTopsy punya `sc.Code` (raw bytes
    instruksi) + `CodeRange.PCOffset/Size` + `disasm` (ARM64/x86
    lifter) tapi tidak ada diff byte/mnemonic antar build.
  - **Inline-tree diff**: `CodeSourceMap` punya inline stack per PC
    (`CodeSourceMapInfo.Entries[].InlineStack`); `InlinedFuncsRef`
    di `CodeEntry` sudah ditangkap. Tidak ada diff "fungsi X dulu
    meng-inline Y, sekarang tidak" — sinyal optimizer/TFA change.
  - **Exception-handler diff**: `PcDescriptors` punya try/catch
    region; tidak ada diff "fungsi X dulu tanpa try/catch, sekarang
    punya".
- **Bukti SDK**:
  - `CodeSourceMap` (`raw_object.h` `UntaggedCodeSourceMap`) menyimpan
    PC → inline stack + token pos. AOTopsy menangkap
    (`CodeSourceMapInfo`, `cluster.go:147`).
  - `ExceptionHandlers` (`raw_object.h`) menyimpan handler table.
    AOTopsy menangkap (`ExceptionHandlerInfo`, `cluster.go:129`).
  - `Code.inlined_id_to_function_` (ref index 4 di 3.x AOT) — AOTopsy
    menangkap (`CodeEntry.InlinedFuncsRef`, `cluster.go:78`).
- **Dampak**: RE harus manual buka dua binary di IDA/Ghidra untuk
  bandingkan call graph dan instruksi. funcdiff tidak memberikan
  "apa yang berubah di dalam fungsi X".
- **Usulan**:
  1. **Call-edge diff**: untuk setiap fungsi common, bangun
     `[]CallEdge` via `disasm` + `callgraph.BuildCallGraph`, lalu
     diff set edge lama vs baru. Tambah `CallEdgeAdded` /
     `CallEdgeRemoved` di `Report` per fungsi.
  2. **Instruction mnemonic diff**: disasm kedua range, diff list
     mnemonic (normalisasi register agar tidak noise reassign).
     Output "first diverging PC" per fungsi.
  3. **Inline-tree diff**: resolve `InlinedFuncsRef` → list Function
     descriptor; diff list lama vs baru. Tambah `InlinedChanged`.
  4. **Exception-handler diff**: diff `PcDescriptors` try/catch
     region lama vs baru. Tambah `TryCatchChanged`.
- **Prioritas**: **P2 — menengah**. Fitur besar tapi infrastruktur
  sudah ada; ini adalah diferensiasi funcdiff vs flutterdec.

### Gap 6: `token_pos_` (line number AOT non-PRODUCT) di-drop oleh `specFunction`

- **Deskripsi**: `specFunction` (`fillspec.go:241`) hanya membaca
  `code_index` + `packed_fields` (2.x) + `kind_tag`. Ia TIDAK membaca
  `token_pos_` yang di-AOT menyimpan **line number** sumber. SDK
  `FunctionDeserializationCluster::ReadFill` membaca `token_pos_`
  di bawah guard
  `#if !defined(DART_PRECOMPILED_RUNTIME) || (defined(DART_PRECOMPILED_RUNTIME) && !defined(PRODUCT))`
  — artinya di AOT **non-PRODUCT** (release dengan simbol, profile
  build) `token_pos_` ada di stream dan berisi line number. Di AOT
  PRODUCT (release final) ia tidak diserialisasi.
- **Bukti SDK**:
  - Serializer (`app_snapshot.cc` @3.7.0 line ~1755):
    ```cpp
    #if defined(DART_PRECOMPILER) && !defined(PRODUCT)
      TokenPosition token_pos = func->untag()->token_pos_;
      if (kind == Snapshot::kFullAOT) {
        // We use then token_pos property to store the line number
        // in AOT snapshots.
        intptr_t line = -1;
        const Function& function = Function::Handle(func);
        const Script& script = Script::Handle(function.script());
        if (!script.IsNull()) {
          script.GetTokenLocation(token_pos, &line, nullptr);
        }
        token_pos = line == -1 ? TokenPosition::kNoSource
                               : TokenPosition::Deserialize(line);
      }
      s->WriteTokenPosition(token_pos);
    #else
      if (kind != Snapshot::kFullAOT) {
        s->WriteTokenPosition(func->untag()->token_pos_);
      }
    #endif
    ```
    Komentar SDK eksplisit: "We use then token_pos property to store
    the line number in AOT snapshots."
  - Deserializer (`app_snapshot.cc` @3.7.0 line ~1930):
    ```cpp
    #if !defined(DART_PRECOMPILED_RUNTIME) || \
        (defined(DART_PRECOMPILED_RUNTIME) && !defined(PRODUCT))
      func->untag()->token_pos_ = d.ReadTokenPosition();
    #endif
    ```
  - AOTopsy `specFunction` (`fillspec.go:245-249`) scalars hanya
    `OpUnsigned` (code_index) + `OpTagged32` (packed_fields, 2.x) +
    `OpTagged32` (kind_tag). Tidak ada `OpTokenPosition` untuk
    `token_pos_`. Akibat: di build non-PRODUCT, stream funcdiff
    salah align (skip token_pos) → kind_tag terbaca sebagai token_pos,
    semua FuncKind salah. Ini bukan hanya gap RE, ini **bug parse**
    untuk binary non-PRODUCT.
- **Dampak**:
  - RE: line number fungsi hilang — funcdiff tidak bisa emit
    "fungsi X di main.dart:42 berubah".
  - Bug parse: untuk binary AOT non-PRODUCT, `specFunction` salah
    baca scalar (drop token_pos) → `FuncKind`/`IsStatic` korup untuk
    semua Function. `funcdiff.Build` lalu mungkin salah owner/name
    kalau ini juga menggeser ref loop (perlu verifikasi lebih lanjut,
    tapi setidaknya kind_tag pasti salah).
- **Usulan**:
  1. Tambah `OpTokenPosition` (atau `OpTagged32` untuk TokenPosition
     yang di-serialize sebagai int32) di `specFunction.Scalars`
     ketika profile menandakan AOT non-PRODUCT. Butuh flag
     `VersionProfile.FunctionHasTokenPos` (per-version, seperti
     `ClassHasTokenPos`).
  2. Simpan `LineNumber` di `NamedObject` untuk Function.
  3. funcdiff emit `LineChanged` (fungsi pindah line = deklarasi
     berubah lokasi, sinyal refactor).
- **Prioritas**: **P0 — kritis** untuk binary non-PRODUCT (bug parse
  + RE gap ganda); **P2** untuk PRODUCT (tidak ada data, tidak bisa
  di-gap).

### Gap 7: Tidak ada diff class-level / field-layout change

- **Deskripsi**: Perubahan field kelas (tambah/hapus field, ubah
  offset, ubah type) memengaruhi semua method kelas itu. funcdiff
  tidak melihat class sama sekali. Padahal `cluster.Result.Classes`
  (`ClassInfo`: InstanceSize, NextFieldOff, TypeArgsOff, SuperTypeRefID,
  LibraryRefID, UnboxedFieldBitmap) dan `cluster.Result.Fields`
  (`FieldInfo`: NameRefID, OwnerRefID, KindBits, HostOffset, TypeRefID,
  InitializerRefID) sudah di-parse.
- **Bukti SDK**:
  - `UntaggedClass` (`raw_object.h`) punya `instance_size_in_words_`,
    `next_field_offset_in_words_`, `type_arguments_field_offset_in_words_`,
    `super_type_`, `library_`. AOTopsy menangkap semua (`ClassInfo`).
  - `UntaggedField` punya `kind_bits_`, `host_offset_or_field_id_`,
    `type_`, `initializer_function_`. AOTopsy menangkap (`FieldInfo`).
- **Dampak**: Refactor class (tambah field, ubah hierarki) tidak
  terdeteksi. RE yang melihat "fungsi X berubah" tidak tahu bahwa
  penyebabnya adalah class-nya tambah field (yang menggeser offset
  semua field lain → semua method akses field berubah).
- **Usulan**:
  1. Tambah `ClassDiff` report terpisah: class added/removed,
     `InstanceSizeChanged`, `FieldAdded`/`FieldRemoved`,
     `FieldOffsetChanged`, `SuperTypeChanged`.
  2. Cross-link: di report fungsi `Changed`, tandai fungsi-fungsi
     yang owner-class-nya juga `Changed` — sinyal bahwa perubahan
     fungsi sekunder terhadap perubahan class.
- **Prioritas**: **P2 — menengah**. Berguna untuk konteks refactor.

### Gap 8: `Report` tidak punya metadata evidence / tidak ada mode "why changed"

- **Deskripsi**: `Report` hanya list nama descriptor. Tidak ada:
  - old/new `CodeSize` (atau size nyata) per fungsi changed — RE tidak
    bisa ranking "fungsi mana yang berubah paling banyak".
  - old/new signature string — RE tidak bisa lihat diff signature
    tanpa buka dua binary.
  - old/new `RefID` — untuk cross-reference ke tool lain (disasm,
    decompiler) yang pakai RefID.
  - `ChangeMagnitude` (delta size, atau hash distance) — untuk
    prioritisasi.
- **Bukti SDK**: N/A (ini gap output format, bukan gap SDK).
- **Dampak**: Report funcdiff hanya bisa dibaca manusia sebagai
  "daftar nama". Tidak bisa di-post-process oleh tool RE lain.
- **Usulan**:
  1. Tambah `ChangedEntry` struct: `Descriptor`, `OldRefID`,
     `NewRefID`, `OldSize`, `NewSize`, `SizeDelta`,
     `OldSignature`, `NewSignature`, `SigChanged bool`,
     `CodeChanged bool`, `OldLine`, `NewLine`.
  2. `Report.Changed` jadi `[]ChangedEntry` (bukan `[]string`).
  3. Tambah `ChangeBuckets` (size delta <8 bytes = "tweak",
     8–64 = "minor", >64 = "major") untuk prioritisasi.
- **Prioritas**: **P2 — menengah**. Quality-of-life untuk RE workflow.

## Register Tracking Gaps

`funcdiff` tidak melakukan register tracking sama sekali — ia tidak
men-disasm instruksi. Tidak ada pelacakan register yang bisa "gap"
karena tidak ada yang dilacak. Namun, jika Gap 5 (instruction-level
diff) diimplementasi, register tracking berikut perlu dipertimbangkan:

- **ARM64**: `disasm/dataflowarm64.go` sudah ada pelacakan register
  per-instruksi. Untuk diff, perlu normalisasi register agar
  reassignment register oleh optimizer tidak men-trigger false
  positive. Usulan: normalisasi ke "register class" (ARG, TMP, RET)
  bukan nama register absolut.
- **x86_64**: `disasm/dataflowx86.go` sudah ada. Sama: normalisasi
  diperlukan.
- **THR register** (`thraudit`): register Thread (THR) di ARM64
  punya field offset konstanta (`thrfields_sdk_test.go`). Diff
  call-site ke THR field (mis. `LDR x16, [THR+#offset]`) bisa
  mendeteksi perubahan runtime call — sinyal kuat untuk patch
  keamanan/behavior. Tidak ada infrastruktur diff untuk ini.

Tidak ada register yang saat ini ditrack oleh funcdiff, jadi tidak
ada "register yang tidak ditrack seharusnya ditrack" — tapi ada
**register-level signal yang bisa ditrack jika instruction diff
diaktifkan** (THR field offset, pool index load via disasm/poolindex).

## Fitur RE Missing/Incomplete

1. **Per-package diff bucketing** (dart: vs package:flutter vs
   package:<app>) — flutterdec punya `collect_diff_package_counts`,
   AOTopsy tidak. Infra sudah ada (`LibraryResolver`,
   `IsFrameworkLibraryURL`).
2. **Closure diff** — kategori fungsi paling sering berubah di UI
   app, sepenuhnya di-skip.
3. **FFI trampoline diff** — callback native, sepenuhnya di-skip.
4. **Field initializer diff** — static config, sepenuhnya di-skip.
5. **Signature/parameter/return-type diff** — kontrak API change
   tidak terdeteksi.
6. **Call-edge diff** — perubahan call graph antar versi tidak
   terdeteksi.
7. **Instruction mnemonic diff** — perubahan implementasi fungsi
   tidak terlihat (hanya "changed" boolean).
8. **Inline-tree diff** — perubahan inlining TFA tidak terdeteksi.
9. **Exception-handler diff** — perubahan try/catch tidak
   terdeteksi.
10. **Line-number annotation** (AOT non-PRODUCT) — `token_pos_`
    di-drop; funcdiff tidak bisa emit "line 42 berubah".
11. **Class/field layout diff** — perubahan struktur class tidak
    terdeteksi, padahal menggeser semua method.
12. **Change magnitude ranking** — report tidak memberi ukuran
    "berapa banyak" per fungsi changed, RE tidak bisa prioritisasi.
13. **Cross-build RefID mapping** — report tidak menyimpan RefID
    lama/baru untuk cross-reference tool lain.
14. **Stable closure identity** — closure di-skip karena "tidak
    stabil", padahal `ClosureData.ParentFunctionRef` + index
    memberi identitas stabil.
15. **Diff vs unstripped build** — `symbolmap` package bisa
    memberi nama simbol untuk fungsi yang di-snapshot tidak punya
    nama; funcdiff tidak integrasi.

## Verifikasi SDK

Semua klaim SDK diverifikasi via dua jalur:

### Jalur 1: `gh api` @ tag `3.7.0`

- `runtime/vm/raw_object.h?ref=3.7.0`:
  - `UntaggedFunction` (line ~1237): field `name`, `owner`,
    `signature`, `data`, `code`, `kind_tag_`, `packed_fields_`,
    `token_pos_`, `end_token_pos_`, `kernel_offset_`,
    `is_optimizable_`, `unboxed_parameters_info_`.
  - `UntaggedFunction::Kind` enum: `RegularFunction`,
    `ClosureFunction`, `ImplicitClosureFunction`, `GetterFunction`,
    `SetterFunction`, `Constructor`, `ImplicitGetter`,
    `ImplicitSetter`, `ImplicitStaticGetter`, `FieldInitializer`,
    `MethodExtractor`, `NoSuchMethodDispatcher`, `InvokeFieldDispatcher`,
    `IrregexpFunction`, `DynamicInvocationForwarder`, `FfiTrampoline`,
    `RecordFieldGetter`.
  - `UntaggedClosureData` (line ~1480): `context_scope`,
    `parent_function`, `closure`, `packed_fields_`.
  - `UntaggedFunctionType` (line ~2851): `type_parameters`,
    `result_type`, `parameter_types`, `named_parameter_names`.
- `runtime/vm/app_snapshot.cc?ref=3.7.0`:
  - `FunctionSerializationCluster` (line ~1687) di balik
    `#if !defined(DART_PRECOMPILED_RUNTIME)` — serializer hanya
    ada di precompiler, bukan AOT runtime.
  - `FunctionDeserializationCluster::ReadFill` (line ~1880):
    membaca `ReadFromTo` + `code_index` (AOT) + `token_pos_`
    (guard `!PRECOMPILED_RUNTIME || (PRECOMPILED_RUNTIME && !PRODUCT)`)
    + `end_token_pos_`/`kernel_offset_`/`is_optimizable_`
    (`!PRECOMPILED_RUNTIME`) + `kind_tag_` (selalu).
  - Serializer `payload_info` (line ~8694):
    `(unchecked_offset << 1) | has_monomorphic_entry` — BUKAN size.
  - Deserializer `payload_info` (line ~9834):
    `unchecked_offset = payload_info >> 1;
    has_monomorphic_entrypoint = (payload_info & 0x1) == 0x1`.
  - Serializer `token_pos_` AOT (line ~1755): komentar eksplisit
    "We use then token_pos property to store the line number in
    AOT snapshots" + `script.GetTokenLocation(token_pos, &line, ...)`.

### Jalur 2: `grep` MCP `searchGitHub` (repo filter `dart-lang/sdk`)

- Query `FunctionSerializationCluster` → konfirmasi lokasi
  `runtime/vm/app_snapshot.cc` + `pkg/native_compiler/lib/snapshot/snapshot.dart`
  (Dart port). Serializer C++ di balik `#if !defined(DART_PRECOMPILED_RUNTIME)`.
- Query `payload_info` → konfirmasi encoding
  `(unchecked_offset << 1) | has_monomorphic_entry` di serializer
  dan decode `payload_info >> 1` di deserializer.

### Cross-check AOTopsy internal

- `internal/cluster/fill_code.go:13` — AOTopsy sendiri menyebut
  `payload_info` tanpa pernah mengklaim itu size; ini konfirmasi
  bahwa `funcdiff.go:32` salah menginterpretasi.
- `internal/cluster/instrtable.go:138-177` — `ResolveCodeRanges`
  menghitung `CodeRange.Size` nyata via PCOffset diff; ini sumber
  size yang benar dan sudah ada di `sc.Ranges`.
- `internal/analysis/libraryxref.go:54` — `LibraryURLForClassRef`
  sudah ada; funcdiff tidak memanggil.
- `internal/cluster/fillspec.go:241` — `specFunction` scalars
  tidak ada `OpTokenPosition`; konfirmasi `token_pos_` di-drop.
- `internal/cluster/fill.go:15-58` — `NamedObject` punya
  `SignatureRefID`, `FuncKind`, `IsStatic`, `NumFixedParams`,
  `NumOptionalParams`, `HasKindTag` — semua tidak dipakai funcdiff.
- `internal/cluster/fill.go:329-344` — `ClosureDataInfo` +
  `ClosureInfo` sudah ditangkap; funcdiff tidak pakai.

Tidak ada build/test/run AOTopsy yang dijalankan, sesuai instruksi.
Verifikasi murni berbasis kode + SDK source.
