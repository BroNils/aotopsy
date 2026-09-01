# RE Gap Analysis Report: internal/typetrack

> **STATUS VERIFIKASI (2026-09-01)** — Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`. Koreksi:
> - **Gap 1 (LDP-from-PP) → CONFIRMED di kode, PRIORITAS SALAH.**
>   `intraproc_handlers.go:183` memang hanya menangani LDP dengan
>   `rn == sdk.ARM64SPReg`. Tapi diukur di biner: LDP dari PP muncul **14×**
>   (3.9.2) dan **123×** (realapp produksi) — ~0,2% dari pool load. Klaim
>   "switchable call adalah pola instance call utama di AOT" tidak terbukti
>   untuk ARM64 rilis; dispatch-table call yang dominan. Perbaikannya murah
>   (decoder LDP sudah inline di file yang sama), tapi bukan P0.
> - **Klaim "form-2 PP load tidak ditrack" (jika terbaca begitu) → tidak
>   berlaku di sini**: `handlePPLoad` (`:250-258`) menangani 2-level PP
>   addressing lewat `LatticePPBase`.
> - **Gap 2 (`imm9 == 7` saja) dan Gap 3 (Closure `entry_point_` vs
>   `function`) → CONFIRMED.** Untuk Gap 3, `:530` menerima `imm9 == 19 || 31`
>   **tanpa** memeriksa `CompressedPointers` — di build compressed, offset 31
>   adalah `entry_point_`, jadi `KnownClass(ownerCID)` yang di-set salah.
> - **Gap 4 (x86_64 PP handler) dan Gap 6 (LEA-from-THR) → CONFIRMED.**
> - Gap 8–11 memang minor, dan report sendiri sudah menilainya rendah — itu
>   penilaian yang jujur.

## Ringkasan

Folder `internal/typetrack` mengimplementasikan type inference dan receiver
recovery untuk binary Dart AOT (libapp.so). Analisis ini membandingkan apa
yang dilakukan kode AOTopsy vs apa yang Dart SDK source code sediakan.

Ditemukan **11 gap** signifikan, dikelompokkan dalam tiga kategori:

1. **Register tracking gaps** (3): LDP-from-PP tidak ditrack, register
   TypeTestABI tidak ditrack, register FUNCTION_REG/CODE_REG tidak ditrack
   sebagai sumber type info.
2. **Logika eksplorasi/analisa gap** (5): Code entry point offsets hanya
   offset 7 (kNormal uncompressed), Closure entry_point_ vs function
   confusion, x86_64 PP load handler tidak resolve Code/UnlinkedCall/TTS,
   LEA-from-THR terlalu agresif, narrowing hanya B.EQ/B.NE (range branch
   tidak ditrack).
3. **Fitur RE missing/incomplete** (3): TTS dst type propagation, write
   barrier slot register (R25) tidak ditrack, MegamorphicCache call pattern
   tidak ditrack.

Beberapa gap ini mematikan jalur resolusi BLR yang seharusnya aktif di AOT:
switchable call (LDP-from-PP), monomorphic entry point load, dan closure
entry_point_ load adalah tiga pola utama yang dipakai SDK untuk instance
call di AOT mode.

## Struktur Folder

```
internal/typetrack/
├── lattice.go                    — type lattice (Top/KnownClass/KnownDispatchIndex/KnownStub/PPBase/Bottom), meet, LCA
├── sources.go                    — TypeContext struct + BuildTypeContext + FieldValueClass + ResolveDispatchCHA
├── sources_builders.go           — sub-builder: class hierarchy, field types, pool class, dispatch tables, closure data
├── intraproc.go                  — ARM64 intra-procedural dataflow: AnalyzeFunction, buildBlocks, transferInstruction, resolveBLR
├── intraproc_handlers.go         — ARM64 per-instruction handlers: stack store/load, THR/PP/dispatch load, field load
├── intraproc_handlers_call.go    — ARM64 call handlers: handleUBFX, handleMOV, handleBLR, handleBL
├── intraproc_decoders.go         — recordFieldStore, recordAllocationSite, isCondBranch
├── intraprocx86.go               — x86_64 intra-procedural dataflow: AnalyzeFunctionX86, buildBlocksX86, transferInstructionX86
├── interproc.go                  — inter-procedural fixed-point: RunInterprocedural, BLEdge, parameter type propagation
├── dispatch.go                   — WriteTypeInferenceReport, WriteDispatchTable, FormatLattice
├── dispatch_shared.go            — scanDispatchSlots, applyDispatchCandidates (shared ARM64/x86)
├── receiver_recovery.go          — pre-3.4.3 receiver stack slot recovery from code (ARM64 + x86)
├── *_test.go                     — unit tests (6 files)
```

Total ~6353 baris Go (termasuk test).

## Gap Analysis

### Gap 1: LDP-from-PP (LoadDoubleWordFromPoolIndex) tidak ditrack

- **Deskripsi**: SDK AOT instance call (`EmitInstanceCallAOT` di
  `flow_graph_compiler_arm64.cc`) memancarkan pola:
  ```asm
  LDP R5, LR, [PP + offset]    ; LoadDoubleWordFromPoolIndex(R5, LR, data_index)
  BLR LR                       ; call through LR
  ```
  `LoadDoubleWordFromPoolIndex` (assembler_arm64.cc) memancarkan `ldp`
  (Load Pair) dari PP atau dari TMP=PP+offset. Ini memuat dua entry pool
  berurutan: `data_index` ke R5 (UnlinkedCall) dan `data_index+1` ke LR
  (stub Code entry point).

  `handlePPLoad` (intraproc_handlers.go:242) hanya menangani `LDR Xt, [PP, #imm]`
  (single load) dan 2-level `LDR Xt, [Xn, #imm]` di mana Xn = PP + offset.
  Tidak ada handler untuk `LDP` dari PP. `handleStackLoad` menangani LDP
  tetapi hanya dari SP (X15), bukan PP (X27).

  Akibatnya, LR tidak pernah ditrack sebagai KnownStub("UnlinkedCall:...")
  atau KnownStub("PPCode:...") untuk pola ini, sehingga resolusi BLR via
  UnlinkedCall/PPCode tidak pernah menyala untuk switchable call AOT.

- **Bukti SDK**:
  - `flow_graph_compiler_arm64.cc` @3.9.2 baris ~528-540 (`EmitInstanceCallAOT`):
    ```c++
    __ LoadDoubleWordFromPoolIndex(R5, LR, data_index);
    CLOBBERS_LR(__ blr(LR));
    ```
  - `flow_graph_compiler_arm64.cc` @3.9.2 baris ~472 (`EmitOptimizedStaticCall`-style):
    ```c++
    __ LoadDoubleWordFromPoolIndex(IC_DATA_REG, CODE_REG, ic_data_index);
    __ Call(FieldAddress(CODE_REG, entry_point_offset));
    ```
  - `assembler_arm64.cc` @3.9.2 (`LoadDoubleWordFromPoolIndex`):
    ```c++
    ldp(lower, upper, Address(PP, offset, Address::PairOffset));
    ```
  - Verifikasi `gh api` ke `runtime/vm/compiler/assembler/assembler_arm64.cc?ref=3.9.2`
    mengkonfirmasi `ldp` instruction emission.

- **Dampak**: Switchable call AOT adalah pola instance call utama di AOT
  mode. Tanpa tracking LDP-from-PP, semua BLR LR yang berasal dari pola
  ini tidak ter-resolve. `PoolUnlinkedCallNames` dan `PoolCodeNames` sudah
  dibangun tetapi tidak pernah dikonsumsi untuk pola ini karena register
  LR tidak ditrack.

- **Usulan**:
  1. Tambah handler `handleLDPFromPP` di `intraproc_handlers.go` yang
     mendeteksi `LDP Xt1, Xt2, [PP, #imm]` (base=PP, pair offset).
  2. Resolvi kedua register: `Xt1` dari `PoolUnlinkedCallNames[poolIdx]`
     atau `PoolCodeNames[poolIdx]`, `Xt2` dari `poolIdx+1`.
  3. Tangani juga 2-level: `ADD TMP, PP, #upper20; LDP Xt1, Xt2, [TMP, #lower12]`.
  4. Set LR (X30) ke KnownStub("PPCode:funcName") atau
     KnownStub("UnlinkedCall:methodName") sesuai entry pool.

- **Prioritas**: **Tinggi** — ini mematikan jalur resolusi BLR utama AOT.

### Gap 2: Code entry point offsets hanya offset 7 (kNormal uncompressed)

- **Deskripsi**: `handleFieldLoad` (intraproc_handlers.go:509) hanya
  menangani `imm9 == 7` untuk PPCode/TTS entry point load:
  ```go
  if imm9 == 7 && base < 31 && tc.state[base].Kind == LatticeKnownStub {
      sn := tc.state[base].StubName
      if strings.HasPrefix(sn, "PPCode:") || strings.HasPrefix(sn, "TTS:") {
          tc.state[rt] = KnownStub(sn, imm9)
          return true
      }
  }
  ```

  SDK `UntaggedCode` (`raw_object.h`) memiliki **empat** entry point fields:
  ```c++
  uword entry_point_;                     // kNormal
  uword monomorphic_entry_point_;         // kMonomorphic (AOT switchable call)
  uword unchecked_entry_point_;           // kUnchecked
  uword monomorphic_unchecked_entry_point_; // kMonomorphicUnchecked
  ```

  Offset tagged (dari `sdk/registers.go`):
  | EntryKind | Uncompressed | Compressed |
  |---|---|---|
  | kNormal | 7 (0x7) | 3 (0x3) |
  | kMonomorphic | 23 (0x17) | 11 (0xb) |
  | kUnchecked | 15 (0xf) | 7 (0x7) |
  | kMonomorphicUnchecked | 31 (0x1f) | 15 (0xf) |

  Handler hanya menangani offset 7. Offset yang miss:
  - kMonomorphic (23/11) — **paling kritis**: dipakai `EmitOptimizedStaticCall`
    dan switchable call monomorphic.
  - kUnchecked (15/7) — dipakai saat call-site tahu type args sudah benar.
  - kMonomorphicUnchecked (31/15).
  - kNormal compressed (3).

  Catatan: di compressed mode, kUnchecked disp = 7 (sama dengan kNormal
  uncompressed), sehingga handler `imm9 == 7` secara tidak sengaja menangani
  kUnchecked compressed tetapi dengan prefix check yang salah (PPCode/TTS
  vs seharusnya tidak peduli entry kind).

- **Bukti SDK**:
  - `raw_object.h` @3.9.2: `UntaggedCode` punya 4 entry_point_ fields.
  - `flow_graph_compiler_arm64.cc` @3.9.2 (`EmitOptimizedStaticCall`):
    ```c++
    const intptr_t entry_point_offset =
        entry_kind == Code::EntryKind::kNormal
            ? Code::entry_point_offset(Code::EntryKind::kMonomorphic)
            : Code::entry_point_offset(Code::EntryKind::kMonomorphicUnchecked);
    __ Call(compiler::FieldAddress(CODE_REG, entry_point_offset));
    ```
  - `sdk/registers.go` baris 193-201 mendokumentasikan keempat offset.

- **Dampak**: Monomorphic switchable call (pola `LDR LR, [CODE_REG, #entry_point_offset]; BLR LR`)
  tidak ter-resolve ketika entry_point_offset ≠ 7. Di AOT dengan compressed
  pointers, kMonomorphic disp = 11, yang tidak ditrack.

- **Usulan**:
  1. Ganti `imm9 == 7` dengan cek himpunan offset:
     `{3, 7, 11, 15, 23, 31}` (atau gunakan `sdk.CodeEntryPointDisp*`).
  2. Atau track entry kind di lattice: tambah field `EntryPointKind` ke
     `TypeLattice` saat Kind = KnownStub dengan prefix PPCode/TTS.
  3. Untuk TTS, `AbstractType::type_test_stub_entry_point_offset` = 8
     untagged = 7 tagged (tidak berubah compressed/uncompressed karena
     field pertama setelah header 8-byte). Tapi di compressed mode dengan
     header 4-byte, offset = 4 untagged = 3 tagged. Verifikasi ke SDK.

- **Prioritas**: **Tinggi**.

### Gap 3: Closure entry_point_ vs function confusion di compressed mode

- **Deskripsi**: `handleFieldLoad` menangani Closure field load:
  ```go
  if strings.HasPrefix(sn, "Closure:") && (imm9 == 19 || imm9 == 31) {
      poolIdx := tc.state[base].StubOff
      if ownerCID, ok := tc.ctx.PoolClosureClass[poolIdx]; ok && ownerCID >= 0 {
          tc.state[rt] = KnownClass(ownerCID)
          return true
      }
  }
  ```

  Komentar mengatakan offset 19 = compressed function, 31 = uncompressed
  function. Tapi di AOT precompiled mode, closure call TIDAK memanggil
  melalui `function` field — ia memanggil melalui `entry_point_` field
  (`il_arm64.cc`):
  ```c++
  if (FLAG_precompiled_mode) {
      __ LoadFieldFromOffset(R2, R0, Closure::entry_point_offset());
      __ blr(R2);
  }
  ```

  Layout `UntaggedClosure` (`raw_object.h` @3.9.2):
  | Field | Compressed offset | Uncompressed offset |
  |---|---|---|
  | instantiator_type_arguments | 4 (3 tagged) | 8 (7 tagged) |
  | function_type_arguments | 8 (7 tagged) | 16 (15 tagged) |
  | delayed_type_arguments | 12 (11 tagged) | 24 (23 tagged) |
  | function | 16 (15 tagged) | 32 (31 tagged) |
  | context | 20 (19 tagged) | 40 (39 tagged) |
  | hash | 24 (23 tagged) | 48 (47 tagged) |
  | **entry_point_** | **32 (31 tagged)** | **56 (55 tagged)** |

  **Masalah**: Di compressed mode, offset 31 adalah `entry_point_`
  (ONLY_IN_PRECOMPILED), BUKAN `function`. AOTopsy menangani offset 31
  sebagai "uncompressed function" dan men-set KnownClass(ownerCID), tetapi
  di compressed AOT, nilai yang dimuat adalah raw entry point address
  (uword), bukan FunctionPtr.

  Sebaliknya, `function` di compressed mode ada di offset 15 (15 tagged),
  yang TIDAK ditrack.

  Di uncompressed mode, `function` ada di offset 31 (benar ditrack), tetapi
  `entry_point_` ada di offset 55 (TIDAK ditrack).

- **Bukti SDK**:
  - `raw_object.h` @3.9.2: `UntaggedClosure` field order:
    `instantiator_type_arguments`, `function_type_arguments`,
    `delayed_type_arguments`, `function`, `context`, `hash`,
    `ONLY_IN_PRECOMPILED(uword entry_point_)`.
  - `il_arm64.cc` @3.9.2: AOT closure call pakai `entry_point_offset()`,
    bukan `function_offset()`.
  - Verifikasi `gh api` ke `runtime/vm/raw_object.h?ref=3.9.2`.

- **Dampak**: Di AOT compressed (Dart 2.18+ / 3.x default), closure call
  via entry_point_ tidak ter-resolve dengan benar. KnownClass(ownerCID)
  yang di-set adalah type yang salah (bukan FunctionPtr melainkan entry
  point address).

- **Usulan**:
  1. Tambah offset `entry_point_`: 31 (compressed) / 55 (uncompressed).
  2. Untuk `entry_point_` load, set KnownStub("ClosureEntry:funcName")
     menggunakan `PoolClosureFunctionNames[poolIdx]`, BUKAN
     KnownClass(ownerCID).
  3. Tangani `function` offset yang benar: 15 (compressed) / 31
     (uncompressed) — tetapi ini hanya dipakai di JIT mode, bukan AOT.
  4. Di handleBLR, tambah case "ClosureEntry:" yang resolve ke
     `PoolClosureFunctionNames[poolIdx]`.

- **Prioritas**: **Tinggi** — closure call adalah pola umum di AOT.

### Gap 4: x86_64 PP load handler tidak resolve Code/UnlinkedCall/TTS/Closure

- **Deskripsi**: Handler x86_64 untuk PP load (`intraprocx86.go:481-501`)
  hanya mengecek `PoolClassByIndex` dan `PoolClosureClass`:
  ```go
  if baseIdx == sdk.X86PP {
      poolIdx, poolIdxOK := disasm.X64PoolIndex(mem.Disp)
      if !poolIdxOK { return }
      if classID, ok2 := ctx.PoolClassByIndex[poolIdx]; ok2 && classID >= 0 {
          state[dstIdx] = KnownClass(classID)
          ctx.PPHits++
      } else if ctx.PoolClosureClass != nil {
          if classID, ok3 := ctx.PoolClosureClass[poolIdx]; ok3 && classID >= 0 {
              state[dstIdx] = KnownClass(classID)
              ctx.PPHits++
              return
          }
          state[dstIdx] = Top()
      } else {
          state[dstIdx] = Top()
      }
      return
  }
  ```

  Handler ARM64 `resolvePPLoad` (intraproc_handlers.go:264-333) mengecek
  **empat** sumber: `PoolUnlinkedCallNames`, `PoolCodeNames`,
  `PoolClassByIndex` (+ TTS), `PoolClosureClass`. Handler x86_64 hanya
  mengecek dua: `PoolClassByIndex` dan `PoolClosureClass`.

  Yang miss di x86_64:
  - `PoolUnlinkedCallNames` — UnlinkedCall target name (switchable call).
  - `PoolCodeNames` — Code object function name (monomorphic call).
  - `TypeTestingStubNames` — TTS stub name (type test call).

  Akibatnya, di x86_64 AOT, `LoadUniqueObject(RCX, initial_stub)` dan
  `LoadUniqueObject(RBX, data)` di `EmitInstanceCallAOT` menghasilkan Top
  di RCX dan RBX, sehingga `call(RCX)` tidak ter-resolve.

- **Bukti SDK**:
  - `flow_graph_compiler_x64.cc` @3.9.2 (`EmitInstanceCallAOT`):
    ```c++
    __ LoadUniqueObject(RCX, initial_stub, snapshot_behavior);
    __ LoadUniqueObject(RBX, data);
    __ call(RCX);
    ```
  - `LoadUniqueObject` → `LoadObjectHelper` → load dari PP.
  - Handler ARM64 `resolvePPLoad` sudah mengecek semua empat sumber.

- **Dampak**: Resolusi BLR via UnlinkedCall/PPCode/TTS tidak berfungsi di
  x86_64. `PoolUnlinkedCallNames`, `PoolCodeNames`, dan
  `TypeTestingStubNames` sudah dibangun di `BuildTypeContext` tetapi tidak
  dikonsumsi di x86_64 PP load handler.

- **Usulan**:
  1. Tambahkan cek `PoolUnlinkedCallNames`, `PoolCodeNames`,
     `TypeTestingStubNames` ke x86_64 PP load handler, mirror ARM64
     `resolvePPLoad`.
  2. Set KnownStub("UnlinkedCall:...") / KnownStub("PPCode:...") /
     KnownStub("TTS:...") sesuai pool index.
  3. Tambah PPHits++ untuk setiap resolve sukses.

- **Prioritas**: **Tinggi** — paritas ARM64/x86_64.

### Gap 5: TypeTestABI register tidak ditrack untuk TTS dispatch

- **Deskripsi**: SDK `TypeTestABI` (`constants_arm64.h` @3.9.2)
  mendefinisikan register convention untuk TypeTestingStub call:
  ```c++
  struct TypeTestABI {
      static constexpr Register kInstanceReg = R0;              // instance being tested
      static constexpr Register kDstTypeReg = R8;               // destination type
      static constexpr Register kInstantiatorTypeArgumentsReg = R2;
      static constexpr Register kFunctionTypeArgumentsReg = R1;
      static constexpr Register kSubtypeTestCacheReg = R3;
      static constexpr Register kScratchReg = R4;
      static constexpr Register kSubtypeTestCacheResultReg = R7;
  };
  ```

  TTS call pattern (`flow_graph_compiler_arm64.cc:188`):
  ```c++
  __ LoadField(TTSInternalRegs::kScratchReg,    // R4
      FieldAddress(reg_to_call, type_test_stub_entry_point_offset()));
  __ LoadWordFromPoolIndex(TypeTestABI::kSubtypeTestCacheReg,  // R3
      sub_type_cache_index);
  __ blr(TTSInternalRegs::kScratchReg);  // BLR R4
  ```

  AOTopsy `handleBLR` menangani TTS:
  ```go
  } else if strings.HasPrefix(sn, "TTS:") {
      stubName := sn[len("TTS:"):]
      tc.result.BLRResolutions = append(...)
  }
  ```

  Tapi AOTopsy tidak melakukan **type propagation** dari TTS call:
  - R0 (kInstanceReg) holds the instance being tested — setelah TTS
    returns, R0 masih holds instance dengan type info yang diperkuat.
  - R8 (kDstTypeReg) holds the destination Type — tidak ditrack.
  - R7 (kSubtypeTestCacheResultReg) holds boolean result — tidak ditrack.

  Setelah TTS call, kode user biasanya melakukan branch pada hasil
  (R7 atau flags) untuk cast atau type check. Tanpa tracking R0 sebagai
  "instance of DstType", narrowing setelah TTS tidak menyala.

- **Bukti SDK**:
  - `constants_arm64.h` @3.9.2: `TypeTestABI` struct dengan 7 register.
  - `flow_graph_compiler_arm64.cc` @3.9.2 baris ~188: TTS call pattern.
  - Verifikasi `gh api` ke `runtime/vm/constants_arm64.h?ref=3.9.2`.

- **Dampak**: Setelah `is` check atau `as` cast via TTS, type narrowing
  tidak menyala karena instance register (R0) tidak ditrack sebagai
  "narrowed to DstType". Ini mempengaruhi resolusi dispatch downstream
  yang bergantung pada type yang diperkuat oleh cast.

- **Usulan**:
  1. Saat handleBLR mendeteksi TTS call (KnownStub "TTS:name"),
     baca DstType dari R8 (jika KnownClass/KnownStub Type) dan set
     R0 = KnownClass(DstType.ClassID) setelah call.
  2. Atau gunakan informasi TTS name (yang sudah berisi type name) untuk
     men-set R0 = KnownClass(classID dari TTS name).
  3. Track R7 sebagai boolean result untuk branch narrowing.

- **Prioritas**: **Sedang** — type narrowing setelah cast adalah fitur
  RE yang useful.

### Gap 6: LEA-from-THR di x86_64 terlalu agresif (false positive)

- **Deskripsi**: `transferInstructionX86` (intraprocx86.go:647) menangani
  `LEA reg, [THR+disp]`:
  ```go
  if baseIdx == sdk.X86THR && mem.Disp != 0 {
      // This loads the dispatch table array from Thread.
      state[dstIdx] = KnownDispatch(0)
      return
  }
  ```

  Komentar mengatakan "This loads the dispatch table array from Thread",
  tetapi LEA dari THR bisa memuat address dari **field Thread manapun**,
  bukan hanya dispatch table. THR memiliki puluhan field
  (`ObjectStoreAOTFieldCount` menghitung ~50+ field).

  `LoadDispatchTable` di SDK (`assembler_x64.cc:1510`) menggunakan `movq`
  (MOV), bukan `LEA`:
  ```c++
  void Assembler::LoadDispatchTable(Register dst) {
      movq(dst, Address(THR, target::Thread::dispatch_table_array_offset()));
  }
  ```

  Jadi LEA dari THR seharusnya TIDAK set KnownDispatch(0). Hanya MOV dari
  THR dengan offset dispatch_table_array yang harus set KnownDispatch(0).

  Handler MOV dari THR sudah ada (intraprocx86.go:521):
  ```go
  if stubName == "dispatch_table_array" {
      state[dstIdx] = KnownDispatch(0)
      return
  }
  ```

  Jadi handler LEA dari THR adalah duplikat yang terlalu luas dan bisa
  meng-overwrite type info yang benar dengan KnownDispatch(0) yang salah.

- **Bukti SDK**:
  - `assembler_x64.cc` @3.9.2: `LoadDispatchTable` pakai `movq`, bukan `lea`.
  - `flow_graph_compiler_x64.cc` @3.9.2: `__ LoadDispatchTable(table_reg)`
    di `EmitDispatchTableCall`.

- **Dampak**: Register yang di-LEA dari THR untuk alasan lain (misalnya
  mengambil address dari Thread field untuk write barrier) salah ditrack
  sebagai KnownDispatch(0), yang bisa menyebabkan resolusi dispatch yang
  salah.

- **Usulan**:
  1. Hapus handler `LEA reg, [THR+disp] → KnownDispatch(0)`.
  2. Atau ganti dengan cek offset spesifik `dispatch_table_array_offset`
     dari `THRFields` map, sama seperti MOV handler.

- **Prioritas**: **Sedang** — false positive yang bisa menyebabkan
  resolusi dispatch salah.

### Gap 7: Narrowing hanya B.EQ/B.NE, range branch tidak ditrack

- **Deskripsi**: `equalitySuccessor` (intraproc.go:661) hanya mengenali
  B.EQ (cond=0) dan B.NE (cond=1) sebagai equality branch:
  ```go
  switch last & 0xF {
  case 0: return sdk.SuccEqual    // B.EQ
  case 1: return sdk.SuccNotEqual // B.NE
  }
  return sdk.SuccUnknown
  ```

  SDK `GenerateNumberTypeCheck` dan `CompareClassId` sering memancarkan
  range check: `CMP class_id, #lower; B.LS target` (class_id <= lower)
  atau `B.HI` / `B.GE` / `B.LT` / `B.GT`.

  Contoh dari SDK (`flow_graph_compiler.h`):
  ```c++
  void GenerateNumberTypeCheck(Register kClassIdReg, ...);
  void GenerateStringTypeCheck(Register kClassIdReg, ...);
  void GenerateListTypeCheck(Register kClassIdReg, ...);
  ```

  Pola umum type check:
  ```asm
  LDR W0, [Xobj, #-1]        ; header
  UBFX W0, W0, #12, #20      ; class id
  CMP W0, #kDoubleCid        ; lower bound
  B.HI not_double             ; class_id > kDoubleCid → not double
  CMP W0, #kDoubleCid         ; exact match
  B.EQ is_double
  ```

  AOTopsy hanya menangani B.EQ (exact match → KnownClass(N)). Range
  branch seperti `B.LS` (class_id <= N) tidak ditrack, padahal ini bisa
  mempersempit ke himpunan class {0..N}.

  Komentar di kode mengakui ini:
  ```
  // the lattice cannot express "not N", so nothing is learned.
  ```

  Tetapi lattice BISA mengekspresikan "class_id <= N" sebagai range
  constraint yang bisa dikonsumsi oleh downstream analysis (misalnya
  filter dispatch candidates).

- **Bukti SDK**:
  - `flow_graph_compiler.h` @3.9.2: `GenerateNumberTypeCheck`,
    `GenerateStringTypeCheck`, `GenerateListTypeCheck` menggunakan
    range check.
  - ARM64 B.cond encoding: cond 0=EQ, 1=NE, 2=CS/HS, 3=CC/LO,
    4=MI, 5=PL, 6=VS, 7=VC, 8=HI, 9=LS, 10=GE, 11=LT, 12=GT, 13=LE.

- **Dampak**: Type narrowing dari range check (yang umum di type test
  stub dan inline type check) tidak menyala. Hanya exact-match CMP+B.EQ
  yang menghasilkan KnownClass.

- **Usulan**:
  1. Tambah lattice kind `LatticeClassRange` dengan field `Lo, Hi int`.
  2. Pada B.LS (cond=9) set range [0, cmpImm]; pada B.HI (cond=8) set
    range [cmpImm+1, MaxCID]; pada B.GE (cond=10) set [cmpImm, MaxCID];
    pada B.LT (cond=11) set [0, cmpImm-1]; pada B.GT (cond=12) set
    [cmpImm+1, MaxCID]; pada B.LE (cond=13) set [0, cmpImm].
  3. Konsumsi range di `selectorCandidates` untuk filter candidates
    yang class ID-nya di luar range.

- **Prioritas**: **Sedang** — meningkatkan presisi type inference.

### Gap 8: FUNCTION_REG (R0) dan CODE_REG (R24) tidak ditrack sebagai type source

- **Deskripsi**: SDK `constants_arm64.h` @3.9.2:
  ```c++
  const Register FUNCTION_REG = R0;  // used for function lookup
  const Register CODE_REG = R24;     // current Code object
  ```

  `FUNCTION_REG` (R0) digunakan di closure call non-AOT dan dynamic
  modules:
  ```c++
  // il_arm64.cc:
  ASSERT(locs()->in(0).reg() == FUNCTION_REG);
  __ LoadCompressedFieldFromOffset(CODE_REG, FUNCTION_REG,
      Function::code_offset());
  ```

  `CODE_REG` (R24) digunakan di monomorphic switchable call:
  ```c++
  __ LoadDoubleWordFromPoolIndex(IC_DATA_REG, CODE_REG, ic_data_index);
  __ Call(FieldAddress(CODE_REG, entry_point_offset));
  ```

  AOTopsy `sdk/registers.go` mendefinisikan `ARM64CodeReg = 24` tetapi
  `handleFieldLoad` dan `handleBLR` tidak memiliki logika khusus untuk
  CODE_REG. Ketika CODE_REG di-load dari PP (sebagai Code object),
  handler PP load men-set KnownStub("PPCode:funcName"), tetapi
  subsequent `LDR LR, [CODE_REG, #entry_point_offset]` hanya menangani
  offset 7 (Gap 2).

  Selain itu, FUNCTION_REG (R0) tidak ditrack sebagai sumber type info.
  Di non-AOT mode, R0 holds FunctionPtr yang bisa di-resolve ke owner
  class. Tapi AOTopsy hanya menangani AOT mode, jadi ini mungkin tidak
  relevan.

- **Bukti SDK**:
  - `constants_arm64.h` @3.9.2: `FUNCTION_REG = R0`, `CODE_REG = R24`.
  - `il_arm64.cc` @3.9.2: FUNCTION_REG digunakan di closure call.
  - `flow_graph_compiler_arm64.cc` @3.9.2: CODE_REG di monomorphic call.

- **Dampak**: Terbatas — CODE_REG sudah ditrack via PPCode KnownStub,
  tetapi entry point load dari CODE_REG hanya ditrack di offset 7
  (Gap 2). FUNCTION_REG tidak relevan di AOT precompiled.

- **Usulan**:
  1. Fokus pada Gap 2 (entry point offsets) untuk CODE_REG.
  2. Tambah dokumentasi bahwa FUNCTION_REG tidak ditrack karena AOT
    precompiled mode tidak menggunakannya.

- **Prioritas**: **Rendah** — sebagian besar sudah ditangani via Gap 2.

### Gap 9: Write barrier slot register (R25) tidak ditrack

- **Deskripsi**: SDK `constants_arm64.h` @3.9.2:
  ```c++
  const Register kWriteBarrierSlotReg = R25;
  const Register kWriteBarrierObjectReg = R1;
  const Register kWriteBarrierValueReg = R0;
  ```

  Write barrier store pattern:
  ```asm
  STR Xn, [Xobj, #offset]       ; field store
  ; ... write barrier ...
  MOV R25, [Xobj, #offset]       ; slot address
  BL write_barrier_stub
  ```

  R25 (kWriteBarrierSlotReg) holds the slot address being written to.
  Ini bisa memberikan info tentang field offset yang sedang di-store,
  yang berguna untuk field-store → field-load tracking.

  AOTopsy tidak menrack R25. `handleStackStore` menangani field store
  via STR/STUR ke `[Xn, #imm]` tetapi tidak melalui R25.

- **Bukti SDK**:
  - `constants_arm64.h` @3.9.2: `kWriteBarrierSlotReg = R25`.
  - `stub_code_compiler_arm64.cc` @3.9.2: write barrier stub pakai R25.

- **Dampak**: Kecil — field store sudah ditrack via STR/STUR handler.
  R25 hanya memberikan info redundan tentang slot yang sama.

- **Usulan**: Tidak perlu ditrack — STR/STUR handler sudah menangani
  field store. R25 hanya dipakai di write barrier stub yang bukan
  target RE utama.

- **Prioritas**: **Rendah** — tidak ada gain signifikan.

### Gap 10: MegamorphicCache call pattern tidak ditrack

- **Deskripsi**: SDK `EmitMegamorphicInstanceCall`
  (`flow_graph_compiler_arm64.cc`) memancarkan:
  ```c++
  __ LoadDoubleWordFromPoolIndex(IC_DATA_REG, CODE_REG, data_index);
  CLOBBERS_LR(__ ldr(LR, FieldAddress(CODE_REG,
      Code::entry_point_offset(Code::EntryKind::kMonomorphic))));
  CLOBBERS_LR(__ blr(LR));
  ```

  Ini adalah pola yang sama dengan monomorphic switchable call:
  LDP-from-PP (Gap 1) + entry point load (Gap 2). Tapi
  `EmitMegamorphicInstanceCall` hanya dipanggil di `!FLAG_precompiled_mode`
  (JIT), jadi tidak muncul di AOT binary.

  Namun, `StubCode::MegamorphicCall()` stub sendiri bisa muncul di AOT
  sebagai fallback. Stub ini menggunakan IC_DATA_REG (R5) yang berisi
  MegamorphicCache, dan melakukan lookup berdasarkan receiver class ID.

  AOTopsy tidak menrack MegamorphicCache object di pool. `PoolUnlinkedCallNames`
  menangani UnlinkedCall tetapi tidak MegamorphicCache.

- **Bukti SDK**:
  - `flow_graph_compiler_arm64.cc` @3.9.2: `EmitMegamorphicInstanceCall`
    dengan `ASSERT(!FLAG_precompiled_mode)`.
  - `stub_code_compiler_arm64.cc` @3.9.2: `GenerateMegamorphicCallStub`.

- **Dampak**: Kecil di AOT — MegamorphicCache call jarang muncul di AOT
  binary (biasanya sudah di-devirtualize ke dispatch table call).

- **Usulan**: Tidak prioritas — AOT mode jarang menggunakan megamorphic
  call. Jika ditemukan di sample binary, tambah tracking MegamorphicCache
  di pool.

- **Prioritas**: **Rendah**.

### Gap 11: NULL_REG (R22) tidak ditrack sebagai KnownClass(kNullCid)

- **Deskripsi**: SDK `constants_arm64.h` @3.9.2:
  ```c++
  const Register NULL_REG = R22;  // Caches NullObject() value.
  #define DART_ASSEMBLER_HAS_NULL_REG 1
  ```

  R22 selalu holds Null object. AOTopsy `sdk/registers.go` mendefinisikan
  `ARM64NullReg = 22` tetapi tidak menrack-nya sebagai KnownClass(kNullCid).

  Ketika kode membandingkan register dengan NULL_REG (null check),
  narrowing bisa menyala: jika `CMP Xn, X22; B.EQ is_null`, maka di edge
  `is_null`, Xn = KnownClass(kNullCid). Di edge `not_null`, Xn ≠ null
  (tetapi lattice tidak bisa ekspresikan "not null").

  Selain itu, `MOV Xn, X22` men-set Xn = null, yang bisa ditrack sebagai
  KnownClass(kNullCid) untuk menghindari false dispatch resolution.

- **Bukti SDK**:
  - `constants_arm64.h` @3.9.2: `NULL_REG = R22`.
  - `DART_ASSEMBLER_HAS_NULL_REG = 1` — ARM64-specific optimization.

- **Dampak**: Kecil — null check jarang mempengaruhi dispatch resolution
  (null tidak memiliki dispatch table entry). Tapi tracking NULL_REG
  bisa mencegah false positive di mana register yang holds null salah
  di-resolve sebagai KnownClass(non-null).

- **Usulan**:
  1. Seed R22 = KnownClass(kNullCid) di entry setiap function.
  2. Atau tambah lattice kind `LatticeNull` untuk distinguish null dari
    KnownClass(kNullCid).
  3. Tangani `MOV Xn, X22` → set Xn = KnownClass(kNullCid).

- **Prioritas**: **Rendah** — null tidak memiliki dispatch entry.

## Register Tracking Gaps

### Register yang TIDAK ditrack tetapi seharusnya ditrack

| Register | SDK Name | Peran | Gap | Prioritas |
|---|---|---|---|---|
| LR (X30) via LDP-from-PP | LR | Switchable call entry point | Gap 1 | Tinggi |
| R8 (kDstTypeReg) | TypeTestABI | Destination type di TTS call | Gap 5 | Sedang |
| R7 (kSubtypeTestCacheResultReg) | TypeTestABI | Boolean result TTS | Gap 5 | Sedang |
| R3 (kSubtypeTestCacheReg) | TypeTestABI | SubtypeTestCache dari PP | Gap 5 | Sedang |
| R4 (TTSInternalRegs::kScratchReg) | TTS scratch | Entry point load untuk BLR | Gap 2, 5 | Tinggi |
| CODE_REG (R24) entry point offsets ≠ 7 | CODE_REG | Monomorphic/unchecked call | Gap 2 | Tinggi |
| Closure entry_point_ field | — | AOT closure call | Gap 3 | Tinggi |
| x86_64: Code/UnlinkedCall/TTS dari PP | — | Switchable call x86_64 | Gap 4 | Tinggi |

### Register yang ditrack tetapi bisa diperbaiki

| Register | Issue | Gap |
|---|---|---|
| R25 (kWriteBarrierSlotReg) | Tidak ditrack, tapi redundan dengan STR handler | Gap 9 |
| R22 (NULL_REG) | Tidak ditrack sebagai KnownClass(kNullCid) | Gap 11 |
| R0 (FUNCTION_REG) | Tidak ditrack, tapi tidak relevan di AOT | Gap 8 |

## Fitur RE Missing/Incomplete

### 1. Switchable call resolution (AOT instance call)
**Status**: Incomplete — LDP-from-PP tidak ditrack (Gap 1), entry point
offset hanya 7 (Gap 2), x86_64 PP handler tidak resolve Code/UnlinkedCall
(Gap 4).

**Dampak RE**: Switchable call adalah pola instance call utama di AOT.
Tanpa resolusi, call graph RE tidak lengkap untuk instance method call.

### 2. Closure call resolution (AOT)
**Status**: Incomplete — entry_point_ vs function confusion (Gap 3).

**Dampak RE**: Closure call (callback, tear-off) tidak ter-resolve dengan
benar di compressed AOT.

### 3. Type test stub (TTS) type propagation
**Status**: Missing — TTS call hanya resolve stub name, tidak propagate
type info ke instance register (Gap 5).

**Dampak RE**: Setelah `is`/`as` cast, type narrowing tidak menyala,
mengurangi presisi dispatch resolution downstream.

### 4. Range-based type narrowing
**Status**: Missing — hanya B.EQ/B.NE yang ditrack (Gap 7).

**Dampak RE**: Type check yang menggunakan range comparison (umum di
SDK type test) tidak menghasilkan narrowing.

### 5. Inter-procedural field type propagation
**Status**: Implemented — `FieldStoreTypes` sudah ditrack dan dikonsumsi
oleh `FieldValueClass`. Tidak ada gap.

### 6. RTA (Rapid Type Analysis)
**Status**: Implemented — `InstantiatedClasses` + `RTAApplied()` + filter
di `selectorCandidates`. Threshold `rtaMinInstantiatedClasses = 100`
sudah diukur. Tidak ada gap.

### 7. CHA (Class Hierarchy Analysis)
**Status**: Implemented — `Subclasses` + `ResolveDispatchCHA` +
`AllSubclasses`. Tidak ada gap.

### 8. Receiver recovery (pre-3.4.3 stack convention)
**Status**: Implemented — `RecoverReceiverStackSlotARM64/X86` dengan
field-access validation. Tidak ada gap.

## Verifikasi SDK

### Verifikasi via grep MCP (searchGitHub)

| Query | Repo | Hasil | Konfirmasi |
|---|---|---|---|
| `kCpuRegistersForArgs` | dart-lang/sdk | ARM64={R1,R2,R3,R5,R6,R7}, x64={RDI,RSI,RDX,RBX,R8,R9} | ✅ AOTopsy `DartArgRegisters` benar |
| `kClassIdReg` | dart-lang/sdk | ARM64 DispatchTableNullErrorABI::kClassIdReg = R0 | ✅ AOTopsy `ARM64ReturnReg = 0` benar |
| `type_test_stub_entry_point_` | dart-lang/sdk | AbstractType field, offset 8 untagged = 7 tagged | ✅ AOTopsy `imm9 == 7` untuk TTS benar |
| `LoadDoubleWordFromPoolIndex` | dart-lang/sdk | ARM64 only, emits `ldp` from PP | ❌ AOTopsy tidak handle LDP-from-PP (Gap 1) |
| `EmitInstanceCall` | dart-lang/sdk | AOT pattern: LoadUniqueObject + call(reg) | ❌ x86_64 PP handler miss (Gap 4) |
| `EmitDispatchTableCall` | dart-lang/sdk | ARM64: AddImmediate(LR, cid_reg, offset) + Call; x64: call [table+cid*8+disp] | ✅ AOTopsy pre-scan benar |
| `Closure::function_offset` | dart-lang/sdk | Closure field layout: function + entry_point_ | ❌ AOTopsy entry_point_ confusion (Gap 3) |
| `Closure::entry_point_offset` | dart-lang/sdk | AOT precompiled: `LoadFieldFromOffset(R2, R0, entry_point_offset())` | ❌ AOTopsy tidak handle entry_point_ offset (Gap 3) |
| `LoadClassId(Register result, Register object)` | dart-lang/sdk | ARM64: ldr + ubfx; x64: movl + shrl | ✅ AOTopsy header load + UBFX handler benar |
| `void Assembler::LoadDispatchTable` | dart-lang/sdk | x64: `movq(dst, [THR + offset])` — MOV, bukan LEA | ❌ AOTopsy LEA-from-THR handler salah (Gap 6) |

### Verifikasi via gh api

| Path | Ref | Konfirmasi |
|---|---|---|
| `runtime/vm/constants_arm64.h` | 3.9.2 | TypeTestABI: R0=kInstance, R8=kDstType, R2=kInstantiator, R1=kFunctionTypeArgs, R3=kSubtypeTestCache, R4=kScratch, R7=kResult. FUNCTION_REG=R0, CODE_REG=R24, NULL_REG=R22, kWriteBarrierSlotReg=R25. |
| `runtime/vm/constants_x64.h` | 3.9.2 | DispatchTableNullErrorABI::kClassIdReg=RCX. DartCallingConvention::kCpuRegistersForArgs={RDI,RSI,RDX,RBX,R8,R9}. |
| `runtime/vm/compiler/backend/flow_graph_compiler_arm64.cc` | 3.9.2 | EmitDispatchTableCall: AddImmediate(LR, cid_reg, offset) + Call(DISPATCH_TABLE_REG, LR, UXTX, Scaled). EmitInstanceCallAOT: LoadDoubleWordFromPoolIndex(R5, LR, data_index) + blr(LR). EmitOptimizedStaticCall-style: LoadDoubleWordFromPoolIndex(IC_DATA_REG, CODE_REG, ic_data_index) + Call(FieldAddress(CODE_REG, kMonomorphic entry_point_offset)). |
| `runtime/vm/compiler/backend/flow_graph_compiler_x64.cc` | 3.9.2 | EmitDispatchTableCall: LoadDispatchTable(RAX) + call [RAX + RCX*8 + disp32]. EmitInstanceCallAOT: LoadUniqueObject(RCX, stub) + LoadUniqueObject(RBX, data) + call(RCX). |
| `runtime/vm/compiler/assembler/assembler_arm64.cc` | 3.9.2 | LoadDoubleWordFromPoolIndex: ldp(lower, upper, Address(PP, offset, PairOffset)). LoadClassId: ldr + ExtractClassIdFromTags (ubfx). |
| `runtime/vm/compiler/assembler/assembler_x64.cc` | 3.9.2 | LoadDispatchTable: movq(dst, [THR + dispatch_table_array_offset]). LoadClassId: movl + shrl(12). |
| `runtime/vm/raw_object.h` | 3.9.2 | UntaggedCode: entry_point_, monomorphic_entry_point_, unchecked_entry_point_, monomorphic_unchecked_entry_point_ (4 uword fields). UntaggedClosure: instantiator_type_arguments, function_type_arguments, delayed_type_arguments, function, context, hash, ONLY_IN_PRECOMPILED(entry_point_). |
| `runtime/vm/compiler/backend/il_arm64.cc` | 3.9.2 | AOT closure call: LoadFieldFromOffset(R2, R0, Closure::entry_point_offset()) + blr(R2). |

---

Report ditulis berdasarkan pembacaan lengkap semua file di
`internal/typetrack/` (infinite depth) dan verifikasi ke Dart SDK source
code via grep MCP (searchGitHub by Vercel) dan `gh api` ke tag 3.9.2.
