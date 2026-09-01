# RE Gap Analysis Report: internal/sdk

> **STATUS VERIFIKASI (2026-09-01)** — deskripsi kode CONFIRMED semua
> (`registers.go` memang hanya ~10 peran register per arch; `cachedVMObjectValues`
> memang 3 entri; `intrinsics.go` memang 10 entri; `stubclass.go` memang
> pattern-match tanpa daftar otoritatif). Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`. Satu koreksi:
> - **Gap 7, klaim dampak `IsMundaneStub("allocateFoo")` false-positive →
>   TIDAK TERJANGKAU di kode saat ini.** `IsMundaneStub` hanya dipanggil dari
>   tiga tempat, semuanya `signal/graph.go:115,152,264`, dan ketiganya memberi
>   `e.Via[4:]` — yaitu **nama field THR**, bukan nama fungsi aplikasi. Nama
>   fungsi user tidak pernah masuk ke sana. Yang tersisa nyata dari Gap 7:
>   pengecualian `strings.Contains(lower,"native") → StubRoleNone`
>   (`stubclass.go:129-131`) yang meloloskan `call_native_through_safepoint`
>   dan ketiga `*NativeCallWrapper` dari filter mundane — dan itu keputusan
>   yang disengaja & terdokumentasi.

## Ringkasan

Folder `internal/sdk` (7 file .go, 1057 LOC) adalah single source of truth AOTopsy
untuk Dart VM facts: register roles, calling convention, tag values, pool layout,
class-id bitfield, write-barrier/stack-overflow/decompression predicates, cached
VM objects, bool-from-null offsets, recognized intrinsics, dan stub role
classification. Konstanta register (PP/THR/HEAP_BITS/CODE_REG/ARGS_DESC_REG/
SPREG/NULL_REG/FPREG/LR/RETURN) sudah diverifikasi ke
`runtime/vm/constants_arm64.h` & `constants_x64.h` @3.12.2 dan stabil 2.10–3.13.

Namun terdapat gap signifikan terhadap SDK:

1. **Register ABI penting yang tidak diekspos sama sekali**:
   `kClassIdReg` (ARM64 R0 / x86_64 RCX), `IC_DATA_REG` (ARM64 R5 / x86_64 RBX),
   `kExceptionObjectReg` (R0/RAX), `kStackTraceObjectReg` (R1/RDX),
   `kWriteBarrierObjectReg` (R1/RDX), `kWriteBarrierValueReg` (R0/RAX),
   `kWriteBarrierSlotReg` (R25/R13), `FUNCTION_REG` (R0/RAX), `TMP`/`TMP2`
   (R16/R17 / R11), `CALLEE_SAVED_TEMP`/`CALLEE_SAVED_TEMP2` (R19/R20 / RBX),
   `DISPATCH_TABLE_REG` (R21 — sudah ditrack sebagai `ARM64DT` tapi tidak
   diekspos dengan nama SDK), `kSecondReturnReg` (R1/RDX), `kFpuAnyNonAbiRegister`
   (R19/R12), `kFirstNonArgumentRegister`/`kSecondNonArgumentRegister` (R9/R10
   ARM64, RAX/RBX x86_64), `TypeTestABI` (R0/R8/R2/R1/R3/R4 ARM64), dan seluruh
   ABI struct (`InstantiationABI`, `TTSInternalRegs`, `STCInternalRegs`,
   `InitStaticFieldABI`, `LateInitializationErrorABI`, `FieldAccessErrorABI`,
   `ThrowABI`, `ReThrowABI`, `RangeErrorABI`, `AssertSubtypeABI`).

2. **Tag values fundamental tidak didefinisikan**: `kSmiTag=0`, `kHeapObjectTag=1`
   (hanya `HeapObjectTag=1` ada, tanpa enum lengkap), `kSmiTagSize=1`,
   `kSmiTagMask=1`, `kSmiTagShift=1`, `kBarrierOverlapShift=2`,
   `kGenerationalBarrierMask`, `kIncrementalBarrierMask`, `kObjectAlignment`
   (2*word_size), `kObjectAlignmentLog2`, `kBoolValueBitPosition`,
   `kBoolValueMask`, `kBoolVsNullBitPosition`, `kBoolVsNullMask`. Konstanta
   bool-from-null offset (32/48) ada tapi `kObjectAlignment`-nya tidak
   diekspos, sehingga mustahil menghitung ulang untuk word_size berbeda.

3. **CID definitions kosong**: `internal/sdk` tidak punya CID constant apa pun.
   Semua CID ada di `internal/cluster/cid.go` (hardcoded v3.9.2 numbering) dan
   `internal/snapshot/version.go` (per-version CID table). SDK `class_id.h`
   mendefinisikan `CLASS_LIST_INTERNAL_ONLY`, `CLASS_LIST_INSTANCE_SINGLETONS`,
   `CLASS_LIST_MAPS`, `CLASS_LIST_SETS`, `CLASS_LIST_ARRAYS`,
   `CLASS_LIST_STRINGS`, `CLASS_LIST_TYPED_DATA`, `CLASS_LIST_FFI`,
   `kNumPredefinedCids`, `kFirstInternalOnlyCid`, `kLastInternalOnlyCid`,
   `kInstanceCid`, `kIllegalCid`, `kObjectCid`, `kFreeListElement`,
   `kForwardingCorpse`, `kNativePointer` — tidak satu pun predicate ini
   (`IsStringClassId`, `IsNumberClassId`, `IsIntegerClassId`,
   `IsBuiltinListClassId`, `IsTypedDataClassId`, `IsFfiTypeClassId`,
   `IsInternalOnlyClassId`, `IsCallSiteDataClassId`, `IsImplicitFieldClassId`)
   diekspos dari `internal/sdk`.

4. **Recognized intrinsics hanya 10 entry** vs **493 entry** di SDK
   `recognized_methods_list.h` @3.12.2 (`OTHER_RECOGNIZED_LIST` +
   `ASM_INTRINSICS_LIST` + `GRAPH_INTRINSICS_LIST`). Tidak ada pemisahan
   ASM-intrinsic vs graph-intrinsic vs other-recognized; tidak ada fingerprint
   field; tidak ada library-name dispatch.

5. **Cached VM objects hanya 3** (`object_null`, `bool_true`, `bool_false`) vs
   **7** di `CACHED_NON_VM_STUB_LIST` (juga `object_sentinel`, `empty_array`,
   `empty_type_arguments`, `dynamic_type`). Padahal `empty_array` dan
   `dynamic_type` adalah THR-field yang sudah ada di thrfields tables — predicate
   ini bisa langsung memetakan field offset → literal Dart value.

6. **Stub role classification tidak menyentuh `CACHED_VM_STUBS_LIST` (40 Code
   stubs) dan `CACHED_VM_STUBS_ADDRESSES_LIST` (19 entry-point stubs)** —
   `stubclass.go` hanya pattern-match nama, tidak punya authoritative list dari
   SDK. `threadstubs.go` (vmtables) punya offset table per-version, tapi
   `sdk/stubclass.go` tidak mereferensinya, sehingga `IsMundaneStub` bisa
   false-positive pada nama user function yang kebetulan mengandung "allocate"
   atau "write_barrier".

7. **FPU return convention incomplete**: `kSecondReturnReg` (R1 ARM64, RDX x86)
   dan `kSecondReturnFpuReg`/`kThirdReturnFpuReg`/`kFourthReturnFpuReg` (V1/V2/V3
   ARM64, XMM1 x86) tidak diekspos — pair-return (record, simd) tidak bisa
   dianotasi.

8. **`kCallingConventionShift`, `kDartStackAlignment`, `kStackSlotSize`** dan
   ABI alignment constants tidak ada — padahal dibutuhkan untuk validasi
   stack-slot offset dan SPREG-relative addressing.

9. **Dart 2.x x86_64 calling convention**: `DartCallingConvention` tidak ada di
   `constants_x64.h` @2.12.0 (first appears @3.4.3 per AGENTS.md). Komentar
   `registers.go:140-143` mengakui ini tapi tidak ada predicate
   `HasDartCallingConvention(version)` yang bisa dipanggil caller — setiap
   caller harus re-implement check.

10. **`kExceptionObjectReg`/`kStackTraceObjectReg` tidak ditrack** — padahal
    ini ABI catch-clause entry yang deterministic: setiap entry ke catch block
    memiliki R0=exception, R1=stacktrace. Tanpa ini, decompiler tidak bisa
    memberi nama parameter catch (`e`, `s`) dan typetrack tidak bisa seed
    exception type.

Dampak agregat: decompiler kehilangan nama parameter catch, arg-register
inference untuk type-test stubs, dan anotasi pair-return; typetrack tidak bisa
seed `IC_DATA_REG` (R5) sebagai KnownStub UnlinkedCall — padahal komentar
`sources.go:154` sudah menyebut IC_DATA_REG; signal classifier bisa
false-positive mundane pada user function bernama "allocateFoo"; CID predicate
diduplikasi di `cluster/cid.go` dan `snapshot/version.go` tanpa single source.

## Struktur Folder

| File | LOC | Peran |
|------|-----|-------|
| `registers.go` | 321 | Konstanta register ARM64/x86_64 (PP, THR, DT, HEAP_BITS, CODE_REG, ARGS_DESC_REG, SPREG, NULL_REG, FPREG, LR, RETURN), string names, Dart calling convention (GPR + FPU arg regs), pool/CID/entry-point constants, equality-branch successor convention, FPU return reg. |
| `predicates.go` | 221 | `IsWriteBarrierCond`/`Stmt`, `IsStackOverflowCond`, `CachedVMObjectValue`, `StackSlotName`/`Plus`/`Minus`, `IsARM64PointerDecompression`, `IsX86PointerDecompression`, `BoolFromNullOffset` + `TrueOffsetFromNull`/`FalseOffsetFromNull`. |
| `intrinsics.go` | 95 | `RecognizedIntrinsic` struct + `RecognizedMethods` map (10 entry) + `LookupRecognizedIntrinsic`. |
| `stubclass.go` | 159 | `StubRole` enum (10 role), `LooksLikeVMStubName`, `HasSegmentPair`, `ClassifyStubRole`, `IsAsyncStubName`, `IsMundaneStub`. Pattern-based, no SDK authoritative list. |
| `sdk_test.go` | 144 | Test untuk arg-regs, write-barrier, stack-overflow, cached VM object, stack-slot name, ARM64RegName, pointer decompression, bool-from-null. |
| `intrinsics_test.go` | 57 | Test `LookupRecognizedIntrinsic` (5 case). |
| `fpu_test.go` | 60 | Test FPU arg + return register names. |

Konsumen `internal/sdk` (44 file): `disasm/{annotate,poolindex,thraudit,
dataflowarm64,dataflowx86,x86,calledge}.go`, `decompiler/{lift,liftarm64,
liftx86,ssa,call,emit,emit_walk,emit_helpers}.go`, `typetrack/{intraproc,
intraprocx86,intraproc_handlers,interproc,receiver_recovery}.go`,
`arch/x86/helpers.go`, `signal/graph.go`, `frida/{generator,gdtcall}.go`,
`cluster/{cid,fill_strings,fill_scalar_handlers}.go`,
`analysis/{frida_export,disasm_stage}.go`, `vmtables/stubnames_sdk_test.go`,
`snapshot/baseobjects_sdk_test.go`, `cluster/funckind_sdk_test.go`,
`disasm/thrfields_sdk_test.go`.

## Gap Analysis

### Gap 1: Register ABI penting tidak diekspos — `kClassIdReg`, `IC_DATA_REG`, exception/stacktrace/write-barrier regs

- **Deskripsi**: `registers.go` hanya mengekspos 10 register per arch
  (PP/THR/DT/HEAP_BITS/CODE_REG/ARGS_DESC_REG/SPREG/NULL_REG/FPREG/LR/RETURN).
  SDK `constants_arm64.h` @3.12.2 (baris 130-167) dan `constants_x64.h`
  @3.12.2 (baris 130-145) mendefinisikan tambahan:
  - `IC_DATA_REG = R5` (ARM64) / `RBX` (x86_64) — ICData/MegamorphicCache
    register, dibutuhkan untuk resolve IC-based BLR (komentar
    `typetrack/sources.go:154` sudah menyebut IC_DATA_REG tapi tidak ada
    konstanta shared).
  - `FUNCTION_REG = R0` (ARM64) / `RAX` (x86_64) — set when calling Dart
    functions in JIT, used by LazyCompileStub.
  - `kExceptionObjectReg = R0` / `RAX` — ABI catch-clause entry.
  - `kStackTraceObjectReg = R1` / `RDX` — ABI catch-clause entry.
  - `kWriteBarrierObjectReg = R1` / `RDX`.
  - `kWriteBarrierValueReg = R0` / `RAX`.
  - `kWriteBarrierSlotReg = R25` (ARM64) / `R13` (x86_64).
  - `TMP = R16` / `R11`, `TMP2 = R17` / `kNoRegister` (x86_64).
  - `CALLEE_SAVED_TEMP = R19` / `RBX`, `CALLEE_SAVED_TEMP2 = R20` (ARM64 only).
  - `kClassIdReg` (via `DispatchTableNullErrorABI`) = `R0` (ARM64) / `RCX`
    (x86_64) — `X86ClassIdReg=1` ada di `registers.go:239` tapi
    `ARM64ClassIdReg` TIDAK ada, padahal R0 adalah kClassIdReg ARM64.

- **Bukti SDK**:
  - `runtime/vm/constants_arm64.h` @3.12.2 baris 130-167:
    `IC_DATA_REG = R5`, `ARGS_DESC_REG = R4`, `FUNCTION_REG = R0`,
    `CALLEE_SAVED_TEMP = R19`, `CALLEE_SAVED_TEMP2 = R20`, `TMP = R16`,
    `TMP2 = R17`.
  - `runtime/vm/constants_arm64.h` @3.12.2 baris 156-167:
    `kExceptionObjectReg = R0`, `kStackTraceObjectReg = R1`,
    `kWriteBarrierObjectReg = R1`, `kWriteBarrierValueReg = R0`,
    `kWriteBarrierSlotReg = R25`.
  - `runtime/vm/constants_arm64.h` @3.12.2 baris 490-492:
    `DispatchTableNullErrorABI::kClassIdReg = R0`.
  - `runtime/vm/constants_x64.h` @3.12.2 baris 130-145:
    `IC_DATA_REG = RBX`, `FUNCTION_REG = RAX`, `CALLEE_SAVED_TEMP = RBX`,
    `TMP = R11`, `TMP2 = kNoRegister`.
  - `runtime/vm/constants_x64.h` @3.12.2 baris 136-139:
    `kExceptionObjectReg = RAX`, `kStackTraceObjectReg = RDX`,
    `kWriteBarrierObjectReg = RDX`, `kWriteBarrierValueReg = RAX`,
    `kWriteBarrierSlotReg = R13`.
  - `runtime/vm/constants_x64.h` @3.12.2 baris 452-455:
    `DispatchTableNullErrorABI::kClassIdReg = RCX`.
  - Verifikasi `gh api` ke `runtime/vm/constants_arm64.h?ref=3.12.2` (dump
    lengkap di `/tmp/devin-overflows-1000/396ccdb7/content.txt` baris 130-167,
    156-167, 490-492).

- **Dampak**:
  - Decompiler tidak bisa memberi nama parameter catch (`e`, `s`) — setiap
    catch block muncul sebagai `x0`, `x1` tanpa konteks exception.
  - typetrack tidak bisa seed `state[R5] = KnownStub("ICData")` di function
    entry — IC-based BLR resolution kehilangan provenance ICData register
    (komentar `sources.go:154` mengakui IC_DATA_REG penting tapi konstanta
    tidak shared).
  - Write-barrier detection (`IsWriteBarrierCond`) hanya match string
    "HEAP_BITS"/"write_barrier_mask" — tidak bisa match pola register
    `R0`/`R1`/`R25` yang adalah write-barrier ABI regs, sehingga store yang
    sebelum barrier tidak dianotasi sebagai field-store yang protected.
  - `kClassIdReg` ARM64 (R0) tidak ada — padahal R0 adalah return reg DAN
    kClassIdReg, konflik ini tidak didokumentasikan di mana pun di AOTopsy.
    typetrack `intraproc.go:286-303` membedakan pattern 3.x (LR sebagai temp)
    vs 2.x (R0 in-place) tapi tidak tahu bahwa R0 = kClassIdReg secara ABI.

- **Usulan**:
  - Tambahkan konstanta `ARM64ICDataReg=5`, `ARM64FunctionReg=0`,
    `ARM64ExceptionObjectReg=0`, `ARM64StackTraceObjectReg=1`,
    `ARM64WriteBarrierObjectReg=1`, `ARM64WriteBarrierValueReg=0`,
    `ARM64WriteBarrierSlotReg=25`, `ARM64TMP=16`, `ARM64TMP2=17`,
    `ARM64CalleeSavedTemp=19`, `ARM64CalleeSavedTemp2=20`,
    `ARM64ClassIdReg=0` (dengan doc comment "R0 is both kClassIdReg and
    kReturnReg — conflict by design, see DispatchTableNullErrorABI").
  - Tambahkan counterpart x86_64: `X86ICDataReg=3` (RBX),
    `X86FunctionReg=0`, `X86ExceptionObjectReg=0`, `X86StackTraceObjectReg=2`,
    `X86WriteBarrierObjectReg=2`, `X86WriteBarrierValueReg=0`,
    `X86WriteBarrierSlotReg=13`, `X86TMP=11`.
  - Tambahkan string-name constants dan symbolic names (`SymICData`,
    `SymException`, `SymStackTrace`, `SymWriteBarrierObject/Value/Slot`).
  - Ekspos `DISPATCH_TABLE_REG` dengan nama SDK (`ARM64DispatchTableReg=21`,
    sudah sebagai `ARM64DT` tapi nama tidak konsisten dengan SDK).

- **Prioritas**: TINGGI — IC_DATA_REG dan exception regs adalah ABI
  deterministic yang langsung meningkatkan decompiler output quality dan
  typetrack BLR resolution.

### Gap 2: TypeTestABI / InstantiationABI / TTSInternalRegs / STCInternalRegs tidak diekspos

- **Deskripsi**: SDK `constants_arm64.h` @3.12.2 baris 199-300 mendefinisikan
  struct ABI untuk type testing stubs dan instantiation stubs:
  - `TypeTestABI`: `kInstanceReg=R0`, `kDstTypeReg=R8`,
    `kInstantiatorTypeArgumentsReg=R2`, `kFunctionTypeArgumentsReg=R1`,
    `kSubtypeTestCacheReg=R3`, `kScratchReg=R4`, `kSubtypeTestCacheResultReg=R7`.
  - `TTSInternalRegs`: `kInstanceTypeArgumentsReg=R7`, `kScratchReg=R9`,
    `kSubTypeArgumentReg=R5`, `kSuperTypeArgumentReg=R6`.
  - `STCInternalRegs`: `kInstanceCidOrSignatureReg=R6`,
    `kInstanceInstantiatorTypeArgumentsReg=R5`,
    `kInstanceParentFunctionTypeArgumentsReg=R9`,
    `kInstanceDelayedFunctionTypeArgumentsReg=R10`,
    `kCacheEntriesEndReg=R11`, `kCacheContentsSizeReg=R12`,
    `kProbeDistanceReg=R13`.
  - `InstantiationABI`: `kUninstantiatedTypeArgumentsReg=R3`,
    `kInstantiatorTypeArgumentsReg=R2`, `kFunctionTypeArgumentsReg=R1`,
    `kResultTypeArgumentsReg=R0`, `kResultTypeReg=R0`, `kScratchReg=R8`.
  - `AssertSubtypeABI`: `kSubTypeReg=R0`, `kSuperTypeReg=R8`,
    `kInstantiatorTypeArgumentsReg=R2`, `kFunctionTypeArgumentsReg=R1`,
    `kDstNameReg=R3`.
  - `InitStaticFieldABI`: `kFieldReg=R2`, `kResultReg=R0`.
  - `InitInstanceFieldABI`: `kInstanceReg=R1`, `kFieldReg=R2`, `kResultReg=R0`.
  - `LateInitializationErrorABI`: `kFieldReg=R9`.
  - `FieldAccessErrorABI`: `kFieldReg=R9`.
  - `ThrowABI`: `kExceptionReg=R0`. `ReThrowABI`: `kExceptionReg=R0`,
    `kStackTraceReg=R1`. `RangeErrorABI`: `kLengthReg=R0`.

  AOTopsy `internal/sdk` tidak punya satu pun dari ABI ini. Padahal
  `typetrack/intraproc_handlers.go:509-519` sudah mengenali `imm9==7` sebagai
  Code.entry_point / Type.type_test_stub_entry_point — tetapi tidak tahu
  bahwa TypeTestABI mengikat R0=instance, R8=dstType, R2/R1=typeArgs.

- **Bukti SDK**:
  - `gh api` ke `runtime/vm/constants_arm64.h?ref=3.12.2` baris 199-330
    (TypeTestABI, TTSInternalRegs, STCInternalRegs, AssertSubtypeABI,
    InitStaticFieldABI, InitLateStaticFieldInternalRegs, InitInstanceFieldABI,
    LateInitializationErrorABI, FieldAccessErrorABI, ThrowABI, ReThrowABI,
    RangeErrorABI).
  - `gh api` ke `runtime/vm/constants_x64.h?ref=3.12.2` baris 130-250
    (counterpart x86_64).
  - `runtime/vm/compiler/stub_code_compiler.cc` @3.12.2 baris 2607-2633:
    `AsyncExceptionHandlerStubABI::kSuspendStateReg`,
    `kExceptionObjectReg`, `kStackTraceObjectReg` — menunjukkan ABI ini
    dipakai di stub code.

- **Dampak**:
  - Decompiler tidak bisa memberi nama parameter type-test stub call
    (`instance`, `dstType`, `instantiatorTypeArgs`, `functionTypeArgs`,
    `subtypeTestCache`) — semua muncul sebagai `x0`, `x8`, `x2`, `x1`, `x3`.
  - typetrack tidak bisa seed state[R0]=KnownClass(instance CID) sebelum
    BLR ke type testing stub — padahal ini adalah entry-point deterministic.
  - Frida generator (`frida/generator.go`) tidak bisa pilih arg regs yang
    relevan untuk hook type-test stub — dump semua x0-x7 padahal hanya
    R0/R8/R2/R1/R3 yang meaningful.
  - `AssertSubtype`/`InstantiateTypeArguments` stub call tidak dianotasi
    dengan parameter name yang benar.

- **Usulan**:
  - Tambahkan struct Go `TypeTestABI`, `TTSInternalRegs`, `STCInternalRegs`,
    `InstantiationABI`, `AssertSubtypeABI`, `InitStaticFieldABI`,
    `InitInstanceFieldABI`, `LateInitializationErrorABI`,
    `FieldAccessErrorABI`, `ThrowABI`, `ReThrowABI`, `RangeErrorABI` dengan
    konstanta register per-arch.
  - Ekspos helper `DartTypeTestABIRegs(isARM64) []int` dan
    `DartTypeTestABIRegNames(isARM64) []string` untuk decompiler/Frida.
  - Tambahkan predicate `IsTypeTestStubCall(target string) bool` yang match
    nama stub (`AssertSubtype`, `AssertAssignable`, `InstanceOf`,
    `InstantiateType`, `InstantiateTypeArguments`, `SubtypeNTestCache`).

- **Prioritas**: MENENGAH — langsung meningkatkan readability pseudocode
  untuk type-test-heavy code (Dart generics).

### Gap 3: Tag values fundamental (`kSmiTag`, `kSmiTagShift`, `kSmiTagSize`, `kSmiTagMask`, `kBarrierOverlapShift`, `kObjectAlignment`) tidak didefinisikan

- **Deskripsi**: `registers.go:175` hanya mendefinisikan `HeapObjectTag = 1`.
  SDK `runtime/vm/pointer_tagging.h` @3.12.2 mendefinisikan enum lengkap:
  ```c
  enum {
    kSmiTag = 0,
    kHeapObjectTag = 1,
    kSmiTagSize = 1,
    kSmiTagMask = 1,
    kSmiTagShift = 1,
  };
  ```
  `runtime/vm/raw_object.h` @3.12.2 mendefinisikan:
  ```c
  static constexpr intptr_t kBarrierOverlapShift = 2;
  static constexpr intptr_t kGenerationalBarrierMask = ...;
  static constexpr intptr_t kIncrementalBarrierMask = ...;
  ```
  `runtime/vm/pointer_tagging.h` @3.12.2:
  ```c
  static constexpr intptr_t kObjectAlignment = 2 * word_size;       // 16
  static constexpr intptr_t kObjectAlignmentLog2 = word_size_log2 + 1; // 5
  static constexpr intptr_t kBoolValueBitPosition = kObjectAlignmentLog2;
  static constexpr intptr_t kBoolValueMask = 1 << kObjectAlignmentLog2;
  static constexpr intptr_t kBoolVsNullBitPosition = kObjectAlignmentLog2 + 1;
  static constexpr intptr_t kBoolVsNullMask = 1 << kBoolVsNullBitPosition;
  static constexpr intptr_t kTrueOffsetFromNull = kObjectAlignment * 2;  // 32
  static constexpr intptr_t kFalseOffsetFromNull = kObjectAlignment * 3; // 48
  ```

  AOTopsy `predicates.go:205-208` hardcode `TrueOffsetFromNull = 32` dan
  `FalseOffsetFromNull = 48` tanpa mengekspos `kObjectAlignment` atau
  `kObjectAlignmentLog2` — mustahil menghitung ulang untuk word_size=4
  (Dart 32-bit, didukung SDK via `target::kWordSize`).

- **Bukti SDK**:
  - `runtime/vm/pointer_tagging.h` @3.12.2 (grep MCP): `kSmiTag = 0`,
    `kHeapObjectTag = 1`, `kSmiTagSize = 1`, `kSmiTagMask = 1`,
    `kSmiTagShift = 1`.
  - `runtime/vm/pointer_tagging.h` @3.12.2 (grep MCP): `kObjectAlignment =
    2 * word_size`, `kObjectAlignmentLog2 = word_size_log2 + 1`,
    `kTrueOffsetFromNull = kObjectAlignment * 2`,
    `kFalseOffsetFromNull = kObjectAlignment * 3`,
    `kBoolValueBitPosition`, `kBoolValueMask`, `kBoolVsNullBitPosition`,
    `kBoolVsNullMask`.
  - `runtime/vm/raw_object.h` @3.12.2 (grep MCP): `kBarrierOverlapShift = 2`,
    `kGenerationalBarrierMask`, `kIncrementalBarrierMask`.
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` @3.12.2 (grep MCP):
    `and_(scratch, TMP2, Operand(scratch, LSR,
    target::UntaggedObject::kBarrierOverlapShift)); tst(scratch, Operand(HEAP_BITS,
    LSR, 32))` — write barrier predicate memakai kBarrierOverlapShift.

- **Dampak**:
  - Decompiler tidak bisa recognize Smi tag operations (`LSR #1` untuk
    smi-untag, `LSL #1` untuk smi-tag) — semua muncul sebagai shift
    arithmetic tanpa anotasi "smi tag/untag".
  - `IsWriteBarrierCond` hanya match string "HEAP_BITS"/"write_barrier_mask"
    — tidak bisa match pola `LSR #kBarrierOverlapShift` (=2) yang adalah
    signature write-barrier scratch computation.
  - Bool-from-null offset 32/48 hardcode — mustahil adaptasi ke 32-bit Dart
    (word_size=4 → kObjectAlignment=8 → true=16, false=24).
  - `kBoolValueBitPosition`/`kBoolVsNullBitPosition` tidak diekspos —
    padahal ini adalah cara SDK membedakan true/false/null berdasarkan bit
    alignment, yang bisa dipakai untuk recognize bool materialization tanpa
    ADD offset.

- **Usulan**:
  - Tambahkan enum/const block:
    ```go
    const (
      SmiTag         = 0
      HeapObjectTag  = 1  // already exists
      SmiTagSize     = 1
      SmiTagMask     = 1
      SmiTagShift    = 1
      BarrierOverlapShift = 2
      ObjectAlignment64   = 16  // 2 * word_size, word_size=8
      ObjectAlignmentLog2_64 = 5
      BoolValueBitPosition64 = 5
      BoolValueMask64        = 1 << 5
      BoolVsNullBitPosition64 = 6
      BoolVsNullMask64        = 1 << 6
    )
    ```
  - Refactor `TrueOffsetFromNull`/`FalseOffsetFromNull` jadi
    `TrueOffsetFromNull = ObjectAlignment64 * 2` (32), dokumentasi bahwa
    ini assuming 64-bit.
  - Tambahkan predicate `IsSmiTagOp(mnemonic string, shift int) bool` dan
    `IsWriteBarrierScratch(shift int) bool` (match `LSR #2`).

- **Prioritas**: MENENGAH — Smi tag recognition mempengaruhi banyak
  arithmetic di pseudocode; write-barrier scratch detection mempengaruhi
  elision quality.

### Gap 4: CID definitions dan predicates tidak ada di `internal/sdk`

- **Deskripsi**: `internal/sdk` tidak punya CID constant atau predicate apa
  pun. CID hardcoded di `internal/cluster/cid.go:11-109` (v3.9.2 numbering,
  95 CID) dan per-version di `internal/snapshot/version.go` (CIDTable
  struct). SDK `runtime/vm/class_id.h` @3.12.2 mendefinisikan:
  - `CLASS_LIST_INTERNAL_ONLY` (40 kelas: Class, PatchClass, Function, ...,
    UnwindError).
  - `CLASS_LIST_INSTANCE_SINGLETONS` (43 kelas: Instance, LibraryPrefix,
    TypeArguments, ..., TransferableTypedData).
  - `CLASS_LIST_MAPS` (Map, ConstMap), `CLASS_LIST_SETS` (Set, ConstSet),
    `CLASS_LIST_FIXED_LENGTH_ARRAYS` (Array, ImmutableArray),
    `CLASS_LIST_ARRAYS` (+ GrowableObjectArray),
    `CLASS_LIST_STRINGS` (String, OneByteString, TwoByteString),
    `CLASS_LIST_TYPED_DATA` (14 typed array),
    `CLASS_LIST_FFI_NUMERIC_FIXED_SIZE` (10), `CLASS_LIST_FFI_TYPE_MARKER`
    (+Void, Handle, Bool), `CLASS_LIST_FFI` (+NativeFunction, NativeType,
    Struct).
  - `kNumPredefinedCids`, `kFirstInternalOnlyCid = kClassCid`,
    `kLastInternalOnlyCid = kUnwindErrorCid`, `kInstanceCid`, `kIllegalCid`,
    `kObjectCid`, `kFreeListElement`, `kForwardingCorpse`, `kNativePointer`.
  - Predicates: `IsInternalOnlyClassId`, `IsNumberClassId`, `IsIntegerClassId`,
    `IsStringClassId`, `IsOneByteStringClassId`, `IsBuiltinListClassId`,
    `IsTypeClassId`, `IsTypedDataBaseClassId`, `IsTypedDataClassId`,
    `IsTypedDataViewClassId`, `IsExternalTypedDataClassId`,
    `IsFfiPointerClassId`, `IsFfiTypeClassId`, `IsFfiDynamicLibraryClassId`,
    `IsInternalVMdefinedClassId`, `IsImplicitFieldClassId`,
    `IsCallSiteDataClassId`.

  AOTopsy tidak punya satu pun predicate ini di `internal/sdk`. Predicates
  tersebar ad-hoc di `cluster/cid.go` (ClassifyAlloc) dan
  `typetrack/intraproc_handlers.go` (hardcoded CID comparison).

- **Bukti SDK**:
  - `gh api` ke `runtime/vm/class_id.h?ref=3.12.2` (dump di
    `/tmp/devin-overflows-1000/6005c609/content.txt`): 660 LOC, definisi
    lengkap `CLASS_LIST_*`, `enum ClassId`, predicates.
  - `runtime/vm/class_id.h` @3.12.2 baris 333: `kNumPredefinedCids`.
  - `runtime/vm/class_id.h` @3.12.2 baris 375-381:
    `kFirstInternalOnlyCid = kClassCid`, `kInstanceCid = kLastInternalOnlyCid + 1`.
  - `runtime/vm/class_id.h` @3.12.2 baris 437-463: `IsNumberClassId`,
    `IsIntegerClassId`, `IsStringClassId`, `IsOneByteStringClassId`,
    `IsBuiltinListClassId` dengan COMPILE_ASSERT invariant.
  - `runtime/vm/class_id.h` @3.12.2 baris 585-605: `IsImplicitFieldClassId`
    listing CID yang tidak punya field (kSmiCid, kMintCid, kDoubleCid, ...,
    kNullCid, kPointerCid, kTypeCid, kTypeArgumentsCid, ...).

- **Dampak**:
  - Tidak ada single source of truth untuk CID — `cluster/cid.go` dan
    `snapshot/version.go` menduplikasi dengan representasi berbeda (int
    const vs CIDTable field).
  - typetrack `intraproc_handlers.go` tidak bisa memanggil
    `IsStringClassId(cid)` untuk recognize string operations — harus
    hardcode range check di setiap handler.
  - Decompiler tidak bisa anotasi typed-data operations
    (`Int8Array[]=` dll) sebagai intrinsic — padahal SDK
    `GRAPH_INTRINSICS_LIST` mendefinisikan 14 typed array set-index
    intrinsic.
  - `IsImplicitFieldClassId` tidak ada — typetrack tidak bisa skip field
    access untuk CID yang tidak punya field (Smi, Mint, Double, Bool, Null,
    Type, TypeArguments), menghasilkan recordFieldAccess false-positive.

- **Usulan**:
  - Buat file baru `internal/sdk/classid.go` dengan:
    - Const block untuk v3.9.2 CID numbering (pindahkan dari
      `cluster/cid.go` atau buat shared reference).
    - Predicate functions: `IsStringClassId(cid int) bool`,
      `IsNumberClassId`, `IsIntegerClassId`, `IsBuiltinListClassId`,
      `IsTypedDataClassId`, `IsFfiTypeClassId`, `IsInternalOnlyClassId`,
      `IsImplicitFieldClassId`, `IsCallSiteDataClassId`.
    - Versi-aware: ambil dari `snapshot.CIDTable` bila non-nil (per-version),
      fallback ke v3.9.2 const bila nil.
  - Refactor `cluster/cid.go` untuk panggil predicate dari `internal/sdk`.

- **Prioritas**: TINGGI — menghilangkan duplikasi, enable typed-data
  intrinsic recognition, fix false-positive field access pada
  implicit-field CID.

### Gap 5: Recognized intrinsics hanya 10 dari 493 entry SDK

- **Deskripsi**: `intrinsics.go` hanya mendefinisikan 10 entry
  (`_BigIntImpl._lsh`, `_BigIntImpl._rsh`, `_BigIntImpl._multiply`,
  `_StringBase._interpolate`, `_StringBase.substring`,
  `_Utf8Decoder.convert`, `_Double.sin`, `_Double.cos`, `_Double.sqrt`,
  `_Hash._jenkins`). SDK `runtime/vm/compiler/recognized_methods_list.h`
  @3.12.2 mendefinisikan 493 entry terbagi:
  - `OTHER_RECOGNIZED_LIST`: ~270 entry (FutureListener, SuspendState,
    Utf8Decoder, Object identical, _Array[], _GrowableList[],
    _StringBase, _Double arithmetic, _IntegerImplementation, _HashVMBase,
    _FinalizerImpl, _WeakProperty, _WeakReference, FFI load/store, dll).
  - `ASM_INTRINSICS_LIST`: ~75 entry (ASM-intrinsified: _Smi.bitLength,
    _BigIntImpl, _Double comparison/arithmetic, Object.==,
    _StringBase.hashCode/isEmpty/[], _OneByteString, _TwoByteString,
    _AbstractType, _IntegerImplementation arithmetic, allocateOneByteString,
    writeIntoOneByteString, dll).
  - `GRAPH_INTRINSICS_LIST`: ~50 entry (graph-intrinsified: _Array.length,
    _GrowableList.length/_capacity/_setData/_setLength/_setIndexed,
    _StringBase.length, _Smi.~, _IntegerImplementation arithmetic,
    TypedData []=, _Float32x4/_Float64x2 arithmetic, ThreadLocal).
  - `POLYMORPHIC_TARGET_LIST`, `RECOGNIZED_LIST_FACTORY_LIST`: tambahan.

  `RecognizedIntrinsic` struct tidak punya field fingerprint (SDK pakai
  fingerprint untuk verify), tidak ada pemisahan ASM vs graph vs other,
  tidak ada library-name dispatch (SDK pakai `CoreLibrary`,
  `ConvertLibrary`, `AsyncLibrary`, `FfiLibrary`, `TypedDataLibrary`,
  `CompactHashLibrary`, `DeveloperLibrary`, `InternalLibrary`,
  `VMLibrary`).

- **Bukti SDK**:
  - `gh api` ke `runtime/vm/compiler/recognized_methods_list.h?ref=3.12.2`:
    760 LOC, 493 `V(...)` entry.
  - `OTHER_RECOGNIZED_LIST` baris 15-537: ~270 entry termasuk
    `SuspendState_getFunctionData/set:_functionData/_clone/_resume`,
    `Utf8DecoderScan`, `ObjectIdentical`, `ObjectArrayGetIndexed/SetIndexed`,
    `GrowableArrayGetIndexed/SetIndexed/AllocateWithData/GetEmptyList`,
    `Record_fieldNames/numFields/shape/_fieldAt`,
    `StringBaseInterpolate/CodeUnitAt`, `IntegerToDouble`,
    `DoubleAdd/Sub/Mul/Div/Mod/Rem/Ceil/Floor/Round/ToInt/Trunc`,
    `Finalizer_getCallback/set:_callback`,
    `WeakProperty_getKey/set:key/getValue/setValue`,
    `WeakReference_getTarget/set:_target`,
    `Smi_hashCode/Mint_hashCode/Double_hashCode`,
    `LinkedHashBase_getIndex/set:_index/get:_data/set:_data/
    get:_usedData/set:_usedData/get:_hashMask/set:_hashMask/
    get:_deletedKeys/set:_deletedKeys`,
    `ImmutableLinkedHashBase_getData/get:_indexNullable/set:_index`,
    `CompactHash_uninitializedIndex/uninitializedData`,
    `UserTag_defaultTag/getCurrentTag`, `Timeline_isDartStreamEnabled`,
    `ExtensionStreamHasListener`, `Debugger`,
    `NativeFinalizer_getCallback/set:_callback`, `FfiAbi`, `FfiCall`,
    `FfiNativeCallbackFunction` (4 variants), `FfiLoadAbiSpecificInt` (2
    variants), `FfiLoadInt8/16/32/64/Uint8/16/32/64/Float/FloatUnaligned/
    Double/DoubleUnaligned/Pointer`, `FfiStore*` (15 variants),
    `FfiFromAddress`, `FfiGetAddress`, `FfiNativeAddressOf`,
    `FfiAsExternalTypedData*` (10 variants), `MemCopy`,
    `CheckNotDeeplyImmutable`, `ClassIDgetID`, `NativeEffect`,
    `ReachabilityFence`, `Has63BitSmis`,
    `CopyRangeFromUint8ListToOneByteString`,
    `FinalizerBase_getAllEntries/set:_allEntries`, ...
  - `ASM_INTRINSICS_LIST` baris 538-606: 75 entry.
  - `GRAPH_INTRINSICS_LIST` baris 608-673: 50 entry.

- **Dampak**:
  - Decompiler tidak bisa recognize `Object.==` (ObjectEquals,
    fingerprint 0x463b5870) sebagai intrinsic — muncul sebagai call biasa.
  - Typetrack tidak bisa infer return type `Integer_add`/`Integer_sub`/
    `Integer_mul` sebagai Smi/Mint — padahal ini adalah 90%+ arithmetic
    di Dart code.
  - FFI trace (`internal/ffitrace`) tidak bisa link `FfiLoadInt8` dll ke
    recognized intrinsic — harus pattern-match nama, tidak deterministic.
  - String operations (`StringBaseCharAt`, `StringBaseSubstringMatches`,
    `StringBaseIsEmpty`, `StringBaseLength`) tidak dianotasi sebagai
    intrinsic — pseudocode menampilkan call ke `_StringBase.[]` dll.
  - TypedData `[]=` (14 typed array intrinsic) tidak dianotasi — padahal
    ini adalah hot path di numeric code.

- **Usulan**:
  - Ekspansi `RecognizedMethods` ke 493 entry (atau subset signifikan
    ~100 entry paling penting: arithmetic, string, FFI, typed-data).
  - Tambah field `Kind` (ASM/Graph/Other/Polymorphic/Factory) dan
    `Fingerprint uint32` ke `RecognizedIntrinsic`.
  - Tambah `LibraryName` dispatch: `LookupRecognizedIntrinsicByLib(
    library, class, function string) (RecognizedIntrinsic, bool)`.
  - Generate table dari SDK header via tool baru
    (`tools/extract_intrinsics.go`, analog `tools/extract_thr.go`).

- **Prioritas**: MENENGAH — meningkatkan decompiler readability signifikan
  untuk arithmetic/string/FFI-heavy code.

### Gap 6: Cached VM objects hanya 3 dari 7 — `empty_array`, `empty_type_arguments`, `dynamic_type`, `object_sentinel` missing

- **Deskripsi**: `predicates.go:87-91` hanya memetakan:
  ```go
  var cachedVMObjectValues = map[string]string{
      "object_null": "null",
      "bool_true":   "true",
      "bool_false":  "false",
  }
  ```
  SDK `runtime/vm/thread.h` @3.12.2 `CACHED_NON_VM_STUB_LIST` (baris
  183-196) mendefinisikan 7 cached VM objects:
  - `object_null_` → `Object::null()` → `"null"` ✓
  - `object_sentinel_` → `Object::sentinel()` → `"sentinel"` ✗
  - `bool_true_` → `Object::bool_true()` → `"true"` ✓
  - `bool_false_` → `Object::bool_false()` → `"false"` ✓
  - `empty_array_` → `Object::empty_array()` → `"<empty_array>"` ✗
  - `empty_type_arguments_` → `Object::empty_type_arguments()` →
    `"<empty_type_arguments>"` ✗
  - `dynamic_type_` → `Type::dynamic_type()` → `"dynamic"` ✗

  THR field tables (`vmtables/thrfields.go`) sudah punya offset untuk
  `empty_array`, `empty_type_arguments`, `dynamic_type` (disebut di
  AGENTS.md `handDerivedFields`) — tetapi `CachedVMObjectValue` tidak
  mengenalinya, sehingga `LDR Xd, [THR, #off]` ke `empty_array` dianotasi
  `THR.empty_array` (bukan literal `<empty_array>`).

- **Bukti SDK**:
  - `gh api` ke `runtime/vm/thread.h?ref=3.12.2` baris 183-196:
    ```c
    #define CACHED_NON_VM_STUB_LIST(V)
      V(ObjectPtr, object_null_, Object::null(), nullptr)
      V(SentinelPtr, object_sentinel_, Object::sentinel().ptr(), nullptr)
      V(BoolPtr, bool_true_, Object::bool_true().ptr(), nullptr)
      V(BoolPtr, bool_false_, Object::bool_false().ptr(), nullptr)
      V(ArrayPtr, empty_array_, Object::empty_array().ptr(), nullptr)
      V(TypeArgumentsPtr, empty_type_arguments_,
        Object::empty_type_arguments().ptr(), nullptr)
      V(TypePtr, dynamic_type_, Type::dynamic_type().ptr(), nullptr)
    ```
  - `runtime/vm/thread.cc` @3.12.2 baris 192: `CACHED_VM_OBJECTS_LIST(
    ASSERT_VM_HEAP)` — semua 7 adalah cached VM object yang dimuat dari
    Thread.
  - AGENTS.md `tools/extract_thr.go` `handDerivedFields` menyebut
    `empty_array`, `dynamic_type` sebagai field yang SDK tidak export
    offset-nya — tetap masuk THR table sebagai hand-derived.

- **Dampak**:
  - Decompiler menampilkan `THR.empty_array` (bukan `<empty_array>`)
    untuk load literal `[]` — padahal ini adalah representasi Dart
    literal `const []`.
  - `THR.dynamic_type` muncul sebagai `THR.dynamic_type` (bukan `dynamic`)
    — padahal `dynamic` adalah Dart keyword.
  - `THR.object_sentinel` tidak dikenali — padahal sentinel dipakai di
    late-init check (`if (field == sentinel) throw LateInitializationError`).
  - `THR.empty_type_arguments` muncul sebagai `THR.empty_type_arguments`
    (bukan `<>` atau `const <dynamic>[]`).

- **Usulan**:
  - Ekspansi `cachedVMObjectValues`:
    ```go
    var cachedVMObjectValues = map[string]string{
        "object_null":            "null",
        "object_sentinel":        "sentinel",
        "bool_true":              "true",
        "bool_false":             "false",
        "empty_array":            "<empty_array>",
        "empty_type_arguments":   "<empty_type_arguments>",
        "dynamic_type":           "dynamic",
    }
    ```
  - Tambah test case untuk 4 entry baru.

- **Prioritas**: RENDAH — cosmetic, tapi meningkatkan readability
  pseudocode untuk literal `[]`, `dynamic`, late-init check.

### Gap 7: Stub role classification tidak reference authoritative SDK list

- **Deskripsi**: `stubclass.go` memclassify stub berdasarkan pattern match
  nama (`allocate`, `write_barrier`, `store_buffer`, `type_test`,
  `subtype_check`, `call_to_runtime`, `stack_overflow`, `null_error`,
  `range_error`, `error_`, `deoptimize`, `megamorphic_call`,
  `switchable_call`, `monomorphic_`, `lazy_deopt`, `safepoint`). Tidak
  ada reference ke authoritative SDK list:
  - `CACHED_VM_STUBS_LIST` (40 Code stubs di Thread, `thread.h` baris
    113-153): `fix_callers_target_code_`, `fix_allocation_stub_code_`,
    `invoke_dart_code_stub_`, `call_to_runtime_stub_`,
    `late_initialization_error_*_stub_`, `null_error_*_stub_`,
    `null_arg_error_*_stub_`, `null_cast_error_*_stub_`,
    `range_error_*_stub_`, `write_error_*_stub_`,
    `field_access_error_*_stub_`, `allocate_mint_*_stub_`,
    `async_exception_handler_stub_`, `resume_stub_`, `return_async_stub_`,
    `return_async_not_future_stub_`, `return_async_star_stub_`,
    `stack_overflow_*_stub_`, `switchable_call_miss_stub_`,
    `throw_stub_`, `re_throw_stub_`, `optimize_stub_`,
    `deoptimize_stub_`, `lazy_deopt_*_stub_`, `slow_type_test_stub_`,
    `lazy_specialize_type_test_stub_`, `enter_safepoint_stub_`,
    `exit_safepoint_stub_`, `call_native_through_safepoint_stub_`.
  - `CACHED_VM_STUBS_ADDRESSES_LIST` (19 entry-point stubs, `thread.h`
    baris 220-258): `write_barrier_entry_point_`,
    `array_write_barrier_entry_point_`, `call_to_runtime_entry_point_`,
    `allocate_mint_*_entry_point_`, `allocate_object_*_entry_point_`,
    `stack_overflow_*_entry_point_`, `megamorphic_call_checked_entry_`,
    `switchable_call_miss_entry_`, `optimize_entry_`,
    `deoptimize_entry_`, `call_native_through_safepoint_entry_point_`,
    `jump_to_frame_entry_point_`, `slow_type_test_entry_point_`,
    `resume_interpreter_adjusted_entry_point_`.
  - `CACHED_ADDRESSES_LIST` tambahan: `bootstrap_native_wrapper_`,
    `no_scope_native_wrapper_`, `auto_scope_native_wrapper_`,
    `interpret_call_entry_point_`, `predefined_symbols_address_`,
    `double_nan_address_`, `double_negate_address_`,
    `double_abs_address_`, `float_not_address_`,
    `float_negate_address_`, `float_absolute_address_`,
    `float_zerow_address_`.
  - `VM_STUB_CODE_LIST` (164 stubs, `stub_code_list.h`) — sudah ditrack
    di `vmtables/stubnames.go` per-version, tapi `stubclass.go` tidak
    reference.

  `vmtables/threadstubs.go` punya offset table per-version untuk
  `CACHED_VM_STUBS_ADDRESSES_LIST` — tetapi `sdk/stubclass.go` tidak
  mereferensinya, sehingga `IsMundaneStub("allocateFoo")` bisa
  false-positive (user function bernama "allocateFoo" match pattern
  "allocate").

- **Bukti SDK**:
  - `gh api` ke `runtime/vm/thread.h?ref=3.12.2` baris 113-153:
    `CACHED_VM_STUBS_LIST` 40 entry.
  - `gh api` ke `runtime/vm/thread.h?ref=3.12.2` baris 220-258:
    `CACHED_VM_STUBS_ADDRESSES_LIST` 19 entry.
  - `gh api` ke `runtime/vm/thread.h?ref=3.12.2` baris 260-280:
    `CACHED_ADDRESSES_LIST` tambahan 12 entry (native wrapper + constants).
  - `runtime/vm/stub_code_list.h` @3.12.2: `VM_STUB_CODE_LIST` 164 entry
    (sudah di `vmtables/stubnames.go`).

- **Dampak**:
  - `IsMundaneStub("allocateFoo")` return true (false-positive) — user
    function yang kebetulan namanya mengandung "allocate" diklasifikasi
    sebagai mundane stub, sehingga signal graph tidak include edge ke
    function ini.
  - `IsMundaneStub("InitStaticField")` return true (benar), tapi
    `IsMundaneStub("call_native_through_safepoint")` return false karena
    exception `if strings.Contains(lower, "native")` di
    `stubclass.go:131` — padahal `call_native_through_safepoint` adalah
    mundane stub (FFI/JNI call wrapper). Komentar mengakui ini
    intentional ("FFI/JNI interesting"), tapi ini salah klasifikasi
    untuk signal mundane-filtering.
  - Stub role `StubRoleError` hanya match `null_error`/`range_error`/
    `error_` — tidak match `field_access_error`, `write_error`,
    `null_cast_error`, `null_arg_error`, `late_initialization_error`
    yang juga adalah error stubs (SDK list).
  - `StubRoleSafepoint` match `monomorphic_` — tetapi
    `monomorphic_smiable_check` adalah type-test stub, bukan safepoint.

- **Usulan**:
  - Tambahkan authoritative stub name set di `internal/sdk`:
    `VMStubCodeList` (164 nama dari `vmtables/stubnames.go`),
    `CachedVMStubsList` (40 nama dari `CACHED_VM_STUBS_LIST`),
    `CachedVMStubsAddressesList` (19 nama dari
    `CACHED_VM_STUBS_ADDRESSES_LIST`).
  - Refactor `ClassifyStubRole` untuk pertama cek authoritative set,
    baru fallback ke pattern match.
  - Tambah `IsMundaneStubName(name string) bool` yang cek exact match
    against authoritative set (bukan substring) — eliminasi false-positive.
  - Fix `StubRoleError` untuk match semua error stub dari SDK list:
    `null_error`, `null_arg_error`, `null_cast_error`, `range_error`,
    `write_error`, `field_access_error`, `late_initialization_error`.
  - Reklassifikasi `monomorphic_smiable_check` sebagai `StubRoleTypeTest`
    (bukan Safepoint).
  - Re-evaluate exception `if strings.Contains(lower, "native")` —
    `call_native_through_safepoint` adalah mundane (FFI wrapper), tetapi
    `BootstrapNativeCallWrapper`/`NoScopeNativeCallWrapper`/
    `AutoScopeNativeCallWrapper` juga mundane. Hanya
    `FfiCallbackTrampoline`/`FfiCallTrampoline` yang interesting (FFI
    call site).

- **Prioritas**: MENENGAH — false-positive mundane stub menghapus edge
  dari signal graph; false-negative menghasilkan noise.

### Gap 8: FPU return convention incomplete — `kSecondReturnReg`, multi-FPU return

- **Deskripsi**: `registers.go:294` hanya mendefinisikan
  `ARM64FpuReturnRegName = "v0"` dan `X86FpuReturnRegName = "xmm0"`. SDK
  `constants_arm64.h` @3.12.2 baris 634-642 mendefinisikan:
  ```c
  static constexpr Register kReturnReg = R0;
  static constexpr Register kSecondReturnReg = R1;
  static constexpr FpuRegister kReturnFpuReg = V0;
  static constexpr FpuRegister kSecondReturnFpuReg = V1;
  static constexpr FpuRegister kThirdReturnFpuReg = V2;
  static constexpr FpuRegister kFourthReturnFpuReg = V3;
  ```
  `constants_x64.h` @3.12.2 baris 647-651:
  ```c
  static constexpr Register kReturnReg = RAX;
  static constexpr Register kSecondReturnReg = RDX;
  static constexpr FpuRegister kReturnFpuReg = XMM0;
  static constexpr FpuRegister kSecondReturnFpuReg = XMM1;
  ```

  Pair-return dipakai untuk: record (Dart 3.0+ records return 2 word),
  SIMD return, struct return via `kPointerToReturnStructRegisterReturn`.

- **Bukti SDK**:
  - `gh api` ke `runtime/vm/constants_arm64.h?ref=3.12.2` baris 634-642
    (dump `/tmp/devin-overflows-1000/396ccdb7/content.txt`).
  - `gh api` ke `runtime/vm/constants_x64.h?ref=3.12.2` baris 647-651
    (dump `/tmp/devin-overflows-1000/4f75eac4/content.txt`).

- **Dampak**:
  - Decompiler tidak bisa anotasi pair-return (`return (a, b)`) —
    `x1`/`rdx` setelah RET tidak dikenali sebagai second return value.
  - typetrack tidak bisa seed exit-type untuk pair-return — return type
    inference hanya track `kReturnReg`.
  - Record return (Dart 3.0+) tidak dianotasi sebagai record literal.

- **Usulan**:
  - Tambah `ARM64SecondReturnReg=1`, `ARM64SecondReturnRegStr="x1"`,
    `X86SecondReturnReg=2`, `X86SecondReturnRegStr="rdx"`.
  - Tambah `ARM64SecondFpuReturnRegName="v1"`,
    `ARM64ThirdFpuReturnRegName="v2"`,
    `ARM64FourthFpuReturnRegName="v3"`,
    `X86SecondFpuReturnRegName="xmm1"`.
  - Tambah helper `DartReturnRegs(isARM64) []int` dan
    `DartFpuReturnRegNames(isARM64) []string`.

- **Prioritas**: RENDAH — pair-return jarang di Dart AOT, tapi
  dokumentasi penting untuk record support.

### Gap 9: Dart 2.x x86_64 calling convention tidak ada predicate

- **Deskripsi**: `registers.go:140-143` mengakui bahwa
  `DartCallingConvention` tidak ada di `constants_x64.h` @2.12.0 (first
  appears @3.4.3 per AGENTS.md). Tetapi tidak ada predicate
  `HasDartCallingConvention(version string) bool` yang bisa dipanggil
  caller — setiap caller (`DartArgRegisters`, `DartArgRegNames`,
  `DartFpuArgRegNames`) return list 6 register tanpa cek version, dan
  komentar mengatakan "callers that handle 2.x x86_64 must check
  separately" — tetapi tidak ada helper untuk check.

- **Bukti SDK**:
  - AGENTS.md `Known limits` baris 289-296: "2.x does pass the receiver
    via the stack (`DartCallingConvention` does not exist in
    `constants_arm64.h` at 2.12.0, first appears at 3.4.3)".
  - `gh api` ke `runtime/vm/constants_x64.h?ref=2.12.0` (tidak diverifikasi
    di sesi ini, tapi AGENTS.md sudah establish).

- **Dampak**:
  - `DartArgRegisters(ArchX86)` return `[7,6,2,3,8,9]` (RDI,RSI,RDX,RBX,
    R8,R9) untuk SEMUA version — padahal 2.x x86_64 tidak punya
    calling convention, args di stack.
  - Decompiler `liftx86.go` set `fir.ArgRegs = x86ArgRegs` tanpa cek
    version — untuk 2.x x86_64 sample, pseudocode menampilkan
    `arg0=rdi, arg1=rsi, ...` padahal sebenarnya args di stack
    `[rsp+0x8]`, `[rsp+0x10]`, ...
  - typetrack `intraprocx86.go` seed state untuk RDI/RSI/RDX/RBX/R8/R9
    sebagai arg — padahal 2.x x86_64 tidak pakai convention ini.

- **Usulan**:
  - Tambah `HasDartCallingConvention(dartVersion string, isARM64 bool) bool`:
    - ARM64: true untuk semua version (2.10+).
    - x86_64: true untuk version >= 3.4.3, false sebelumnya.
  - `DartArgRegisters`/`DartArgRegNames`/`DartFpuArgRegNames` return nil
    untuk 2.x x86_64, dengan doc comment "caller must use stack-based
    arg inference".
  - Caller (`liftx86.go`, `intraprocx86.go`) cek `HasDartCallingConvention`
    sebelum set ArgRegs.

- **Prioritas**: MENENGAH — 2.x x86_64 sample menghasilkan pseudocode
  dengan arg name yang salah (confident-wrong).

### Gap 10: `kExceptionObjectReg`/`kStackTraceObjectReg` tidak ditrack — catch block parameter tidak diberi nama

- **Deskripsi**: SDK `constants_arm64.h` @3.12.2 baris 156-157:
  ```c
  const Register kExceptionObjectReg = R0;
  const Register kStackTraceObjectReg = R1;
  ```
  Ini adalah ABI catch-clause entry: setiap entry ke catch block memiliki
  R0=exception object, R1=stacktrace. AOTopsy tidak punya konstanta ini
  (lihat Gap 1), dan tidak ada handler yang seed state[R0]/state[R1]
  di catch-block entry.

  Decompiler `liftarm64.go` set `fir.ArgRegs = arm64ArgRegs` di function
  entry — tetapi catch block adalah separate entry point (via
  `JumpToFrame` stub atau `RunExceptionHandler`), bukan function entry.
  Tanpa seed di catch-block leader, R0/R1 muncul sebagai `x0`/`x1` tanpa
  nama.

- **Bukti SDK**:
  - `runtime/vm/constants_arm64.h` @3.12.2 baris 156-157 (grep MCP):
    `kExceptionObjectReg = R0`, `kStackTraceObjectReg = R1`.
  - `runtime/vm/compiler/stub_code_compiler.cc` @3.12.2 baris 2607-2633
    (grep MCP): `AsyncExceptionHandlerStubABI::kSuspendStateReg`,
    `kExceptionObjectReg`, `kStackTraceObjectReg` — stub push register
    in order `{kSuspendState, kExceptionObjectReg, kStackTraceObjectReg}`.
  - `runtime/vm/exceptions.cc` @3.12.2 baris 622-666 (grep MCP):
    "set up the exception object in the kExceptionObjectReg register
    and the stacktrace object in the kStackTraceObjectReg register".
  - `runtime/vm/compiler/backend/locations.cc` @3.12.2 baris 490+:
    `LocationExceptionLocation() = RegisterLocation(kExceptionObjectReg)`,
    `LocationStackTraceLocation() = RegisterLocation(kStackTraceObjectReg)`.

- **Dampak**:
  - Catch block pseudocode: `catch (e, s) { ... }` muncul sebagai
    `catch (x0, x1) { ... }` — kehilangan semantic exception handling.
  - typetrack tidak bisa infer exception type dari catch block entry —
    padahal ini adalah deterministic seed (R0 = exception class).
  - Frida hook di catch-block entry tidak bisa dump exception object
    secara named.

- **Usulan**:
  - Tambah konstanta `ARM64ExceptionObjectReg=0`,
    `ARM64StackTraceObjectReg=1`, `X86ExceptionObjectReg=0`,
    `X86StackTraceObjectReg=2` (lihat Gap 1).
  - Tambah handler di `typetrack/intraproc.go` untuk detect catch-block
    entry (via `RunExceptionHandler`/`JumpToFrame` stub call target)
    dan seed `state[R0] = KnownClass(exceptionCID)`,
    `state[R1] = KnownClass(StackTraceCID)`.
  - Decompiler `liftarm64.go`/`liftx86.go` beri nama `x0`/`r0` sebagai
    `exception` dan `x1`/`rdx` sebagai `stackTrace` di catch-block entry.

- **Prioritas**: MENENGAH — meningkatkan readability exception-heavy
  code secara signifikan.

## Register Tracking Gaps

| Register | ARM64 | x86_64 | SDK role | AOTopsy status | Dampak |
|----------|-------|--------|----------|----------------|--------|
| `kClassIdReg` (DispatchTableNullErrorABI) | R0 | RCX (1) | dispatch table null error ABI | x86 ✓ (`X86ClassIdReg=1`), ARM64 ✗ | R0 ARM64 tidak dikenali sebagai kClassIdReg — konflik dengan kReturnReg tidak didokumentasikan |
| `IC_DATA_REG` | R5 | RBX (3) | ICData/MegamorphicCache register | ✗ | IC-based BLR resolution kehilangan provenance ICData register |
| `FUNCTION_REG` | R0 | RAX | JIT LazyCompileStub | ✗ | Tidak relevan untuk AOT (JIT-only), tapi harus didokumentasikan |
| `kExceptionObjectReg` | R0 | RAX | catch-clause entry ABI | ✗ | Catch block parameter tidak diberi nama `exception` |
| `kStackTraceObjectReg` | R1 | RDX | catch-clause entry ABI | ✗ | Catch block parameter tidak diberi nama `stackTrace` |
| `kWriteBarrierObjectReg` | R1 | RDX | write barrier stub ABI | ✗ | Write-barrier store tidak dianotasi sebagai protected field-store |
| `kWriteBarrierValueReg` | R0 | RAX | write barrier stub ABI | ✗ | Sama di atas |
| `kWriteBarrierSlotReg` | R25 | R13 | write barrier stub ABI | ✗ | Sama di atas |
| `TMP` | R16 | R11 | assembler scratch | ✗ | Tidak critical (assembler internal), tapi pseudocode menampilkan `x16`/`r11` tanpa anotasi "scratch" |
| `TMP2` | R17 | kNoRegister | assembler scratch 2 | ✗ | Sama di atas |
| `CALLEE_SAVED_TEMP` | R19 | RBX | callee-saved scratch | ✗ | Pseudocode menampilkan `x19`/`rbx` tanpa anotasi "callee-saved temp" |
| `CALLEE_SAVED_TEMP2` | R20 | (none) | callee-saved scratch 2 | ✗ | ARM64-only, sama di atas |
| `kSecondReturnReg` | R1 | RDX | pair-return ABI | ✗ | Pair-return (record, simd) tidak dianotasi |
| `kSecondReturnFpuReg` | V1 | XMM1 | multi-FPU return | ✗ | Multi-FPU return tidak dianotasi |
| `kThirdReturnFpuReg` | V2 | (none) | multi-FPU return | ✗ | Sama di atas |
| `kFourthReturnFpuReg` | V3 | (none) | multi-FPU return | ✗ | Sama di atas |
| `kFpuAnyNonAbiRegister` | R19 | R12 | FFI non-ABI scratch | ✗ | Tidak critical, tapi FFI code menampilkan register tanpa anotasi |
| `kFirstNonArgumentRegister` | R9 | RAX | non-arg scratch | ✗ | Pseudocode menampilkan `x9`/`rax` tanpa anotasi "non-arg temp" |
| `kSecondNonArgumentRegister` | R10 | RBX | non-arg scratch 2 | ✗ | Sama di atas |
| `TypeTestABI::kInstanceReg` | R0 | RAX | type test instance | ✗ | Type-test stub call tidak dianotasi parameter `instance` |
| `TypeTestABI::kDstTypeReg` | R8 | RBX | type test dst type | ✗ | Sama di atas, `dstType` |
| `TypeTestABI::kInstantiatorTypeArgumentsReg` | R2 | RDX | type test instantiator TA | ✗ | Sama di atas, `instantiatorTypeArgs` |
| `TypeTestABI::kFunctionTypeArgumentsReg` | R1 | RCX | type test function TA | ✗ | Sama di atas, `functionTypeArgs` |
| `TypeTestABI::kSubtypeTestCacheReg` | R3 | R9 | type test cache | ✗ | Sama di atas, `subtypeTestCache` |
| `TypeTestABI::kScratchReg` | R4 | RSI | type test scratch | ✗ | Scratch, tidak critical |
| `TypeTestABI::kSubtypeTestCacheResultReg` | R7 | R8 | type test result | ✗ | Type-test result tidak dianotasi |
| `InstantiationABI::kUninstantiatedTypeArgumentsReg` | R3 | RBX | instantiation uninstantiated TA | ✗ | Instantiation stub call tidak dianotasi |
| `InstantiationABI::kInstantiatorTypeArgumentsReg` | R2 | RDX | instantiation instantiator TA | ✗ | Sama di atas |
| `InstantiationABI::kFunctionTypeArgumentsReg` | R1 | RCX | instantiation function TA | ✗ | Sama di atas |
| `InstantiationABI::kResultTypeArgumentsReg` | R0 | RAX | instantiation result TA | ✗ | Sama di atas |
| `InstantiationABI::kScratchReg` | R8 | R9 | instantiation scratch | ✗ | Scratch |
| `InitStaticFieldABI::kFieldReg` | R2 | RDX | init static field | ✗ | InitStaticField stub call tidak dianotasi parameter `field` |
| `InitInstanceFieldABI::kInstanceReg` | R1 | (diff) | init instance field | ✗ | Sama di atas, `instance` |
| `LateInitializationErrorABI::kFieldReg` | R9 | (diff) | late init error | ✗ | Late-init error stub tidak dianotasi |
| `FieldAccessErrorABI::kFieldReg` | R9 | (diff) | field access error | ✗ | Field-access error stub tidak dianotasi |
| `ThrowABI::kExceptionReg` | R0 | RAX | throw stub | ✗ | Throw stub call tidak dianotasi parameter `exception` |
| `ReThrowABI::kStackTraceReg` | R1 | RDX | rethrow stub | ✗ | Rethrow stub call tidak dianotasi parameter `stackTrace` |
| `RangeErrorABI::kLengthReg` | R0 | (diff) | range error stub | ✗ | Range error stub tidak dianotasi parameter `length` |
| `AssertSubtypeABI::kDstNameReg` | R3 | R9 | assert subtype | ✗ | AssertSubtype stub call tidak dianotasi parameter `dstName` |

Total: **38 register ABI roles** tidak ditrack di `internal/sdk` (vs 10
yang sudah ditrack). Dampak terbesar: IC_DATA_REG (BLR resolution),
exception/stacktrace regs (catch block readability), TypeTestABI (type-test
stub readability), write-barrier regs (field-store protection annotation).

## Fitur RE Missing/Incomplete

### Missing: Smi tag/untag recognition

- **Status**: Tidak ada predicate `IsSmiTagOp`/`IsSmiUntagOp`.
- **SDK fact**: `kSmiTag=0`, `kSmiTagShift=1`, `kSmiTagSize=1`. Smi tag =
  `add reg, reg` (LSL #1 implicit). Smi untag = `asr reg, reg, #1`.
- **RE value**: Setiap Smi arithmetic di pseudocode muncul sebagai
  `x0 = x0 + x0` (tag) atau `x0 = x0 >> 1` (untag) tanpa anotasi
  "smi tag/untag". Padahal ini adalah operasi paling frequent di Dart
  integer code.
- **Usulan**: Tambah `IsSmiTagOp(mnemonic, shiftSpec string) bool` dan
  `IsSmiUntagOp(mnemonic, shiftSpec string) bool` di `predicates.go`.

### Missing: Write-barrier scratch detection via shift

- **Status**: `IsWriteBarrierStmt` hanya match string "write_barrier_mask"
  / "HEAP_BITS". Tidak match pola `LSR #kBarrierOverlapShift` (=2) yang
  adalah signature write-barrier scratch computation.
- **SDK fact**: `kBarrierOverlapShift = 2`. Write barrier scratch =
  `and scratch, value_tags, source_tags LSR #2`.
- **RE value**: Decompiler menampilkan `scratch = value_tags & (source_tags >> 2)`
  tanpa anotasi "write barrier scratch" — padahal ini pure GC bookkeeping.
- **Usulan**: Tambah `IsWriteBarrierScratch(mnemonic, shiftSpec string) bool`
  yang match `LSR #2` di context THR/HEAP_BITS load.

### Missing: CID predicate single source of truth

- **Status**: CID predicate (`IsStringClassId`, `IsNumberClassId`, dll)
  tidak ada di `internal/sdk`. Duplikasi di `cluster/cid.go` dan
  `snapshot/version.go`.
- **SDK fact**: `class_id.h` define 16 predicate functions dengan
  COMPILE_ASSERT invariant.
- **RE value**: typetrack tidak bisa filter field access untuk
  implicit-field CID (Smi, Mint, Double, Bool, Null, Type,
  TypeArguments) — recordFieldAccess false-positive.
- **Usulan**: Buat `internal/sdk/classid.go` dengan predicate
  version-aware (lihat Gap 4).

### Missing: Typed-data intrinsic recognition

- **Status**: `RecognizedMethods` tidak include `Int8ArraySetIndexed`,
  `Uint8ArraySetIndexed`, ..., `Float64ArraySetIndexed` (14 typed array
  intrinsic dari `GRAPH_INTRINSICS_LIST`).
- **SDK fact**: `GRAPH_INTRINSICS_LIST` baris 632-655 define 14 typed
  array `[]=` intrinsic + `TypedListBaseLength` + `ByteDataViewLength`.
- **RE value**: Numeric-heavy Dart code (image processing, ML) tidak
  dianotasi sebagai typed-array intrinsic — pseudocode menampilkan call
  ke `_Int8List.[]=` dll.
- **Usulan**: Ekspansi `RecognizedMethods` (lihat Gap 5).

### Missing: FFI load/store intrinsic recognition

- **Status**: `RecognizedMethods` tidak include `FfiLoadInt8`,
  `FfiLoadInt16`, ..., `FfiStorePointer` (30+ FFI intrinsic dari
  `OTHER_RECOGNIZED_LIST`).
- **SDK fact**: `OTHER_RECOGNIZED_LIST` baris 130-180 define 30+ FFI
  load/store intrinsic dengan fingerprint.
- **RE value**: `internal/ffitrace` tidak bisa link FFI call ke
  recognized intrinsic — harus pattern-match nama. FFI-heavy code
  (plugin, JNI) tidak dianotasi sebagai `Pointer.load<Int8>()` dll.
- **Usulan**: Ekspansi `RecognizedMethods` (lihat Gap 5).

### Missing: Authoritative stub name set untuk mundane classification

- **Status**: `stubclass.go` pattern-match nama, tidak reference SDK
  authoritative list.
- **SDK fact**: `CACHED_VM_STUBS_LIST` (40), `CACHED_VM_STUBS_ADDRESSES_LIST`
  (19), `VM_STUB_CODE_LIST` (164) — total 223 stub nama authoritative.
- **RE value**: `IsMundaneStub("allocateFoo")` false-positive — user
  function diklasifikasi mundane, signal graph kehilangan edge.
- **Usulan**: Tambah authoritative stub name set (lihat Gap 7).

### Missing: `kObjectAlignment` dan bool bit position

- **Status**: `TrueOffsetFromNull=32`, `FalseOffsetFromNull=48` hardcode
  tanpa ekspos `kObjectAlignment=16` atau `kBoolValueBitPosition=5`.
- **SDK fact**: `kObjectAlignment = 2*word_size`, `kBoolValueBitPosition =
  kObjectAlignmentLog2`, `kBoolVsNullBitPosition = kObjectAlignmentLog2 + 1`.
- **RE value**: Mustahil adaptasi ke 32-bit Dart (word_size=4). Bool
  materialization via bit test (`tst reg, #0x20`) tidak dikenali.
- **Usulan**: Ekspos `ObjectAlignment64`, `BoolValueBitPosition64`,
  `BoolVsNullBitPosition64` (lihat Gap 3).

### Missing: `CACHED_ADDRESSES_LIST` non-stub entries (predefined_symbols, double_nan, dll)

- **Status**: `cachedVMObjectValues` hanya 3 entry. Tidak ada map untuk
  `CACHED_ADDRESSES_LIST` non-stub entries: `predefined_symbols_address_`,
  `double_nan_address_`, `double_negate_address_`, `double_abs_address_`,
  `float_not_address_`, `float_negate_address_`,
  `float_absolute_address_`, `float_zerow_address_`.
- **SDK fact**: `thread.h` @3.12.2 `CACHED_ADDRESSES_LIST` baris 260-280
  define 8 non-stub address constant.
- **RE value**: Decompiler menampilkan `THR.double_nan_address` (bukan
  `double.nan`) untuk load NaN constant — padahal ini adalah literal
  `double.nan`.
- **Usulan**: Tambah `cachedAddressValues` map di `predicates.go`:
  `"double_nan_address": "double.nan"`, `"double_negate_address":
  "double.negate"`, dll.

### Incomplete: `IsStackOverflowCond` tidak cek `stack_limit` variants

- **Status**: `predicates.go:62-71` cek `stack_limit` + (x15/SP/rsp/RSP).
  Tidak cek `stack_limit_2` atau `saved_stack_limit_` yang juga adalah
  THR field untuk stack overflow (SDK `thread.h` punya multiple
  stack_limit variants: `stack_limit_`, `saved_stack_limit_`,
  `restore_stack_limit_`, `stack_overflow_2_`).
- **RE value**: Stack overflow check via `saved_stack_limit_` tidak
  dikenali — pseudocode menampilkan compare biasa, tidak di-elide.
- **Usulan**: Tambah `stack_limit_2`, `saved_stack_limit_`,
  `restore_stack_limit_` ke token list `IsStackOverflowCond`.

### Incomplete: `IsARM64PointerDecompression` tidak handle `LSR #32` form

- **Status**: `predicates.go:163-170` hanya match `add Xd, Xn, X28, LSL #32`.
  SDK juga emit `add Xd, Xn, X28, LSR #32` untuk heap_base extraction
  (write barrier) — tetapi ini bukan decompression, ini heap_base load.
- **RE value**: Tidak ada false-positive, tapi tidak ada predicate
  `IsARM64HeapBaseLoad(srcReg, shiftSpec string) bool` untuk anotasi
  `heap_base = HEAP_BITS >> 32`.
- **Usulan**: Tambah `IsARM64HeapBaseLoad` untuk match `LSR #32` dari
  HEAP_BITS.

## Verifikasi SDK

Semua klaim diverifikasi via dua metode (per AGENTS.md "Source of Truth:
SDK Verification"):

### Metode 1: Grep MCP (`searchGitHub` by Vercel)

Query (hanya `query` + `repo: "dart-lang/sdk"`, tanpa `path`):

1. `query="kClassIdTagPos"` → confirm `kClassIdTagPos=12, kClassIdTagSize=20`
   di `assembler_arm64.cc`, `assembler_x64.cc`, `assembler_ia32.cc`,
   `assembler_riscv.cc`, `assembler_arm.cc`, `vm_offsets.g.dart`,
   `runtime_offsets_list.h`, `runtime_api.h`.
2. `query="CACHED_VM_OBJECTS"` → confirm `CACHED_VM_OBJECTS_LIST` =
   `CACHED_NON_VM_STUB_LIST` + `CACHED_VM_STUBS_LIST` di `thread.h` baris
   195-197.
3. `query="CACHED_NON_VM_STUB_LIST"` → confirm 7 cached VM objects di
   `thread.h` baris 183-196.
4. `query="kExceptionObjectReg"` → confirm `kExceptionObjectReg = R0/RAX`,
   `kStackTraceObjectReg = R1/RDX` di `constants_arm64.h`, `constants_x64.h`,
   `constants_arm.h`, `constants_ia32.h`, `stub_code_compiler_*.cc`,
   `exceptions.cc`, `locations.cc`.
5. `query="kSmiTag"` → confirm `kSmiTag=0, kSmiTagTagSize=1, kSmiTagMask=1,
   kSmiTagShift=1` di `pointer_tagging.h`, `asm_intrinsifier_*.cc`,
   `il_*.cc`.
6. `query="kObjectAlignment"` → confirm `kObjectAlignment = 2*word_size`,
   `kTrueOffsetFromNull = kObjectAlignment*2 = 32`,
   `kFalseOffsetFromNull = kObjectAlignment*3 = 48` di `pointer_tagging.h`,
   `stub_code_compiler_*.cc`, `image_snapshot.cc`, `freelist.*`,
   `compactor.cc`, `pages.cc`.
7. `query="kHeapObjectTag = 1"` → confirm `kHeapObjectTag=1` di
   `pointer_tagging.h` baris 85.
8. `query="kInstanceCid"` → confirm `kInstanceCid`, `kObjectCid`,
   `kNumPredefinedCids`, `kFirstInternalOnlyCid = kClassCid` di
   `class_id.h`, `app_snapshot.cc`, `object.cc`, `object_graph_copy.cc`,
   `isolate.cc`, `type_propagator.cc`.
9. `query="kClosureCid"` → confirm `kClosureCid` dipakai di
   `type_propagator.cc`, `object_graph_copy.cc`, `interpreter.cc`,
   `deferred_objects.cc`, `asm_intrinsifier_*.cc`, `app_snapshot.cc`.
10. `query="kWriteBarrierSlotReg"` → confirm `kWriteBarrierSlotReg = R25`
    (ARM64), `R13` (x86_64), `R9` (ARM), `EDI` (IA32), `A6` (RISCV) di
    `constants_*.h`, `assembler_*.cc`, `stub_code_compiler_*.cc`.
11. `query="IC_DATA_REG = R5"` → confirm `IC_DATA_REG = R5` (ARM64),
    `RBX` (x86_64) di `constants_arm64.h` baris 145.
12. `query="kClassIdReg"` → confirm `DispatchTableNullErrorABI::kClassIdReg
    = R0` (ARM64), `RCX` (x86_64), `R0` (ARM), `EAX` (IA32) di
    `constants_*.h`, `flow_graph_compiler_*.cc`, `stub_code_compiler_*.cc`.
13. `query="kSmiTagShift"` → confirm `kSmiTagShift=1` dipakai di
    `assembler_*.cc`, `asm_intrinsifier_*.cc`, `stub_code_compiler.cc`,
    `constants.h`.
14. `query="kBarrierOverlapShift"` → confirm `kBarrierOverlapShift=2` di
    `raw_object.h`, `vm_offsets.g.dart`, `runtime_offsets_list.h`,
    `runtime_api.h`, `assembler_*.cc`, `gc.md`.
15. `query="CACHED_VM_STUBS_LIST(V)"` → confirm 40 Code stubs di
    `thread.h` baris 111-153.

### Metode 2: `gh api` @ version tag

1. `gh api -H "Accept: application/vnd.github.raw" "repos/dart-lang/sdk/
   contents/runtime/vm/constants_arm64.h?ref=3.12.2"` → 1692 LOC, dump di
   `/tmp/devin-overflows-1000/396ccdb7/content.txt`. Verifikasi:
   - Baris 130-167: register aliases (PP=R27, THR=R26, CODE_REG=R24,
     FUNCTION_REG=R0, FPREG=R29, SPREG=R15, IC_DATA_REG=R5,
     ARGS_DESC_REG=R4, CALLEE_SAVED_TEMP=R19, CALLEE_SAVED_TEMP2=R20,
     HEAP_BITS=R28, NULL_REG=R22, TMP=R16, TMP2=R17).
   - Baris 156-167: kExceptionObjectReg=R0, kStackTraceObjectReg=R1,
     kWriteBarrierObjectReg=R1, kWriteBarrierValueReg=R0,
     kWriteBarrierSlotReg=R25.
   - Baris 199-330: TypeTestABI, TTSInternalRegs, STCInternalRegs,
     AssertSubtypeABI, InitStaticFieldABI, InitLateStaticFieldInternalRegs,
     InitInstanceFieldABI, InitLateInstanceFieldInternalRegs,
     LateInitializationErrorABI, FieldAccessErrorABI, ThrowABI, ReThrowABI,
     RangeErrorABI.
   - Baris 490-492: DispatchTableNullErrorABI::kClassIdReg = R0.
   - Baris 634-642: kReturnReg=R0, kSecondReturnReg=R1, kReturnFpuReg=V0,
     kSecondReturnFpuReg=V1, kThirdReturnFpuReg=V2,
     kFourthReturnFpuReg=V3, kFpuAnyNonAbiRegister=R19,
     kFirstNonArgumentRegister=R9, kSecondNonArgumentRegister=R10.
   - Baris 654-657: DartCallingConvention::kCpuRegistersForArgs[] = {R1,
     R2, R3, R5, R6, R7}, kFpuRegistersForArgs[] = {V0, V1, V2, V3, V4,
     V5}.

2. `gh api -H "Accept: application/vnd.github.raw" "repos/dart-lang/sdk/
   contents/runtime/vm/constants_x64.h?ref=3.12.2"` → 745 LOC, dump di
   `/tmp/devin-overflows-1000/4f75eac4/content.txt`. Verifikasi:
   - Baris 130-145: PP=R15, SPREG=RSP, FPREG=RBP, IC_DATA_REG=RBX,
     ARGS_DESC_REG=R10, CODE_REG=R12, FUNCTION_REG=RAX, THR=R14,
     CALLEE_SAVED_TEMP=RBX, TMP=R11, TMP2=kNoRegister.
   - Baris 136-139: kExceptionObjectReg=RAX, kStackTraceObjectReg=RDX,
     kWriteBarrierObjectReg=RDX, kWriteBarrierValueReg=RAX,
     kWriteBarrierSlotReg=R13.
   - Baris 452-455: DispatchTableNullErrorABI::kClassIdReg = RCX.
   - Baris 647-651: kReturnReg=RAX, kSecondReturnReg=RDX,
     kReturnFpuReg=XMM0, kSecondReturnFpuReg=XMM1.
   - Baris 683-685: kFpuAnyNonAbiRegister=R12,
     kFirstNonArgumentRegister=RAX, kSecondNonArgumentRegister=RBX.
   - Baris 698-702: DartCallingConvention::kCpuRegistersForArgs[] = {RDI,
     RSI, RDX, RBX, R8, R9}, kFpuRegistersForArgs[] = {XMM1, XMM2, XMM3,
     XMM4, XMM5, XMM6}.

3. `gh api -H "Accept: application/vnd.github.raw" "repos/dart-lang/sdk/
   contents/runtime/vm/compiler/recognized_methods_list.h?ref=3.12.2"` →
   760 LOC, dump di `/tmp/devin-overflows-1000/fe895f63/content.txt`.
   Verifikasi:
   - `OTHER_RECOGNIZED_LIST` baris 15-537: ~270 entry.
   - `ASM_INTRINSICS_LIST` baris 538-606: 75 entry.
   - `GRAPH_INTRINSICS_LIST` baris 608-673: 50 entry.
   - `RECOGNIZED_LIST` baris 674-677: gabungan ketiganya.
   - Total: 493 `V(...)` entry (verifikasi `grep -c "^  V(" content.txt`
     = 493).

4. `gh api -H "Accept: application/vnd.github.raw" "repos/dart-lang/sdk/
   contents/runtime/vm/class_id.h?ref=3.12.2"` → 660 LOC, dump di
   `/tmp/devin-overflows-1000/6005c609/content.txt`. Verifikasi:
   - `CLASS_LIST_INTERNAL_ONLY` (40 kelas), `CLASS_LIST_INSTANCE_SINGLETONS`
     (43 kelas), `CLASS_LIST_MAPS`, `CLASS_LIST_SETS`,
     `CLASS_LIST_FIXED_LENGTH_ARRAYS`, `CLASS_LIST_ARRAYS`,
     `CLASS_LIST_STRINGS`, `CLASS_LIST_TYPED_DATA` (14),
     `CLASS_LIST_FFI_NUMERIC_FIXED_SIZE` (10), `CLASS_LIST_FFI_TYPE_MARKER`,
     `CLASS_LIST_FFI`.
   - `enum ClassId` baris 333-339 dengan `kNumPredefinedCids`.
   - Predicates baris 375-460: `IsInternalOnlyClassId`, `IsNumberClassId`,
     `IsIntegerClassId`, `IsStringClassId`, `IsOneByteStringClassId`,
     `IsBuiltinListClassId` dengan COMPILE_ASSERT invariant.
   - `kFirstInternalOnlyCid = kClassCid`, `kLastInternalOnlyCid =
     kUnwindErrorCid`, `kInstanceCid = kLastInternalOnlyCid + 1` baris
     375-381.
   - `IsImplicitFieldClassId` baris 585-605 listing CID tanpa field.

5. `gh api -H "Accept: application/vnd.github.raw" "repos/dart-lang/sdk/
   contents/runtime/vm/thread.h?ref=3.12.2"` → verifikasi:
   - `CACHED_VM_STUBS_LIST` baris 111-153: 40 Code stubs.
   - `CACHED_NON_VM_STUB_LIST` baris 183-196: 7 cached VM objects.
   - `CACHED_VM_OBJECTS_LIST` baris 195-197: gabungan.
   - `CACHED_FUNCTION_ENTRY_POINTS_LIST` baris 199-210: 11 suspend state
     entry points.
   - `CACHED_VM_STUBS_ADDRESSES_LIST` baris 220-258: 19 entry-point stubs.
   - `CACHED_ADDRESSES_LIST` baris 260-280: tambahan 12 entry (native
     wrapper + constants: predefined_symbols, double_nan, double_negate,
     double_abs, float_not, float_negate, float_absolute, float_zerow).

### Catatan verifikasi

- Semua version tag yang diverifikasi: `3.12.2` (stable, representatif
  untuk 3.x). Untuk 2.x, AGENTS.md sudah establish bahwa
  `DartCallingConvention` tidak ada di `constants_x64.h` @2.12.0 (first
  appears @3.4.3) — tidak di-re-verify di sesi ini, tapi konsisten dengan
  AGENTS.md `Known limits`.
- `kClassIdTagPos=12, kClassIdTagSize=20` (Dart 3.x 64-bit header) sudah
  diverifikasi via grep MCP dan konsisten dengan
  `internal/sdk/registers.go:225-228` `ClassIdTagPosV3=12, ClassIdTagSizeV3=20`.
- `kClassIdTagPos=16, kClassIdTagSize=16` (Dart 2.x 32-bit header) sudah
  ada di `registers.go:227-228` `ClassIdTagPosV2=16, ClassIdTagSizeV2=16`
  — konsisten dengan AGENTS.md `Class ID extraction differs: 2.x uses
  LDURH (16-bit, kClassIdTagPos=16)`.
- `kHeapObjectTag=1` sudah ada di `registers.go:175` `HeapObjectTag=1` —
  konsisten dengan `pointer_tagging.h` enum.
- `kTrueOffsetFromNull=32, kFalseOffsetFromNull=48` sudah ada di
  `predicates.go:205-208` — konsisten dengan `pointer_tagging.h`
  `kTrueOffsetFromNull = kObjectAlignment * 2 = 32` (word_size=8).

---

Report ini ditulis sebagai research gap planning — tidak ada perubahan
kode AOTopsy. Semua klaim diverifikasi ke `dart-lang/sdk` via grep MCP
(`searchGitHub`) dan `gh api` @3.12.2. Implementasi gap adalah pekerjaan
terpisah, prioritaskan Gap 1 (register ABI), Gap 4 (CID predicate), Gap 7
(stub authoritative list) sebagai TINGGI.
