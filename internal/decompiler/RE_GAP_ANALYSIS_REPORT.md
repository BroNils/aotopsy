# RE Gap Analysis Report: internal/decompiler

> **STATUS VERIFIKASI (2026-09-01)** — semua 11 gap CONFIRMED. Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> - Gap 1: nol penyebutan `DispatchTableReg`/`x21`/`ARM64DT` di seluruh paket.
> - Gap 2: `emit.go:460-472` seed 4 register (THR/PP/SP/HEAP_BITS);
>   `ssa.go:90-113 seedEntryState` seed 6 + arg0..N — asimetri persis seperti
>   klaim report.
> - Gap 10/11: `call.go:234,317` hanya menangani
>   `StubRoleAsyncInit/Await/Return`; `StubRoleTypeTest`/`StubRoleError`
>   tidak dikonsumsi.
> - **Temuan tambahan (tidak ada di report): `FuncIR.FpuArgRegs` dan
>   `FpuReturnReg` adalah field mati.** Diisi di `liftarm64.go:47-48` dan
>   `liftx86.go:65-66`, lalu **tidak pernah dibaca** di mana pun
>   (`grep -rn FpuArgRegs internal/` hanya menemukan penulisan + definisi).
>   Doc comment di `ir.go` mengklaim "Used by the lifter … and by the emitter
>   to display double/float parameters" — klaim itu tidak dijalankan.

## Ringkasan

Folder `internal/decompiler/` (~16.6k LOC, 67 file) adalah pseudocode decompiler AOTopsy yang mengubah ARM64/x86_64 instruction stream menjadi IR (`FuncIR`/`Block`/`Instr`) lalu pseudocode Dart-like via string-rewriting emitter (porting arsitektur `flutterdec`). Lifter sudah cukup matang: register reserved (THR/PP/SP/HEAP_BITS/NULL_REG/CODE_REG/ARGS_DESC_REG) sudah di-track, calling convention Dart-specific sudah benar (bukan C ABI), pool operand, THR field/stub, decompression, bool-from-null, class-id UBFX, async state machine, try/catch region, for-in/for-loop recovery, cascade/null-aware idiom, dan SSA fixpoint+loop phi sudah diimplementasikan.

Namun analisis terhadap Dart SDK source (`dart-lang/sdk` @3.12.2/3.9.2) menemukan beberapa gap signifikan: (1) **DISPATCH_TABLE_REG (R21 ARM64)** — register reserved AOT yang menampung base Global Dispatch Table **tidak di-seed** di emitter walk maupun FuncIR, sehingga setiap `BLR [X21, Xm, LSL #3]` dispatch call membocorkan token `x21` mentah; (2) **CODE_REG & ARGS_DESC_REG seeding inkonsisten** — doc comment ir.go mengklaim "seeded" tetapi `EmitPseudocode` hanya seed THR/PP/SP/HEAP_BITS, hanya fixpoint `seedEntryState` yang seed keduanya (rapuh, hanya via backdoor `seedFromFixpoint`); (3) **Smi tag/untag idiom tidak dikenali** — `SmiTag = LSL #1` (ARM64) / `add reg,reg` (x86), `SmiUntag = SBFM` (ARM64) / `SAR #1` (x86) adalah operasi terlalu umum yang SDK pakai di mana-mana tetapi decompiler render sebagai shift/add generik; (4) **Code entry-point load (monomorphic/unchecked) tidak dianotasi** — SDK punya 4 entry point per Code object (`entry_point_`, `unchecked_entry_point_`, `monomorphic_entry_point_`, `monomorphic_unchecked_entry_point_`) dengan displacement terverifikasi di `sdk/registers.go` tetapi decompiler tidak mengenali pola load-then-call-nya; (5) **switchable call miss stub** tidak diidentifikasi sebagai bookkeeping yang bisa di-elide; (6) beberapa instruksi ARM64 yang sering muncul di Dart AOT (`sbfm`/`ubfm`/`bfi`/`sbfx` non-classId, `rev`/`rev16`/`rev32`, `clz`/`cls`, `madd`/`msub` fused-multiply) tidak ada handler khusus. Mayoritas gap adalah **readability/coverage gap** (output honest tetapi noisy), bukan correctness bug — kecuali gap (1) dan (2) yang menyebabkan raw-register leak yang signifikan.

## Struktur Folder

### File inti IR & lifting
- **`ir.go`** (521 baris) — definisi `FuncIR`/`Block`/`Instr`/`Op` enum, `TryRegionEntry`, `ExceptionHandlerEntry`, field resolver, `SnapTryRegionsToBlocks`, `CatchClause`. Central data structure.
- **`lift.go`** (1078 baris) — `LiftState` (register/local string-expression map), `Clone`/`MergeJoin`, `operandExpr`, `fieldExpr`, `applyStore`, `ApplyOther` (shared mnemonic handler), `boolFromNullOffset`, `isPointerDecompression`, `dartFieldResolver`, `threadFieldExpr`, `stackSlotExpr`.
- **`liftarm64.go`** (485 baris) — `BuildARM64IR`, `liftARM64Instr` (BL/BLR/B/BR/CBZ/TBZ/LDR-pool), `arm64CondOp`, `applyOtherARM64` (movk/ubfx/ldr/cmn/str/ldp/stp/csel/cset/fadd/fcmp/fcvt/scvtf/fcvtzs).
- **`liftx86.go`** (684 baris) — `BuildX86IR`, `classifyX86Branch`, `classifyX86Condition` (BT/TEST/CMP → bittest/eqz/cmp), `applyOtherX86` (movzx/movsxd/push/pop/addsd/subsd/ucomisd/cvtsi2sd/cvttsd2si/cmov/set).

### Emission
- **`emit.go`** (707 baris) — `EmitPseudocode` entry point, signature generation, async/sync*/async* detection, try/catch annotation, post-walk modifier patch, naming/compaction pipeline.
- **`emit_walk.go`** (714 baris) — `emitBlock`/`emitBlockBody`/`emitBranch`/`emitJump`/`emitSuccessor` recursive CFG walk, `buildCondition`, `killDeadRegsAtSafepoint` (CSM liveness), `emitAsyncStateBranch` (switch dispatch), loop header detection.
- **`emit_helpers.go`** (502 baris) — `emitLoadPool`, `appendHelperFunctions` (helper extraction/inlining), `extractLoopCondition`, `invertCondition`, `inferReturnTypeFromName`.

### Dataflow & SSA
- **`ssa.go`** (445 baris) — `runFixpoint` reaching-definition, `joinStates`, `computeLoopPhis`, `isInductionRegister`, `declareLoopPhis`/`updatePinnedPhis` (loop-carried phi materialization), `seedFromFixpoint`.
- **`arity.go`** (288 baris) — `inferLiveInArgIndices` (intraprocedural arg liveness), `inspectInstrRegUsage`.

### Compaction & readability
- **`compact.go`** (472 baris) — `compactLines` (16-pass fixed point), `applyArgRenaming`, `simplifyExpressions`, `nullSafetyAnnotation`, `localTypeInference`.
- **`hoist_strings.go`** (122 baris) — hoist repeated long string literals to function-local `const`.
- **`naming.go`** (100 baris) — `applyNamingPass` (framePointer/returnAddress rename), `cleanCalleeName` (hash strip, mixin compact).
- **`selector.go`** (294 baris) — 166-entry static selector table, `classifyStandardSelector`, `selectorCandidates`.
- **`intent.go`** (113 baris) — `inferCallIntentFromSymbolName` (dart_/flutter_/package_/vm_runtime_ prefix decode).
- **`call.go`** (446 baris) — `emitCall`/`emitDirectCall`/`emitIndirectCall`, FFI vm_tag sentinel, THR stub sentinel, `knownVoidSelectors`, async stub role classification.
- **`pool_operand.go`** (83 baris) — pool operand resolution untuk non-load instruction (x86 cmp-against-pool).
- **`regcanon.go`** (114 baris) — `canonReg` (ARM64 w/x collapse, x86 r8-r15 width collapse), `stackComputedSlot`.
- **`validate.go`** (130 baris) — `ValidateSource` (keyword-as-operator, spaced-member-operator, assign-to-final, brace balance).
- **`cfg_verify.go`** (138 baris) — `VerifyCFG` structural CFG-vs-pseudocode comparison.
- **`project_synthesizer.go`** (261 baris) — `SynthesizeClass`/`SynthesizeLibrary` Dart source reconstruction.

### stmt/ subpackage — statement-tree readability passes
- **`stmt/stmt.go`** (382) — `Stmt` interface, `Line`/`Construct`/`Verbatim`, `ParseStmts`/`PrintStmts`, `BraceDelta`.
- **`stmt/stmt_passes.go`** (415) — `CompactTree` (dead-code, self-assign, empty-else, else-if collapse, duplicate-return, dead-while-true, if-else-return, guard merge, for-loop, dead-store).
- **`stmt/stmt_dataflow.go`** (339) — `CopyPropagationStmt`, `CommonSubexpressionEliminationStmt` (scope-aware via tree).
- **`stmt/stmt_idioms.go`** (550) — `CollectionIdiomsStmt` (Set/List literal), `StringInterpolationIdiomStmt`, `NullAwareIdiomStmt` (??/??=/?.), `CascadeIdiomStmt` (..).
- **`stmt/stmt_loops.go`** (220) — `mergeGuardsStmt`, `forLoopRecoveryStmt`.
- **`stmt/stmt_for_in.go`** (166) — `ForInLoopRecoveryStmt` (iterator→for-in).
- **`stmt/stmt_closure.go`** (99) — `ClosureInliningStmt` (AllocateClosure tear-off inline).
- **`stmt/stmt_inline.go`** (131) — `InlineSingleUseTempsStmt`.
- **`stmt/stmt_types.go`** (151) — `TypedDeclarationsStmt` (literal type inference).
- **`stmt/stmt_expr.go`** (367) — `CleanExprs`, `constantFoldExpr`, `rewriteNegatedComparisonsExpr`.
- **`stmt/async_linearizer.go`** (285) — `LinearizeAsyncStmt` (state-machine flatten, await for recovery).
- **`stmt/expr.go`** / **`stmt/helpers.go`** — expression tree parser & helpers.

### compare/ subpackage — cross-tool comparison
- **`compare/blutter_compare.go`** (342) — blutter output comparison.
- **`compare/darter_reflutter.go`** (147) — darter/reflutter version comparison.
- **`compare/ident_stats.go`** (233) — IdentStats-based temp re-classification.
- **`compare/fingerprint_dict.go`** (156) — fingerprint dictionary.
- **`compare/cross_sample.go`** (228) — cross-sample comparison.
- **`compare/r2_export.go`** (105) — r2 export.

## Gap Analysis

### Gap 1: DISPATCH_TABLE_REG (R21 ARM64) tidak di-seed

- **Deskripsi**: SDK `constants_arm64.h` @3.12.2 baris 142: `const Register DISPATCH_TABLE_REG = R21;` — register reserved AOT-only yang menampung base Global Dispatch Table (GDT). `SetupGlobalPoolAndDispatchTable()` di `assembler_arm64.cc` baris 1471 me-load-nya dari `THR.dispatch_table_array_offset`. Setiap `EmitDispatchTableCall` (`flow_graph_compiler_arm64.cc` baris 628) memancarkan `Call(Address(DISPATCH_TABLE_REG, LR, UXTX, Scaled))` = `BLR [X21, XL, LSL #3]`. AOTopsy's `sdk.ARM64DT = 21` ada untuk typetrack tetapi `FuncIR` **tidak punya field `DispatchTableReg`** dan `EmitPseudocode` (`emit.go` baris 460-472) **tidak men-seed R21** dengan nama simbolik seperti `DT`/`DISPATCH_TABLE`. Akibatnya setiap dispatch table call membocorkan token `x21` mentah di target BLR.
- **Bukti SDK**:
  - `runtime/vm/constants_arm64.h` @3.12.2 baris 142 (grep MCP): `const Register DISPATCH_TABLE_REG = R21;` dengan komentar `// R21 = 21, // DISPATCH_TABLE_REG (AOT only)` (baris 51).
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` baris 1469-1472 (grep MCP): `ldr(DISPATCH_TABLE_REG, Address(THR, target::Thread::dispatch_table_array_offset()));`
  - `runtime/vm/compiler/backend/flow_graph_compiler_arm64.cc` @3.12.2 baris 628 (gh api): `__ Call(compiler::Address(DISPATCH_TABLE_REG, LR, UXTX, compiler::Address::Scaled));`
  - `runtime/vm/ama_test.cc` baris 17 (grep MCP): `COMPILE_ASSERT(R21 == DISPATCH_TABLE_REG);` — ABI-stable.
  - Catatan: x86_64 **tidak** punya DISPATCH_TABLE_REG fixed; `flow_graph_compiler_x64.cc` baris 604 me-load table ke `RAX` dinamik via `LoadDispatchTable(table_reg)`, jadi gap ini ARM64-only.
- **Dampak**: Setiap GDT call (pola `ADD LR, cid, #offset; BLR [X21, LR, LSL #3]`) di pseudocode muncul sebagai `dynamicCall(indirectTarget_lr, [...])` atau `final tN = dynamicCall(...)` dengan target tidak ter-resolve ke `DT[selector]`. Untuk aplikasi Flutter besar dengan ribuan virtual call, ini adalah sumber raw-register leak terbesar setelah CODE_REG (yang sudah di-seed via fixpoint). RE user kehilangan konteks "ini adalah dispatch table call ke selector N" yang adalah informasi paling penting untuk RE method override.
- **Usulan**:
  1. Tambah `DispatchTableReg string` field di `FuncIR` (ARM64: `"x21"`, x86_64: `""` karena dinamik).
  2. Tambah `const SymDT = "DT"` di `sdk/registers.go`.
  3. Seed di `EmitPseudocode` (`emit.go` ~baris 468) dan `seedEntryState` (`ssa.go` ~baris 104): `if fir.DispatchTableReg != "" { e.state.setReg(fir.DispatchTableReg, sdk.SymDT) }`.
  4. Di `applyOtherARM64`/`operandExpr`, kenali pola `LDR Xd, [X21, Xm, LSL #3]` sebagai `DT[Xm]` (dispatch table index load) untuk membantu `emitIndirectCall` resolve target.
  5. Perubahan kecil (~20 baris), tidak destruktif, strictly additive.
- **Prioritas**: **tinggi** — ini adalah register reserved AOT paling sering diakses yang belum di-seed; dampak langsung ke ribuan call site.

### Gap 2: CODE_REG & ARGS_DESC_REG seeding inkonsisten antara doc dan kode

- **Deskripsi**: `ir.go` baris 100-111 doc comment `CodeReg`/`ArgsDescReg` mengklaim "Seeding it as the honest name 'CODE' resolves every read..." dan "Seeded as 'argsDesc'". Tetapi `EmitPseudocode` (`emit.go` baris 460-472) **hanya men-seed** `ThreadReg`→THR, `PoolReg`→PP, `StackReg`→SP, `HeapBitsReg`→HEAP_BITS. `CodeReg` dan `ArgsDescReg` **tidak di-seed** di emitter walk. Hanya `seedEntryState` di `ssa.go` baris 104-109 yang men-seed keduanya, dan itu hanya mencapai emitter via `seedFromFixpoint` (backdoor yang hanya mengisi register yang **belum** known). Pada function entry block 0, ini bekerja karena fixpoint entry state punya CODE/argsDesc dan emitter walk state belum. Tetapi jika fixpoint dinonaktifkan, atau jika ada path yang tidak lewat `seedFromFixpoint` (e.g. helper sub-emitter di `appendHelperFunctions` yang pakai `newLiftState` fresh — baris 71, hanya seed `NullReg`), CODE_REG bocor sebagai `x24`/`r12` dan ARGS_DESC_REG bocor sebagai `x4`/`r10`.
- **Bukti SDK**:
  - `runtime/vm/constants_arm64.h` @3.12.2 baris 143 (grep MCP): `const Register CODE_REG = R24;`
  - `runtime/vm/constants_x64.h` @3.12.2 baris 127-128 (gh api): `const Register ARGS_DESC_REG = R10; const Register CODE_REG = R12;`
  - `ir.go` baris 100-111 doc: "Seeding it as the honest name 'CODE'..." — klaim yang tidak dijalankan di `EmitPseudocode`.
  - `emit.go` baris 460-472: hanya 4 register di-seed (THR/PP/SP/HEAP_BITS).
  - `ssa.go` baris 104-109: `seedEntryState` men-seed CodeReg & ArgsDescReg — tetapi ini hanya via fixpoint.
  - `emit_helpers.go` baris 71: helper sub-emitter pakai `newLiftState(e.fir.NullReg)` — **tidak** seed CODE/argsDesc/THR/PP sama sekali (hanya dapat via `liveState.Clone()` di baris 92 jika `omittedStates` ada).
- **Dampak**: Raw-register leak `x24`/`r12` (CODE_REG) dan `x4`/`r10` (ARGS_DESC_REG) di helper sub-emitter dan setiap path yang tidak lewat fixpoint. Doc comment menyesatkan maintainer — mengklaim sesuatu sudah di-seed padahal tidak.
- **Usulan**:
  1. Tambah seeding eksplisit di `EmitPseudocode` setelah baris 472:
     ```go
     if fir.CodeReg != "" { e.state.setReg(fir.CodeReg, sdk.SymCode) }
     if fir.ArgsDescReg != "" { e.state.setReg(fir.ArgsDescReg, sdk.SymArgsDesc) }
     ```
  2. Perbaiki helper sub-emitter di `emit_helpers.go` baris 71 untuk seed reserved register sama seperti `seedEntryState` (atau pakai `seedEntryState` langsung).
  3. Perbaiki doc comment `ir.go` agar konsisten dengan implementasi (atau implementasi mengikuti doc).
  4. Perubahan kecil (~10 baris), strictly additive.
- **Prioritas**: **sedang** — sudah setengah-work via fixpoint, tetapi rapuh dan doc menyesatkan.

### Gap 3: Smi tag/untag idiom tidak dikenali

- **Deskripsi**: Dart Smi (small integer) ditandai dengan `kSmiTag = 0, kSmiTagShift = 1` (`pointer_tagging.h` baris 89-94). SDK memancarkan:
  - ARM64 `SmiTag(reg)` = `LslImmediate(dst, src, 1)` → `LSL #1` (`assembler_arm64.h` baris 1726)
  - ARM64 `SmiUntag(dst, src)` = `sbfm(dst, src, 1, kSmiBits+1)` → `SBFM Xd, Xs, #1, #62` (baris 1722)
  - x86 `SmiTag(reg)` = `add reg, reg` (`assembler_x64.h` baris 1072)
  - x86 `SmiUntag(reg)` = `sar reg, 1` (`assembler_x64.h` baris 1074)
  Decompiler merender semua ini sebagai shift/add generik: `(x << 1)`, `(x >> 1)`, `(x + x)`. RE user tidak tahu ini adalah Smi tag/untag (konversi integer Dart ↔ raw value), yang adalah operasi paling umum di Dart AOT setelah field load.
- **Bukti SDK**:
  - `runtime/vm/pointer_tagging.h` baris 89-94 (grep MCP): `kSmiTag = 0, kSmiTagSize = 1, kSmiTagShift = 1`
  - `runtime/vm/compiler/assembler/assembler_arm64.h` baris 1721-1728 (grep MCP): `SmiUntag(dst, src) { sbfm(dst, src, kSmiTagSize, kSmiBits+1); }` dan `SmiTag(dst, src) { LslImmediate(dst, src, kSmiTagSize); }`
  - `runtime/vm/compiler/assembler/assembler_x64.h` baris 1071-1078 (grep MCP): `SmiTag(reg) { add(reg, reg); }` dan `SmiUntag(reg) { sar(reg, Immediate(kSmiTagSize)); }`
- **Dampak**: Pseudocode penuh `(x << 1)` dan `(x >> 1)` yang sebenarnya adalah `smiTag(x)` / `smiUntag(x)`. RE user harus mentally reverse-tag setiap integer. Untuk fungsi numerik (counter, accumulator, index arithmetic) ini adalah noise dominan.
- **Usulan**:
  1. Di `applyOtherARM64`, kenali `lsl Xd, Xs, #1` (atau `add Xd, Xs, Xs` dengan shift #1) sebagai `smiTag(Xs)` — tetapi **hati-hati**: `LSL #1` punya banyak use case lain (index scale, bitwise). Hanya anotasi sebagai `// smiTag` comment, jangan rewrite, KECUALI jika konteks mendukung (e.g. sebelum `BLR [X21, ...]` dispatch yang pakai cid-as-smi).
  2. Kenali `sbfm Xd, Xs, #1, #62` sebagai `smiUntag(Xs)` — pola SBFM ini lebih spesifik (lsb=1, width=62) dan jarang dipakai di luar SmiUntag.
  3. Di x86, `add reg, reg` terlalu ambigu (bisa self-add untuk doubling); jangan rewrite. `sar reg, 1` juga ambigu. Hanya anotasi comment jika konteks mendukung.
  4. Perubahan sedang (~30 baris), risiko false-positive tinggi — perlu gate konteks.
- **Prioritas**: **rendah** — readability improvement, bukan correctness. Risiko false-positive tinggi karena operasi yang sama punya banyak arti lain.

### Gap 4: Code entry-point load (monomorphic/unchecked) tidak dianotasi

- **Deskripsi**: SDK Code object punya 4 entry point (`raw_object.h` baris 2017-2049): `entry_point_` (kNormal), `unchecked_entry_point_` (kUnchecked), `monomorphic_entry_point_` (kMonomorphic, AOT-only, switchable call), `monomorphic_unchecked_entry_point_` (kMonomorphicUnchecked). `sdk/registers.go` baris 193-201 sudah punya displacement terverifikasi (`CodeEntryPointDispCompressed = 0x3`, `CodeMonomorphicEntryPointDispCompressed = 0xb`, dll.). Tetapi decompiler tidak mengenali pola `LDR Xd, [Xcode, #disp]` sebagai "load entry point N dari Code object" — ia hanya render sebagai `code.f3` / `code.f11` generik via `fieldExpr`. RE user kehilangan konteks "ini adalah monomorphic entry point load untuk switchable call".
- **Bukti SDK**:
  - `runtime/vm/raw_object.h` baris 2017-2049 (grep MCP): `uword entry_point_; uword monomorphic_entry_point_; uword unchecked_entry_point_; uword monomorphic_unchecked_entry_point_;`
  - `runtime/vm/object.h` baris 6960-6966 (grep MCP): `case EntryKind::kMonomorphic: return OFFSET_OF(UntaggedCode, monomorphic_entry_point_);`
  - `runtime/vm/compiler/runtime_offsets_list.h` baris 159 (grep MCP): `CONSTANT(UntaggedCode, monomorphic_entry_point_)` — ada di generated offsets.
  - `sdk/registers.go` baris 193-201: displacement constants sudah ada tetapi tidak dipakai decompiler.
- **Dampak**: Load entry point Code object (pola umum sebelum `BLR Xd`) muncul sebagai `code.f3` bukan `code.monomorphicEntryPoint`. RE user tidak tahu call site ini pakai entry kind mana (normal vs unchecked vs monomorphic) — informasi penting untuk memahami devirtualization strategy compiler.
- **Usulan**:
  1. Tambah `CodeEntryPointName(disp int64, compressed bool) string` di `sdk/registers.go` yang map displacement → `"entryPoint"`/`"uncheckedEntryPoint"`/`"monomorphicEntryPoint"`/`"monomorphicUncheckedEntryPoint"`.
  2. Di `fieldExpr` atau `dartFieldResolver`, jika base register's class adalah Code (CID kCodeCid) dan disp cocok, pakai nama entry point.
  3. Alternatif: kenali pola `LDR Xd, [Xcode, #0x3]` → `BLR Xd` sebagai "monomorphic call" dan anotasi `// monomorphic entry point call`.
  4. Perubahan sedang (~40 baris), perlu integrasi dengan typetrack untuk deteksi base register class.
- **Prioritas**: **sedang** — informasi berguna untuk RE devirtualization analysis, tetapi bukan raw-register leak.

### Gap 5: Switchable call miss stub tidak di-elide sebagai bookkeeping

- **Deskripsi**: SDK AOT switchable call mechanism (`runtime/docs/README.md` baris 779): call site dimulai unlinked → `SwitchableCallMissStub` → `DRT_SwitchableCallMiss` runtime → patch caller. Stub load via `ldr(CODE_REG, Address(THR, target::Thread::switchable_call_miss_stub_offset()))` (`stub_code_compiler_arm64.cc` baris 3742). Decompiler sudah elide stack-overflow check dan write-barrier check via `sdk.IsStackOverflowCond`/`IsWriteBarrierCond`, tetapi **tidak ada elision untuk switchable call miss stub**. Call ke `switchable_call_miss_stub` / `switchable_call_miss_entry` muncul sebagai call biasa di pseudocode.
- **Bukti SDK**:
  - `runtime/vm/compiler/stub_code_compiler_arm64.cc` baris 3742 (grep MCP): `__ ldr(CODE_REG, Address(THR, target::Thread::switchable_call_miss_stub_offset()));`
  - `runtime/vm/compiler/stub_code_compiler_x64.cc` baris 3694 (grep MCP): `__ jmp(Address(THR, target::Thread::switchable_call_miss_entry_offset()));`
  - `runtime/docs/README.md` baris 779 (grep MCP): "Initially all `dynamic` calls in AOT start in the *unlinked* state. When such call-site is reached for the first time SwitchableCallMissStub is invoked."
- **Dampak**: Call ke switchable-call-miss stub (compiler bookkeeping, bukan application logic) muncul sebagai `final tN = switchable_call_miss_stub(...)` di pseudocode. RE user mengira ini application call padahal adalah runtime patching machinery.
- **Usulan**:
  1. Tambah `StubRoleSwitchableCallMiss` ke `sdk/stubclass.go` `StubRole` enum.
  2. Di `classifyMundanePattern`, tambah pattern `"switchable_call_miss"` → `StubRoleSwitchableCallMiss`.
  3. Di `emitDirectCall`/`emitIndirectCall`, elide call ke stub dengan role ini (emit comment, jangan emit `final tN = ...`).
  4. Perubahan kecil (~15 baris).
- **Prioritas**: **rendah** — stub ini relatif jarang di release AOT (kebanyakan call site sudah linked); lebih sering muncul di debug/profile build.

### Gap 6: Instruksi ARM64 yang sering muncul tanpa handler khusus

- **Deskripsi**: `applyOtherARM64` (`liftarm64.go` baris 257-484) handle ~20 mnemonic, tetapi beberapa instruksi yang sering muncul di Dart AOT tidak ada handler-nya dan jatuh ke `ApplyOther` default (generic 3-operand ALU yang hanya set `s.setReg(dst, ...)` tanpa semantic):
  - **`sbfm`/`ubfm`/`bfi`/`sbfx` non-classId** — `SBFM Xd, Xs, #1, #62` adalah SmiUntag (Gap 3), `UBFM` lain adalah bitfield extract/insert. Hanya `ubfx` dengan lsb=12/width=20 yang di-handle sebagai `classId(...)`.
  - **`rev`/`rev16`/`rev32`** — byte reverse, muncul di endian conversion, hash, UTF-8 encoding.
  - **`clz`/`cls`** — count leading zeros/sign bits, muncul di bit manipulation intrinsics.
  - **`madd`/`msub`** — fused multiply-add/subtract, muncul di numeric computation. Saat ini `mul` di-handle tetapi `madd`/`msub` tidak.
  - **`sdiv`/`udiv`** — integer divide, muncul di int arithmetic. Tidak ada handler.
  - **`extr`** — extract register pair, muncul di 128-bit constant materialization.
  - **`adc`/`sbc`/`sbfiz`/`ubfiz`** — carry/add with carry, bitfield insert zero.
- **Bukti SDK**: `runtime/vm/compiler/assembler/assembler_arm64.h` mendefinisikan semua ini; `flow_graph_compiler_arm64.cc` dan `il_arm64.cc` memancarkannya untuk berbagai IL node. Tidak ada grep spesifik karena pola tersebar.
- **Dampak**: Instruksi-instruksi ini dirender sebagai `dst = (src1 ? src2)` atau tidak dirender sama sekali (jika mnemonic tidak match case apa pun). RE user melihat register yang "berubah nilai secara magic" atau ekspresi yang tidak ada.
- **Usulan**:
  1. Tambah handler di `applyOtherARM64` untuk: `madd`/`msub` → `(a * b + c)`/`(a * b - c)`; `sdiv`/`udiv` → `(a / b)` (Dart integer division adalah `~/`, tetapi `sdiv` adalah raw truncating division); `rev` → `byteSwap(x)`; `clz` → `countLeadingZeros(x)`; `sbfm`/`ubfm` generik → `bitField(x, lsb, width)`.
  2. Perubahan sedang (~50 baris), strictly additive.
- **Prioritas**: **sedang** — `madd`/`msub`/`sdiv` cukup sering di numeric code; `rev`/`clz` lebih jarang.

### Gap 7: TMP/TMP2 (R16/R17 ARM64) scratch register tidak di-annotasi

- **Deskripsi**: SDK `constants_arm64.h` baris 138-139: `const Register TMP = R16; const Register TMP2 = R17;` — scratch register yang dipakai assembler untuk intermediate computation. Tidak reserved globally (register allocator boleh pakai), tetapi sering muncul di compiler-generated code sequence. Decompiler tidak punya anotasi khusus — `x16`/`x17` muncul sebagai token mentah ketika register allocator pakai untuk short-lived temp.
- **Bukti SDK**: `runtime/vm/constants_arm64.h` @3.12.2 baris 138-139 (grep MCP): `const Register TMP = R16; const Register TMP2 = R17;` dengan komentar `// Used as scratch register by assembler.`
- **Dampak**: `x16`/`x17` muncul sebagai raw token di pseudocode ketika scratch register tidak di-forward ke ekspresi. Tidak sefatal DISPATCH_TABLE_REG karena TMP/TMP2 benar-benar scratch (tidak carry meaning across instructions), tetapi tetap noise.
- **Usulan**: Tidak perlu seed (TMP/TMP2 tidak persistent). Tetapi di `applyOtherARM64`, jika `mov X16, Xexpr` diikuti `use X16` dalam 1-2 instruksi berikutnya, inline `Xexpr` ke use site. Ini sudah sebagian dilakukan oleh copy propagation pass, tetapi hanya pada `tN` temp, bukan raw register. Perluas copy propagation ke register alias. Perubahan besar, prioritas rendah.
- **Prioritas**: **rendah** — scratch register bersifat transient, copy propagation sebagian sudah handle.

### Gap 8: Megamorphic call stub (BLR via IC_DATA_REG) tidak dikenali

- **Deskripsi**: SDK AOT megamorphic call (`stub_code_compiler_arm64.cc` baris 3456 `GenerateMegamorphicCallStub`) pakai `IC_DATA_REG = R5` (ARM64, `constants_arm64.h` baris 148) untuk cache lookup. Pola: `LDR X5, [pool, #icDataSlot]; LDR Xcode, [X5, #entriesOffset]; ...; BLR Xcode`. Decompiler tidak mengenali IC_DATA_REG sebagai register khusus dan tidak mengidentifikasi pola megamorphic call. `IC_DATA_REG` hanya muncul di JIT; di AOT murni, megamorphic call pakai dispatch table (Gap 1). Tetapi beberapa AOT build masih punya IC-based fallback.
- **Bukti SDK**: `runtime/vm/constants_arm64.h` @3.12.2 baris 148 (grep MCP): `const Register IC_DATA_REG = R5; // ICData/MegamorphicCache register.` — tetapi dengan komentar `// Set when calling Dart functions in JIT mode`. Di AOT murni, IC_DATA_REG tidak reserved.
- **Dampak**: Minimal di AOT murni (dispatch table dominan). Hanya relevan untuk build hybrid/debug.
- **Usulan**: Tidak ada action — IC_DATA_REG adalah JIT-only, AOTopsy targetnya AOT murni. Dokumentasikan saja di komentar.
- **Prioritas**: **rendah** — bukan target AOT murni.

### Gap 9: CompressedStackMaps NonSpillBits hanya kill, tidak type

- **Deskripsi**: `killDeadRegsAtSafepoint` (`emit_walk.go` baris 630-657) pakai `CompressedStackMaps` `NonSpillBits` untuk kill register yang dead di safepoint. Tetapi CSM juga punya informasi **spill slot location** (di mana object live di-spill di stack) yang bisa membantu `operandExpr` resolve `[FP, #off]` ke object name ketika register di-spill. Decompiler tidak memanfaatkan ini — stack slot yang hold object di safepoint tetap dirender sebagai `local_mNN` generik.
- **Bukti SDK**: `runtime/vm/compiler/backend/code_metrics.h` dan `runtime/vm/data/compressed_stackmaps.h` — CSM format punya `spill_slots` bitmap per PC. Tidak diverifikasi lebih lanjut karena formatnya kompleks dan berubah antar versi.
- **Dampak**: Stack slot yang hold live object di GC safepoint tidak diberi nama semantik. RE user melihat `local_m24 = someObject; ...; use(local_m24)` tanpa indikasi `local_m24` adalah spill slot untuk object tertentu.
- **Usulan**: Memerlukan dekoder CSM yang lebih lengkap (saat ini hanya `NonSpillBits` yang di-decode di `cluster`). Perubahan besar, lintas-package. Prioritas rendah.
- **Prioritas**: **rendah** — kompleksitas tinggi, payoff terbatas.

### Gap 10: Type test / subtype check stub call tidak dianotasi sebagai `is`-check

- **Deskripsi**: SDK AOT type test (`StubCodeCompiler::GenerateTypeTestStub` / `SubtypeTestStub`) dipanggil untuk `is`/`as` check. `sdk/stubclass.go` sudah punya `StubRoleTypeTest` (baris 33) dan `classifyMundanePattern` mengenali `"type_test"`/`"subtype_check"` (baris 113-114). Tetapi `emitDirectCall`/`emitIndirectCall` **tidak punya branch khusus** untuk `StubRoleTypeTest` — call ke type test stub muncul sebagai `final tN = type_test_stub(args)` bukan `final tN = (arg is Type)`.
- **Bukti SDK**:
  - `runtime/vm/compiler/stub_code_compiler_arm64.cc` — `GenerateTypeTestStub` / `GenerateSubtypeTestStub`.
  - `sdk/stubclass.go` baris 33: `StubRoleTypeTest` sudah didefinisikan.
  - `sdk/stubclass.go` baris 113-114: pattern `"type_test"`/`"subtype_check"` → `StubRoleTypeTest`.
  - `call.go` — `emitDirectCall`/`emitIndirectCall` hanya handle `StubRoleAsyncInit/Await/Return`, tidak handle `StubRoleTypeTest`.
- **Dampak**: `is`/`as` check (sangat umum di Dart) muncul sebagai call ke stub, bukan sebagai type check expression. RE user kehilangan salah satu konstruksi Dart paling umum.
- **Usulan**:
  1. Di `emitDirectCall`/`emitIndirectCall`, tambah branch untuk `StubRoleTypeTest`: jika call target adalah type test stub, render sebagai `final tN = (arg0 is Type)` (memerlukan resolusi type dari stub name atau pool).
  2. Stub name biasanya mengandung type name (e.g. `TypeTest_<Type>`), bisa di-extract.
  3. Perubahan sedang (~30 baris), tetapi resolusi type name dari stub name bisa rapuh.
- **Prioritas**: **sedang** — `is`/`as` check adalah konstruksi Dart fundamental; anotasi akan signifikan meningkatkan readability.

### Gap 11: Null-error stub call tidak dikenali sebagai null-check guard

- **Deskripsi**: SDK `DispatchTableNullErrorABI::kClassIdReg = R0` (ARM64, `constants_arm64.h` baris 490) — dispatch table call pakai R0 sebagai class ID register; jika receiver null, `GenerateDispatchTableNullErrorStub` dipanggil. `sdk/stubclass.go` sudah punya `StubRoleError` (baris 36) dan mengenali `"null_error"`/`"range_error"` (baris 117-118). Tetapi decompiler tidak mengenali pola `if (arg == null) { null_error_stub(); }` sebagai null-check guard yang bisa di-render sebagai `arg!` (null assertion) atau `if (arg != null) { ... }`.
- **Bukti SDK**:
  - `runtime/vm/constants_arm64.h` @3.12.2 baris 489-490 (gh api): `struct DispatchTableNullErrorABI { static constexpr Register kClassIdReg = R0; };`
  - `runtime/vm/compiler/stub_code_compiler_arm64.cc` baris 590 (grep MCP): `GenerateDispatchTableNullErrorStub` — `SmiTag(kClassIdReg); PushRegister(kClassIdReg); CallRuntime(kDispatchTableNullErrorRuntimeEntry, 1);`
- **Dampak**: Null-check guard (sangat umum di null-safe Dart) muncul sebagai `if (arg == null) { null_error_stub(arg); }` bukan `arg!` atau `if (arg != null) { ... }`. RE user tidak melihat null-safety pattern.
- **Usulan**:
  1. Di `emitDirectCall`, kenali `StubRoleError` dengan stub name mengandung `"null_error"` → render sebagai `arg!` (null assertion) atau anotasi `// null check`.
  2. Kombinasikan dengan `nullSafetyAnnotation` pass yang sudah ada.
  3. Perubahan sedang (~20 baris).
- **Prioritas**: **sedang** — null-safety adalah fitur Dart inti; anotasi akan membantu RE user memahami null-flow.

## Register Tracking Gaps

| Register | SDK Role | AOTopsy Status | Dampak |
|----------|----------|----------------|--------|
| **R21 (ARM64)** | `DISPATCH_TABLE_REG` — GDT base, reserved AOT-only, callee-saved | **NOT seeded** in `FuncIR`/`EmitPseudocode`/`seedEntryState`. `sdk.ARM64DT=21` ada untuk typetrack saja. | Setiap `BLR [X21, Xm, LSL #3]` dispatch call bocor sebagai `x21` raw token. **Gap terbesar.** |
| **R24 (ARM64) / R12 (x86)** | `CODE_REG` — current Code object | **Inconsistently seeded**: doc claim "seeded" tetapi `EmitPseudocode` tidak seed; hanya `seedEntryState` (fixpoint) seed. Helper sub-emitter tidak seed. | `x24`/`r12` bocor di helper sub-emitter dan path tanpa fixpoint. |
| **R4 (ARM64) / R10 (x86)** | `ARGS_DESC_REG` — arguments descriptor | **Inconsistently seeded**: sama seperti CODE_REG. | `x4`/`r10` bocor di helper sub-emitter. |
| **R16/R17 (ARM64)** | `TMP`/`TMP2` — assembler scratch | Not seeded (correct — scratch, not persistent). Tidak di-annotate. | `x16`/`x17` muncul sebagai raw token untuk short-lived temp. Minor noise. |
| **R0 (ARM64) / RCX (x86)** | `DispatchTableNullErrorABI::kClassIdReg` — class ID untuk dispatch | Not seeded (correct — hanya ABI untuk dispatch call, tidak persistent). | Tidak ada dampak langsung; R0 sudah return reg, RCX sudah kClassIdReg di sdk. |
| **R5 (ARM64)** | `IC_DATA_REG` — ICData/MegamorphicCache (JIT-only) | Not seeded (correct — JIT-only, AOT tidak pakai). | Tidak ada dampak di AOT murni. |
| **R3 (ARM64) / RBX (x86)** | `SuspendStubABI::kSuspendStateReg` — suspend state (stub-ABI only) | Not seeded (correct — stub-ABI, tidak persistent global). | Tidak ada dampak; async detection via call target sudah benar. |
| **V0-V7 (ARM64) / XMM0-XMM7 (x86)** | FPU arg/return registers | `FpuArgRegs`/`FpuReturnReg` di `FuncIR` tetapi **tidak di-seed** di `EmitPseudocode`/`seedEntryState`. | FPU arg register (`v0`-`v5`/`xmm1`-`xmm6`) tidak dapat nama `farg0`-`farg5`; double parameter tidak dianotasi di signature. |

## Fitur RE Missing/Incomplete

### Missing (tidak ada implementasi sama sekali)
1. **Dispatch table call resolution** — `BLR [DT, cid, LSL #3]` tidak di-resolve ke selector/callee. SDK: `EmitDispatchTableCall` (`flow_graph_compiler_arm64.cc` baris 628). AOTopsy punya `KnownDispatchIndex` di typetrack tetapi decompiler tidak konsumsi.
2. **Smi tag/untag recognition** — `LSL #1`/`add reg,reg`/`SBFM #1,#62`/`SAR #1` tidak dikenali sebagai Smi operation. SDK: `SmiTag`/`SmiUntag` di `assembler_arm64.h`/`assembler_x64.h`.
3. **Code entry-point kind annotation** — load `entry_point_`/`unchecked_entry_point_`/`monomorphic_entry_point_` tidak dianotasi. SDK: 4 entry point di `raw_object.h` baris 2017-2049, displacement di `sdk/registers.go` tetapi tidak dipakai.
4. **Type test (`is`/`as`) stub → expression** — call ke `TypeTestStub`/`SubtypeTestStub` tidak di-render sebagai `(x is Type)`. `StubRoleTypeTest` ada di sdk tetapi `emitCall` tidak konsumsi.
5. **Null-error stub → null assertion** — call ke `null_error_stub` tidak di-render sebagai `x!` atau null guard. `StubRoleError` ada tetapi tidak ada branch khusus.
6. **Switchable call miss stub elision** — `switchable_call_miss_stub` tidak di-elide sebagai bookkeeping. `StubRoleSwitchableCallMiss` belum ada.
7. **FPU arg register seeding** — `v0`-`v5`/`xmm1`-`xmm6` tidak di-seed sebagai `farg0`-`farg5` di signature/emitter. `FpuArgRegs` field ada tetapi tidak dipakai.
8. **CSM spill-slot typing** — `CompressedStackMaps` spill slot location tidak dipakai untuk type stack slot yang hold live object.

### Incomplete (ada tetapi tidak lengkap)
1. **ARM64 instruction coverage** — `madd`/`msub`/`sdiv`/`udiv`/`rev`/`clz`/`sbfm`/`ubfm` generik/`extr`/`adc`/`sbc` tidak ada handler khusus (Gap 6).
2. **Monomorphic call pattern** — pola `LDR Xentry, [Xcode, #monomorphicDisp]; BLR Xentry` tidak dikenali sebagai monomorphic dispatch (Gap 4 + Gap 1).
3. **Helper sub-emitter reserved register seeding** — `appendHelperFunctions` pakai `newLiftState(NullReg)` tanpa seed THR/PP/SP/CODE/argsDesc (Gap 2).
4. **Loop phi for FPU registers** — `computeLoopPhis`/`isInductionRegister` hanya cek GPR; FPU loop-carried (double accumulator) tidak dapat phi materialization.
5. **`sbfm`/`ubfm` non-classId** — hanya `ubfx` dengan lsb=12/width=20 yang di-handle sebagai `classId(...)`; bitfield extract lain jatuh ke generic.

## Verifikasi SDK

### grep MCP (searchGitHub) — verifikasi literal code pattern di `dart-lang/sdk`

1. **`kCpuRegistersForArgs[] = {R1, R2, R3, R5, R6, R7}`** → `runtime/vm/constants_arm64.h` baris 649 (ARM64 calling convention, terverifikasi).
2. **`kCpuRegistersForArgs[] = {RDI`** → `runtime/vm/constants_x64.h` baris 698-699 (x86_64 calling convention, terverifikasi: `{RDI, RSI, RDX, RBX, R8, R9}`).
3. **`CODE_REG = R24`** → `runtime/vm/constants_arm64.h` baris 143 (terverifikasi).
4. **`DISPATCH_TABLE_REG = R21`** → `runtime/vm/constants_arm64.h` baris 142 + `ama_test.cc` baris 17 `COMPILE_ASSERT(R21 == DISPATCH_TABLE_REG)` (terverifikasi, ABI-stable).
5. **`DISPATCH_TABLE_REG`** (cross-arch) → ARM64=R21, ARM32=NOTFP, RISCV=S9. x86_64 **tidak punya** fixed DISPATCH_TABLE_REG (pakai RAX dinamik via `LoadDispatchTable`).
6. **`kSuspendStateReg`** → stub-ABI only (SuspendStubABI/ResumeStubABI), bukan globally reserved. ARM64: R3 (SuspendStub) / R2 (ResumeStub). x86_64: RBX.
7. **`DispatchTableNullErrorABI`** → ARM64: `kClassIdReg = R0` (`constants_arm64.h` baris 490). x86_64: `kClassIdReg = RCX` (`constants_x64.h` baris 453).
8. **`EmitDispatchTableCall`** → `flow_graph_compiler_arm64.cc` baris 616-631: `AddImmediate(LR, cid_reg, offset); Call(Address(DISPATCH_TABLE_REG, LR, UXTX, Scaled));`. x86_64: `flow_graph_compiler_x64.cc` baris 604: `LoadDispatchTable(table_reg=RAX); call(Address(table_reg, cid_reg, TIMES_8, offset));`.
9. **`monomorphic_entry_point_`** → `raw_object.h` baris 2017-2049: 4 entry point field. `object.h` baris 6960-6966: `EntryKind` enum. `app_snapshot.cc` baris 9825-9856: serialization.
10. **`SwitchableCallMissStub`** → `stub_code_compiler_arm64.cc` baris 3742: `ldr(CODE_REG, Address(THR, switchable_call_miss_stub_offset()))`. `stub_code_compiler_x64.cc` baris 3694: `jmp(Address(THR, switchable_call_miss_entry_offset()))`.
11. **`kSmiTagShift`** → `pointer_tagging.h` baris 89-94: `kSmiTag = 0, kSmiTagSize = 1, kSmiTagShift = 1`.
12. **`SmiUntag(dst, src)`** → `assembler_arm64.h` baris 1722: `sbfm(dst, src, kSmiTagSize, kSmiBits+1)`. `assembler_x64.h` baris 1074: `sar(reg, Immediate(kSmiTagSize))`.
13. **`SmiTag(dst, src)`** → `assembler_arm64.h` baris 1726: `LslImmediate(dst, src, kSmiTagSize)`. `assembler_x64.h` baris 1072: `add(reg, reg)`.
14. **`kClassIdTagPos`** → `assembler_arm64.cc` baris 1341: `ExtractClassIdFromTags` pakai `ubfx(result, tags, kClassIdTagPos=12, kClassIdTagSize=20)`. Sudah di-handle decompiler (`liftarm64.go` baris 289).
15. **`SetupGlobalPoolAndDispatchTable`** → `assembler_arm64.cc` baris 1469-1472: `ldr(PP, THR.global_object_pool); sub(PP, kHeapObjectTag); ldr(DISPATCH_TABLE_REG, THR.dispatch_table_array)`.

### gh api — verifikasi konten file utuh di tag versi

1. **`runtime/vm/constants_x64.h` @3.12.2** (gh api raw):
   - Baris 123: `const Register PP = R15;`
   - Baris 124-125: `SPREG = RSP; FPREG = RBP;`
   - Baris 127-128: `ARGS_DESC_REG = R10; CODE_REG = R12;`
   - Baris 131: `THR = R14;`
   - Baris 453: `DispatchTableNullErrorABI::kClassIdReg = RCX;`
   - Baris 457: `kClassIdReg = RCX;`
   - Baris 576/648: `kReturnFpuReg = XMM0;`
   - Baris 698-700: `kCpuRegistersForArgs[] = {RDI, RSI, RDX, RBX, R8, R9}; kFpuRegistersForArgs[] = {XMM1, XMM2, XMM3, XMM4, XMM5, XMM6};`
   - **Tidak ada `DISPATCH_TABLE_REG` alias** — dikonfirmasi x86_64 pakai RAX dinamik.

2. **`runtime/vm/constants_arm64.h` @3.12.2** (gh api raw):
   - Baris 489-490: `DispatchTableNullErrorABI::kClassIdReg = R0;`

3. **`runtime/vm/compiler/backend/flow_graph_compiler_arm64.cc` @3.12.2** (gh api raw, baris 610-670):
   - `EmitDispatchTableCall`: `cid_reg = DispatchTableNullErrorABI::kClassIdReg; AddImmediate(LR, cid_reg, offset); Call(Address(DISPATCH_TABLE_REG, LR, UXTX, Scaled));`

4. **`runtime/vm/compiler/backend/flow_graph_compiler_x64.cc` @3.12.2** (gh api raw, baris 590-640):
   - `EmitDispatchTableCall`: `table_reg = RAX; LoadDispatchTable(table_reg); call(Address(table_reg, cid_reg, TIMES_8, offset));` — dikonfirmasi x86_64 **tidak** pakai fixed DISPATCH_TABLE_REG.

### Verifikasi internal AOTopsy code

- `internal/sdk/registers.go` baris 38-49: `ARM64DT = 21` ada tetapi tidak diekspos ke `FuncIR`.
- `internal/decompiler/ir.go`: tidak ada field `DispatchTableReg`.
- `internal/decompiler/emit.go` baris 460-472: hanya seed THR/PP/SP/HEAP_BITS.
- `internal/decompiler/ssa.go` baris 90-113: `seedEntryState` seed THR/PP/SP/HEAP_BITS/CODE_REG/ARGS_DESC_REG (6 register) — tetapi `EmitPseudocode` hanya seed 4.
- `internal/decompiler/emit_helpers.go` baris 71: helper sub-emitter pakai `newLiftState(NullReg)` — hanya seed NULL_REG.
- `internal/decompiler/liftarm64.go` baris 279-294: `ubfx` handler hanya untuk classId (lsb=12, width=20); `sbfm`/`ubfm` generik tidak ada handler.
- `internal/decompiler/call.go` baris 234-255: `emitDirectCall` hanya handle `StubRoleAsyncInit/Await/Return`; tidak handle `StubRoleTypeTest`/`StubRoleError`.
- `internal/sdk/stubclass.go` baris 33-36: `StubRoleTypeTest`/`StubRoleError` sudah didefinisikan tetapi tidak dikonsumsi `emitCall`.
