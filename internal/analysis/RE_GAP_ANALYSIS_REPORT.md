# RE Gap Analysis Report: internal/analysis

> **STATUS VERIFIKASI (2026-09-01)** — Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`. Koreksi:
> - **Tabel register di Gap 4 dan di bagian "Register Tracking Gaps" SALAH.**
>   Report menulis "ARGS_DESC_REG di R25/X25, CODE_REG di R26/X26" dan
>   "R28/R14 (THR)". Ground truth `internal/sdk/registers.go:38-49`:
>   PP=R27, **THR=R26**, DT=R21, **HEAP_BITS=R28**, **CODE_REG=R24**,
>   **ARGS_DESC=R4**, SP=R15, NULL=R22, FP=R29, LR=R30. Jadi R26 adalah THR
>   (bukan CODE_REG) dan R25 bukan ARGS_DESC (R25 = `kWriteBarrierSlotReg`).
>   Inti gap-nya tetap benar (R4/R24 memang tidak di-seed di typetrack);
>   yang salah nomor registernya. CONSOLIDATED_SUMMARY §7.1 memakai angka yang
>   benar — dua dokumen ini sempat bertentangan.
> - Gap 3, 5, 6 **CONFIRMED**: `runFromExisting` (`pipeline.go:484-522`) memang
>   hanya menjalankan signal + meta; `RunDisasmStageX86` memang serial
>   (`for i := 0; i < n; i++`) vs ARM64 chunk+`sync.WaitGroup`; disasm memang
>   diulang 3× (disasm stage → typetrack stage → signal stage dari `.bin`).
> - Bagian "Catatan tentang field yang TIDAK ada di AOT snapshot" **benar dan
>   penting** — khususnya `obfuscation_map` setelah batas `to_snapshot(kFullAOT)`.
>   Report `internal/snapshot` mengusulkan mengekstraknya sebagai prioritas
>   tinggi; yang benar adalah catatan di report ini.

## Ringkasan

Folder `internal/analysis/` adalah orkestrator pipeline AOTopsy: mengkoordinasi
ELF load → snapshot parse → cluster scan/fill → instructions table → code
ranges → disassembly → type inference → cross-ref → signal → meta → output.
Berisi 38 file sumber (non-test) + 21 file test + 4 golden JSON, total ~13k
baris Go.

Pipeline saat ini sudah cukup matang untuk ARM64 (Dart 2.10–3.13) dan x86_64
(Dart 3.x), dengan coverage yang terverifikasi melalui golden gate, symtabdiff
gate, dan cross-version differential gate. Namun analisis gap terhadap SDK
menemukan **11 gap signifikan** yang melewatkan informasi register, melewatkan
metadata snapshot yang tersedia, atau skip tahap eksplorasi yang seharusnya
dijalankan.

Gap paling berdampak:

1. **`catch_entry_moves_maps` tidak didecode** — metadata register/stack
   liveness di exception handler entry, tersedia di AOT snapshot tapi tidak
   dibaca sama sekali.
2. **CodeSourceMap `kChangePosition` (token position) tidak diekstrak** —
   AOTopsy decode inline frame stack tapi bukan source position, padahal
   keduanya ada di payload yang sama.
3. **`runFromExisting` skip type inference** — mode `--from-dir` tidak
   menjalankan type inference, BLR edges tetap unresolved.
4. **Register calling convention tidak ditrack penuh** — `ARGS_DESC_REG`,
   `CODE_REG` tidak dipropagasi; arg-reg mask hanya di-build untuk decompiler,
   bukan untuk type tracker.
5. **x86_64 disasm stage serial** — tidak memakai parallel chunk pattern
   seperti ARM64, lambat pada binary besar.

## Struktur Folder

```
internal/analysis/
├── pipeline.go              # Run(): orchestrator utama (11 langkah)
├── snapshot_loader.go       # LoadSnapshot(): ELF→snapshot→cluster→pool
├── context.go               # AnalysisContext + DecompileEnrichment (lazy maps)
├── disasm_stage.go          # RunDisasmStage(): per-function ARM64 disasm
├── disasm_stagex86.go       # RunDisasmStageX86(): x86_64 counterpart
├── typetrack_stage.go       # RunTypeInferenceStage(): BLR resolution
├── signal_stage.go          # RunSignalStage(): behavioral classification
├── meta_stage.go            # RunMetaStage(): flutter_meta.json
├── decompile.go             # BuildDecompileNativeDeps()
├── decompile_from_main.go   # RunFromMain(): BFS from main()
├── decompile_loop.go        # RunDecompileLoop(): --all mode
├── decompile_output.go      # stats aggregation + Frida finalize
├── dispatchtable.go         # ResolveDispatchTable()
├── xref.go                  # writeXrefJSONL(): cross-ref outputs
├── x86refs.go               # x86 dump/callers/hash-scan/pool-refs
├── refinfo.go               # ref chain / class / field inspection
├── class_layouts.go         # BuildClassLayouts()
├── captured_records.go      # scripts/instances/contexts/typeargs/exc-handlers
├── ffi_bridges.go           # BuildFfiBridges()
├── platform_channels.go     # BuildPlatformChannels()
├── deobfuscate.go           # BuildDeobfuscationMap()
├── libraryxref.go           # BuildLibraryFunctions()
├── threadfields.go          # ThreadFieldOffsets() adapter
├── thraudit.go              # RunTHRAudit()
├── artifacts.go             # CopyGhidra/IDAArtifacts()
├── ghidra.go                # FindGhidra()
├── ida.go                   # FindPython()/FindIDAScript()
├── frida_export.go          # BuildFridaMetadata()
├── r2_fingerprint_export.go # writeR2Export() + writeFunctionFingerprints()
├── reflutter.go             # RunReFlutterImport()
├── findlibapp.go            # FindLibappInZip()
├── inventory.go             # InventoryScanLibapp()
├── parity.go                # RunParity()
├── symtabdiff.go            # CompareNamesToSymbols()
├── graph.go                 # RunGraph(): named-object graph
├── firbuild_helpers.go      # BuildFieldTypeByClassOffset() + ResolveArgRegIndices()
└── testdata/golden/         # SHA-256 golden records (4 files)
```

## Gap Analysis

### Gap 1: `catch_entry_moves_maps` tidak didecode

- **Deskripsi**: Di AOT, field `Code.catch_entry` berisi `TypedDataPtr
  catch_entry_moves_maps` (bukan `SmiPtr num_variables` seperti JIT).
  CatchEntryMoves adalah urutan move (register→stack, stack→register,
  stack→stack) yang runtime jalankan saat memasuki catch entry untuk
  merekonstruksi state yang catch entry harapkan. Setiap entry dipetakan ke
  PC offset via PcDescriptors kind=kOther. AOTopsy sudah decode
  `CompressedStackMaps` (safepoint liveness) dan `PcDescriptors` (try/catch
  regions), tapi `catch_entry_moves_maps` tidak dibaca sama sekali — tidak
  ada field `CatchEntryMovesRef` di `cluster.CodeEntry`, tidak ada decode
  di `cluster` package, tidak ada di `DecompileEnrichment`.
- **Bukti SDK**: `runtime/vm/raw_object.h` @3.9.2:
  ```cpp
  // If FLAG_precompiled_mode, then this field contains
  //   TypedDataPtr catch_entry_moves_maps
  // Otherwise, it is
  //   SmiPtr num_variables
  POINTER_FIELD(ObjectPtr, catch_entry)
  ```
  `runtime/docs/compiler/exceptions.md`: "AOT compiler does not associate
  any deoptimization metadata... converted into CatchEntryMoves metadata
  during code generation and stored in RawCode::catch_entry_moves_maps_ in
  a compressed form."
  `runtime/vm/compiler/assembler/disassembler.cc` @3.9.2:
  ```cpp
  #if defined(DART_PRECOMPILED_RUNTIME) || defined(DART_PRECOMPILER)
  if (FLAG_precompiled_mode && code.catch_entry_moves_maps() != Object::null()) {
    CatchEntryMovesMapReader reader(TypedData::Handle(code.catch_entry_moves_maps()));
    reader.PrintEntries();
  }
  ```
- **Dampak**: Analyst tidak tahu register mana yang hold nilai Dart object
  vs. nilai intermediate saat exception handler dimasuki. Untuk fungsi
  dengan try/catch, ini adalah satu-satunya sumber truth untuk variable
  liveness di handler entry — tanpa ini, pseudocode handler adalah tebakan.
- **Usulan**: Tambahkan `CatchEntryMovesRef` ke `cluster.CodeEntry`, decode
  payload di `cluster.ReadFill` (format: SLEB128-encoded move list per
  PC offset, keyed by PcDescriptors entry), dan expose via
  `DecompileEnrichment.CatchEntryMovesByCode` untuk `wireTryCatch` di
  `context.go`. Emitter bisa menambahkan `// catch entry: x0←[fp+16],
  x1←[fp+24]` annotation di handler block.
- **Prioritas**: Tinggi — ini adalah metadata AOT-spesifik yang tidak
  tersedia di JIT, sehingga blutter dan tool lain juga melewatkannya.

### Gap 2: CodeSourceMap `kChangePosition` (token position) tidak diekstrak

- **Deskripsi**: AOTopsy sudah decode CodeSourceMap untuk inline frame
  stack (`InlineStackAt` di `cluster.CodeSourceMapInfo`), digunakan oleh
  `wireInlineFrames` di `context.go`. Tapi `kChangePosition` opcode —
  yang membawa token position (source line/column offset dalam Script) —
  tidak diekstrak. `InlineStackAt` mengembalikan frames dan `pcOffset`
  tapi membuang token position. Padahal opcode `kChangePosition` ada di
  setiap entry dan membawa arg1 (token position delta).
- **Bukti SDK**: `runtime/vm/code_descriptors.h` @3.9.2:
  ```cpp
  struct CodeSourceMapOps : AllStatic {
    static constexpr uint8_t kChangePosition = 0;
    static constexpr uint8_t kAdvancePC = 1;
    static constexpr uint8_t kPushFunction = 2;
    static constexpr uint8_t kPopFunction = 3;
    static constexpr uint8_t kNullCheck = 4;
  };
  ```
  `runtime/vm/dwarf.cc` @3.9.2 menggunakan kChangePosition untuk
  membangun DWARF line table:
  ```cpp
  case CodeSourceMapOps::kChangePosition: {
    DebugInfoPosition& pos = token_positions[token_positions.length() - 1];
    pos.ChangePosition(arg1, arg2);
    break;
  }
  ```
- **Dampak**: Analyst tahu fungsi mana yang inlined di suatu PC, tapi
  tidak tahu baris/kolom source mana yang sesuai. Untuk RE, ini adalah
  jembatan dari asm → source: token position + Script.URL + Script
  line_offset = "file:line" untuk setiap instruction. Tanpa ini, inline
  frame annotation hanya memberi nama fungsi, bukan lokasi source.
- **Usulan**: Modifikasi `cluster.CodeSourceMapInfo.InlineStackAt` untuk
  juga mengembalikan token position (atau tambahkan method
  `SourcePositionAt(pcOffset) (tokenPos int32, ok bool)`). Gabungkan
  dengan `Script.URL` + `Script.LineOffset` di `DecompileEnrichment`
  untuk menghasilkan `fir.SourceLocations map[uint64]SourceLoc`. Emitter
  tambahkan `// at: file.dart:42` comment di setiap block.
- **Prioritas**: Sedang — inline frame names sudah memberi banyak nilai;
  token position adalah enhancement, bukan blocker.

### Gap 3: `runFromExisting` skip type inference

- **Deskripsi**: `pipeline.go:484` `runFromExisting` (mode `--from-dir`)
  hanya menjalankan signal stage dan meta stage. Type inference stage
  (`RunTypeInferenceStage`) tidak dipanggil, sehingga BLR edges di
  `call_edges.jsonl` tetap unresolved. Padahal `runFromExisting` sudah
  memvalidasi bahwa `functions.jsonl` dan `call_edges.jsonl` ada —
  semua input yang type inference butuhkan sudah tersedia.
- **Bukti SDK**: Tidak ada SDK equivalent — ini adalah gap orkestrasi
  internal AOTopsy. Type inference adalah tahap AOTopsy-specific yang
  resolve dispatch-table BLR via receiver class inference.
- **Dampak**: User yang menjalankan `aotopsy signal --from-dir <dir>`
  mendapat signal graph dengan BLR edges unresolved, padahal data untuk
  resolve mereka sudah ada di dir yang sama (dispatch_table.jsonl,
  functions.jsonl, call_edges.jsonl). Signal classification menjadi
  lebih lemah karena banyak edge "unresolved" yang sebenarnya bisa
  di-resolve.
- **Usulan**: Tambahkan opsi `opts.TypeInference bool` dan jalankan
  `RunTypeInferenceStage` di `runFromExisting` ketika
  `dispatch_table.jsonl` ada. Atau lebih sederhana: selalu jalankan
  type inference di `runFromExisting` jika `dispatch_table.jsonl` ada,
  karena tahapnya non-fatal.
- **Prioritas**: Sedang — hanya mempengaruhi mode `--from-dir`, tapi
  mode itu adalah workflow utama untuk re-analisis tanpa re-disasm.

### Gap 4: Register calling convention tidak ditrack penuh

- **Deskripsi**: Dart AOT memakai calling convention khusus (bukan ABI
  standar). ARM64: receiver di R0/X0, argumen di R1,R2,R3,R5,R6,R7
  (R4/X4 dilewati), ARGS_DESC_REG di R25/X25, CODE_REG di R26/X26,
  DISPATCH_TABLE_REG di R21/X21. x86_64: receiver di RDX, argumen di
  RDI,RSI,RDX,RBX,R8,R9, ARGS_DESC_REG di R10, DISPATCH_TABLE_REG di
  RAX. AOTopsy's type tracker hanya track receiver (R0/X0 atau stack
  slot pre-3.4.3) dan DISPATCH_TABLE_REG untuk dispatch table loads.
  `ARGS_DESC_REG` dan `CODE_REG` tidak ditrack, padahal:
  - `ARGS_DESC_REG` hold arguments descriptor Array yang berisi
    num_arguments, num_named, size — ini adalah cara untuk recover
    real arity tanpa arg-reg mask aggregation.
  - `CODE_REG` hold current Code object — ini bisa resolve
    `CODE_REG.field` loads yang akses Code's exception_handlers,
    pc_descriptors, dll.
- **Bukti SDK**: `runtime/vm/constants_arm64.h` @3.9.2:
  ```cpp
  struct DartCallingConvention {
    static constexpr Register kCpuRegistersForArgs[] = {R1, R2, R3, R5, R6, R7};
  };
  ```
  `runtime/vm/constants_x64.h` @3.9.2:
  ```cpp
  struct DartCallingConvention {
    static constexpr Register kCpuRegistersForArgs[] = {RDI, RSI, RDX, RBX, R8, R9};
  };
  ```
  ARGS_DESC_REG, CODE_REG, DISPATCH_TABLE_REG didefinisikan di
  `constants_arm64.h` / `constants_x64.h` (verified via grep MCP).
- **Dampak**: Untuk fungsi yang call via dispatch table, type tracker
  tidak tahu arity call site (hanya tahu receiver class). Arg-reg mask
  aggregation (`BuildArgRegMasks`) recover arity tapi hanya untuk
  direct BL/CALL, bukan dispatch-table BLR. ARGS_DESC_REG tracking
  akan memberikan arity untuk dispatch-table calls juga.
- **Usulan**: Tambahkan `ARGS_DESC_REG` dan `CODE_REG` ke
  `typetrack.LiftState` register tracking. Saat `LDR X25, [PP+idx]`
  terdeteksi, resolve pool entry ke ArgumentsDescriptor Array dan
  ekstrak `num_arguments`. Propagasi ini ke call site untuk arity
  recovery. Untuk `CODE_REG`, track loads dari PP yang resolve ke
  Code object, dan gunakan untuk `CODE_REG.field` resolution.
- **Prioritas**: Sedang — arg-reg mask sudah memberi arity untuk
  direct calls; gap ini utamanya untuk dispatch-table calls.

### Gap 5: x86_64 disasm stage serial (no parallel chunks)

- **Deskripsi**: `RunDisasmStage` (ARM64) memakai parallel chunk
  pattern: `workers = min(NumCPU, 4)`, `chunkSize = workers * 8`,
  compute in parallel, drain in order. `RunDisasmStageX86` (x86_64)
  memakai loop serial sederhana `for i := 0; i < n; i++`. Pada binary
  besar (129k fungsi), ini perbedaan 4× atau lebih.
- **Bukti SDK**: Tidak ada — ini adalah gap performa internal.
- **Dampak**: x86_64 pipeline 4× lebih lambat dari ARM64 pada binary
  dengan jumlah fungsi setara. Untuk production app (Gopay, dll), ini
  bisa berarti perbedaan menit vs. detik.
- **Usulan**: Refactor `RunDisasmStageX86` ke pattern yang sama:
  `funcOutput` struct, `compute` closure, parallel chunk dengan
  `sync.WaitGroup`, drain in order. Peephole state per-worker. Pattern
  sudah terbukti di ARM64 stage — copy verbatim.
- **Prioritas**: Sedang — bukan gap korektnes, tapi gap performa yang
  mempengaruhi UX pada binary besar.

### Gap 6: Re-disassembly duplikat di 4 tahap pipeline

- **Deskripsi**: Fungsi yang sama di-disassemble ulang di 4 tahap:
  1. `RunDisasmStage` / `RunDisasmStageX86` (disasm stage)
  2. `runTypeInference` (type inference stage, re-disasm semua fungsi)
  3. `BuildSignalContent` (signal stage, re-disasm signal funcs dari
     .bin files)
  4. `BuildArgRegMasks` (re-disasm semua fungsi untuk arg-reg mask)
  
  `disasm.Disassemble` dipanggil 3× untuk setiap fungsi (1+2+4),
  `disasm.DecodeX86Simple` atau `ScanX86FunctionCFG` juga 3×.
- **Bukti SDK**: Tidak ada — ini adalah gap efisiensi internal.
- **Dampak**: Pipeline menghabiskan 3× waktu disasm. Pada binary
  dengan 10k fungsi, ini ~30 detik vs. ~10 detik. Memori juga 3×
  karena `funcInstsARM64` / `funcInstsX86` di type inference stage
  menyimpan semua instruksi di memory.
- **Usulan**: Cache hasil disasm di `SnapshotContext` atau
  `AnalysisContext`. Tahap 1 (disasm stage) sudah menulis .bin files;
  tahap 2 dan 4 bisa baca dari .bin files (sudah ada untuk signal
  stage). Atau lebih baik: satukan tahap 1, 2, 4 jadi satu pass —
  type inference dan arg-reg mask collection bisa dijalankan inline
  di disasm stage's `compute` closure.
- **Prioritas**: Sedang — 3× overhead tidak buruk untuk binary
  kecil, tapi signifikan untuk production app.

### Gap 7: Token position / Script source location tidak direcovery

- **Deskripsi**: AOTopsy sudah capture `Script.URL`, `Script.LineOffset`,
  `Script.ColOffset` di `captured_records.go` (`BuildScripts`). Dan
  `CodeSourceMap` sudah di-decode untuk inline frames. Tapi tidak ada
  tahap yang menggabungkan keduanya untuk menghasilkan source location
  per PC: `(Script.URL, token_pos + Script.LineOffset)` = "file:line".
  `Script` objects sudah ada di `result.Scripts` dengan `URLRef` yang
  resolve ke string pool.
- **Bukti SDK**: `runtime/vm/dwarf.cc` @3.9.2 melakukan ini untuk
  DWARF generation:
  ```cpp
  Function& root_function = Function::Handle(zone, code.function());
  Script& script = Script::Handle(function.script());
  String& url = String::Handle(script.url());
  ```
  Token position di CodeSourceMap adalah offset ke Script's source.
- **Dampak**: Analyst tidak bisa navigasi dari asm/PC ke source file
  dan line number. Untuk RE, ini adalah fitur paling berharga: "PC
  0x12345 corresponds to main.dart:42" langsung memberi konteks
  semantic.
- **Usulan**: Tambahkan `SourceLocationResolver` yang map
  (Code.RefID, PC offset) → (Script.URL, line, col). Build dari
  CodeSourceMap token positions (Gap 2) + Script metadata. Output
  sebagai `source_locations.jsonl` di pipeline. Tambahkan ke
  `flutter_meta.json` untuk Ghidra/IDA import.
- **Prioritas**: Tinggi — ini adalah fitur RE yang paling langsung
  memberi nilai ("di baris mana kode ini berasal").

### Gap 8: Cross-loading-unit reference tracking incomplete

- **Deskripsi**: `PartitionCodesByLoadingUnit` di
  `captured_records.go` sudah mempartisi Code menjadi root-unit dan
  deferred buckets. Tapi tidak ada tracking referensi cross-unit:
  fungsi di root unit yang call fungsi di deferred unit (via
  `BLR` ke PP-loaded Code object yang `ClusterIndex == -1`).
  `LoadingUnitRecord` hanya melaporkan count, bukan cross-ref.
- **Bukti SDK**: `runtime/vm/app_snapshot.cc` @3.9.2:
  `ReadInstructions` early-returns untuk deferred codes
  (`ClusterIndex == -1`), sehingga instructions mereka tidak ada
  di snapshot ini. Tapi Code OBJECT-nya ada (sebagai ref), dan
  PP entries yang point ke mereka bisa di-resolve namanya.
  `LoadingUnit` cluster ada di AOT dengan `parent_` dan `base_objects_`.
- **Dampak**: Analyst tidak tahu dependency graph antara loading
  units — fungsi root mana yang memanggil fungsi deferred mana.
  Untuk app dengan deferred imports, ini adalah struktur modular
  yang penting.
- **Usulan**: Di `writeCapturedJSONL`, setelah `PartitionCodesByLoadingUnit`,
  scan `call_edges.jsonl` untuk edges yang target-nya adalah
  deferred Code ref. Output `loading_unit_xref.jsonl`:
  `{from_func, to_func, from_unit, to_unit}`. Untuk deferred Code
  yang namanya tidak resolve di snapshot ini, mark sebagai
  "deferred:unit_N" dengan unit ID dari LoadingUnit metadata.
- **Prioritas**: Rendah — hanya relevan untuk app dengan deferred
  imports, dan mayoritas Flutter app tidak memakainya.

### Gap 9: Closure call resolution incomplete

- **Deskripsi**: Dart AOT memanggil closure via
  `call_closure_no_such_method_stub` dan allocate_closure_stub. BLR
  ke register yang hold closure object tidak di-resolve oleh type
  tracker, karena closure object bukan instance dengan ClassID yang
  ada di dispatch table. AOTopsy's `resolveViaPoolDisplay` menangkap
  PP-loaded Code objects, tapi closure yang dipass via arg register
  atau stack tidak ditrack.
- **Bukti SDK**: `runtime/vm/object_store.h` @3.9.2:
  ```cpp
  RW(Code, call_closure_no_such_method_stub)
  ```
  Closure call di AOT: load closure dari field/arg, load
  `closure.function_` field, load `function.code_` field, BLR
  `code.entry_point_`. Ini adalah chain field-loads yang type tracker
  bisa ikuti jika closure object's class diketahui.
- **Dampak**: Closure calls (callback, async completer, event handler)
  tetap unresolved. Untuk Flutter app yang heavy dengan callback
  (Stream, Future.then), ini adalah kategori BLR yang signifikan.
- **Usulan**: Di type tracker, tambahkan pattern: saat BLR target
  register hold hasil `LDR [Xn, #closure_function_offset]` →
  `LDR [Xm, #function_code_offset]` → BLR, resolve via
  `FieldTypeByClassOffset` chain: receiver class → field type →
  field type → Code object → function name. Ini adalah field-load
  chain yang sudah didukung `FieldTypeResolver` di `context.go`.
- **Prioritas**: Sedang — closure calls adalah kategori BLR yang
  besar di Flutter app, tapi resolusinya butuh field-type chain
  yang mungkin tidak selalu available.

### Gap 10: No inter-procedural constant propagation

- **Deskripsi**: Type tracker (`typetrack.RunInterprocedural`)
  melakukan inter-procedural TYPE propagation (receiver class →
  BLR target). Tapi tidak ada inter-procedural CONSTANT propagation:
  jika fungsi A call B dengan argumen = konstanta dari PP, B
  tidak tahu argumen tersebut adalah konstanta. Ini penting untuk:
  - Switch/case pada konstanta string → recover case labels
  - MethodChannel name yang di-pass sebagai arg → recover channel
    name tanpa string-ref scan
  - FFI call dengan konstanta function pointer → resolve native target
- **Bukti SDK**: Tidak ada — ini adalah fitur RE yang tidak ada
  di SDK runtime. SDK tidak perlu constant propagation karena
  compiler sudah inline konstanta.
- **Dampak**: MethodChannel detection (`platform_channels.go`)
  memakai heuristic string matching, bukan dataflow. Switch/case
  recovery (`wireSwitchCases` di `context.go`) hanya recover
  case count, bukan case values. FFI bridge detection
  (`ffi_bridges.go`) hanya baca FfiTrampolineData cluster, bukan
  trace FFI call site.
- **Usulan**: Tambahkan `ConstValue` ke `typetrack.LiftState`.
  Saat `LDR Xn, [PP+idx]` terdeteksi dan PP entry adalah immediate
  atau string, set `LiftState.ConstValue[Xn] = {kind, value}`.
  Propagasi via BL return values dan arg registers di call sites.
  Di inter-procedural pass, seed callee's arg registers dengan
  konstanta dari call site.
- **Prioritas**: Sedang — signifikan untuk RE tapi butuh refactor
  type tracker untuk carry constant values, bukan hanya types.

### Gap 11: No whole-program reachability / dead-code analysis

- **Deskripsi**: Pipeline tidak mengidentifikasi fungsi yang
  unreachable dari main(). `--from-main` mode melakukan BFS dari
  main, tapi itu adalah mode decompile, bukan tahap pipeline.
  Tidak ada output `unreachable_functions.jsonl` yang memberi
  analyst daftar fungsi yang tidak terjangkau dari entry point
  manapun (main, native entry points, FFI callbacks).
- **Bukti SDK**: Tidak ada — ini adalah fitur RE. SDK compiler
  sudah menghapus unreachable code di precompiler
  (`Precompiler::DoCompile`), tapi tidak semua unreachable code
  dihapus (beberapa retained untuk type testing, stubs, dll).
- **Dampak**: Analyst tidak bisa membedakan "fungsi live" vs.
  "fungsi dead code yang tidak dihapus precompiler". Untuk RE
  fokus pada app logic, ini adalah noise yang bisa di-filter.
- **Usulan**: Tambahkan tahap `RunReachabilityStage` setelah
  type inference: BFS dari entry points (main, FFI callbacks,
  native entry points, THR stubs yang call ke Dart). Output
  `reachability.jsonl`: `{func, reachable, depth, entry_point}`.
  Tambahkan `unreachable` flag ke `functions.jsonl`.
- **Prioritas**: Rendah — nice-to-have untuk filtering, bukan
  blocker untuk RE.

## Register Tracking Gaps

| Register | ARM64 | x86_64 | Tracked? | Gap |
|----------|-------|--------|----------|-----|
| R0/X0 (receiver) | THR? | RDX | Ya (type tracker) | Pre-3.4.3: stack slot, post-3.4.3: R0. OK. |
| R1-R3,R5-R7 (args) | Ya | RDI,RSI,RBX,R8,R9 | Tidak | Arg-reg mask hanya untuk direct BL, bukan dispatch BLR |
| R4/X4 (skipped) | - | - | N/A | Tidak dipakai calling convention |
| R25/X25 (ARGS_DESC) | Ya | R10 | Tidak | Arity recovery untuk dispatch calls |
| R26/X26 (CODE_REG) | Ya | ? | Tidak | `CODE_REG.field` loads tidak resolve |
| R21/X21 (DISPATCH_TABLE) | Ya | RAX | Ya (dispatch loads) | OK untuk dispatch table, tapi tidak full dataflow |
| R27/R15 (PP) | Ya | R15 | Ya (pool loads) | OK |
| R28/R14 (THR) | Ya | R14 | Ya (THR annotations) | OK |
| R29/RBP (FP) | Ya | RBP | Tidak | Frame slot recovery untuk pre-3.4.3 receiver |
| SP | Ya | RSP | Tidak | Stack slot tracking untuk spill liveness |

**Ringkasan register gap:**

1. **ARGS_DESC_REG (X25/R10)**: Tidak ditrack. Hold ArgumentsDescriptor
   Array yang berisi num_arguments, num_named, size. Tracking ini akan
   memberikan arity untuk dispatch-table BLR calls (arg-reg mask hanya
   untuk direct BL/CALL).

2. **CODE_REG (X26)**: Tidak ditrack. Hold current Code object.
   `CODE_REG.field` loads (mis. `LDR Xn, [X26, #exception_handlers_offset]`)
   tidak di-resolve, padahal field offset diketahui dari Code layout.

3. **Arg registers (R1-R3,R5,R6,R7 / RDI,RSI,RBX,R8,R9)**: Tidak ditrack
   untuk dispatch-table BLR. Type tracker hanya track receiver (R0/RDX).
   Arg-reg mask aggregation (`BuildArgRegMasks`) hanya collect mask di
   direct BL/CALL sites, bukan dispatch BLR.

4. **FP (R29/RBP)**: Tidak ditrack sebagai frame base. Pre-3.4.3
   receiver recovery (`FuncReceiverStackSlot`) sudah hardcode
   `FP + (1 + N) * 8`, tapi tidak ada general FP-relative slot
   tracking untuk spill liveness atau local variable recovery.

## Fitur RE Missing/Incomplete

| Fitur | Status | Prioritas | Catatan |
|-------|--------|-----------|---------|
| catch_entry_moves decode | Missing | Tinggi | AOT-spesifik, register liveness di handler |
| Source location (token pos + Script) | Missing | Tinggi | PC → file:line mapping |
| ARGS_DESC_REG tracking | Missing | Sedang | Arity untuk dispatch calls |
| CODE_REG.field resolution | Missing | Sedang | Code metadata field loads |
| Constant propagation | Missing | Sedang | Switch labels, channel names, FFI targets |
| Closure call resolution | Incomplete | Sedang | Field-load chain untuk closure.function.code |
| x86_64 parallel disasm | Missing | Sedang | 4× speedup |
| Re-disasm dedup | Missing | Sedang | 3× speedup + memory |
| runFromExisting type inference | Missing | Sedang | --from-dir BLR resolution |
| Cross-loading-unit xref | Incomplete | Rendah | Deferred import dependency graph |
| Reachability / dead-code | Missing | Rendah | Filter unreachable functions |
| Inter-procedural return type | Partial | Sedang | BL return type sudah di-track, tapi tidak untuk dispatch BLR |

## Verifikasi SDK

Semua klaim tentang SDK Dart diverifikasi via:
1. **Grep MCP (`searchGitHub` by Vercel)** dengan `repo: "dart-lang/sdk"`
   dan query literal simbol/pola kode.
2. **`gh api` @ tag 3.9.2** untuk membaca file SDK utuh pada tag versi
   rilis yang ditargetkan.

### Verifikasi kunci:

| Klaim | Sumber SDK | Hasil |
|-------|-----------|-------|
| DartCallingConvention ARM64 = {R1,R2,R3,R5,R6,R7} | `constants_arm64.h` @3.9.2 via grep MCP | Confirmed |
| DartCallingConvention x64 = {RDI,RSI,RDX,RBX,R8,R9} | `constants_x64.h` @3.9.2 via grep MCP | Confirmed |
| kOriginElement ARM64=4096, x64=16 | `dispatch_table.h` @3.9.2 via grep MCP | Confirmed (AOTopsy hardcodes same values in typetrack_stage.go:286-289) |
| catch_entry_moves_maps in AOT | `raw_object.h` @3.9.2 via gh api | Confirmed: `POINTER_FIELD(ObjectPtr, catch_entry)` with AOT comment |
| CodeSourceMap kChangePosition | `code_descriptors.h` @3.9.2 via gh api | Confirmed: opcode 0, carries token position |
| static_calls_target_table NOT_IN_PRECOMPILED | `raw_object.h` @3.9.2 via grep MCP | Confirmed: `NOT_IN_PRECOMPILED(POINTER_FIELD(ArrayPtr, static_calls_target_table))` |
| var_descriptors NOT_IN_PRODUCT | `raw_object.h` @3.9.2 via grep MCP | Confirmed: `NOT_IN_PRODUCT(POINTER_FIELD(LocalVarDescriptorsPtr, var_descriptors))` |
| UnlinkedCall/ICData/MegamorphicCache NOT in AOT | `app_snapshot.cc` @3.9.2 via gh api | Confirmed: `#if !defined(DART_PRECOMPILED_RUNTIME)` guard |
| ObjectStore AOT roots end at slow_tts_stub_ | `object_store.h` @3.9.2 via gh api | Confirmed: `to_snapshot(kFullAOT)` returns `&slow_tts_stub_` |
| Dispatch table serialized separately for AOT | `app_snapshot.cc` @3.9.2 via gh api | Confirmed: `s->WriteDispatchTable(dispatch_table_entries_)` after roots |
| CodeSourceMap in AOT (not dwarf mode) | `app_snapshot.cc` @3.9.2 via grep MCP | Confirmed: `WriteField(code, code_source_map_)` unless dwarf_stack_traces_mode |
| CompressedStackMaps in AOT | `app_snapshot.cc` @3.9.2 via grep MCP | Confirmed: written to RO data, not as heap object |
| PcDescriptors in AOT | `raw_object.h` @3.9.2 via grep MCP | Confirmed: `VISIT_TO(code_source_map)` in PRECOMPILED_RUNTIME (includes pc_descriptors) |
| SingleTargetCallStub is AOT-only | `stub_code_compiler_ia32.cc` via grep MCP | Confirmed: `__ int3(); // AOT only.` on ia32 (not used there), but present on arm64/x64 |
| OBJECT_STORE_FIELD_LIST has 9 categories | `object_store.h` @3.9.2 via grep MCP | Confirmed: R_, RW, ARW_RELAXED, ARW_AR, LAZY_CORE, LAZY_ASYNC, LAZY_ISOLATE, LAZY_INTERNAL, LAZY_FFI |

### Catatan tentang field yang TIDAK ada di AOT snapshot:

- `static_calls_target_table` — NOT_IN_PRECOMPILED. Direct call targets
  hanya ada di instruction stream (BL/CALL rel32). AOTopsy dengan benar
  resolve dari instruction stream, bukan dari table ini.
- `var_descriptors` — NOT_IN_PRODUCT. Local variable names tidak ada
  di release build. Tidak bisa direcovery dari snapshot.
- `deopt_info_array` — NOT_IN_PRECOMPILED. Tidak ada deopt di AOT.
- `active_instructions` — NOT_IN_PRECOMPILED. Hanya ada
  `instructions_` (the actual code bytes).
- `UnlinkedCall`, `ICData`, `MegamorphicCache`, `SingleTargetCache`,
  `MonomorphicSmiableCall` — semua JIT-only, tidak ada di AOT snapshot.
  Precompiler mengkonversi semua calls ke direct BL/CALL atau
  dispatch-table lookup.
- `obfuscation_map` — ada di ObjectStore field list tapi SETELAH
  `to_snapshot(kFullAOT)` boundary, jadi TIDAK diserialisasi di AOT
  roots. Hanya ada jika obfuscation diaktifkan dan field ditulis
  sebelum snapshot (kasus khusus).
