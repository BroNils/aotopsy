# RE Gap Analysis Report: internal/disasm

> **STATUS VERIFIKASI (2026-09-01)** — Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`. Koreksi:
> - **Gap 1 (LDP dari PP) → CONFIRMED tapi PRIORITAS SALAH ~300×.** Sweep
>   bitmask atas seluruh `.so`: LDP dari PP (langsung + via ADD) muncul
>   **14×** di `dart-3.9.2-arm64.so` dan **123×** di `dart-3.12.2-realapp-arm64.so`,
>   melawan puluhan ribu pool load biasa (~0,2%). Konsisten dengan AOT
>   bare-instructions: instance call ARM64 lewat **dispatch table**, bukan
>   switchable-call LDP. Report `strxref` menilai fenomena yang sama sebagai
>   **P3** — penilaian itu yang benar.
> - **Gap 2, sub-klaim "case 2 (add+ldr) ditrack untuk anotasi TAPI tidak di
>   dataflow" → SALAH.** `touchInstrEffect` menerima daftar `annotators` yang
>   berisi `peep.Annotate` (`disasm_stage.go:226` → `ExtractCallEdgesCFG(...,
>   annotators)`), dan cabang annotator men-`defineReg` semua dst dengan
>   `PP[idx] …`. Form-2 memang sampai ke dataflow. (Case 3 movz+movk+ldr tetap
>   CONFIRMED tidak ditrack.) Ukuran form-2: **5.919** (3.9.2) dan **38.716**
>   (realapp, = 60% dari seluruh pool load) — besar, tapi jalur pipeline
>   utama sudah menanganinya; yang buta adalah IR decompiler + strxref.
> - **Temuan tambahan (tidak ada di report): kontaminasi state peephole
>   antar-pass.** `disasm_stage.go` membuat satu `*PeepholeState` per worker,
>   me-`Reset()` sekali per fungsi, lalu menjalankannya **tiga kali** atas
>   instruksi yang sama tanpa reset di antaranya (`output.WriteASM`, lalu
>   `ExtractCallEdgesCFG` yang memutarnya dua kali: precompute per-blok +
>   pass emisi). `addValid/addDestReg` bertahan lintas pass → sebuah `LDR` di
>   awal pass berikutnya bisa dipasangkan dengan `ADD Xd,PP,#imm` dari akhir
>   pass sebelumnya dan menghasilkan anotasi `PP[idx]` palsu.
> - Gap 6, 7, 9 (NULL_REG/HEAP_BITS tidak di-seed; `LDUR [SP/FP]` dilabeli
>   `object_field`) — **CONFIRMED**.

## Ringkasan

Folder `internal/disasm` berisi decoder instruksi ARM64 + x86_64, anotator
PP/THR, tracker provenance register berbasis CFG-wide dataflow, dan ekstraktor
call-edge. Kode ini sudah memverifikasi sebagian besar fakta SDK ke
`dart-lang/sdk` (register roles, pool index arithmetic, Code entry-point
displacements, THR field tables via `tools/extract_thr.go -check`). Namun
terdapat sejumlah gap signifikan: (1) **LDP (pair load) dari PP sama sekali
tidak dianotasi/ditrack** — padahal SDK `LoadDoubleWordFromPoolIndex`
menggunakan LDP untuk setiap IC/switchable call site di AOT, sehingga
provenance `code_reg` hilang dan BLR through LR tidak resolve; (2) **pool load
via register offset (MOVZ+MOVK+LDR [PP, Xm]) tidak ditrack** — case 3 dari SDK
`DecodeLoadWordFromPool` untuk pool index besar; (3) **tail call (BR/B pada
ARM64, JMP pada x86) tidak pernah diemis sebagai call edge** — call graph
kehilangan semua edge tail-call; (4) **register ABI penting (IC_DATA_REG,
ARGS_DESC_REG, NULL_REG, HEAP_BITS, CODE_REG, SPREG, FPREG) tidak di-seed di
dataflow** — sehingga provenance null/true/false, argument descriptor, ic_data,
dan pointer decompression hilang dari anotasi disasm.

Dampak agregat: call graph kehilangan edge tail-call dan edge dari IC call
sites yang menggunakan LDP; string-ref dan pool-annotation melewatkan seluruh
pool entry yang diakses via LDP atau reg-offset; arg-count reconstruction
hanya mengandalkan backward-scan noisy, bukan ARGS_DESC_REG yang deterministik.

## Struktur Folder

| File | Peran |
|------|------|
| `arm64.go` | Decoder ARM64 entry-point (`Disassemble`, `Format`, `DisasmOne`, `PlaceholderLookup`). Hanya decode linear, tidak ada analisis. |
| `x86.go` | Decoder x86_64: `classifyX86Call` (CALL/CALL indirect/[mem]), `ExtractX86THRAccesses`, `BuildX86AuditRecords`, `DecodeX86Simple`, arg-reg mask inference. |
| `annotate.go` | Annotator ARM64: `PPAnnotator` (LDR [X27,#imm]), `THRAnnotator`/`THRContextAnnotator` (LDR/STR [X26,#imm] dengan klasifikasi konteks), `PeepholeState` (ADD+LDR PP split). |
| `branch.go` | `DecodeBranch`: deteksi RET/BR/B/B.cond/CBZ/CBNZ/TBZ/TBNZ/B.AL/B.NV. |
| `cfg.go` | `BuildCFG`: partisi instruksi ARM64 → basic blocks, successor edges (T/F/unconditional). |
| `calledge.go` | `CallEdge` struct, `inferCallArgRegMaskLocal` (backward-scan arg setup), `IsCodeEntryPointDisp`, `ObjectFieldViaAt`. |
| `dataflowarm64.go` | `ExtractCallEdgesCFG`: reaching-definitions dataflow ARM64 (lattice top/known/bottom, 31 GP regs), `touchInstrEffect` (define/kill per instruksi), emit BL/BLR edges. |
| `dataflowx86.go` | `ScanX86FunctionCFG`: counterpart x86_64 (16 GP regs), `buildX86Blocks`, `touchX86InstrEffect`, `poolStringRefFor`. |
| `poolindex.go` | `ARM64PoolIndex` / `X64PoolIndex`: konversi displacement → pool index (verified ke SDK `ObjectPool::IndexFromOffset`). |
| `thraudit.go` | `ExtractTHRAccesses` ARM64: scan LDR/STR [X26,#imm] → `THRAccess` records, `BuildAuditRecords` dengan context window. |
| `types.go` | Record types JSONL: `FuncRecord`, `CallEdgeRecord`, `UnresolvedTHRRecord`, `StringRefRecord`, `ResolvedTargets` helper. |
| `*_test.go` | Unit + regression tests (8 file). |

## Gap Analysis

### Gap 1: LDP (pair load) dari PP tidak dianotasi/ditrack — IC/switchable call sites kehilangan provenance

- **Deskripsi**: SDK `LoadDoubleWordFromPoolIndex` (assembler_arm64.cc:491)
  memuat pasangan `(ic_data, code)` dari object pool menggunakan **LDP**
  (load pair) dalam 4 varian:
  1. `ldp lower, upper, [PP, #offset]` — single LDP
  2. `add TMP, PP, #imm; ldp lower, upper, [TMP, 0]`
  3. `add TMP, PP, #upper; ldp lower, upper, [TMP, #lower]`
  4. `add TMP, PP, #high; add TMP, TMP, #low; ldp lower, upper, [TMP, 0]`

  AOTopsy memiliki decoder `arm64.LDP64UnsignedOffset` (arch/arm64/decoders.go:409)
  tetapi **tidak pernah memanggilnya** di `internal/disasm`. `PPAnnotator`
  hanya cek `LDR64UnsignedOffset`; `PeepholeState.Annotate` hanya cek
  ADD+LDR (bukan ADD+LDP); `touchInstrEffect` (dataflowarm64.go:245) hanya
  handle `LDRRegExtended` (base==DT) dan `LDUR64` — bukan LDP dari PP.
  `DstRegsOfInst` memang mendeteksi LDP dan mengembalikan `[rt1, rt2]`,
  tetapi karena tidak ada annotator yang fires untuk LDP dari PP, kedua
  register tujuan di-**kill** (provenance kosong), bukan di-define dengan
  pool entry.

  Dampak beruntun: `ICCallPattern` (instructions_arm64.cc:42) memuat
  `(data_reg=R5, code_reg=LR)` via LDP, lalu `ldr LR, [LR, #entry_point];
  blr LR`. Karena LR di-kill (bukan di-define dengan `pp[idx] Code`),
  `IsCodeEntryPointDisp` di `touchInstrEffect` menemukan `regs[base]` kosong
  → fallback ke `ObjectFieldViaAt(off)` → BLR Via kosong → call edge
  unresolved.

- **Bukti SDK**:
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` @3.9.2 baris 491–548
    (`LoadDoubleWordFromPoolIndex`, semua 4 varian menggunakan `ldp`).
  - `runtime/vm/instructions_arm64.cc` @3.9.2 baris 248–320
    (`DecodeLoadDoubleWordFromPool`, assertion `ldr_instr->IsLoadStoreRegPairOp()`).
  - `runtime/vm/instructions_arm64.cc` @3.9.2 baris 36–48 (`ICCallPattern`:
    `DecodeLoadDoubleWordFromPool(pc - 2*Instr::kInstrSize, &data_reg,
    &code_reg, &pool_index); ASSERT(data_reg == R5)`).
  - `runtime/vm/compiler/assembler/object_pool_builder.h` @3.9.2:
    `kResetToSwitchableCallMissEntryPoint` — "Only used in AOT. Every
    switchable call site will put (ic_data, [kTaggedObject] code) into the
    object pool."
  - Verifikasi grep MCP: `searchGitHub` query `"DecodeLoadDoubleWordFromPool"`
    repo `dart-lang/sdk` → konfirmasi path `runtime/vm/instructions_arm64.cc`.

- **Dampak**: Setiap IC/switchable call site di AOT ARM64 yang menggunakan
  LDP tidak resolve di call graph. `Via` kosong, target tidak diberi nama.
  String-ref dan pool-annotation juga melewatkan pool entry yang dimuat via
  LDP (mis. ic_data yang berisi nama selector).

- **Usulan**: Tambahkan `LDPAnnotator(pool)` di `annotate.go` yang memanggil
  `arm64.LDP64UnsignedOffset`, cek `baseReg == sdk.ARM64PP`, konversi
  `byteOffset` via `ARM64PoolIndex`, anotasikan **kedua** register tujuan
  (rt1 = `pp[idx]`, rt2 = `pp[idx+1]`). Di `touchInstrEffect`, tangani LDP
  dari PP sebelum fallback kill: jika `LDP64UnsignedOffset` dan
  `base == sdk.ARM64PP`, define rt1=`pp[idx] display`, rt2=`pp[idx+1]
  display`. Tambahkan juga varian ADD+LDP di `PeepholeState`. Perubahan
  menengah (~60 baris di annotate.go + ~20 baris di dataflowarm64.go +
  decoder `LDP64SignedOffset`/`LDP64PreIndex` jika diperlukan).

- **Prioritas**: **tinggi** — ini adalah pola call site AOT yang umum;
  kehilangan ini berarti call graph tidak lengkap.

### Gap 2: Pool load via register offset (MOVZ+MOVK+LDR [PP, Xm]) tidak ditrack

- **Deskripsi**: SDK `LoadWordFromPoolIndex` (assembler_arm64.cc:439) memiliki
  3 case:
  1. `ldr dst, [PP, #offset]` — ditrack (`PPAnnotator`).
  2. `add dst, PP, #upper20; ldr dst, [dst, #lower12]` — ditrack untuk
     anotasi (`PeepholeState`), **tetapi tidak ditrack di dataflow**
     (`touchInstrEffect` tidak punya logic ADD+LDR split; `add dst, PP, #imm`
     di-kill karena tidak ada annotator yang fires untuk ADD murni).
  3. `movz dst, #low; movk dst, #high; ldr dst, [PP, dst]` — **tidak ditrack
     sama sekali**. `LDRRegExtended` dideteksi di `touchInstrEffect` hanya
     jika `base == regDT` (X21 dispatch table), bukan `base == PP` (X27).

  Pool index besar (> 4096*8 = 32768 byte offset) memerlukan case 2 atau 3
  karena imm12 LDR unsigned offset maksimum 4095*8 = 32760. Pool AOT yang
  besar (aplikasi Flutter production) memiliki puluhan ribu entry.

- **Bukti SDK**:
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` @3.9.2 baris 439–455
    (`LoadWordFromPoolIndex`, case 3: `movz(dst, Immediate(offset_low), 0);
    movk(dst, Immediate(offset_high), 1); ldr(dst, Address(pp, dst))`).
  - `runtime/vm/instructions_arm64.cc` @3.9.2 baris 196–227
    (`DecodeLoadWordFromPool` case 3: `movz dst, low_offset, 0; movk dst,
    high_offset, 1; ldr dst, [pp, dst]`).
  - Verifikasi grep MCP: `searchGitHub` query `"LoadWordFromPoolIndex"` repo
    `dart-lang/sdk` → konfirmasi.

- **Dampak**: Pool entry di index tinggi (string, class, type argument) yang
  dimuat via reg-offset tidak dianotasi di output `.asm`, tidak muncul di
  `string_refs.jsonl`, dan provenance-nya hilang di dataflow → BLR through
  register tersebut unresolved. Untuk app besar, fraksi pool entry dengan
  offset > 32KB bisa signifikan.

- **Usulan**:
  1. Di `touchInstrEffect`, tambahkan: `if base, rm, dstR, ok :=
     arm64.LDRRegExtended(inst.Raw); ok && base == sdk.ARM64PP` →
     reconstruct offset dari MOVZ/MOVK sebelumnya (perlu state register
     tracker untuk immediate values, atau scan backward dalam block).
     Pendekatan lebih sederhana: track MOVZ/MOVK immediate di `noWindowRegs`
     sebagai nilai numerik, lalu saat `LDR [PP, Xm]` hitung offset = nilai
     Xm.
  2. Di `PeepholeState`, tambahkan pola MOVZ+MOVK+LDR [PP, Xd].
  3. Tambahkan `LDRRegExtendedPP` decoder path di `PPAnnotator`.
  Perubahan besar (~100 baris) karena perlu immediate tracking.

- **Prioritas**: **sedang** — hanya affect pool index > ~4096; untuk app
  kecil tidak terlihat, untuk app besar bisa signifikan.

### Gap 3: Tail call (BR/B ARM64, JMP x86) tidak diemis sebagai call edge

- **Deskripsi**: `DecodeBranch` (branch.go) mendeteksi BR (indirect) dan B
  (unconditional). `BuildCFG` (cfg.go:117) menandai BR sebagai `IsTerm`
  (terminal, no successors) dan B ke luar fungsi sebagai `IsTerm`.
  `ExtractCallEdgesCFG` hanya mengemis edge untuk BL dan BLR — **BR dan B
  tidak pernah menjadi CallEdge**. Demikian pula di x86, `buildX86Blocks`
  (dataflowx86.go:220) menandai JMP sebagai terminator; `ScanX86FunctionCFG`
  hanya mengemis edge untuk CALL — **JMP rel32 dan JMP reg tidak pernah
  menjadi CallEdge**.

  SDK menggunakan tail call di AOT:
  - ARM64: `Jump(Register target) { br(target); }` (assembler_arm64.h:491).
  - ARM64: `GenerateUnRelocatedPcRelativeTailCall` — `b #offset` PC-relative
    tail call.
  - x86: `PcRelativeTailCallPattern` (0xe9 = JMP rel32,
    instructions_x64.h:196).
  - x86: `Jump(Register target)` = `jmp target` (indirect tail call).

  Tail call ke fungsi lain adalah edge call graph yang sah (caller → callee),
  tetapi AOTopsy menempatkannya sebagai "terminal block" dan menghilangkan
  edge-nya.

- **Bukti SDK**:
  - `runtime/vm/compiler/assembler/assembler_arm64.h` @3.9.2 baris 491:
    `void Jump(Register target) { br(target); }`.
  - `runtime/vm/compiler/assembler/assembler_arm64.h` @3.9.2 baris 2236:
    `void GenerateUnRelocatedPcRelativeTailCall(...)`.
  - `runtime/vm/instructions_x64.h` @3.9.2 baris 163–209:
    `PcRelativeTrampolineJumpPattern` (0xe9), `PcRelativeTailCallPattern`.
  - Verifikasi grep MCP: `searchGitHub` query `"PcRelativeTailCallPattern"`
    repo `dart-lang/sdk` → konfirmasi.

- **Dampak**: Call graph kehilangan semua tail-call edge. Fungsi yang
  hanya dipanggil via tail call (umum di AOT untuk optimisasi tail-call
  Dart) tidak muncul di reachable set, tidak dapat di-diff, tidak dapat
  di-classify sinyalnya. Untuk RE, ini berarti callee dari tail call tidak
  terlihat sebagai "dipanggil oleh fungsi X".

- **Usulan**:
  1. Di `ExtractCallEdgesCFG`, tambahkan deteksi BR dan B ke luar fungsi
     sebagai edge `Kind: "tail_br"` / `Kind: "tail_b"` dengan `TargetPC` /
     `Reg` / `Via` (provenance BR register).
  2. Di `ScanX86FunctionCFG`, tambahkan deteksi JMP rel32 sebagai
     `Kind: "tail_jmp"` (direct) dan JMP reg sebagai `Kind: "tail_jmp_ind"`
     (indirect dengan Via dari tracker).
  3. Di `types.go`, perluas `CallEdgeRecord.Kind` dengan nilai tail-call.
  4. Konsumen (render, callgraph, signal) harus mengikuti edge tail-call
     sama seperti BL/BLR.
  Perubahan menengah-besar (~80 baris disasm + ripple ke konsumen).

- **Prioritas**: **tinggi** — tail call adalah pola AOT yang umum;
  kehilangan edge ini membuat call graph tidak lengkap dan reachable set
  underestimate.

### Gap 4: IC_DATA_REG (R5 ARM64 / RBX x86) tidak ditrack

- **Deskripsi**: SDK `ICCallPattern` (instructions_arm64.cc:42) memuat
  `ic_data` ke R5 (ARM64) / RBX (x86) via pool load. `IC_DATA_REG` berisi
  ICData atau MegamorphicCache yang menyimpan nama selector dan type
  feedback. AOTopsy tidak men-track R5/RBX sebagai register khusus —
  disembunyikan di antara 31/16 GP regs generik.

  Dampak: di IC call site, `R5` di-kill (bukan di-define dengan `pp[idx]
  ICData`), sehingga:
  - Nama selector tidak terlihat di anotasi disasm.
  - `signal` tidak dapat mengklasifikasi call site sebagai IC call.
  - `typetrack` tidak dapat seed receiver type dari ICData.

- **Bukti SDK**:
  - `runtime/vm/constants_arm64.h` @3.9.2 baris 151:
    `const Register IC_DATA_REG = R5;`.
  - `runtime/vm/constants_x64.h` @3.9.2 baris 126:
    `const Register IC_DATA_REG = RBX;`.
  - `runtime/vm/instructions_arm64.cc` @3.9.2 baris 44:
    `ASSERT(data_reg == R5);` di ICCallPattern.
  - Verifikasi grep MCP: `searchGitHub` query `"IC_DATA_REG"` repo
    `dart-lang/sdk` → konfirmasi penggunaan di stub_code_compiler_*.cc.

- **Dampak**: IC call site tidak diidentifikasi sebagai IC; nama selector
  dan receiver-type info dari ICData hilang dari output RE.

- **Usulan**: Tambahkan `sdk.ARM64ICDataReg = 5` dan `sdk.X86ICDataReg = 3`
  (RBX canonical) di `sdk/registers.go`. Di `touchInstrEffect`, saat LDP
  dari PP (Gap 1) mendefinisikan R5, anotasikan sebagai `pp[idx] ICData`
  bukan generik. Konsumen dapat mengenali token `ICData` di Via untuk
  klasifikasi. Perubahan kecil setelah Gap 1 diselesaikan (~10 baris).

- **Prioritas**: **sedang** — bergantung pada Gap 1 (LDP tracking) untuk
  efek penuh; tanpa Gap 1, R5 di-kill regardless.

### Gap 5: ARGS_DESC_REG (R4 ARM64 / R10 x86) tidak ditrack — arg-count deterministik hilang

- **Deskripsi**: SDK memuat arguments descriptor ke `ARGS_DESC_REG` sebelum
  call dan stub. Descriptor ini berisi `size` (arg count) dan
  `type_args_len`. AOTopsy hanya menginfer arg count dari backward-scan
  register arg yang di-touch (`inferCallArgRegMaskLocal`) — ini noisy
  (register allocator noise, value preserved across calls).

  `ARGS_DESC_REG` di-set via `ldr R4, [IC_DATA_REG,
  CallSiteData::arguments_descriptor_offset()]` (stub_code_compiler_arm64.cc)
  atau via pool load. Tidak ditrack → arg-count deterministik dari descriptor
  hilang.

- **Bukti SDK**:
  - `runtime/vm/constants_arm64.h` @3.9.2 baris 152:
    `const Register ARGS_DESC_REG = R4;`.
  - `runtime/vm/constants_x64.h` @3.9.2 baris 127:
    `const Register ARGS_DESC_REG = R10;`.
  - `runtime/vm/compiler/stub_code_compiler_arm64.cc` @3.9.2:
    `__ ldr(ARGS_DESC_REG, FieldAddress(IC_DATA_REG,
    target::CallSiteData::arguments_descriptor_offset()));`.
  - Verifikasi grep MCP: `searchGitHub` query `"ARGS_DESC_REG"` repo
    `dart-lang/sdk` → konfirmasi.

- **Dampak**: `ArgCountHint` di `CallEdge` hanya dari backward-scan noisy.
  RE yang ingin tahu "fungsi ini butuh berapa arg" harus aggregate banyak
  call site dan tetap tidak deterministik. Descriptor yang ada di binary
  tidak dimanfaatkan.

- **Usulan**: Tambahkan `sdk.ARM64ArgsDescReg = 4` (sudah ada sebagai
  `ARM64ArgsDesc = 4` di registers.go tetapi tidak digunakan di disasm).
  Di `touchInstrEffect`, track R4 sebagai `argsDesc` saat dimuat dari
  ICData field atau pool. Konsumen dapat membaca `ArgumentsDescriptor` dari
  snapshot cluster untuk ekstrak arg count. Perubahan menengah (~30 barang
  disasm + integrasi cluster).

- **Prioritas**: **sedang** — arg-count reconstruction saat ini noisy;
  descriptor memberikan ground truth.

### Gap 6: NULL_REG (R22 ARM64) tidak di-seed di dataflow — null/true/false materialization tidak dikenali di disasm

- **Deskripsi**: SDK `NULL_REG = R22` (ARM64) caches `Object::null()`.
  `mov dst, NULL_REG` materialisasi null; `AddImmediate(dst, NULL_REG, 32)`
  → true; `AddImmediate(dst, NULL_REG, 48)` → false (sdk/predicates.go
  `BoolFromNullOffset`). SDK juga: `if (IsSameObject(compiler::NullObject(),
  object)) { mov(dst, NULL_REG); return; }` (assembler_arm64.cc:642).

  AOTopsy memiliki `sdk.ARM64NullReg = 22` dan `BoolFromNullOffset` tetapi
  **disasm dataflow tidak me-seed R22**. `entryState` block 0 diinisialisasi
  semua `lvBottom`. R22 tidak pernah di-define (tidak ada instr yang
  menulis R22 di AOT — itu register khusus yang di-set saat thread init).
  Akibatnya `mov dst, R22` → `DstRegsOfInst` mendeteksi dst, tetapi tidak
  ada annotator yang fires → dst di-kill. Lalu `add dst, R22, #32` → dst
  di-kill lagi. Null/true/false tidak terlihat di anotasi disasm.

  Catatan: `typetrack` dan `decompiler` mungkin menangani ini secara
  terpisah, tetapi `disasm` sebagai lapisan anotasi tidak.

- **Bukti SDK**:
  - `runtime/vm/constants_arm64.h` @3.9.2 baris 157:
    `const Register NULL_REG = R22; // Caches NullObject() value.`
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` @3.9.2 baris 642–648:
    `mov(dst, NULL_REG); ... AddImmediate(dst, NULL_REG,
    kTrueOffsetFromNull); ... AddImmediate(dst, NULL_REG,
    kFalseOffsetFromNull);`.
  - Verifikasi grep MCP: `searchGitHub` query `"NULL_REG"` repo
    `dart-lang/sdk` → konfirmasi `DART_ASSEMBLER_HAS_NULL_REG` di ARM64 &
    RISC-V (x86 tidak punya NULL_REG, load dari Thread.object_null).

- **Dampak**: Anotasi `.asm` tidak menampilkan `null`/`true`/`false` untuk
  `mov dst, R22` / `add dst, R22, #32` / `add dst, R22, #48`. RE harus
  tahu manual bahwa R22 = null.

- **Usulan**: Di `ExtractCallEdgesCFG`, seed `entryState[0][sdk.ARM64NullReg]
  = lvalue{kind: lvKnown, note: "null"}`. Tambahkan annotator yang cek
  `mov dst, R22` → `defineReg(dst, "null")` dan `add dst, R22, #32/#48` →
  `defineReg(dst, "true"/"false")` via `BoolFromNullOffset`. Perubahan
  kecil (~25 baris). Untuk x86, seed dari `THR.object_null` pool entry.

- **Prioritas**: **sedang** — meningkatkan readability output signifikan;
  null/true/false adalah literal paling umum.

### Gap 7: HEAP_BITS (R28 ARM64) tidak dikenali di dataflow — pointer decompression kehilangan provenance

- **Deskripsi**: SDK `HEAP_BITS = R28` holds
  `write_barrier_mask << 32 | heap_base >> 32`. Pada compressed-pointer
  builds, `add dst, src, X28, LSL #32` adalah pointer decompression
  (sdk/predicates.go `IsARM64PointerDecompression`). SDK:
  `add(dst, src, Operand(HEAP_BITS, LSL, 32))` (assembler_arm64.cc).

  AOTopsy memiliki `sdk.ARM64HeapBits = 28` dan `IsARM64PointerDecompression`
  tetapi `touchInstrEffect` (dataflowarm64.go:245) **tidak mengenali pola
  ini**. `ADD64Register` mendeteksi `add dst, src, rm` tetapi `touchInstrEffect`
  tidak memanggilnya — hanya `DstRegsOfInst` yang fires, lalu dst di-kill
  karena tidak ada annotator. Akibatnya objek yang baru di-decompress
  kehilangan provenance class-nya.

  Seharusnya: `add dst, src, X28, LSL #32` → `defineReg(dst, regs[src])`
  (identitas — class tidak berubah, hanya representasi pointer).

- **Bukti SDK**:
  - `runtime/vm/constants_arm64.h` @3.9.2 baris 156:
    `const Register HEAP_BITS = R28; // write_barrier_mask << 32 | heap_base
    >> 32`.
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` @3.9.2: under
    `DART_COMPRESSED_POINTERS`: `add(dst, src, Operand(HEAP_BITS, LSL,
    32))`.
  - Verifikasi: `sdk/predicates.go` baris 160–170 sudah ada
    `IsARM64PointerDecompression` — tetapi tidak dipanggil di disasm.

- **Dampak**: Setelah decompression, objek kehilangan type provenance di
  dataflow → field access berikutnya tidak resolve, BLR through register
  tersebut tidak dapat Via. Pada compressed-pointer builds (Dart 2.18+,
  semua 3.x modern), ini adalah pola umum.

- **Usulan**: Di `touchInstrEffect`, tambahkan deteksi `ADD64Register` +
  shift LSL #32 dengan `rm == sdk.ARM64HeapBits` → `defineReg(dst,
  regs[src])` (identitas). Perlu decoder `ADD64RegisterShifted` di
  arch/arm64 (saat ini `ADD64Register` tidak mengembalikan shift). Perubahan
  menengah (~30 barang disasm + ~15 baris decoder).

- **Prioritas**: **sedang** — compressed pointer adalah default di Dart 3.x;
  kehilangan provenance di setiap decompression site berakumulasi.

### Gap 8: CODE_REG (R24 ARM64 / R12 x86) tidak di-seed — stub call via CODE_REG hilang

- **Deskripsi**: Di AOT precompiled mode, `BranchLink` menggunakan LR
  (bukan CODE_REG) untuk code object, tetapi stubs tertentu masih
  menggunakan CODE_REG: `__ ldr(CODE_REG, Address(THR,
  target::Thread::switchable_call_miss_stub_offset()));` (stub_code_compiler).
  `CODE_REG = R24` (ARM64) / `R12` (x86).

  AOTopsy tidak men-seed CODE_REG di dataflow entry. Saat stub memuat
  `CODE_REG` dari THR field, `THRAnnotator` fires → define R24 dengan
  `THR.field_name`. Lalu `ldr LR, [R24, #entry]; blr LR` →
  `IsCodeEntryPointDisp` → inherit R24 provenance. Ini **sebenarnya
  bekerja** untuk stub via THR. Tetapi untuk stub via pool (`LoadObject(CODE_REG,
  stub)` di JIT), AOT tidak menggunakan ini. Jadi gap ini minor untuk AOT.

  Namun, `CODE_REG` juga digunakan sebagai base untuk field access di
  beberapa stub (mis. `FieldAddress(CODE_REG, ...)`), dan tidak men-seed
  provenance-nya berarti akses tersebut menjadi `object_field` generik.

- **Bukti SDK**:
  - `runtime/vm/constants_arm64.h` @3.9.2 baris 146:
    `const Register CODE_REG = R24;`.
  - `runtime/vm/constants_x64.h` @3.9.2 baris 128:
    `const Register CODE_REG = R12;`.
  - `runtime/vm/compiler/stub_code_compiler_arm64.cc` @3.9.2 baris 3742+:
    `__ ldr(CODE_REG, Address(THR,
    target::Thread::switchable_call_miss_stub_offset()));`.

- **Dampak**: Minor untuk AOT — sebagian besar call via LR. Field access
  dari CODE_REG di stub menjadi generik.

- **Usulan**: Tidak perlu seed khusus (CODE_REG di-set per-instruksi, bukan
  konstanta). Pastikan `touchInstrEffect` menangani `ldr LR, [CODE_REG,
  #entry]` → `IsCodeEntryPointDisp` → inherit. Sudah bekerja jika
  `THRAnnotator` fires untuk load CODE_REG dari THR. Prioritas rendah.

- **Prioritas**: **rendah** — sebagian besar sudah bekerja via annotator.

### Gap 9: SPREG/FPREG tidak dianotasikan sebagai stack slot — stack provenance hilang

- **Deskripsi**: SDK `SPREG = R15` (ARM64) / `RSP` (x86), `FPREG = R29` /
  `RBP`. Akses `[SP, #off]` dan `[FP, #off]` adalah stack slot, bukan field
  objek. AOTopsy memiliki `sdk.StackSlotName(off)` (predicates.go:102) tetapi
  `disasm` tidak memanggilnya. `touchInstrEffect` menangani `LDUR64` →
  `ObjectFieldViaAt(off)` untuk base non-PP/THR — termasuk SP/FP — sehingga
  stack slot diberi label `object_field+0xN` yang **menyesatkan** (bukan
  field objek, melainkan slot stack).

  `ExtractTHRAccesses` hanya cek base==THR. Tidak ada `StackAccessAnnotator`.

- **Bukti SDK**:
  - `runtime/vm/constants_arm64.h` @3.9.2 baris 149–150:
    `const Register FPREG = FP; const Register SPREG = R15;`.
  - `runtime/vm/constants_x64.h` @3.9.2 baris 124–125:
    `const Register SPREG = RSP; const Register FPREG = RBP;`.
  - `runtime/vm/compiler/stub_code_compiler_arm64.cc` @3.9.2: akses
    `Address(SP, ...)` / `Address(FP, ...)` umum di prologue/epilogue.
  - `sdk/predicates.go` baris 93–143: `StackSlotName` sudah ada tetapi
    tidak digunakan di disasm.

- **Dampak**: Anotasi `.asm` menampilkan `object_field+0x10` untuk stack
  slot, bukan `stack_p16`. RE salah mengira stack slot sebagai field objek.
  Provenance stack slot (local variable, spilled register) hilang.

- **Usulan**: Tambahkan `StackAnnotator` yang cek `LDUR64`/`LDR64UnsignedOffset`/
  `STUR64`/`STR64` dengan `base == sdk.ARM64SPReg || base ==
  sdk.ARM64FrameReg` → anotasikan `StackSlotName(off)`. Di
  `touchInstrEffect`, untuk base SP/FP, define dengan `stack_slot` bukan
  `object_field`. Perubahan kecil (~30 baris annotate.go + ~10 baris
  dataflowarm64.go).

- **Prioritas**: **sedang** — stack slot adalah pola umum di setiap fungsi;
  label `object_field` yang salah aktif menyesatkan RE.

### Gap 10: x86 `ExtractX86THRAccesses` tidak menangani CMP/TEST/ADD dengan operand THR

- **Deskripsi**: `ExtractX86THRAccesses` (x86.go:262) mengiterasi semua arg
  mencari `Mem` dengan `base == THR` — jadi mendeteksi CMP/TEST/ADD dengan
  `[THR+off]` sebagai "load" (IsStore=false). Ini sebagian benar. Tetapi
  klasifikasi store hanya cek `argIdx == 0 && (MOV/MOVZX/MOVSX/MOVSXD)`.
  Instruksi seperti `MOV [THR+off], reg` terdeteksi sebagai store (benar),
  tetapi `ADD [THR+off], imm` (yang SDK gunakan untuk update counter) juga
  membaca DAN menulis — tidak terdeteksi sebagai store.

  SDK `DecodeLoadObjectFromPoolOrThread` (instructions_x64.cc:38) cek
  `movq, cmpq` untuk THR/PP. AOTopsy lebih luas (semua opcode dengan Mem
  THR) tetapi tidak membedakan read-modify-write.

- **Bukti SDK**:
  - `runtime/vm/instructions_x64.cc` @3.9.2 baris 38–55:
    `if ((bytes[1] == 0x8b) || (bytes[1] == 0x3b))` — movq, cmpq.
  - `runtime/vm/compiler/stub_code_compiler_x64.cc` @3.9.2: update counter
    via `addl` field.

- **Dampak**: Minor — THR audit mungkin melewatkan read-modify-write
  sebagai store. Tidak memengaruhi call graph.

- **Usulan**: Tambahkan deteksi read-modify-write opcode (ADD/SUB/AND/OR/XOR
  dengan Mem THR di argIdx 0). Perubahan kecil (~15 baris).

- **Prioritas**: **rendah** — THR audit sudah menangkap akses utama.

### Gap 11: Tidak ada anotator untuk TypeTestABI / DispatchTableNullErrorABI register roles

- **Deskripsi**: SDK mendefinisikan ABI khusus untuk type test stubs
  (`TypeTestABI: kInstanceReg=R0, kDstTypeReg=R8, kScratchReg=R4, ...`) dan
  dispatch table null error (`kClassIdReg=R0` ARM64 / `RCX` x86). AOTopsy
  tidak men-anotasi penggunaan register-register ini.

  `kClassIdReg` (R0 ARM64, RCX x86) digunakan di dispatch table call:
  `LDR X0, [obj, #tags]; UBFX X0, X0, #kClassIdPos, #kClassIdSize; LDR X30,
  [X21, X0, LSL #3]; BLR X30`. AOTopsy men-track X21 sebagai dispatch_table
  dan menangani `LDRRegExtended base==DT`, tetapi tidak men-anotasi R0/RCX
  sebagai `class_id` — sehingga pola "extract class id → dispatch" tidak
  diberi label.

- **Bukti SDK**:
  - `runtime/vm/constants_arm64.h` @3.9.2 baris 477:
    `static constexpr Register kClassIdReg = R0;` (DispatchTableNullErrorABI).
  - `runtime/vm/constants_x64.h` @3.9.2 baris 444:
    `static constexpr Register kClassIdReg = RCX;`.
  - `runtime/vm/constants_arm64.h` @3.9.2 baris 237–258: `TypeTestABI`
    struct.

- **Dampak**: RE tidak melihat "class id extraction" di anotasi; pola
  dispatch table call tidak diberi label sebagai "extract cid → dispatch".

- **Usulan**: Tambahkan annotator yang cek `UBFX Xd, Xn, #lsb, #width`
  dengan `lsb == ClassIdTagPosV3 && width == ClassIdTagSizeV3` →
  `defineReg(dst, "class_id")`. Tambahkan label di call edge saat
  `LDRRegExtended base==DT` dengan index register = class_id register.
  Perubahan menengah (~40 baris).

- **Prioritas**: **rendah** — informasi nice-to-have, bukan blocker.

## Register Tracking Gaps

Register ARM64 yang **tidak ditrack seharusnya ditrack** (berdasarkan
`runtime/vm/constants_arm64.h` @3.9.2):

| Register | SDK Role | Di-track AOTopsy? | Dampak |
|----------|----------|-------------------|--------|
| R22 (NULL_REG) | Caches Object::null() | ❌ Tidak di-seed | null/true/false materialization tidak dikenali |
| R28 (HEAP_BITS) | write_barrier_mask<<32 \| heap_base>>32 | ❌ Tidak dikenali di dataflow | Pointer decompression kehilangan provenance |
| R5 (IC_DATA_REG) | ICData/MegamorphicCache | ❌ Tidak di-track khusus | IC call site tidak diidentifikasi |
| R4 (ARGS_DESC_REG) | Arguments descriptor | ❌ Tidak di-track | Arg-count deterministik hilang |
| R24 (CODE_REG) | Current Code object | ⚠️ Hanya via annotator THR | Field access dari CODE_REG generik |
| R15 (SPREG) | Dart stack pointer | ❌ Tidak dianotasikan | Stack slot dilabel `object_field` (salah) |
| R29 (FPREG) | Frame pointer | ❌ Tidak dianotasikan | Stack slot dilabel `object_field` (salah) |
| R0 (kClassIdReg) | Class ID untuk dispatch | ❌ Tidak dianotasikan | Pola dispatch tidak diberi label |

Register x86_64 yang **tidak ditrack seharusnya ditrack** (berdasarkan
`runtime/vm/constants_x64.h` @3.9.2):

| Register | SDK Role | Di-track AOTopsy? | Dampak |
|----------|----------|-------------------|--------|
| RBX (IC_DATA_REG) | ICData/MegamorphicCache | ❌ Tidak di-track khusus | IC call site tidak diidentifikasi |
| R10 (ARGS_DESC_REG) | Arguments descriptor | ❌ Tidak di-track | Arg-count deterministik hilang |
| R12 (CODE_REG) | Current Code object | ⚠️ Hanya via annotator | Sama dengan ARM64 |
| RCX (kClassIdReg) | Class ID untuk dispatch | ⚠️ Dicek di classifyX86Call untuk dispatch | Tidak dianotasikan sebagai class_id |
| RSP (SPREG) | Stack pointer | ❌ Tidak dianotasikan | Stack slot dilabel `object_field` |
| RBP (FPREG) | Frame pointer | ❌ Tidak dianotasikan | Stack slot dilabel `object_field` |

Catatan: x86_64 tidak memiliki NULL_REG (`DART_ASSEMBLER_HAS_NULL_REG`
tidak didefinisikan); null dimuat dari `Thread.object_null` (offset 0x70
@3.9.2). AOTopsy sudah menangani ini via `CachedVMObjectValue` di
`sdk/predicates.go`, tetapi `disasm` dataflow tidak menggunakannya.

## Fitur RE Missing/Incomplete

1. **LDP pool annotation** — IC/switchable call site tidak dianotasi.
   Fitur SDK: `LoadDoubleWordFromPoolIndex` (assembler_arm64.cc:491).

2. **Pool load via register offset** — pool index besar tidak ditrack.
   Fitur SDK: `DecodeLoadWordFromPool` case 3 (instructions_arm64.cc:196).

3. **Tail call edge extraction** — BR/B/JMP tidak menjadi call edge.
   Fitur SDK: `Jump(Register)`, `GenerateUnRelocatedPcRelativeTailCall`,
   `PcRelativeTailCallPattern`.

4. **IC call site identification** — tidak ada label "IC call" di output.
   Fitur SDK: `ICCallPattern`, `IC_DATA_REG`.

5. **Arguments descriptor extraction** — arg-count dari descriptor hilang.
   Fitur SDK: `ARGS_DESC_REG`, `ArgumentsDescriptor::size_offset()`.

6. **Null/true/false literal annotation** — tidak dikenali di disasm.
   Fitur SDK: `NULL_REG`, `kTrueOffsetFromNull`, `kFalseOffsetFromNull`.

7. **Pointer decompression tracking** — provenance hilang setelah decompress.
   Fitur SDK: `HEAP_BITS, LSL 32` decompression pattern.

8. **Stack slot annotation** — stack slot dilabel `object_field` (salah).
   Fitur SDK: `SPREG`, `FPREG`, `StackSlotName` (sudah ada di sdk, tidak
   dipakai di disasm).

9. **Class ID extraction annotation** — pola UBFX tags → class_id tidak
   diberi label. Fitur SDK: `kClassIdTagPos`, `kClassIdTagSize`,
   `kClassIdReg`.

10. **Read-modify-write THR detection (x86)** — ADD/SUB [THR+off] tidak
    terdeteksi sebagai store. Fitur SDK: counter update via `addl`.

## Verifikasi SDK

### grep MCP (searchGitHub by Vercel)

| Query | Repo | Hasil |
|-------|------|-------|
| `"NULL_REG"` | `dart-lang/sdk` | Konfirmasi `constants_arm64.h:157`, `constants_riscv.h`, `DART_ASSEMBLER_HAS_NULL_REG` di ARM64/RISC-V (x86 tidak punya). |
| `"IC_DATA_REG"` | `dart-lang/sdk` | Konfirmasi `constants_arm64.h:151` (R5), `constants_x64.h:126` (RBX), penggunaan di `stub_code_compiler_*.cc` dan `flow_graph_compiler_*.cc`. |
| `"ARGS_DESC_REG"` | `dart-lang/sdk` | Konfirmasi `constants_arm64.h:152` (R4), `constants_x64.h:127` (R10), penggunaan di stubs. |
| `"DecodeLoadDoubleWordFromPool"` | `dart-lang/sdk` | Konfirmasi `instructions_arm64.cc:248` + `instructions_arm64.h:57` + `assembler_arm64.cc:491`. |
| `"LoadWordFromPoolIndex"` | `dart-lang/sdk` | Konfirmasi `assembler_arm64.cc:439` (3 case: ldr / add+ldr / movz+movk+ldr). |
| `"SwitchableCallMiss"` | `dart-lang/sdk` | Konfirmasi `stub_code_compiler_*.cc`, `code_patcher_*.cc`, `runtime_entry.cc`, `object_pool_builder.h` (kResetToSwitchableCallMissEntryPoint: "Only used in AOT"). |
| `"BranchLink"` | `dart-lang/sdk` | Konfirmasi `assembler_arm64.cc:756` (AOT: code_reg = LR, LoadWordFromPoolIndex, Call(FieldAddress(LR, entry))). |
| `"PcRelativeTailCallPattern"` | `dart-lang/sdk` | Konfirmasi `instructions_x64.h:196` (JMP rel32 = 0xe9). |
| `"IndexFromOffset"` | `dart-lang/sdk` | Konfirmasi `object.h:5732` (`IndexFromOffset(offset) = (offset + kHeapObjectTag - element_offset(0)) / kWordSize`). |

### gh api @ tag 3.9.2

| File | Verifikasi |
|------|-----------|
| `runtime/vm/constants_arm64.h?ref=3.9.2` | Baris 56–63: R21=DISPATCH_TABLE_REG, R22=NULL_REG, R24=CODE_REG, R26=THR, R27=PP, R28=HEAP_BITS. Baris 144–157: PP, DISPATCH_TABLE_REG, CODE_REG, FUNCTION_REG, FPREG, SPREG, IC_DATA_REG=R5, ARGS_DESC_REG=R4, THR, HEAP_BITS, NULL_REG. Baris 477: kClassIdReg=R0 (DispatchTableNullErrorABI). Baris 633: `kCpuRegistersForArgs[] = {R1, R2, R3, R5, R6, R7}`. Baris 634: `kFpuRegistersForArgs[] = {V0..V5}`. |
| `runtime/vm/constants_x64.h?ref=3.9.2` | Baris 35: R12=CODE_REG. Baris 123–132: PP=R15, SPREG=RSP, FPREG=RBP, IC_DATA_REG=RBX, ARGS_DESC_REG=R10, CODE_REG=R12, THR=R14. Baris 444: kClassIdReg=RCX. Baris 683–685: `kCpuRegistersForArgs[] = {RDI, RSI, RDX, RBX, R8, R9}`, `kFpuRegistersForArgs[] = {XMM1..XMM6}`. |
| `runtime/vm/compiler/assembler/assembler_arm64.cc?ref=3.9.2` | Baris 439–455: `LoadWordFromPoolIndex` 3 case (ldr / add+ldr / movz+movk+ldr). Baris 491–548: `LoadDoubleWordFromPoolIndex` 4 varian (ldp / add+ldp / add+add+ldp). Baris 756–777: `BranchLink` AOT (code_reg=LR, LoadWordFromPoolIndex, Call(FieldAddress(LR, entry))). Baris 642–648: `mov(dst, NULL_REG)` / `AddImmediate(dst, NULL_REG, kTrueOffsetFromNull)`. |
| `runtime/vm/compiler/assembler/assembler_arm64.h?ref=3.9.2` | Baris 491: `Jump(Register target) { br(target); }`. Baris 1750–1755: `Call(Address target) { ldr(LR, target); blr(LR); }`. Baris 2236: `GenerateUnRelocatedPcRelativeTailCall`. |
| `runtime/vm/instructions_arm64.cc?ref=3.9.2` | Baris 36–48: `ICCallPattern` (`DecodeLoadDoubleWordFromPool`, `ASSERT(data_reg == R5)`). Baris 196–227: `DecodeLoadWordFromPool` case 3 (movz+movk+ldr [pp, dst]). Baris 248–320: `DecodeLoadDoubleWordFromPool` (ldp, assertion `IsLoadStoreRegPairOp`). |
| `runtime/vm/instructions_x64.cc?ref=3.9.2` | Baris 19–55: `IndexFromPPLoadDisp8/32`, `DecodeLoadObjectFromPoolOrThread` (movq/cmpq [THR+disp] / [PP+disp]). Baris 74–110: `TypeTestingStubCallPattern::GetSubtypeTestCachePoolIndex` (movq R9, [PP+offset]). |
| `runtime/vm/instructions_x64.h?ref=3.9.2` | Baris 113–161: `PcRelativeCallPattern` (0xe8, CALL rel32). Baris 163–209: `PcRelativeTrampolineJumpPattern` (0xe9, JMP rel32), `PcRelativeTailCallPattern`. |
| `runtime/vm/code_patcher_x64.cc?ref=3.9.2` | Baris 19–25: `kCallPatternJIT` (callq [CODE_REG+entry, disp8]), `kCallPatternAOT` (callq [TMP+entry, disp8]). Baris 38–67: `kLoadCodeFromPoolDisp8/32AOT` (movq TMP, [PP+disp]). |
| `runtime/vm/object.h?ref=3.9.2` | Baris 5639–5645: `element_offset(index) = data_offset() + 8*index`. Baris 5732–5740: `IndexFromOffset(offset) = (offset + kHeapObjectTag - element_offset(0)) / kWordSize`. |
| `runtime/vm/compiler/runtime_offsets_extracted.h?ref=3.9.2` | `Thread_dispatch_table_array_offset` (0x2c x86 / 0x58 ARM64), `Thread_object_null_offset` (0x38/0x70), `Thread_stack_limit_offset` (0x1c/0x38). |
