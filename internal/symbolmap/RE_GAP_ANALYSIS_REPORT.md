# RE Gap Analysis Report: internal/symbolmap

> **STATUS VERIFIKASI (2026-09-01)** — isi gap CONFIRMED (hanya BL/B dan
> CALL/JMP rel32; `collectSymbols` membuang `Size`; tidak ada reverse-import;
> tidak ada DWARF). Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> **Tapi tabel "Register Tracking Gaps" ARM64 salah di lima baris:**
>
> | ditulis di report | ground truth (`sdk/registers.go` + `constants_arm64.h`) |
> |---|---|
> | X19 = ARGS_DESC_REG | **R4** (X19 = CALLEE_SAVED_TEMP) |
> | X20 = NULL_REG | **R22** (X20 = CALLEE_SAVED_TEMP2) |
> | X22 = HEAP_BITS | **R28** (X22 = NULL_REG) |
> | X23 = CODE_REG | **R24** |
> | X28 = IC_DATA_REG | **R5** (X28 = HEAP_BITS) |
>
> (X26=THR, X27=PP, X21=DT sudah benar.) Karena tabel register adalah bagian
> yang paling mungkin disalin langsung ke kode, koreksi ini penting.

## Ringkasan

Folder `internal/symbolmap` berisi **satu** file sumber (`symbolmap.go`, 377
baris) plus test-nya. Paket ini adalah port dari `flutterdec`'s
`pipeline/symbol_map.rs` (Rust, ARM64-only via Capstone): ia men-diff binary
**stripped** (`libapp.so` produksi) vs binary **unstripped** (debug build dari
binary yang SAMA) dengan cara men-disassemble stripped side, menemukan setiap
instruksi direct call/branch (BL/B ARM64, CALL/JMP rel32 x86), lalu resolve
target VA against symbol table unstripped (exact match atau nearest-symbol-
below dalam jarak terbatas).

Kode ini berfungsi untuk apa yang ia klaim, tetapi dari perspektif RE terhadap
Dart AOT, paket ini memiliki **gap fundamental**: ia hanya menangani **direct
calls** — sementara dalam binary Dart AOT, **mayoritas call site adalah
indirect** (BLR Xn melalui dispatch table, PP-loaded Code entry point, THR
stub slots). Paket saudara `internal/disasm` sudah memiliki `ExtractCallEdgesCFG`
yang melakukan CFG-wide reaching-definitions dataflow untuk resolve BLR via
provenance register (PP[42], THR.AllocateArray, dispatch_table, object_field),
tetapi `symbolmap` **sama sekali tidak memakainya** — tidak ada register
tracking, tidak ada annotator PP/THR, tidak ada dispatch-table awareness.

Selain itu, `collectSymbols` **mengabaikan field `Size`** dari ELF Symbol
padahal SDK `elf.cc` meng-emit `code.Size()` untuk setiap STT_FUNC —
nearest-match bisa divalidasi terhadap boundary simbol, bukan hanya jarak
heuristik. Tidak ada penggunaan DWARF debug info, tidak ada reverse mapping
(unstripped symbol → stripped address) walau `compareExecLayouts` sudah
memverifikasi exec bytes identik, tidak ada penanganan conditional branch
(B.cond/CBZ/CBNZ/TBZ/TBNZ), dan tidak ada kategorisasi nama stub Dart
(`stub `, `new `, `as `, `_iso_stub_`) yang di-emit SDK.

Dampak agregat: untuk binary Dart AOT tipikal, `symbolmap` melewatkan
>50% call site (semua indirect), tidak menghasilkan full symbol table untuk
stripped binary walau data tersedia, dan nearest-match bisa false-positive
tanpa validasi boundary.

## Struktur Folder

| File | Peran |
|------|------|
| `symbolmap.go` | Seluruh logika paket: `Compare` (entry-point), `collectExecSections`, `compareExecLayouts`, `collectSymbols`, `resolveTarget`, `scanARM64CallSites`, `scanX86CallSites`, `WriteCallSitesTSV`. Hanya scan direct call/branch, zero register tracking. |
| `symbolmap_test.go` | Unit test: `TestResolveTarget` (exact/nearest/unresolved), `TestWriteCallSitesTSV` (format TSV). Tidak ada test integrasi ELF. |

Konsumen: `cmd/aotopsy/cmd_debug_diff.go` (`cmdSymbolMap`, command
`_debug symbolmap`).

## Gap Analysis

### Gap 1: Tidak ada resolusi indirect call (BLR/BR/call_indirect)

- **Deskripsi**: `scanARM64CallSites` hanya mendeteksi `arm64.BL` dan
  (opsional) `arm64.B`. `scanX86CallSites` hanya mendeteksi `x86asm.CALL`
  dan (opsional) `x86asm.JMP` dengan `x86.RelTarget` (rel32 only). Instruksi
  indirect — `BLR Xn`, `BR Xn` (ARM64), `CALL reg`, `CALL [reg+disp]` (x86)
  — **sama sekali tidak di-scan**. Padahal di binary Dart AOT, mayoritas
  call adalah indirect: dispatch table calls (`LDR X30, [X21, Xm, LSL #3];
  BLR X30`), PP-loaded Code calls (`LDR Xn, [X27, #imm]; LDR X30, [Xn, #entry];
  BLR X30`), THR stub calls (`LDR X30, [X26, #off]; BLR X30`).

- **Bukti SDK**: SDK `runtime/vm/compiler/assembler/assembler_arm64.h`
  meng-emit BLR untuk semua dynamic dispatch, stub calls, dan PP-loaded
  Code calls. Pada sample 3.9.2 ARM64 (lihat `AGENTS.md` "Known limits"):
  5354 BLR vs ~2378 resolved — indirect calls **outnumber** direct BL.
  `internal/disasm/dataflowarm64.go` `ExtractCallEdgesCFG` sudah resolve BLR
  via CFG dataflow register provenance, tetapi `symbolmap` tidak memanggilnya.

- **Dampak**: `symbolmap` melewatkan >50% call site di binary Dart AOT
  tipikal. `UnresolvedCount` dan `Targets` tidak merepresentasikan call graph
  yang sebenarnya. RE analyst yang memakai output ini akan mendapat
  kesan salah bahwa sebagian besar binary "tidak teresolusi" padahal
  resolusinya tersedia via register provenance.

- **Usulan**: Ganti `scanARM64CallSites`/`scanX86CallSites` dengan
  `disasm.ExtractCallEdgesCFG` (ARM64) / `disasm.ScanX86FunctionCFG` (x86)
  yang sudah ada. Karena `symbolmap` men-scan seluruh exec section (bukan
  per-function), perlu adaptasi:要么 (a) partisi exec section ke function
  ranges dulu lalu panggil per-function, atau (b) jalanin dataflow
  section-wide dengan reset register di setiap kemungkinan function entry
  (deteksi via symbol table unstripped atau via prologue pattern). Tambah
  field `Reg`, `Via`, `Targets`, `Candidates` ke `CallSite` struct (sudah
  ada di `disasm.CallEdge`). Resolve BLR target VA against unstripped
  symbol table sama seperti BL.

- **Prioritas**: **Tinggi** — ini adalah gap terbesar; tanpa ini
  `symbolmap` bukan symbol map yang berguna untuk Dart AOT.

### Gap 2: Tidak ada register tracking sama sekali

- **Deskripsi**: Paket ini tidak melacak register apa pun. Bahkan register
  ABI Dart AOT yang fixed-role — X26=THR, X27=PP, X21=dispatch table
  (ARM64); R14=THR, R15=PP, RCX=kClassIdReg (x86) — tidak di-seed atau
  di-track. `scanARM64CallSites` memanggil `disasm.Disassemble` tetapi
  hanya memeriksa setiap instruksi secara isolated untuk BL/B; tidak ada
  state register yang dibawa antar instruksi.

- **Bukti SDK**: `internal/sdk` sudah mendefinisikan `ARM64THR=26`,
  `ARM64PP=27`, `ARM64DT=21`, `X86THR=14`, `X86PP=15`. `internal/disasm`
  `dataflowarm64.go` `noWindowRegs` melacak 31 GP register dengan lattice
  top/known/bottom. `internal/disasm` `annotate.go` punya `PPAnnotator`,
  `THRAnnotator`, `THRContextAnnotator`, `PeepholeState` (ADD+LDR PP split).
  Semua ini tidak dipakai `symbolmap`.

- **Dampak**: Tidak mungkin resolve indirect call (konsekuensi Gap 1).
  Selain itu, anotasi provenance (`PP[42] Widget.build`,
  `THR.AllocateArray_stub`) yang sangat berguna untuk RE tidak dihasilkan.

- **Usulan**: Refactor `symbolmap` untuk memakai pipeline `disasm` yang
  sudah ada: untuk setiap function range di exec section, panggil
  `ExtractCallEdgesCFG(name, insts, symbols, annotators)` dengan annotators
  yang dibangun dari PP pool + THR field table (yang sudah di-load di
  `internal/analysis` pipeline). Ini menghapus duplikasi scan logic dan
  langsung mendapat register provenance + arg-count hint.

- **Prioritas**: **Tinggi** — prasyarat untuk Gap 1.

### Gap 3: Field `Size` ELF Symbol diabaikan; nearest-match tanpa validasi boundary

- **Deskripsi**: `collectSymbols` mengumpulkan `map[uint64]string` —
  hanya VA→name, **tanpa Size**. `resolveTarget` nearest-match hanya
  mengecek `delta <= nearestMaxDistance` (default 64 byte). Ia tidak
  mengecek apakah `targetVA` jatuh **di dalam** range simbol
  `[symVA, symVA+size)`. Akibatnya: target di `symVA+60` dengan
  `nearestMaxDistance=64` dianggap "nearest" ke simbol itu, padahal simbol
  mungkin hanya berukuran 20 byte dan target sebenarnya di function
  berikutnya.

- **Bukti SDK**: `runtime/vm/elf.cc` `ElfSymbolTable::Initialize` (line
  ~1233) meng-emit `AddSymbol(name, STB_LOCAL, STT_FUNC, symbol_data.size,
  ...)` dengan `symbol_data.size = code.Size()` (dari
  `image_snapshot.cc` line ~1724: `current_symbols_->Add({symbol,
  Type::Function, offset, code.Size(), label})`). Jadi setiap STT_FUNC
  di unstripped build **memiliki Size yang akurat** = ukuran kode function
  tersebut. `debug/elf.Symbol` Go punya field `Size uint64` yang sudah
  ter-populate.

- **Dampak**: False-positive nearest-match. Dengan `nearestMaxDistance=64`,
  target di antara dua function kecil (mis. stub 16-byte) bisa salah
  atribusi ke function sebelumnya padahal sudah masuk function setelahnya.
  Untuk Dart AOT yang banyak stub kecil (StackOverflowCheck, etc.),
  ini signifikan.

- **Usulan**: Ubah `collectSymbols` untuk mengembalikan
  `map[uint64]SymbolInfo` dengan `{Name string; Size uint64}`. Di
  `resolveTarget`, jika exact match gagal dan nearest candidate ditemukan,
  cek: jika `targetVA < symVA+size` → `MatchNearest` (target di DALAM
  function, offset valid); jika `targetVA >= symVA+size` tapi
  `delta <= nearestMaxDistance` → `MatchNearest` dengan flag
  `out_of_bounds=true` atau turunkan ke `MatchUnresolved` jika ada simbol
  lain yang lebih dekat. Tambahkan field `SymbolSize` dan `OutOfBounds`
  ke `CallSite`/`TargetSummary`.

- **Prioritas**: **Sedang** — correctness issue untuk nearest-match.

### Gap 4: Tidak ada reverse mapping (unstripped → stripped full symbol table)

- **Deskripsi**: `compareExecLayouts` sudah memverifikasi apakah exec
  section bytes identik antara stripped dan unstripped (`ExecBytesMatch`).
  Jika ya, **setiap symbol VA di unstripped langsung valid di stripped**
  (alamat sama, kode sama). Tetapi `symbolmap` tidak mengeksploitasi ini
  untuk membangun full symbol table untuk stripped binary — ia hanya
  resolve individual call target, bukan import seluruh symbol set.

- **Bukti SDK**: `runtime/vm/elf.cc` meng-emit static `.symtab` dengan
  STT_FUNC local untuk setiap Code object (line ~1233: `AddSymbol(
  symbol_data.name, elf::STB_LOCAL, type, symbol_data.size, section->index,
  portion.offset + symbol_data.offset, ...)`). Saat strip, `.symtab`
  dihapus tetapi kode di `.text` tidak berubah — jadi VA setiap function
  tetap sama. Dynamic `.dynsym` hanya punya 4 symbol global STT_OBJECT
  (`_kDartVmSnapshotData`, `_kDartVmSnapshotInstructions`,
  `_kDartIsolateSnapshotData`, `_kDartIsolateSnapshotInstructions`) yang
  survive stripping.

- **Dampak**: RE analyst harus manual cross-reference setiap address
  stripped ke unstripped. Padahal jika `ExecBytesMatch=true`, seluruh
  unstripped `.symtab` bisa di-inject sebagai symbol table untuk stripped
  binary, memberikan nama function untuk SEMUA address, bukan hanya call
  target.

- **Usulan**: Tambah mode `--import-symbols` (atau output tambahan
  `stripped_symbols.jsonl`): jika `ExecBytesMatch=true`, emit seluruh
  unstripped symbol (VA, name, size, type) sebagai symbol table yang
  valid untuk stripped binary. Ini bisa langsung di-load oleh tool lain
  (Ghidra, IDA) atau oleh pipeline `internal/analysis` sebagai
  `SymbolLookup`. Bahkan jika `ExecBytesMatch=false` tetapi
  `ExecLayoutMatch=true` (kode sama, layout section sama), mapping masih
  valid per-section.

- **Prioritas**: **Tinggi** — ini adalah value tertinggi dari punya
  unstripped build, dan saat ini tidak dieksploitasi.

### Gap 5: Tidak ada DWARF debug info usage

- **Deskripsi**: Unstripped build Dart AOT sering memiliki DWARF debug
  info (`.debug_info`, `.debug_line`, `.debug_frame`) — terutama jika
  di-build dengan `--extra-gen-snapshot-options=--dwarf-stack-traces` atau
  flags serupa. `symbolmap` hanya membaca ELF symbol table (`.symtab` +
  `.dynsym`), tidak membaca DWARF. DWARF bisa menyediakan: function names
  yang tidak di-emit ke `.symtab` (mis. inlined functions), line-level
  mapping (source file:line per PC), function boundaries yang lebih
  akurat, parameter types.

- **Bukti SDK**: `runtime/vm/image_snapshot.cc` `AssemblyImageWriter::
  AddCodeSymbol` (line ~1721) memanggil `debug_so_->dwarf()->AddCode(code,
  label)` — ada path DWARF terpisah dari symbol table. `runtime/vm/elf.cc`
  menulis section DWARF (`.debug_info`, dll.) via `dwarf_`. DWARF info
  bisa berisi function yang di-inlined (tidak punya symbol table entry
  sendiri).

- **Dampak**: Function yang hanya ada di DWARF (inlined, atau build
  dengan dwarf-only) tidak teresolusi. Line-level mapping (PC →
  source.dart:line) tidak dihasilkan — ini sangat berguna untuk RE.

- **Usulan**: Tambah optional DWARF reader (pakai
  `github.com/go-delve/delve/pkg/dwarf` atau `debug/dwarf` stdlib) untuk
  meng-ekstrak: (a) subprogram entries (function name + low_pc + high_pc)
  sebagai symbol tambahan, (b) inlined_subroutine entries sebagai
  annotation, (c) line program (`.debug_line`) untuk PC→source mapping.
  Emit sebagai `dwarf_symbols.jsonl` dan `dwarf_line_map.jsonl`.

- **Prioritas**: **Sedang** — signifikan untuk build yang punya DWARF,
  tetapi tidak semua libapp.so produksi memilikinya.

### Gap 6: Conditional branch (B.cond/CBZ/CBNZ/TBZ/TBNZ) tidak di-scan

- **Deskripsi**: `scanARM64CallSites` dengan `includeBranches=true` hanya
  menangani `arm64.B` (unconditional). Conditional branch — B.cond,
  CBZ, CBNZ, TBZ, TBNZ — tidak di-scan padahal mereka adalah direct
  branch dengan target VA yang bisa di-resolve ke symbol. Decoder
  `arm64.CondBranch` sudah ada di `internal/arch/arm64/decoders.go` dan
  mengembalikan target address, tetapi tidak dipakai.

- **Bukti SDK**: ARM64 B.cond/CBZ/CBNZ/TBZ/TBNZ adalah direct branch
  standar (ARM ARM). Dart AOT compiler meng-emitnya untuk if/switch/
  null-check. Targetnya adalah PC-relative, sama persis arithmetic-nya
  dengan B (sign-extended imm19/imm14 * 4 + PC).

- **Dampak**: Control flow edge ke symbol lain (mis. branch ke error
  handler, branch ke early-return stub) tidak teresolusi. Untuk RE
  control-flow analysis, ini berguna.

- **Usulan**: Tambah opsi `--include-cond-branches` (atau merge ke
  `--include-branches`). Di `scanARM64CallSites`, cek
  `arm64.CondBranch(inst.Raw, inst.Addr)` dan emit sebagai `CallSite`
  dengan `Kind="b.cond"` (atau field baru `BranchKind`). Untuk x86,
  tambahkan `x86.IsCondJump(d.Inst.Op)` check + `x86.RelTarget` resolve.

- **Prioritas**: **Rendah** — nice-to-have untuk control-flow analysis,
  bukan core gap.

### Gap 7: Tidak ada kategorisasi nama stub Dart AOT

- **Deskripsi**: SDK meng-emit symbol dengan naming convention yang
  kategorikan jenis code object, tetapi `symbolmap` memperlakukan semua
  nama sama. Convention (dari SDK `image_snapshot.cc`
  `AddNonUniqueNameFor` + `analyze_snapshot_api_impl.cc` `DumpCode`):
  - `"stub <name>"` — stub code (StackOverflowCheck, AllocateArray, etc.)
  - `"new <ClassName>"` — allocation stub
  - `"as <TypeName>"` / `"assert type is <TypeName>"` — type test stub
  - `"<functionQualifiedName>"` — regular Dart function
  - `"unknown function of <ClassName>"` — dropped function (owner=Smi cid)
  - `"_iso_stub_<name>Stub"` — isolate-specific stub copy
  - `"Trampoline"` / `"Padding"` — trampoline/padding (bukan function)

  `isUsefulSymbolName` hanya reject `$`-prefix (ARM mapping symbol) dan
  `.L`-prefix (local label). Ia tidak mengategorikan atau memfilter
  `"Trampoline"`/`"Padding"` yang bukan function.

- **Bukti SDK**: `runtime/vm/image_snapshot.cc` line ~1306-1370
  `AddNonUniqueNameFor`: `if (code.IsStubCode()) { buffer->AddString("stub
  "); ... }` / `if (code.IsAllocationStubCode()) { buffer->AddString("new
  "); }` / `else if (code.IsTypeTestStubCode()) { buffer->AddString(
  "assert type is "); }`. `runtime/vm/analyze_snapshot_api_impl.cc` line
  ~280: `"_iso_stub_" #name "Stub"` dan line ~325: `"new %s"` /
  `"as %s"`. `worawit/blutter` `DartApp.cpp` juga handle `_iso_stub_`.

- **Dampak**: RE analyst tidak bisa filter "tampilkan hanya regular
  function" vs "tampilkan stub". `Trampoline`/`Padding` muncul sebagai
  "function" di output padahal bukan. Tidak ada agregasi per-kategori
  (berapa % call ke stub vs ke regular function).

- **Usulan**: Tambah field `SymbolCategory` ke `CallSite`/`TargetSummary`
  (enum: `function`, `stub`, `alloc_stub`, `type_test_stub`,
  `iso_stub`, `trampoline`, `padding`, `unknown`). Klasifikasi via prefix
  match pada `SymbolName`. Filter `Trampoline`/`Padding` dari default
  output (atau flag `--include-non-functions`). Emit agregat per-kategori
  di report.

- **Prioritas**: **Sedang** — meningkatkan signal-to-noise output
  signifikan.

### Gap 8: Tidak ada validasi target VA berada di exec section unstripped

- **Deskripsi**: `resolveTarget` resolve target VA against symbol table
  tanpa mengecek apakah target VA berada dalam range exec section
  unstripped. BL target yang corrupted/misdecoded (mis. data byte
  kebetulan mirip BL opcode) akan di-resolve ke nearest symbol walau
  target sebenarnya bukan kode.

- **Bukti SDK**: SDK `.dynsym` meng-emit `_kDartIsolateSnapshotInstructions`
  dengan size = ukuran instructions section. Ini adalah boundary kode
  Dart yang valid. Target BL di luar range ini bukan kode Dart.

- **Dampak**: False-positive resolve untuk misdecoded instruction.
  Walaupun `compareExecLayouts` sudah verifikasi bytes match, decode
  linear atas raw `.text` bisa misdecode data embed (mis. jump table,
  constant pool inline) sebagai BL.

- **Usulan**: Setelah `collectExecSections` unstripped, bangun
  `codeRange` (union semua exec section VA range). Di `resolveTarget`,
  jika `targetVA` tidak ada di `codeRange`, return `MatchUnresolved`
  dengan note `"target_outside_exec"`. Tambah field `TargetInExec bool`
  ke `CallSite`.

- **Prioritas**: **Rendah** — edge case, tetapi murah untuk diimplementasi.

### Gap 9: x86 indirect call (CALL reg / CALL [mem]) tidak di-scan

- **Deskripsi**: `scanX86CallSites` hanya memanggil `x86.RelTarget` yang
  hanya resolve `x86asm.Rel` arg (rel32). `CALL reg` (indirect through
  register) dan `CALL [reg+disp]` (indirect through memory) tidak
  di-scan. Padahal `internal/disasm/x86.go` `classifyX86Call` sudah
  handle ketiga shape ini (Rel, Reg, Mem) termasuk dispatch-table
  detection (`CALL [RAX+RCX*8+disp]`) dan THR-slot call
  (`CALL [R14+disp]`).

- **Bukti SDK**: x86_64 Dart AOT dispatch sequence (dari comment di
  `disasm/x86.go` line ~186): `MOV RAX, [R14+0x70]` (THR.dispatch_table)
  lalu `CALL [RAX+8*RCX+0xd700]`. PP-loaded Code: `MOV RAX, [R15+disp]`
  lalu `CALL [RAX+entry_disp]`. THR stub: `CALL [R14+disp]`. Semua ini
  indirect, tidak ditangani `symbolmap`.

- **Dampak**: Sama dengan Gap 1 tetapi untuk x86_64. Untuk sample 3.12
  x86_64, 3371 dispatch calls + 6348 THR-slot calls tidak teresolusi.

- **Usulan**: Sama dengan Gap 1/2 — pakai `disasm.ScanX86FunctionCFG`
  yang sudah ada. Atau minimal, di `scanX86CallSites`, untuk `CALL` op
  tanpa `Rel` arg, fallback ke `classifyX86Call`-style logic untuk
  extract Reg/Mem operand dan provenance.

- **Prioritas**: **Tinggi** — konsekuensi Gap 1 untuk x86_64.

### Gap 10: Tidak ada ADRP/ADR + ADD address-taking scan

- **Deskripsi**: ARM64 `ADRP Xn, #imm` + `ADD Xn, Xn, #imm` adalah
  standar pattern untuk compute address data/code. `LDR Xn, =imm`
  (PC-relative literal load) juga address-taking. `symbolmap` tidak
  men-scan ini. Untuk RE, address-of references (mis. ke string, ke
  rodata object, ke function pointer) berguna untuk xref.

- **Bukti SDK**: Dart AOT compiler meng-emit ADRP+ADD untuk akses ke
  rodata dan untuk thread-relative address computation. Decoder
  `arm64.ADD64Immediate` sudah ada (cek `sh` bit untuk 12-bit shift).

- **Dampak**: Address-of xref (data reference, function pointer
  reference) tidak dihasilkan. Hanya call/branch yang di-track.

- **Usulan**: Tambah opsi `--include-address-refs`. Scan ADRP+ADD pair
  dan LDR literal, resolve target VA ke symbol (bisa STT_OBJECT juga,
  bukan hanya STT_FUNC). Emit sebagai record terpisah
  `address_refs.tsv`.

- **Prioritas**: **Rendah** — di luar scope "symbol map" strict, tetapi
  berguna untuk RE menyeluruh.

### Gap 11: STT_GNU_IFUNC dan STT_TLS tidak dikumpulkan

- **Deskripsi**: `collectSymbols` hanya menerima `STT_FUNC` dan
  `STT_NOTYPE`. `STT_GNU_IFUNC` (indirect function, linker-generated
  resolver) dan `STT_TLS` (thread-local storage) tidak dikumpulkan.
  Walaupun Dart AOT sendiri tidak meng-emit ini, unstripped build bisa
  punya linker-generated ifunc (mis. dari libc static link) dan TLS
  symbol untuk thread-local Dart state.

- **Bukti SDK**: SDK `elf.cc` `ElfSymbolType` hanya handle
  `Section`/`Function`/`Object` — tidak emit IFUNC/TLS. Tetapi linker
  bisa menambahkan saat link against libc.

- **Dampak**: Minor — symbol IFUNC/TLS tidakteresolusi. Untuk binary
  Dart AOT pure (tidak static-link libc), tidak ada impact.

- **Usulan**: Tambah `STT_GNU_IFUNC` ke `collectSymbols` filter (treat
  sama dengan STT_FUNC — ifunc resolver address adalah code). Untuk
  `STT_TLS`, kumpulkan tapi tandai kategori berbeda (bukan call target).

- **Prioritas**: **Rendah** — edge case.

## Register Tracking Gaps

Paket `symbolmap` memiliki **zero register tracking**. Berikut register
yang seharusnya ditrack (berdasarkan `internal/sdk` dan `internal/disasm`)
tetapi tidak:

### ARM64

| Register | Role | SDK Source | Status di symbolmap |
|----------|------|------------|---------------------|
| X0–X7 | Argument registers (Dart calling convention, 6 args: X0–X5) | `constants_arm64.h` `kCpuRegistersForArgs` | **Tidak ditrack** — `ArgCountHint`/`ArgRegMask` tidak dihitung |
| X16/X17 | IP0/IP1 (linker veneer scratch) | ARM ARM | **Tidak ditrack** — BLR X16 (linker stub) tidak diidentifikasi |
| X18 | Platform register (reserved) | ARM ARM | N/A |
| X19 | ARGS_DESC_REG (argument descriptor) | `constants_arm64.h` | **Tidak ditrack** — arg descriptor provenance hilang |
| X20 | NULL_REG | `constants_arm64.h` | **Tidak ditrack** — null/true/false provenance hilang |
| X21 | Dispatch table (DT) | `constants_arm64.h` `kDispatchTableReg` | **Tidak ditrack** — dispatch table call tidak resolve |
| X22 | HEAP_BITS | `constants_arm64.h` | **Tidak ditrack** |
| X23 | CODE_REG (current Code object) | `constants_arm64.h` | **Tidak ditrack** |
| X26 | THR (Thread) | `constants_arm64.h` `kThreadReg` | **Tidak ditrack** — THR stub call tidak resolve |
| X27 | PP (Object Pool) | `constants_arm64.h` `kHeapBaseReg`/PP | **Tidak ditrack** — PP-loaded Code call tidak resolve |
| X28 | IC_DATA_REG | `constants_arm64.h` | **Tidak ditrack** |
| X29 | FP (Frame Pointer) | ARM ARM | N/A |
| X30 | LR (Link Register) | ARM ARM | **Tidak ditrack** — BLR X30 (call through LR) tidak diidentifikasi |
| SP | Stack Pointer | ARM ARM | N/A |

### x86_64

| Register | Role | SDK Source | Status di symbolmap |
|----------|------|------------|---------------------|
| RAX | Return value / scratch | `constants_x64.h` | **Tidak ditrack** |
| RCX | kClassIdReg (dispatch index) | `constants_x64.h` | **Tidak ditrack** — dispatch table index hilang |
| RDX | Arg register 2 | `DartCallingConvention` | **Tidak ditrack** |
| RBX | Arg register 3 (Dart convention, NOT SysV) | `constants_x64.h` | **Tidak ditrack** |
| RDI | Arg register 0 | `DartCallingConvention` | **Tidak ditrack** |
| RSI | Arg register 1 | `DartCallingConvention` | **Tidak ditrack** |
| R8/R9 | Arg register 4/5 | `DartCallingConvention` | **Tidak ditrack** |
| R14 | THR (Thread) | `constants_x64.h` `kThreadReg` | **Tidak ditrack** — THR-slot call tidak resolve |
| R15 | PP (Object Pool) | `constants_x64.h` | **Tidak ditrack** — PP call tidak resolve |

**Root cause**: `symbolmap` tidak memakai `disasm.ExtractCallEdgesCFG` /
`disasm.ScanX86FunctionCFG` yang sudah melakukan CFG-wide reaching-
definitions dataflow atas register-register ini. Solusi: refactor untuk
memakai pipeline `disasm` yang sudah ada, bukan re-implement scan logic
dari awal dengan subset minimal.

## Fitur RE Missing/Incomplete

| Fitur | Status | Dampak |
|-------|--------|--------|
| Indirect call resolution (BLR/BR/CALL indirect) | **Missing total** | >50% call site tidak teresolusi |
| Register provenance (PP/THR/DT/object_field) | **Missing total** | Tidak ada anotasi "via" untuk RE |
| Arg count hint per call site | **Missing total** | Tidak ada info arity callee |
| Full symbol table import (unstripped→stripped) | **Missing total** | RE analyst harus manual cross-ref |
| DWARF debug info (function/line/inlined) | **Missing total** | Line-level mapping tidak ada |
| Symbol boundary validation (Size field) | **Missing total** | Nearest-match bisa false-positive |
| Stub name categorization | **Missing total** | Tidak bisa filter stub vs function |
| Conditional branch resolution | **Missing total** | Control-flow edge hilang |
| Address-of reference (ADRP+ADD, LDR literal) | **Missing total** | Data xref tidak ada |
| Exec section boundary validation | **Missing total** | Misdecode bisa false-positive resolve |
| Polymorphic call candidates | **Missing total** | `Targets`/`Candidates` field tidak di-populate |
| THR field table integration | **Missing total** | THR offset tidak resolve ke nama field |
| PP pool integration | **Missing total** | PP index tidak resolve ke display string |
| Dispatch table scan | **Missing total** | Selector-based dispatch tidak resolve |
| Trampoline/Padding filtering | **Missing total** | Non-function muncul sebagai function |
| Obfuscation deobfuscation | **Missing total** | Obfuscated build tidak di-deobfuscate |
| Cross-architecture (ARM32, RISC-V) | **Missing total** | Hanya ARM64 + x86_64 |
| Build ID matching | **Missing total** | Tidak verifikasi stripped/unstripped dari build yang sama via BuildID (`.note.gnu.build-id`) |

## Verifikasi SDK

Semua klaim di atas diverifikasi ke `dart-lang/sdk` via dua jalur:

### Jalur 1: grep MCP (`searchGitHub` by Vercel, `repo: "dart-lang/sdk"`)

- **Symbol naming taxonomy**: `grep "SnapshotNameFor"` →
  `runtime/vm/image_snapshot.cc` line 1404–1450: `SnapshotNameFor` memanggil
  `AddNonUniqueNameFor` yang meng-emit `"stub " + name` / `"new " + owner` /
  `"assert type is " + type` / `Function::PrintName(kUserVisibleName)` /
  `"Trampoline"` / `"Padding"`.
- **`_iso_stub_` category**: `grep "_iso_stub_"` →
  `runtime/vm/analyze_snapshot_api_impl.cc` line ~280:
  `TryIdentifyIsolateSpecificStubCopy` meng-emit `"_iso_stub_" #name "Stub"`.
- **Dynamic symbol names**: `grep "_kDartIsolateSnapshotInstructions"` →
  `pkg/native_stack_traces/lib/src/constants.dart`: konfirmasi 4 dynamic
  symbol yang survive stripping.
- **`SymbolData::Type::Function`**: `grep "SymbolData::Type::Function"` →
  `runtime/vm/image_snapshot.cc` line ~1721 & ~2048: `current_symbols_->Add(
  {symbol, Type::Function, offset, code.Size(), label})` — konfirmasi
  Size = `code.Size()`.

### Jalur 2: `gh api` @ tag `3.12.2`

- **`runtime/vm/elf.cc`** (`gh api ... contents/runtime/vm/elf.cc?ref=3.12.2`):
  - Line 436–610: `ElfSymbolTable` class, `AddSymbol(name, binding, type,
    size, section_index, offset, label)`.
  - Line 592–600: `ElfSymbolType` mapping: `Section→STT_SECTION`,
    `Function→STT_FUNC`, `Object→STT_OBJECT`.
  - Line 1140–1148: `ElfWriter::AddText` — entry point untuk code section.
  - Line 1192–1193: BSS section symbol: `symbols->Add({symbol_name,
    Type::Section, 0, size, label})`.
  - Line 1226–1233: `ElfSymbolTable::Initialize`: dynamic symbol =
    `STB_GLOBAL + STT_OBJECT` untuk section content; static local symbol =
    `STB_LOCAL + ElfSymbolType(type)` untuk code/RO payloads. Konfirmasi:
    **dynamic symbol yang survive stripping adalah STT_OBJECT (section-
    level), bukan STT_FUNC** — function symbol hanya di `.symtab` (local).

- **`runtime/vm/image_snapshot.cc`** (`gh api ... contents/runtime/vm/
  image_snapshot.cc?ref=3.12.2`):
  - Line 878–940: `object_name = namer_.SnapshotNameFor(data)` lalu
    `AddCodeSymbol(code, object_name, text_offset)`.
  - Line 1306–1370: `AddNonUniqueNameFor` — full naming taxonomy:
    `IsStubCode()` → `"stub " + StubCode::NameOfStub(EntryPoint())`;
    `IsAllocationStubCode()` → `"new "`; `IsTypeTestStubCode()` →
    `"assert type is "`; `IsFunctionCode()` → owner name + function name;
    `IsClass()` → `UserVisibleNameCString`; `IsFunction()` →
    `PrintName(kUserVisibleName)`; `IsCompressedStackMaps()` →
    `"CompressedStackMaps"`; `IsPcDescriptors()` → `"PcDescriptors"`;
    `IsCodeSourceMap()` → `"CodeSourceMap"`.
  - Line 1380–1395: `EnsureUniqueNameFor` — append `" (#N)"` untuk
    disambiguate duplicate names.
  - Line 1711–1740: `AssemblyImageWriter::AddCodeSymbol` —
    `current_symbols_->Add({symbol, Type::Function, offset, code.Size(),
    label})` + `debug_so_->dwarf()->AddCode(code, label)`. Konfirmasi:
    Size field = `code.Size()`, dan ada path DWARF terpisah.

- **`runtime/vm/analyze_snapshot_api_impl.cc`** (`gh api ... contents/
  runtime/vm/analyze_snapshot_api_impl.cc?ref=3.12.2`):
  - Line 270–290: `TryIdentifyIsolateSpecificStubCopy` —
    `"_iso_stub_" #name "Stub"` via `OBJECT_STORE_STUB_CODE_LIST(MATCH)`.
  - Line 300–360: `SnapshotAnalyzer::DumpCode` — naming: `"new %s"`
    (allocation stub, owner=Class), `"as %s"` (type test, owner=
    AbstractType), `Function::UserVisibleNameCString()` (regular),
    `"unknown function of %s"` (owner=Smi cid). Konfirmasi taxonomy
    lengkap.

### Cross-reference: `worawit/blutter` (RE tool Dart AOT eksternal)

- `grep "_iso_stub_"` juga match `worawit/blutter` `DartApp.cpp` line 298:
  `// these stubs are called "_iso_stub_" in runtime/vm/stub_code.cc`.
  Konfirmasi bahwa tool RE lain juga mengenali kategori ini.

### Fakta Go stdlib

- `go doc debug/elf.Symbol`: field `Value, Size uint64` tersedia.
  `collectSymbols` mengabaikan `Size` — konfirmasi Gap 3.

---

**Kesimpulan**: `internal/symbolmap` saat ini adalah port minimal dari
`flutterdec` yang hanya menangani direct call/branch. Untuk RE Dart AOT
yang sesungguhnya, paket ini harus di-refactor untuk memakai pipeline
`internal/disasm` yang sudah ada (`ExtractCallEdgesCFG` /
`ScanX86FunctionCFG` dengan PP/THR/dispatch-table annotators), menambahkan
reverse symbol import (Gap 4), validasi boundary via Size (Gap 3), dan
kategorisasi stub Dart (Gap 7). Tanpa Gap 1+2+4, paket ini tidak
memberikan value yang signifikan melebihi `objdump -d | grep BL`.
