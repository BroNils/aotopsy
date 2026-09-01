# RE Gap Analysis Report: internal/arch

> **STATUS VERIFIKASI (2026-09-01)** — diadu dengan `arch/arm64/decoders.go` +
> `arch/x86/helpers.go`. Detail: `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> Koreksi untuk folder ini:
> - **Gap 12 (DstRegsOfInst menangkap STP → dianggap define) → SALAH.** Mask
>   `0x3E400000 == 0x28400000` (`decoders.go:448`) **mengunci bit 22 (L)=1**.
>   STP (`L=0`, mis. `0xA9000000` → `0x28000000`) tidak pernah cocok dan
>   mengembalikan `nil`. LDP pre/post-index (`0xA8C00000` → `0x28400000`)
>   justru sudah tertangkap dengan rt1/rt2 benar. Klaim yang sama diulang di
>   CONSOLIDATED_SUMMARY P2-6 — sama-sama gugur.
> - **Gap 3** — decoder memang unsigned-only, tapi alasan dampak "offset
>   dianggap unsigned padahal signed" tidak relevan: `DstRegsOfInst` tidak
>   mengembalikan offset sama sekali.
> - **Gap 9** — nyatanya lebih buruk dari yang ditulis: `mul rcx` →
>   `Args[0]=RCX` → dilaporkan **menulis RCX** (false define), bukan "tidak
>   menulis apa-apa".
> - **Tambahan yang terlewat**: tidak ada `SUBS64Immediate` sama sekali, jadi
>   `CMP Xn, #imm` 64-bit (bentuk cek class-id Dart 3.x) tidak punya decoder —
>   lebih besar daripada Gap 15 yang hanya bicara helper ergonomis.

## Ringkasan

Folder `internal/arch` adalah **single source of truth** untuk instruction
decoders ARM64 + x86_64 di AOTopsy. Dua subfolder:

- `internal/arch/arm64/` — 1 file produksi (`decoders.go`, 650 baris) +
  1 file test. Berisi bitmask decoders murni: `BL`, `B`, `BLR`, `IsRet`,
  `IsBR`, `CondBranch`, `LDR/STR/LDUR/STUR/LDP/STP` (unsigned-offset &
  unscaled), `ADD/SUB/SUBS` immediate, `ADD64Register`, `MOVZ64`, `UBFX`,
  `MOVOrr`, plus dua helper dataflow `DstRegsOfInst` / `DstRegOfInst`.
- `internal/arch/x86/` — 2 file produksi (`decode.go`, `helpers.go`) +
  2 file test. Hanya tipis: linear sweep (`Walk`/`Decode`/`DecodeUntilBad`)
  di atas `golang.org/x/arch/x86/x86asm`, `CanonReg`, `RelTarget`,
  `IsCondJump`, `EqualitySuccessor`, `DstRegsOfInst`.

Paket ini **sudah benar untuk apa yang ada** — bitmask & sign-extension
di `arm64/decoders.go` diverifikasi manual terhadap ARM ARM dan SDK header.
Tetapi **cakupan encodernya sangat sempit** dibandingkan instruksi yang
sebenarnya diemis Dart AOT, dan **asimetri ARM64 vs x86 sangat besar**:
ARM64 punya 17 decoder spesifik + 1 generic `DstRegsOfInst`; x86 hanya
punya wrapper `x86asm` + 1 generic `DstRegsOfInst`. Akibatnya hampir semua
analisa arsitektur-spesifik (PP/THR annotation, pool-index decode, dispatch
table load, receiver recovery, intraprocedural dataflow) **hanya jalan di
ARM64**, dan harus di-reimplement secara ad-hoc di tiap konsumen untuk x86.

Gap utama yang ditemukan:

1. **MOVK / MOVN tidak didecode** — padahal SDK `LoadWordFromPoolIndex` case 3
   (`movz + movk + ldr [PP, Xm]`) dan `StoreWordToPoolIndex` case 3 adalah
   satu-satunya path untuk pool index besar (> 32 KB). Decoder `MOVZ64`
   ada, `MOVK`/`MOVN` **tidak**. Konsumen harus re-implement bit-slice
   sendiri.
2. **LDR register-offset hanya untuk `LDR Xt, [Xn, Xm, LSL #3]`** — option
   field (S, option=011) di-hardcode. SDK juga memakai `LDR Xt, [PP, Xm]`
   **tanpa shift** (case 3 `LoadWordFromPoolIndex`) dan `LDR Xt, [Xn, Xm]`
   untuk dispatch table scan; decoder saat ini menolak keduanya karena
   value `0xF8607800` mengunci `S=1, option=011`.
3. **LDP/STP hanya unsigned-offset** — SDK `LoadDoubleWordFromPoolIndex`
   memakai `Address::PairOffset` yang bisa **pre-index / post-index /
   signed-offset**; decoder `LDP64UnsignedOffset` hanya satu varian.
4. **STR pre-index / post-index / LDR literal / LDRS** tidak didecode
   sama sekali — padahal `TagAndPushPP` (`str TMP, [SP, #-8, pre-index]`)
   dan `Pop` (`ldr reg, [SP, #8, post-index]`) adalah pola prologue/epilogue
   universal Dart.
5. **Tidak ada decoder untuk ADRP/ADR** — `DstRegsOfInst` mengklaim
   "ADR/ADRP: mask 0x1F000000 == 0x10000000" tetapi **mask itu juga
   menangkap LDP/STP (0x10000000? tidak — LDP/STP mulai 0xA9000000 /
   0xA9400000, jadi tidak overlap)**. Namun tidak ada decoder spesifik yang
   menghitung target absolut ADRP (page) / ADR — padahal Dart memakai
   ADRP+ADD untuk mengakses literal pool di PIC code, dan `ExtractPC`
   memakai ADR.
6. **Tidak ada decoder untuk BRK / HLT / SVC** — Dart memakai `BRK #imm`
   untuk breakpoint/single-step dan `SVC #0` untuk leaf-call trap di
   simulator; tidak ada deteksi.
7. **Tidak ada decoder untuk FMOV / floating-point load/store** — Dart AOT
   memakai `FMOV Dd, #imm` untuk double constant, `LDR Dt, [Xn, #imm]`
   (V=1) untuk double load dari pool; `DstRegsOfInst` tidak mengembalikan
   register FPU manapun, sehingga value tracker tidak tahu `V0` ditulis
   oleh `BoxDoubleStub`.
8. **`DstRegsOfInst` ARM64 tidak menangani MOVK** — `MOVZ` di-define
   tetapi `MOVK` (yang menulis **sebagian** register, merge dengan
   high/low 16-bit existing) masuk ke cabang `0x12800000` yang sama dan
   dianggap menulis full register. Ini salah secara dataflow: `MOVK X0,
   #high, LSL #16` **membaca** X0 lama, bukan menulis dari nol.
9. **`x86/helpers.go::DstRegsOfInst` sangat dangkal** — hanya cek `Args[0]`
   register; `MUL`/`IMUL` (RDX:RAX), `MULX`/`SHLD`/`SHRD` multi-output,
   `CMOV*` (conditional write), `XCHG` (two-way), `LEA` (writes dst tapi
   bukan memory), `POPCNT`/`LZCNT`/`TZCNT`, `MOVQ xmm, r64` (xmm dst)
   semuanya tidak ditangani. `DIV`/`IDIV` mengembalikan `[0, 2]` tetapi
   **tidak mengembalikan flag writes** dan tidak menandai RAX/RDX
   sebagai **read** juga.
10. **`x86/helpers.go::EqualitySuccessor` hanya JE/JNE** — JA/JB/JG/JL
    (magnitude) memang benar `SuccUnknown`, tetapi **JZ/JNZ aliasing
    dengan ZF dari TEST/AND/OR** tidak didecode; tidak ada helper
    "which flag did the previous CMP/TEST set" yang dipakai typetrack
    untuk narrow tipe via class-id range check.
11. **Tidak ada register ABI table di arch/** — `CanonReg` x86 hanya fold
    width; tidak ada konstanta `THR=14, PP=15, CODE_REG=12, IC_DATA=3,
    ARGS_DESC=10, FPREG=5, SPREG=4` di paket ini. Konstanta itu hidup di
    `internal/sdk` tetapi **tidak dikenal arch/**, sehingga `DstRegsOfInst`
    tidak bisa mengembalikan "THR" sebagai symbolic register — konsumen
    harus mapping ulang. ARM64 bahkan tidak punya `CanonReg` sama sekali:
    register 0..30 langsung dipakai sebagai int, dan konstanta `THR=26,
    PP=27, DT=21, NULL_REG=22, HEAP_BITS=28, CODE_REG=24, SPREG=15,
    FPREG=29, IC_DATA=5, ARGS_DESC=4, TMP=16, TMP2=17, FUNCTION=0,
    CALLEE_SAVED_TEMP=19, CALLEE_SAVED_TEMP2=20, kExceptionObjectReg=0,
    kStackTraceObjectReg=1` semuanya di-hardcode di konsumen, bukan di
    arch/.
12. **Tidak ada decoder untuk `LDP` pre-index / post-index** — Dart
    `EnterFrame`/`LeaveFrame` memakai `stp X29, X30, [SP, #-16, pre-index]`
    dan `ldp X29, X30, [SP, #16, post-index]`; `DstRegsOfInst` hanya cek
    `0x3E400000 == 0x28400000` yang menangkap unsigned-offset LDP/STP,
    sehingga pre/post-index pair load/store **dianggap tidak menulis
    register tujuan** di dataflow.
13. **`CondBranch` mengecualikan B.AL/B.NV dengan return `ok=false`**
    — benar untuk "is this conditional", tetapi konsumen yang ingin
    mendapatkan **target branch B.AL** (yang masih punya target address
    meskipun unconditional) harus panggil `B()` terpisah. Tidak ada
    helper `AnyBranch(raw, pc)` yang mengembalikan (target, kind).
14. **Tidak ada decoder untuk `CBZ`/`CBNZ` 64-bit vs 32-bit** —
    `CondBranch` mengembalikan target tetapi **tidak** mengembalikan
    `sf` (32 vs 64-bit) dan **tidak** mengembalikan `Rt`. Typetrack
    perlu `Rt` untuk narrow "register yang di-CMP dengan 0 adalah
    non-null di edge not-taken". Saat ini konsumen harus re-parse
    `raw & 0x1F` sendiri.
15. **Tidak ada decoder untuk `TBZ`/`TBNZ` bit position** — `CondBranch`
    hanya mengembalikan target; `b5 + b40` (bit position 0..63) tidak
    diekstrak. Padahal Dart memakai `TBZ X0, #kSmiTagShift, ...` untuk
    Smi check dan `TBNZ X0, #0, ...` untuk tag check — bit position
    adalah semantic RE signal.
16. **`x86/decode.go::Walk` tidak melaporkan prefix secara terstruktur**
    — `x86asm.Inst.Prefix` ada tetapi `Decoded` tidak meng-eksposnya.
    Dart AOT x86 memakai `REP`/`LOCK`/`REX` prefix untuk string ops dan
    atomics; konsumen yang ingin deteksi `REP MOVSB` (memcpy) harus akses
    `Inst.Prefix` langsung, tidak lewat `Decoded`.
17. **Tidak ada decoder untuk `CMP`/`CMN`/`TST` immediate yang
    mengembalikan operand** — `SUBS32Immediate` ada, tetapi tidak ada
    helper "extract CMP immediate + register" yang konsumen bisa pakai
    untuk "CMP X0, #kSmiTagMask" → narrow. Konsumen harus re-implement
    bit-slice `imm12 + shift`.
18. **`arm64/decoders.go` tidak punya `IsCall` / `IsJump` / `IsReturn`
    predikat** — `BL`, `BLR`, `IsRet`, `IsBR` ada sebagai decoder
    terpisah, tetapi tidak ada predikat satu-panggilan. Konsumen
    (`branch.go`, `dataflowarm64.go`) masing-masing re-derive dengan
    bitmask sendiri.
19. **`x86/helpers.go::IsCondJump` tidak termasuk `JECXZ`/`JRCXZ` di
    `EqualitySuccessor`** — `IsCondJump` mengembalikan true untuk JCXZ
    family, tetapi `EqualitySuccessor` mengembalikan `SuccUnknown`
    (benar, karena JCXZ test register, bukan flag). Tidak ada helper
    terpisah "is this a register-test conditional jump" yang dipakai
    untuk membedakan path dataflow.
20. **Tidak ada decoder untuk `MOV` register-register ARM64
    (`MOV Xd, Xm` alias `ORR Xd, XZR, Xm`)** — `MOVOrr` mengembalikan
    hanya `rd`, bukan `rm`. Konsumen yang ingin track "MOV X0, X1 →
    X0 inherits X1's value" harus re-parse `rm = (raw >> 16) & 0x1F`
    sendiri. Ini adalah **operasi paling umum** di Dart AOT (register
    shuffling untuk calling convention) dan tidak ada decoder satu-panggilan.

Dampak agregat: konsumen (`internal/disasm`, `internal/typetrack`,
`internal/decompiler`, `internal/symbolmap`) **re-implement bit-slice
sendiri** untuk semua gap di atas, yang menyebabkan drift (sama seperti
yang sudah terjadi sebelum konsolidasi `arch/` ini dibuat — lihat header
komentar `decoders.go` baris 4-7). Setiap gap adalah kandidat langsung
untuk dipindahkan ke `arch/` sebagai decoder kanonik.

## Struktur Folder

```
internal/arch/
├── arm64/
│   ├── decoders.go          (650 baris) — bitmask decoders + DstRegsOfInst
│   └── decoders_test.go     (121 baris) — unit test untuk BL/B/BLR/IsRet/
│                                           IsBR/CondBranch/DstReg
└── x86/
    ├── decode.go            (74 baris)  — Walk/Decode/DecodeUntilBad linear
    │                                     sweep di atas x86asm
    ├── decode_test.go       (60 baris)  — TestDecodeBasic/BadByteRecovery/
    │                                     UntilBad/EarlyStop
    ├── helpers.go           (152 baris) — CanonReg/RelTarget/IsCondJump/
    │                                     EqualitySuccessor/DstRegsOfInst
    └── helpers_test.go      (153 baris) — TestCanonReg/RelTarget/IsCondJump/
                                           EqualitySuccessor/DstRegsOfInst
```

Tidak ada subfolder lain. Tidak ada `riscv/`, `arm/` (32-bit), `ia32/`.

## Gap Analysis

### Gap 1: MOVK / MOVN tidak didecode — pool index besar tidak ditrack

- **Deskripsi**: `arm64/decoders.go` hanya punya `MOVZ64` (line 365).
  `MOVK Xd, #imm16, LSL #shift` dan `MOVN Xd, #imm16, LSL #shift` tidak
  punya decoder spesifik. SDK `LoadWordFromPoolIndex` case 3
  (`assembler_arm64.cc:459-463` @3.9.2) memakai `movz dst, #low; movk dst,
  #high; ldr dst, [PP, dst]` untuk pool offset > 32 KB. `StoreWordToPoolIndex`
  case 3 (`assembler_arm64.cc:479-483`) memakai pola yang sama dengan `str`.
  Tanpa decoder `MOVK`, konsumen yang ingin track "MOVZ+MOVK → imm32 di
  register" harus re-implement `(raw >> 5) & 0xFFFF` + `hw = (raw >> 21) &
  0x3` sendiri.

- **Bukti SDK**:
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` @3.9.2 baris
    459-463: `movz(dst, Immediate(offset_low), 0); movk(dst,
    Immediate(offset_high), 1); ldr(dst, Address(pp, dst));`
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` @3.9.2 baris
    479-483: `movz(TMP, Immediate(offset_low), 0); movk(TMP,
    Immediate(offset_high), 1); str(src, Address(pp, TMP));`
  - Verifikasi `gh api`:
    `repos/dart-lang/sdk/contents/runtime/vm/compiler/assembler/assembler_arm64.cc?ref=3.9.2`
    baris 439-463 (`LoadWordFromPoolIndex`) dan 467-483
    (`StoreWordFromPoolIndex`).

- **Dampak**: Pool entry dengan index besar (> 4096 entries = > 32 KB
  offset) tidak ditrack provenance-nya. Pool AOT untuk app besar
  (129k+ function) hampir selalu melebihi 32 KB. Konsumen
  (`PPAnnotator`, `touchInstrEffect`) hanya handle case 1 (`ldr [PP,
  #imm]`) dan case 2 (`add + ldr`), bukan case 3.

- **Usulan**: Tambah `MOVK64(raw) (rd, imm16, hw int, ok bool)` dan
  `MOVN64(raw) (rd, imm16, hw int, ok bool)` di `decoders.go`.
  `hw` = `(raw >> 21) & 0x3`, `imm16` = `(raw >> 5) & 0xFFFF`,
  `rd` = `raw & 0x1F`. Mask `MOVK64`: `0xFFA00000 == 0xF2800000`;
  `MOVN64`: `0xFFE00000 == 0x92800000`. Tambah juga helper
  `MOVWideImm(raw) (rd int, imm uint64, ok bool)` yang menggabungkan
  MOVZ+MOVK berurutan (stateful, perlu 2 instr) — atau ekspos
  per-instr dan biarkan konsumen match.

- **Prioritas**: **tinggi** — pool index besar adalah kasus umum di
  app production.

### Gap 2: LDRRegExtended mengunci option/S — tidak menangkap LDR [PP, Xm] tanpa shift

- **Deskripsi**: `LDRRegExtended` (line 182) memakai mask `0xFFE0FC00`
  dan value `0xF8607800`. Bit yang diunci:
  - `option` (bits 15:13) = `011` (LSL)
  - `S` (bit 12) = `1` (scaled by 3 for 64-bit)
  Ini menolak `LDR Xt, [Xn, Xm]` tanpa shift (`S=0, option=011`) dan
  `LDR Xt, [Xn, Xm, UXTX]` (`option=010`). SDK `LoadWordFromPoolIndex`
  case 3 memakai `ldr dst, Address(pp, dst)` yang di-emit sebagai
  `LDR Xt, [Xn, Xm, LSL #3]` **atau** `LDR Xt, [Xn, Xm]` tergantung
  apakah offset sudah kelipatan 8. Decoder saat ini hanya menangkap
  yang LSL #3.

- **Bukti SDK**:
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` @3.9.2 baris
    462: `ldr(dst, Address(pp, dst));` — `Address(Register base,
    Register reg)` di assembler_arm64.cc default-nya emit
    `LDR Xt, [Xn, Xm, UXTX]` (option=010, S=0) atau `LSL #3` (option=011,
    S=1) tergantung `Address::CanHoldOffset`.
  - ARM ARM section C4.1.66: `LDR (register)` encoding
    `11 111 0 00 1 0 1 Rm option S 10 Rn Rt`, mask `0xFFE00C00 ==
    0xF8600800` untuk base form (option & S free).

- **Dampak**: Pool load via register offset tanpa shift (offset yang
  sudah aligned 8-byte tetapi tidak butuh LSL) tidak didecode.
  Konsumen `touchInstrEffect` (dataflowarm64.go) hanya handle
  `LDRRegExtended` dengan `base == DISPATCH_TABLE_REG`, bukan `base
  == PP` — jadi gap ini ganda: decoder terlalu sempit **dan**
  konsumen tidak match PP.

- **Usulan**: Ganti `LDRRegExtended` ke mask `0xFFE00C00` value
  `0xF8600800` (option & S free), kembalikan `(base, rm, rt, option,
  S, ok)`. Konsumen yang butuh "scaled LSL #3" cek `option == 0b011
  && S == 1` sendiri. Atau tambah decoder terpisah
  `LDRRegExtendedScaled` (existing behavior) + `LDRRegExtendedRaw`
  (option/S free).

- **Prioritas**: **tinggi** — bersama Gap 1, ini buka pool index besar.

### Gap 3: LDP/STP hanya unsigned-offset — pre/post-index & signed-offset tidak didecode

- **Deskripsi**: `LDP64UnsignedOffset` (line 409) dan
  `STP64UnsignedOffset` (line 427) memakai mask `0xFFC00000` value
  `0xA9400000` / `0xA9000000`. Tiga varian lain tidak didecode:
  - **Pre-index**: `STP Xt1, Xt2, [Xn, #imm, pre-index]` (mask
    `0xFFC00000 == 0xA9800000`), `LDP ... pre-index` (`0xA9C00000`).
  - **Post-index**: `STP ... post-index` (`0xA8800000`), `LDP ...
    post-index` (`0xA8C00000`).
  - **Signed-offset**: sama dengan unsigned-offset untuk 64-bit pair
    (sudah ditangani, tetapi `DstRegsOfInst` line 448 memakai mask
    `0x3E400000 == 0x28400000` yang menangkap **semua** pair load/store
    termasuk pre/post-index — tetapi kemudian mengasumsikan `imm7 <<
    3` adalah unsigned offset, padahal pre/post-index `imm7` adalah
    signed).

  SDK `LoadDoubleWordFromPoolIndex` (`assembler_arm64.cc:491-548`
  @3.9.2) memakai `Address::PairOffset` yang bisa pre/post-index.
  SDK `EnterFrame`/`LeaveFrame` memakai `stp X29, X30, [SP, #-16,
  pre-index]` dan `ldp X29, X30, [SP, #16, post-index]` universal.

- **Bukti SDK**:
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` @3.9.2 baris
    491-548 (`LoadDoubleWordFromPoolIndex`) — 4 varian, semua `ldp`.
  - `runtime/vm/compiler/assembler/assembler_arm64.h` @3.9.2:
    `void TagAndPushPP() { add(TMP, PP, kHeapObjectTag); str(TMP,
    Address(SP, -1 * target::kWordSize, Address::PreIndex)); }` —
    pre-index store.
  - Verifikasi `gh api`:
    `repos/dart-lang/sdk/contents/runtime/vm/compiler/assembler/assembler_arm64.h?ref=3.9.2`
    baris 1643-1650 (`TagAndPushPP`).

- **Dampak**: `DstRegsOfInst` line 448 (`0x3E400000 == 0x28400000`)
  menangkap pre/post-index LDP/STP dan mengembalikan `[rt1, rt2]`
  (untuk load) — tetapi **offset-nya salah** (dianggap unsigned,
  padahal signed). Lebih buruk: konsumen yang panggil
  `LDP64UnsignedOffset` untuk pre-index instruction dapat `ok=false`
  (karena mask `0xFFC00000` menolak `0xA9C0...`), sehingga
  dataflow menganggap instruksi tidak menulis register sama sekali.

- **Usulan**: Tambah `LDP64PreIndex`, `LDP64PostIndex`,
  `STP64PreIndex`, `STP64PostIndex`. Atau generalisasi:
  `LDP64(raw) (base, rt1, rt2, off int, mode int, ok bool)` di mana
  `mode` = `0=unsigned, 1=pre, 2=post`. Sesuaikan `DstRegsOfInst`
  untuk menggunakan decoder ini.

- **Prioritas**: **tinggi** — `EnterFrame`/`LeaveFrame` adalah
  pola universal; tanpa ini prologue/epilogue register save/restore
  tidak ditrack.

### Gap 4: STR/LDR pre-index & post-index tidak didecode

- **Deskripsi**: `LDUR64`/`STUR64`/`LDUR32`/`STUR32`/`LDURH` (line
  196-275) menangani **unscaled signed imm9** (encoding `0x... 00
  imm9 00 Rn Rt`). Tiga varian lain tidak didecode:
  - **Pre-index**: `STR Xt, [Xn, #imm9, pre-index]` (mask
    `0xFFE00C00 == 0xF8000C00`), `LDR ... pre-index` (`0xF8400C00`).
  - **Post-index**: `STR ... post-index` (`0xF8000400`), `LDR ...
    post-index` (`0xF8400400`).

  SDK `Push(reg)` = `str reg, [SP, #-8, pre-index]`; `Pop(reg)` =
  `ldr reg, [SP, #8, post-index]` (`assembler_arm64.h:1590-1596`
  @3.9.2). Ini adalah **operasi stack frame paling dasar**.

- **Bukti SDK**:
  - `runtime/vm/compiler/assembler/assembler_arm64.h` @3.9.2 baris
    1590-1596: `void Push(Register reg) { ... str(reg, Address(SP,
    -1 * target::kWordSize, Address::PreIndex)); } void Pop(Register
    reg) { ... ldr(reg, Address(SP, 1 * target::kWordSize,
    Address::PostIndex)); }`
  - Verifikasi `gh api`:
    `repos/dart-lang/sdk/contents/runtime/vm/compiler/assembler/assembler_arm64.h?ref=3.9.2`
    baris 1590-1596.

- **Dampak**: `DstRegsOfInst` line 484-487 menangkap unscaled LDUR
  (`0xFFE00C00 == 0xF8400000`) tetapi **tidak** menangkap pre/post
  (`0xF8400C00` / `0xF8400400`). `Pop X19, [SP, #8, post-index]` di
  epilogue tidak dianggap menulis X19 — sehingga konsumen yang track
  callee-saved register restore (untuk reconstruct frame layout)
  melewatkan semua restore.

- **Usulan**: Tambah `LDR64PreIndex`, `LDR64PostIndex`,
  `STR64PreIndex`, `STR64PostIndex` (dan 32-bit counterpart). Atau
  generalisasi `LDR64(raw) (base, rt, off, mode, ok)`.

- **Prioritas**: **tinggi** — tanpa ini, prologue/epilogue analysis
  mustahil.

### Gap 5: ADRP / ADR tidak didecode spesifik

- **Deskripsi**: `DstRegsOfInst` line 552 mengklaim menangani
  `ADR/ADRP: mask 0x1F000000 == 0x10000000` dan mengembalikan `rd`.
  Tetapi **tidak ada decoder yang menghitung target absolut**:
  - `ADRP Xd, label` = `(PC & ~0xFFF) + (sign_extend(immhi:immlo, 21)
    << 12)`.
  - `ADR Xd, label` = `PC + sign_extend(immhi:immlo, 21)`.
  Dart AOT memakai ADRP+ADD untuk mengakses literal pool di PIC code
  dan `ExtractPC` memakai ADR (`adr X0, .+0`).

- **Bukti SDK**:
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` @3.9.2:
    `void Assembler::ExtractPC(Register dst) { adr(dst, 0); }` —
    memakai ADR untuk dapatkan PC.
  - Verifikasi `gh api`:
    `repos/dart-lang/sdk/contents/runtime/vm/compiler/assembler/assembler_arm64.cc?ref=3.9.2`
    — search `ExtractPC`.

- **Dampak**: Konsumen yang ingin track "ADRP X0, page; ADD X0, X0,
  #offset" → absolute address harus re-implement `immhi:immlo` bit
  slice sendiri. Tidak ada helper kanonik.

- **Usulan**: Tambah `ADRP(raw, pc) (target uint64, rd int, ok bool)`
  dan `ADR(raw, pc) (target uint64, rd int, ok bool)`. Encoding:
  - `ADRP`: `1 immlo 10000 immhi Rd`, mask `0x9F000000 == 0x90000000`.
  - `ADR`: `0 immlo 10000 immhi Rd`, mask `0x9F000000 == 0x10000000`.

- **Prioritas**: **menengah** — Dart AOT jarang memakai ADRP (sebagian
  besar pool access via PP), tetapi `ExtractPC` (ADR) muncul di
  stub code.

### Gap 6: BRK / HLT / SVC tidak didecode

- **Deskripsi**: Tidak ada decoder untuk exception-generating
  instructions. Dart memakai `BRK #imm` untuk breakpoint di debug
  build dan `SVC #0` di simulator mode; `HLT #imm` untuk halt.
  `DstRegsOfInst` tidak menangani ketiganya (tidak menulis GPR —
  benar), tetapi **tidak ada predikat `IsBRK`/`IsSVC`** untuk
  konsumen yang ingin deteksi "ini adalah breakpoint / trap" sebagai
  terminasi fungsi.

- **Bukti SDK**:
  - `runtime/vm/constants_arm64.h` @3.9.2 baris 696-702:
    `enum ExceptionGenOp { ExceptionGenMask = 0xff000000,
    ExceptionGenFixed = CompareBranchFixed | B31 | B30, SVC =
    ExceptionGenFixed | B0, BRK = ExceptionGenFixed | B21, HLT =
    ExceptionGenFixed | B22, };`
  - Verifikasi `gh api`:
    `repos/dart-lang/sdk/contents/runtime/vm/constants_arm64.h?ref=3.9.2`
    baris 696-702.

- **Dampak**: Konsumen yang ingin beda "fungsi berakhir dengan RET
  vs BRK vs bad-byte" harus re-implement bitmask. Saat ini
  `IsRet` ada, `IsBRK`/`IsSVC` tidak.

- **Usulan**: Tambah `IsBRK(raw) bool`, `IsSVC(raw) bool`,
  `IsHLT(raw) bool`, dan `BRKImm(raw) (imm16 int, ok bool)`.
  Encoding: `BRK` mask `0xFFE0001F == 0xD4200000`, `SVC` mask
  `0xFFE0001F == 0xD4000001`, `HLT` mask `0xFFE0001F == 0xD4400000`.

- **Prioritas**: **rendah** — Dart AOT release jarang memakai BRK
  (hanya di debug build), tetapi berguna untuk identifikasi stub
  yang sengaja trap.

### Gap 7: Floating-point load/store & FMOV tidak didecode

- **Deskripsi**: Dart AOT memakai `LDR Dt, [Xn, #imm]` (V=1) untuk
  load double dari pool, `STR Dt, [Xn, #imm]` (V=1) untuk store, dan
  `FMOV Dd, #imm` untuk double constant. Decoder saat ini
  (`LDR64UnsignedOffset` dst.) memakai `V=0` (bit 26 = 0), sehingga
  semua FP load/store ditolak. `DstRegsOfInst` juga tidak
  mengembalikan V register.

  SDK `BoxDoubleStubABI` (`constants_arm64.h:325-329` @3.9.2):
  `kValueReg = V0`. `DoubleToIntegerStubABI`: `kInputReg = V0`.
  Jadi V0 adalah register kritis untuk double flow.

- **Bukti SDK**:
  - `runtime/vm/constants_arm64.h` @3.9.2 baris 325-329:
    `struct BoxDoubleStubABI { static constexpr FpuRegister
    kValueReg = V0; static constexpr Register kTempReg = R1;
    static constexpr Register kResultReg = R0; };`
  - Verifikasi `gh api`:
    `repos/dart-lang/sdk/contents/runtime/vm/constants_arm64.h?ref=3.9.2`
    baris 325-329.

- **Dampak**: Tracker value tidak tahu `V0` ditulis oleh
  `BoxDoubleStub` return. Double constant yang dimuat dari pool via
  `LDR D0, [PP, #imm]` tidak dianotasi (FP load dari PP sama sekali
  tidak ditrack).

- **Usulan**: Tambah `LDRDUnsignedOffset(raw) (base, rt, off, ok)`
  (V=1, size=11, opc=00 untuk 64-bit FP load), `STRDUnsignedOffset`,
  `FMOVDImm(raw) (rd int, imm uint8, ok bool)`. Pertimbangkan
  `DstRegsOfInst` mengembalikan V register dengan namespace terpisah
  (mis. `[]FpuReg` atau `[]int` dengan offset +32).

- **Prioritas**: **menengah** — double flow adalah minoritas tetapi
  critical untuk math-heavy app.

### Gap 8: DstRegsOfInst salah untuk MOVK — dianggap full-write, padahal partial

- **Deskripsi**: `DstRegsOfInst` line 521 menangani `MOVZ / MOVK /
  MOVN` dengan mask `0x1F800000 == 0x12800000` dan mengembalikan
  `[]int{rd}`. Tetapi **MOVK menulis sebagian register** (16-bit slice
  pada posisi `hw*16`), membaca sisanya dari nilai lama. Secara
  dataflow, `MOVK X0, #high, LSL #16` adalah **read-modify-write**,
  bukan full define. Tracker yang menganggap MOVK = define penuh
  akan kehilangan dependensi pada MOVZ sebelumnya.

- **Bukti SDK**:
  - ARM ARM C4.1.30: `MOVK` merujuk "Move wide with keep" —
    "preserves the other bits of the destination register".
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` @3.9.2 baris
    461-462: `movz(dst, Immediate(offset_low), 0); movk(dst,
    Immediate(offset_high), 1);` — MOVK di sini menggabungkan
    high 16-bit ke low 16-bit yang sudah ditulis MOVZ.

- **Dampak**: Dataflow yang menganggap MOVK = kill + define penuh
  akan salah track "X0 setelah MOVZ+MOVK = imm32" jika ada path
  lain yang hanya MOVK tanpa MOVZ (yang seharusnya tidak mungkin
  tetapi tracker tidak tahu).

- **Usulan**: Pisahkan case di `DstRegsOfInst`:
  - `MOVZ`/`MOVN` (op=00 / op=10): full define, kembalikan `[]int{rd}`.
  - `MOVK` (op=11): partial define — kembalikan `[]int{rd}` tetapi
    tandai sebagai "merge" (perlu konvensi baru, mis. return
    `[]int{rd}` dengan flag terpisah, atau ekspos `MOVKPartial`).
  Minimal: dokumentasikan bahwa `MOVK` adalah RMW dan konsumen
  dataflow harus cek `raw & 0x60000000` untuk op.

- **Prioritas**: **menengah** — bug halus, dampak terbatas pada
  tracker yang mengasumsikan MOVK = define penuh.

### Gap 9: x86 DstRegsOfInst dangkal — MUL/IMUL/CMOV/XCHG/LEA/POPCNT tidak ditangani

- **Deskripsi**: `x86/helpers.go::DstRegsOfInst` (line 132) hanya
  cek `Args[0]` register. Instruksi yang menulis register **bukan
  di Args[0]** atau menulis **multi register** tidak ditangani:
  - `MUL`/`IMUL` (1-operand form): menulis RDX:RAX, bukan Args[0].
  - `IMUL` (2/3-operand form): menulis Args[0] (sudah ditangani
    secara default, tetapi tidak ada kasus khusus untuk 1-operand).
  - `CMOVcc`: menulis Args[0] **conditional**, bukan unconditional.
  - `XCHG`: menulis **kedua** operand.
  - `LEA`: menulis Args[0] tetapi **bukan memory read** — tracker
    yang menganggap LEA = memory access akan salah.
  - `POPCNT`/`LZCNT`/`TZCNT`: menulis Args[0].
  - `MOVQ xmm, r64` / `MOVQ r64, xmm`: menulis XMM register, bukan
    GP — `CanonReg` kembalikan -1 untuk XMM, sehingga `DstRegsOfInst`
    kembalikan nil.

- **Bukti SDK**:
  - `runtime/vm/constants_x64.h` @3.9.2: `const Register THR =
    R14; const Register PP = R15; const Register CODE_REG = R12;
    const Register IC_DATA_REG = RBX; const Register ARGS_DESC_REG
    = R10; const Register TMP = R11; const Register SPREG = RSP;
    const Register FPREG = RBP; const Register CALLEE_SAVED_TEMP =
    RBX;` — ABI register set x64.
  - Verifikasi `gh api`:
    `repos/dart-lang/sdk/contents/runtime/vm/constants_x64.h?ref=3.9.2`
    baris 118-130.

- **Dampak**: Tracker value x86 kehilangan banyak define. `MUL`
  dianggap tidak menulis apa-apa. `CMOV` dianggap unconditional
  write (salah — harus conditional). `LEA` dianggap menulis
  register tetapi tracker tidak tahu itu bukan memory load.

- **Usulan**: Tambah kasus eksplisit di `DstRegsOfInst`:
  - `MUL, IMUL` (1-operand): return `[]int{0, 2}` (RAX, RDX).
  - `CMOVcc` family: return `[]int{canon(Args[0])}` tetapi tandai
    conditional (perlu konvensi baru).
  - `XCHG`: return `[]int{canon(Args[0]), canon(Args[1])}`.
  - `LEA`: return `[]int{canon(Args[0])}` (sudah ditangani default,
    tetapi dokumentasikan).
  - `POPCNT, LZCNT, TZCNT`: return `[]int{canon(Args[0])}` (sudah
    ditangani default).

- **Prioritas**: **menengah** — x86 adalah target second-class
  di AOTopsy, tetapi gap ini membuat tracker value x86 jauh lebih
  buruk daripada ARM64.

### Gap 10: EqualitySuccessor x86 hanya JE/JNE — magnitude test tidak narrow

- **Deskripsi**: `x86/helpers.go::EqualitySuccessor` (line 117)
  hanya return `SuccEqual` untuk JE dan `SuccNotEqual` untuk JNE.
  JA/JB/JG/JL (magnitude) return `SuccUnknown` (benar). Tetapi
  **tidak ada helper terpisah** untuk "magnitude test narrow":
  `JA` membuktikan `CMP left > right` di taken edge, yang bisa
  narrow class-id range ("CMP X0, #kMaxCid; JA outside_range").
  Typetrack ARM64 punya `equalitySuccessor` di `intraproc.go` yang
  setara — gap ini paralel di kedua arch.

- **Bukti SDK**:
  - `runtime/vm/compiler/backend/flow_graph_compiler_x64.cc`
    @3.9.2: emit `cmp` + `ja`/`jb`/`jg`/`jl` untuk range check
    class-id dan Smi tag.
  - Verifikasi `gh api`:
    `repos/dart-lang/sdk/contents/runtime/vm/compiler/backend/flow_graph_compiler_x64.cc?ref=3.9.2`.

- **Dampak**: Narrow tipe via class-id range check (`CMP X0, #cid;
  B.LT not_int`) tidak jalan di x86. Hanya equality (JE/JNE) yang
  narrow.

- **Usulan**: Tambah `MagnitudeSuccessor(op, numSuccs) (successor,
  relation int)` di mana `relation` = `1=GT, -1=LT, 2=GE, -2=LE,
  3=UGT, -3=ULT, ...`. Atau ekspos `CondRelation(op) (relation int)`
  yang dipakai konsumen untuk narrow.

- **Prioritas**: **menengah** — narrow range adalah fitur RE useful
  untuk class-id recovery.

### Gap 11: Tidak ada register ABI table di arch/

- **Deskripsi**: `x86/helpers.go::CanonReg` hanya fold width (RAX/
  EAX/AX/AL → 0). Tidak ada konstanta `THR=14, PP=15, CODE_REG=12,
  IC_DATA=3, ARGS_DESC=10, FPREG=5, SPREG=4, TMP=11,
  CALLEE_SAVED_TEMP=3, kExceptionObjectReg=0,
  kStackTraceObjectReg=2, kWriteBarrierObjectReg=1,
  kWriteBarrierValueReg=0, kWriteBarrierSlotReg=13` di paket ini.
  ARM64 bahkan tidak punya `CanonReg` sama sekali — register 0..30
  langsung dipakai sebagai int, dan konstanta `THR=26, PP=27,
  DT=21, NULL_REG=22, HEAP_BITS=28, CODE_REG=24, SPREG=15,
  FPREG=29, IC_DATA=5, ARGS_DESC=4, TMP=16, TMP2=17, FUNCTION=0,
  CALLEE_SAVED_TEMP=19, CALLEE_SAVED_TEMP2=20,
  kExceptionObjectReg=0, kStackTraceObjectReg=1,
  kWriteBarrierObjectReg=1, kWriteBarrierValueReg=0,
  kWriteBarrierSlotReg=25, kResultReg=0, kHeapBase=28` semuanya
  di-hardcode di konsumen (`internal/sdk`, `internal/disasm`,
  `internal/typetrack`).

  `arch/` seharusnya adalah tempat kanonik untuk "register N di
  arch ini berperan sebagai apa di Dart ABI". Saat ini peran itu
  hidup di `internal/sdk` (yang sudah diverifikasi via
  `tools/extract_thr.go -check`), tetapi **tidak dikenal arch/**,
  sehingga `DstRegsOfInst` tidak bisa mengembalikan "THR" sebagai
  symbolic register.

- **Bukti SDK**:
  - `runtime/vm/constants_x64.h` @3.9.2 baris 118-130: register
    alias lengkap (THR=R14, PP=R15, CODE_REG=R12, IC_DATA_REG=RBX,
    ARGS_DESC_REG=R10, TMP=R11, SPREG=RSP, FPREG=RBP,
    CALLEE_SAVED_TEMP=RBX).
  - `runtime/vm/constants_arm64.h` @3.9.2 baris 139-160: register
    alias lengkap (TMP=R16, TMP2=R17, PP=R27,
    DISPATCH_TABLE_REG=R21, CODE_REG=R24, FUNCTION_REG=R0,
    FPREG=R29, SPREG=R15, IC_DATA_REG=R5, ARGS_DESC_REG=R4,
    THR=R26, CALLEE_SAVED_TEMP=R19, CALLEE_SAVED_TEMP2=R20,
    HEAP_BITS=R28, NULL_REG=R22).
  - Verifikasi `gh api`:
    `repos/dart-lang/sdk/contents/runtime/vm/constants_arm64.h?ref=3.9.2`
    baris 139-160 dan `contents/runtime/vm/constants_x64.h?ref=3.9.2`
    baris 118-130.

- **Dampak**: Konsumen harus mapping ulang int → symbolic register
  sendiri. Tidak ada helper `RegName(arm64, 26) == "THR"` atau
  `IsTHR(arm64, 26) == true` di arch/. Drift terjadi jika SDK
  mengubah ABI (mis. Dart 2.12 vs 3.9.2 — lihat AGENTS.md "Known
  limits" tentang `DartCallingConvention` yang first appears di
  3.4.3).

- **Usulan**: Tambah `arm64/abi.go` dengan konstanta
  `THR=26, PP=27, DT=21, NULL_REG=22, HEAP_BITS=28, CODE_REG=24,
  SPREG=15, FPREG=29, IC_DATA=5, ARGS_DESC=4, TMP=16, TMP2=17,
  FUNCTION=0, CALLEE_SAVED_TEMP=19, CALLEE_SAVED_TEMP2=20,
  LR=30, kExceptionObjectReg=0, kStackTraceObjectReg=1,
  kWriteBarrierObjectReg=1, kWriteBarrierValueReg=0,
  kWriteBarrierSlotReg=25, kResultReg=0` dan helper `RegName(int)
  string`, `IsReserved(int) bool`, `IsCalleeSaved(int) bool`,
  `IsArgument(int) bool`. Tambah `x86/abi.go` dengan konstanta
  setara. **Pertimbangkan versi-tag**: Dart 2.12 ARM64 tidak punya
  `DartCallingConvention` (first appears 3.4.3), jadi tabel arg
  register berbeda per versi.

- **Prioritas**: **tinggi** — ini adalah root cause dari banyak
  re-implementasi di konsumen.

### Gap 12: DstRegsOfInst ARM64 salah untuk LDP pre/post-index

> **[REFUTED 2026-09-01]** Bit 22 (`L`) **ada** di dalam mask `0x3E400000` dan
> value `0x28400000` menuntutnya =1, jadi STP tidak pernah masuk cabang ini.
> Cek: `0xA9000000 & 0x3E400000 = 0x28000000 ≠ 0x28400000`. Tidak ada bug di
> sini; "Prioritas tinggi — bug dataflow konkret" gugur.

- **Deskripsi**: `DstRegsOfInst` line 448 memakai mask
  `0x3E400000 == 0x28400000` untuk menangkap "Load Pair (LDP)".
  Mask ini menangkap **semua** pair load/store (32-bit, 64-bit,
  LDPSW, pre/post-index, signed-offset). Tetapi:
  - Line 449-458 mengasumsikan `rt1 = raw & 0x1F`, `rt2 = (raw >>
    10) & 0x1F` — **benar untuk semua varian** (field position sama).
  - **Tetapi tidak bedakan load vs store**: bit 22 (`L`) menentukan
    load (1) vs store (0). Mask `0x3E400000` tidak mengunci bit 22,
    sehingga **STP pre/post-index juga masuk** dan dianggap menulis
    `rt1, rt2` — padahal STP **membaca** rt1, rt2 (sebagai source).

  Ini adalah bug: `STP X29, X30, [SP, #-16, pre-index]` (store pair
  di prologue) akan dianggap menulis X29 dan X30 oleh
  `DstRegsOfInst`, padahal sebaliknya **membaca** keduanya untuk
  disimpan ke stack.

- **Bukti SDK**:
  - ARM ARM C4.1.62-65: `LDP` (L=1) menulis Rt1, Rt2; `STP` (L=0)
    membaca Rt1, Rt2.
  - `runtime/vm/compiler/assembler/assembler_arm64.h` @3.9.2:
    `TagAndPushPP` memakai `str TMP, [SP, -8, pre-index]` (store,
    bukan load).

- **Dampak**: Dataflow yang pakai `DstRegsOfInst` untuk determine
  "register ini di-define di sini" akan salah: STP dianggap define,
  sehingga register yang sebenarnya di-save dianggap di-overwrite.
  Tracker value akan kehilangan provenance register callee-saved
  setelah prologue.

- **Usulan**: Tambah cek bit 22 (`L`) di `DstRegsOfInst` line 448:
  ```go
  if raw&0x3E400000 == 0x28400000 {
      if raw&(1<<22) == 0 { // STP — read, not write
          return nil
      }
      // ... existing LDP logic
  }
  ```
  Atau pecah mask: `LDP` saja yang kembalikan `[rt1, rt2]`,
  `STP` kembalikan `nil` (atau list "read register" terpisah).

- **Prioritas**: **tinggi** — bug dataflow konkret.

### Gap 13: CondBranch mengecualikan B.AL/B.NV — tidak ada AnyBranch helper

- **Deskripsi**: `CondBranch` (line 73) return `ok=false` untuk
  B.AL (cond=14) dan B.NV (cond=15) karena "unconditional despite
  using B.cond encoding". Benar untuk "is this conditional", tetapi
  konsumen yang ingin **target branch B.AL** (yang masih punya
  target address) harus panggil `B()` terpisah — dan `B()` memakai
  mask `0xFC000000 == 0x14000000` yang **menolak** B.AL (encoding
  `0x54000000 | (imm19 << 5) | 14`). Tidak ada helper `AnyBranch(raw,
  pc) (target, kind, ok)` di mana `kind` = `B_BL, B_COND, CBZ,
  CBNZ, TBZ, TBNZ, B_AL, B_NV`.

- **Bukti SDK**:
  - ARM ARM C1.2.3: B.AL dan B.NV menggunakan B.cond encoding
    tetapi unconditional.
  - `runtime/vm/constants_arm64.h` @3.9.2 baris 670-672: `AL = 14,
    NV = 15, kNumberOfConditions = 16`.

- **Dampak**: Konsumen CFG (`branch.go::DecodeBranch`) harus
  fallback ke `B()` lalu `CondBranch()` lalu special-case B.AL.
  Tidak ada satu-panggilan.

- **Usulan**: Tambah `AnyBranch(raw, pc) (target uint64, kind int,
  ok bool)` di mana `kind` = `KindB, KindBL, KindBCond, KindCBZ,
  KindCBNZ, KindTBZ, KindTBNZ, KindBAL, KindBNV`. Konsumen yang
  hanya perlu "all branch targets" panggil satu helper.

- **Prioritas**: **rendah** — ergonomis, bukan correctness.

### Gap 14: CondBranch tidak mengembalikan Rt / sf / bit-position

- **Deskripsi**: `CondBranch` hanya mengembalikan `target, ok`.
  Untuk CBZ/CBNZ: tidak mengembalikan `Rt` (register yang di-test)
  dan `sf` (32 vs 64-bit). Untuk TBZ/TBNZ: tidak mengembalikan
  `bit-position` (b5 + b40) dan `Rt`. Konsumen typetrack yang ingin
  narrow "register yang di-CBZ dengan 0 adalah non-null di edge
  not-taken" harus re-parse `raw & 0x1F` dan `raw >> 31` sendiri.

- **Bukti SDK**:
  - ARM ARM C4.1.18-21: CBZ/CBNZ encoding `sf 011010 op imm19 Rt`,
    `sf` = bit 31, `Rt` = bits 4:0.
  - ARM ARM C4.1.84-85: TBZ/TBNZ encoding `b5 011011 op b40 imm14
    Rt`, `bit-position` = `(b5 << 5) | b40`, `Rt` = bits 4:0.
  - Dart memakai `TBZ X0, #kSmiTagShift, ...` untuk Smi check —
    bit-position adalah semantic signal.

- **Dampak**: Narrow tipe via "CBZ X0, label → X0 non-null di
  fall-through" dan "TBZ X0, #0, label → X0 bukan Smi di
  fall-through" tidak jalan otomatis; konsumen harus re-implement
  bit-slice.

- **Usulan**: Ubah signature `CondBranch` ke `(raw, pc) (target,
  rt, sf, bitPos, kind, ok)` atau tambah decoder terpisah
  `CBZDetails(raw) (rt, sf, target, ok)`, `TBZDetails(raw) (rt,
  bitPos, target, ok)`. Pertimbangkan backward-compat: tambah
  fungsi baru, jangan break yang lama.

- **Prioritas**: **menengah** — narrow tipe adalah fitur RE useful.

### Gap 15: Tidak ada decoder untuk CMP/CMN/TST immediate yang mengembalikan operand

- **Deskripsi**: `SUBS32Immediate` (line 341) menangani `SUBS Wd,
  Wn, #imm` dan menyebut "CMP Wn, #imm is an alias for SUBS WZR,
  Wn, #imm". Tetapi tidak ada helper `CMPImmediate(raw) (rn, imm,
  ok)` yang konsumen bisa pakai langsung untuk "CMP X0, #cid" →
  narrow. Konsumen harus re-implement `imm12 + shift` bit-slice.
  Demikian juga `CMN` (ADDS alias) dan `TST` (ANDS alias) tidak
  punya decoder.

- **Bukti SDK**:
  - ARM ARM C4.1.27-28: CMP = SUBS XZR, ...; CMN = ADDS XZR, ...;
    TST = ANDS XZR, ...
  - Dart AOT memakai `CMP X0, #kSmiTagMask`, `TST X0, #kTagMask`
    untuk tag check.

- **Dampak**: Narrow tipe via CMP immediate tidak otomatis;
  konsumen (`typetrack/intraproc_handlers.go`) harus re-parse.

- **Usulan**: Tambah `CMPImmediate64(raw) (rn, imm, ok)`,
  `CMPImmediate32(raw) (rn, imm, ok)`, `TSTImmediate(raw) (rn,
  imm, ok)`. Atau ekspos `SUBSImmediate` dengan flag `isCMP =
  (rd == 31)`.

- **Prioritas**: **menengah** — narrow tipe adalah fitur RE useful.

### Gap 16: x86 Walk tidak ekspos prefix secara terstruktur

- **Deskripsi**: `x86/decode.go::Decoded` struct hanya punya
  `Inst, VA, Len, Bad`. `x86asm.Inst.Prefix` ada tetapi tidak
  di-ekspos. Dart AOT x86 memakai `REP MOVSB` untuk memcpy,
  `LOCK CMPXCHG` untuk atomic, `REX` prefix untuk 64-bit. Konsumen
  yang ingin deteksi `REP MOVSB` harus akses `Inst.Prefix`
  langsung.

- **Bukti SDK**:
  - `runtime/vm/compiler/assembler/assembler_x64.cc` @3.9.2:
    `movsdq` untuk memcpy, `lock cmpxchg` untuk atomic.
  - Verifikasi `gh api`:
    `repos/dart-lang/sdk/contents/runtime/vm/compiler/assembler/assembler_x64.cc?ref=3.9.2`.

- **Dampak**: Tidak ada helper `IsRepMovSB(inst) bool` atau
  `IsAtomic(inst) bool` di arch/x86.

- **Usulan**: Tambah field `Prefix []x86asm.Prefix` di `Decoded`,
  atau helper `HasPrefix(inst, prefix) bool`, `IsStringOp(inst)
  bool`, `IsAtomic(inst) bool`.

- **Prioritas**: **rendah** — minoritas instruksi, tetapi berguna
  untuk identifikasi memcpy/atomic.

### Gap 17: Tidak ada IsCall / IsJump / IsReturn predikat ARM64

- **Deskripsi**: `BL`, `BLR`, `IsRet`, `IsBR` ada sebagai decoder
  terpisah, tetapi tidak ada predikat satu-panggilan. Konsumen
  (`branch.go::DecodeBranch`, `dataflowarm64.go::touchInstrEffect`)
  masing-masing re-derive dengan bitmask sendiri. Tidak ada
  `IsCall(raw) bool` (BL atau BLR), `IsJump(raw) bool` (B atau BR),
  `IsReturn(raw) bool` (RET atau `BR X30` alias RET).

- **Bukti SDK**:
  - `runtime/vm/instructions_arm64.cc` @3.9.2: `Pattern::IsCall`
    dan `Pattern::IsReturn` membedakan BL/BLR vs RET.
  - Verifikasi `gh api`:
    `repos/dart-lang/sdk/contents/runtime/vm/instructions_arm64.cc?ref=3.9.2`.

- **Dampak**: Konsumen re-implement predikat. Drift terjadi jika
  satu konsumen menganggap `BR X30` = RET tetapi yang lain tidak.

- **Usulan**: Tambah `IsCall(raw) bool` (BL || BLR), `IsJump(raw)
  bool` (B || BR), `IsReturn(raw) bool` (IsRet || (IsBR && rn ==
  30)). Pertimbangkan juga `IsTailCall(raw) bool` (B ke entry point
  + cek target).

- **Prioritas**: **menengah** — ergonomis + anti-drift.

### Gap 18: MOVOrr tidak mengembalikan rm — operasi paling umula tidak ditrack

- **Deskripsi**: `MOVOrr` (line 395) mendeteksi `MOV Xd, Xm` (alias
  `ORR Xd, XZR, Xm`) tetapi hanya mengembalikan `rd`, bukan `rm`.
  Konsumen yang ingin track "MOV X0, X1 → X0 inherits X1's value"
  harus re-parse `rm = (raw >> 16) & 0x1F` sendiri. Ini adalah
  **operasi paling umum** di Dart AOT (register shuffling untuk
  calling convention, `mov R0, R1` untuk pindahkan receiver ke
  arg-0 slot, dll).

- **Bukti SDK**:
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` @3.9.2:
    `mov(reg, reg)` di-emit sebagai `orr reg, ZR, reg`.
  - `runtime/vm/compiler/backend/flow_graph_compiler_arm64.cc`
    @3.9.2: banyak `__ mov(R0, R1)` untuk calling convention
    shuffle.

- **Dampak**: Tracker value tidak otomatis tahu "MOV X0, X1 → X0
  inherits X1". Konsumen (`typetrack/intraproc_handlers.go`) harus
  re-parse bit-slice.

- **Usulan**: Ubah signature `MOVOrr(raw) (rd, rm int, ok bool)`.
  Backward-compat: tambah `MOVOrrSrc(raw) (rm int, ok bool)` atau
  pecah ke `MOVReg(raw) (rd, rm, ok)`.

- **Prioritas**: **tinggi** — operasi paling umum, gap ini
  menyebabkan banyak re-implementasi.

### Gap 19: x86 IsCondJump tidak bedakan register-test vs flag-test

- **Deskripsi**: `x86/helpers.go::IsCondJump` (line 100) mengembalikan
  `true` untuk JCXZ/JECXZ/JRCXZ (register-test) dan JE/JNE/JA/JB
  (flag-test). `EqualitySuccessor` mengembalikan `SuccUnknown` untuk
  JCXZ family (benar), tetapi **tidak ada helper terpisah** "is
  this a register-test conditional jump" yang dipakai untuk
  membedakan path dataflow. Konsumen yang ingin tahu "JCXZ tidak
  narrow dari CMP sebelumnya" harus cek op == JCXZ sendiri.

- **Bukti SDK**:
  - x86 ISA: JCXZ/JECXZ/JRCXZ test RCX/ECX, bukan flags.
  - Dart AOT x86 jarang memakai JCXZ family, tetapi ada di
    simulator.

- **Dampak**: Minor — konsumen yang mengasumsikan semua cond jump
  berasal dari CMP akan salah untuk JCXZ.

- **Usulan**: Tambah `IsRegTestCondJump(op) bool` yang return true
  untuk JCXZ/JECXZ/JRCXZ. Dokumentasikan bahwa `EqualitySuccessor`
  return `SuccUnknown` untuk op ini.

- **Prioritas**: **rendah** — edge case.

### Gap 20: Tidak ada decoder untuk ADD/SUB extended register

- **Deskripsi**: `DstRegsOfInst` line 592 menangani "Add/Sub
  extended register" (mask `0x1FE00000 == 0x0B200000`) dan
  mengembalikan `rd`. Tetapi **tidak ada decoder spesifik** yang
  mengembalikan `(rd, rn, rm, extend, shift)`. Dart AOT memakai
  `add Xd, Xn, Xm, UXTB` untuk zero-extend narrow, `add Xd, Xn,
  Xm, SXTW` untuk sign-extend 32-bit ke 64-bit (umum di string
  loop index).

- **Bukti SDK**:
  - ARM ARM C4.1.4-5: `ADD (extended register)` encoding
    `sf 0 0 01011 opt 1 Rm imm3 Rn Rd`, opt = extend type
    (UXTB, UXTH, UXTW, UXTX, SXTB, SXTH, SXTW, SXTX).
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` @3.9.2:
    `add(reg, reg, Operand(reg, SXTW))` untuk sign-extend.

- **Dampak**: Tracker yang ingin tahu "ADD X0, X1, X2, SXTW → X0
  = X1 + sign_extend(X2)" harus re-parse opt field sendiri.

- **Usulan**: Tambah `ADD64Extended(raw) (rd, rn, rm, opt, shift,
  ok)` dan `SUB64Extended` setara.

- **Prioritas**: **menengah** — narrow type via extend adalah RE
  signal.

## Register Tracking Gaps

### ARM64 register yang seharusnya ditrack sebagai symbolic ABI

Berdasarkan `runtime/vm/constants_arm64.h` @3.9.2 baris 139-160
(verifikasi `gh api`):

| Register | Konstanta SDK | Ditrack di arch/? | Ditrack di konsumen? |
|----------|---------------|-------------------|----------------------|
| R0 | FUNCTION_REG / kResultReg / kExceptionObjectReg | ❌ | ✅ di sdk/ |
| R1 | kStackTraceObjectReg / kWriteBarrierObjectReg | ❌ | ✅ di sdk/ |
| R4 | ARGS_DESC_REG | ❌ | ✅ di sdk/ |
| R5 | IC_DATA_REG | ❌ | ✅ di sdk/ |
| R15 | SPREG (Dart SP) | ❌ | ✅ di sdk/ |
| R16 | TMP (IP0) | ❌ | ✅ di sdk/ |
| R17 | TMP2 (IP1) | ❌ | ✅ di sdk/ |
| R19 | CALLEE_SAVED_TEMP | ❌ | ❌ (gap) |
| R20 | CALLEE_SAVED_TEMP2 | ❌ | ❌ (gap) |
| R21 | DISPATCH_TABLE_REG | ❌ | ✅ di sdk/ |
| R22 | NULL_REG | ❌ | ✅ di sdk/ |
| R24 | CODE_REG | ❌ | ✅ di sdk/ |
| R25 | kWriteBarrierSlotReg | ❌ | ❌ (gap) |
| R26 | THR | ❌ | ✅ di sdk/ |
| R27 | PP | ❌ | ✅ di sdk/ |
| R28 | HEAP_BITS | ❌ | ✅ di sdk/ |
| R29 | FPREG (FP) | ❌ | ✅ di sdk/ |
| R30 | LR | ❌ | ✅ di sdk/ |

**Gap konkret**:
- `CALLEE_SAVED_TEMP` (R19) dan `CALLEE_SAVED_TEMP2` (R20) tidak
  ditrack di mana pun — padahal Dart memakai ini untuk value
  yang harus survive across C++ call (mis. `BoxDoubleStub`).
- `kWriteBarrierSlotReg` (R25) tidak ditrack — padahal write
  barrier stub memakai ini sebagai slot address.
- `arch/arm64/` tidak punya tabel ABI sama sekali; semua mapping
  hidup di `internal/sdk`.

### x86 register yang seharusnya ditrack sebagai symbolic ABI

Berdasarkan `runtime/vm/constants_x64.h` @3.9.2 baris 118-130
(verifikasi `gh api`):

| Register | Konstanta SDK | Ditrack di arch/? | Ditrack di konsumen? |
|----------|---------------|-------------------|----------------------|
| RAX (0) | FUNCTION_REG / kResultReg / kWriteBarrierValueReg | ❌ | ✅ di sdk/ |
| RBX (3) | IC_DATA_REG / CALLEE_SAVED_TEMP | ❌ | ✅ di sdk/ |
| RBP (5) | FPREG | ❌ | ✅ di sdk/ |
| RSP (4) | SPREG | ❌ | ✅ di sdk/ |
| R10 (10) | ARGS_DESC_REG | ❌ | ✅ di sdk/ |
| R11 (11) | TMP | ❌ | ✅ di sdk/ |
| R12 (12) | CODE_REG | ❌ | ✅ di sdk/ |
| R14 (14) | THR | ❌ | ✅ di sdk/ |
| R15 (15) | PP | ❌ | ✅ di sdk/ |
| RDX (2) | kStackTraceObjectReg | ❌ | ❌ (gap) |
| RCX (1) | (volatile, scratch) | ❌ | ❌ (gap) |

**Gap konkret**:
- `kStackTraceObjectReg` (RDX) tidak ditrack.
- `arch/x86/` tidak punya tabel ABI; `CanonReg` hanya fold width.

### FPU register

ARM64: `V0` = `BoxDoubleStubABI::kValueReg`, `DoubleToIntegerStubABI::kInputReg`,
`CallingConventions::kReturnFpuReg`. Tidak ada decoder FP load/store
di `arch/arm64/`. x86: XMM register tidak dikenal `CanonReg`
(returns -1).

## Fitur RE Missing/Incomplete

### Missing: Decoder untuk pool-index reconstruction (MOVZ+MOVK+LDR)

SDK `LoadWordFromPoolIndex` case 3 (`assembler_arm64.cc:459-463`)
memakai `movz + movk + ldr [PP, Xm]` untuk pool offset > 32 KB.
AOTopsy tidak punya decoder yang menggabungkan tiga instruksi ini
menjadi "pool index N". Konsumen harus match pola + decode
masing-masing instr sendiri. **Fitur RE yang hilang**: anotasi
otomatis "LDR X0, [PP, #12345]" untuk pool entry besar.

### Missing: Decoder untuk LDP-from-PP (IC call site)

SDK `LoadDoubleWordFromPoolIndex` (`assembler_arm64.cc:491-548`)
memakai LDP untuk load `(ic_data, code)` dari pool di setiap IC/
switchable call site. `arch/arm64` punya `LDP64UnsignedOffset`
tetapi tidak dipakai oleh konsumen untuk anotasi PP. **Fitur RE
yang hilang**: anotasi "LDP X5, LR, [PP, #N] → ic_data=pp[N],
code=pp[N+1]" yang buka resolve IC call site.

### Missing: Decoder untuk TBZ/TBNZ bit-position

`CondBranch` tidak mengembalikan bit-position. Dart memakai
`TBZ X0, #kSmiTagShift, ...` untuk Smi check — bit-position
adalah semantic signal yang bisa narrow "X0 adalah Smi di edge
taken". **Fitur RE yang hilang**: narrow tipe otomatis via
bit-position.

### Missing: Decoder untuk CMP immediate operand

`SUBS32Immediate` ada tetapi tidak ada helper `CMPImmediate`
yang langsung mengembalikan `(rn, imm)`. Dart memakai `CMP X0,
#cid` untuk class-id check — narrow "X0 adalah class cid N di
edge EQ". **Fitur RE yang hilang**: narrow class-id otomatis.

### Missing: Predikat IsCall / IsJump / IsReturn / IsTailCall

Tidak ada predikat satu-panggilan. Konsumen re-derive. **Fitur
RE yang hilang**: identifikasi terminasi fungsi yang konsisten
lintas konsumen.

### Missing: Decoder untuk ADRP/ADR target absolut

`DstRegsOfInst` mengklaim menangani ADR/ADRP tetapi tidak
menghitung target. **Fitur RE yang hilang**: track ADRP+ADD
untuk akses literal pool PIC.

### Missing: Decoder untuk FP load/store & FMOV

Tidak ada decoder untuk `LDR Dt, [Xn, #imm]` (V=1) atau `FMOV
Dd, #imm`. **Fitur RE yang hilang**: track double constant dan
double flow dari pool.

### Missing: Decoder untuk BRK/SVC/HLT

Tidak ada predikat exception-generating. **Fitur RE yang
hilang**: identifikasi breakpoint/trap sebagai terminasi fungsi.

### Incomplete: DstRegsOfInst ARM64 untuk STP

`DstRegsOfInst` line 448 menangkap STP (store pair) dan
menganggap menulis rt1, rt2 — padahal STP **membaca**. Bug
dataflow konkret.

### Incomplete: DstRegsOfInst ARM64 untuk MOVK

`DstRegsOfInst` menganggap MOVK = define penuh, padahal RMW.
Bug halus dataflow.

### Incomplete: x86 DstRegsOfInst untuk MUL/CMOV/XCHG

`DstRegsOfInst` x86 tidak menangani MUL (RDX:RAX), CMOV
(conditional), XCHG (two-way). Tracker value x86 kehilangan
banyak define.

## Verifikasi SDK

### Verifikasi via grep MCP (`searchGitHub` by Vercel)

| Query | Repo | Hasil |
|-------|------|-------|
| `DartCallingConvention` | `dart-lang/sdk` | Konfirmasi `runtime/vm/constants_arm64.h` @main baris 648-653: `kCpuRegistersForArgs[] = {R1, R2, R3, R5, R6, R7}`, `kFpuRegistersForArgs[] = {V0, V1, V2, V3, V4, V5}`. |
| `const Register PP =` | `dart-lang/sdk` | Konfirmasi `runtime/vm/constants_arm64.h` @main baris 139-148: `PP = R27`, `DISPATCH_TABLE_REG = R21`, `CODE_REG = R24`, `THR = R26`, `NULL_REG = R22`, `HEAP_BITS = R28`, `TMP = R16`, `TMP2 = R17`, `SPREG = R15`, `FPREG = FP (R29)`, `IC_DATA_REG = R5`, `ARGS_DESC_REG = R4`, `FUNCTION_REG = R0`, `CALLEE_SAVED_TEMP = R19`, `CALLEE_SAVED_TEMP2 = R20`. |
| `const Register THR =` | `dart-lang/sdk` | Konfirmasi `runtime/vm/constants_x64.h` @main baris 118-130: `THR = R14`, `PP = R15`, `CODE_REG = R12`, `IC_DATA_REG = RBX`, `ARGS_DESC_REG = R10`, `TMP = R11`, `SPREG = RSP`, `FPREG = RBP`, `CALLEE_SAVED_TEMP = RBX`, `FUNCTION_REG = RAX`. |
| `kCpuRegistersForArgs` | `dart-lang/sdk` | Konfirmasi `runtime/vm/constants_x64.h` @main baris 692-697: `kCpuRegistersForArgs[] = {RDI, RSI, RDX, RBX, R8, R9}`, `kFpuRegistersForArgs[] = {XMM1, XMM2, XMM3, XMM4, XMM5, XMM6}`. |
| `LoadWordFromPoolIndex` | `dart-lang/sdk` | Konfirmasi `runtime/vm/compiler/assembler/assembler_arm64.cc` @main baris 504-525: 3 case (ldr, add+ldr, movz+movk+ldr). |
| `TagAndPushPP` | `dart-lang/sdk` | Konfirmasi `runtime/vm/compiler/assembler/assembler_arm64.h` @main baris 1643-1650: `add(TMP, PP, kHeapObjectTag); str(TMP, Address(SP, -1 * target::kWordSize, Address::PreIndex));` — pre-index store. |

### Verifikasi via `gh api` @ version tag 3.9.2

| Path | Baris | Konfirmasi |
|------|-------|------------|
| `runtime/vm/constants_arm64.h` | 139-160 | Register alias: `TMP=R16, TMP2=R17, PP=R27, DISPATCH_TABLE_REG=R21, CODE_REG=R24, FUNCTION_REG=R0, FPREG=R29, SPREG=R15, IC_DATA_REG=R5, ARGS_DESC_REG=R4, THR=R26, CALLEE_SAVED_TEMP=R19, CALLEE_SAVED_TEMP2=R20, HEAP_BITS=R28, NULL_REG=R22`. |
| `runtime/vm/constants_arm64.h` | 325-329 | `BoxDoubleStubABI::kValueReg = V0`. |
| `runtime/vm/constants_arm64.h` | 648-653 | `DartCallingConvention::kCpuRegistersForArgs = {R1, R2, R3, R5, R6, R7}`. |
| `runtime/vm/constants_arm64.h` | 670-672 | `AL = 14, NV = 15` — kondisi unconditional di encoding B.cond. |
| `runtime/vm/constants_arm64.h` | 696-702 | `ExceptionGenOp`: `SVC = ExceptionGenFixed | B0`, `BRK = ExceptionGenFixed | B21`, `HLT = ExceptionGenFixed | B22`. |
| `runtime/vm/constants_x64.h` | 118-130 | Register alias: `TMP=R11, PP=R15, SPREG=RSP, FPREG=RBP, IC_DATA_REG=RBX, ARGS_DESC_REG=R10, CODE_REG=R12, FUNCTION_REG=RAX, THR=R14, CALLEE_SAVED_TEMP=RBX`. |
| `runtime/vm/constants_x64.h` | 692-697 | `DartCallingConvention::kCpuRegistersForArgs = {RDI, RSI, RDX, RBX, R8, R9}`. |
| `runtime/vm/compiler/assembler/assembler_arm64.cc` | 439-463 | `LoadWordFromPoolIndex`: 3 case (ldr, add+ldr, movz+movk+ldr). |
| `runtime/vm/compiler/assembler/assembler_arm64.cc` | 467-483 | `StoreWordToPoolIndex`: 3 case setara. |
| `runtime/vm/compiler/assembler/assembler_arm64.cc` | 491-548 | `LoadDoubleWordFromPoolIndex`: 4 case (ldp, add+ldp, add+ldp split, add+add+ldp). |
| `runtime/vm/compiler/assembler/assembler_arm64.h` | 1590-1596 | `Push(reg) = str(reg, [SP, -8, pre-index])`, `Pop(reg) = ldr(reg, [SP, +8, post-index])`. |
| `runtime/vm/compiler/assembler/assembler_arm64.h` | 1643-1650 | `TagAndPushPP`: pre-index store. |

### Catatan versi

- `DartCallingConvention` (ARM64) **first appears di 3.4.3**, bukan
  2.12.0 — lihat AGENTS.md "Known limits". Tabel arg register di
  atas valid untuk 3.9.2; untuk 2.12 receiver di-pass via stack,
  bukan R1.
- `NULL_REG` (R22) dan `DART_ASSEMBLER_HAS_NULL_REG` — periksa
  apakah 2.12 sudah punya NULL_REG. Jika tidak, tracker yang
  mengasumsikan R22 = Null akan salah untuk 2.12.
- `DISPATCH_TABLE_REG` (R21) hanya ada di AOT mode — di JIT, R21
  adalah register allocator free.
