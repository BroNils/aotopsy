# RE Gap Analysis Report: internal/strxref

> **STATUS VERIFIKASI (2026-09-01)** — report ini **paling akurat** dari 29
> report; keenam gap CONFIRMED dan tidak ada koreksi. Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> Angka pendukung untuk Gap 1 (sweep bitmask atas seluruh `.so`):
>
> | sampel | form-1 `ldr [x27,#imm]` | form-2 `add+ldr` | LDP dari PP |
> |---|---|---|---|
> | dart-3.9.2-arm64 | 11.042 | **5.919** | 14 |
> | dart-3.12.2-**realapp** (produksi) | 25.885 | **38.716 (60%)** | 123 |
> | dart-3.13.0-arm64 | 10.686 | ~6.700 | 2 |
> | dart-2.12.0-arm64 | 10.807 | ~5.300 | 4 |
>
> Jadi klaim "mayoritas string di app ARM64 nyata terlewat" terbukti angka.
> Penilaian **P3 untuk Gap 6 (LDP)** juga terbukti benar (~0,2%) — dan itu
> bertentangan dengan penilaian P0 untuk fenomena yang sama di report
> `disasm`/`typetrack`/CONSOLIDATED; yang benar adalah penilaian di sini.
>
> Catatan cakupan (Gap 4 sudah menyinggungnya): jalur **pipeline utama** tidak
> buta — `analysis.ExtractStringRefs` memakai `PeepholeState` (`Kind:"PP_peep"`)
> dan `typetrack` punya `LatticePPBase`. Yang buta hanya IR decompiler
> (`isARM64PoolLoad` hanya cocok `[x27`) + `strxref` yang memfilter
> `ins.Op == decompiler.OpLoadPool`.

## Ringkasan

`internal/strxref` adalah package kecil (1 file sumber `strxref.go` 106 baris +
1 file test 128 baris) yang melakukan **string cross-referencing**: diberikan
sekumpulan pool index, scan semua fungsi dan laporkan fungsi mana yang
memuat pool slot tersebut via instruksi `OpLoadPool`. Ini menjawab pertanyaan
RE "string ini ada di snapshot, tapi fungsi mana yang **memakainya**?".

Mekanisme inti benar dan teruji: `FindPoolReferences` iterasi `ctx.Ranges`,
membangun `FuncIR` per fungsi via `ctx.FuncIRFor`, lalu mencari instruksi
`OpLoadPool` yang `PoolIndex`-nya ada di target set. Default unbounded scan
(terukur 9.3s / flat memory pada 129k-function libapp.so) adalah pilihan
desain yang sahih.

**Temuan utama: strxref hanya menangkap 1 dari 3 bentuk instruksi pool-load
yang dipancarkan SDK Dart AOT pada ARM64.** Dua bentuk lainnya (untuk pool
index besar) sama sekali tidak ter-classified sebagai `OpLoadPool` atau
ter-classified tapi `PoolIndex = -1`, sehingga **sebagian besar referensi
string di app ARM64 nyata terlewat secara sistematis**. Selain itu, pada x86_64
pola `cmpq reg, [r15+disp]` (compare-against-pool-string) yang eksplisit
dihandle SDK juga terlewat. Ada juga duplikasi arsitektural: `internal/disasm`
memiliki sistem string-xref paralel (`StringRefRecord` / `string_refs.jsonl`
via `PeepholeState`) yang punya coverage berbeda dari strxref dan tidak
dipakai strxref.

## Struktur Folder

| File | Baris | Peran |
|------|-------|-------|
| `strxref.go` | 106 | `Reference` struct, `Options`, `FindPoolReferences` — scan semua fungsi untuk `OpLoadPool` yang match pool index target. |
| `strxref_test.go` | 128 | 4 test: matching load, no-match untargeted, default unbounded, MaxScan narrows. Semua test pakai form-1 ARM64 (`ldr x0, [x27, #24]`). |

**Pipeline pemanggilan** (dari `cmd/aotopsy/cmd_debug_strings.go`):
1. `--find <substr>` → scan `cluster.Result.Strings` (VM + Isolate) → kumpulkan `matchedRefIDs`.
2. `ctx.PoolIndicesForRefIDs(refSet)` → scan `c.Result.Pool` (app isolate pool) untuk `PoolTagged` entry yang `RefID`-nya match → kembalikan pool indices.
3. `strxref.FindPoolReferences(ctx, poolIndices, opts)` → scan semua fungsi, cari `OpLoadPool` dengan `PoolIndex` di target set.

**Dependency kunci:**
- `decompiler.OpLoadPool` + `Instr.PoolIndex` — di-set oleh `liftARM64Instr` (`liftarm64.go:145`) dan `liftX86Instr` (`liftx86.go:275`). **Hanya inilah sumber pool-index yang dipakai strxref.**
- `disasm.ARM64PoolIndex` / `disasm.X64PoolIndex` — konversi displacement byte → pool index (verified ke SDK `ObjectPool::IndexFromOffset`).

## Gap Analysis

### Gap 1: ARM64 form-2 pool-load (ADD+LDR split) tidak ter-classified sebagai OpLoadPool

- **Deskripsi**: SDK `Assembler::LoadWordFromPoolIndex` (ARM64) memancarkan 3
  bentuk instruksi tergantung besarnya byte offset (`element_offset(idx) =
  16 + 8*idx`, PP untagged):
  - **Form 1**: `ldr xt, [pp, #imm12]` — saat `Address::CanHoldOffset(offset)`. Offset ≤ 32760 (12-bit scaled by 8) → **pool index 0..4093**.
  - **Form 2**: `add xt, pp, #upper20; ldr xt, [xt, #lower12]` — saat upper20 fit di Operand immediate tapi offset penuh tidak fit di Address. LDR-nya berbasis **register tujuan sendiri** (`[xt, #lower]`), BUKAN `[x27, ...]`. Offset gabungan = `(add.Imm12 << 12) + ldr.Imm12` → 24-bit → **pool index 4094..~2 juta**.
  - **Form 3**: `movz xt, #low; movk xt, #high, lsl #16; ldr xt, [pp, xt]` — offset > 24 bit → **pool index > ~2 juta**.

  `strxref` hanya menangkap **form 1**. Akar masalah di `liftarm64.go:215`
  `isARM64PoolLoad`: `strings.Contains(lower, "["+sdk.ARM64PoolRegStr)` —
  hanya cocok `[x27`. Form 2 LDR-nya `[xt, #lower]` (base = register tujuan,
  bukan x27) → `isARM64PoolLoad` return **false** → instruksi jatuh ke
  `OpOther`, bukan `OpLoadPool`. strxref tidak pernah melihatnya.

- **Bukti SDK**:
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` @3.9.2 baris 439-463
    (`LoadWordFromPoolIndex`, 3 case: `ldr` / `add+ldr` / `movz+movk+ldr`).
    Verifikasi `gh api` @3.9.2: `if (Address::CanHoldOffset(offset)) { ldr(...) } else if (Operand::CanHold(upper20...)) { add(dst,pp,op); ldr(dst,Address(dst,lower12)); } else { movz; movk; ldr(dst,Address(pp,dst)); }`.
  - `runtime/vm/instructions_arm64.cc` @3.9.2 baris 300-356
    (`DecodeLoadObjectFromPoolOrThread`): case form-2 eksplisit —
    `if (instr->RnField() == instr->RtField())` lalu lihat `add` sebelumnya,
    `offset = (add->Imm12Field() << 12) + offset`. SDK runtime sendiri
    mengenali form 2.
  - `runtime/vm/compiler/assembler/assembler_arm64.h` @3.9.2 baris 164-178
    (`Address::CanHoldOffset`): offset fit jika `Utils::IsUint(12+scale, offset)` (12-bit unscaled → 15-bit untuk 64-bit → 0..32767) → index ≤ 4093.
  - Verifikasi grep MCP `searchGitHub` query `"LoadWordFromPoolIndex"` repo
    `dart-lang/sdk` → konfirmasi 3-branch di `assembler_arm64.cc:439`.
  - `internal/disasm/RE_GAP_ANALYSIS_REPORT.md` Gap 2 sudah mendokumentasikan
    hal sama dari sisi disasm: `PeepholeState` mengenali form 2 untuk
    **annotasi** tapi tidak ditrack di dataflow/IR.

- **Dampak**: **KRITIKAL**. Pada app ARM64 nyata (pool puluhan ribu entry),
  mayoritas string berada di index > 4093 → dimuat via form 2 → **terlewat
  sepenuhnya** oleh strxref. Sebuah `--xref` search untuk string yang ada di
  pool index 5000 akan melaporkan "0 references" padahal string itu dipakai
  20 fungsi. Ini membuat output strxref pada app nyata **false-negative
  secara sistematis** untuk sebagian besar string. Test existing hanya pakai
  `ldr x0, [x27, #24]` (index 1, form 1) sehingga gap tidak tertangkap.

- **Usulan**:
  1. Di `liftarm64.go`, tambah deteksi form 2: track `add xt, x27, #imm`
     (via `arm64.ADD64Immediate`, seperti `PeepholeState`), lalu saat LDR
     berikutnya `ldr xt2, [xt, #lower]` dengan `base == addDestReg` dan
     register belum di-kill, hitung `PoolIndex = ARM64PoolIndex(addImm +
     lower)` dan set `Op = OpLoadPool`. Implementasi paralel sudah ada di
     `internal/disasm/annotate.go:202` (`PeepholeState.Annotate`) — bisa
     di-port ke lifter atau di-faktor jadi shared helper.
  2. Alternatif arsitektural: jadikan `internal/disasm.PPAnnotator` +
     `PeepholeState` sebagai sumber tunggal pool-index resolution, dan
     konsumsi di lifter (saat ini lifter re-implement deteksi pool-load
     secara terpisah dari annotator → dua sumber kebenaran yang divergen).
  3. Tambah test dengan form 2 (`add x0, x27, #0x4000; ldr x0, [x0, #0x10]`
     → pool index 2048) untuk mencegah regresi.

- **Prioritas**: **P0 — KRITIKAL**. Tanpa fix ini, strxref pada app nyata
  ARM64 melaporkan hasil yang fundamentally incomplete untuk mayoritas
  string.

### Gap 2: ARM64 form-3 pool-load (MOVZ+MOVK+LDR [PP, reg]) ter-classified tapi PoolIndex = -1

- **Deskripsi**: Form 3 (`movz xt, #low; movk xt, #high, lsl #16; ldr xt,
  [x27, xt]`) — LDR-nya `[x27, xt]` (register offset, tidak ada `#imm`).
  `isARM64PoolLoad` cocok (`[x27` ada) → `Op = OpLoadPool`. Tapi
  `arm64PoolIndex` (`liftarm64.go:224`) mencari `#` dalam operand — tidak
  ada → return **-1**. strxref lookup `target[-1]` selalu false (kecuali -1
  di target set, yang tidak mungkin) → **miss**.

- **Bukti SDK**:
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` @3.9.2 baris 456-462
    (case 3: `movz(dst, Immediate(offset_low), 0); movk(dst,
    Immediate(offset_high), 1); ldr(dst, Address(pp, dst))`).
  - `runtime/vm/instructions_arm64.cc` @3.9.2 baris 196-227
    (`DecodeLoadWordFromPool`): handle `movz`/`movk` sebelum LDR register-offset,
    offset = `Imm16Field` (low) | `Imm16Field << 16` (high).
  - Catatan: `DecodeLoadObjectFromPoolOrThread` (baris 327) punya
    `// TODO(rmacnak): Loads with offsets beyond 24 bits.` — path runtime
    object-resolution SDK sendiri belum handle form 3, tapi `DecodeLoadWordFromPool`
    (assembler-side) handle. Form 3 valid dan dipancarkan.
  - Verifikasi grep MCP `searchGitHub` query `"DecodeLoadWordFromPool"` repo
    `dart-lang/sdk` → konfirmasi.

- **Dampak**: **TINGGI secara struktural, RENDAH secara praktis**. Form 3
  hanya untuk pool index > ~2 juta (offset > 24 bit / 16 MB). Pool app nyata
  jarang exceed 2M entry. Tapi gap ini membuat `OpLoadPool` dengan
  `PoolIndex = -1` muncul di IR — sinyal "ada pool load tapi index tidak
  diketahui" yang seharusnya bisa di-resolve dengan dataflow tracking
  MOVZ/MOVK immediate. Saat ini strxref silently drop, bukan report sebagai
  "unresolved pool load".

- **Usulan**:
  1. Di lifter, track MOVZ/MOVK immediate ke register (small constant
     propagation: reg → known 16/32-bit value). Saat `ldr xt, [x27, xm]`
     dengan `xm` punya known immediate value, hitung
     `PoolIndex = ARM64PoolIndex(xm_value)`.
  2. Minimal: jika `OpLoadPool` terdeteksi tapi `PoolIndex = -1` (register
     offset dari PP), tetap report ke strxref sebagai "unresolved pool load
     at addr" agar RE tahu ada pool reference yang tidak ter-resolve, bukan
     silently drop. Tambah field `Resolved bool` di `Reference`.
  3. `internal/disasm/RE_GAP_ANALYSIS_REPORT.md` Gap 2 usulan 2 sudah
     mendokumentasikan approach MOVZ/MOVK tracking di `noWindowRegs`.

- **Prioritas**: **P2** — struktural penting (komplitkan 3-form coverage),
  praktis rendah dampak pada app nyata saat ini.

### Gap 3: x86_64 CMP-against-pool-string (cmpq reg, [r15+disp]) tidak ter-classified sebagai OpLoadPool

- **Deskripsi**: Pada x86_64, SDK `DecodeLoadObjectFromPoolOrThread`
  mengenali DUA opcode pool reference: `movq` (0x8b, load) DAN `cmpq`
  (0x3b, compare-against-memory). Sebuah fungsi yang membandingkan nilai
  dengan string konstan tanpa load dulu (`cmpq rax, [r15+0x3f]`) adalah
  referensi pool valid yang SDK hitung. Tapi `liftx86.go:275` hanya set
  `OpLoadPool` untuk `in.Inst.Op == x86asm.MOV && isX86PoolLoad(in)`.
  `CMP` tidak ter-classify → strxref miss.

- **Bukti SDK**:
  - `runtime/vm/instructions_x64.cc` @3.9.2 baris 19-55
    (`DecodeLoadObjectFromPoolOrThread`): `if ((bytes[1] == 0x8b) ||
    (bytes[1] == 0x3b))` — `0x8b` = movq, `0x3b` = cmpq, keduanya cek
    `[PP+disp8]` / `[PP+disp32]` → `ObjectAtPoolIndex`. Juga cek `[THR+disp]`
    untuk `Thread::ObjectAtOffset`.
  - Verifikasi grep MCP `searchGitHub` query `"DecodeLoadObjectFromPoolOrThread"`
    repo `dart-lang/sdk` → konfirmasi `instructions_x64.cc` handle movq+cmpq.
  - `internal/decompiler/ir.go` baris 130-137 (komentar field `PoolIndexOf`)
    sudah menyadari: "x86_64 can compare directly against memory, so
    `cmp eax, [r15+0x3f]` reads a pool entry without ever loading it" —
    tapi hanya di-resolve untuk **display** via `PoolIndexOf`, bukan
    di-classify sebagai `OpLoadPool` untuk konsumsi strxref.

- **Dampak**: **MENENGAH**. Compare-against-pool-string lebih jarang dari
  load-then-use, tapi valid (e.g. equality check `if (x == "literal")` bisa
  di-compile ke `cmpq` langsung). strxref pada sample x86_64 akan miss
  referensi tipe ini. Untuk RE, ini adalah false-negative pada pola
  "apakah nilai ini sama dengan string konstan X?".

- **Usulan**:
  1. Di `liftx86.go`, tambah case `in.Inst.Op == x86asm.CMP &&
     isX86PoolLoad(in)` → set `Op = OpLoadPool`, `PoolIndex = x86PoolIndex(in)`.
     `Target` tidak ada register tujuan (cmp tidak write) — set `Target = ""`
     atau nama register sumber pertama.
  2. Tambah test x86 dengan `cmp rax, [r15+0x3f]` → verify OpLoadPool.

- **Prioritas**: **P1** — komplitkan coverage x86_64, dampak menengah.

### Gap 4: Dua sistem string-xref paralel (strxref vs disasm.StringRefRecord) tidak ter-unifikasi

- **Deskripsi**: Ada **dua** sistem string cross-ref di codebase:
  - **strxref** (`internal/strxref`): konsumsi `decompiler.FuncIR.OpLoadPool`.
    Coverage: ARM64 form-1 saja; x86 MOV saja.
  - **disasm** (`internal/disasm/dataflowx86.go:166` `poolStringRefFor` +
    `annotate.go:202` `PeepholeState`): menghasilkan `string_refs.jsonl`
    via `StringRefRecord`. Coverage: x86 MOV (form-1) + ARM64 form-1 via
    `PPAnnotator` + ARM64 form-2 via `PeepholeState` (annotation path).
    Form-3 dan x86-CMP juga miss di sini.

  Keduya tidak share code. strxref tidak memanfaatkan `PeepholeState` yang
  sudah handle form-2. `string_refs.jsonl` tidak memanggil strxref. Hasilnya:
  coverage gap berlapis — strxref miss form-2 yang sebenarnya sudah
  ter-solve di disasm (untuk annotation), tapi tidak diteruskan ke IR yang
  strxref baca.

- **Bukti SDK**: (tidak langsung — ini gap arsitektural internal, bukan
  perbedaan vs SDK) Lihat `internal/disasm/annotate.go:176-250`
  (`PeepholeState` handle ADD+LDR PP split), `internal/disasm/dataflowx86.go:386-415`
  (`poolStringRefFor` hanya MOV), `internal/decompiler/liftarm64.go:145-148`
  (lifter hanya form-1). `internal/disasm/RE_GAP_ANALYSIS_REPORT.md` Gap 2
  mendokumentasikan bahwa `PeepholeState` track form-2 untuk annotasi tapi
  `touchInstrEffect` (dataflow) tidak.

- **Dampak**: **MENENGAH**. Duplikasi logic pool-index resolution di 3 tempat
  (lifter, annotator, dataflow) dengan coverage berbeda → maintenance hazard
  dan inconsistent results. RE user yang baca `string_refs.jsonl` dapat
  hasil berbeda dari `aotopsy _debug strings --xref` untuk string yang sama.
  Fix form-2 di satu tempat tidak otomatis fix di tempat lain.

- **Usulan**:
  1. Faktor pool-load detection jadi satu shared module (e.g.
     `internal/disasm.PoolLoadResolver`) yang mengembalikan
     `(poolIndex int, ok bool, form string)` untuk semua 3 form ARM64 +
     MOV/CMP x86. Konsumsi oleh lifter (→ `OpLoadPool`/`PoolIndex`),
     annotator (→ display), dataflow (→ register define), dan strxref.
  2. Atau: buat strxref konsumsi `string_refs.jsonl` path (yang sudah
     punya form-2 via PeepholeState) sebagai fallback/supplement saat
     `OpLoadPool` miss.

- **Prioritas**: **P1** — eliminasi duplikasi, pastikan fix form-2 sekali
  merata ke semua consumer.

### Gap 5: Reference struct tidak bawa destination register / string value / data-flow downstream

- **Deskripsi**: `Reference` struct hanya punya `FuncName`, `FuncVA`,
  `InstrAddr`, `PoolIndex`. Tidak ada:
  - **DestReg**: register tujuan pool load (IR punya di `Instr.Target` tapi
    tidak diteruskan ke `Reference`). Untuk RE, "string X dimuat ke x5 di
    addr Y" memungkinkan trace ke mana x5 mengalir (ke call `print`, ke
    field store, ke compare).
  - **StringValue**: nilai string yang di-load. Caller (`cmd_debug_strings`)
    tahu string-nya dari `--find`, tapi `Reference` tidak bawa → kalau
    multiple string match, user harus cross-reference PoolIndex ke pool
    manual untuk tahu string mana.
  - **DownstreamUse**: instruksi berikutnya yang memakai DestReg (apakah
    string di-pass ke fungsi, di-store, di-compare). Ini info RE paling
    useful: "string ini dipakai sebagai argumen print() di fungsi Z".

- **Bukti SDK**: (gap fitur RE, bukan perbedaan vs SDK) `Instr.Target`
  (`ir.go:41`) sudah berisi destination register untuk `OpLoadPool` — tinggal
  diteruskan. `PoolIndexOf` (`ir.go:137`) + `PoolLookups.StringForRef`
  (`naming/pool.go:342`) bisa resolve PoolIndex → string value.

- **Dampak**: **RENDAH-MENENGAH**. Output strxref saat ini (`used in:
  <func> @ <va> (pool load @ <addr>, pool[<idx>])`) menjawab "fungsi mana"
  tapi tidak "buat apa". Untuk RE workflow (reconstruct apa yang dilakukan
  fungsi terhadap string ini), user harus manual buka decompiler dan cari
  addr. Ini mengurangi utilitas strxref sebagai tool RE cepat.

- **Usulan**:
  1. Tambah field `DestReg string` dan `StringValue string` di `Reference`.
     Isi di `FindPoolReferences` dari `ins.Target` dan
     `ctx.Pool.StringForRef(poolEntry.RefID)`.
  2. (Ambisius) Tambah `UseKind string` — klasifikasi penggunaan downstream:
    "call_arg", "field_store", "compare", "return", "interpolate". Butuh
    small forward-scan dari InstrAddr ke use berikutnya dari DestReg.
    `internal/disasm` sudah punya dataflow reaching-definitions
    (`dataflowarm64.go`) yang bisa di-reuse.
  3. Output format `cmd_debug_strings.go:242` tambahkan DestReg/StringValue.

- **Prioritas**: **P2** — peningkatan kualitas RE, bukan koreksi benar/salah.

### Gap 6: LDP (LoadDoubleWordFromPoolIndex) — load 2 pool entry berdekatan — tidak ter-handle

- **Deskripsi**: SDK `LoadDoubleWordFromPoolIndex` (ARM64) memancarkan `ldp
  rt1, rt2, [pp, #offset]` yang memuat **dua** pool entry berurutan (idx dan
  idx+1) sekaligus. strxref hanya catch single `ldr` (form-1). `ldp` dari PP
  tidak ter-classify sebagai `OpLoadPool` → kalau satu dari pasangan itu
  string, miss. `internal/disasm/RE_GAP_ANALYSIS_REPORT.md` Gap 1
  mendokumentasikan `arm64.LDP64UnsignedOffset` ada tapi tidak pernah
  dipanggil di disasm/annotator/dataflow.

- **Bukti SDK**:
  - `runtime/vm/compiler/assembler/assembler_arm64.cc` @3.9.2 baris 491-548
    (`LoadDoubleWordFromPoolIndex`, 4 varian: ldp / add+ldp / add+add+ldp /
    movz+movk+ldp).
  - `runtime/vm/instructions_arm64.cc` @3.9.2 baris 248-320
    (`DecodeLoadDoubleWordFromPool`).
  - Verifikasi grep MCP `searchGitHub` query `"DecodeLoadDoubleWordFromPool"`
    repo `dart-lang/sdk` → konfirmasi.

- **Dampak**: **RENDAH**. LDP dari pool tipikal untuk pasangan (Code, ICData)
  pada call site, bukan string. Tapi secara teori dua string berdekatan di
  pool bisa di-load via LDP. Praktis jarang untuk string-xref.

- **Usulan**:
  1. Di lifter, deteksi `ldp rt1, rt2, [x27, #imm]` → set dua `Instr`
     `OpLoadPool` (idx dan idx+1), atau satu `Instr` dengan dua PoolIndex.
  2. Lebih simple: tambah `LDP` ke `isARM64PoolLoad` dan set `PoolIndex =
     ARM64PoolIndex(imm)`, catat idx+1 di field terpisah.

- **Prioritas**: **P3** — komplitkan coverage, dampak praktis rendah.

## Register Tracking Gaps

| Register | Peran SDK | Status di strxref / lifter | Dampak |
|----------|-----------|---------------------------|--------|
| **PP (X27 / R15)** | Object-pool base register. Semua pool load berbasis ini. | Ter-track sebagai `fir.PoolReg`. `isARM64PoolLoad` / `isX86PoolLoad` cocok base == PP. | OK — tapi hanya cek base == PP, tidak cek form-2 (base == dst reg pasca ADD). |
| **ADD dest reg (form 2)** | Hasil `add xt, pp, #upper` — hold PP+upper20. Base LDR form-2. | **TIDAK ter-track** di lifter. `PeepholeState` (disasm) track untuk annotasi saja. | **Akar Gap 1** — form-2 miss karena lifter tidak propagate ADD dest → LDR base. |
| **MOVZ/MOVK dest reg (form 3)** | Hasil `movz; movk` — hold 32-bit byte offset. Index reg LDR form-3. | **TIDAK ter-track** di lifter. Tidak ada immediate-propagation ke register. | **Akar Gap 2** — form-3 jadi PoolIndex=-1 karena offset register tidak diketahui. |
| **Pool-load DestReg (LDR/MOV target)** | Register yang menerima nilai pool entry (string ptr). | Ter-capture di `Instr.Target` (IR) tapi **tidak diteruskan ke `Reference`**. | **Gap 5** — RE tidak tahu ke mana string mengalir setelah load. |
| **THR (X26 / R14)** | Thread register. `ldr xt, [THR, #off]` → `Thread::ObjectAtOffset` (null/true/false/empty_array/empty_type_arguments/dynamic_type). | Tidak relevan untuk strxref — **tidak ada string** di `CACHED_NON_VM_STUB_LIST` (verified `thread.h:187-194`). | Bukan gap untuk string-xref. |
| **NULL_REG (X22)** | Cache `Object::null()`. `mov dst, NULL_REG` / `add dst, NULL_REG, kTrue/kFalseOffset`. | Tidak relevan — null/true/false bukan string. | Bukan gap. |
| **CODE_REG (X24 / R12)** | Current Code object. Dipakai di prologue untuk derive PP. | Tidak relevan untuk string pool load. | Bukan gap. |

## Fitur RE Missing/Incomplete

| Fitur | Status | Catatan |
|-------|--------|---------|
| **Cross-ref string → fungsi pemuat** | **Partial** — hanya form-1 ARM64 + MOV x86. | Gap 1/2/3. Mayoritas string di app ARM64 nyata terlewat. |
| **Cross-ref string → penggunaan downstream** | **Missing** — tidak ada info "string dipakai untuk apa" (call arg / field store / compare / return). | Gap 5 usulan 2. `internal/disasm` dataflow reaching-defs bisa reuse. |
| **String value di output Reference** | **Missing** — `Reference` hanya bawa PoolIndex, bukan string. | Gap 5 usulan 1. `PoolLookups.StringForRef` sudah ada. |
| **DestReg di output Reference** | **Missing** — `Instr.Target` ada tapi tidak diteruskan. | Gap 5. |
| **Unresolved pool-load reporting** | **Missing** — `OpLoadPool` dengan `PoolIndex=-1` (form-3) silently drop, bukan report sebagai "unresolved". | Gap 2 usulan 2. RE user tidak tahu ada pool reference yang tidak ter-resolve. |
| **LDP (double-word pool load)** | **Missing** — tidak ada `OpLoadPool` untuk LDP. | Gap 6. |
| **x86 CMP-against-pool** | **Missing** — hanya MOV yang ter-classify. | Gap 3. |
| **Filter by function name** | **OK** — `Options.Filter` match substring di `fir.Name`. | Bekerja, tapi fungsi unnamed (stub) tetap discan (Filter=""); Reference.FuncName bisa kosong. |
| **Unbounded default scan** | **OK** — terukur 9.3s/flat memory pada 129k-func sample. | Desain sahih, test regression ada. |
| **VM-isolate string cross-ref** | **OK** — `PoolIndicesForRefIDs` scan app pool untuk `PoolTagged` entry yang RefID-nya match (VM string RefID < BaseObjLimit, app RefID >=). RefID space unified. | Bukan gap — verified via `naming/pool.go:342` `StringForRef` + `ResolvePoolDisplay:658` handle VmRefToStr fallback. |
| **Thread-loaded object cross-ref** | **N/A** — `CACHED_NON_VM_STUB_LIST` = null/true/false/empty_array/empty_type_arguments/dynamic_type, bukan string. | Bukan gap untuk strxref. |

## Verifikasi SDK

Semua klaim diverifikasi via **grep MCP `searchGitHub`** (repo `dart-lang/sdk`)
dan/atau **`gh api` @ tag 3.9.2** (raw content).

| Query / Path | Hasil |
|--------------|-------|
| grep MCP `"LoadWordFromPoolIndex"` repo `dart-lang/sdk` | Konfirmasi `assembler_arm64.cc:439` (3 case: ldr / add+ldr / movz+movk+ldr), `assembler_x64.cc:1422` (movq FieldAddress(PP, offset) — single form), `assembler_arm.cc:1580`, `assembler_riscv.cc:4612`. |
| grep MCP `"DecodeLoadObjectFromPoolOrThread"` repo `dart-lang/sdk` | Konfirmasi `instructions_x64.cc:30-55` (movq 0x8b + cmpq 0x3b vs [PP+disp] dan [THR+disp]), `instructions_arm64.cc:300-356` (form-1 + form-2 + TODO form-3), `instructions_arm.cc`, `instructions_riscv.cc`. |
| grep MCP `"DecodeLoadDoubleWordFromPool"` repo `dart-lang/sdk` | Konfirmasi `instructions_arm64.cc:248` + `instructions_arm64.h:57` + `assembler_arm64.cc:491` (LDP 4 varian). |
| `gh api .../assembler_arm64.cc?ref=3.9.2` baris 439-463 | `LoadWordFromPoolIndex`: `if (Address::CanHoldOffset(offset)) { ldr } else if (Operand::CanHold(upper20...)) { add(dst,pp,op); ldr(dst,Address(dst,lower12)); } else { movz; movk; ldr(dst,Address(pp,dst)); }` |
| `gh api .../assembler_arm64.h?ref=3.9.2` baris 164-178 | `Address::CanHoldOffset`: `(Utils::IsUint(12 + scale, offset) && aligned)` → 12-bit unscaled + 3-bit scale (64-bit) = 15-bit → offset ≤ 32767 → index ≤ 4093. |
| `gh api .../instructions_arm64.cc?ref=3.9.2` baris 196-227 | `DecodeLoadWordFromPool` 3 sub-case: (1a) ldr [pp,#imm] Rn==PP; (1b) ldr [xt,#imm] Rn==Rt, add sebelumnya; (2) ldr [pp,xt] register-offset, movz/movk sebelumnya. |
| `gh api .../instructions_arm64.cc?ref=3.9.2` baris 300-356 | `DecodeLoadObjectFromPoolOrThread`: form-1 (ldr [PP,#imm]), form-2 (ldr [xt,#imm] + add), `// TODO(rmacnak): Loads with offsets beyond 24 bits.` (form-3 belum di runtime path), `add xt, NULL_REG, #kTrue/kFalseOffset` → bool. |
| `gh api .../instructions_x64.cc?ref=3.9.2` baris 19-55 | `DecodeLoadObjectFromPoolOrThread`: `(bytes[1] == 0x8b) \|\| (bytes[1] == 0x3b)` → movq ATAU cmpq vs `[THR+disp]` / `[PP+disp8]` / `[PP+disp32]`. |
| `gh api .../thread.h?ref=3.9.2` baris 187-194 | `CACHED_NON_VM_STUB_LIST`: object_null_, bool_true_, bool_false_, empty_array_, empty_type_arguments_, dynamic_type_ — **tidak ada string**. |
| `gh api .../thread.cc?ref=3.9.2` baris 1294-1309 | `Thread::ObjectAtOffset`: iterate `CACHED_VM_OBJECTS_LIST` (= `CACHED_NON_VM_STUB_LIST` + `CACHED_VM_STUBS_LIST`) — stubs adalah Code ptr, bukan string. |
