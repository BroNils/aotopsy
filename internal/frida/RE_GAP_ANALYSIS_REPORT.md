# RE Gap Analysis Report: internal/frida

> **STATUS VERIFIKASI (2026-09-01)** — semua 12 gap CONFIRMED. Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> - Gap 1 CONFIRMED di `script_gen.go:260-265`:
>   `receiverReg = (arch==='arm64') ? 'x1' : 'rcx'` lalu
>   `extractClassId(receiverPtr)`. Di x86_64 RCX = `DispatchTableNullErrorABI::
>   kClassIdReg` (integer), dan receiver sebenarnya di **RDI** (arg0
>   `DartCallingConvention`). Di ARM64 `x1` memang benar (arg0).
> - **Gap 2 lebih tajam dari yang ditulis**: paket ini **sudah punya** decoder
>   GDT x86 yang terverifikasi-SDK (`gdtcall.go`, `ScanIndirectCalls`), tapi
>   satu-satunya konsumennya adalah `cmd/aotopsy/cmd_debug_x64refs.go:134` —
>   tidak pernah menyuplai probe Frida. Jadi ini "sudah ditulis, tidak
>   disambungkan", bukan "belum ditulis".
> - Gap 10/11 CONFIRMED: script mengirim stream `send({type:'dispatch'…})` /
>   `send({type:'function'…})`, sementara `import.go:14-38` menuntut satu file
>   JSON `{dispatch_resolutions, type_snapshots, call_graph, heap_objects}`;
>   tidak ada konverter, dan `type_snapshots`/`heap_objects`/`call_graph`
>   tidak pernah diproduksi generator manapun. `CopyStaticFiles`
>   (`import.go:168-177`) menyalin `evidence.jsonl` tanpa memanggil
>   `MergeRuntime`.

## Ringkasan

Folder `internal/frida/` berisi 6 file yang mengimplementasikan dua jalur
generasi Frida script (parallel, tidak konsisten), satu import-merge pipeline,
dan satu x86_64 indirect-call scanner:

| File | Peran |
|------|-------|
| `generator.go` | Jalur #1: `--gen-frida` di `decompile-native`. Hook function entry + probe indirect call dari `FuncIR`. |
| `script_gen.go` | Jalur #2: `frida-export --gen-script`. Hook dari `FridaMetadata` JSON. |
| `export.go` | Struct `FridaMetadata` untuk JSON export. |
| `import.go` | `frida-import`: merge Frida runtime results ke static output. |
| `gdtcall.go` | x86_64 indirect-call scanner (GDT/pool/unresolved). |
| `frida_test.go` | Test minimal untuk `script_gen.go`. |

Ditemukan **12 gap** signifikan: 4 bug kritis (x86_64 class-id salah baca,
GDT call tidak di-probe, dead code `safeReadString`/`safeReadPtr`, import
type-snapshot dibuang), 3 register tracking gap (FPU args, ARGS_DESC, CODE_REG
tidak di-capture), 3 fitur RE missing (backtrace, Dart String deref, dispatch
table runtime lookup), dan 2 arsitektur gap (dua generator parallel tidak
konsisten, script/import protocol mismatch).

## Struktur Folder

```
internal/frida/
├── generator.go     # 362 lines — FridaHook/FridaProbe/FridaOptions, GenerateFridaScriptWithOptions, WriteFridaScript, CollectIndirectCallProbes, RealArgRegs
├── script_gen.go    # 305 lines — GenerateFridaScriptFromMeta (dari FridaMetadata JSON)
├── export.go        # 54 lines  — FridaMetadata + sub-structs (JSON schema)
├── import.go        # 178 lines — CmdFridaImport (merge frida_results.json → call_edges.jsonl)
├── gdtcall.go       # 258 lines — ScanIndirectCalls x86_64 (GDT/pool/unresolved classification)
└── frida_test.go    # 47 lines  — TestGenerateFridaScriptFromMeta (header + name + BLR PC only)
```

Dua pemanggil utama:
- `internal/analysis/decompile_output.go` → `EmitSingleFuncFrida` (single `--func`)
- `internal/analysis/decompile_loop.go` / `decompile_from_main.go` → `FinalizeFridaOutput` (batch `--all`/`--from-main`)
- `cmd/aotopsy/cmd_frida_export.go` → `GenerateFridaScriptFromMeta` (export pipeline)

## Gap Analysis

### Gap 1: x86_64 BLR probe membaca RCX sebagai pointer — seharusnya class id langsung

- **Deskripsi**: Di `script_gen.go:260-265`, probe BLR meng-hardcode receiver
  register:
  ```js
  var receiverReg = (META.arch === 'arm64') ? 'x1' : 'rcx';
  var receiverPtr = this.context[receiverReg];
  var classId = -1;
  if (receiverPtr && !receiverPtr.isNull()) {
    classId = extractClassId(receiverPtr);
  }
  ```
  Pada x86_64, `rcx` adalah `DispatchTableNullErrorABI::kClassIdReg` —
  **integer class id langsung**, BUKAN object pointer. Memanggil
  `extractClassId(rcx)` membaca memory di alamat `rcx` (angka kecil seperti
  cid=5) → SIGSEGV atau return -1. Receiver sebenarnya ada di `rdi` (arg-0
  Dart calling convention).

  Pada ARM64, `x1` adalah receiver (arg-0) — benar. Tetapi `x0` adalah
  `kClassIdReg` (R0) dan sudah berisi class id langsung tanpa perlu
  dereference memory. Script ARM64 melakukan dereference berisiko padahal
  nilai langsung tersedia di `x0`.

- **Bukti SDK**:
  - MCP `searchGitHub` repo `dart-lang/sdk`, query `kClassIdReg = R0`:
    `runtime/vm/constants_arm64.h:485` — `static constexpr Register kClassIdReg = R0;`
  - `gh api` `runtime/vm/constants_x64.h?ref=3.12.2`:
    `struct DispatchTableNullErrorABI { static constexpr Register kClassIdReg = RCX; };`
  - `gh api` `runtime/vm/compiler/backend/flow_graph_compiler_x64.cc?ref=3.12.2`:
    `EmitDispatchTableCall` menggunakan `cid_reg = DispatchTableNullErrorABI::kClassIdReg` (RCX) sebagai index register ke dispatch table — RCX adalah integer cid, bukan pointer.
  - `sdk/registers.go:239`: `X86ClassIdReg = 1` (RCX canonical) — AOTopsy tahu ini, tapi script_gen.go tidak menggunakannya.
  - `sdk/registers.go:160`: `DartArgRegNames(false)` return `["rdi","rsi","rdx","rbx","r8","r9"]` — receiver = `rdi`, bukan `rcx`.

- **Dampak**: Setiap BLR probe di x86_64 menghasilkan `class_id: -1` (atau
  crash). Runtime class identification — fitur utama Frida untuk RE dispatch
  — 100% broken pada x86_64. ARM64 berfungsi tetapi tidak optimal (dereference
  berisiko vs. baca langsung dari X0).

- **Usulan**:
  1. x86_64: baca class id langsung dari `this.context['rcx']` (toInt), bukan
     `extractClassId(rcx)`. Receiver baca dari `this.context['rdi']` jika
     perlu object header verification.
  2. ARM64: baca class id langsung dari `this.context['x0']` (toInt) sebagai
     primary source; fallback ke `extractClassId(x1)` hanya jika X0=0.
  3. Tambahkan `META.classIdReg` ke metadata (dari `sdk.ARM64ReturnReg`=0 /
     `sdk.X86ClassIdReg`=1) sehingga script tahu register mana yang baca cid.

- **Prioritas**: **KRITIS** — bug kritis pada x86_64, fitur utama RE tidak
  berfungsi.

### Gap 2: CollectIndirectCallProbes skip SEMUA x86_64 GDT calls

- **Deskripsi**: `generator.go:355-357`:
  ```go
  if strings.HasPrefix(ins.Target, "0x") || (strings.Contains(ins.Target, "[") && strings.Contains(ins.Target, "+")) {
      continue
  }
  ```
  Filter ini skip target yang mengandung `[` DAN `+`. Tujuannya: skip
  THR-cached calls seperti `[r14+0x238]` (base+offset, sudah di-resolve oleh
  `vmtables.ThreadStubOffsets`). Tetapi filter juga skip GDT calls:
  `[rax+rcx*8+0xd700]` (base+index*scale+offset) — yang TIDAK di-resolve
  karena target bergantung pada runtime class id di RCX.

  Pada ARM64, GDT call adalah `BLR Xn` dimana Xn di-load dari
  `[X21, LR, LSL #3]`. Decompiler menghasilkan `Target = "x16"` (bare
  register, no brackets) → tidak di-skip → di-probe. Jadi gap ini
  x86_64-specific.

- **Bukti SDK**:
  - `gh api` `flow_graph_compiler_x64.cc?ref=3.12.2`:
    ```cpp
    const Register table_reg = RAX;
    __ LoadDispatchTable(table_reg);
    __ call(compiler::Address(table_reg, cid_reg, TIMES_8, offset));
    ```
    Instruksi: `call [rax+rcx*8+0xd700]` — memory operand dengan base+index*scale+disp.
  - `gh api` `flow_graph_compiler_arm64.cc?ref=3.12.2`:
    ```cpp
    __ AddImmediate(LR, cid_reg, offset);
    __ Call(compiler::Address(DISPATCH_TABLE_REG, LR, UXTX, compiler::Address::Scaled));
    ```
    Instruksi: `blr lr` dimana LR = cid + offset — bare register call.
  - `internal/disasm/x86.go:160-166`: `classifyX86Call` mengklasifikasi GDT
    call sebagai `kind=call_indirect, via=dispatch_table, reg=[rax+rcx*8+0x...]`
    — AOTopsy tahu ini GDT call, tapi `CollectIndirectCallProbes` tidak
    membedakannya dari THR-cached call.

- **Dampak**: Pada x86_64, GDT calls (primary mechanism untuk virtual/dynamic
  dispatch di Dart AOT) tidak di-probe oleh `--gen-frida`. RE user kehilangan
  runtime target untuk setiap virtual call — informasi paling penting untuk
  RE method override. Pada binary besar dengan ribuan GDT call, ini berarti
  mayoritas dispatch site tidak ter-cover.

- **Usulan**:
  1. Ganti filter: skip hanya `[r14+` (THR) dan `[r15+` (PP) — base register
     yang peran-nya statis. Atau gunakan info `Via` dari `call_edges.jsonl`
     (sudah diklasifikasi sebagai `dispatch_table` vs `THR.xxx` vs `pp[N]`).
  2. Untuk GDT call x86_64, emit probe yang membaca `this.context['rax']`
     (table base) + `this.context['rcx']` (cid) + parse disp dari string,
     lalu `Memory.readPointer(rax.add(rcx.mul(8)).add(disp))` untuk dapat
     runtime target.
  3. Tambahkan field `FridaProbe.BaseReg`, `IndexReg`, `Scale`, `Disp` untuk
     memory-operand probe (bukan hanya `Reg` string).

- **Prioritas**: **KRITIS** — mayoritas indirect call di x86_64 tidak
  ter-cover.

### Gap 3: script_gen.go BLR probe tidak handle memory-operand reg (x86_64 GDT)

- **Deskripsi**: `script_gen.go:255-258`:
  ```js
  var reg = s.reg.toLowerCase();
  var targetPtr = this.context[reg];
  if (!targetPtr) return;
  ```
  Untuk x86_64 GDT call, `s.reg` = `[rax+rcx*8+0xd700]` (dari
  `call_edges.jsonl` field `reg`). `this.context["[rax+rcx*8+0xd700]"]`
  adalah `undefined` → probe silently return, tidak ada output. Probe
  ter-install (Interceptor.attach berhasil) tetapi tidak pernah menghasilkan
  data.

  `frida_export.go:100-107` memang meng-include GDT calls di
  `UnresolvedBLRs` (filter `Via == "dispatch_table"`), jadi metadata
  berisi entry yang valid — tetapi script tidak bisa menggunakannya.

- **Bukti SDK**: Sama dengan Gap 2 — x86_64 GDT call adalah
  `call [rax+rcx*8+offset]`, memory operand.

- **Dampak**: `frida-export --gen-script` di x86_64 menghasilkan script
  dengan ratusan/ratusan BLR probe yang ter-install tetapi tidak pernah
  fire. User melihat "Probed N BLR sites" tetapi tidak ada output saat
  aplikasi berjalan. Silent failure — tidak ada error message.

- **Usulan**:
  1. Parse `s.reg` untuk memory operand: extract base, index, scale, disp.
  2. Jika `s.via == "dispatch_table"`, baca table base dari `this.context[base]`,
     cid dari `this.context['rcx']`, compute `target = Memory.readPointer(base + cid*8 + disp)`.
  3. Jika reg adalah bare register (ARM64 case), tetap baca
     `this.context[reg]` seperti sekarang.

- **Prioritas**: **TINGGI** — silent failure pada fitur utama.

### Gap 4: FPU argument registers (V0-V5 / XMM1-XMM6) tidak di-capture

- **Deskripsi**: `generator.go:143-149` `dumpArgs` hanya baca register dari
  `ctx[r]` dimana `r` berasal dari `regs` (GPR arg regs saja). FPU arg
  registers tidak di-pass ke `dumpArgs`. `sdk.DartFpuArgRegNames` dan
  `FuncIR.FpuArgRegs` tersedia tetapi tidak digunakan oleh Frida generator.

  `script_gen.go:229` hanya baca `args[0..3]` (Frida `args[]` array = GPR
  saja), tidak baca FPU context.

- **Bukti SDK**:
  - `gh api` `constants_arm64.h?ref=3.12.2`:
    `static constexpr FpuRegister kFpuRegistersForArgs[] = {V0, V1, V2, V3, V4, V5};`
    `static constexpr FpuRegister kReturnFpuReg = V0;`
  - `gh api` `constants_x64.h?ref=3.12.2`:
    `static constexpr FpuRegister kFpuRegistersForArgs[] = {XMM1, XMM2, XMM3, XMM4, XMM5, XMM6};`
    `static constexpr FpuRegister kReturnFpuReg = XMM0;`
  - `sdk/registers.go:289-312`: `ARM64FpuArgRegNames()`, `X86FpuArgRegNames()`,
    `DartFpuArgRegNames()` — semua tersedia, tidak dipakai oleh frida package.

- **Dampak**: Dart function dengan `double`/`float` parameter (umum di
  game/finance/physics app) — argumen tidak ter-capture. Demikian juga
  return value `double` — `retval` di `onLeave` adalah GPR return reg
  (X0/RAX), bukan FPU return reg (V0/XMM0). RE user kehilangan seluruh
  floating-point argument/return data.

- **Usulan**:
  1. Tambah `FpuArgRegs []string` ke `FridaHook` (dari `fir.FpuArgRegs`).
  2. Emit `dumpFpuArgs(ctx, fpuRegs)` yang baca `ctx['v0']`/`ctx['xmm1']`
     dll. Frida CpuContext menyediakan `q0`-`q31` (ARM64) / `xmm0`-`xmm15`
     (x86_64).
  3. Di `onLeave`, baca FPU return reg: `this.context['v0']` (ARM64) /
     `this.context['xmm0']` (x86_64) untuk detect double return.
  4. Tambah `FpuReturnReg` ke `FridaMetadata` dan gunakan di script_gen.go.

- **Prioritas**: **TINGGI** — double/float argumen dan return value adalah
  tipe umum di Dart app.

### Gap 5: ARGS_DESC_REG (R4/R10) tidak di-capture

- **Deskripsi**: Pada function entry, `ARGS_DESC_REG` (R4 ARM64, R10 x86_64)
  berisi arguments descriptor — Smi-encoded description dari actual argument
  count, positional vs named, dll. Ini adalah satu-satunya cara mengetahui
  runtime argument count untuk function dengan optional/named parameters.
  Frida hook tidak membaca register ini.

- **Bukti SDK**:
  - `gh api` `constants_arm64.h?ref=3.12.2`: `const Register ARGS_DESC_REG = R4;`
  - `gh api` `constants_x64.h?ref=3.12.2`: `const Register ARGS_DESC_REG = R10;`
  - `gh api` `flow_graph_compiler_arm64.cc?ref=3.12.2`:
    `EmitDispatchTableCall`: `__ LoadObject(ARGS_DESC_REG, arguments_descriptor);`
    — ARGS_DESC_REG di-load sebelum setiap dispatch call.
  - `sdk/registers.go:43,95`: `ARM64ArgsDesc = 4`, `X86ArgsDesc = 10` —
    AOTopsy tahu ini, tapi Frida hook tidak menggunakannya.

- **Dampak**: Untuk function dengan optional/named parameters (mayoritas
  Dart API), hook hanya melihat 6 GPR arg regs tetapi tidak tahu berapa
  yang benar-benar terisi. Arguments descriptor juga berguna untuk
  verifikasi: jika `ArgRegIndices` static analysis bilang arity=3 tetapi
  runtime args_desc bilang count=5, static analysis salah.

- **Usulan**:
  1. Tambah `argsDescReg` ke metadata (dari `sdk.ARM64ArgsDescStr`/`X86ArgsDescStr`).
  2. Di `onEnter`, baca `this.context[argsDescReg]` dan decode Smi
     (shift right 1) untuk dapatkan raw descriptor.
  3. Atau baca dari `args[]` kalau args_desc tidak reliable — Frida `args[N]`
     memberikan Nth GPR arg tanpa perlu tahu register name.

- **Prioritas**: **MENENGAH** — berguna untuk arity verification, bukan
  blocker.

### Gap 6: CODE_REG (R24/R12) tidak di-capture

- **Deskripsi**: Pada function entry, `CODE_REG` (R24 ARM64, R12 x86_64)
  berisi pointer ke current Code object. Code object berisi metadata:
  active_instructions, exception handlers, stack maps, inline info. Hook
  tidak membaca register ini.

- **Bukti SDK**:
  - `gh api` `constants_arm64.h?ref=3.12.2`: `const Register CODE_REG = R24;`
  - `gh api` `constants_x64.h?ref=3.12.2`: `const Register CODE_REG = R12;`
  - `sdk/registers.go:42,94`: `ARM64CodeReg = 24`, `X86CodeReg = 12`.

- **Dampak**: RE user tidak bisa cross-reference function entry dengan Code
  object snapshot data (inline frames, stack maps). Untuk function yang
  di-inlined ke caller lain, Code object di CODE_REG bisa mengidentifikasi
  caller context.

- **Usulan**: Tambah `codeReg` ke metadata, baca di `onEnter`, log sebagai
  module-relative offset (untuk cross-ref dengan `functions.jsonl`).

- **Prioritas**: **RENDAH** — nice-to-have untuk advanced RE.

### Gap 7: Tidak ada backtrace capture di hook entry

- **Deskripsi**: Baik `generator.go` maupun `script_gen.go` tidak memanggil
  `Thread.backtrace(this.context, Backtracer.ACCURATE)` di `onEnter`.
  Backtrace adalah salah satu fitur Frida paling berguna untuk RE: mengetahui
  SIAPA yang memanggil function ini. Tanpa backtrace, hook hanya memberikan
  "function X dipanggil dengan args Y" tetapi tidak "function X dipanggil
  dari function Z di baris N".

- **Bukti SDK**: N/A — ini adalah fitur Frida API, bukan SDK fact. Tetapi
  Dart AOT call stack dapat di-backtrace karena LR (ARM64) / return address
  di stack (x86_64) menyimpan caller VA. Backtracer.ACCURATE mengikuti
  frame pointer chain (FPREG = R29/RBP).

- **Dampak**: RE user harus menebak caller dari call_edges.jsonl (static
  analysis). Runtime call chain — yang bisa berbedang dari static call graph
  karena dispatch, reflection, callback — tidak ter-capture.

- **Usulan**:
  1. Tambah option `Backtrace bool` ke `FridaOptions`.
  2. Di `onEnter`, jika enabled: `var bt = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n')`.
  3. Log backtrace bersama args.
  4. Default OFF (overhead), ON via `--gen-frida-backtrace`.

- **Prioritas**: **TINGGI** — fitur RE fundamental yang missing.

### Gap 8: Tidak ada Dart String / object dereferencing

- **Deskripsi**: Hook dump register values sebagai hex string (`toString()`).
  Tidak ada attempt untuk membaca Dart object content. Untuk Dart String
  (Salah satu tipe paling umum di Dart app — log message, URL, SQL query,
  API endpoint), hook menampilkan `0x1234567890` alih-alih isi string.

  `script_gen.go:151-156` mendefinisikan `safeReadString` tetapi tidak
  pernah dipanggil — dead code. `safeReadPtr` (line 147-149) juga dead code.

- **Bukti SDK**:
  - `gh api` `raw_object.h?ref=3.12.2`:
    ```
    class UntaggedString : public UntaggedInstance {
      COMPRESSED_SMI_FIELD(SmiPtr, hash)
      COMPRESSED_SMI_FIELD(SmiPtr, length)
      // Variable length data follows here.
      uint8_t* data() { OPEN_ARRAY_START(uint8_t, uint8_t); }
    ```
  - Layout (compressed, Dart 2.18+/3.x): header(4) + hash(4) + length(4) +
    data[]. Tagged pointer = untagged + 1, jadi data offset dari tagged ptr
    = 4+4+4-1 = 11 (OneByteString).
  - `sdk/registers.go:225-228`: `ClassIdTagPosV3 = 12`, `ClassIdTagSizeV3 = 20`
    — class id di header bisa di-read untuk verify objek adalah String.

- **Dampak**: Untuk function yang menerima String parameter (e.g.
  `User.login(String username, String password)`), hook menampilkan
  pointer alih-alih `"admin"` / `"secret123"`. RE user harus manual
  dereference di Frida console untuk setiap call — sangat tidak efisien.

- **Usulan**:
  1. Tambah `derefDartObject(ptr, classId)` utility: baca header, extract
     cid, jika cid di range String class → baca length + data, return string.
  2. Tambah option `DerefStrings bool` ke `FridaOptions`.
  3. Di `onEnter`, jika enabled: untuk setiap arg register, cek apakah
     pointer ke heap object (bit 0 = 1), baca cid, jika String → deref.
  4. Gunakan `THR_FIELDS` map (sudah di-emit di script_gen.go tetapi tidak
     dipakai) untuk baca `object_null`/`bool_true`/`bool_false` dan
     compare dengan arg value → log `null`/`true`/`false` alih-alih hex.

- **Prioritas**: **TINGGI** — fitur RE paling requested untuk Dart app.

### Gap 9: DISPATCH_MAP dan THR_FIELDS di-emit tetapi tidak dipakai

- **Deskripsi**: `script_gen.go:86-112` meng-emit `DISPATCH_MAP` (2000
  entries) dan `THR_FIELDS` maps. Kedua map ini tidak pernah direferensikan
  oleh hook/probe code mana pun. `DISPATCH_MAP` bisa dipakai untuk resolve
  GDT call target dari cid (baca cid dari RCX/X0, lookup
  `DISPATCH_MAP[selectorOffset + cid]`). `THR_FIELDS` bisa dipakai untuk
  annotate THR-relative loads.

- **Bukti SDK**:
  - Dispatch table: `flow_graph_compiler_arm64.cc` —
    `Call(Address(DISPATCH_TABLE_REG, LR, UXTX, Scaled))` dimana
    `LR = cid + selector_offset`. Entry di dispatch table adalah Code
    entry point. `DISPATCH_MAP[index]` = target function name.
  - THR fields: `thread.h` CACHED_VM_STUBS_ADDRESSES_LIST —
    `THR_FIELDS[offset]` = stub name.

- **Dampak**: Script size membengkak (2000 dispatch entries + semua THR
  fields) tanpa fungsi tambahan. Dead data di generated script.

- **Usulan**:
  1. BLR probe dengan `via == "dispatch_table"`: baca cid register, baca
     dispatch table base, compute index, lookup `DISPATCH_MAP[index]` untuk
     resolve target name tanpa perlu Memory.readPointer.
  2. Atau hapus `DISPATCH_MAP`/`THR_FIELDS` dari script jika tidak akan
     dipakai (kurangi script size).
  3. THR hook: jika THR field load terdeteksi (via `THR_FIELDS` map),
     annotate dengan field name alih-alih hex offset.

- **Prioritas**: **MENENGAH** — dead code, bukan bug, tetapi waste.

### Gap 10: import.go membuang TypeSnapshots dan HeapObjects

- **Deskripsi**: `import.go:14-19` mendefinisikan:
  ```go
  type fridaRuntimeResult struct {
      DispatchResolutions []fridaDispatchResolution `json:"dispatch_resolutions"`
      TypeSnapshots       []fridaTypeSnapshot       `json:"type_snapshots"`
      CallGraph           map[string]int            `json:"call_graph"`
      HeapObjects         []fridaHeapObject         `json:"heap_objects"`
  }
  ```
  Tetapi code hanya memproses `DispatchResolutions` (merge ke call_edges)
  dan `CallGraph` (mark `runtime_confirmed`). `TypeSnapshots` dan
  `HeapObjects` hanya di-count untuk report (line 152-153), tidak di-merge
  ke output file mana pun.

- **Bukti SDK**: N/A — ini adalah AOTopsy internal data flow gap.

- **Dampak**: Runtime type information (register types observed at runtime)
  dan heap object inventory (class instances seen at runtime) — data
  berharga untuk type inference validation dan heap analysis — dikumpulkan
  tetapi dibuang. User harus manually parse frida_results.json untuk
  mengaksesnya.

- **Usulan**:
  1. Merge `TypeSnapshots` ke `functions.jsonl`: tambah field
     `runtime_types` per function (map register → type name).
  2. Merge `HeapObjects` ke `classes.jsonl`: tambah field
     `runtime_instance_count` per class.
  3. Atau tulis ke file terpisah: `runtime_types.jsonl`,
     `runtime_heap.jsonl` di output directory.

- **Prioritas**: **MENENGAH** — data terkumpul tetapi tidak accessible.

### Gap 11: Script/import protocol mismatch

- **Deskripsi**: `script_gen.go` mengirim data via `send()` dengan format:
  ```js
  send({type: 'function', name, args, ret});
  send({type: 'dispatch', blr_addr, from_func, reg, via, target_va, target_name, class_id});
  ```
  `import.go` mengharapkan JSON dengan top-level keys:
  ```go
  json.Unmarshal(data, &result) // result.dispatch_resolutions, result.type_snapshots, dll
  ```
  Tidak ada adapter di antara `send()` output dan `frida_import` input.
  User harus manually mengumpulkan `send()` messages dan reformasi ke
  `fridaRuntimeResult` JSON structure. Selain itu, script tidak mengirim
  `type_snapshots`, `call_graph`, atau `heap_objects` — field yang
  `import.go` harapkan.

- **Bukti SDK**: N/A — AOTopsy internal protocol gap.

- **Dampak**: `frida-import` command tidak bisa langsung mengkonsumsi
  output dari `frida-export --gen-script`. Workflow broken: export → run
  Frida → ??? → import. User harus menulis custom adapter script.

- **Usulan**:
  1. Tambah `onUnload` / `recv()` handler di generated script yang mengumpulkan
     semua data ke `fridaRuntimeResult` format dan `send()` sebagai batch.
  2. Atau tambah `frida-collect` subcommand yang menerima raw `send()` log
     dan konversi ke `fridaRuntimeResult` JSON.
  3. Pastikan script mengirim `call_graph` (dari Stalker summary) dan
     `type_snapshots` (dari register type sampling).

- **Prioritas**: **TINGGI** — workflow end-to-end broken.

### Gap 12: Dua generator parallel tidak konsisten

- **Deskripsi**: `generator.go` dan `script_gen.go` adalah dua implementasi
  paralel dengan behavior berbeda:

  | Aspek | generator.go | script_gen.go |
  |-------|-------------|---------------|
  | Input | `FuncIR` (live decompiler output) | `FridaMetadata` JSON |
  | Hook cap | `MaxFridaProbes = 300` (probes only) | `MAX_HOOKS = 50`, `MAX_PROBES = 100` |
  | Arg dump | `dumpArgs(ctx, regs)` — configurable regs | `args[0..3]` — hardcoded 4 |
  | Class id | Tidak di-capture | `extractClassId` (broken on x86_64) |
  | Stalker | Opt-in via `FridaOptions.Stalker` | Stalker.exclude only (no follow) |
  | Anti-crash | Tidak ada | `isGCThread()` filter, Houdini exclude |
  | send() vs console.log | `console.log` | `send()` |
  | FuncMap | Tidak ada (hook by VA) | `FUNC_MAP` (capped 500) |
  | Backtrace | Tidak ada | Tidak ada |
  | String deref | Tidak ada | `safeReadString` (dead code) |

  Dua generator menghasilkan script yang berbeda untuk binary yang sama,
  dengan fitur yang berbeda, dan tidak ada yang complete.

- **Bukti SDK**: N/A — AOTopsy internal architecture gap.

- **Dampak**: User bingung: `--gen-frida` (decompile-native) dan
  `frida-export --gen-script` menghasilkan script berbeda. Fitur yang ada
  di satu tidak ada di yang lain. Maintenance burden: bug fix harus
  dilakukan di dua tempat.

- **Usulan**:
  1. Konsolidasi: satu generator, satu code path. `script_gen.go`
     harus dibangun di atas `generator.go`'s primitives (atau
     sebaliknya).
  2. `FridaMetadata` → `[]FridaHook` + `[]FridaProbe` converter, lalu
     panggil `GenerateFridaScriptWithOptions`.
  3. Atau hapus salah satu: jika `frida-export` adalah primary workflow,
     hapus `--gen-frida` dari `decompile-native` dan route semuanya
     melalui `frida-export`.

- **Prioritas**: **MENENGAH** — technical debt, bukan bug, tetapi
  menyulitkan maintenance dan user experience.

## Register Tracking Gaps

### Register yang TIDAK Di-track di Hook Entry (onEnter)

| Register | ARM64 | x86_64 | Peran SDK | Status di Frida script |
|----------|-------|--------|-----------|----------------------|
| kClassIdReg (R0/RCX) | X0 | RCX | Class id untuk dispatch | ❌ Tidak di-capture (generator.go); broken di script_gen.go |
| ARGS_DESC_REG (R4/R10) | X4 | R10 | Arguments descriptor (runtime arity) | ❌ Tidak di-capture |
| CODE_REG (R24/R12) | X24 | R12 | Current Code object pointer | ❌ Tidak di-capture |
| DISPATCH_TABLE_REG (R21) | X21 | (RAX, di-load) | Dispatch table base | ❌ Tidak di-capture |
| FPU arg regs (V0-V5 / XMM1-XMM6) | V0-V5 | XMM1-XMM6 | Double/float arguments | ❌ Tidak di-capture |
| FPU return reg (V0 / XMM0) | V0 | XMM0 | Double return value | ❌ Tidak di-capture di onLeave |
| NULL_REG (R22) | X22 | (tidak ada) | Object::null() cache | ❌ Tidak di-capture |
| HEAP_BITS (R28) | X28 | (tidak ada) | heap_base decompression | ❌ Tidak di-capture |

### Register yang Di-track tetapi TIDAK Optimal

| Register | Issue |
|----------|-------|
| Receiver (X1/RDI) | Di-capture sebagai arg-0 GPR, tetapi tidak di-label sebagai "receiver" dan tidak di-dereference untuk extract class id / String content. |
| THR (X26/R14) | Tidak di-capture di hook entry. THR-relative field access (stub calls, object_null/bool_true/bool_false loads) tidak ter-annotate. |
| PP (X27/R15) | Tidak di-capture. Pool-relative loads tidak ter-annotate dengan pool entry display. |

### Register yang Di-track dengan Benar

| Register | Status |
|----------|--------|
| GPR arg regs (X1-X3,X5-X7 / RDI,RSI,RDX,RBX,R8,R9) | ✅ Di-capture via `dumpArgs` (generator.go) atau `args[0..3]` (script_gen.go, hanya 4) |
| GPR return reg (X0/RAX) | ✅ Di-capture via `retval` di onLeave |
| BLR target register | ✅ Di-capture di probe onEnter (ARM64); ❌ broken untuk memory operand (x86_64 GDT) |

## Fitur RE Missing/Incomplete

### Missing (tidak ada sama sekali)

1. **Backtrace capture** — `Thread.backtrace(this.context, Backtracer.ACCURATE)`
   di onEnter. Prioritas: TINGGI.

2. **Dart String dereferencing** — baca OneByteString/TwoByteString content
   dari tagged pointer. Layout: header(4) + hash(4) + length(4) + data[].
   Prioritas: TINGGI.

3. **Dart object class identification** — baca class id dari header, lookup
   class name dari `classes.jsonl`. Prioritas: TINGGI.

4. **Dispatch table runtime resolution** — baca cid register + dispatch
   table base, compute index, lookup target. Prioritas: TINGGI (x86_64).

5. **FFI call site hooking** — `FridaFFICallSite` ada di metadata tetapi
   tidak di-hook. FFI call site adalah point dimana Dart code memanggil
   native C function — critical untuk RE native interop. Prioritas: MENENGAH.

6. **String ref hooking** — `FridaStringRef` ada di metadata tetapi tidak
   di-hook. String ref adalah point dimana Dart string literal di-load
   dari pool — berguna untuk "string breakpoint". Prioritas: MENENGAH.

7. **Heap walk / object enumeration** — walk Dart heap dari THR fields
   (`top`, `end`, `new_space`) untuk enumerate live objects. Prioritas:
   RENDAH.

8. **GC safepoint detection** — hook `stack_overflow_shared_*_entry_point`
   (THR stub) untuk detect GC safepoint. Prioritas: RENDAH.

### Incomplete (ada tetapi tidak berfungsi penuh)

1. **BLR probe class id extraction** — broken pada x86_64 (Gap 1).
   Prioritas: KRITIS.

2. **x86_64 GDT call probing** — di-skip oleh CollectIndirectCallProbes
   (Gap 2) dan tidak handle di script_gen.go (Gap 3). Prioritas: KRITIS.

3. **Stalker call tracing** — hanya di `generator.go` (opt-in via
   `--gen-frida-stalker`), tidak di `script_gen.go`. Stalker.exclude
   untuk Houdini/libflutter hanya di script_gen.go. Tidak konsisten.
   Prioritas: MENENGAH.

4. **Type snapshot collection** — `fridaTypeSnapshot` struct ada di
   import.go tetapi script tidak mengirim type_snapshots. Prioritas:
   MENENGAH.

5. **Call graph collection** — `CallGraph` map ada di import.go tetapi
   script tidak mengirim call_graph data (Stalker summary tidak di-send
   ke importer). Prioritas: MENENGAH.

6. **Heap object collection** — `fridaHeapObject` struct ada di import.go
   tetapi script tidak mengirim heap_objects. Prioritas: RENDAH.

7. **`safeReadString`/`safeReadPtr`** — defined di script_gen.go:147-156
   tetapi never called. Dead code. Prioritas: RENDAH (cleanup).

8. **`DISPATCH_MAP`/`THR_FIELDS`** — emitted di script_gen.go:86-112
   tetapi never referenced. Dead data. Prioritas: RENDAH (cleanup).

## Verifikasi SDK

Semua claim tentang SDK register roles dan calling conventions diverifikasi
melalui dua jalur:

### Jalur 1: MCP `searchGitHub` (Vercel grep)

```
Tool: grep / searchGitHub
Repo: dart-lang/sdk
Query: "kClassIdReg = R0"
Hasil: runtime/vm/constants_arm64.h:485
  struct DispatchTableNullErrorABI {
    static constexpr Register kClassIdReg = R0;
  };
```

### Jalur 2: `gh api` @ tag 3.12.2

| File | Verifikasi |
|------|-----------|
| `runtime/vm/constants_arm64.h?ref=3.12.2` | `kCpuRegistersForArgs = {R1,R2,R3,R5,R6,R7}`, `kFpuRegistersForArgs = {V0..V5}`, `kClassIdReg = R0`, `CODE_REG = R24`, `ARGS_DESC_REG = R4`, `DISPATCH_TABLE_REG = R21`, `NULL_REG = R22`, `HEAP_BITS = R28`, `SPREG = R15`, `FPREG = R29`, `kSuspendStateReg = R2/R3` |
| `runtime/vm/constants_x64.h?ref=3.12.2` | `kCpuRegistersForArgs = {RDI,RSI,RDX,RBX,R8,R9}`, `kFpuRegistersForArgs = {XMM1..XMM6}`, `kClassIdReg = RCX`, `CODE_REG = R12`, `ARGS_DESC_REG = R10`, `kSuspendStateReg = RBX`, `kReturnReg = RAX`, `kReturnFpuReg = XMM0` |
| `runtime/vm/compiler/backend/flow_graph_compiler_arm64.cc?ref=3.12.2` | `EmitDispatchTableCall`: `cid_reg = kClassIdReg (R0)`, `AddImmediate(LR, cid_reg, offset)`, `Call(Address(DISPATCH_TABLE_REG, LR, UXTX, Scaled))` — BLR via register, bukan memory operand |
| `runtime/vm/compiler/backend/flow_graph_compiler_x64.cc?ref=3.12.2` | `EmitDispatchTableCall`: `cid_reg = kClassIdReg (RCX)`, `table_reg = RAX`, `call(Address(table_reg, cid_reg, TIMES_8, offset))` — CALL via memory operand `[rax+rcx*8+disp]` |
| `runtime/vm/compiler/assembler/assembler_arm64.cc?ref=3.12.2` | `SetupGlobalPoolAndDispatchTable`: `ldr(DISPATCH_TABLE_REG, Address(THR, Thread::dispatch_table_array_offset()))` — DISPATCH_TABLE_REG = R21 loaded from THR |
| `runtime/vm/thread.h?ref=3.12.2` | `CACHED_VM_STUBS_ADDRESSES_LIST`: write_barrier, array_write_barrier, call_to_runtime, allocate_object_*, stack_overflow_shared_*, call_native_through_safepoint, jump_to_frame, slow_type_test, resume_interpreter_adjusted, bootstrap/no_scope/auto_scope_native_wrapper, interpret_call. `write_barrier_wrappers_entry_points_[kNumberOfDartAvailableCpuRegs]` — per-register WB wrapper array. `object_null_`, `bool_true_`, `bool_false_` — cached VM objects. |
| `runtime/vm/raw_object.h?ref=3.12.2` | `UntaggedString`: `COMPRESSED_SMI_FIELD(hash)`, `COMPRESSED_SMI_FIELD(length)`, `data()` — String layout untuk deref. `UntaggedOneByteString`: variable-length `uint8_t data[]`. |

### Cross-reference: AOTopsy sdk package vs Frida script

| SDK Fact | `sdk/registers.go` | `frida/generator.go` | `frida/script_gen.go` |
|----------|---------------------|---------------------|----------------------|
| `kClassIdReg` ARM64 = R0 | ❌ tidak ada konstanta (hanya `ARM64ReturnReg=0`) | ❌ tidak dipakai | ❌ tidak dipakai (baca X1 sebagai receiver) |
| `kClassIdReg` x86 = RCX | ✅ `X86ClassIdReg = 1` | ❌ tidak dipakai | ❌ salah: baca RCX sebagai pointer |
| `ARGS_DESC_REG` ARM64 = R4 | ✅ `ARM64ArgsDesc = 4` | ❌ tidak di-capture | ❌ tidak di-capture |
| `ARGS_DESC_REG` x86 = R10 | ✅ `X86ArgsDesc = 10` | ❌ tidak di-capture | ❌ tidak di-capture |
| `CODE_REG` ARM64 = R24 | ✅ `ARM64CodeReg = 24` | ❌ tidak di-capture | ❌ tidak di-capture |
| `CODE_REG` x86 = R12 | ✅ `X86CodeReg = 12` | ❌ tidak di-capture | ❌ tidak di-capture |
| FPU arg regs ARM64 = V0-V5 | ✅ `ARM64FpuArgRegNames()` | ❌ tidak dipakai | ❌ tidak dipakai |
| FPU arg regs x86 = XMM1-6 | ✅ `X86FpuArgRegNames()` | ❌ tidak dipakai | ❌ tidak dipakai |
| FPU return reg ARM64 = V0 | ✅ `ARM64FpuReturnRegName` | ❌ tidak di-capture di onLeave | ❌ tidak di-capture |
| FPU return reg x86 = XMM0 | ✅ `X86FpuReturnRegName` | ❌ tidak di-capture di onLeave | ❌ tidak di-capture |
| `DISPATCH_TABLE_REG` ARM64 = R21 | ✅ `ARM64DT = 21` | ❌ tidak di-capture | ❌ tidak di-capture |
| Dart arg regs ARM64 = X1,X2,X3,X5,X6,X7 | ✅ `DartArgRegNames(true)` | ✅ dipakai via `RealArgRegs` | ❌ hardcoded `args[0..3]` |
| Dart arg regs x86 = RDI,RSI,RDX,RBX,R8,R9 | ✅ `DartArgRegNames(false)` | ✅ dipakai via `RealArgRegs` | ❌ hardcoded `args[0..3]` |

**Kesimpulan**: `sdk` package memiliki semua fakta SDK yang dibutuhkan, tetapi
`frida` package hanya menggunakan `DartArgRegNames` (GPR args). Semua register
peran lain (class id, args desc, code reg, dispatch table, FPU) — yang sudah
diverifikasi dan tersedia di `sdk` — tidak di-pass ke generated Frida script.
