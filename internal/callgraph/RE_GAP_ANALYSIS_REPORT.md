# RE Gap Analysis Report: internal/callgraph

> **STATUS VERIFIKASI (2026-09-01)** — kedelapan gap CONFIRMED, tidak ada
> koreksi. Detail: `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> Bukti yang dicek ulang: `BuildCallGraph` dipanggil di dalam Step 4
> (`disasm_stage.go:424`, `disasm_stagex86.go:255`) sementara
> `RunTypeInferenceStage` baru di `pipeline.go:259`; `callgraph.go:21-41` hanya
> membaca `TargetName`→`Via` dan mengabaikan `Kind`; dan `Edge.Args`,
> `CallSite.Args`, `BasicBlock.Props`, `FuncCFG.Children` benar-benar
> **nol produsen** di seluruh repo (hanya konsumen di
> `callgraph/render/cfg.go:55,79,86,203,263-318`).

## Ringkasan

Folder `internal/callgraph` adalah package DOT-rendering tipis: mengubah
`disasm.Inst`/`disasm.CallEdge` (in-memory, ARM64) dan
`decompiler.BuildX86IR` output (x86_64) menjadi `Graph` / `FuncCFG` /
`CFGGraph`, lalu `render.DOT` / `render.DOTCFG` mengemis Graphviz DOT.

Analisis menemukan **dua kelas gap besar**:

1. **Gap arsitektur yang terukur dan terverifikasi**: `BuildCallGraph`
   dipanggil **di dalam `RunDisasmStage` (Step 4 pipeline)** — **sebelum**
   `RunTypeInferenceStage` (Step 4.5) yang mengisi `CallEdgeRecord.Targets`
   (kandidat polymorphic BLR). Akibatnya `callgraph.dot` yang dihasilkan
   pipeline utama **kehilangan semua kandidat polymorphic BLR** — hanya
   `TargetName`/`Via` tunggal yang dipakai (`callgraph.go:26-32`). Jalur
   `_debug render` (membaca ulang JSONL post-typetrack) adalah satu-satunya
   yang memakai `ResolvedTargets()` dan mendapat polymorphism. Ini
   inkonsistensi output yang serius: dua "call graph" untuk binary yang
   sama dengan edge set berbeda.

2. **Fitur RE missing/incomplete**:
   - `Edge.Args`, `CallSite.Args`, `BasicBlock.Props`, `FuncCFG.Children`
     adalah **field dead** — dideklarasikan di `graph.go`, di-render
     (`render/callgraph.go:97`, `render/cfg.go:278-285`, `render/cfg.go:203`),
     tetapi **tidak pernah di-populate oleh siapa pun** di seluruh codebase
     (grep `\.Props\s*=|\.Children\s*=|Args:\s*\[` → 0 produsen). Label
     HTML argument-coloring dan prop-access rendering adalah dead UI.
   - `internal/callgraph/render` tidak memiliki: reachability filtering,
     entry-point detection, owner-based clustering, class-level aggregation,
     edge provenance classification (THR/PP/dispatch/object_field/direct/
     unresolved), edge-count weighting, stats, theme system. Semua fitur
     ini ada di `internal/render` (saudara rich-feature) tetapi **tidak
     di-port** ke `internal/callgraph/render` yang dipakai pipeline utama.
   - `CallEdge.Kind` (`"bl"`/`"blr"`/`"call"`/`"call_indirect"`) **diabaikan**
     total di `BuildCallGraph` dan `render.DOT` — semua edge di-render
     identik. Padahal `internal/render` mengklasifikasi provenance dan
     mewarnai/style berbeda.
   - Tail-call edge (`Kind: "tail_br"`/`"tail_b"`/`"tail_jmp"`/`"tail_jmp_ind"`)
     diusulkan di report `internal/disasm` tetapi konsumen `internal/callgraph`
     **tidak punya logic untuk menerima Kind baru** — `BuildCallGraph` hanya
     cek `TargetName`/`Via` non-empty, jadi edge tail-call dengan `TargetName`
     akan masuk tetapi tanpa label kind; edge tail-call indirect dengan Via
     kosong akan di-skip sama seperti BLR unresolved.

Tidak ada register-tracking di package ini (pure rendering), sehingga
"Register Tracking Gaps" section fokus pada data yang **tidak diteruskan**
dari upstream (`disasm.CallEdge.ArgCountHint`, `ArgRegMask`, `Kind`, `Reg`)
yang seharusnya berguna untuk anotasi call graph RE.

## Struktur Folder

| File | Peran |
|------|------|
| `callgraph.go` | `FuncInfo` struct + `BuildCallGraph`: konversi `[]FuncInfo` → `Graph` (nodes/edges). Edge dipilih via `TargetName` fallback `Via`, skip jika kosong. `Dedup` by (Caller,Callee). |
| `cfg.go` | `BuildFuncCFG` (ARM64): wrap `disasm.BuildCFG`, `convertFuncCFG` map `disasm.FuncCFG` → `FuncCFG`, attach `CallEdge` ke block via `edgeByPC[FromPC]` lookup. Fallback callee = `0x%x` TargetPC. |
| `cfgx86.go` | `BuildX86FuncCFG` (x86_64): wrap `decompiler.BuildX86IR` + `DecodeX86Range`, `convertX86FuncCFG` map `decompiler.FuncIR` → `FuncCFG`. Same edge-attach pattern. |
| `graph.go` | Tipe data: `Edge{Caller,Callee,Args}`, `Graph{Nodes,Edges}+Dedup`, `CallSite{Offset,Callee,Args}`, `Successor{BlockID,Cond}`, `PropAccess{Name}`, `BasicBlock{ID,Start,End,Calls,Props,Succs,Term}`, `FuncCFG{Name,Blocks,Children}`, `CFGGraph{Funcs}`. Vendored from lattice. |
| `cfg_test.go` | 2 test: `TestBuildCFG_DOTOutput` (4-block ARM64 CFG), `TestBuildCallGraph_DOTOutput` (4-func graph dengan BLR Via). |
| `render/callgraph.go` | `DOT(g *Graph, title)` — DOT render call graph. Style NASA/Bauhaus. Special-case `main` (blue), `anon#*` (dashed gray), external (plaintext red/gray by IsAllCaps). `formatEdgeLabel` untuk Args (dead — Args never populated). |
| `render/cfg.go` | `DOTCFG(g *CFGGraph, title)` — DOT render CFG per-function cluster. Style Japanese minimalist. `ResolveTarget` follow empty-block chain. `buildBlockLabel` HTML label dengan calls+props (props dead). Cross-function edges via `lhead=cluster_N`. Self-recursion dashed. Parent→child via `f.Children` (dead). |
| `render/helpers.go` | `DotEscape`, `DotID` (safe identifier), `IsAllCaps` (constant detection). |

## Gap Analysis

### Gap 1: `BuildCallGraph` dijalankan sebelum type inference — polymorphic BLR candidates hilang dari `callgraph.dot` pipeline

- **Deskripsi**: Pipeline `internal/analysis/pipeline.go:245` menjalankan
  `RunDisasmStage` (Step 4) yang **di dalamnya** memanggil
  `callgraph.BuildCallGraph(funcInfos)` (`disasm_stage.go:424`) dan menulis
  `callgraph.dot`. Step 4.5 `RunTypeInferenceStage` (`pipeline.go:259`)
  yang mengisi `CallEdgeRecord.Targets` (kandidat polymorphic) baru
  berjalan **setelahnya** (`typetrack_stage.go:672`: `e.Targets =
  res.TargetNames`).

  `BuildCallGraph` (`callgraph.go:21-41`) hanya menerima
  `FuncInfo{CallEdges []disasm.CallEdge}` — dan `disasm.CallEdge`
  (`disasm/calledge.go:13-40`) **tidak punya field `Targets []string`**,
  hanya `TargetName string` dan `Via string`. Jadi meskipun type inference
  sudah berjalan, tipenya tidak bisa membawa polymorphic candidates ke
  `BuildCallGraph` tanpa refactor signature.

  Akibatnya: untuk binary dengan N polymorphic BLR site (Dart 3.9.2 sample
  punya 2997 polymorphic BLR per catatan `agents.md`), `callgraph.dot`
  pipeline utama hanya menampilkan **satu edge per site** (Via terakhir
  atau kosong), bukan N kandidat. `internal/render.CallgraphDOT` (jalur
  `_debug render`, baca JSONL) memakai `e.ResolvedTargets()` dan mendapat
  semua kandidat. **Dua output call graph untuk binary yang sama berbeda
  edge set-nya.**

- **Bukti SDK**:
  - `runtime/vm/instructions_arm64.cc` (`ICCallPattern`, `BareSwitchableCallPattern`):
    AOT call site adalah `blr lr` setelah pool-load code_reg. Resolusi
    callee-nya adalah ICData/dispatch-table — **polymorphic by design**.
    Verifikasi grep MCP `searchGitHub` query `"BareSwitchableCallPattern"`
    repo `dart-lang/sdk` → konfirmasi `instructions_arm64.cc:468`
    `ASSERT(*(pc-1) == 0xd63f03c0)` (blr lr).
  - `runtime/vm/instructions_arm64.h:132` `SwitchableCallPattern`:
    "target slot is always a [Code] object: Either the code of the
    monomorphic function or a stub code." — runtime bisa patch target,
    sehingga satu site bisa call multiple callee sepanjang waktu.
  - `internal/disasm/types.go:62` `ResolvedTargets()` — policy
    polymorphic: `Target` → `Targets` → `Via` → nil. `internal/callgraph`
    tidak memakai helper ini (tidak bisa — tipenya `disasm.CallEdge` bukan
    `CallEdgeRecord`).

- **Dampak**: `callgraph.dot` dari pipeline utama (yang dipakai HTML
  report `internal/render/html.go:116` link "Function-level graph")
  underestimate edge count untuk semua polymorphic dispatch. RE yang
  memakai callgraph.dot untuk trace reachability akan miss fungsi yang
  hanya reachable via polymorphic BLR candidate. Inkonsistensi dengan
  `internal/render.CallgraphDOT` (jalur debug) membuat validasi cross-tool
  sulit.

- **Usulan**: Refactor `BuildCallGraph` untuk menerima `[]FuncInfo` yang
  membawa `Targets []string` (tambah field di `FuncInfo.CallEdges` atau
  pindah ke `CallEdgeRecord`). Pindahkan pemanggilan `BuildCallGraph` +
  `render.DOT` **keluar dari `RunDisasmStage`** ke step post-typetrack
  (Step 4.7), baca ulang `call_edges.jsonl` seperti `xref.go` lakukan, dan
  pakai `ResolvedTargets()` untuk expand polymorphic. Alternatif lebih
  kecil: tambah `render.DOT` path yang menerima `[]CallEdgeRecord` langsung
  (sudah ada di `internal/render.CallgraphDOT` — bisa di-adopsi). Prioritas
  **tinggi** — ini adalah bug output yang terukur.

- **Prioritas**: **tinggi**

### Gap 2: `Edge.Args`, `CallSite.Args`, `BasicBlock.Props`, `FuncCFG.Children` — field dead, rendering-nya pura-pura

- **Deskripsi**:
  - `graph.go:14` `Edge.Args []string` — di-render `render/callgraph.go:59`
    `formatEdgeLabel(e.Args)`, tetapi `BuildCallGraph` (`callgraph.go:33`)
    mengemis `Edge{Caller, Callee}` **tanpa Args**. Grep `Args:\s*\[|\.Args =`
    di seluruh repo → hanya test `arch/x86/helpers_test.go` (unrelated) dan
    render-side reads. **Tidak ada produsen.**
  - `graph.go:53` `CallSite.Args []string` — di-render `render/cfg.go:294-308`
    (HTML argument coloring), tetapi `convertFuncCFG` (`cfg.go:53`) dan
    `convertX86FuncCFG` (`cfgx86.go:55`) mengemis `CallSite{Offset, Callee}`
    **tanpa Args**. Tidak ada produsen.
  - `graph.go:73` `BasicBlock.Props []PropAccess` — di-render
    `render/cfg.go:278-285, 315-318`, dipakai di `hasContent` decision
    (`cfg.go:55`). Tidak ada produsen. `Props` selalu nil → blok dengan
    hanya Props dianggap tidak punya konten dan di-skip.
  - `graph.go:86` `FuncCFG.Children []int` — di-render `render/cfg.go:203-211`
    (parent→child edge). Tidak ada produsen. `Children` selalu nil → tidak
    ada parent→child edge pernah di-render.

  Field-field ini diwariskan dari vendored lattice (zboralski/lattice)
  yang aslinya untuk bytecode/source scanning. Di AOTopsy, scanning
  dilakukan di `disasm`/`decompiler` yang tidak mengemis Props/Children/
  Args, sehingga field-nya jadi dead UI — label HTML argument-coloring,
  prop-access row, parent→child cluster edge semua tidak pernah fires.

- **Bukti SDK**: N/A — ini adalah gap fitur RE AOTopsy, bukan fakta SDK.
  Field `Args` relevan secara konsep: SDK `CallEdge.ArgCountHint`/
  `ArgRegMask` (`disasm/calledge.go:31-39`) sudah menginfer arg count per
  site, dan `ARGS_DESC_REG` (R4 ARM64 / R10 x86, lihat report
  `internal/disasm` Gap 5) membawa descriptor deterministik. Tidak
  ada alasan `CallSite.Args` tidak bisa di-populate dari data yang sudah
  ada.

- **Dampak**:
  - `render.DOT` edge label `(arg1, arg2)` tidak pernah muncul — padahal
    untuk RE Dart AOT, arg literal (string, bool, null) di call site
    adalah sinyal kuat (mis. `Logger.log("auth_token")`).
  - `render.DOTCFG` block label tidak pernah menampilkan prop access
    (field read, getter) — padahal field access adalah mayoritas instruksi
    Dart AOT.
  - Parent→child edge (nested closure, local function) tidak pernah
    di-render — padahal Dart punya local function dan closure yang
    di-compile sebagai fungsi terpisah dengan parent reference.

- **Usulan**:
  1. **Hapus field dead** jika tidak akan di-implement (destruktif, sesuai
     rule): buang `Edge.Args`, `CallSite.Args`, `BasicBlock.Props`,
     `FuncCFG.Children` + semua rendering-nya. Ini mengurangi ~60 baris
     dead code dan menghilangkan false impression of capability.
  2. **ATAU implement**:
     - `CallSite.Args`: di `convertFuncCFG`, saat attach CallEdge, baca
       `CallEdge.ArgCountHint` dan seed `Args = []string{"<arg0>", ...}`
       (placeholder count-based) — minimal. Lebih baik: integrasi dengan
       `decompiler` yang sudah infer arg literal.
     - `BasicBlock.Props`: scan instruksi di block untuk PP-load yang
       resolve ke string/class name (sudah ada di
       `disasm.ExtractStringRefs`), attach sebagai PropAccess.
     - `FuncCFG.Children`: butuh info parent-function dari cluster
       (snapshot punya parent field di Code object) — integrasi
       `internal/cluster`.
  Pilihan (2) lebih ambisius; (1) adalah cleanup jujur. **Pilih satu,
  jangan biarkan dead.**

- **Prioritas**: **sedang** — dead code yang menyesatkan; implementasi
  fitur adalah bonus RE signifikan.

### Gap 3: `CallEdge.Kind` diabaikan — semua edge di-render identik (no provenance/style differentiation)

- **Deskripsi**: `disasm.CallEdge.Kind` (`calledge.go:15`) bernilai
  `"bl"`, `"blr"`, `"call"`, `"call_indirect"` (dan future `"tail_*"`).
  `BuildCallGraph` (`callgraph.go:21-41`) **tidak pernah membaca Kind** —
  semua edge jadi `Edge{Caller, Callee}` seragam. `render.DOT`
  (`render/callgraph.go:56-89`) hanya membedakan: inner vs external,
  `main` vs `anon#*` vs default, `IsAllCaps` vs not. **Tidak ada
  diferensiasi BL direct vs BLR indirect vs dispatch-table vs THR stub vs
  PP-load vs object-field.**

  Bandingkan `internal/render.callgraph.go:21-76` yang punya
  `ClassifyEdgeProv` → 6 kategori (ProvTHR, ProvPP, ProvDispatch,
  ProvObject, ProvDirect, ProvUnresolved) + `edgeColor` + `edgeStyle`
  (solid/dotted/dashed) per kategori. Itu memberi RE visual cue langsung:
  edge merah = THR stub, edge biru = PP-resolved, dotted = dispatch table,
  dashed = unresolved.

- **Bukti SDK**:
  - `runtime/vm/instructions_arm64.cc` `ICCallPattern` (grep MCP
    konfirmasi): AOT instance call = `ldr code_reg, [pp, #idx]; ldr lr,
    [code_reg, #entry]; blr lr` — provenance PP.
  - `BareSwitchableCallPattern` (grep MCP konfirmasi `instructions_arm64.cc:468`):
    AOT switchable call = pool-load target entry, `blr lr` — provenance PP
    (target slot).
  - `runtime/vm/instructions_arm64.cc` `MonomorphicSmCallSite` (lihat
    report `internal/disasm`): dispatch-table call — provenance
    dispatch_table.
  - THR stub call: `blr X16` dengan X16 dimuat dari THR field — provenance
    THR.
  - Object-field call (rare): `ldr xN, [obj, #field]; blr xN` — provenance
    object_field.
  - Direct BL: `bl #offset` — provenance direct.
  Kelima kategori ini adalah **fakta SDK yang berbeda secara semantik**
  dan seharusnya visual berbeda di call graph RE.

- **Dampak**: RE yang melihat `callgraph.dot` pipeline utama tidak bisa
  membedakan "edge ini adalah virtual dispatch yang mungkin polymorphic"
  vs "edge ini adalah direct call ke fungsi known" vs "edge ini adalah
  THR stub (runtime)". Untuk triase RE (prioritas fungsi mana yang
  di-reverse duluan), provenance edge adalah sinyal kunci: direct BL ke
  fungsi named = high-confidence; BLR unresolved = perlu type inference.

- **Usulan**: Tambahkan `Kind`/`Prov` field di `Edge` (`graph.go:11`).
  Di `BuildCallGraph`, baca `e.Kind` dan `e.Via` → klasifikasi provenance
  (port `ClassifyEdgeProv` dari `internal/render`). Di `render.DOT`,
  mewarnai/style per prov. Perubahan kecil (~40 baris di callgraph.go +
  render/callgraph.go). Lebih baik lagi: **konsolidasikan**
  `internal/callgraph/render` ke `internal/render` (lihat Gap 5) sehingga
  tidak duplikasi logic.

- **Prioritas**: **tinggi** — provenance edge adalah fitur RE core.

### Gap 4: Tidak ada reachability filtering, entry-point detection, owner-clustering, class-level aggregation, stats

- **Deskripsi**: `internal/callgraph/render` hanya mengemis raw graph
  (semua node, semua edge). Fitur RE standar yang **ada di
  `internal/render`** tetapi **tidak di `internal/callgraph/render`**:

  | Fitur | `internal/render` | `internal/callgraph/render` |
  |-------|-------------------|------------------------------|
  | `FindEntryPoints` (func tanpa incoming BL/BLR) | `reachability.go:13` | ❌ |
  | `ReachableSet` BFS dari entry | `reachability.go:45` | ❌ |
  | `ReachabilityDOT` (filter ke reachable) | `reachability.go:87` | ❌ |
  | Owner-based clustering (`subgraph cluster_*`) | `callgraph.go:208` | ❌ |
  | `ClassgraphDOT` (class-level aggregation) | `classgraph.go:24` | ❌ |
  | `ComputeStats` (TopCallers/Callees/Owners, ProvCounts) | `callgraph.go:300` | ❌ |
  | Edge-count weighting (`penwidth`, `Nx` label) | `callgraph.go:266` | ❌ |
  | `maxNodes` truncation | `callgraph.go:132` | ❌ |
  | Theme system (`Theme` struct, NASA palette) | `theme.go` | hardcoded |
  | `stripOwnerHash`, `stripMethodName`, `truncLabel` | `helpers.go` | ❌ |

  Pipeline utama (`disasm_stage.go:424-432`) memakai
  `callgraph.BuildCallGraph` + `render.DOT` (versi miskin). Jalur
  `_debug render` (`cmd_debug_graph.go:115`) memakai
  `render.CallgraphDOT` (versi rich). **Output pipeline utama lebih
  jelek dan kurang informatif daripada output debug.**

- **Bukti SDK**: N/A — fitur RE tooling. Namun konsep "entry point" dan
  "reachability" relevan: SDK AOT tidak punya main() tunggal (semua
  fungsi adalah Code object di snapshot, dipanggil via entry point
  table). RE perlu identifikasi entry point (fungsi yang tidak dipanggil
  oleh siapa pun = kandidat top-level / event handler / lifecycle).

- **Dampak**: `callgraph.dot` pipeline utama untuk app besar (129k fungsi)
  adalah satu file DOT raksasa dengan semua node — Graphviz render lambat,
  tidak terbaca, tidak ada highlight entry/reachable. RE harus manual
  filter atau jalankan `_debug render` terpisah. Inkonsistensi dua jalur
  output.

- **Usulan**: **Konsolidasi** `internal/callgraph/render` ke
  `internal/render` (Gap 5), atau port fitur-fitur ini ke
  `internal/callgraph/render`. Yang lebih jujur: hapus
  `internal/callgraph/render` dan pakai `internal/render` di pipeline
  utama (baca JSONL post-typetrack, sama seperti `xref.go`). Ini
  menghilangkan duplikasi dan membuat pipeline utama dan debug output
  identik.

- **Prioritas**: **tinggi** — fitur RE core missing di jalur utama.

### Gap 5: Dua package render paralel (`internal/callgraph/render` vs `internal/render`) — duplikasi, drift, inkonsistensi

- **Deskripsi**: Dua package yang sama-sama render DOT call graph:
  - `internal/callgraph/render` (DOT, DOTCFG) — dipakai pipeline utama
    (`disasm_stage.go:289,425`), input `callgraph.Graph`/`CFGGraph`
    (in-memory, pre-typetrack).
  - `internal/render` (CallgraphDOT, ClassgraphDOT, ReachabilityDOT,
    CFGDOT, ComputeStats, FindEntryPoints, ReachableSet) — dipakai
    `_debug render` (`cmd_debug_graph.go:115`), input
    `[]disasm.FuncRecord`/`[]CallEdgeRecord` (JSONL, post-typetrack).

  Keduanya punya: `dotEscape`/`DotEscape`, `dotID`/`DotID` (identik),
  `IsAllCaps` (hanya callgraph), `digraph callgraph` preamble (sama:
  rankdir=LR, splines=true, nodesep=0.4, ranksep=0.6). Tetapi
  `internal/render` punya 5x fitur lebih banyak (lihat Gap 4). Drift
  sudah terjadi: `internal/callgraph/render` hardcode NASA palette di
  `DOT` dan Japanese palette di `DOTCFG`; `internal/render` punya
  `Theme` struct + `NASA` constant.

- **Bukti SDK**: N/A — arch issue.

- **Dampak**: Maintenance ganda, drift perilaku, RE bingung mana output
  yang authoritative. Bug fix di satu package tidak propagasi. Output
  pipeline utama (yang dipakai HTML report) lebih miskin daripada output
  debug.

- **Usulan**: **Hapus `internal/callgraph/render`** dan refactor pipeline
  utama (`disasm_stage.go`, `disasm_stagex86.go`) untuk baca ulang
  `call_edges.jsonl` + `functions.jsonl` post-typetrack dan panggil
  `internal/render.CallgraphDOT` + `ReachabilityDOT` + `ClassgraphDOT`.
  Pindahkan `DOTCFG` (per-function CFG, tidak ada equivalent di
  `internal/render` untuk CFGGraph multi-func cluster) ke
  `internal/render` sebagai `CFGGraphDOT`, atau keep di callgraph tapi
  tanpa package render terpisah. Perubahan besar (~150 baris refactor)
  tetapi eliminasi duplikasi permanen.

- **Prioritas**: **tinggi** — root cause dari Gap 1, 3, 4.

### Gap 6: Tail-call edge (`tail_br`/`tail_b`/`tail_jmp`/`tail_jmp_ind`) tidak diterima oleh konsumsi callgraph

- **Deskripsi**: Report `internal/disasm` Gap 3 mengusulkan emisi edge
  tail-call dengan `Kind` baru. Tetapi `BuildCallGraph`
  (`callgraph.go:21-41`) tidak punya logic khusus untuk Kind tail-call:
  - Edge dengan `TargetName` non-empty akan masuk (OK, tapi tanpa label
    "tail" — tidak bisa dibedakan dari BL).
  - Edge tail-call indirect (`tail_jmp_ind`) dengan `Via` kosong akan
    **di-skip** (`callgraph.go:30-32` `if callee == "" continue`) sama
    seperti BLR unresolved.
  - `render.DOT` tidak punya style untuk tail-call (tail-call seharusnya
    visual berbeda — mis. arrowhead=empty atau style=dashed berbeda dari
    BLR unresolved).

- **Bukti SDK**:
  - `runtime/vm/compiler/assembler/assembler_arm64.cc:2161`
    `GenerateUnRelocatedPcRelativeTailCall` — emit `b <offset>` (grep MCP
    konfirmasi `PcRelativeTailCallPattern` repo `dart-lang/sdk` →
    `instructions_arm64.cc:512` `bool PcRelativeTailCallPattern::IsValid()
    { return (word >> 26) == 0x5; }` = B unconditional).
  - `runtime/vm/instructions_x64.h:191` `PcRelativeTailCallPattern`
    extends `PcRelativeTrampolineJumpPattern` (0xe9 JMP rel32).
  - `runtime/vm/compiler/assembler/assembler_arm64.h:491`
    `void Jump(Register target) { br(target); }` — indirect tail call.
  Tail call adalah edge call graph yang sah (caller → callee, control
  transfer penuh, tidak return ke caller).

- **Dampak**: Ketika `internal/disasm` implement tail-call edge (Gap 3
  report disasm), `internal/callgraph` tidak akan otomatis mendapat
  benefit — perlu konsumen update. Tanpa update, tail-call indirect
  dengan Via kosong tetap missing, dan tail-call direct tidak terlabel
  kind.

- **Usulan**: Tambah `Kind` field di `Edge` (Gap 3). Di `BuildCallGraph`,
  terima semua Kind dengan `TargetName`/`Via`/`Targets` non-empty (jadi
  tail-call direct masuk). Untuk tail-call indirect dengan Via kosong,
  pertimbangkan fallback ke `0x%x` TargetPC (seperti `convertFuncCFG`
  lakukan untuk CallSite) supaya edge tetap masuk sebagai node alamat.
  Di `render.DOT`, style tail-call berbeda (mis. `arrowhead=empty,
  style=bold`). Perubahan kecil setelah Gap 3.

- **Prioritas**: **sedang** — dependen pada implementasi upstream
  (`internal/disasm` Gap 3).

### Gap 7: `convertFuncCFG` edge-attach by `FromPC` — collision jika dua edge share PC (rare but possible di dataflow)

- **Deskripsi**: `cfg.go:21-24` dan `cfgx86.go:36-39` bangun
  `edgeByPC := make(map[uint64]disasm.CallEdge, len(edges))` dengan key
  `e.FromPC`. Jika dua edge berbeda punya `FromPC` sama (mis. BLR dan
  tail-call di PC yang sama, atau dataflow emit duplikat), **edge
  kedua menimpa edge pertama** di map. `cfg_test.go` hanya uji 3 edge
  dengan PC berbeda — tidak cover collision.

  `disasm.CallEdge` di-emis satu per instruksi call-site di
  `dataflowarm64.go:175,190` — secara normal satu PC satu edge. Tetapi
  setelah `typetrack_stage` menambah `Targets`, dan jika future tail-call
  di-emis di PC yang sama dengan BLR (kasus: `blr lr` yang sebenarnya
  tail-call), map akan collide.

- **Bukti SDK**: N/A — implementation detail. Tetapi konseptual: satu
  instruksi `blr lr` bisa di-interpret sebagai call (ICCallPattern) atau
  tail-call (Jump) tergantung konteks — SDK membedakan via pattern
  match, AOTopsy bisa emit dua edge berbeda.

- **Dampak**: Edge hilang dari CFG rendering jika collision terjadi.
  Silent — tidak ada error, hanya edge count berkurang.

- **Usulan**: Ganti `edgeByPC` ke `map[uint64][]disasm.CallEdge` (slice
  per PC) dan iterate semua edge di block-range. Atau dedup edge by
  (FromPC, Kind, TargetName, Via) sebelum map. Perubahan kecil (~10
  baris).

- **Prioritas**: **rendah** — kasus collision belum terbukti di sample
  binaries, tetapi fragile.

### Gap 8: `DOTCFG` cross-function edge hanya ke entry block (block 0), bukan ke block spesifik yang berisi call

- **Deskripsi**: `render/cfg.go:155` `dstID := blockNodeID(targetFI, 0)`
  — cross-function call edge selalu ke entry block fungsi target, bukan
  ke block yang berisi callee (yang selalu entry block anyway untuk
  function call, jadi ini benar secara semantik). Tetapi untuk
  self-recursion (`cfg.go:166` `dstID := blockNodeID(fi, 0)`) juga ke
  entry block — OK. Yang gap: **tidak ada edge dari block berisi RET ke
  block caller continuation** (return edge) — wajar, CFG intra-function
  tidak track return. Tetapi untuk CFGGraph multi-function, tidak ada
  visualisasi "call return" — RE tidak bisa trace "fungsi A call B, B
  return ke A di block mana".

  Lebih konkret: `DOTCFG` tidak punya edge data-flow antar fungsi
  selain call edge. Arg flow (X0-X7 di call site → arg di callee entry)
  tidak di-render. Untuk RE Dart AOT, arg flow adalah sinyal kuat (mis.
  receiver type di X0).

- **Bukti SDK**: N/A — fitur RE. Dart AOT calling convention:
  `DartCallingConvention` (ARM64 sejak 3.4.3, lihat `agents.md`) —
  receiver di X0, args di X1-X7, descriptor di ARGS_DESC_REG.

- **Dampak**: CFG multi-function tidak menunjukkan arg flow — RE harus
  cross-reference manual antara call site dan callee entry.

- **Usulan**: Tambah opsi `--with-arg-flow` di `DOTCFG` yang render edge
  dari call site ke callee entry dengan label arg register (X0=receiver,
  X1=arg1, ...). Butuh data arg dari `CallEdge.ArgRegMask` (sudah ada di
  `disasm.CallEdge`). Perubahan menengah.

- **Prioritas**: **rendah** — nice-to-have, bukan gap core.

## Register Tracking Gaps

Package `internal/callgraph` adalah pure rendering — tidak melakukan
register tracking sendiri. Gap di sini adalah **data register/arg yang
sudah ditrack upstream tetapi tidak diteruskan ke rendering**:

| Field upstream | Di-track di | Diteruskan ke callgraph? | Dampak |
|----------------|-------------|--------------------------|--------|
| `disasm.CallEdge.ArgCountHint` | `dataflowarm64.go:175` | ❌ tidak | Arg count per call site hilang dari DOT label |
| `disasm.CallEdge.ArgRegMask` | `dataflowarm64.go:175` | ❌ tidak | Arg register shape (X0-only vs X0+X1) hilang |
| `disasm.CallEdge.Kind` | `dataflowarm64.go:175,190` | ❌ tidak (Gap 3) | No provenance differentiation |
| `disasm.CallEdge.Reg` | `dataflowarm64.go:190` | ❌ tidak | BLR register (X16, LR) hilang dari label |
| `disasm.CallEdge.TargetPC` | `dataflowarm64.go:175` | ❌ tidak di BuildCallGraph (hanya di convertFuncCFG fallback) | Edge ke fungsi unnamed tidak punya node alamat di callgraph.dot |
| `decompiler.FuncIR.ArgRegs/FrameReg/ReturnReg/PoolReg/ThreadReg/NullReg/CodeReg/ArgsDescReg/HeapBitsReg` | `decompiler/ir.go:82-111` | ❌ tidak | Register ABI context hilang dari CFG label |
| `disasm.Inst.Mnemonic/Operands` | `disasm/arm64.go:17-18` | ❌ tidak (hanya `Text`) | CFG block label (`render/cfg.go:buildBlockLabel`) hanya tampilkan callee name, bukan instruksi |

**Catatan**: `internal/render/cfg.go:42-46` (`CFGDOT`) menampilkan
`inst.Addr` + `inst.Text` per instruksi (full disasm di block label),
sedangkan `internal/callgraph/render/cfg.go:buildBlockLabel` hanya
menampilkan callee name + Args (dead). Ini perbedaan besar: CFGDOT
(debug) informatif untuk RE instruction-level, DOTCFG (pipeline) hanya
call-level. Untuk RE Dart AOT, instruction-level CFG jauh lebih berguna.

## Fitur RE Missing/Incomplete

1. **Polymorphic BLR expansion di callgraph.dot pipeline** (Gap 1) —
   kandidat multi-callee dari type inference tidak muncul.
2. **Edge provenance coloring** (Gap 3) — THR/PP/dispatch/object/direct/
   unresolved tidak dibedakan visual.
3. **Reachability filtering & entry-point highlight** (Gap 4) — semua
   node di-render, tidak ada filter reachable set.
4. **Owner-based clustering** (Gap 4) — fungsi tidak di-group per class
   owner di cluster subgraph.
5. **Class-level aggregation graph** (Gap 4) — tidak ada classgraph.dot
   di pipeline utama (hanya di `_debug render`).
6. **Call-site argument display** (Gap 2) — `Edge.Args`/`CallSite.Args`
   dead, arg literal (string/bool/null) tidak muncul di edge label.
7. **Property access display di CFG** (Gap 2) — `BasicBlock.Props` dead,
   field read tidak muncul di block label.
8. **Parent→child function edge** (Gap 2) — `FuncCFG.Children` dead,
   nested closure/local function relationship tidak di-render.
9. **Tail-call edge support** (Gap 6) — konsumen tidak siap menerima
   Kind tail-call.
10. **Instruction-level CFG label** (Register Tracking Gaps) — DOTCFG
    hanya callee name, bukan disasm line per instruksi (CFGDOT punya).
11. **Stats / top callers / top callees** (Gap 4) — tidak ada di
    pipeline utama.
12. **Theme system** (Gap 5) — hardcoded palette, tidak configurable.
13. **maxNodes truncation** (Gap 4) — app besar (129k fungsi) menghasilkan
    DOT tidak terbaca.
14. **Edge-count weighting** (Gap 4) — edge dengan count > 1 tidak
    di-bold/label Nx.
15. **Cross-architecture parity** — `BuildFuncCFG` (ARM64) dan
    `BuildX86FuncCFG` (x86) duplikasi logic convertFuncCFG; perbedaan
    hanya sumber block (disasm.FuncCFG vs decompiler.FuncIR). Tidak ada
    shared abstraction.

## Verifikasi SDK

| Fakta | Sumber SDK | Metode verifikasi |
|-------|------------|-------------------|
| `PcRelativeTailCallPattern` ada di ARM64/x86/ARM/RISC-V | `runtime/vm/instructions_arm64.h:230`, `instructions_x64.h:191`, `instructions_arm.h:220`, `instructions_riscv.h:223` | grep MCP `searchGitHub` query `"PcRelativeTailCallPattern"` repo `dart-lang/sdk` → 10+ file konfirmasi |
| `GenerateUnRelocatedPcRelativeTailCall` emit `b <offset>` (ARM64 tail call direct) | `runtime/vm/compiler/assembler/assembler_arm64.cc:2161` | grep MCP konfirmasi snippet: `EmitUnconditionalBranchOp(B, 0); pattern.set_distance(...)` |
| ARM64 `PcRelativeTailCallPattern::IsValid` = `(word >> 26) == 0x5` (B unconditional) | `runtime/vm/instructions_arm64.cc:512` | grep MCP konfirmasi |
| `ICCallPattern` ARM64: last instr `blr lr`, pool-load code_reg sebelumnya | `runtime/vm/instructions_arm64.cc:32` | grep MCP `searchGitHub` query `"ICCallPattern"` repo `dart-lang/sdk` → konfirmasi `ASSERT(IsBranchLinkScratch(reg))` + "Last instruction: blr lr" |
| `BareSwitchableCallPattern` AOT: `ASSERT(*(pc-1) == 0xd63f03c0)` (blr lr) | `runtime/vm/instructions_arm64.cc:468` | grep MCP `searchGitHub` query `"BareSwitchableCallPattern"` repo `dart-lang/sdk` → konfirmasi |
| `SwitchableCallPattern`: "target slot is always a [Code] object: monomorphic function or stub" | `runtime/vm/instructions_arm64.h:132` | grep MCP konfirmasi snippet |
| Tail call adalah edge call graph sah (control transfer penuh, no return to caller) | `Jump(Register target) { br(target); }` `assembler_arm64.h:491` | grep MCP konfirmasi via `PcRelativeTailCallPattern` context |

**Catatan verifikasi**:
- Tidak ada `MegalomorphicCallPattern` di SDK (grep MCP query
  `"MegaMorphicCallPattern"` → "No results found"). Nama yang benar
  adalah `SwitchableCallPattern` / `BareSwitchableCallPattern` (AOT).
- `MonomorphicSmCallSite` juga tidak ditemukan via grep MCP
  (`"MonomorphicSmCallSite"` → no results) — kemungkinan nama internal
  AOTopsy, bukan SDK. Verifikasi lebih lanjut diperlukan jika ingin
  mengklaim sebagai fakta SDK.
- SDK tidak punya konsep DOT/graph rendering (C++ compiler, bukan RE
  tool) — verifikasi SDK di sini fokus pada **pola call site yang
  seharusnya muncul sebagai edge di call graph AOTopsy**, bukan pada
  rendering DOT itu sendiri.
