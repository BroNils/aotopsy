# RE Gap Analysis Report: internal/output

> **STATUS VERIFIKASI (2026-09-01)** — dibaca penuh `sarif.go` + `output.go`;
> hampir semuanya CONFIRMED. Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> - CONFIRMED: `sarifRegion{StartLine:1}` + `uri:"libapp.so"` hardcoded
>   (`sarif.go:200-210`); `sarifRun` hanya `{Tool, Results}`; `sarifResult`
>   hanya 5 field; `toolVersion` literal `"1.0.0"` (`signal_stage.go:220`);
>   `writeJSON` memakai default `SetEscapeHTML(true)`; **`meta.json` benar-benar
>   dead read** (1 pembaca di `signal_stage.go:146`, **nol** penulis di seluruh
>   repo); `WriteSymbolsJSON`/`WriteSnapshotJSON` hanya dari `_debug dump`.
> - **Koreksi Gap 46**: kalimat "field access records … tidak ada di output
>   mana pun" terlalu luas. `field_accessor_xref.jsonl` **ditulis**
>   (`analysis/typetrack_stage.go:505`, `writeFieldAccessorXref:526-623`),
>   lengkap dengan readers/writers per (class, offset). Yang benar: field
>   access tidak masuk **`evidence.jsonl`** dan tidak masuk **SARIF**.

## Ringkasan

Folder `internal/output` (3 file .go, 402 LOC) adalah lapisan serialisasi hasil
analisis AOTopsy. Isinya sangat tipis dibandingkan klaim paketnya ("JSONL &
SARIF 2.1.0 output"):

- `output.go` (73 LOC): 5 fungsi — `WriteSnapshotJSON`, `WriteSymbolsJSON`,
  `WriteASM`, `WriteASMSingle`, `WriteBin`. Semua menulis **JSON** (bukan
  JSONL) atau **text/binary**. Tidak ada satu pun fungsi JSONL di paket ini.
- `sarif.go` (249 LOC): `WriteSARIF` + tipe SARIF subset + 2 map hardcoded
  (`ruleLevel`, `ruleDescription`).
- `sarif_test.go` (80 LOC): 1 test, hanya cek level mapping.

**Fakta struktural yang merusak klaim paket:**

1. **Paket `output` tidak menulis satu baris JSONL pun.** Semua 22+ file
   JSONL (`functions.jsonl`, `call_edges.jsonl`, `string_refs.jsonl`,
   `classes.jsonl`, `pool_immediates.jsonl`, `evidence.jsonl`,
   `crypto_findings.jsonl`, `taint_findings.jsonl`, `yara_findings.jsonl`,
   `behavioral_findings.jsonl`, `entropy_findings.jsonl`,
   `method_channels.jsonl`, `plugins.jsonl`, `network_endpoints.jsonl`,
   `deobfuscation_strings.jsonl`, `scripts.jsonl`, `loading_units.jsonl`,
   `kpi.jsonl`, `instances.jsonl`, `contexts.jsonl`, `type_arguments.jsonl`,
   `exception_handlers.jsonl`, `icdata.jsonl`, `closure_data.jsonl`,
   `library_functions.jsonl`, `ffi_bridges.jsonl`, `platform_channels.jsonl`,
   `deobfuscate_map.jsonl`, `dispatch_table.jsonl`,
   `selector_dispatch_xref.jsonl`, `function_fingerprints.jsonl`) ditulis
   oleh `internal/analysis/pipeline.go` dan sub-stage-nya langsung memakai
   `internal/jsonutil` atau inline `json.NewEncoder`. Paket `output` hanya
   menulis `snapshot.json` + `symbols.json` + `aotopsy.sarif` + `asm/*.txt`.
2. **Skema JSONL tidak dimiliki `output`.** `FuncRecord`/`CallEdgeRecord`/
   `StringRefRecord`/`UnresolvedTHRRecord` ada di `internal/disasm/types.go`;
   `Evidence`/`SDKReference` di `internal/evidence/evidence.go`;
   `TaintFinding`/`YaraFinding`/`BehavioralFinding`/`CryptoFinding`/
   `EntropyFinding` di `internal/signal/*`; `SignalFinding` satu-satunya
   yang ada di `output`. Tidak ada registry skema terpusat.
3. **Dua jalur penulisan JSONL paralel yang inkonsisten.** `jsonutil.WriteJSONLFile`
   (generic, streaming, `SetEscapeHTML(false)`) vs inline
   `json.NewEncoder`+loop untuk `classes.jsonl` (`pipeline.go:152-167`) dan
   `pool_immediates.jsonl` (`pipeline.go:200-227`) yang membypass `jsonutil`.
4. **`meta.json` (hash+source) adalah dead read.** `signal_stage.go:146`
   membaca `filepath.Join(filepath.Dir(inDir), "meta.json")` untuk
   `hash`+`source`, tetapi **tidak ada satu pun kode di repo yang menulis
   file `meta.json` itu** (diverifikasi: `grep -rn '"meta.json"'` hanya
   menemukan 1 read, 0 write). `digest` fallback ke `filepath.Base(filepath.Dir(inDir))`
   dan `filename` tetap path output dir. SHA-256 ELF file tidak pernah
   dipersisten ke output mana pun.

**Verifikasi SDK:** `runtime/vm/snapshot.h@3.12.2` (via `gh api`) mengonfirmasi
`enum Kind { kFull, kFullCore, kFullJIT, kFullAOT, kModule, kNone, kInvalid }`
— AOTopsy `SnapshotKind` (`snapshot.go:55-66`) hanya memetakan 0-3 dan
menumpang `KindFullJIT`/`KindFullAOT` ke arti ganda untuk 3.13+ (`kModule`).
`snapshot.Info` (`snapshot.go:148-158`) hanya berisi Region + Header +
Version + Diags — **tidak ada** ELF provenance (file hash, arch, endianness,
machine, build-id, sections).

**Verifikasi SARIF 2.1.0:** spec OASIS (§3.29, §3.32, §3.14, §3.27) mengonfirmasi
SARIF punya dukungan native untuk binary analysis (`physicalLocation.address`,
`run.addresses`, `region.byteOffset`/`byteLength`) yang sama sekali tidak
dipakai AOTopsy. Setiap result menulis `region.startLine: 1` + snippet text —
secara semantik salah untuk binary (§3.30.21: "For regions in binary artifacts,
a region object SHALL define a binary region and SHALL NOT define a text region").

Terdapat **47 gap** yang ditemukan, dikelompokkan menjadi: SARIF structural
(20), SignalFinding data routing (12), snapshot/symbols/asm (7), register
tracking & dataflow output (5), arsitektur ownership (3).

## Struktur Folder

| File | LOC | Peran |
|------|-----|-------|
| `output.go` | 73 | `WriteSnapshotJSON` (snapshot.json), `WriteSymbolsJSON` (symbols.json), `WriteASM`/`WriteASMSingle` (asm/*.txt), `WriteBin` (asm/*.bin). `SymbolEntry` struct. `writeJSON` helper (indent 2 spasi, `SetEscapeHTML` default=true). |
| `sarif.go` | 249 | Tipe SARIF subset: `sarifLog`/`sarifRun`/`sarifTool`/`sarifDriver`/`sarifRule`/`sarifResult`/`sarifLocation`/`sarifPhysicalLocation`/`sarifArtifactLocation`/`sarifRegion`/`sarifSnippet`. 2 map hardcoded: `ruleLevel` (28 kategori), `ruleDescription` (28 kategori). `SignalFinding` struct (4 field). `WriteSARIF` — build rules dari findings, build results, encode. |
| `sarif_test.go` | 80 | `TestWriteSARIF` — 3 finding (rooting/ssl_pinning/unknown), cek version/runs/driver/rules/results/level mapping. Tidak cek `address`, `artifacts`, `invocations`, `codeFlows`, determinism. |

**Konsumen:** `cmd/aotopsy/cmd_debug_dump.go` (WriteSnapshotJSON,
WriteSymbolsJSON, WriteASM, WriteASMSingle), `internal/analysis/disasm_stage.go`
(WriteASM), `internal/analysis/signal_stage.go` (WriteSARIF via
`output.SignalFinding`), `internal/evidence/evidence.go` (konsumsi
`output.SignalFinding`).

## Gap Analysis

### Gap 1: SARIF location salah secara semantik untuk binary — pakai `startLine` bukan `address`

- **Deskripsi**: Setiap `sarifResult` menulis `region.startLine: 1` dan
  `artifactLocation.uri: "libapp.so"` (`sarif.go:205-209`). PC sebenarnya
  hanya disematkan di `snippet.text` sebagai string `"Function: %s at %s —
  String: %q"`. SARIF 2.1.0 §3.29.6 menyediakan `physicalLocation.address`
  (object §3.32) dengan `absoluteAddress` (§3.32.6), `relativeAddress`
  (§3.32.7), `offsetFromParent` (§3.32.8), `length` (§3.32.9) — dirancang
  khusus untuk binary. §3.30.21 eksplisit: "For regions in binary artifacts,
  a region object SHALL define a binary region [`byteOffset`/`byteLength`]
  and SHALL NOT define a text region." AOTopsy melanggar SHALL NOT ini.
- **Bukti SDK/Spec**: SARIF §3.29.2 "Either artifactLocation, address, or
  both SHALL be present"; §3.32 example menunjukkan PE module/section
  hierarchy via `parentIndex`; §3.30.11 `byteOffset`, §3.30.12 `byteLength`.
  `signal_stage.go:180-185` sudah punya `f.PC` sebagai hex string
  (`"0x1000"`) — tinggal parse ke `uint64` dan emit ke `address.absoluteAddress`.
- **Dampak**: SARIF viewer (GitHub Code Scanning, VS Code SARIF Viewer,
  Azure DevOps) tidak bisa melompat ke alamat biner. Filtering by address
  impossible. `partialFingerprints.primaryLocationLineHash` = `function:pc`
  adalah satu-satunya identitas — lemah, tidak stabil跨 recompile (function
  name berubah saat symbol stripped). Diferensiasi dua finding di PC berbeda
  di function sama hanya lewat snippet text.
- **Usulan**: Tambah `sarifAddress` struct (`AbsoluteAddress uint64`,
  `RelativeAddress int64`, `Length int`, `Name string`, `Kind string`).
  `sarifPhysicalLocation` tambah field `Address *sarifAddress`. `sarifRegion`
  tambah `ByteOffset int`, `ByteLength int`, hapus `StartLine` untuk binary
  (atau set 0 + omitempty). Emit `address.absoluteAddress` dari parsed PC.
  Tambah `run.addresses` (§3.14.18) dengan hierarchy: index 0 = libapp.so
  module (`kind:"module"`, `absoluteAddress`: base VA), index 1 = .text
  section (`parentIndex:0`, `kind:"section"`, `offsetFromParent`: text offset).
  Setiap result `address.parentIndex` → 1 (.text).
- **Prioritas**: **TINGGI** — ini adalah bug spesifikasi, bukan fitur
  missing. Setiap SARIF consumer yang valid akan menandai ini sebagai
  text-region-on-binary violation.

### Gap 2: Tidak ada `run.artifacts` — libapp.so tidak dideklarasikan

- **Deskripsi**: SARIF §3.14.15 `artifacts` array of `artifact` objects
  (§3.24). Setiap artifact: `location` (uri), `length` (bytes),
  `hashes` (`sha256` dll), `sourceLanguage`, `encoding`. AOTopsy menulis
  `artifactLocation.uri: "libapp.so"` di setiap result tetapi tidak
  pernah mendeklarasikan artifact-nya. Konsekuensi: viewer tidak tahu
  ukuran file, hash, atau bahwa ini adalah file yang sama dengan referensi
  lain.
- **Bukti SDK/Spec**: §3.24.3 `length`, §3.24.4 `hashes` (map algorithm→
  value), §3.24.8 `sourceLanguage`. AOTopsy sudah hitung SHA-256 region
  (`Region.SHA256` di `snapshot.go:48`) tetapi **SHA-256 file ELF utuh
  tidak pernah dihitung/ditulis** (lihat Gap 33: dead `meta.json` read).
- **Dampak**: Tidak ada way untuk viewer mengkonfirmasi bahwa SARIF ini
  berlaku untuk libapp.so versi tertentu. Diferensial analysis (bandingkan
  dua SARIF dari dua versi APK) tidak bisa memverifikasi apakah artifact
  sama. `artifactLocation.index` (§3.4.5) tidak dipakai — viewer harus
  menebak uri.
- **Usulan**: Tambah `sarifArtifact` struct. `sarifRun` tambah `Artifacts
  []sarifArtifact`. Hitung SHA-256 libapp.so di pipeline, emit sebagai
  `artifact.hashes["sha-256"]`. Set `location.uri` ke basename, `length`
  ke file size, `sourceLanguage` ke "dart" (atau "dart-aot"). Setiap
  `artifactLocation` di result tambah `Index int` → 0.
- **Prioritas**: **TINGGI**.

### Gap 3: Tidak ada `run.invocations` — no provenance run

- **Deskripsi**: SARIF §3.14.11 `invocations` array. Setiap invocation:
  `commandLine`, `arguments`, `responseFiles`, `startTimeUtc`,
  `endTimeUtc`, `executionTime`, `exitCode`, `toolExecutionNotifications`,
  `processId`, `workingDirectory`. AOTopsy tidak menulis salah satu pun.
  Sebuah SARIF log tanpa invocation tidak bisa dibedakan dari log yang
  di-generate oleh CI vs manual vs lama.
- **Bukti SDK/Spec**: §3.52.2 `invocation` object. `pipeline.go:80` `Run`
  sudah punya `opts.LibPath`, `opts.OutDir`, `opts.Signal`, dll — semua
  informasi yang seharusnya jadi `arguments`. `os.Args` ada di `cmd/aotopsy`.
- **Dampak**: Tidak ada audit trail. Reproduksi analysis impossible dari
  SARIF saja. `toolVersion` dihardcode `"1.0.0"` (`signal_stage.go:220`)
  — bukan versi AOTopsy sebenarnya (lihat Gap 4).
- **Usulan**: Tambah `sarifInvocation` struct. `sarifRun` tambah
  `Invocations []sarifInvocation`. Pass `os.Args` + `opts` + `time.Now()`
  ke `WriteSARIF`. Emit `startTimeUtc`/`endTimeUtc`/`executionTime`/
  `commandLine`/`arguments`/`workingDirectory`/`exitCode`.
- **Prioritas**: **MENENGAH**.

### Gap 4: `toolVersion` dihardcode `"1.0.0"` — bukan versi sebenarnya

- **Deskripsi**: `signal_stage.go:220` memanggil `output.WriteSARIF(inDir,
  findings, "1.0.0")`. String `"1.0.0"` literal, bukan dari build info /
  `cmd/aotopsy` version flag. `sarifDriver.Version` (`sarif.go:30`) jadi
  `"1.0.0"` untuk semua release.
- **Bukti SDK/Spec**: §3.19.3 `version` property. SARIF consumer memakai
  ini untuk menentukan rule compatibility. Dua SARIF dari AOTopsy versi
  berbeda tidak bisa dibedakan.
- **Dampak**: Tidak ada way untuk mengetahui versi AOTopsy yang
  menghasilkan SARIF. Bug report tidak bisa repro. `informationUri`
  (`sarif.go:228`) ke `github.com/BroNils/aotopsy` tidak punya tag/version.
- **Usulan**: Pass `cmd/aotopsy` version (dari build info / git describe /
  `internal/strutil` version helper) ke `RunSignalStage` → `WriteSARIF`.
  Hapus hardcoded `"1.0.0"`.
- **Prioritas**: **MENENGAH**.

### Gap 5: Tidak ada `result.codeFlows` — taint/dataflow tidak terrepresentasi

- **Deskripsi**: SARIF §3.27.18 `codeFlows` array of `codeFlow` (§3.36).
  Setiap codeFlow = `threadFlows` array, setiap threadFlow = `locations`
  array of `threadFlowLocation` (§3.38) dengan `location` + `nestingLevel`
  + `executionOrder`. Ini adalah cara SARIF merepresentasikan source→sink
  data flow. AOTopsy punya `TaintFinding` (`signal/behavioral.go:13-20`)
  dengan `Source`/`Sink`/`SourceFn`/`SinkFn`/`FlowType`/`Confidence`,
  ditulis ke `taint_findings.jsonl` — **tetapi tidak pernah dirutekan ke
  SARIF**. `signal_stage.go:175-198` hanya mengambil `sf.StringRefs` +
  `sf.Categories` → `SignalFinding`. Taint, crypto, entropy, yara,
  behavioral findings semua terisolasi di JSONL sendiri.
- **Bukti SDK/Spec**: §3.36 codeFlow, §3.37 threadFlow, §3.38
  threadFlowLocation. `evidence.go:54-97` `FromCallEdges` sudah punya
  call-edge provenance yang bisa jadi threadFlow steps. `typetrack` punya
  register lattice + field access yang bisa jadi codeFlow locations.
- **Dampak**: Taint finding di SARIF hanya muncul (jika muncul) sebagai
  string-category finding dengan message text, tanpa path. RE analyst
  tidak bisa melihat "IMEI loaded at PC 0x100 → passed to X0 → bl
  Socket_Write at PC 0x120". Ini adalah use case RE nomor 1 untuk SARIF.
- **Usulan**: `SignalFinding` tambah field `CodeFlows [][]FlowLocation`
  (`{PC, Function, NestingLevel, ExecutionOrder, Message}`). `WriteSARIF`
  emit `result.codeFlows`. Rutekan `TaintFinding` ke SARIF sebagai result
  dengan `ruleId: "AOTOPSY_taint"`, `codeFlows` dari source→sink path.
  Konsumsi `evidence.jsonl` records yang sudah punya PC+function+inputs+
  result untuk bangun threadFlow.
- **Prioritas**: **TINGGI** — ini fitur RE paling bernilai yang missing.

### Gap 6: Tidak ada `result.graphs`/`graphTraversals` — call-graph pattern tidak terrepresentasi

- **Deskripsi**: SARIF §3.27.19 `graphs`, §3.27.20 `graphTraversals`.
  Graph (§3.42) = nodes + edges; graphTraversal (§3.43) = ordered path
  through graph. `BehavioralFinding` (`signal/behavioral.go:341-347`)
  punya `Pattern`/`Category`/`Functions`/`EdgeCount`/`Confidence` —
  pattern call-graph seperti `root_check_calls_anti_debug`. Ditulis ke
  `behavioral_findings.jsonl`, **tidak pernah ke SARIF**.
- **Bukti SDK/Spec**: §3.42 graph object, §3.43 graphTraversal object.
  AOTopsy sudah bangun call graph (`internal/callgraph`, `signal_graph.json`).
- **Dampak**: Call-graph behavioral pattern tidak bisa divisualisasi di
  SARIF viewer. RE analyst harus cross-reference `behavioral_findings.jsonl`
  manual dengan `signal_graph.json`.
- **Usulan**: `WriteSARIF` emit `run.graphs` (§3.14.20) dengan call graph
  subset. Setiap `BehavioralFinding` → result dengan `graphTraversals`
  berisi path fungsi-fungsi.
- **Prioritas**: **MENENGAH**.

### Gap 7: Tidak ada `result.relatedLocations` — finding multi-PC diratakan

- **Deskripsi**: SARIF §3.27.22 `relatedLocations` array of `location`
  (§3.28). Sebuah finding sering melibatkan beberapa PC: string-ref PC
  (di mana "imei" di-load dari PP), call PC (di mana `Socket_Write` di-bl),
  receiver-type PC (di mana class ID di-resolve). AOTopsy hanya simpan
  1 PC per `SignalFinding` (`sarif.go:155`). `signal_stage.go:178-186`
  iterasi `sf.StringRefs` — setiap ref jadi finding terpisah dengan PC
  ref itu sendiri, meskipun ref dan call ada di fungsi yang sama.
- **Bukti SDK/Spec**: §3.28 location object punya `id` (§3.28.3) untuk
  referensi silang dari `message` via `{id}` placeholder (§3.5.5).
- **Dampak**: Tidak bisa ekspresikan "finding ini melibatkan string di
  PC 0x100 DAN call di PC 0x200". Setiap ref jadi finding orphant.
  Duplikasi: 1 fungsi dengan 5 string ref kategori sama → 5 finding
  terpisah, semua level sama, semua function sama.
- **Usulan**: `SignalFinding` tambah `RelatedPCs []string`. Group findings
  by (function, category) sebelum emit; jadikan PC utama = call PC,
  related = string-ref PCs. Emit `relatedLocations` dengan `id` integer,
  `message.text` pakai placeholder `"String at {1} used in call at {2}"`.
- **Prioritas**: **MENENGAH**.

### Gap 8: Tidak ada `result.rank` — severity hanya 3 level

- **Deskripsi**: SARIF §3.27.25 `rank` (float 0.0–100.0). AOTopsy hanya
  punya `level` (`error`/`warning`/`note`) dari `ruleLevel` map
  (`sarif.go:87-116`). Tidak ada gradasi: `rooting` dan `accessibility`
  sama-sama `error`, padahal rooting detection bypass lebih kritis dari
  accessibility abuse untuk app banking.
- **Bukti SDK/Spec**: §3.27.25 rank, §3.13.4 `level` vs `rank`:
  level = categorical, rank = continuous. GitHub Code Scanning memakai
  rank untuk prioritization.
- **Dampak**: Triage tidak bisa memilah dalam kategori `error`. 100
  finding `error` tidak bisa diurutkan.
- **Usulan**: Tambah `ruleRank map[string]float64` (e.g. rooting=90,
  ssl_pinning=70, accessibility=85, fraud=95, crypto_const=30). Emit
  `result.rank`. Bisa juga compute dari `SignalFunc.Severity`
  (`signal/graph.go:29` "high"/"medium"/"low") → 80/50/20.
- **Prioritas**: **MENENGAH**.

### Gap 9: Tidak ada `result.baselineState` — no differential analysis

- **Deskripsi**: SARIF §3.27.24 `baselineState` (`new`/`unchanged`/
  `updated`/`absent`). AOTopsy punya `function_fingerprints.jsonl`
  (SHA-256 per-function instruction bytes, `pipeline.go:344`) untuk
  cross-sample name transfer, tetapi SARIF tidak membandingkan baseline.
- **Bukti SDK/Spec**: §3.27.24, §3.14.5 `baselineGuid`.
- **Dampak**: Tidak bisa jawab "fitur rooting baru di v2 APK?" dari SARIF.
  `funcdiff` package ada tetapi tidak terhubung ke SARIF.
- **Usulan**: Tambah opsi `--baseline <prev.sarif>` ke `WriteSARIF`.
  Match by `partialFingerprints.primaryLocationLineHash` (function:pc) —
  tapi ini lemah (lihat Gap 1); setelah Gap 1 diperbaiki, match by
  `address.absoluteAddress` + `ruleId`. Emit `baselineState`.
- **Prioritas**: **RENDAH** (butuh baseline infra dulu).

### Gap 10: Tidak ada `result.guid`/`correlationGuid`/`fingerprints`

- **Deskripsi**: SARIF §3.27.3 `guid`, §3.27.4 `correlationGuid`,
  §3.27.16 `fingerprints` (map). AOTopsy hanya `partialFingerprints`
  dengan 1 key `primaryLocationLineHash` = `function:pc` (`sarif.go:214-216`).
  Tidak ada `fingerprints` (stronger), tidak ada `guid` (stable ID).
- **Bukti SDK/Spec**: §3.27.16 fingerprints vs §3.27.17
  partialFingerprints: fingerprints = computed by tool, stable;
  partialFingerprints = computed by viewer, less stable.
- **Dampak**: Tracking finding across runs impossible. `function:pc`
  berubah saat function di-rename (obfuscation rotation) atau recompile
  dengan layout berbeda.
- **Usulan**: Tambah `fingerprints` dengan key `aotopsy/pc/v1` =
  `sha256(pc+ruleId+snippet)`, `aotopsy/context/v1` =
  `sha256(function+callerChain+ruleId)`. Emit `guid` = UUIDv5 dari
  fingerprints.
- **Prioritas**: **MENENGAH**.

### Gap 11: Tidak ada `result.provenance` — no detector metadata

- **Deskripsi**: SARIF §3.27.29 `provenance` (§3.48): `firstDetectionTimeUtc`,
  `lastDetectionTimeUtc`, `firstDetectionRunGuid`, `lastDetectionRunGuid`,
  `invocationIndex`. AOTopsy tidak menulis salah satu. `SignalFinding`
  tidak punya field detector/timestamp.
- **Bukti SDK/Spec**: §3.48 resultProvenance object.
- **Dampak**: Tidak ada way untuk mengetahui kapan finding pertama
  terdeteksi (berguna untuk regression tracking).
- **Usulan**: Pass `time.Now()` ke `WriteSARIF`, emit `provenance.
  firstDetectionTimeUtc`. Butuh `invocations` (Gap 3) dulu untuk
  `invocationIndex`.
- **Prioritas**: **RENDAH**.

### Gap 12: Tidak ada `rule.help` (markdown) — hanya `shortDescription` text

- **Deskripsi**: SARIF §3.49.7 `help` (markdown object §3.11). AOTopsy
  `sarifRule` (`sarif.go:35-43`) punya `ShortDescription` (text) +
  `HelpURI` + `Properties` tetapi tidak ada `Help` (markdown). RE analyst
  yang klik rule di viewer tidak dapat panduan cara interpretasi.
- **Bukti SDK/Spec**: §3.49.7 help, §3.11 markdown object.
- **Dampak**: Viewer menampilkan "Root/jailbreak detection or bypass
  code found" saja. Tidak ada: cara trigger, false-positive pattern,
  rekomendasi Frida hook, SDK reference.
- **Usulan**: Tambah `Help *sarifMarkdown` ke `sarifRule`. Isi per-kategori
  dengan: deskripsi mendalam, contoh Dart code yang trigger, Frida hook
  stub, SDK file reference (e.g. `runtime/vm/bootstrap_natives.h`).
- **Prioritas**: **RENDAH**.

### Gap 13: Tidak ada `rule.relationships` — kategori terkait tidak terhubung

- **Deskripsi**: SARIF §3.49.9 `relationships` array of `reportingDescriptorRelationship`
  (§3.50): `target` (rule ref), `kinds` (e.g. "superset"/"related"/
  "impacts"). AOTopsy punya 28 kategori yang overlap: `ssl_pinning`
  terkait `net`, `crypto_const` terkait `encryption`, `rooting` terkait
  `anti_analysis`. Tidak ada hubungan ini di SARIF.
- **Bukti SDK/Spec**: §3.50, §3.53.2 `relationshipKinds`.
- **Dampak**: Viewer tidak bisa group/filter "tampilkan semua finding
  terkait network" (ssl_pinning + net + covert_channel).
- **Usulan**: Tambah `Relationships` ke `sarifRule`. Definisikan relasi
  di map terpisah. Emit `target.id` = `"AOTOPSY_net"`, `kinds` =
  `["related"]`.
- **Prioritas**: **RENDAH**.

### Gap 14: Tidak ada `tool.extensions` — multi-stage pipeline diratakan

- **Deskripsi**: SARIF §3.18.3 `extensions` array of `toolComponent`
  (§3.19). AOTopsy pipeline punya 8+ stage analisis (disasm, typetrack,
  signal/classify, signal/crypto_id, signal/entropy, signal/behavioral
  taint, signal/behavioral yara, signal/behavioral callgraph) — semua
  dilaporkan sebagai 1 driver `AOTopsy`. Tidak ada way untuk mengetahui
  finding dari stage mana.
- **Bukti SDK/Spec**: §3.18.3, §3.19 toolComponent. `result.ruleId`
  bisa di-namespace per extension.
- **Dampak`: Tidak bisa audit "crypto_id stage menemukan 5 finding,
  classify stage menemukan 50". Debugging false-positive sulit.
- **Usulan**: Deklarasikan setiap stage sebagai `extension` dengan
  `name`/`version`/`rules`. Setiap result tambah `ruleId` dengan prefix
  extension (e.g. `aotopsy.crypto/aes_constant` vs `aotopsy.classify/
  crypto_const`).
- **Prioritas**: **RENDAH**.

### Gap 15: Tidak ada `run.taxonomies` — 28 kategori adalah taxonomy tak terdeklarasi

- **Deskripsi**: SARIF §3.14.8 `taxonomies` array of `toolComponent`
  dengan `isComprehensive` + `taxa` (array of `reportingDescriptor`).
  AOTopsy 28 kategori adalah taxonomy tetapi dideklarasikan inline sebagai
  `rules`, bukan `taxa`. Tidak ada way untuk mengetahui apakah list
  exhaustive.
- **Bukti SDK/Spec**: §3.14.8, §3.19.10 `supportedTaxonomies`,
  §3.49.3 `taxa` pada result.
- **Dampak**: Consumer tidak bisa membangun filter UI dari taxonomy.
  Tidak ada metadata "kategori X adalah leaf vs parent".
- **Usulan`: Pindahkan 28 kategori ke `run.taxonomies[0].taxa`. Setiap
  result `taxa` = `[{toolComponent: {name:"AOTopsy"}, id:"rooting"}]`.
  `isComprehensive: false` (kategori bisa grow).
- **Prioritas`: **RENDAH**.

### Gap 16: Tidak ada `run.versionControlProvenance` — no sample VCS info

- **Deskripsi**: SARIF §3.14.13 `versionControlProvenance` array of
  `versionControlDetails` (§3.51): `repositoryUri`, `revisionId`,
  `branch`, `tag`, `asOfTimeUtc`, `mappedTo`. Untuk sample APK yang
  dianalisis, ini bisa catat source repo + commit jika diketahui (e.g.
  dari debug symbols atau package metadata).
- **Bukti SDK/Spec**: §3.51.
- **Dampak`: Tidak ada provenance sample.
- **Usulan`: Jika `dart_meta.json` / `kpi.jsonl` punya info package,
  emit ke `versionControlProvenance`. Untuk sebagian besar obfuscated
  app ini akan kosong — acceptable.
- **Prioritas`: **RENDAH**.

### Gap 17: Tidak ada `run.originalUriBaseIds` — relative URI tanpa base

- **Deskripsi**: SARIF §3.14.14 `originalUriBaseIds` map. `artifactLocation.uri`
  AOTopsy = `"libapp.so"` (relative) tanpa `uriBaseId`. Viewer tidak
  tahu apakah `libapp.so` relatif terhadap cwd, output dir, atau temp.
- **Bukti SDK/Spec`: §3.4.4 `uriBaseId`, §3.14.14.
- **Dampak`: Path ambiguity. Dua SARIF dari dua mesin dengan layout
  berbeda tidak bisa di-resolve.
- **Usulan`: Tambah `OriginalUriBaseIds map[string]sarifArtifactLocation`
  ke `sarifRun`. Set `artifactLocation.uriBaseId` = `"SRCROOT"` di
  setiap result. `originalUriBaseIds["SRCROOT"]` = `{uri: "file:///abs/path/to/"}`.
- **Prioritas`: **RENDAH**.

### Gap 18: `region` untuk binary harus `byteOffset`/`byteLength`, bukan `startLine`

- **Deskripsi**: `sarifRegion` (`sarif.go:74-78`) hanya punya `StartLine`/
  `StartColumn`/`Snippet`. §3.30.11 `byteOffset`, §3.30.12 `byteLength`
  tidak ada. Setiap result `StartLine: 1` — untuk binary ini meaningless
  (libapp.so bukan text file dengan line).
- **Bukti SDK/Spec`: §3.30.1 "The region object defines both text
  properties and binary properties"; §3.30.21 "For regions in binary
  artifacts, a region object SHALL define a binary region and SHALL NOT
  define a text region."
- **Dampak`: Spesifikasi violation. Viewer yang strict akan reject.
- **Usulan`: Tambah `ByteOffset int`, `ByteLength int` ke `sarifRegion`.
  Hapus `StartLine`/`StartColumn` untuk binary results (set omitempty,
  jangan emit). `ByteOffset` = PC - base VA, `ByteLength` = 4 (ARM64
  instruction) atau instruction size.
- **Prioritas`: **TINGGI** (bagian dari Gap 1, tetapi cukup fundamental
  untuk disebut sendiri).

### Gap 19: `ruleLevel`/`ruleDescription` diduplikasi dari `signal/classify.go`

- **Deskripsi`: `sarif.go:84-86` comment: "Category strings are
  duplicated from signal/classify.go to keep output independent of the
  signal package." Dua map hardcoded `ruleLevel` (28 entry) +
  `ruleDescription` (28 entry) adalah salinan kategori dari
  `signal/classify.go`. Dua sumber kebenaran → drift. Jika `signal`
  menambah kategori, `output` tidak tahu → fallback `"note"` + generic
  description.
- **Bukti SDK/Spec`: N/A (architectural).
- **Dampak`: Kategori baru di `signal` tidak dapat level/description
  yang benar di SARIF. `TestWriteSARIF` (`sarif_test.go:27-31`) test
  `custom_unknown_cat` → fallback `note` — ini mengkonfirmasi drift
  sudah di-test sebagai expected behavior, padahal seharusnya error.
- **Usulan`: Hapus duplikasi. `output` import `signal` (atau sebaliknya,
  pindahkan kategori ke package netral `internal/catsig`). `WriteSARIF`
  query `signal.CategoryLevel(cat)` + `signal.CategoryDescription(cat)`.
  Atau: `SignalFinding` tambah field `Level` + `Description` yang
  diisi oleh `signal_stage.go` saat construct.
- **Prioritas`: **MENENGAH** (maintenance hazard).

### Gap 20: SARIF test tidak cek determinism, address, artifacts, codeFlows

- **Deskripsi`: `sarif_test.go` hanya 1 test, cek: version, runs count,
  driver name, rules count, results count, level mapping. Tidak cek:
  - `run.artifacts` ada (Gap 2)
  - `result.physicalLocation.address` ada (Gap 1)
  - `result.codeFlows` (Gap 5)
  - Determinism (run WriteSARIF 2x, bandingkan byte-identical —
    `golden_test.go` pattern)
  - `partialFingerprints` format
  - `tool.driver.informationUri` valid
- **Bukti SDK/Spec`: N/A.
- **Dampak`: Regresi SARIF structural tidak tertangkap.
- **Usulan`: Tambah test: determinism (2x write, bytes.Equal), address
  emission, artifacts emission, codeFlows emission, rule dedup.
- **Prioritas`: **MENENGAH**.

### Gap 21: `SignalFinding` tidak punya confidence score

- **Deskripsi`: `SignalFinding` (`sarif.go:151-156`) = 4 field:
  `Category`/`StringValue`/`Function`/`PC`. `evidence.go:30` `Evidence`
  punya `Confidence` (`exact`/`static_inferred`/`polymorphic`/`stub`/
  `unknown`/`runtime_confirmed`). `signal_stage.go:180-185` construct
  `SignalFinding` tanpa confidence. SARIF result tidak punya confidence.
- **Bukti SDK/Spec`: SARIF tidak punya field confidence native, tetapi
  `result.properties` (§3.27.31 extension) bisa bawa custom.
  `evidence.go:290-302` `classifyEdgeConfidence` sudah klasifikasi.
- **Dampak`: RE analyst tidak tahu apakah finding "rooting" adalah
  exact match (string "su" di fungsi `isRooted`) atau static_inferred
  (fungsi panggil `RootCheck` stub). Triage salah prioritas.
- **Usulan`: `SignalFinding` tambah `Confidence string`. `signal_stage.go`
  isi dari `sf.Role` + string-ref kind. Emit ke `result.properties.
  "aotopsy.confidence"`.
- **Prioritas`: **MENENGAH**.

### Gap 22: `SignalFinding` tidak punya evidence chain / cross-ref

- **Deskripsi`: `SignalFinding` tidak link ke `evidence.jsonl` record,
  call-edge, atau string-ref yang mendukungnya. `evidence.go:132-143`
  `FromSignalFindings` membuat `Evidence` dari `SignalFinding` tetapi
  tidak sebaliknya — tidak ada back-reference.
- **Bukti SDK/Spec`: SARIF `result.attachments` (§3.27.26) bisa bawa
  evidence artifacts. `result.codeFlows` (Gap 5) bisa bawa path.
- **Dampak`: Tidak bisa trace "finding ini berdasarkan string ref
  mana? call edge mana?".
- **Usulan`: `SignalFinding` tambah `Evidence []EvidenceRef`
  (`{Kind, PC, Function, Detail}`). Emit sebagai `result.attachments`
  atau `result.properties."aotopsy.evidence"`.
- **Prioritas`: **MENENGAH**.

### Gap 23: `TaintFinding` tidak dirutekan ke SARIF

- **Deskripsi`: `signal/behavioral.go:13-20` `TaintFinding` ditulis ke
  `taint_findings.jsonl` oleh `WriteTaintFindings` (`pipeline.go:304`).
  `signal_stage.go:175-198` hanya ambil string-category findings untuk
  SARIF. Taint findings terisolasi.
- **Bukti SDK/Spec`: SARIF `codeFlows` (Gap 5).
- **Dampak`: Taint flow (source→sink) tidak muncul di SARIF — padahal
  ini finding RE paling actionable.
- **Usulan`: Rutekan `TaintFinding` ke SARIF sebagai result dengan
  `ruleId: "AOTOPSY_taint"`, `codeFlows` dari source→sink, `level:
  "warning"`.
- **Prioritas`: **TINGGI** (subset dari Gap 5, tetapi cukup signifikan
  untuk disebut — 5 jenis finding orphaned, ini yang pertama).

### Gap 24: `CryptoFinding` tidak dirutekan ke SARIF

- **Deskripsi`: `signal/crypto_id.go:76-81` `CryptoFinding` ditulis ke
  `crypto_findings.jsonl` (`pipeline.go:297`). Tidak ke SARIF.
- **Dampak`: Algoritma crypto terdeteksi (AES/SHA/MD5/ChaCha) tidak
  muncul di SARIF.
- **Usulan`: Rutekan ke SARIF, `ruleId: "AOTOPSY_crypto_algorithm"`,
  `level: "note"`, `locations` = pool index atau byte offset.
- **Prioritas`: **MENENGAH**.

### Gap 25: `EntropyFinding` tidak dirutekan ke SARIF

- **Deskripsi`: `signal/entropy.go:13-19` `EntropyFinding` (packed/
  encrypted section) ditulis ke `entropy_findings.jsonl` (`pipeline.go:285`).
  Tidak ke SARIF.
- **Dampak`: Packed/encrypted section tidak muncul di SARIF.
- **Usulan`: Rutekan, `ruleId: "AOTOPSY_packed_section"`, `level:
  "warning"`, `physicalLocation.address` = section offset.
- **Prioritas`: **MENENGAH**.

### Gap 26: `BehavioralFinding` tidak dirutekan ke SARIF

- **Deskripsi`: `signal/behavioral.go:341-347` `BehavioralFinding`
  (call-graph pattern) ditulis ke `behavioral_findings.jsonl`
  (`pipeline.go:314`). Tidak ke SARIF. Lihat Gap 6.
- **Prioritas`: **MENENGAH**.

### Gap 27: `YaraFinding` tidak dirutekan ke SARIF

- **Deskripsi`: `signal/behavioral.go:250-255` `YaraFinding` ditulis ke
  `yara_findings.jsonl` (`pipeline.go:309`). Tidak ke SARIF.
- **Prioritas`: **MENENGAH**.

### Gap 28: Obfuscation finding menempati `SignalFinding` dengan Function/PC kosong

- **Deskripsi`: `signal_stage.go:212-215` construct `SignalFinding{
  Category: CatObfuscation, StringValue: "..."}` — `Function` dan `PC`
  kosong. `WriteSARIF` (`sarif.go:193-217`) emit result dengan
  `Locations[0].PhysicalLocation.Region.Snippet.Text` =
  `"Function:  at  — String: %q"` (double space, empty function/PC).
  `partialFingerprints.primaryLocationLineHash` = `":"` (empty function
  + empty PC). Ini adalah binary-level finding dipaksa ke schema
  per-function.
- **Dampak`: Finding obfuscation tidak punya lokasi. Fingerprints
  collides (`":"` sama untuk semua). Viewer menampilkan "Function:  at
  — String: ..." yang broken.
- **Usulan`: Tambah `SignalFinding.IsBinaryLevel bool` atau pisah tipe
  `BinaryFinding`. Emit sebagai result dengan `run-level` location
  (artifact-level, tanpa function/PC) atau `analysisTarget` (§3.27.13).
- **Prioritas`: **MENENGAH**.

### Gap 29: `SignalFinding` tidak punya detector/rule metadata

- **Deskripsi`: Tidak ada field untuk "finding ini dari classifier
  mana" (string keyword match vs THR-call pattern vs call-graph pattern
  vs crypto byte scan). `evidence.go:139` `Rule: "signal." + f.Category`
  adalah konstruksi ad-hoc di evidence layer, bukan field SignalFinding.
- **Dampak`: Tidak bisa audit false-positive per-detector.
- **Usulan`: `SignalFinding` tambah `Detector string` (e.g.
  `"string_keyword"`, `"thr_call"`, `"callgraph_pattern"`, `"crypto_scan"`).
- **Prioritas`: **RENDAH**.

### Gap 30: `SignalFinding` tidak punya timestamp

- **Deskripsi`: Tidak ada field waktu. SARIF `result.provenance`
  (Gap 11) butuh ini.
- **Prioritas`: **RENDAH**.

### Gap 31: `SignalFinding` tidak punya multiple PCs

- **Deskripsi`: Lihat Gap 7. `SignalFinding.PC` single string. Sebuah
  finding bisa melibatkan string-load PC + call PC + receiver-resolve PC.
- **Prioritas`: **MENENGAH** (subset Gap 7).

### Gap 32: `signal_stage.go` dedup findings tidak deterministik

- **Deskripsi`: `signal_stage.go:175-198` append findings dari iterasi
  `g.Funcs` (slice) → `sf.StringRefs` (slice) → `ref.Categories`
  (slice). Tidak sort sebelum `WriteSARIF`. `WriteSARIF` (`sarif.go:159-218`)
  iterasi findings untuk build rules (map dedup) + results. Map iteration
  Go tidak deterministik, tetapi `ruleSet` map hanya untuk skip dup,
  rules append order = findings order. Jika `g.Funcs` order berubah
  (e.g. map-based construction), SARIF bytes berubah.
- **Bukti`: `golden_test.go` `TestGoldenOutputIsDeterministic` cek
  determinism pipeline, tetapi SARIF dihasilkan di `signal_stage` yang
  adalah bagian pipeline — jika golden test cakup SARIF, ini seharusnya
  tertangkap. Verifikasi: `golden_test.go:45-55` list file yang di-SHA —
  perlu cek apakah `aotopsy.sarif` termasuk.
- **Dampak`: SARIF non-deterministic → diff noise.
- **Usulan`: Sort findings by (category, function, pc) sebelum
  `WriteSARIF`. Sort rules by ID.
- **Prioritas`: **MENENGAH**.

### Gap 33: `snapshot.json` tidak punya ELF provenance — `meta.json` dead read

- **Deskripsi`: `WriteSnapshotJSON` (`output.go:15-17`) menulis
  `snapshot.Info` yang berisi Region + Header + Version + Diags
  (`snapshot.go:148-158`). **Tidak ada**: file SHA-256, source path
  (libapp.so path), architecture (ARM64/x64), endianness, machine type,
  ELF build-id, section layout, dynamic symbols. `signal_stage.go:146`
  membaca `../meta.json` untuk `hash`+`source` — **tidak ada penulis
  `meta.json` di seluruh repo** (diverifikasi `grep -rn '"meta.json"'`:
  1 read, 0 write). `digest` fallback ke `filepath.Base(filepath.Dir(inDir))`.
- **Bukti SDK`: `snapshot.Region.SHA256` (`snapshot.go:48`) sudah hitung
  SHA-256 per-region, tetapi SHA-256 file ELF utuh tidak. `elfx.File`
  punya arch/machine/sections tetapi tidak diteruskan ke `Info`.
- **Dampak`: `snapshot.json` tidak self-contained. Dua output dir dari
  dua libapp.so berbeda tidak bisa dibedakan dari `snapshot.json` saja.
  SARIF `run.artifacts` (Gap 2) butuh file hash — sumbernya tidak ada.
- **Usulan`: Tambah field `ELF *ELFInfo` ke `snapshot.Info`:
  `{FilePath, SHA256, Arch, Endianness, Machine, BuildID, Sections,
  DynamicSymbols}`. `WriteSnapshotJSON` otomatis emit. Hapus dead read
  `meta.json` di `signal_stage.go:146`, ganti dengan baca `snapshot.json`.
- **Prioritas`: **TINGGI**.

### Gap 34: `snapshot.json` tidak punya cluster counts / loading-unit partition

- **Deskripsi`: `pipeline.go:406-414` `PartitionCodesByLoadingUnit`
  hitung partition (UnitCount, MainCodeRefs, DeferredCodeRefs) tetapi
  hanya `logf` ke stderr. `writeCapturedJSONL` tulis `loading_units.jsonl`
  tetapi partition summary (kode root vs deferred) tidak di `snapshot.json`.
  Cluster counts (`num_clusters`, `num_canonical_clusters`) di-parse di
  `cluster` tetapi tidak diekspos di `Info`.
- **Bukti SDK`: `runtime/vm/app_snapshot.cc` `FillHeader`/`ReadHeader`
  menulis/membaca cluster counts di snapshot header.
- **Dampak`: RE analyst tidak tahu dari `snapshot.json` apakah app
  punya deferred imports (loading units) — harus baca stderr log atau
  `loading_units.jsonl` manual.
- **Usulan`: Tambah `ClusterStats` + `LoadingUnitPartition` ke `Info`.
- **Prioritas`: **RENDAH**.

### Gap 35: `symbols.json` terlalu tipis — hanya address/name/size

- **Deskripsi`: `SymbolEntry` (`output.go:20-24`) = `Address`/`Name`/
  `Size`. Tidak ada: `Type` (function/object/section), `Section`
  (.text/.rodata), `Binding` (global/local/weak), `Source` (ELF symbol
  vs recovered name vs THR stub vs PP entry), `Owner` (Dart class).
- **Bukti SDK/Spec`: ELF symbol table punya `st_info` (type+binding),
  `st_shndx` (section). `naming.PoolLookups` punya owner info.
- **Dampak`: IDA/Ghidra import tidak bisa filter "hanya function" atau
  "hanya global". Tidak bisa audit "nama ini recovered dari mana".
- **Usulan`: Tambah field `Type`/`Section`/`Binding`/`Source`/`Owner`
  ke `SymbolEntry`. Set dari ELF symbol + recovered name.
- **Prioritas`: **MENENGAH**.

### Gap 36: `WriteSymbolsJSON` hanya dipanggil `_debug dump` — pipeline utama tidak tulis symbols.json

- **Deskripsi`: `grep` menunjukkan `WriteSymbolsJSON` hanya dipanggil di
  `cmd_debug_dump.go:86`. Pipeline utama (`analysis.Run`) tidak pernah
  tulis `symbols.json`. Recovered function names → `functions.jsonl`
  saja. IDA/Ghidra import memakai `flutter_meta.json` (via meta stage),
  bukan `symbols.json`.
- **Dampak`: `symbols.json` tidak ada di output pipeline normal. Tool
  eksternal yang expect symbols.json (e.g. r2 `f` script via
  `r2_fingerprint_export.go`) harus baca `functions.jsonl` sendiri.
- **Usulan`: Pipeline utama tulis `symbols.json` dari `functions.jsonl`
  (FuncRecord → SymbolEntry). Atau dokumentasikan `symbols.json` hanya
  untuk `_debug dump` dan hapus dari public API.
- **Prioritas`: **MENENGAH**.

### Gap 37: `asm/<name>.txt` tidak punya JSON sidecar metadata

- **Deskripsi`: `WriteASM` (`output.go:33-41`) tulis text formatted
  instructions. `WriteBin` tulis raw bytes. Tidak ada sidecar JSON per-
  function dengan: CFG (basic blocks + edges), register state in/out,
  annotation table (THR refs, PP refs, dispatch table refs), parameter
  types, return type.
- **Bukti`: `typetrack.LiftState` punya register lattice; `disasm`
  punya annotators; `callgraph` punya CFG. Semua hilang saat write asm.
- **Dampak`: RE analyst yang baca `asm/OwnerClass/func.txt` tidak punya
  machine-readable metadata untuk cross-reference. Harap re-parse text.
- **Usulan`: Tambah `WriteASMMeta(dir, name, meta)` yang tulis
  `asm/<name>.json` dengan CFG + register state + annotations.
- **Prioritas`: **RENDAH**.

### Gap 38: Tidak ada manifest/index file — no output registry

- **Deskripsi`: Tidak ada file tunggal yang list semua output, schema,
  record count, generation timestamp. `README.md:206-255` list output
  files manual (stale risk). Consumer (Frida export, Ghidra import) harus
  tahu hardcode list.
- **Dampak`: Output set berubah (tambah JSONL baru) → consumer break
  silently. `frida/import.go:169-170` hardcode list file
  (`functions.jsonl`, `classes.jsonl`, dst) — drift.
- **Usulan`: Tulis `manifest.json` di akhir pipeline: array of
  `{filename, schema, recordCount, bytes, sha256, generatedAt}`.
- **Prioritas`: **MENENGAH**.

### Gap 39: Tidak ada streaming output — semua buffered

- **Deskripsi`: `writeJSON` (`output.go:60-73`) `json.NewEncoder`+
  `Encode` (one-shot). `jsonutil.WriteJSONLFile` iterate slice (buffer
  full slice). Pipeline hold semua `classLayouts`, `funcs`, `edges`,
  `stringRefs` di memory sebelum write. Untuk 129k-function app ini OOM
  risk (lihat AGENTS.md host memory limits).
- **Dampak`: Pipeline tidak bisa stream >RAM. `--limit` partial workaround.
- **Usulan`: `jsonutil.JSONLWriter` sudah streaming — gunakan untuk
  semua JSONL. Untuk JSON (`snapshot.json`, `symbols.json`), tetap
  one-shot acceptable (kecil).
- **Prioritas`: **RENDAH** (sudah partial via jsonutil).

### Gap 40: `writeJSON` `SetEscapeHTML` default=true — HTML escape corrupts URLs

- **Deskripsi`: `output.go:67-68` `json.NewEncoder(f)` tanpa
  `SetEscapeHTML(false)`. Default Go = escape `<`/`>`/`&` → `&lt;` dll.
  `symbols.json` name dengan `<` (e.g. obfuscated `a<b>`) di-escape.
  `jsonutil.NewJSONLWriter` (`jsonutil.go:64`) set `SetEscapeHTML(false)`.
  Inkonsistensi: JSONL unescaped, JSON escaped.
- **Dampak`: Consumer yang baca `symbols.json` dapat `&lt;` bukan `<`.
  SARIF `helpUri` dengan `&` di-escape → broken URL.
- **Usulan`: `writeJSON` tambah `enc.SetEscapeHTML(false)`.
- **Prioritas`: **MENENGAH**.

### Gap 41: Paket `output` tidak own JSONL schema — no central registry

- **Deskripsi`: Lihat Ringkasan. `FuncRecord`/`CallEdgeRecord`/`StringRefRecord`
  di `disasm/types.go`; `Evidence` di `evidence/evidence.go`; 5 finding
  type di `signal/*`; `SignalFinding` di `output`. Tidak ada `output/
  schema.go` yang registry semua. `manifest.json` (Gap 38) butuh ini.
- **Dampak`: Schema drift. `disasm.FuncRecord` tambah field → semua
  consumer harus update, tidak ada central place yang fail.
- **Usulan`: Pindahkan record type definitions ke `output/schema.go`
  (atau `internal/schema`). `disasm`/`evidence`/`signal` import dari sana.
- **Prioritas`: **RENDAH** (large refactor).

### Gap 42: Dua jalur JSONL write paralel inkonsisten

- **Deskripsi`: `pipeline.go:152-167` (classes.jsonl) dan
  `pipeline.go:200-227` (pool_immediates.jsonl) pakai inline
  `json.NewEncoder`+loop. `pipeline.go:426-469` (9 captured files) pakai
  `jsonutil.WriteJSONLFile`. Inkonsistensi: inline tidak pakai
  `SetEscapeHTML(false)`? Cek: `pipeline.go:158` `classesEnc.
  SetEscapeHTML(false)` — OK. `pipeline.go:207` `poolImmEnc.
  SetEscapeHTML(false)` — OK. Tapi pattern duplikasi: 2 inline + 9
  generic. Error handling inline berbeda (return error vs log+continue).
- **Dampak`: Maintenance burden. Bug fix di `jsonutil` tidak auto-apply
  ke inline.
- **Usulan`: Migrasi `classes.jsonl` + `pool_immediates.jsonl` ke
  `jsonutil.WriteJSONLFile`.
- **Prioritas`: **RENDAH**.

### Gap 43: Tidak ada output validation — no schema enforcement post-write

- **Deskripsi`: Tidak ada check bahwa JSONL yang ditulis bisa di-parse
  balik dengan schema yang sama. `golden_test.go` cek SHA-256 (content
  stable) tetapi tidak cek schema valid. `regression_test.go` baca
  JSONL dan cek count, tetapi tidak cek field type.
- **Dampak`: Field rename/typo tidak tertangkap sampai consumer break.
- **Usulan`: Tambah `output.Validate(dir)` yang baca semua JSONL,
  unmarshal ke expected type, report mismatch. Jalankan di test.
- **Prioritas`: **RENDAH**.

## Register Tracking Gaps

### Gap 44: Tidak ada per-function register-state output

- **Deskripsi`: `typetrack.LiftState` punya register lattice (per-PC
  type/value untuk X0-X30, SP, dst). `disasm/dataflowarm64.go` punya
  register provenance. **Tidak ada satu pun yang ditulis ke file output.**
  RE analyst tidak bisa lihat "di PC 0x1234, X21=dispatch_table_base,
  X0=receiver class C, X30=return addr".
- **Bukti SDK`: `runtime/vm/compiler/backend/il_arm64.cc` register
  allocation. AOTopsy sudah reverse-engineer ini di typetrack.
- **Dampak`: Hasil analisis paling bernilai (register tracking) tidak
  accessible. Hanya visible di asm annotation inline (jika annotator
  aktif) — tidak queryable.
- **Usulan`: Tulis `register_state.jsonl` per-function: `{func, pc,
  reg, value, type, provenance}`. Atau sidecar per-function (Gap 37).
- **Prioritas`: **TINGGI** untuk RE.

### Gap 45: Register-level dataflow tidak dirutekan ke SARIF codeFlows

- **Deskripsi`: Lihat Gap 5 + Gap 44. `typetrack` + `disasm/dataflow`
  bisa bangun path "X0 = IMEI @ PC_a → X0 = arg @ PC_b → bl Socket_Write
  @ PC_c". Path ini ideal untuk SARIF `codeFlows`/`threadFlows`. Tidak
  ada rute.
- **Dampak`: Taint analysis (Gap 23) tidak punya register-level
  precision. SARIF codeFlows kosong.
- **Usulan`: Bangun `codeFlow` dari `typetrack` field-access +
  `disasm` register provenance + `evidence` call-edge. Emit ke SARIF.
- **Prioritas`: **TINGGI**.

### Gap 46: Field-access records tidak ditulis ke output / tidak ke SARIF

- **Deskripsi`: `evidence.go:146-164` `FromFieldAccesses` membuat
  `Evidence` dari `typetrack.FieldAccess` (`{ClassID, ByteOffset,
  IsStore, PC}`). Tetapi `pipeline.go:351-357` hanya panggil
  `evCollector.FromCallEdges` — **tidak pernah `FromFieldAccesses`**.
  Field access records tidak ada di `evidence.jsonl`. Tidak ada di
  SARIF.
- **Bukti`: `evidence_test.go:102-104` test `FromFieldAccesses` —
  function ada dan tested, tetapi tidak dipanggil pipeline.
- **Dampak`: Field access (class.member read/write) — info RE kritis
  untuk understanding state — tidak ada di output mana pun.
- **Usulan`: Pipeline panggil `evCollector.FromFieldAccesses` per-
  function dari `typetrack` results. Emit ke `evidence.jsonl` + SARIF
  `relatedLocations`.
- **Prioritas`: **TINGGI**.

### Gap 47: `dispatch_table.jsonl` + `selector_dispatch_xref.jsonl` tidak ke SARIF

- **Deskripsi`: `typetrack` tulis `dispatch_table.jsonl`;
  `analysis/xref.go` tulis `selector_dispatch_xref.jsonl`. BLR
  resolution (polymorphic dispatch) adalah info RE kritis. Tidak
  dirutekan ke SARIF. `evidence.go:100-129` `FromBLRResolutions` ada
  tetapi `pipeline.go` tidak panggil (hanya `FromCallEdges`).
- **Dampak`: Polymorphic call resolution tidak muncul di SARIF. RE
  analyst tidak tahu "BLR X16 @ PC 0x200 → salah satu dari [A.m, B.m,
  C.m]".
- **Usulan`: Pipeline panggil `evCollector.FromBLRResolutions`.
  Rutekan ke SARIF sebagai result `ruleId: "AOTOPSY_dispatch"`,
  `relatedLocations` = candidate callees.
- **Prioritas`: **MENENGAH**.

## Fitur RE Missing/Incomplete

1. **SARIF binary location** (`address.absoluteAddress`) — Gap 1, 18.
   Saat ini pakai `startLine:1` yang salah untuk binary.
2. **SARIF codeFlows untuk taint/dataflow** — Gap 5, 23, 45. Taint
   finding orphaned di JSONL.
3. **SARIF graphTraversals untuk call-graph pattern** — Gap 6, 26.
4. **SARIF artifacts + file hash** — Gap 2, 33. ELF provenance missing.
5. **SARIF invocations + real tool version** — Gap 3, 4.
6. **SARIF relatedLocations untuk multi-PC finding** — Gap 7, 31.
7. **SARIF rank (numeric severity)** — Gap 8.
8. **SARIF baselineState (differential)** — Gap 9.
9. **SARIF fingerprints/guid (stable ID)** — Gap 10.
10. **SARIF rule.help markdown** — Gap 12.
11. **SARIF tool.extensions (multi-stage)** — Gap 14.
12. **SARIF taxonomies** — Gap 15.
13. **Routing 5 finding types ke SARIF** (taint/crypto/entropy/yara/
    behavioral) — Gap 23-27.
14. **SignalFinding confidence + evidence chain** — Gap 21, 22, 29.
15. **Register-state output file** — Gap 44.
16. **Field-access + BLR-resolution ke evidence/SARIF** — Gap 46, 47.
17. **snapshot.json ELF provenance** — Gap 33.
18. **symbols.json kaya (type/section/binding/source)** — Gap 35, 36.
19. **asm JSON sidecar (CFG + register + annotation)** — Gap 37.
20. **manifest.json output registry** — Gap 38.
21. **Determinism sort di SARIF** — Gap 32.
22. **`writeJSON` SetEscapeHTML(false)** — Gap 40.
23. **Hapus duplikasi ruleLevel/ruleDescription** — Gap 19.
24. **Hapus dead `meta.json` read** — Gap 33.
25. **Centralisasi JSONL schema** — Gap 41, 42, 43.

## Verifikasi SDK

### via `gh api` (dart-lang/sdk @ tag)

1. **`runtime/vm/snapshot.h@3.12.2`** (gh api raw):
   - `enum Kind { kFull, kFullCore, kFullJIT, kFullAOT, kModule, kNone,
     kInvalid }` — 7 nilai. AOTopsy `SnapshotKind` (`snapshot.go:55-66`)
     hanya 4 + alias 3.13. `kModule` (Dart 3.x deferred) tidak punya
     nama sendiri di AOTopsy (ditumpang ke `KindFullAOT`).
   - `kMagicValue = 0xdcdcf5f5`, `kMagicOffset=0`, `kLengthOffset=4`,
     `kKindOffset=12` — cocok dengan AOTopsy `Header` layout
     (`snapshot.go:84-98`).
   - `IncludesCode(kind)` = JIT/AOT/Module. AOTopsy asumsikan AOT saja.

2. **`runtime/vm/app_snapshot.cc@3.12.2`** (gh api raw):
   - `Snapshot::Kind kind()` dispatch, `ASSERT(kind != kFullAOT)` di
     beberapa cluster (ICData, Context, KernelProgramInfo) —
     mengkonfirmasi comment `pipeline.go:170-197` bahwa ICData/Context/
     KernelProgramInfo tidak ada di AOT (alasan: precompiler drop, bukan
     #if guard).

### via SARIF 2.1.0 spec (OASIS, webfetch)

3. **§3.29 physicalLocation**: "Either artifactLocation, address, or
   both SHALL be present" — AOTopsy hanya artifactLocation, tidak
   address. **§3.29.6 address property** ada, tidak dipakai.
4. **§3.30.21**: "For regions in binary artifacts, a region object
   SHALL define a binary region and SHALL NOT define a text region" —
   AOTopsy `StartLine:1` = text region pada binary = **SHALL NOT
   violation**.
5. **§3.32 address object**: `absoluteAddress`/`relativeAddress`/
   `offsetFromParent`/`length`/`name`/`kind`/`parentIndex` — semua
   tidak dipakai AOTopsy.
6. **§3.14 run object properties**: `invocations` (§3.14.11),
   `artifacts` (§3.14.15), `addresses` (§3.14.18), `logicalLocations`
   (§3.14.17), `taxonomies` (§3.14.8), `versionControlProvenance`
   (§3.14.13), `originalUriBaseIds` (§3.14.14), `threadFlowLocations`
   (§3.14.19), `graphs` (§3.14.20) — **tidak satu pun dipakai** AOTopsy
   (`sarifRun` `sarif.go:19-22` hanya `Tool` + `Results`).
7. **§3.27 result object properties**: `guid`/`correlationGuid` (§3.27.3-4),
   `ruleIndex` (§3.27.6), `codeFlows` (§3.27.18), `graphs`/`graphTraversals`
   (§3.27.19-20), `stacks` (§3.27.21), `relatedLocations` (§3.27.22),
   `suppressions` (§3.27.23), `baselineState` (§3.27.24), `rank`
   (§3.27.25), `attachments` (§3.27.26), `workItemUris` (§3.27.27),
   `hostedViewerUri` (§3.27.28), `provenance` (§3.27.29), `fixes`
   (§3.27.30), `occurrenceCount` (§3.27.31) — AOTopsy `sarifResult`
   (`sarif.go:53-59`) hanya `RuleID`/`Level`/`Message`/`Locations`/
   `PartialFingerprints`. **15 property SARIF result tidak dipakai.**
8. **§3.49 reportingDescriptor (rule)**: `help` (§3.49.7),
   `relationships` (§3.49.9), `defaultConfiguration` (§3.49.11),
   `configuration` (§3.49.12) — AOTopsy `sarifRule` (`sarif.go:35-43`)
   hanya `ID`/`Name`/`ShortDescription`/`FullDescription`/`HelpURI`/
   `DefaultConfig`/`Properties`. `help` (markdown) + `relationships`
   missing.

### Cross-check internal

9. **`grep -rn '"meta.json"'`**: 1 hit (`signal_stage.go:146` read), 0
   write. **Dead read confirmed.**
10. **`grep -rn 'WriteSymbolsJSON'`**: 1 caller (`cmd_debug_dump.go:86`).
    Pipeline utama tidak tulis `symbols.json`. **Confirmed.**
11. **`grep -rn 'FromFieldAccesses|FromBLRResolutions'` di pipeline**:
    `pipeline.go:351-357` hanya `FromCallEdges`. `FromFieldAccesses`/
    `FromBLRResolutions` hanya di test. **Confirmed orphant.**
12. **`grep -rn 'WriteSARIF'`**: 1 caller (`signal_stage.go:220`) dengan
    `toolVersion "1.0.0"` hardcoded. **Confirmed.**
13. **`grep -rn 'SignalFinding{'`**: 4 construct di `signal_stage.go`
    (line 180, 191, 212) + test. Tidak ada construct dari taint/crypto/
    entropy/yara/behavioral. **5 finding type orphaned confirmed.**
