# RE Gap Analysis Report: internal/jsonutil

> **STATUS VERIFIKASI (2026-09-01)** — semua 9 gap CONFIRMED. Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> `ReadJSONL` (`jsonutil.go:13-31`) memang memuat seluruh file ke slice; tidak
> ada streaming reader, manifest, kompresi, atau append. `WriteJSONLFile`
> memakai `SetEscapeHTML(false)` sementara `output.writeJSON`
> (`output/output.go:62-72`) **tidak** — inkonsistensi yang disebut report
> memang ada. Error swallow di `pipeline.go:267-269`
> (`funcs, _ := jsonutil.ReadJSONL...`) juga CONFIRMED.

## Ringkasan

`internal/jsonutil` adalah package utilitas generik untuk I/O JSONL
(JavaScript Object Notation Lines) yang dipakai oleh hampir seluruh stage
pipeline AOTopsy. Package ini sangat kecil (82 barang di `jsonutil.go`, 48
baris test) dan mengekspos tiga simbol publik:

- `ReadJSONL[T any](path string) ([]T, error)` — baca seluruh file JSONL
  ke slice memori.
- `WriteJSONLFile[T any](path string, records []T) (int, error)` — tulis
  slice record ke file JSONL, satu record per baris.
- `JSONLWriter[T]` + `NewJSONLWriter[T]` — writer streaming per-record
  (`Write(rec)`, `Close()`).

Verifikasi ke Dart SDK (`dart-lang/sdk` @ 3.9.2) mengkonfirmasi bahwa SDK
**tidak memiliki konsep JSONL/NDJSON**. JSONL adalah format output AOTopsy
murni untuk konsumsi tooling RE (Ghidra, IDA, diff, Frida, downstream
analyst). Yang ada di SDK hanyalah `JSONWriter` (`runtime/vm/json_writer.h`)
yang menulis JSON tunggal (bukan line-delimited) untuk V8 snapshot profile
(`runtime/vm/v8_snapshot_writer.cc`) dan service protocol. Jadi "verifikasi
SDK" di sini tidak membandingkan format wire, melainkan memastikan bahwa
data yang dipancarkan JSONL AOTopsy benar-benar menutupi field/struktur
yang ada di snapshot Dart AOT, dan bahwa helper JSONL sendiri tidak
menggagalkan data tersebut.

Gap analysis menemukan **9 gap** (5 logika, 4 fitur RE missing). Tidak ada
"register yang tidak ditrack" — `jsonutil` adalah layer I/O murni, tidak
menyentuh register ARM64/x86. Tapi ada celah serius di sisi **stream
processing** (OOM pada file besar, error swallow, tidak ada resume) dan
**fitur RE** (tidak ada schema/manifest, tidak ada validasi, tidak ada
streaming reader, tidak ada kompresi, tidak ada append/merge untuk
incremental analysis).

## Struktur Folder

```
internal/jsonutil/
├── jsonutil.go          (82 baris) — ReadJSONL, WriteJSONLFile, JSONLWriter
├── jsonutil_test.go     (48 baris) — 1 test: round-trip 3 record
└── RE_GAP_ANALYSIS_REPORT.md  (file ini)
```

Tidak ada subfolder. Tidak ada file lain. Package ini hanya bergantung pada
`encoding/json`, `fmt`, `os` — zero dependency internal.

Pemakaian lintas package (28 call site, 6 importer):
- `internal/analysis/pipeline.go` — 17 call (write captured JSONL + read
  functions/edges/string_refs untuk xref)
- `cmd/aotopsy/cmd_debug_graph.go` — 3 call (read untuk graph build)
- `internal/analysis/xref.go` — 1 call (read dispatch_table.jsonl)
- `internal/analysis/typetrack_stage.go` — 1 call (read call_edges)
- `internal/analysis/signal_stage.go` — 3 call (read functions/edges/
  string_refs)
- `internal/analysis/meta_stage.go` — 3 call (read functions/classes/
  string_refs)

Selain itu, **banyak stage menulis JSONL dengan `json.NewEncoder` langsung**
tanpa lewat `jsonutil` (lihat `disasm_stage.go` 10 site, `disasm_stagex86.go`
10 site, `evidence.go`, `thraudit.go`, `graph.go`, `xref.go`, `typetrack.go`,
`crypto_id.go`, `signal_stage.go`, `meta_stage.go`, `cmd_debug_*`). Ini
duplikasi pola yang harusnya di-konsolidasi ke `jsonutil`.

## Gap Analysis

### Gap 1: ReadJSONL memuat seluruh file ke memori — OOM pada app besar

- **Deskripsi**: `ReadJSONL` meng-`append` setiap record ke `[]T` dan
  mengembalikan slice penuh. Untuk `call_edges.jsonl` app production
  (129k function, ~40k–80k edge) atau `string_refs.jsonl` (ratusan ribu
  baris), ini membebani host 6 GB yang disebut AGENTS.md. Tidak ada opsi
  streaming/callback.
- **Bukti SDK**: N/A (format AOTopsy). Tapi `clusterOnly` harness di
  `loadingunit_test.go` sudah ada justru karena pipeline full OOM pada
  app besar — bukti bahwa beban memori adalah masalah nyata.
- **Dampak**: Stage xref/signal/meta yang memanggil `ReadJSONL` pada
  `call_edges.jsonl`/`string_refs.jsonl` besar akan swap/OOM. Pipeline
  harus dijalankan per-stage dengan `--from` untuk menghindari ini.
- **Usulan**: Tambah `ReadJSONLStream[T](path, func(T) error)` yang
  decode-per-record tanpa akumulasi. Refactor `signal_stage.go`,
  `meta_stage.go`, `xref.go` untuk pakai stream callback. Pertahankan
  `ReadJSONL` untuk file kecil (functions.jsonl, classes.jsonl).
- **Prioritas**: Tinggi — membatasi ukuran app yang bisa dianalisis
  end-to-end.

### Gap 2: Error swallow pada ReadJSONL di pipeline.go (line 267–269)

- **Deskripsi**: Tiga pemanggilan `ReadJSONL` di `pipeline.go:267-269`
  mengabaikan error dengan `_, _ :=`:
  ```go
  funcs, _ := jsonutil.ReadJSONL[disasm.FuncRecord](...("functions.jsonl"))
  edges, _ := jsonutil.ReadJSONL[disasm.CallEdgeRecord](...("call_edges.jsonl"))
  stringRefs, _ := jsonutil.ReadJSONL[disasm.StringRefRecord](...("string_refs.jsonl"))
  ```
  Jika file corrupt/truncated (mis. pipeline crash sebelumnya, disk
  penuh), `funcs/edges/stringRefs` jadi `nil` dan `writeXrefJSONL`
  diam-diam menghasilkan xref kosong. Tidak ada log, tidak ada fatal.
- **Bukti SDK**: N/A. Tapi pola "data limitation is not the end of
  research" di AGENTS.md menekankan bahwa error harus terlihat, bukan
  ditelan.
- **Dampak**: Xref/signal stage menghasilkan output kosong tanpa
  peringatan. Analyst tidak tahu apakah "0 cross-ref" = tidak ada
  cross-ref atau = file input rusak. Golden test tidak menangkap ini
  karena golden direkam dari pipeline sehat.
- **Usulan**: Bedakan "file not found" (log warning, lanjut) vs "decode
  error" (fatal dengan konteks line number). `ReadJSONL` sudah
  mengembalikan `line %d: %w` — tinggal dipakai, bukan ditelan.
- **Prioritas**: Tinggi — silent failure adalah anti-pattern yang
  dilarang AGENTS.md ("Two gates that must stay green").

### Gap 3: Tidak ada JSONL manifest / schema — downstream tool harus menebak field

- **Deskripsi**: Setiap file JSONL (`functions.jsonl`, `call_edges.jsonl`,
  `classes.jsonl`, `string_refs.jsonl`, `dispatch_table.jsonl`,
  `evidence.jsonl`, `pool_immediates.jsonl`, `instances.jsonl`,
  `contexts.jsonl`, `type_arguments.jsonl`, `exception_handlers.jsonl`,
  `icdata.jsonl`, `closure_data.jsonl`, `library_functions.jsonl`,
  `ffi_bridges.jsonl`, `platform_channels.jsonl`, `deobfuscate_map.jsonl`,
  `scripts.jsonl`, `loading_units.jsonl`, `kpi.jsonl`,
  `selector_dispatch_xref.jsonl`, `field_accessor_xref.jsonl`,
  `function_fingerprints.jsonl`, `signals.jsonl`, `unresolved_thr.jsonl`,
  `index.jsonl`) tidak punya deklarasi schema. Field diturunkan dari
  struct Go yang tersebar di `disasm`, `cluster`, `strutil`, `evidence`,
  `signal`. Downstream (Ghidra script, IDA script, Python notebook) harus
  reverse-engineer struct Go dari source atau inspeksi sample.
- **Bukti SDK**: V8 snapshot profile writer (`v8_snapshot_writer.cc:307`)
  menulis `meta.node_fields`/`meta.edge_fields`/`node_types`/`edge_types`
  eksplisit di awal JSON — schema self-describing. AOTopsy tidak.
- **Dampak**: Setiap integrasi baru (Frida export, r2 fingerprint export,
  funcdiff) harus hardcode field name. Breaking change field name tidak
  terdeteksi sampai downstream crash.
- **Usulan**: Tambah `WriteManifest(dir)` yang menulis `manifest.json`
  berisi: nama file, record type (Go struct name), field list dengan
  json tag + type, version AOTopsy, Dart version target, SHA-256 input
  binary. Refactor `WriteJSONLFile` untuk auto-register ke manifest
  global. Downstream baca manifest dulu, bukan tebak.
- **Prioritas**: Sedang — tidak menghalangi RE tapi memperbesar friction
  setiap integrasi baru.

### Gap 4: Tidak ada validasi round-trip / integrity check JSONL

- **Deskripsi**: `WriteJSONLFile` menulis record tanpa checksum, tanpa
  count header, tanpa trailer. `ReadJSONL` tidak memverifikasi jumlah
  baris vs ekspektasi. Jika disk penuh di tengah penulisan
  `call_edges.jsonl`, file terpotong dan `ReadJSONL` mengembalikan
  error `unexpected EOF` pada baris terakhir — tapi stage yang menelan
  error (Gap 2) tidak akan sadar.
- **Bukti SDK**: `app_snapshot.cc` snapshot format punya header
  `Snapshot::kHeaderSize` dengan magic + length (`header->set_length
  (stream_->bytes_written())`) dan checksum. JSONL AOTopsy tidak punya
  proteksi serupa.
- **Dampak**: Output pipeline yang terpotong tidak terdeteksi. Golden
  test hanya jalan pada pipeline sehat. RE analyst yang meng-copy
  sebagian output tidak tahu file incomplete.
- **Usulan**: Tambah opsi `WriteJSONLFileWithTrailer` yang menulis
  `{"_meta":{"count":N,"sha256":"...","aotopsy_version":"..."}}` di
  baris terakhir (dibedakan dari record biasa via field `_meta`).
  `ReadJSONL` opsional verifikasi trailer. Atau lebih sederhana:
  tulis `<file>.count` sidecar berisi jumlah baris.
- **Prioritas**: Sedang — penting untuk reproducibility & audit trail.

### Gap 5: Duplikasi pola JSONL writer di 20+ file — inkonsistensi SetEscapeHTML

- **Deskripsi**: `jsonutil.JSONLWriter` sudah set `SetEscapeHTML(false)`
  (line 64), tapi 20+ site lain menulis JSONL langsung dengan
  `json.NewEncoder` dan setengahnya lupa `SetEscapeHTML(false)`:
  - **Lupa SetEscapeHTML(false)**: `evidence.go:199`, `cmd_debug_dart2.go:90`,
    `cmd_debug_ffitrace.go:52`, `typetrack/dispatch.go:175`,
    `crypto_id.go:639`, `disasm_test.go` (test, OK).
  - **Pakai SetIndent (bukan JSONL)**: `cmd_frida_export.go:75`,
    `thraudit/thrclassify.go:130`, `strutil/dartmeta.go:84`,
    `output/sarif.go:244`, `signal_stage.go:130`, `meta_stage.go:166`,
    `output/output.go:68`.
  - **Benar (SetEscapeHTML false, no indent)**: `disasm_stage.go`,
    `disasm_stagex86.go`, `cmd_debug_thr.go`, `cmd_debug_objects.go`,
    `cmd_corpus.go`, `thraudit.go`, `xref.go`, `r2_fingerprint_export.go`,
    `graph.go`, `crypto_id.go:640`.
- **Bukti SDK**: N/A (Go stdlib). `encoding/json` default `SetEscapeHTML
  (true)` akan escape `<`, `>`, `&` ke `\u003c` dll. Untuk string Dart
  yang mengandung operator (`<`, `>`) atau HTML, ini mengubah nilai
  string secara semantik dari sisi RE.
- **Dampak**: String `"<"` di `string_refs.jsonl` (dari evidence.go)
  menjadi `"\u003c"` — downstream grep untuk `<` miss. Inkonsistensi
  antar file: `functions.jsonl` (escape off) vs `evidence.jsonl`
  (escape on) untuk string yang sama.
- **Usulan**: Konsolidasi SEMUA penulisan JSONL ke `jsonutil`. Hapus
  `json.NewEncoder` langsung dari `evidence.go`, `thraudit.go`,
  `graph.go`, `xref.go`, `typetrack_stage.go`, `crypto_id.go`,
  `signal_stage.go`, `meta_stage.go`, `disasm_stage.go`,
  `disasm_stagex86.go`, `cmd_debug_*`. Pisahkan JSONL (escape off, no
  indent) vs JSON-pretty (escape off, indent) ke dua helper berbeda.
- **Prioritas**: Tinggi — bug semantik yang diam-diam mengubah data RE.

### Gap 6: Tidak ada streaming reader untuk incremental / resume analysis

- **Deskripsi**: `ReadJSONL` hanya bisa baca dari awal. Tidak ada API
  untuk: (a) baca N record pertama (sampling), (b) baca dari offset
  tertentu (resume setelah crash), (c) filter record saat baca (mis.
  hanya `kind=="blr"` dari `call_edges.jsonl`). Untuk app besar,
  analyst sering mau inspect subset tanpa load semua.
- **Bukti SDK**: N/A. Tapi `ReadStream` di `app_snapshot.cc:702`
  (`stream_.Position()`, `stream_.SetPosition(p)`) mendukung random
  access — snapshot reader bisa seek. JSONL AOTopsy tidak.
- **Dampak**: Setiap tool downstream (funcdiff, frida export, graph
  build) harus load full file. Tidak bisa preview. Tidak bisa parallel
  partition (worker baca range [i,j)).
- **Usulan**: Tambah `NewJSONLReader[T](path) (*JSONLReader[T], error)`
  dengan `Next() (T, bool, error)`, `Seek(line int)`, `Close()`.
  Implementasi: `bufio.Scanner` + `json.Unmarshal` per line (bukan
  `json.Decoder.More` yang tidak support seek). Untuk seek, simpan
  byte offset per-N-line di sidecar index.
- **Prioritas**: Sedang — nice-to-have untuk tooling besar.

### Gap 7: Tidak ada kompresi / opsi encoding untuk file besar

- **Deskripsi**: JSONL ditulis plain text. `call_edges.jsonl` app
  production bisa 50–100 MB, `string_refs.jsonl` bisa 200+ MB. Tidak
  ada opsi gzip. `render/signal_html.go` sudah pakai gzip+base64 untuk
  embed graph, tapi output JSONL pipeline tidak.
- **Bukti SDK**: N/A. Tapi V8 snapshot profile writer pakai
  `file_write` callback langsung (tidak kompres) — same as AOTopsy.
- **Dampak**: Disk space. Transfer antar mesin lambat. `funcdiff`
  cross-sample harus copy ratusan MB JSONL.
- **Usulan**: Tambah `NewJSONLWriterGz[T](path)` yang wrap `gzip.Writer`
  di atas `bufio.NewWriter`. Auto-detect `.gz` suffix di `ReadJSONL`
  untuk transparent decompress. Backward-compatible: file non-.gz
  tetap jalan.
- **Prioritas**: Rendah — optimasi, bukan correctness.

### Gap 8: Tidak ada append/merge untuk incremental analysis & cross-sample

- **Deskripsi**: `WriteJSONLFile` selalu `os.Create` (truncate). Tidak
  bisa append record ke file existing. `JSONLWriter` juga `os.Create`.
  Padahal use case RE: (a) jalankan pipeline per-loading-unit lalu
  merge, (b) tambahkan runtime evidence dari Frida ke
  `evidence.jsonl` existing, (c) cross-sample fingerprint merge untuk
  name transfer.
- **Bukti SDK**: N/A. Tapi `evidence.Collector.MergeRuntime`
  (`evidence.go:223`) sudah ada konsep merge runtime+static — tapi
  implementasinya load-full-then-rewrite, bukan append.
- **Dampak**: Setiap penambahan evidence / fingerprint / funcdiff
  result butuh rewrite full file. Tidak bisa streaming merge dari
  multiple sample.
- **Usulan**: Tambah `AppendJSONL[T](path, records []T) (int, error)`
  yang `os.OpenFile(path, O_APPEND|O_WRONLY|O_CREATE, 0644)`. Tambah
  `MergeJSONL[T](dst string, srcs []string) (int, error)` untuk
  concat+dedup by key field.
- **Prioritas**: Sedang — unlock workflow cross-sample & incremental.

### Gap 9: Test coverage minimal — tidak ada test edge case

- **Deskripsi**: `jsonutil_test.go` hanya 1 test: round-trip 3 record
  sederhana. Tidak ada test untuk:
  - File kosong (0 record) — `ReadJSONL` return `nil, nil`?
  - File tidak ada — error path.
  - Record dengan string mengandung newline (`\n` literal di JSON
    value) — `json.Encoder.Encode` harus escape, tapi verify.
  - Record dengan karakter Unicode / emoji.
  - Record dengan field `omitempty` — verify tidak ada trailing comma.
  - File truncated di tengah record — error message line number.
  - Concurrent `JSONLWriter.Write` dari multiple goroutine (disasm
    stage pakai chunk parallel, tapi write di main goroutine — aman,
    tapi tidak di-test).
  - Large record (10k field) — memory.
- **Bukti SDK**: N/A. Tapi AGENTS.md "Two gates that must stay green"
  menekankan test determinism. Test `jsonutil` tidak ada gate untuk
  edge case yang akan muncul di app nyata.
- **Dampak**: Bug edge case (mis. newline-in-string, truncated file)
  tidak tertangkap sampai production. Tidak ada regression guard saat
  refactor Gap 5.
- **Usulan**: Tambah table-driven test untuk 8 case di atas. Tambah
  benchmark `ReadJSONL` 100k record untuk ukur memory. Tambah fuzz test
  `ReadJSONL` dengan random JSONL input.
- **Prioritas**: Sedang — prerequisite untuk refactor Gap 5.

## Register Tracking Gaps

**Tidak ada.** `internal/jsonutil` adalah layer I/O murni yang tidak
menyentuh register ARM64/x86, tidak men-disassemble, tidak men-track
register value. Tidak ada `X0`–`X28`, `SP`, `LR`, `PC`, `THR` reference
di package ini. Register tracking gap ada di `internal/disasm`,
`internal/typetrack`, `internal/sdk` — bukan di sini.

Satu catatan: `jsonutil` men-serialisasi struct yang **dihasilkan** oleh
stage yang men-track register (mis. `disasm.CallEdgeRecord.Via` berasal
dari register tracking di typetrack). Tapi `jsonutil` hanya encode/decode,
tidak ada logika register. Jika field register-tracking hilang dari
struct, itu gap di package penghasil struct, bukan di `jsonutil`.

## Fitur RE Missing/Incomplete

1. **Streaming reader (Gap 6)** — tidak bisa inspect subset JSONL tanpa
   load full. Penting untuk app besar & exploratory RE.

2. **Manifest/schema (Gap 3)** — downstream tool (Ghidra/IDA/Frida/
   notebook) harus tebak field. Tidak ada self-describing format.

3. **Integrity/trailer (Gap 4)** — tidak ada deteksi file truncated.
   Output pipeline crash tidak terdeteksi.

4. **Append/merge (Gap 8)** — tidak bisa incremental analysis
   (tambah evidence runtime ke existing) atau cross-sample merge
   (fingerprint name transfer).

5. **Kompresi opsional (Gap 7)** — file besar tanpa gzip membebani
   disk & transfer.

6. **Konsolidasi writer (Gap 5)** — 20+ site duplikasi pola, setengah
   salah (SetEscapeHTML on). Bug semantik diam-diam.

7. **Error propagation (Gap 2)** — silent failure pada read corrupt
   menyembunyikan masalah dari analyst.

8. **Test edge case (Gap 9)** — tidak ada guard untuk newline-in-string,
   truncated file, concurrent write, large record.

9. **OOM guard (Gap 1)** — `ReadJSONL` load-full membatasi ukuran app
   yang bisa dianalisis end-to-end pada host terbatas.

## Verifikasi SDK

Verifikasi dilakukan dengan dua metode sesuai instruksi:

### 1. Grep MCP (`searchGitHub` by Vercel), `repo: "dart-lang/sdk"`

| Query | Hasil |
|-------|-------|
| `JSONLWriter` | No results |
| `WriteJSONLFile` | No results |
| `json.NewEncoder` | No results (Go code, SDK adalah C++/Dart) |
| `WriteJSONL` | No results |
| `JSONL` | 8 hasil, **tidak ada** yang relevan: `dwds` extension
  request (JSON list, bukan JSONL), `monitored.py`, `_fe_analyzer_shared`
  DiagnosticMessageFromJson, `data_types.dart`, `program_split_constraints`,
  test pattern, `convert_patch.dart` (JSON parser), `packages.dart`.
  Tidak ada format JSONL/NDJSON di SDK. |

**Kesimpulan**: Dart SDK tidak memiliki konsep JSONL. JSONL adalah
format output AOTopsy murni. Tidak ada perbandingan format wire
langsung.

### 2. `gh api` @ tag 3.9.2

| Path | Temuan |
|------|--------|
| `runtime/vm/app_snapshot.cc` | Snapshot serializer pakai
  `NonStreamingWriteStream` (bukan JSON). Header `Snapshot` punya
  magic + length (`header->set_length(stream_->bytes_written())`).
  Tidak ada JSONL. Konfirmasi Gap 4: snapshot punya integrity header,
  JSONL AOTopsy tidak. |
| `runtime/vm/v8_snapshot_writer.cc` | V8 profile writer pakai
  `JSONWriter` (JSON tunggal, bukan line-delimited). Schema
  self-describing: `meta.node_fields`, `meta.edge_fields`,
  `node_types`, `edge_types` ditulis eksplisit (line 320–345).
  Konfirmasi Gap 3: SDK self-describe schema, AOTopsy tidak. |
| `runtime/vm/v8_snapshot_writer.h` | `V8SnapshotProfileWriter` punya
  `IdSpace` enum (kSnapshot, kVmText, kIsolateText, kVmData,
  kIsolateData, kArtificial) — structured id space. JSONL AOTopsy
  tidak punya namespace id. |
| `runtime/vm/json_writer.h` | `JSONWriter` adalah JSON builder
  in-memory (`TextBuffer`), bukan streaming JSONL. Punya
  `PrintValueStr(const String& s, offset, count)` untuk Dart String
  dengan escape — konfirmasi bahwa escape handling penting (Gap 5). |

**Kesimpulan verifikasi**: Tidak ada gap "format wire tidak cocok dengan
SDK" karena SDK tidak pakai JSONL. Yang ada adalah gap "fitur yang SDK
punya di format snapshot-nya (schema self-describing, integrity header,
structured id space) tidak direplikasi di JSONL AOTopsy". Ini dasar
Gap 3 (manifest) dan Gap 4 (integrity).
