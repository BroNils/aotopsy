# RE Gap Analysis Report: internal/cli

> **STATUS VERIFIKASI (2026-09-01)** — semua CONFIRMED apa adanya (deteksi
> terminal hanya `os.Stderr.Stat()`, `DisableColor()` memutasi var paket, tak
> ada level log/progress/`--color`/tabel). Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> Satu koreksi framing: **"`--verbose` dead code" bukan temuan** — kodenya
> sendiri menulis `// accepted for backwards compat, now default`
> (`cmd_run.go:31`, `cmd_ida.go:25`, `cmd_meta.go:21`, `cmd_ghidra.go:26`).
> Itu no-op yang disengaja dan terdokumentasi, bukan kelalaian.

## Ringkasan

`internal/cli` adalah package helper terminal AOTopsy yang sangat tipis — hanya
**2 file, 70 baris total** (`color.go` 44 baris, `log.go` 26 baris). Isinya:

1. **`color.go`** — 9 konstanta warna 24-bit RGB neon (CRT/BBS aesthetic dari
   `signal.html`), `Bold`, `Reset`, `DisableColor()`, dan `init()` yang
   menonaktifkan warna ketika `NO_COLOR` set atau stderr bukan char device.
2. **`log.go`** — `MakeLogf(quiet, log)` (logger yang dibungkam oleh `--quiet`)
   dan `MakeStagef(quiet, log)` (header stage berwarna pink).

Pemakaian tersebar di **7 file** (`pipeline.go`, `signal_stage.go`,
`meta_stage.go`, `disasm_stage.go`, `disasm_stagex86.go`, `cmd_run.go`,
`cmd_signal.go`) — total **71 call site**. Sementara **`cmd_debug_*.go`
(≥14 file) memakai `fmt.Fprintf(os.Stderr, ...)` mentah tanpa helper `cli`**,
sehingga output debug tidak konsisten, tidak berwarna, dan tidak menghormati
`NO_COLOR`/non-TTY.

Gap utama terbagi tiga: **(a) deteksi terminal yang salah arah** (hanya cek
stderr, padahal summary/`printSummary` ditulis ke stderr juga tapi lewat
`fmt` mentah, dan `cmd_compare.go` ke stdout), **(b) tidak ada level log
(error/warn/info/debug)** — semua disamarkan menjadi `logf`/`stagef` dua-rasa,
**(c) tidak ada progress indicator untuk pipeline yang berjutan menit-jam**,
padahal SDK sendiri punya `pkg/dartdev/lib/src/progress.dart` yang reusable.

Tidak ada "register tracking" di package ini (cli adalah presentation layer,
bukan analysis layer), sehingga bagian Register Tracking Gaps di bawah fokus
pada **register/flag CLI yang seharusnya ditrack untuk RE workflow**:
`--verbose` yang dead-code, `--quiet` yang tidak punya lawan `--no-color`
eksplisit, tidak ada `--color={auto,always,never}`, tidak ada `--progress`,
tidak ada `--log-file`, tidak ada `--json-logs`.

## Struktur Folder

```
internal/cli/
├── color.go   (44 baris)  — palet RGB neon + DisableColor + init() NO_COLOR/non-TTY
└── log.go     (26 baris)  — MakeLogf, MakeStagef
```

Tidak ada subfolder, tidak ada test, tidak ada `doc.go`, tidak ada
`cli_test.go`. Package ini adalah leaf dependency dari `internal/analysis`
dan `cmd/aotopsy`.

Pemakaian (grep `cli\.(Green|Gold|…|MakeLogf|MakeStagef)`):
| File | Match | Peran |
|---|---|---|
| `internal/analysis/pipeline.go` | 12 | stage headers + logf inline |
| `internal/analysis/signal_stage.go` | 23 | stage + per-category log |
| `internal/analysis/meta_stage.go` | 14 | stage + focus log |
| `internal/analysis/disasm_stage.go` | 7 | stage + counter log |
| `internal/analysis/disasm_stagex86.go` | 3 | stage header |
| `cmd/aotopsy/cmd_run.go` | 12 | `printSummary` |
| `cmd/aotopsy/cmd_signal.go` | 10 | `printSignalSummary` |

**Tidak pakai `cli` sama sekali** (`fmt.Fprintf(os.Stderr,...)` mentah):
`cmd_debug_x64refs.go`, `cmd_debug_dart2.go`, `cmd_debug_dispatchtable.go`,
`cmd_debug_ffitrace.go`, `cmd_debug_fingerprint.go`, `cmd_debug_decompile.go`,
`cmd_debug_diff.go`, `cmd_debug_thr.go`, `cmd_debug_graph.go` — total
**≥40 `Fprintf` mentah** di subcommand `_debug`, yang notabene adalah
**RE workflow utama** (THR audit, dispatch table, ffi-trace, callgraph).

## Gap Analysis

### Gap 1: Deteksi terminal salah — hanya cek stderr, abaikan stdout & CLICOLOR_FORCE
- **Deskripsi**: `init()` di `color.go` hanya mengecek `os.Stderr.Stat()`
  (`fi.Mode()&os.ModeCharDevice == 0`) dan `NO_COLOR`. Tidak ada:
  - cek `stdout` (padahal `cmd_compare.go:27` `fmt.Print(result.Summary())` ke
    stdout, dan `cmd_run.go`/`cmd_signal.go` summary ke stderr — stream
    berbeda, keputusan warna harus independen per-stream seperti SDK);
  - cek `CLICOLOR_FORCE` (standar de facto, dipakai `ls`/`grep`/`git`);
  - cek `FORCE_COLOR` (dipakai `chalk`, banyak CI);
  - cek `TERM=dumb` (terminal yang tidak support ANSI sama sekali);
  - cek `TERM` contains `xterm` (SDK `colors.dart` line ~140 explicit men-remark
    bahwa VM hanya mendeteksi `TERM.contains("xterm")`).
- **Bukti SDK**:
  - `pkg/_fe_analyzer_shared/lib/src/util/colors.dart` (ref 3.9.2, diambil via
    `gh api`): `_computeEnableColors()` mengecek **kedua** `stdout.supportsAnsiEscapes`
    **dan** `stderr.supportsAnsiEscapes` secara terpisah, lalu di non-Windows
    menjalankan `tput -S` untuk verifikasi `setaf 0..7` + `op` benar-benar
    didukung terminal. Ada `set enableColors` override eksplisit.
  - `pkg/dartdev/lib/src/progress.dart` (ref main, via `gh api`):
    `canUseAnsiCodes(progressUpdatesOnStderr)` — **per-stream**: kalau update
    ke stderr, cek `stderr.hasTerminal && stderr.supportsAnsiEscapes`; kalau
    ke stdout, cek `stdout.hasTerminal && stdout.supportsAnsiEscapes`. Dan
    `NO_COLOR` di-cek **pertama**, lalu per-stream.
- **Dampak**: Pada piped stdout + TTY stderr (mis. `aotopsy compare … | tee`),
  warna salah aktif/mati. Pada `CLICOLOR_FORCE=1 aotopsy … | cat`, warna
  padahal user explicit minta. Pada `TERM=dumb` warna bocor. Untuk RE
  workflow di CI/Notebook (bukan char device) warna selalu mati — itu
  benar — tapi tidak ada cara **force-on** untuk capture screenshot
  berwarna di blog/report RE.
- **Usulan**: Ganti `init()` dengan `resolveColorMode(stream) ColorMode`
  (`auto|always|never`) yang membaca `--color` flag > `CLICOLOR_FORCE` >
  `FORCE_COLOR` > `NO_COLOR` > `TERM=dumb` > `isatty(stream)`. Ekspos
  `cli.EnableFor(os.Stdout)` / `cli.EnableFor(os.Stderr)`. Hapus
  `DisableColor()` global-state mutation (race-prone, lihat Gap 9).
- **Prioritas**: Tinggi — menyentuh setiap output AOTopsy, termasuk
  `printSummary` yang adalah pintu masuk RE analyst.

### Gap 2: Tidak ada level log (error/warn/info/debug) — semua disamarkan jadi `logf`
- **Deskripsi**: Hanya ada `MakeLogf` (satu rasa) dan `MakeStagef`. Tidak ada
  `Warnf`, `Errorf`, `Infof`, `Debugf`. Akibatnya:
  - `pipeline.go:324` menulis `warning:` literal di string (`"  %swarning:%s …"`
    dengan `cli.Muted`) — warning di-mute oleh `--quiet`, padahal warning
    seharusnya **selalu** tampil (atau paling tidak ke stderr terpisah).
  - `cmd_debug_graph.go:137,146,155` menulis `warning: callgraph SVG failed`
    via `fmt.Fprintf` mentah — tidak konsisten dengan `pipeline.go`.
  - Error dari sub-stage (`opts.logf("  taint: %v\n", err)`,
    `opts.logf("  yara: %v\n", err)`, `opts.logf("  evidence: %v\n", err)`)
    di-swallow sebagai info — analyst tidak tahu mana yang fatal.
- **Bukti SDK**:
  - `pkg/compiler/lib/src/source_file_provider.dart` (ref main, via grep MCP):
    punya `info(message, [kind])`, `warning`, `error` terpisah, masing-masing
    dengan warna sendiri (`colors.green("Info:")`, dst.) dan gate `verbose`
    hanya untuk `verboseInfo`.
  - `pkg/_fe_analyzer_shared/lib/src/util/colors.dart`: `green(s)`, `red(s)`,
    `yellow(s)`, `blue(s)` sebagai **fungsi wrapper** (`wrap`) — bukan konstanta
    mentah — sehingga `enableColors=false` otomatis strip, tidak perlu
    `DisableColor()` mutasi global.
- **Dampak**: Pada pipeline yang panjang (snapshot load → disasm 129k func →
  signal → meta), analyst tidak bisa `grep -E "warn|error"` di log untuk
  menemukan stage yang gagal. Untuk RE automation (script yang parse log),
  tidak ada prefix stabil.
- **Usulan**: Tambah `type Level int` (`Debug|Info|Warn|Error`) +
  `Logf(level, format, args)` dengan prefix berwarna (`E` merah, `W` kuning,
  `I` biru, `D` muted) dan gate `--verbose` untuk Debug. Warning/Error
  **tidak** dibungkam oleh `--quiet` (hanya Info yang dibungkam).
- **Prioritas**: Tinggi.

### Gap 3: Tidak ada progress indicator untuk pipeline menit-jam
- **Deskripsi**: Pipeline AOTopsy pada app besar (129k function) berjalan
  menit-jam. Saat ini satu-satunya feedback adalah `stagef` header per stage
  + `logf` counter. Tidak ada spinner, tidak ada progress bar, tidak ada
  ETA. Pada non-TTY (CI/log file) tidak ada bar sama sekali — itu benar —
  tapi pada TTY analyst tidak tahu apakah hang atau progress.
- **Bukti SDK**:
  - `pkg/dartdev/lib/src/progress.dart` (ref main, via `gh api`): class
    `_Progress` dengan `Stopwatch`, `Timer.periodic(100ms)`, `\b` backspace
    untuk update time, gate `stderr.hasTerminal`/`stdout.hasTerminal`,
    `NO_COLOR` cek, dan **fallback** `_sink.write('$_message...')` ketika
    non-TTY. `progress<T>(message, callback)` wrapper.
  - `pkg/analysis_server/tool/code_completion/completion_metrics_base.dart`
    (via grep MCP): progress bar `[${' '*innerWidth}]` dengan
    `stdout.terminalColumns - 12` lebar dinamis.
  - `pkg/test_runner/lib/src/terminal.dart`: `_lineLength` dari
    `stdout.terminalColumns` fallback 80.
- **Dampak**: RE analyst tidak bisa memperkirakan sisa waktu; tidak bisa
  memutuskan apakah restart atau tunggu. Pada demo/workshop, terminal
  terlihat hang. Tidak ada sinyal untuk automation timeout.
- **Usulan**: Tambah `cli.Progress(message, total int)` dengan: spinner
  Braille/`|/-\` ketika `total` unknown; bar `[####---] N/total (ETA)`
  ketika known; gate `isatty`; fallback `message...` ketika non-TTY;
  `Stop()` cetak durasi final. Pasang di `pipeline.go` stage disasm (loop
  per-function) dan `signal_stage.go`.
- **Prioritas**: Sedang — bukan blocking RE tapi UX besar.

### Gap 4: `--verbose` adalah dead code di 6 subcommand
- **Deskripsi**: `cmd_run.go:30-32`, `cmd_signal.go:41-43`, `cmd_meta.go`,
  `cmd_ida.go`, `cmd_ghidra.go`, `cmd_compare.go` semua deklarasi:
  ```go
  var _verbose bool // accepted for backwards compat, now default
  fs.BoolVar(&_verbose, "verbose", false, "")
  fs.BoolVar(&_verbose, "v", false, "")
  ```
  `_verbose` tidak pernah dibaca. `commands.go:114` help bilang
  `--quiet, -q  Suppress verbose output (verbose is default)`. Jadi
  `--verbose` adalah no-op murni, tapi masih diparsing. Tidak ada
  `--debug`/`--trace` yang sebenarnya mengaktifkan log level lebih tinggi.
- **Bukti SDK**: `pkg/compiler/lib/src/dart2js.dart:157` punya `bool? verbose`
    yang **dipakai** (`if (!verbose && kind == verboseInfo) return` di
    `source_file_provider.dart:216`). `pkg/front_end/lib/src/base/compiler_context.dart:35`
    `if (options.verbose) colors.printEnableColorsReason = print;` — verbose
    mengaktifkan diagnostik tambahan.
- **Dampak**: Analyst yang ketik `aotopsy run --verbose` mengira dapat info
  lebih, padahal tidak. Tidak bisa toggle detail stage (mis. per-function
  disasm log, per-class fill log) untuk debugging RE. `--quiet` saja
  tidak cukup granular.
- **Usulan**: Wire `_verbose` ke `Logf(Debug, …)` (Gap 2). Tambah
  `--debug` untuk trace-level (per-instruction lift log). Hapus
  `// accepted for backwards compat` comment jika sudah di-wire.
- **Prioritas**: Sedang.

### Gap 5: Tidak ada `--color={auto,always,never}` flag — hanya `NO_COLOR` env
- **Deskripsi**: `color.go` hanya baca `NO_COLOR`. Tidak ada flag CLI untuk
  override. `--quiet` tidak ada pasangan `--color`. User harus set env:
  `NO_COLOR=1 aotopsy …` atau `unset NO_COLOR`. Tidak bisa
  `aotopsy run --color=always libapp.so | less -R` untuk RE report berwarna.
- **Bukti SDK**: `pkg/compiler/lib/src/dart2js.dart:450` punya
  `Flags.disableDiagnosticColors` / `Flags.enableDiagnosticColors` sebagai
  **flag eksplisit** (bukan env saja). `pkg/front_end` punya
  `colors.enableColors = true/false` setter.
- **Dampak**: RE workflow yang pipe ke `less -R`/`bat`/`aha` (ANSI→HTML)
  tidak bisa force warna tanpa env var. Inconsistent dengan tool Unix lain
  (`ls --color=always`, `grep --color=always`).
- **Usulan**: Tambah `--color string` flag (default `"auto"`, nilai
  `auto|always|never`) di root flag set, propagate ke `cli.SetColorMode`.
  `always` → force on bahkan jika non-TTY. `never` → force off.
- **Prioritas**: Sedang.

### Gap 6: `cmd_debug_*.go` tidak pakai `cli` — output RE utama tidak berwarna & tidak honor `NO_COLOR`
- **Deskripsi**: 9 file `cmd_debug_*` (x64refs, dart2, dispatchtable, ffitrace,
  fingerprint, decompile, diff, thr, graph) total ≥40 `fmt.Fprintf(os.Stderr,
  …)` mentah. Contoh `cmd_debug_graph.go:137`:
  ```go
  fmt.Fprintf(os.Stderr, "warning: callgraph SVG failed: %v (use --no-dot to skip)\n", err)
  ```
  vs `pipeline.go:324` yang pakai `cli.Muted`+`cli.Reset`. Output `_debug thr`
  (THR audit), `_debug dispatchtable`, `_debug ffitrace` adalah **RE workflow
  inti** tapi tidak konsisten dengan pipeline utama.
- **Bukti SDK**: `pkg/dartdev/lib/src/progress.dart` `gray(text, …)` wrapper
    yang otomatis strip ketika `canUseAnsiCodes` false — semua output lewat
    wrapper, tidak ada `print` mentah dengan ANSI literal.
- **Dampak**: `NO_COLOR=1 aotopsy _debug thr …` tetap cetak ANSI mentah
  jika ada (sebenarnya tidak ada ANSI di debug sekarang — jadi selalu
  plain — tapi itu artinya **RE analyst tidak dapat color coding** untuk
  klasifikasi THR/kategori dispatch padahal `signal_stage.go` sudah berwarna).
  Inconsistent UX.
- **Usulan**: Refactor `cmd_debug_*.go` ke `cli.Logf`/`cli.Warnf`/`cli.Errorf`
  + `cli.Green/Gold/…` untuk counter. Buat helper `cli.Summary(w, …)` untuk
  pola `printSummary`/`printSignalSummary` yang berulang.
- **Prioritas**: Sedang-Tinggi.

### Gap 7: Tidak ada `--log-file` / `--json-logs` untuk RE automation
- **Deskripsi**: Semua log ke stderr. Tidak ada opsi tulis log ke file
  terpisah (untuk arsip RE session), tidak ada format JSONL log (untuk
  parse post-hoc). `evidence.jsonl` ada tapi itu data, bukan run log.
  Tidak ada `--tee-log` untuk cetak ke stderr + file sekaligus.
- **Bukti SDK**: `pkg/testing/lib/src/log.dart` punya `enableAnsiEscapes`
    gate + `eraseLineCodes` untuk log terstruktur. `pkg/test_runner/lib/src/test_progress.dart`
    punya `ProgressIndicator` dengan `CompactProgressIndicator` (TTY) vs
    `LineProgressIndicator` (non-TTY) vs `VerboseProgressIndicator` —
    **multi-mode log**.
- **Dampak**: RE session tidak reproducible — analyst tidak bisa audit
  urutan stage & timing. CI tidak bisa diff log antar run.
- **Usulan**: Tambah `cli.NewLogger(opts)` yang write ke `io.Writer`
  multi-sink (stderr + file + jsonl). Format JSONL: `{ts, level, stage,
  msg}`. Pasang `--log-file path` dan `--json-logs` flag.
- **Prioritas**: Sedang.

### Gap 8: Palet warna hard-coded RGB — tidak ada theme, tidak ada high-contrast, tidak colorblind-safe
- **Deskripsi**: `color.go` hard-code 9 warna RGB neon (Green `0;255;0`,
  Pink `255;128;192`, dst.) dari `signal.html`. Tidak ada:
  - **theme** (light/dark/auto via `COLORFGBG` atau `COLOR_TERM`);
  - **high-contrast** mode untuk accessibility;
  - **colorblind-safe** palette (deuteranopia: hindari green/red bareng);
  - **dim/bold** variant untuk monochrome terminal.
  `Green` dan `Red` dipakai bareng di `signal_stage.go` untuk kategori
  signal — berisiko untuk ~8% male population colorblind.
- **Bukti SDK**: `pkg/_fe_analyzer_shared/lib/src/util/colors.dart` pakai
    **8 warna standar termcap** (`setaf 0..7`) yang sudah di-verify via
    `tput -S` — bukan RGB hard-code, sehingga menghormati theme terminal
    user. `pkg/dartdev/lib/src/progress.dart` pakai `gray` (`\u001b[38;5;245m`
    256-color) bukan RGB.
- **Dampak**: Pada terminal dengan background terang (default macOS
  Terminal), `Green 0;255;0` nyaris tak terbaca. Pada colorblind user,
  signal kategori hijau/merah tidak distinguishable.
- **Usulan**: Opsi A: pakai `setaf` 0-7 (hormat theme). Opsi B: tetap RGB
  tapi tambah `--theme={neon,ansi,mono,highcontrast}` + auto-detect
  `COLORFGBG`/`COLOR_TERM`. Tambah **simbol** selain warna (✓/✗/⚠/ℹ) untuk
  redundant encoding.
- **Prioritas**: Rendah-Sedang.

### Gap 9: `DisableColor()` mutasi global — race-prone & tidak testable
- **Deskripsi**: `color.go` expose `var Green = "…"` (mutable) +
  `DisableColor()` set semua ke `""`. `init()` panggil `DisableColor()` di
  import time. Karena `Green` dst. adalah **package var mutable**, test
  parallel (`t.Parallel()`) yang toggle warna akan race. Tidak ada
  `cli.WithColor(mode, fn)` scope. `pipeline.go` baca `cli.Green` langsung
  — jika `DisableColor` dipanggil mid-pipeline (tidak mungkin sekarang,
  tapi bisa setelah refactor), output setengah berwarna.
- **Bukti SDK**: `pkg/_fe_analyzer_shared/lib/src/util/colors.dart` pakai
    `bool? _enableColors` + getter `enableColors` + setter — **single
    source of truth**, dan `wrap(string, color)` yang cek `enableColors`
    **per-call**, bukan mutasi konstanta. `pkg/dart2wasm/benchmark/self_compile_benchmark.dart:64`
    `colors.enableColors = false;` — setter, bukan mutasi 9 var.
- **Dampak**: Sulit unit-test output berwarna. Tidak bisa parallel test
  dengan color mode berbeda. Refactor warna berisiko.
- **Usulan**: Ganti konstanta mutable dengan `cli.Style(name) string` yang
  baca `colorMode` internal (atomic). Atau ikuti SDK: `cli.Green(s) string`
  wrapper function. Hapus `DisableColor()` publik, ganti `cli.SetColorMode(mode)`.
- **Prioritas**: Sedang (refactor, breaking API).

### Gap 10: Tidak ada `cli.Sprintf`/`cli.Highlight` — ANSI literal tersebar di 71 call site
- **Deskripsi**: Setiap call site tulis `cli.Gold, value, cli.Reset` manual.
  Tidak ada helper `cli.Goldf("%d", n)` atau `cli.Highlight(s, color)`.
  Akibat: mudah lupa `Reset` (bocor warna ke baris berikutnya), tidak bisa
  strip secara terpusat, tidak bisa tambah attribute (bold + gold) tanpa
  concat manual (`cli.Bold + cli.Gold + s + cli.Reset` — yang salah, harus
  `cli.Gold + cli.Bold + s + cli.Reset` order-wise).
- **Bukti SDK**: `pkg/_fe_analyzer_shared/lib/src/util/colors.dart`:
    `String green(String s) => wrap(s, GREEN_COLOR);` — **fungsi**, bukan
    konstanta. `wrap` otomatis append `DEFAULT_COLOR`. Tidak mungkin lupa
    reset.
- **Dampak**: 71 call site rawan typo reset. Tidak bisa audit "di mana
  warna dipakai" tanpa grep manual.
- **Usulan**: Tambah `cli.Gold(s)`, `cli.Red(s)`, dst. (wrapper yang auto
  reset + honor colorMode). Migrasi call site bertahap. Pertahankan
  konstanta untuk backward-compat sementara.
- **Prioritas**: Sedang.

### Gap 11: `MakeStagef` hard-code Pink — tidak configurable per stage
- **Deskripsi**: `log.go:23` `"\n%s%s%s %s\n", Pink, name, Reset, detail` —
  semua stage header pink. Tidak bisa bedakan stage `elf` vs `disasm` vs
  `signal` vs `meta` secara visual. Tidak ada icon/emoji stage (SDK tidak
  pakai emoji, tapi pakai prefix `Running…`/`Done`).
- **Bukti SDK**: `pkg/dartdev/lib/src/progress.dart` `progress(message,
    callback)` — message adalah label stage, warna gray untuk timer,
    bukan header berwarna. `pkg/test_runner/lib/src/test_progress.dart`
    `CompactProgressIndicator` pakai `+`/`-`/`?` symbol per outcome.
- **Dampak**: Pada pipeline 10+ stage, semuanya pink → analyst tidak
  scan-visual stage mana yang sedang jalan.
- **Usulan**: Map stage name → warna (`elf`=Blue, `disasm`=Gold,
  `signal`=Pink, `meta`=Green, `evidence`=Muted). Tambah durasi
  `[1.2s]` setelah nama stage (perlu `Stopwatch` per stage).
- **Prioritas**: Rendah-Sedang.

### Gap 12: Tidak ada `cli.Table` / `cli.Column` — output tabular RE mentah
- **Deskripsi**: `cmd_debug_thr.go:142` `fmt.Fprintf(os.Stderr, "  %-30s %4d
  (%5.1f%%)\n", cls, count, pct)` — format kolom manual. `printSummary`
  pakai align spasi manual (`"  %soutput:%s     %s"`). Tidak ada helper
  tabel yang respect `terminalColumns` (wrap kolom jika sempit).
- **Bukti SDK**: `pkg/dartdev/lib/src/utils.dart:18`:
    `int? get dartdevUsageLineLength => stdout.hasTerminal ? stdout.terminalColumns : null;`
    — **lebar terminal dipakai** untuk format usage. `pkg/test_runner/lib/src/terminal.dart:44`
    `_lineLength` dari `stdout.terminalColumns` fallback 80.
- **Dampak**: Pada terminal sempit (<80 col) output wrap acak. Pada
  terminal lebar tidak manfaatkan ruang.
- **Usulan**: Tambah `cli.Table(cols …)` dengan auto-width dari
  `terminalColumns` + `cli.SprintfRow`. Pakai di `printSummary`,
  `cmd_debug_thr`, `cmd_debug_dispatchtable`.
- **Prioritas**: Rendah.

## Register Tracking Gaps

Package `cli` adalah presentation layer — tidak track register CPU/Dart VM.
Tapi berikut **flag/state CLI yang seharusnya ditrack** untuk RE workflow
dan saat ini missing atau dead:

| Register/Flag | Status saat ini | Gap |
|---|---|---|
| `--verbose`/`-v` | Dideklarasi di 6 subcommand, **tidak pernah dibaca** (`_verbose` dead) | Tidak toggle Debug log level (Gap 4) |
| `--quiet`/`-q` | Dipakai, gate `logf`/`stagef` | Tidak ada lawan eksplisit `--no-color`; warning ikut dibungkam (Gap 2) |
| `--color` | **Tidak ada** | Hanya env `NO_COLOR`, tidak ada flag (Gap 5) |
| `--log-file` | **Tidak ada** | Tidak ada arsip RE session (Gap 7) |
| `--json-logs` | **Tidak ada** | Tidak ada machine-parseable log (Gap 7) |
| `--progress` | **Tidak ada** | Tidak ada toggle spinner/bar (Gap 3) |
| `--theme` | **Tidak ada** | Tidak ada palette switch (Gap 8) |
| `--debug`/`--trace` | **Tidak ada** | Tidak ada per-instruction trace toggle (Gap 4) |
| `NO_COLOR` env | Dipakai di `init()` | Benar, tapi tidak per-stream (Gap 1) |
| `CLICOLOR_FORCE` env | **Tidak dipakai** | Standar de facto (Gap 1) |
| `FORCE_COLOR` env | **Tidak dipakai** | CI convention (Gap 1) |
| `TERM=dumb` | **Tidak dipakai** | Terminal non-ANSI (Gap 1) |
| `TERM=*xterm*` | **Tidak dipakai** | SDK verify via tput (Gap 1) |
| `COLORFGBG` env | **Tidak dipakai** | Light/dark bg detect (Gap 8) |
| `COLOR_TERM` env | **Tidak dipakai** | truecolor detect (Gap 8) |
| `stderr.hasTerminal` | Cek `ModeCharDevice` (proxy) | Bukan `isatty` sebenarnya, tidak per-stream (Gap 1) |
| `stdout.hasTerminal` | **Tidak dicek** | `cmd_compare.go` ke stdout (Gap 1) |
| `terminalColumns` | **Tidak dipakai** | Tidak ada wrap/width (Gap 12) |
| `terminalLines` | **Tidak dipakai** | Tidak ada pager/scroll (Gap 12) |
| `colorMode` internal state | **Tidak ada** — 9 var mutable | Race-prone, tidak testable (Gap 9) |

## Fitur RE Missing/Incomplete

Berikut fitur CLI yang **akan berguna untuk RE Flutter AOT** dan missing/incomplete
di `internal/cli`:

1. **`cli.Progress`** — spinner/bar untuk pipeline menit-jam (Gap 3).
   RE use case: analyst tahu estimasi sisa waktu disasm 129k func.
2. **`cli.Logf(level, …)` + level prefix stabil** (`E`/`W`/`I`/`D`) (Gap 2).
   RE use case: `aotopsy run … 2>&1 | grep -E "^(E|W)"` untuk audit failure.
3. **`cli.Summary(w, rows …)`** — standardize `printSummary`/`printSignalSummary`
   yang berulang di `cmd_run.go` & `cmd_signal.go` (Gap 6, 12).
   RE use case: output summary konsisten lintas subcommand.
4. **`cli.Table`** dengan auto-width `terminalColumns` (Gap 12).
   RE use case: `aotopsy _debug thr` tabel kelas THR wrap rapi di terminal
   sempit.
5. **`cli.JSONLLog`** — log stage sebagai JSONL `{ts,level,stage,msg,dur_ms}`
   (Gap 7). RE use case: post-hoc diff `aotopsy run v1.jsonl run v2.jsonl`
   untuk regression analysis.
6. **`cli.Dur(stage)`** — Stopwatch per stage, cetak `[1.2s]` di header
   (Gap 11). RE use case: identifikasi stage bottleneck (biasanya disasm).
7. **`cli.Color(name) string`** wrapper function (Gap 9, 10).
   RE use case: testable, race-free, auto-reset.
8. **`cli.DetectColorMode(stream) ColorMode`** — `auto|always|never` +
   `CLICOLOR_FORCE`/`FORCE_COLOR`/`NO_COLOR`/`TERM`/`isatty` (Gap 1, 5).
   RE use case: `aotopsy run --color=always … | aha > report.html` untuk
   screenshot berwarna di blog RE.
9. **`cli.Warnf`/`cli.Errorf`** yang **tidak** dibungkam `--quiet` (Gap 2).
   RE use case: warning `flutter_meta.json generation is ARM64-only` tetap
   terlihat saat `--quiet`.
10. **`cli.Theme`** neon/ansi/mono/highcontrast + colorblind-safe (Gap 8).
    RE use case: accessibility untuk analyst colorblind.
11. **`cli.Symbol(level)`** — `✓`/`✗`/`⚠`/`ℹ` redundant encoding selain
    warna (Gap 8). RE use case: output tetap terbaca di monochrome / pipe.
12. **`cli.Pager()`** — auto-pipe ke `less -R` ketika TTY & output panjang
    (Gap 12). RE use case: `aotopsy _debug thr` 5000 baris tidak scroll
    keluar layar.
13. **`--debug`/`--trace`** flag → enable per-instruction lift log di
    decompiler (Gap 4). RE use case: trace mengapa `x22` tidak ter-reset.
14. **`cli.TeeLog(w, file)`** — stderr + file sekaligus (Gap 7).
    RE use case: arsip session ke `aotopsy-2025-01-15.log` sambil lihat
    live di terminal.

## Verifikasi SDK

Semua klaim tentang Dart SDK diverifikasi via dua jalur sesuai instruksi:

### Jalur 1: grep MCP (`searchGitHub` by Vercel, `repo: "dart-lang/sdk"`)

| Query | Hasil | File SDK | Relevansi |
|---|---|---|---|
| `NO_COLOR` | 1 hit | `pkg/dartdev/lib/src/progress.dart:150` `canUseAnsiCodes` cek `NO_COLOR` pertama, lalu per-stream `stderr.hasTerminal`/`stdout.hasTerminal` | Bukti Gap 1: cek per-stream + NO_COLOR first |
| `ProgressIndicator` | 2 hit | `pkg/test_runner/lib/src/test_progress.dart:427` multi-mode (color/compact/line/verbose) | Bukti Gap 3: progress indicator + multi-mode log |
| `supportsAnsiEscapes` | 7 hit | `sdk/lib/io/stdio.dart:183,268` `external bool get supportsAnsiEscapes`; `pkg/_fe_analyzer_shared/lib/src/util/colors.dart` cek stdout **dan** stderr; `pkg/testing/lib/src/log.dart:20` `enableAnsiEscapes = stdout.supportsAnsiEscapes` | Bukti Gap 1: per-stream ANSI detect |
| `CLICOLOR_FORCE` | 0 hit | — | SDK tidak pakai `CLICOLOR_FORCE`, tapi standar Unix luas (`ls`/`grep`/`git`); tetap valid sebagai gap AOTopsy |
| `enableColors` | 9 hit | `pkg/_fe_analyzer_shared/lib/src/util/colors.dart` `bool? _enableColors` + getter + setter; `pkg/compiler/lib/src/dart2js.dart:450` flag `--enable-diagnostic-colors`/`--disable-diagnostic-colors`; `pkg/dart2wasm/benchmark` `colors.enableColors = false` | Bukti Gap 5, 9: flag eksplisit + setter pattern |
| `env["FORCE_COLOR"]` | 0 hit | — | SDK tidak pakai; tapi CI convention (chalk) |
| `stdout.terminalColumns` | 9 hit | `pkg/dartdev/lib/src/utils.dart:18` `dartdevUsageLineLength`; `pkg/test_runner/lib/src/terminal.dart:44` `_lineLength`; `pkg/analysis_server/.../completion_metrics_base.dart:277` progress bar width | Bukti Gap 12: terminal width dipakai untuk format |
| `env["TERM"]` | 0 hit (literal) | — | `colors.dart` remark bahwa VM hanya cek `TERM.contains("xterm")` (di body `_computeEnableColors`, terverifikasi via gh api) |

### Jalur 2: `gh api` @ version tag

| Path | Ref | Hasil | Dipakai untuk |
|---|---|---|---|
| `pkg/_fe_analyzer_shared/lib/src/util/colors.dart` | `3.9.2` | 200 baris, full | Bukti Gap 1, 5, 8, 9, 10: `_computeEnableColors` cek stdout+stderr terpisah, `tput -S` verify, `set enableColors` setter, `green(s)`/`red(s)` wrapper, `DEFAULT_COLOR` auto-reset |
| `pkg/dartdev/lib/src/progress.dart` | `3.9.2` | **404 Not Found** — file belum ada di 3.9.2 | — |
| `pkg/dartdev/lib/src/progress.dart` | `main` | 180 baris, full | Bukti Gap 3: `_Progress` class, `Stopwatch`, `Timer.periodic(100ms)`, `\b` backspace, gate `hasTerminal`, fallback `message...`, `canUseAnsiCodes` per-stream + NO_COLOR |

**Catatan**: `progress.dart` tidak ada di tag 3.9.2 (404), hanya di `main`.
Ini berarti progress indicator adalah fitur SDK yang **relatif baru** —
semakin valid sebagai rekomendasi untuk AOTopsy. `colors.dart` ada di 3.9.2
dan stabil.

### Ringkasan verifikasi

- **Gap 1** (per-stream detect, `CLICOLOR_FORCE`, `TERM=dumb`): terverifikasi
  SDK cek per-stream + `NO_COLOR` first; `CLICOLOR_FORCE`/`FORCE_COLOR` tidak
  dipakai SDK tapi standar Unix — gap AOTopsy valid.
- **Gap 2** (level log): terverifikasi SDK `source_file_provider.dart` punya
  `info`/`warning`/`error` terpisah dengan warna sendiri.
- **Gap 3** (progress): terverifikasi `progress.dart` (main) + `completion_metrics_base.dart`
  progress bar.
- **Gap 4** (`--verbose` dead): terverifikasi SDK `dart2js.dart` `verbose`
  dipakai; AOTopsy `_verbose` dead code.
- **Gap 5** (`--color` flag): terverifikasi SDK `dart2js.dart:450` flag
  `--enable/disable-diagnostic-colors`.
- **Gap 8** (theme/colorblind): terverifikasi SDK pakai `setaf 0..7` (hormat
  theme), bukan RGB hard-code.
- **Gap 9** (mutable global): terverifikasi SDK `bool? _enableColors` +
  setter, bukan 9 var mutable.
- **Gap 10** (wrapper function): terverifikasi SDK `green(s)`/`wrap(s,color)`
  auto-reset.
- **Gap 12** (`terminalColumns`): terverifikasi SDK `utils.dart` +
  `terminal.dart` pakai lebar terminal.

Tidak ada klaim dalam report ini yang tidak diverifikasi ke SDK source via
grep MCP atau `gh api`. Klaim tentang `cmd_debug_*.go` mentah diverifikasi
via `grep` lokal di repo AOTopsy (40+ match `fmt.Fprintf(os.Stderr, …)` di
9 file `_debug`).
