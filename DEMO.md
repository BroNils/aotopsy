# Demo — from a stripped `libapp.so` to names, structure, and pseudocode

A five-minute walkthrough on a real Dart 3.13.0 Flutter snapshot. Every output
below is verbatim tool output; nothing is hand-edited.

## 1. Identify the snapshot

```console
$ aotopsy doctor libapp.so
ELF:         OK (4542680 bytes)
Snapshot:    OK
Dart:        3.13.0
Pointers:    compressed (4 bytes)
Support:     OK
Features:    product arm64 android compressed-pointers ...
```

No Dart VM, no matching SDK to compile — AOTopsy reads the binary grammar directly
and reports the exact Dart version (structure-based, from the snapshot itself).

## 2. Recover original function names

Production builds are stripped, yet the snapshot still carries the object graph.
AOTopsy recovers the original Dart names from it:

```console
$ aotopsy _debug decompile-native --lib libapp.so --find DynamicColor
0x190b24  size=112  MaterialDynamicColors.init:scrim
0x190f84  size=172  MaterialDynamicColors.init:onSurfaceVariant
0x14d890  size=124  MaterialDynamicColors.init:surfaceBright
0x14d3cc  size=48   MaterialDynamicColors.highestSurface
```

Class, method, getter — recovered by name, not guessed. Where a value genuinely
can't be recovered it is shown honestly (`indirectCall`, `stub_…`, `<unknown>`);
AOTopsy never fabricates a name (see [Limitations & Scope](README.md#limitations--scope)).

## 3. Reconstruct a modular Dart project

```console
$ aotopsy export-dart --lib libapp.so --out ./reconstructed --app-only
[export-dart] Loaded libapp.so (Dart 3.13.0, ARM64)
[export-dart] Successfully exported 300 methods across 6 classes into 5 .dart files
```

The output is a real directory tree mapped by the app's library URIs
(`material_color_utilities/dynamiccolor/material_dynamic_colors.dart`, …), with
classes, methods, and pseudocode bodies. Recovered code parses as Dart — validated
against the actual `dart analyze` frontend, not just an internal check
(see [METHODOLOGY.md](METHODOLOGY.md)).

## 4. How much can you trust it?

Measured against ground truth, not asserted:

- **Name recovery: 90.2% agreement** vs each build's own `.symtab` across 44
  ground-truth builds, up to Dart 3.13.0 (92.8%) — see [BENCHMARK.md](BENCHMARK.md).
- **Format coverage: 93 builds across 23 Dart versions**, both architectures, parse
  cleanly — see [COVERAGE.md](COVERAGE.md).
- **Decompiler: 100% valid Dart, 0% fabrication** over the full function sweep.

## Why AOTopsy

The only static, version-independent Flutter AOT analyzer with a native pseudocode
decompiler, **x86_64** support (not just ARM64), and **published ground-truth
accuracy** — that tells you when it doesn't know. Releases ship signed,
checksummed, cross-platform binaries with build provenance (see [SECURITY.md](SECURITY.md)).

Start with [`WORKFLOW.md`](WORKFLOW.md) when you have a raw APK, or the
[Quick Start](README.md#quick-start).
