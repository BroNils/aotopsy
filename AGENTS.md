# AGENTS.md — AOTopsy

## Build & Test

Do NOT use `./...` — it traverses `runtime_test/` (thousands of non-Go files) causing slow stat and OOM. Use:

```bash
go build ./cmd/... ./internal/... ./tools/...
go test ./cmd/... ./internal/... ./tools/...
```

Build just the binary: `go build -o aotopsy ./cmd/aotopsy/`

## Project Structure

```mermaid
flowchart TD
    CLI[cmd/aotopsy<br/>CLI entry point]
    subgraph "internal/"
        ELFX[elfx<br/>ELF validation]
        SNAP[snapshot<br/>version profiles]
        DART[dartfmt<br/>wire encoding]
        CLUST[cluster<br/>snapshot deserialization]
        DISASM[disasm<br/>ARM64 + x86_64 decode]
        CG[callgraph<br/>DOT rendering]
        SIG[signal<br/>behavioral classification]
        REND[render<br/>HTML/DOT/SVG]
        OUT[output<br/>JSONL serialization]
        DEC[decompiler<br/>pseudocode]
        TT[typetrack<br/>type inference]
        FP[fingerprint<br/>version ID]
        FD[funcdiff<br/>function diffing]
        SM[symbolmap<br/>symbol resolution]
        FFI[ffitrace<br/>dart:ffi tracing]
        SX[strxref<br/>string cross-ref]
        SU[strutil<br/>shared utilities]
        PIPE[pipeline<br/>orchestration]
    end
    TOOLS[tools/<br/>THR extractor]
    GHIDRA[ghidra_scripts/<br/>Python]
    IDA[ida_scripts/<br/>Python]

    CLI --> PIPE
    CLI --> DEC
    CLI --> DISASM
    PIPE --> ELFX
    PIPE --> SNAP
    PIPE --> CLUST
    PIPE --> DISASM
    PIPE --> SIG
    PIPE --> TT
    CLUST --> DART
    CLUST --> SNAP
    DISASM --> DART
    DEC --> DISASM
    TT --> DISASM
    TT --> CLUST
    FFI --> PIPE
    FFI --> DEC
    SX --> PIPE
    SX --> DEC
    FD --> CLUST
    FD --> PIPE
    SM --> DISASM
    FP --> ELFX
    CG --> DISASM
    REND --> CG
    REND --> SIG
```

- `cmd/aotopsy/` — CLI entry point, command handlers
- `internal/` — library packages (21 packages, see ARCHITECTURE.md)
- `tools/` — standalone utilities (THR table extractor)
- `ghidra_scripts/` — Ghidra integration (Python)
- `ida_scripts/` — IDA integration (Python)

## Integration Tests

Set environment variables to enable regression tests:

- `AOTOPSY_TEST_SAMPLE_ARM64` — Dart 3.9.2 ARM64 libapp.so
- `AOTOPSY_TEST_SAMPLE_312_ARM64` — Dart 3.12 ARM64 libapp.so
- `AOTOPSY_TEST_SAMPLE_312_X64` — Dart 3.12 x86_64 libapp.so
- `AOTOPSY_TEST_SAMPLE_DART212` — Dart 2.12.0 ARM64 libapp.so

Tests skip automatically if not set.

## Key Conventions

- `main.go`'s `switch` statement is the source of truth for command dispatch — always check it
- `PoolLookups` (`pipeline.PoolLookups`) is the central name-resolution surface
- PatchClass hop: `OwnerRefID` may point at a PatchClass (CID 6), not the real Class
- `DetectVersion` returns a copy to prevent data races
- `LiftState.Clone` shares Locals by reference (intentional for cross-branch visibility)
