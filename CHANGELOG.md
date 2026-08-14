# Changelog

## Feature Overview

```mermaid
mindmap
  root((AOTopsy))
    Architecture
      ARM64 support
      x86_64 support
      Dart 2.10–3.12
    Decompiler
      Native pseudocode
      IR lift + emit
      Selector hints
      Void call detection
    Type Inference
      Intraprocedural dataflow
      Interprocedural propagation
      5-level type lattice
      BLR receiver resolution
    Naming
      THR-cached stubs
      VM stub names
      Discarded-Code recovery
      Shared stub detection
    Dispatch Table
      Full table parsing
      Code/Stub/Null classification
    Frida
      Script generation
      Indirect-call probes
      Arity-aware hooks
    Signal
      15+ behavioral categories
      Crypto, network, gambling
      SIM, location, WebView
    Tools
      String cross-ref
      FFI tracing
      Fingerprinting
      Function diffing
      Symbol mapping
    Integration
      Ghidra headless
      IDA idalib
      Corpus inventory
      Parity reporting
```

## Features

- **Dual-architecture support** — ARM64 and x86_64, sharing the same snapshot parser front half with separate disassembly backends
- **Dart 2.10–3.12 coverage** — Version-specific layouts verified against `dart-lang/sdk` source at each version tag
- **Native decompiler** — `decompile-native` produces readable pseudocode without Ghidra/IDA, for both architectures
- **Whole-program type inference** — `internal/typetrack` resolves BLR receiver types via intraprocedural dataflow + interprocedural propagation
- **Dispatch table parsing** — Full `DispatchTable` decode with entry classification (Code/Stub/Null)
- **THR-cached stub resolution** — Thread-relative indirect calls resolved to real names using ground-truth offsets from `runtime_offsets_extracted.h`
- **VM stub naming** — VM isolate's stub Code objects named by `VM_STUB_CODE_LIST` creation order
- **Discarded-Code function naming** — Functions whose Code object was discarded are name-recoverable via `Function.CodeIndex`
- **Frida script generation** — `--gen-frida` emits hooks for runtime verification of static analysis results
- **Signal classification** — 15+ behavioral categories: crypto, network, gambling, SIM, location, WebView, blockchain, attribution
- **String cross-referencing** — `_debug strings --find <substring> --xref` finds which functions load a given string
- **FFI call-site tracing** — `_debug ffi-trace` statically finds `dart:ffi` `DynamicLibrary.open`/`.lookup` calls
- **Fingerprinting** — Build-id and Dart/Flutter version marker identification
- **Function diffing** — Function-set diff between two `libapp.so` builds
- **Symbol mapping** — Stripped-vs-unstripped call/branch-target resolution
- **Ghidra/IDA integration** — Headless decompilation with metadata injection (ARM64 only)
- **Corpus tools** — `inventory`, `parity`, batch `find-libapp`, `dart2-buckets`, `thr-audit`/`thr-cluster`/`thr-classify`

## Bug Fixes

- `Code.OwnerRef` x86_64 unreliability fixed project-wide (CodeIndex-based resolution preferred)
- Dispatch table indexing off-by-one (1-based for Dart >=2.16, 0-based for <=2.15)
- Signal classification false positives removed (RefCID check against OneByteString/TwoByteString before quoting)
- x86_64 signal graph edge mapping (call/call_indirect vs bl/blr)
- Dart 2.12.0 string extraction (0 to 8,529 isolate strings)
- Compressed pointer load tracking (BLR resolution 2x improvement)
- `STUR` imm9, `STP`/`LDP` imm7, qualified name lookup fixes
- Memory layout overlap at large sample scale (`UC_ERR_MAP` fix)
- `DetectVersion` returns a copy to prevent data races
- `ParseDispatchTable` caps length against `len(data)*8` to prevent OOM on malformed data
- `ResolveStubRanges` caps `FirstEntryWithCode` at `len(table.Entries)` to prevent panic
- `find-libapp` temp path bug (hardcoded relative `./scratch` → `os.CreateTemp("")`)
- `B.cond` bit mask in typetrack (0x7FFFFF → 0x7FFFF, 23 bits → 19 bits)
- `meetType` preserves `KnownStub` when both stubs are identical
- x86_64 typetrack completeness: stack tracking, field lookup, LEA dispatch, allocation stub detection
- `knownVoidSelectors` removed non-void entries (`IOSink.write()` returns `Future`)
- THR store FFI detection scope: only `vm_tag` field triggers FFI sentinel (was any THR store, 43528 false positives on x86_64)
- ROData payload alignment: `extractRODataPayloads` uses `kObjectAlignmentLog2=4` (was `dataImageAlignment`, conflating base alignment with delta stride)
- `recordFieldStore` unanimity: conflicting field stores drop entry (sentinel -1) instead of first-write-wins
- `funcKindMask` version-keyed decoding: 2.10 had 4-bit mask (should be 5), 2.18 had 5-bit (should be 4) — SDK gate across 22 versions
- VM stub names reversed: image laid out backwards from `VM_STUB_CODE_LIST`, 9 type-testing stubs positioned after Subtype7TestCache
- x86_64 calling convention: was using ARM64's `{R1,R2,R3,R5,R6,R7}` instead of `{RDI,RSI,RDX,RBX,R8,R9}` — parameter 3 seeded into RBP (frame pointer)
- x86_64 compressed-pointer decompression: `ADD RAX, [THR+heap_base]` was killing KnownClass at every field load — now identity on type lattice
- Async detection: `asyncStubRole` shared between `call.go` and `emit.go` (was loose `Contains` in both, independently wrong)
- `invertCondition` regex: `'-()` in character class was a range, negative literals stopped matching
- `replaceIdent` skips string literals to avoid corrupting constants
- `LoadContext` fd leak: `frida_export.go` found as real leaking caller, 7 manual `Close()` → one `defer`
- `readFillInstance` unboxed read: TODO settled against SDK — bitmap IS compressed-word indexed, count locked by `kBitsPerWord/kBitsPerInt32`

## Code Quality

- `.golangci.yml` lint configuration
- `errcheck`, `gofmt`, `goimports`, `gosec`, `staticcheck` findings resolved
- Dead code removed, package doc comments added
- `internal/strutil` shared package replaces three duplicated string-sanitization implementations
- `internal/arch` shared package replaces 7 duplicated x86 register/branch functions across 3 packages (−247 lines)
- `transferInstruction` 860-baris if-chain → 10 handler functions (`intraproc_handlers.go`)
- `readFillRefs` 200-baris scalar if-chain → 6 handler functions (`fill_scalar_handlers.go`)
- `BuildTypeContext` 456-baris monolith → 10 sub-builder functions (`sources_builders.go`)
- `buildFuncIR` 202-baris closure → `funcIRBuilder` struct + `Build` method (`funcir_builder.go`)
- Dead code removed: `retryLoopSynthesis`, `OldArrayFill`/`OldTypeArgsFill`, `isVM` parameter from `extractRODataPayloads`
- Regression tests use environment variable lookups (`AOTOPSY_TEST_SAMPLE_*`) instead of hardcoded paths
- `NOTICE` file for Dart SDK derived-data attribution (BSD-3-Clause compatibility)
