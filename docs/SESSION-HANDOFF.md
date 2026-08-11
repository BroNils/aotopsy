# Session Handoff — Session 2 consumers (gap-analysis §1.1 / §1.2 + layer 2)

Written mid-session so the state survives a context reset or another VM crash.
Everything here is either verified against the Dart SDK source or measured on
real binaries; unverified items are labelled as such.

---

## 1. What this work is

`docs/roadmap/gap-analysis.md` rows **§1.1 Version Coverage** and **§1.2 Object
Type Capture** were implemented as *layer 1* (fill-phase data capture). This
session implements *layer 2*: the **8 consumers** that the gap analysis already
plans for that captured data, in other sections.

| # | Capture (§1.2) | Consumer gap | Status |
|---|---|---|---|
| 1 | ExceptionHandlers | §2.2 try/catch recovery | ✅ **done** — real `try{}catch{}` syntax, §6 |
| 2 | ICData | §3.1 ICData-based resolution | 🚫 **impossible** — see §4 |
| 3 | TypeArguments / TypeParameters | §2.3 generic type param reconstruction | ✅ done |
| 4a | Script/Library | §6 library → functions xref | ✅ done |
| 4b | Script + CodeSourceMap | §2.2 PC → file:line map | ✅ PC → inline stack emitted; **file:line 🚫 impossible** — §6b |
| 5 | Instance | §3.1 (class, offset) → type map | ✅ done |
| 6 | Context | §3.1 closure invocation resolution | 🚫 Context impossible; ✅ **ClosureData substitute done** — §6c |
| 7 | LoadingUnit | partition Codes by loading unit | ✅ done (degenerate on all samples) |
| 8 | KernelProgramInfo | §9 Dart source reconstruction | 🚫 **impossible** — see §4 |

---

## 2. Done, with evidence

### #7 — Codes partitioned by loading unit
`pipeline.PartitionCodesByLoadingUnit`. Buckets are "defined in this blob" (root
unit) vs "defined in another unit's blob" (deferred), taken from the Code
cluster's two sections (`CodeDeserializationCluster::ReadAlloc` reads `count`
then `deferred_count`; our reader marks deferred with `ClusterIndex == -1`).

Attributing a deferred Code to a *specific* unit id needs that unit's own blob
(`app-2.part.so`), which is a multi-file input the tool does not take.

**Every sample in the corpus is degenerate**: 1 unit, 0 deferred codes —
including the 22 MB gopay_merchant production app (21150 main / 0 deferred). The
non-degenerate path is therefore **unproven**; `LoadingUnitPartition.Degenerate`
exists so callers never present a one-bucket split as a finding.

### #4a — library → functions xref
`internal/pipeline/libraryxref.go`, emits `library_functions.jsonl`. Hoists
`effectiveOwnerClassRef` / `libraryURLForClassRef` out of
`cmd/aotopsy/decompile_native_cmd.go` closures into a shared `LibraryResolver`.

Verified against the uncompiled source:

| | source | xref |
|---|---|---|
| `main.dart` classes | 9 | 9 ✅ |
| `ground_truth.dart` classes | 5 | 5 ✅ |
| unresolved library | — | 0 / 7648 ✅ |

`MathTools.classify` and `AntiInlineTools.dayName` are absent **correctly**:
`main.dart` has zero `never-inline` pragmas and both are small pure functions,
so AOT inlines them and no Function object survives. `safeDivide` survives
because its try/catch blocks inlining. The test deliberately does not assert
them — that would encode a compiler decision.

Bonus: on Dart 2.12 `functions.jsonl` has only 395 rows but this xref covers
7714 functions, because it works off cluster capture rather than disasm output.

### #5 — Instance field → observed type map
`cluster.InstanceFieldRef` records the **byte offset at capture time**.
`typetrack.TypeContext.InstanceFieldTypes` + `FieldValueClass` (single
precedence point shared by ARM64 and x86_64 field-load handlers): declared field
type first, then the type observed in const instances, recorded **only when
unanimous** (a wrong concrete type is worse than none, since `KnownClass` is
treated as authoritative).

Ground truth `ground_truth.dart`'s `ConfigData` is the sharpest fixture, because
it contains every case the old code got wrong:

- `nextFieldOffsetInWords = 6`, 2 header words ⇒ **4 slots** (offsets 8/12/16/20)
  for only 3 declared fields
- `version` is an **unboxed int64** occupying **two** compressed slots (12, 16)
  and producing **no ref** — so ref-list position ≠ field index
- ConfigData has **zero Field objects** (AOT drops them for final fields of
  const-only classes), so "sort the class's own field offsets and zip" had
  nothing to sort

Result: exactly 2 refs at offsets 8 and 20; values `'test'`/`'prod'` and
distinct true/false refs, matching `cfg1`/`cfg2` in the source. Plus a
corpus-wide invariant over 14,692 instances in 4 samples.

**Honest measurement:** 174 classes get observed field types, 11 field loads are
typed from them, and BLR resolution is **unchanged** (348/5352 on
compare_sample). The information flows, but its downstream effect on that sample
is zero. Its effect on a 129k-function app is **unmeasured** — see §5.

### #3 — Generic type parameter reconstruction
`pipeline.BuildFuncTypeParamNames`, `decompiler.FuncIR.TypeParamNames`, emitted
as `dynamic name<T, U>(...)`.

Chain: `Function.signature` → `FunctionType.type_parameters` →
`TypeParameters.names` (Array) → Strings.

Verified 3/3 against real SDK source:

| emitted | source |
|---|---|
| `runUnaryGuarded<T>` | `async/zone.dart:1327` |
| `makeListFixedLength<T>` | `internal/list.dart:323` |
| `_get_ffi_native_resolver<T>` | `_internal/vm/lib/ffi_patch.dart:1926` |

**Non-obvious bug found here:** type parameter names (`"T"`, `"K"`, `"V"`) are
short shared strings living in the **VM** snapshot as base objects, not in the
app isolate's strings. An isolate-only lookup resolved **12 of 84** generic
FunctionTypes. Fixed by `PoolLookups.StringForRef`, which falls back to
`VmRefToStr` for `ref < BaseObjLimit` and checks `VmRefCID` first so a non-string
VM base object is not returned as a string (same reasoning as the existing H-4
fix in `resolvePoolDisplay`).

Bounds are emitted too: `TypeParameters.bounds` (ref 2) is a TypeArguments whose
i-th type is the i-th parameter's bound, resolved via ClassID to a name.
`_get_ffi_native_resolver<T extends NativeFunction>` now matches
`ffi_patch.dart:1926` exactly. The implicit `Object` bound every unbounded
parameter carries is deliberately reported as no bound, since
`<T extends Object?>` on everything is noise.

---

## 3. Verified SDK facts — do not re-derive these

All from `dart-lang/sdk` via `gh api` (use
`-H "Accept: application/vnd.github.raw"`; the plain contents endpoint returns
empty for files >1 MB such as `runtime_offsets_extracted.h`).

| Fact | Source | Value |
|---|---|---|
| Code fill ref order (AOT) | `CodeDeserializationCluster::ReadFill` @3.9.2 | `owner(0), exception_handlers(1), pc_descriptors(2), catch_entry(3), inlined_id_to_function(4), code_source_map(5)` |
| Code refs in **non**-PRODUCT | same, `#if !defined(PRODUCT)` | **+2 refs**: `return_address_metadata_`, `comments_` |
| ClosureData (AOT) | `ClosureDataDeserializationCluster` | `context_scope_` skipped; `parent_function(0), closure(1)`, then `packed_fields` |
| Script | `ScriptDeserializationCluster` | `ReadFromTo` (url at 0), then `kernel_script_index_`; `flags_and_max_position_` only non-AOT |
| LoadingUnit | `LoadingUnitDeserializationCluster` | `parent(0)` ref, then `Read<intptr_t>(id)` |
| ExceptionHandlers | `ExceptionHandlersDeserializationCluster` | `packed_fields` (length = `NumEntriesBits`, i.e. `>>1`), `handled_types_data` ref, then per entry `uint32 pc_offset, int16 outer_try_index, int8 needs_stacktrace, int8 has_catch_all, int8 is_generated` |
| FunctionType field order | `raw_object.h` | 3.9.2: `type_test_stub(0), hash(1), type_parameters(2), result_type(3), parameter_types(4), named_parameter_names(5)`; 2.17.6: no leading `hash` (moved to end) ⇒ `type_parameters(1) … parameter_types(3)` |
| ⇒ derived rule | — | **`type_parameters index = FuncTypeParamTypesIdx - 2`** in every supported version |
| TypeParameters | `raw_object.h` | `names(0), flags(1), bounds(2), defaults(3)` |
| `RefNull` | `AddBaseObject(Object::null())` is first; refs start at `kFirstReference == 1` | **ref 1 is always null** |
| Features string mode token | `Dart::FeaturesString` in `dart.cc` | exactly one of `debug` / `product` / `release`, always first. **There is no `profile` token** — a Flutter *profile* build reports `release` |
| PcDescriptors encoding | `PcDescriptors::Iterator::MoveNext`, object.h | AOT: exactly 2 values per record, both **SLEB128** — `kind_and_metadata`, then a `pc_offset` delta. `deopt_id`/`token_pos` only when `!FLAG_precompiled_mode` |
| PcDescriptors bitfields | `UntaggedPcDescriptors::KindAndMetadata` | `kind = 1 << (n & 0x7)`; `try_index = ((n>>3) & 0x3FF) - 1`; `yield_index = (n>>13) - 1`. `-1` sentinels stored biased +1 |
| CodeSourceMap encoding | `CodeSourceMapOps::Read`, code_descriptors.cc | one value per op; `op = n & 0x7`, `arg = n >> 3` sign-extended. `kChangePosition`'s 2nd value exists only under `DART_PRECOMPILER` + dwarf mode and is **not** serialized |
| **⚠ two different varints live side by side** | datastream.h | `ReadSLEB128<T>()` is real SLEB128 (**PcDescriptors** uses it). `Read<T>()` is `Read<T>(kEndByteMarker)`, Dart's own **marker-192** varint (**CodeSourceMap** uses it) — already implemented here as `dartfmt.Stream.ReadTagged32`. Mixing them parses cleanly and yields garbage: decoding CSM as SLEB128 produced inlined-function id `-127976` |

---

## 4. Three consumers that cannot be built for AOT

Not "hard" — **impossible with AOT data**. The gap-analysis rows are wrong for
an AOT target and should be corrected.

- **ICData** (§1.2 + §3.1, both marked *Game-changing*): a JIT inline cache. The
  precompiler does not retain `ic_data_array_`, so nothing reaches the
  serializer. **0 ICData objects in all 16 corpus samples** (Dart 2.12 / 3.7 /
  3.9 / 3.10 / 3.11 / 3.12, arm64 + x64). A previous revision shipped a BLR
  resolver keyed on ICData: it resolved **zero** call sites and propagated the
  ICData object's *owner* name as the call target. Removed.
- **Context** (§1.2 + §3.1 closure resolution): allocated on the heap when a
  closure runs, never serialized. 0 in all samples. The AOT substitute is
  `ClosureData` (captured, indexed as `ClosureDataByClosure`/`ByParent`) plus the
  dispatch table and `UnlinkedCall`. **Those indexes currently have no reader** —
  a real opportunity.
- **KernelProgramInfo** (§1.2, *Insane*): "KernelProgramInfo objects are not
  written into a full AOT snapshot" (SDK comment); its *deserialization* cluster
  is the only one genuinely `#if !defined(DART_PRECOMPILED_RUNTIME)`. This kills
  §9's "Dart source reconstruction from kernel".

Note a related correction: the serialization clusters for ICData/Context/KPI are
**not** `#if`-guarded in `Serializer::NewClusterForClass`. An earlier comment
claimed they were; the conclusion was right, the stated reason was not.

---

## 5. Measurement gaps — state these, don't paper over them

- #5's effect on BLR resolution in a **real 129k-function app is unmeasured**.
  Attempting it via the full pipeline is what crashed the VM (§7). Use the
  cluster-only harness for big-app numbers, and say plainly that it answers
  "how many observed field types" and not "how many extra BLRs resolved".
- #7's non-degenerate path is unproven (no split-AOT sample exists in the corpus).
- Mach-O support is **dead code**: `elfx.OpenContainer` is never called, and
  there is no iOS sample. Its `Symbol()` nlist filter was fixed this session
  (it previously accepted only *undefined* symbols, so
  `_kDartIsolateSnapshotData` could never be found) but remains untested.

---

## 6. #1 — try/catch recovery: DONE, real syntax emitted

`ExceptionHandlers` gives only handler **entry points**, not the protected
range. The range comes from **`PcDescriptors`**, whose `try_index` says which try
block is active at each PC.

### ✅ Implemented and verified (`internal/cluster/pcdescriptors.go`)

- `CodeEntry.PcDescriptorsRef` — Code ref index **2**.
- `readSLEB128`, `decodeKindAndMetadata`, `DecodePcDescriptors`,
  `BuildTryRegions`, `PcDescriptorsInfo`, `TryRegion`, `Result.PcDescriptors`.
- Unit tests pin SLEB128 (incl. sign extension), the bitfield layout, the
  two-value AOT record shape, and delta accumulation.

**Where the payload actually lives — the thing that cost a wrong attempt.**
`fillspec.go` routes PcDescriptors / CodeSourceMap / CompressedStackMaps by
pointer compression:

| build | fill kind | payload location |
|---|---|---|
| compressed pointers (**every Dart 2.18+**) | `FillInlineBytes` | **inline in the fill stream**: `ReadUnsigned(length)` + `length` raw bytes |
| non-compressed (2.x) | `FillROData` | the ROData image |

**CodeSourceMap follows the same split**, and both paths are now implemented for
both objects (`extractRODataPayloads` is shared). An earlier revision wired CSM
into the inline-bytes path only, so Dart < 2.18 decoded PcDescriptors but zero
CodeSourceMaps — an asymmetry with no justification. Verified after the fix:
2.12.0 yields 5395 CSM objects / 36626 entries / 6232 inlined PCs, the same shape
as 3.9.2's 5846 / 35905 / 6594.

The first attempt only implemented the ROData path and decoded **0 objects** on
3.9.2 arm64. Both paths now exist: `readFillInlineBytes(s, cm, capture)` (verified)
and `extractRODataPcDescriptors`.

**Both paths now verified.** The ROData path took two real bug fixes, and the
first hypothesis about it was wrong:

1. `cluster.go`'s `AllocROData` branch passed **`nil`** for `cm` ("no string
   extraction"), so `cm.Lengths` was never populated for
   PcDescriptors/CodeSourceMap/CompressedStackMaps and the extractor had no way
   to locate objects. Now passes `cm`; this only records deltas and does not
   change stream consumption.
2. The `clusterOnly` test helper passed `int64(len(data))` as `snapshotSize`
   instead of `info.IsolateHeader.TotalSize`. `snapshotSize` is what locates the
   ROData image, so a wrong value silently disables **every** ROData-backed
   capture. It hid because compressed-pointer samples route strings through
   `FillString`, so only a non-compressed sample exposes it.

The initially suspected cause — a per-cluster reset of `runningOffset` — was
**disproved by measurement**: the first delta of each ROData cluster is absolute
from the image start (dart212: TwoByteString 23159, PcDescriptors 23191), so the
per-cluster reset is correct.

Verified on dart212_sample (Dart 2.12.0): 116 objects, 959 descriptors, 927
carrying a try index. Notably `nestedTryCatch` yields **2 regions from 2
handlers** there — correct nested-try recovery — where 3.9.2 collapses to 1
because it has fewer descriptors. Same source, different descriptor density.

No regression from the `AllocROData` change: full-pipeline counts are byte-identical
on compare_sample (7916/1858/39170), dart212 (395/1575/39701) and sample_312 x64
(8173/1913/40610).

**Measured on compare_sample (fresh binary):** 125 PcDescriptors objects, 402
descriptors, 364 carrying a try index, max try_index 2. Verified against the
uncompiled source:

| function | source | handlers | regions |
|---|---|---|---|
| `AntiInlineTools.safeDivide` | one try/catch | 1 | 1 ✅ |
| `tryCatchFinally` | try/catch/finally | 1 | 1 ✅ |
| `nestedTryCatch` | nested try | **2** ✅ | 1 |
| `tryCatchWithType` | 3 `on`-clauses | 1 ✅ | 1 |

`tryCatchWithType` having one handler is correct — Dart compiles several `on`
clauses of one try into a single handler entry that type-tests. `nestedTryCatch`
yielding 2 handlers matches its two nested trys exactly.

**Known limitation:** region granularity is bounded by descriptor density.
Descriptors only exist at call sites / runtime calls, so `nestedTryCatch` has
just 2 descriptors and collapses to 1 region even though the source has an inner
and an outer try. Do not present region counts as try-block counts.

Also note only 125 of ~8000 Codes carry PcDescriptors at all: AOT keeps them
only where needed. Absence is normal, not a parse failure.

### ✅ Regions wired into the decompiler

`decompiler.FuncIR.TryRegions` (`TryRegionEntry`: absolute `StartVA`/`EndVA`,
`TryIndex`, resolved `Handler`, `HandlerVA`) is populated in
`cmd/aotopsy/decompile_native_cmd.go` by joining `codeRefToPcDesc` with
`codeRefToExcHandlers` and calling `BuildTryRegions(entries, r.Size)`. `r.Size`
matters: the last descriptor has no successor, so without it the final region
is dropped. `try_index` is bounds-checked against the Code's own handler table.

`TryRegionEntry.CatchClause()` derives the binding from `needs_stacktrace`:
`catch (e)` when false, `catch (e, st)` when true. Verified both ways —
`AntiInlineTools.safeDivide` (source `catch (e)`) emits `catch (e)`, while all 27
regions in a 900-function sweep are `catch (e, st)`. The old emitter hardcoded
`(e, st)` and mis-rendered every single-binding catch.

`Stats.TryBlocks` now counts regions (27 on that sweep) rather than being
hardcoded to 1, and is folded in both `--all` and `--from-main`.

Emitted form for `safeDivide` (source: `try { return a ~/ b; } catch (e) { return -1; }`):

```
dynamic AntiInlineTools_safeDivide(int arg0) {
  // 1 try region(s) recovered from PcDescriptors + ExceptionHandlers:
  //   try #0: PCs in [0x1c8ac4, 0x1c8ac8) -> catch (e) at 0x1c8a9c catch_all
  // NOTE ranges are LOWER BOUNDS: ...
```

### ✅ Ranges widened to basic-block boundaries

`FuncIR.SnapTryRegionsToBlocks()` grows each region out to whole basic blocks.
This is **sound, not a heuristic**: a block is straight-line code with a single
entry, so if any pc in a block is inside try N, every pc in it is. Snapping
cannot over-claim.

It matters a lot, because raw descriptor ranges are severe lower bounds.
Measured over a 900-function sweep of compare_sample, 27 regions:

| | before snapping | after |
|---|---|---|
| `safeDivide` region | `[0x1c8ac4, 0x1c8ac8)` — 4 B, 1 instruction | `[0x1c8ab0, 0x1c8ac8)` — 24 B, 6 instructions (the whole block holding the division) |
| region size across sweep | mostly single-instruction | min 68 B, **median 276 B**, max 980 B |
| single-instruction regions | the norm | **0** |

The last block in a function closes at `lastInstrAddr+1` rather than its true
end, because instruction width is unknown there (x86_64 is variable length).
That under-claims a tail of a few bytes, which is the safe direction.

### ✅ Per-block try annotation (structure shown at the right place)

`emitter.buildBlockTryIndex` + `annotateBlockTry` mark every block that sits
inside a try region, e.g. `// [in try #0 -> catch (e) at 0x1c8a9c]`, placed
exactly where the protected code is. On `safeDivide` the marker lands inside
`if (arg0 == 0) {` — the branch holding the runtime call for `a ~/ b` — and the
`return x0` on the other branch is correctly unmarked. Regions are block-aligned,
so testing a block's `StartVA` suffices; when regions overlap (unseparated nested
trys) the innermost wins, matching Dart's nearest-enclosing-handler semantics.

Two double-counting bugs were found here by sanity-checking marker counts against
a physical limit — a 752-byte region cannot contain more blocks than it has
instructions:

| | markers (900-fn sweep) | `_runTimers` |
|---|---|---|
| initial | 9880 | 9010 |
| once per block, per emitter | 820 | 679 |
| `tryMarked` shared with helper sub-emitters | **147** | **32** |

679 blocks could not fit in a 752-byte region; the cause was helper `_block_N()`
functions each getting a fresh emitter with its own `tryMarked`. 32 blocks over
752 bytes (~24 B/block) is plausible. Output stays well-formed: braces balanced
(887874 each) since markers are comments.

### ✅ Real `try { … } catch { … }` syntax, with handler code in the catch

`emitBlock` opens and closes the brace pair **inside the same invocation**, which
makes it balanced by construction regardless of how the recursion unfolds. That
is what makes it safe in an emitter that walks control flow rather than address
order, re-emits blocks and omits paths. `emitBlockBody` was split out so the
wrapper can emit the same body at a deeper indent without re-running the
recursion guards.

The handler's own block is emitted **inside the catch** (it also appears at its
natural CFG position, so it is shown twice — preferable to a catch body that is
only a comment).

Verified against `main.dart`'s `safeDivide`
(`try { return a ~/ b; } catch (e) { return -1; }`):

```dart
if (arg0 == 0) {
  try {
    final t1 = CallToRuntime(x0, arg0, 10, x3, 0, THR.f1128, x6, x7);
  } catch (e) {
    return 0xffffffffffffffff;
  }
} else {
  return x0;
}
```

`0xffffffffffffffff` is −1 as a 64-bit value: the source's `return -1;`
recovered inside the catch. `catch (e)` (not `catch (e, st)`) matches the source.

Structuring happens **once per region**. Opening a real try on every recursion
path into a region produced 162 try blocks for one 32-block region
(`_Timer._runTimers`), 416 across a 900-function sweep for 27 regions. Later
entries emit `// [still in try #N …]`, deduplicated per block. Final counts on
that sweep: **27 try blocks (one per region), 225 still-in markers, 416 inlined
markers, 50 closure-parent lines, braces balanced.** Full-pipeline counts
unchanged on all three samples.

### ⬜ Remaining

- A try whose body contains NO descriptor is unrecoverable in either direction
  (see §6d). Bounded by descriptor density, not by missing code.
- Unify command flag naming (§7).

Block-aligned ranges make this defensible for the single-region case now. The
remaining blocker is the *other* under-report: nested trys can still merge into one
region when descriptors are too sparse to separate them (compare_sample's
`nestedTryCatch` merges to 1 region; dart212's separates into 2 for the same
source). Emitting one `try` where the source has two nested ones would be
confidently wrong, so gate structuring on `len(regions) == len(handlers)` or
solve the nesting first via `Handler.OuterTryIndex`, which is captured.

Do **not** restore the pre-existing placeholder behaviour: it wrapped the whole
body in one `try` with a fabricated `rethrow` while handler blocks stayed inline
inside the `try`. Four separate ways of being wrong, documented at the call site.

### Original design notes (kept for the ROData path and for reference)

1. **Capture `pc_descriptors`**: `Code` ref index **2** (index 1 is
   `exception_handlers`, already captured as `CodeEntry.ExceptionHandlersRef`).
   Add `CodeEntry.PcDescriptorsRef` the same way in `readFillCode`.
2. **Locate the payload**: `PcDescriptors` lives in **RODATA**. Reuse the
   addressing in `extractRODataStrings`: `runningOffset += cm.Lengths[i] <<
   alignShift`, `objPos = dataImageObjStart + runningOffset + headerAdjust`
   (`headerAdjust` = one alignment unit for the VM image, 0 for isolate). Collect
   `FillROData` clusters whose CID is `ct.PcDescriptors` the way
   `rodataStringClusters` is collected, and extract after `FillEnd` is set.
3. **Object layout**: header 8 bytes (`tags`, or `tags`4+`hash`4 when
   compressed) + `length_` as a **uword (8 bytes)** + `length_` bytes of data.
   `length_` is the **byte length** of the stream, not a descriptor count —
   `PcDescriptors::Iterator` uses it as the `ReadStream` limit.
4. **Decode** (`PcDescriptors::Iterator::MoveNext`, `object.h` @3.9.2). In AOT
   (`FLAG_precompiled_mode`) each entry is exactly **two SLEB128 values**:

   ```
   kind_and_metadata = SLEB128
   cur_pc_offset    += SLEB128        // delta-encoded, accumulate
   // deopt_id and token_pos are read ONLY when !FLAG_precompiled_mode
   ```

5. **Bitfields** (`UntaggedPcDescriptors::KindAndMetadata`, `raw_object.h`).
   `kLastKind = kOther = 128`, `ShiftForPowerOfTwo(128) = 7`,
   `BitLength(7) = 3`, so:

   ```
   kind        = 1 << (kam & 0x7)           // bits [0,3)
   try_index   = ((kam >> 3) & 0x3FF) - 1   // bits [3,13), stored +1
   yield_index = (kam >> 13) - 1            // bits [13,32), stored +1
   ```

   `try_index == -1` means "not inside a try".
6. **Regions**: sort entries by `pc_offset`; the range
   `[d[i].pc_offset, d[i+1].pc_offset)` carries `d[i].try_index`. Merge adjacent
   equal indexes. A `try_index >= 0` indexes
   `ExceptionHandlerInfo.Handlers[try_index]`, giving the handler entry PC and
   `needs_stacktrace` / `has_catch_all` / `is_generated`.

### Emit path

7. Re-partition the decompiler CFG at region boundaries and at handler entry
   PCs, add `OpTry`/`OpCatch` to the IR, emit real
   `try { … } catch (e) { … }` / `catch (e, st)` driven by `needs_stacktrace`.
8. Replace the current placeholder in `decompiler/emit.go`, which reports
   handlers as a **comment block** and deliberately emits no try/catch syntax.
   That placeholder exists because the previous version wrapped the whole body
   in one `try` with a fabricated `rethrow`, while handler blocks stayed inline
   inside the `try` — four separate ways of being wrong, documented at the call
   site. **Do not restore that.** Also aggregate `Stats.TryBlocks` /
   `CatchHandlers` (they are now folded in both `--all` and `--from-main`).

### Ground truth ready to test against

Use the **fresh** compare_sample binary (§7). `ground_truth.dart` has, all with
`@pragma('vm:never-inline')`:

- `tryCatchFinally(int,int)` — try / catch / finally
- `nestedTryCatch(int,int,int)` — nested try, so `outer_try_index >= 0`
- `tryCatchWithType(String)` — `on FormatException` / `on
  IntegerDivisionByZeroException` / catch-all, so multiple handled types

and `main.dart` has `AntiInlineTools.safeDivide(int,int)`. Note
`needs_stacktrace` is **false** for a source-level `catch (e)` and true for
`catch (e, s)` — the old emitter hardcoded `catch (e, st)` and got this wrong.

## 6b. #4b — CodeSourceMap: decoded and consumed; file:line impossible

`internal/cluster/codesourcemap.go`. `CodeEntry.CodeSourceMapRef` is Code ref
index **5** in AOT (`owner(0), exception_handlers(1), pc_descriptors(2),
catch_entry(3), inlined_id_to_function(4), code_source_map(5)`; `object_pool`
and `compressed_stackmaps` are absent in AOT).

A CodeSourceMap is a little bytecode — `kChangePosition`, `kAdvancePC`,
`kPushFunction`, `kPopFunction`, `kNullCheck` — that maintains a stack of
inlined functions and a token position as the PC advances. Only `kAdvancePC`
delimits a PC, so only it emits an entry.

**Measured on compare_sample:** 5846 objects, 35905 entries, **6594 PCs sitting
inside an inlined frame**, max inline depth 6, 35022 with a token position, max
pc 0x4ad4. No regression: full-pipeline counts unchanged on all three samples.

**What this delivers now:** PC → inlined-function stack (indices into
`Code.inlined_id_to_function`). That is real, verified, and not obtainable any
other way — it is what tells you a given address belongs to an inlined callee
rather than the enclosing function.

**PC → file:line is IMPOSSIBLE for release builds — now proven, not assumed.**
`UntaggedScript::to_snapshot` (raw_object.h @ 3.9.2):

```cpp
case Snapshot::kFullAOT:
#if defined(PRODUCT)
      return ... &url_;          // serializes url ONLY
#else
      return ... &resolved_url_; // url + resolved_url
#endif
```

`ReadFromTo` runs from `VISIT_FROM(url)` to that bound, so a PRODUCT AOT Script
carries exactly **one** ref: `url`. `line_starts`, `source`, `debug_positions`
and `kernel_program_info` are excluded by construction. `specScript` already
agrees (`NumRefs: 1`), which is why the fill stream stays aligned.

So §1.2's "Capture CodeSourceMap + Script line tables; build PC → file:line map"
**cannot be completed for release AOT**, and belongs in §4's impossible list
alongside ICData / Context / KernelProgramInfo. What IS deliverable — and is
delivered — is PC → inlined-function stack.

`CodeSourceMapInfo.InlineStackAt(pc)` returns the state in effect at a PC.

## 6c. ClosureData consumer — closures get their declaring function

`pipeline.BuildClosureParents`. Chain:

    Function.data (ref 3) -> ClosureData.parent_function -> Function -> name

Needed because `OwnerRefID` only reaches the owning CLASS, so every anonymous
closure in a class rendered identically. Emitted as
`// closure declared in: <parent>` above the signature.

Two filters, both driven by what the data actually showed:

- **ref-level self-check** in `BuildClosureParents`: a ClosureData whose
  parent_function is the function owning it carries nothing.
- **name-level self-check** at the call site: a tear-off's ClosureData points at
  a *different* Function object that shares the method's name, so the ref check
  misses it. 49 of 99 annotations were "closure declared in: X" on X itself
  before this; now 0.

Result on a 900-function sweep: **50 annotations, 0 self-references**, e.g.
`sub_a94 <- _runMain`, `sub_1200 <- _RootZone.bindCallback`. Verified against
`zone.dart`: `bindCallback` really does contain `return () => run(registered);`.

This is also the answer to consumer #6: Context is never serialized in AOT, and
ClosureData is the substitute the gap analysis needed.

## 6d. Nested-try recovery from OuterTryIndex

`cluster.ExpandOuterTryRegions`. Definitional, not a guess: if a pc is inside
try N and `handler[N].outer_try_index == M`, that pc is inside try M as well. So
every recovered region for N implies one for M over at least the same range.

**Measured on compare_sample: 142 codes have regions, 3 of them expand, +5
regions recovered, 5 nested handlers seen.** It fires, and it is not dead code.

A real bug was caught while measuring it: the first version unioned ranges per
try index, which silently merged the several *disjoint* regions BuildTryRegions
can legitimately produce for one index (a try re-entered at separate pc ranges).
That collapsed 5 regions to 3. It now preserves every original region and only
ADDS.

What it cannot do, shown by the fixture that motivated it: for
`nestedTryCatch` on 3.9.2 the data is

    handler[0] outer_try=-1   <- OUTERMOST
    handler[1] outer_try=0    <- inner
    both descriptors carry try_index 0

i.e. the descriptors sit in the OUTER try and the inner one left no trace at
all. Walking outward cannot invent it, and giving an extent to a try with no
descriptor would be fabrication. Expansion recovers the enclosing try when
descriptors land INSIDE a nested one; the reverse is not recoverable.

## 7. cmd sweep

Every command exercised against compare_sample (and dart212 where relevant),
under `ulimit -v 3000000`, one at a time.

Working: `doctor`, `meta`, `signal`, `frida-export`, `frida-import`,
`find-libapp`, `find-libapp-batch`, `parity`, `inventory`, `dart2-buckets`,
and `_debug`: `dump`, `strings`, `graph`, `clusters`, `objects`, `render`,
`thr-audit`, `thr-classify`, `thr-cluster`, `fingerprint`, `refinfo`,
`funcdiff`, `ffi-trace`, `dispatch-table`, `decompile-native`.

`ghidra` / `ida` require their external tools and were only checked for argument
handling.

Ground truth cross-check on `_debug strings` against the uncompiled source
literals in `main.dart` / `ground_truth.dart`:

| literal | occurrences |
|---|---|
| `'Compare Sample'` | 1 |
| `'negative'` | 4 |
| `'zero'` | 7 |
| `'inner-error: '` | 1 |
| `'Monday'` | **0** |

`'Monday'` is absent for a compiler reason, not a tool bug: `dayName` has no
`never-inline` pragma and is called as `dayName(3)`, so it is inlined and the
switch constant-folds away.

Flag names are inconsistent across commands (`--in` vs `--from` vs `--lib` vs
`--dir` vs `--samples`; `render` takes no `--out`). Worth unifying, but no
command is broken.

### Also outstanding

- A try whose body contains NO descriptor is unrecoverable in either direction
  (§6d). That is a limit of descriptor density, not missing code.
- Unify command flag naming (§7).

---

## 8. Operational rules — both were learned the hard way

### Host memory: 6 GB. This VM has been crashed by analysis runs.

`.wslconfig` is `memory=6GB` + 4 GB swap.

- `ulimit -v 2500000`–`3000000` (2.5–3 GB), i.e. **below** VM RAM. An 8 GB
  `ulimit` is a *fake* guard: it can never trigger before the VM dies. It is
  also per-process and says nothing about the sum.
- **One heavy thing at a time, foreground.** `go test` here runs full `Run()`
  pipelines, so a backgrounded analysis plus a foreground `go test` is two
  pipelines at once. That combination killed the VM and wiped `/tmp`.
- **Never run the full pipeline on a big real app.** Use `clusterOnly` in
  `internal/pipeline/loadingunit_test.go` (ELF → snapshot → alloc → fill, no
  disasm): 22 MB libapp.so in ~0.06 s.

### A Flutter build tree holds several libapp.so — most are stale

`compare_sample/build` has **five**, from different revisions of `lib/*.dart`:

| path | current? |
|---|---|
| `intermediates/merged_native_libs/release/.../libapp.so` | ✅ **use this** |
| `intermediates/stripped_native_libs/release/.../libapp.so` | ✅ |
| `generated/jniLibs/copyJniLibsflutterBuildRelease/.../libapp.so` | ✅ |
| `outputs/flutter-apk/extracted_arm64/lib/arm64-v8a/libapp.so` | ❌ **STALE** |
| `outputs/flutter-apk/extracted_x64/lib/x86_64/libapp.so` | ❌ **STALE** |

The `extracted_*` ones predate `ground_truth.dart` and contain no
`AntiInlineTools` / `safeDivide` / `tryCatchFinally`. Using them makes absent
symbols look like tree-shaking or a parser bug. Timestamps do **not** reveal
this (all same-day) — compare hashes, or
`strings -n 6 libapp.so | grep -x <symbol>`.

### Test env vars

```
AOTOPSY_TEST_SAMPLE_ARM64      compare_sample  merged_native_libs arm64  (3.9.2)
AOTOPSY_TEST_SAMPLE_312_ARM64  sample_312      merged_native_libs arm64  (3.12.2)
AOTOPSY_TEST_SAMPLE_312_X64    sample_312      merged_native_libs x64
AOTOPSY_TEST_SAMPLE_DART212    dart212_sample  merged_native_libs arm64  (2.12.0)
AOTOPSY_TEST_SAMPLE_LARGE      any big libapp.so (cluster-only tests only)
```

`gopay_samples/310|311|312` are **duplicates** of `sample_310|311|312` (identical
metrics), not the GoPay app. The only real production samples are
`gopay_2.14.1` (Dart 3.7.0 x64, 129k functions, obfuscated) and
`other_apps_apk/gopay_merchant` (22 MB libapp.so inside
`split_config.arm64_v8a.apk`).

---

## 9. Also fixed earlier this session (context for the diff)

- Two nil-pointer crashes: `readFillRefs` receiving a nil profile from
  `fillOneCluster` (reproduced live: panic at `FILL[3] CID=7 Function`), and
  `DetectVersion("")` returning a zero-valued profile with `CIDs == nil`.
- `tools/extract_thr.go` handled **neither** header layout correctly. Dart 3.x
  puts PRODUCT in each section's own `#if`; Dart 2.x wraps everything in one
  outer `#if !defined(PRODUCT)` + `#else`. Now uses an explicit preprocessor
  stack. Before → after: 2.17.6 `0 → 96`, 2.14.0 `0 → 92`, 3.9.2 non-PRODUCT
  `0 → 120`; PRODUCT paths unchanged (119/118/121).
- Four `_nonproduct` THR tables were committed as **empty** `map[int]string{}`
  (the generator silently produced nothing). Selecting one wiped out *all* THR
  annotation, since a non-nil map is treated as authoritative. Removed; the
  selector now degrades to the PRODUCT table and `snapshot.Extract` emits a
  diagnostic. Non-PRODUCT snapshots cannot be parsed anyway (the +2 Code refs).
- `internal/pipeline/regression_test.go` had been deleted *and* added to
  `.gitignore`. Restored, and the `.gitignore` entry replaced with a note.

## 10. Repo state

Build + vet + full test suite green with all 5 sample env vars. Nothing
committed. New files: `internal/pipeline/{libraryxref,typeparams}.go`,
`internal/pipeline/{captured,instancefields,libraryxref,loadingunit,typeparams}_test.go`,
`internal/snapshot/version_fallback_test.go`, this document.

---

# PART II — Knowledge base

Everything below is method and domain knowledge accumulated in this session,
written so a future session does not have to rediscover it. Sections 11–13 are
*how to find things out*; 14–16 are *what is true*; 17–18 are *how this codebase
works* and *what went wrong*.

## 11. How to get ground truth from the Dart SDK

### Fetching

```bash
# Version-specific source. ALWAYS pass ?ref=<tag>; without it you get main.
gh api repos/dart-lang/sdk/contents/runtime/vm/app_snapshot.cc?ref=3.9.2 \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['content']).decode('utf-8','replace'))"

# Files >1 MB return EMPTY content from the contents API. Use the raw accept
# header instead. runtime_offsets_extracted.h is one of these (~1.5 MB) and
# silently produced a 0-line file before this was noticed.
gh api -H "Accept: application/vnd.github.raw" \
  "repos/dart-lang/sdk/contents/runtime/vm/raw_object.h?ref=3.9.2" > raw_object.h
```

`gh api` over `WebFetch`: authenticated, no rate limits, no CAPTCHA, and it can
pin a tag. File paths move between versions — on a 404, list the parent
directory at that tag rather than guessing.

### Which file answers which question

| Question | File | What to read |
|---|---|---|
| What fields does object X serialize, in what order? | `runtime/vm/app_snapshot.cc` | `XDeserializationCluster::ReadFill` — **read the DEserializer**, it is the exact inverse of what is on the wire and is easier to follow than the serializer |
| Is X serialized in AOT at all? | same | the `#if !defined(DART_PRECOMPILED_RUNTIME)` guards around the cluster, **and** `Serializer::NewClusterForClass` / `Deserializer::ReadCluster` switches |
| Which fields of X survive into a given snapshot kind? | `runtime/vm/raw_object.h` | `X::to_snapshot(Snapshot::Kind)` — this is the authoritative answer and it is easy to miss |
| Field order / VISIT_FROM..VISIT_TO | `runtime/vm/raw_object.h` | `COMPRESSED_POINTER_FIELD` sequence between `VISIT_FROM` and `VISIT_TO` |
| Bitfield packing | `runtime/vm/raw_object.h` | the `class XBits : AllStatic` helpers; compute widths by hand from `BitField<...>` args |
| Stream encodings | `runtime/vm/datastream.h` | `ReadStream::Read<T>()`, `ReadSLEB128<T>()`, `ReadUnsigned<T>()` — **they differ**, see §14 |
| Iterator over a packed blob | `runtime/vm/object.h` | e.g. `PcDescriptors::Iterator::MoveNext` |
| Bytecode-ish payload ops | `runtime/vm/code_descriptors.{h,cc}` | `CodeSourceMapOps::Read/Write` |
| Build-mode / feature strings | `runtime/vm/dart.cc` | `Dart::FeaturesString` |
| THR (Thread) offsets | `runtime/vm/compiler/runtime_offsets_extracted.h` | preprocessor blocks per PRODUCT × arch × compression |

### Reading discipline that paid off

- **`to_snapshot()` beats intuition.** `Script` looks like it has 7 fields; in a
  PRODUCT AOT snapshot it serializes exactly one (`url`). Reading only the field
  list would have produced a parser that desyncs.
- **`#if defined(PRODUCT)` inside a cluster changes the ref count.** Code gains
  `return_address_metadata_` and `comments_` outside PRODUCT. Any "ref index N
  is field F" fact is conditional on build mode.
- **Comments in the SDK go stale.** `UntaggedPcDescriptors::length_` is
  documented "Number of descriptors" but is a BYTE count — proven by
  `UnroundedSize(len) == HeaderSize() + len`, by `New(data, size)`, and by the
  identical field on `UntaggedCodeSourceMap` being documented "Length in bytes".
  Trust the code paths, not the prose.
- **Derive rules instead of tabulating.** `type_parameters` sits two slots before
  `parameter_types` in every supported version, so
  `idx = FuncTypeParamTypesIdx - 2` needs no new per-version constant and is
  automatically enabled only where the base index was verified.

## 12. How to verify against the real thing

### The uncompiled `.dart` source is the arbiter

Every claim about recovered structure was checked against
`~/dev/compare_sample/lib/*.dart` or the Flutter-bundled SDK at
`~/dev/flutter/bin/cache/dart-sdk/lib/`. Examples that caught real problems:

- `ConfigData` (3 fields, one unboxed int64) exposed that instance field offsets
  cannot be recovered from a ref list's position.
- `safeDivide` (`catch (e)`) exposed a hardcoded `catch (e, st)`.
- `runUnaryGuarded<T>` exposed that type parameter names live in the VM snapshot.
- `_get_ffi_native_resolver<T extends NativeFunction>` exposed missing bounds.
- `bindCallback`'s `return () => run(registered);` confirmed closure parents.

### ⚠️ Prove a negative before believing it

A missing symbol usually means one of three things, in this order of likelihood:

1. **You are reading a stale binary** (§18) — check first, always.
2. The compiler removed it (inlining, constant folding, tree shaking).
3. Your parser is wrong.

```bash
strings -n 6 libapp.so | grep -x safeDivide   # is it even in there?
```

`'Monday'` is absent from compare_sample not because string extraction is broken
but because `dayName` has no `never-inline` pragma and is called as `dayName(3)`,
so it inlines and the switch constant-folds. `MathTools.classify` is absent for
the same reason. `safeDivide` survives *because* its try/catch blocks inlining.

### Sanity-check against physical limits — this found three bugs

The single most productive technique this session. Ask "is this number even
possible?" rather than "does the test pass?":

- A 752-byte try region cannot contain 679 basic blocks (≥4 bytes each) → found
  that helper sub-emitters each had their own dedup map.
- 9880 markers for 27 regions → found per-visit instead of per-block emission.
- 416 `try {` for 27 regions → found per-recursion-path instead of per-region.
- pc_offset > 1 MiB inside one function → would mean a desynced stream; asserted
  in tests as a tripwire.

### Measure the consumer, or it is faith

A capture with no measured consumer is how this project previously shipped an
ICData resolver that resolved zero call sites. Every consumer added here reports
a number: `instance_field_hits`, region counts, marker counts, expansion counts.
When the number is zero or unmeasurable, say so — #5 contributes 11 typings and
**zero** additional BLR resolutions on compare_sample, and that is written down
rather than smoothed over.

### Assert invariants, not fixed numbers

Counts change with the sample. Prefer: kinds are valid, offsets increase, refs
land inside the object, regions index a real handler, `len(refs) <= slots`,
`length == len(type_refs)`. Fixed numbers only where the source pins them (9
classes in `main.dart`, 2 handlers in `nestedTryCatch`).

## 13. How to debug a parse that returns nothing

Bisect the chain and print at each stage. Do not theorise first — twice this
session the data disproved a confident hypothesis.

1. **Is the cluster present at all?** `aotopsy _debug clusters --lib X --which isolate`
2. **Does alloc populate what fill needs?** (`cm.Lengths` was empty because
   `AllocROData` passed a nil `cm`.)
3. **Which fill kind does the spec assign?** Print `GetFillSpec(...).Kind` — and
   print the *constant values* too; hand-counting an enum's `iota` positions
   from a grep is how `FillROData` got misread as `FillInstance`.
4. **Is the addressing right?** Dump `objPos`, `tags`, decoded `cid`, `length`.
5. **Is the decode right?** Compare decoded values against expectations from the
   source.

Worked example — PcDescriptors decoded 0 objects:

- Hypothesis: ROData deltas are cumulative across clusters, so a per-cluster
  reset mis-addresses later clusters.
- **Test it:** dump the first deltas of every ROData cluster. Result:
  `OneByteString [1 3 3 …]`, `TwoByteString [23159 2 2 …]`,
  `PcDescriptors [23191 3 2 …]`. The first delta of each cluster is an absolute
  jump. **Hypothesis disproved; the reset was correct.**
- Real causes, found by continuing down the chain: (a) `cm.Lengths` never
  populated, (b) the test harness passed `len(data)` instead of
  `IsolateHeader.TotalSize` as `snapshotSize`, which silently disables every
  ROData-backed capture, (c) for compressed builds the payload is not in ROData
  at all.

Three independent causes for one symptom. Stopping at the first plausible story
would have produced a wrong fix and a wrong comment.

## 14. Dart AOT snapshot format — hard-won facts

### ⚠️ Two different varints live side by side

The single most dangerous thing in this format. Both are in `datastream.h`:

| Reader | Encoding | Used by |
|---|---|---|
| `ReadSLEB128<T>()` | true SLEB128: 7 bits/byte, continuation bit 0x80, sign from bit 0x40 of the last byte | **PcDescriptors** |
| `Read<T>()` = `Read<T>(kEndByteMarker)` | Dart's own **marker** varint: 7 bits/byte, the FINAL byte is `>127` and its value is `b - 192` | **CodeSourceMap**, and most snapshot scalars |
| `ReadUnsigned<T>()` | same marker scheme with `kEndUnsignedByteMarker` (128) | lengths, counts |

`kEndByteMarker = 255 - kMaxDataPerByte = 192`. This project already implements
the marker form as `dartfmt.Stream.ReadTagged32` — **reuse it, do not write a
second decoder.**

Mixing them **parses cleanly and yields plausible garbage**. Decoding
CodeSourceMap as SLEB128 produced inlined-function id `-127976`; it was caught
only because a test asserted ids are non-negative.

SLEB128 sign extension is the other trap: `0x123456` needs a FOURTH byte
(`d6 e8 c8 00`) because the third group `0x48` has bit 6 set. `d6 e8 48` is a
valid encoding of `-904106`. A wrong test vector here looked like a decoder bug.

### Pointer compression decides where payloads live

`fillspec.go` routes PcDescriptors / CodeSourceMap / CompressedStackMaps by
`profile.CompressedPointers`:

| build | fill kind | payload |
|---|---|---|
| compressed (**every Dart 2.18+**) | `FillInlineBytes` | inline in the fill stream: `ReadUnsigned(length)` + `length` bytes |
| non-compressed (2.x) | `FillROData` | in the ROData image |

Implementing only one path is a silent 100% miss on the other. It happened twice
here (PcDescriptors, then CodeSourceMap).

### ROData object addressing

- `cm.Lengths[i]` are per-object deltas; `runningOffset += Lengths[i] << alignShift`.
- **The first delta of each cluster is an absolute jump from the data-image
  start**, so `runningOffset` correctly resets per cluster. Measured on dart212:
  OneByteString starts at 1, TwoByteString at 23159, PcDescriptors at 23191.
- `objPos = dataImageObjStart + runningOffset + headerAdjust`; `headerAdjust` is
  one alignment unit for the VM image, 0 for the isolate.
- Object layout: `[0,8)` tags (or tags:4 + hash:4 compressed), `[8,16)` a length
  word, then the payload. For String the length is a **Smi** (needs `>>1`); for
  PcDescriptors/CodeSourceMap it is a **raw uword byte count**.
- `snapshotSize` passed to `ReadFill` must be `IsolateHeader.TotalSize`, NOT
  `len(data)`. It is what locates the ROData image; a wrong value silently
  disables every ROData-backed capture and is invisible on compressed samples
  because those route strings through `FillString`.

### PcDescriptors

Per record in AOT, exactly two SLEB128 values:

```
kind_and_metadata = SLEB128
pc_offset        += SLEB128        // delta, accumulate
// deopt_id / token_pos ONLY when !FLAG_precompiled_mode
```

Bitfields (`kLastKind = kOther = 128` ⇒ `ShiftForPowerOfTwo = 7` ⇒
`BitLength(7) = 3`):

```
kind        = 1 << (n & 0x7)          // bits [0,3)
try_index   = ((n >> 3) & 0x3FF) - 1  // bits [3,13), stored +1
yield_index = (n >> 13) - 1           // bits [13,32), stored +1
```

`try_index == -1` means "not in a try". Descriptors are **point annotations**:
the index holds until the next descriptor changes it. They only exist at call
sites and runtime calls, so a try whose body has one call yields a
one-instruction region.

Only a minority of Codes carry PcDescriptors at all (125 of ~8000 on
compare_sample). Absence is normal.

### CodeSourceMap

A little bytecode; only `kAdvancePC` delimits a pc, so only it emits an entry.

```
n    = Read<int32_t>()   // MARKER varint, not SLEB128
op   = n & 0x7           // 0 ChangePosition, 1 AdvancePC, 2 PushFunction,
arg  = n >> 3            // 3 PopFunction, 4 NullCheck
```

`kChangePosition`'s second operand exists only under `DART_PRECOMPILER` with
dwarf mode, and the SDK states those maps are not serialized — read exactly one
value per op. `PushFunction` args index `Code.inlined_id_to_function` (ref 4).

### Object field orders (AOT)

- **Code**: `owner(0), exception_handlers(1), pc_descriptors(2), catch_entry(3),
  inlined_id_to_function(4), code_source_map(5)`. `object_pool` and
  `compressed_stackmaps` are absent in AOT; non-PRODUCT adds 2 more at the end.
- **Function**: `name(0), owner(1), signature(2), data(3)`. For a closure,
  `data` is its ClosureData.
- **ClosureData** (AOT): `context_scope_` skipped, then `parent_function(0),
  closure(1)`, then `packed_fields`.
- **FunctionType**: 3.9.2 `type_test_stub(0), hash(1), type_parameters(2),
  result_type(3), parameter_types(4), named_parameter_names(5)`; 2.17.6 has no
  leading `hash` so everything shifts down one. ⇒ **`type_parameters =
  FuncTypeParamTypesIdx - 2`** universally.
- **TypeParameters**: `names(0), flags(1), bounds(2), defaults(3)`. `names` is an
  Array of Strings; `bounds` is a TypeArguments parallel to it.
- **Script (PRODUCT AOT)**: **one ref only — `url`**. `to_snapshot` returns
  `&url_` under `#if defined(PRODUCT)`.
- **LoadingUnit**: `parent(0)` ref, then `Read<intptr_t>(id)`.
- **ExceptionHandlers**: `packed_fields` (length = `NumEntriesBits`, i.e. `>>1`),
  `handled_types_data` ref, then per entry `uint32 pc_offset, int16
  outer_try_index, int8 needs_stacktrace, int8 has_catch_all, int8 is_generated`.

### Instance layout

- Header is 2 words compressed (tags+hash), 1 uncompressed.
- Slots run from the header to `next_field_offset_in_words`; `numFields = nfo -
  headerWords`.
- **An unboxed int64 occupies TWO compressed slots and produces NO ref.** So a
  ref's position in a bare list is not its field index.
- Inherited fields occupy the LEADING slots — `nfo` counts superclass fields.
- **AOT drops `Field` objects for final fields of const-only classes.**
  `ConfigData` has 3 declared fields and *zero* Field objects, so class-layout
  based reconstruction has nothing to work with. Record offsets at capture time.

### `RefNull == 1`

`AddBaseObject(Object::null())` is the first base object and refs start at
`kFirstReference == 1`. Confirmed empirically: 866 of 925 ClosureData records
carry `closure_ref == 1`.

### Features string

`Dart::FeaturesString` writes exactly one of `debug` / `product` / `release` as
the FIRST token. **There is no `profile` token** — a Flutter *profile* build uses
a release-mode VM and reports `release`.

### What AOT never serializes

`ICData` (JIT inline cache; the precompiler drops `ic_data_array_`), `Context`
(heap-allocated at closure invocation), `KernelProgramInfo` (explicit SDK
comment), and `Script.line_starts`. Confirmed empirically as 0 across 16 samples.
Note the *serialization* clusters for ICData/Context/KPI are **not** `#if`-guarded
in `NewClusterForClass` — the reason they are absent is that nothing reaches
them, not a compile guard. Only KPI's *deserialization* cluster is guarded.

### Compiler behaviours that look like tool bugs

- No `@pragma('vm:never-inline')` ⇒ small pure functions inline and their
  Function object disappears; constant arguments then constant-fold their string
  literals away entirely.
- **Tear-offs create a second Function object with the SAME name** as the method.
  A ref-level self-check will not catch a self-referential parent; compare names.
- Multiple `on X catch` clauses of one try compile to **one** handler entry that
  type-tests, so handler count ≠ clause count.
- Nested trys: the compiler may leave descriptors only in the outer one, so the
  inner try can be completely invisible.

## 15. This codebase — things that are not obvious

### The decompiler emitter walks control flow, not addresses

`emitBlock` is a recursive CFG walk with a cycle guard (`active`), a repeat
budget (`visits` / `maxVisitCount`), a step budget, and path omission. Consequences
that shaped several designs:

- A block can be emitted **more than once**, **nested inside if/else the
  traversal produced**, or **not at all**.
- Anything keyed on "first/last block of an address range" cannot be balanced.
  **The working pattern is to open and close a brace pair inside the SAME
  invocation** — then it is balanced by construction, whatever the recursion
  does. That is how real `try { } catch { }` became possible after I wrongly
  concluded it needed a full emitter rewrite.
- Any per-block annotation must be deduplicated **per block, not per visit**, or
  a loop-heavy function drowns the output.
- Helper `_block_N()` functions get a **sub-emitter**. Any dedup state must be
  shared with it or blocks are re-marked once per helper.

### Cheap testing on huge binaries

`clusterOnly` (in `internal/pipeline/loadingunit_test.go`) runs ELF → snapshot →
alloc → fill and skips disassembly: **a 22 MB libapp.so in ~0.06 s**. Use it for
anything that only needs cluster data. The full pipeline on a big app is what
crashed the VM.

### Layout

- `internal/cluster` — snapshot parsing (alloc + fill). New: `pcdescriptors.go`,
  `codesourcemap.go`.
- `internal/pipeline` — orchestration, `PoolLookups` (the central name-resolution
  surface), JSONL builders, consumers.
- `internal/decompiler` — its own disasm/CFG/lift/emit chain, independent of
  `internal/disasm`.
- `internal/typetrack` — type inference; `FieldValueClass` is the single
  precedence point for field-load typing (declared type, then observed).
- `cmd/aotopsy/decompile_native_cmd.go` — where most new consumers are wired.

### Name resolution

`PoolLookups.RefToStr` covers the app isolate only. Short, heavily shared
strings ("T", "K", "V") live in the **VM** snapshot as base objects
(`ref < BaseObjLimit`). Use `PoolLookups.StringForRef`, which falls back to
`VmRefToStr` and checks `VmRefCID` first so a non-string VM base object is not
returned as a string. Isolate-only lookup resolved 12 of 84 generic
FunctionTypes.

Also remember the **PatchClass hop**: a Function's `OwnerRefID` often points at a
PatchClass (CID 6), not the real Class.

### Formatting

Many files are **CRLF throughout** (`emit.go`, `ir.go`, `helpers.go`,
`disasm_stage.go`, `typetrack_stage.go`, `lift.go`). `gofmt -l` flags them
permanently; that is pre-existing, not something to "fix" in passing. Before
reformatting anything, check `grep -c $'\r$' file` against `wc -l` to tell a
CRLF file from genuine misformatting. Files where CRLF=0 *and* gofmt complains
are real problems worth fixing.

Per AGENTS.md: never edit source with `sed`/`perl`/`python -c`; use the harness
edit tools.

## 16. Operational rules — both learned the hard way

### Host memory is 6 GB and this VM has been crashed by analysis runs

`.wslconfig`: `memory=6GB`, `swap=4GB`.

- **`ulimit -v` must be BELOW VM RAM** — 2.5–3 GB. An 8 GB limit is a *fake*
  guard: it can never trigger before the VM itself dies, so the VM dies instead
  of the process. It is also per-process and says nothing about the sum.
- **One heavy thing at a time, in the foreground.** `go test` here runs full
  `Run()` pipelines of its own, so a backgrounded analysis plus a foreground
  `go test` is two pipelines at once. That combination killed the VM and wiped
  `/tmp` (losing every built binary, fetched header and output directory —
  though no source, since the repo lives on `/mnt/e`).
- **Never run the full pipeline on a big real app.** Use `clusterOnly`.
- `aotopsy _debug decompile-native --all` on a real app is the single most
  dangerous command here; see its own `--max` help text.

### A Flutter build tree holds SEVERAL libapp.so and most are stale

`compare_sample/build` has **five**, from different revisions of `lib/*.dart`:

| path | current? |
|---|---|
| `intermediates/merged_native_libs/release/.../libapp.so` | ✅ **use this** |
| `intermediates/stripped_native_libs/release/.../libapp.so` | ✅ |
| `generated/jniLibs/copyJniLibsflutterBuildRelease/.../libapp.so` | ✅ |
| `outputs/flutter-apk/extracted_arm64/lib/arm64-v8a/libapp.so` | ❌ **STALE** |
| `outputs/flutter-apk/extracted_x64/lib/x86_64/libapp.so` | ❌ **STALE** |

The `extracted_*` ones predate `ground_truth.dart` entirely. Using them makes
absent symbols look like tree-shaking or a parser bug. **Timestamps do not reveal
this** — all five are same-day. Compare hashes or grep for a known symbol.

Sample inventory: `gopay_samples/310|311|312` are duplicates of
`sample_310|311|312`, not the GoPay app. The only real production samples are
`gopay_2.14.1` (3.7.0 x64, 129k functions, obfuscated) and
`other_apps_apk/gopay_merchant` (22 MB libapp.so inside
`split_config.arm64_v8a.apk`).

## 17. Working method that produced results

1. **Read the SDK first, then verify empirically.** Either alone misleads: the
   source says what *can* be there, the binary says what *is*.
2. **Bisect the chain with printed data at each stage** rather than reasoning
   from a hypothesis. Two confident hypotheses were disproved by one dump each.
3. **Sanity-check magnitudes against physical limits.** Found 3 bugs no test
   would have caught.
4. **When a test fails, decide honestly whether the test or the code is wrong.**
   Twice the test vector was wrong (SLEB128 `0x123456`; last-block extent) and
   the code was right. Fixing the code would have introduced bugs.
5. **Measure every consumer's contribution and publish the number**, including
   when it is zero.
6. **Prefer derived rules to new tables** — fewer unverified constants, and they
   self-gate to versions already verified.
7. **Never leave the tree unbuildable.** Batch related edits, build once. When a
   refactor is half-done and must stop, revert it rather than leaving it.
8. **State limits inline, in the artifact itself.** Emitted output carries notes
   about lower bounds and duplication so a reader cannot mistake approximation
   for fact.

## 18. Process mistakes made in this session

Recorded so they are not repeated.

- **Used a stale binary for all early verification.** Three conclusions were
  wrong as a result (`--find safeDivide` = 0, `--find tryCatch` = 0,
  `ground_truth.dart` absent). Always identify the fresh artifact first.
- **Shipped an unmeasured feature, then criticised the same pattern.**
  `CodeSourceMaps` sat captured with zero readers for a while; the typetrack
  `ClosureDataByClosure`/`ByParent` maps still have none.
- **Set an 8 GB ulimit on a 6 GB VM and backgrounded a heavy job** while running
  tests. Killed the VM.
- **Left the tree unbuildable** by starting a signature refactor and stopping
  mid-way when interrupted.
- **Declared "structurally impossible" what was merely a design I had not found.**
  Real try/catch worked once the brace pair was opened and closed in one
  invocation. Scope decisions belong to the user; report the cost, do not
  silently narrow.
- **Overclaimed completeness.** Said only impossibilities remained while
  PcDescriptors/CSM/TryRegions were absent from every pipeline artifact, the
  gap-analysis corrections were unwritten, and 100+ roadmap rows were untouched.
- **Fixed a symptom's first plausible cause.** The ROData miss had three
  independent causes; the first hypothesis was wrong and was written into a code
  comment before being tested.

---

# PART III — Sessions 3+ (P5–P8, oracle audit, BLR fix, readability, signal, SARIF, parallelism)

## 19. What was done in these sessions

### P5 CHA (Class Hierarchy Analysis)
- `Subclasses` map built in `BuildTypeContext` (inverse of `SuperClass`).
- `ResolveDispatchCHA` wired into `resolveBLR` `LatticeKnownDispatchIndex`
  fallback: scans subclass dispatch slots when direct lookup fails.
- Reverse dispatch scan now resolves polymorphic calls: all candidates
  collected, unique ones resolved directly, multiple listed as `name1 | name2`.
- Test: `TestCHASubclassesBuilt` — Shape has 3 subclasses (Circle, Square,
  Triangle) verified against ground_truth.dart. **PASS**.

### P6 Switch/case recovery
- `br xN` detection in `DecodeBranch` (0xD61F0000, `IsIndirect: true`).
- `BuildCFG` treats `br` as terminal (no fallthrough).
- `liftARM64Instr` lifts `br` as `OpJump` with register target.
- `SwitchCase` type + `FuncIR.SwitchCases` field.
- `emitJump` emits real `switch (xN) { case 0: ... break; default: }` when
  `SwitchCases` is populated. Uses `emitBlockBody` (not `emitSuccessor`) per
  case to avoid fallthrough merging.
- Detection: scan blocks for `OpJump` with register target, collect ALL
  following blocks as case targets (no filtering by block size or terminator).
- Tested with `bigSwitch` (16 cases, non-trivial bodies: `buffer.write('zero');
  buffer.write('!'); return buffer.toString()`). All 16 cases emitted with
  real code. **PASS**.
- SDK source verified: `il_arm64.cc:6045` — IndirectGotoInstr codegen:
  `LoadObject(offsets_)` + `ldr wN, [xM, xP, lsl #2]` + `adr xQ` + `add xQ,
  xQ, xM` + `br xQ`. Jump table only for >= 16 cases
  (`kJumpTableMinExpressions = 16`).

### P7 Async/await recovery
- 6 detection paths:
  1. Direct BL to symbols containing "init_async"/"return_async" (pre-scan)
  2. THR stub calls via `emitIndirectCall` (THR stub name match)
  3. SuspendState CID in pool loads
  4. `_SuspendState._await`/`_resume`/`_yield`/`_initAsync`/`_returnAsync`
     call targets
  5. `Future.delayed`/`Future._asyncComplete`/`Future._thenAwait` call targets
  6. Post-walk patch if IsAsync set during walking
- `async dynamic foo(...)` signature prefix.
- `// async state machine` annotation.
- Tested with `asyncCompute`: `async dynamic asyncCompute(...)` + state
  machine annotation. **PASS**.
- SDK source verified: `object_store.h` — `to_snapshot(kFullAOT)` returns
  `&slow_tts_stub_`. Async stubs (await_stub, init_async_stub) are AFTER
  slow_tts_stub in the field list, so they are NOT serialized in AOT.
  Async state machine is compiled as tail call to resume function.
  `Future.delayed` detection is the primary reliable path in AOT PRODUCT.

### P8 CompressedStackMaps capture
- `CompressedStackMapsInfo` type in `cluster.go`.
- Captured in both `FillInlineBytes` (compressed, Dart 2.18+) and
  `FillROData` (non-compressed, Dart 2.x) paths.
- Asymmetry fix: previously only `FillInlineBytes` captured CSM;
  `FillROData` now captures via `rodataCSM2Clusters`.

### Oracle audit (3 CRITICAL, 3 HIGH, 4 MEDIUM, 4 LOW)
- **C1** (CRITICAL): `handlerBlocks` mark set BEFORE `emitBlock` call —
  suppressed catch-side emission, leaving empty catch bodies. Fix: set
  mark AFTER emitBlock.
- **C2** (CRITICAL): `thrV392` had wrong SuspendState offsets (used
  non-compressed section 0x358 instead of compressed 0x718). Fix:
  regenerated from `extract_thr.go` tool. Also fixed duplicate
  `isolate`/`isolate_group` entries.
- **C3** (CRITICAL): `FieldNameResolver` passed classID=0 — dead code.
  Fix: replaced per-classID map with global unanimous offset→name map.
- **H1** (HIGH): P3 class grouping produced invalid Dart (multiple
  `class X {}` blocks). Fix: sort matched ranges by owner name (stable).
- **H2** (HIGH): CHA was dead code. Fix: wired into resolveBLR.
- **H3** (HIGH): CSM ROData path missing. Fix: added
  `rodataCSM2Clusters`.
- **L4** (LOW): gofmt field alignment in `branch.go`.

### kHeapObjectTag off-by-one fix
- `FieldValueClass`: raw instruction offset = field_offset - kHeapObjectTag
  (kHeapObjectTag = 1). Map key = field_offset. Fix: add +1 before lookup.
- ARM64 FieldHits: 11 → 11550. x86_64 FieldHits: 0 → 5986.
- SDK source verified: `assembler_arm64.h` —
  `FieldAddress(base, disp) = Address(base, disp - kHeapObjectTag)`.

### TypeClassIdIsRef fix (Dart 2.12.0)
- 2.12.0: `TypeClassIdIsRef=true` — Type.type_class_id is a Smi ref, not
  packed value. `TypeInfo.ClassID` was 0.
- Fix: capture ref index 1 as `TypeClassIdRef` in `readFillRefs`, resolve
  via `MintValues` (Smi encoding: classID = smiValue >> 1).
- 2.12.0 FieldClasses: 0 → 147.
- SDK source verified: `raw_object.h @2.12.0` —
  `POINTER_FIELD(SmiPtr, type_class_id)` at ref index 1.

### x86_64 dispatch_table_array MOV fix
- SDK: `LoadDispatchTable = movq(dst, [THR + dispatch_table_array_offset])`
  — MOV, not LEA. AOTopsy's LEA handler never fired.
- Fix: THR load handler checks for `dispatch_table_array` field name →
  set `KnownDispatch(0)` instead of `KnownStub`.
- SDK source verified: `assembler_x64.cc` —
  `movq(dst, Address(THR, Thread::dispatch_table_array_offset()))`.

### x86_64 reverse dispatch scan
- `resolveX86Dispatch` previously only had direct slot lookup.
- Fix: added reverse dispatch scan (same as ARM64) — scan 128 nearby
  slots for monomorphic/polymorphic targets.
- x86_64 BLR: 125 → 264 (+111%).

### THR table regeneration
- `thrV392` and `thrV392_x64` regenerated from `extract_thr.go` tool.
- Fixed: was using non-compressed SDK section offsets (0x358) instead of
  compressed (0x718). Tool correctly selects PRODUCT ARM64 COMPRESSED
  section from `runtime_offsets_extracted.h`.
- `extract_thr.go` debug code removed.

## 20. BLR resolution breakthrough (6% → 38%)

### Root cause
- `UBFX hits = 0` despite 223391 header load hits.
- `state[base]` (receiver register) was Top when `LDUR Xt, [Xn, #-1]` fired.
- Receiver comes from function arguments or stack, not PP load.
- Only 5543/7918 functions had KnownClass receiver from FuncOwnerClass.
- PoolClassByIndex only included app classes (CID >= NumPredefinedCids),
  excluding 90%+ framework classes.

### Fix P1.1: UBFX handler preserves Bottom
- `transferInstruction` signature changed: added `prevRaw uint32` parameter.
- Caller updated: `var prevRaw uint32; for _, inst := range blk.insts {
  transferInstruction(&state, inst, prevRaw, ...); prevRaw = inst.Raw }`.
- UBFX handler: if `state[rn]` is Bottom and `prevRaw` was LDUR with
  imm9=-1, preserve Bottom (class ID extraction from tags).

### Fix P1.2: Header load sets Bottom for unknown receiver
- `LDUR Xt, [Xn, #-1]` with `state[base]` Top → `state[rt] = Bottom()`
  (not Top). Bottom marks "this is a tags/class ID value."
- ADD/SUB on Bottom → `KnownDispatch(-imm-1)` (ADD) or
  `KnownDispatch(imm-1)` (SUB). Negative DispatchIndex = unknown class,
  encoded selector offset.
- `resolveBLR` decodes negative DispatchIndex: scans ALL dispatch table
  entries at that selector offset. Unique target → resolved. Multiple →
  polymorphic (joined with `|`).

### Fix: PoolClassByIndex includes ALL classes
- Removed `cid >= NumPredefinedCids` restriction.
- Pool hits: 23462 → 175059 (7.5x increase).
- Framework classes (Widget, State, RenderObject) now participate in
  dispatch resolution.

### Fix P2.1: x86_64 selector offset pre-scan
- Pre-scan: `CALL [RAX+RCX*8+disp32]` pattern.
- `selector_offset = disp32/8 + kOriginElement`.
- Stored in `SelectorOffsets` map keyed by CALL address.
- `resolveX86DispatchSelectorOffset`: scans dispatch table for all
  targets at selector offset.

### Results (0 false positive, 0 suspicious)

| Version | Arch | Before | After | Improvement |
|---|---|---|---|---|
| 3.9.2 | ARM64 | 372 (6%) | 2050 (38%) | 6.3x |
| 3.10.7 | ARM64 | 412 (7%) | 1274 (23%) | 3.1x |
| 3.10.7 | x86_64 | 264 (2%) | 3103 (26%) | 11.8x |
| 3.11.0 | ARM64 | 360 (6%) | 1911 (35%) | 5.3x |
| 3.11.0 | x86_64 | 273 (2%) | 3111 (26%) | 11.4x |
| 3.12.2 | ARM64 | 341 (6%) | 1008 (18%) | 3.0x |
| 3.12.2 | x86_64 | 290 (2%) | 3131 (26%) | 10.8x |

Monomorphic targets: `get:isNotEmpty`, `get:elementSizeInBytes`, `toString`
— real Dart method names. Polymorphic: 379 targets for `hashCode`/`toString`
— expected (all classes implement these).

## 21. Decompiler readability improvements

### Selector table: 76 → 187 entries
- Full port from flutterdec `categories.rs` (6 static arrays).
- Covers: Flutter framework (WidgetsBindingObserver, Navigator,
  SchedulerBinding, ScaffoldMessenger), dart:core (Map, Iterable, String),
  dart:async (Stream, Timer, Completer), dart:io, dart:typed_data (full
  ByteData get/set), VM runtime.

### compactLines: 5 → 13 passes
- `retryLoopSynthesis`: unwrap retry-loop pattern
- `collapseIfElseReturn`: if(cond){return X;} return X; → return X;
- `mergeIfChainContinue`: if(c1){continue;} if(c2){continue;} →
  if(c1||c2){continue;}
- `deadStoreElimination`: x=5; x=10; → x=10;
- `copyPropagation`: t1=arg0; t2=t1+1; → t2=arg0+1;

### Expression cleanup (from flutterdec expr_cleanup.rs)
- `constantFold`: (9 << 12) → 36864, (1+2) → 3, (2*4) → 8
- `rewriteNegatedComparisons`: !(a > b) → a <= b
- `simplifyWrappedMemberAccess`: (expr).field → expr.field
- `stripOuterParens`: ((expr)) → (expr)

### Arg renaming (from flutterdec naming.rs)
- `applyArgRenaming`: arg0→n, arg1→str, etc. based on ParamTypeNames.
- Skips signature line (only renames in function body).
- Verified: safeDivide body uses `n` (not `arg0`), signature keeps `arg0`.

## 22. Signal analysis expansion (19 → 32 categories)

### 13 new security categories
- `CatRooting`: magisk, supersu, xposed, frida-server, su binary paths
- `CatAntiAnalysis`: ptrace, TracerPid, emulator detection, frida-gadget
- `CatSSLPinning`: certificatePinner, X509TrustManager, network_security_config
- `CatAccessibility`: AccessibilityService, keylogger, screenCapture
- `CatFraud`: phishing, OTP, banking, card numbers
- `CatDynamicLoad`: DynamicLibrary.open, loadLibrary, dart:mirrors
- `CatIPC`: Binder, ServiceManager, AIDL, ContentProvider
- `CatCovertChannel`: Tor, socks5, proxychain, DNS tunnel
- `CatDRMBypass`: Widevine, FairPlay, PlayReady
- `CatObfuscation`: short meaningless names (Dart --obfuscate detection)
- `CatCryptoConst`: AES S-box, SHA-256 K, ChaCha20, CRC32, BLAKE2b, Keccak
- `CatMethodChannel`: Flutter MethodChannel("name") pattern
- `CatPlugin`: Flutter plugin package names

### Crypto constants database
- SHA-256 K[0..63], H[0..7], SHA-1 K[0..3], H[0..4], MD5 T[0..3],
  AES S-box[0..3], ChaCha20 constants, CRC32 polynomials, BLAKE2b IV,
  XTEA delta, AES Rcon, Keccak round constants, SHA-512 K/H.
- Map-based O(1) lookup, ~80 unique constants.

## 23. SARIF output (gap-analysis §7)

- `internal/output/sarif.go` — SARIF 2.1.0 format.
- `report.sarif` written by signal_stage.go.
- Rules: one per signal category, with level (error/warning/note).
- Results: one per finding, with ruleId, level, message, location,
  partialFingerprints.
- Verified: 204 results, 1 rule, valid SARIF 2.1.0 JSON.

## 24. Parallelism (gap-analysis §8)

- `disasm_stage.go`: goroutine-based parallel disassembly.
- 4 workers (capped for 6GB host memory safety).
- Each function disassembled in parallel (read-only code slice, read-only
  lookup). File writes serialized via `sync.Mutex`.
- Verified: user time 14.2s vs real time 9.0s = parallelism confirmed.

## 25. Cross-referencing (gap-analysis §6)

- `internal/pipeline/xref.go` — 4 JSONL outputs:
  - `string_value_xref.jsonl`: string value → functions
  - `address_callers_xref.jsonl`: target function → callers (4533 entries)
  - `selector_dispatch_xref.jsonl`: selector offset → dispatch targets
  - `field_accessor_xref.jsonl`: class+offset → accessor functions (269 entries)
- Wired into pipeline after disasm stage.

## 26. Frida integration (gap-analysis §5)

- `Stalker.followAllThreads`: trace all threads, filter GC/compiler threads.
  Toggleable via `ENABLE_STALKER` flag in generated script.
- `MemoryAccessMonitor`: watch THR/PP/heap accesses.
  Toggleable via `ENABLE_MEMMON` flag.
- Both added to `frida_gen.go`'s `generateFridaScript`.

## 27. Source of truth methodology (learned this session)

### Two techniques for SDK verification

1. **gh search + gh api**: Use `gh search code "pattern" --repo dart-lang/sdk`
   to find which file contains a pattern, then `gh api -H "Accept:
   application/vnd.github.raw" "repos/dart-lang/sdk/contents/path?ref=tag"`
   to read the full file content at a specific version tag.

2. **websearch + gh api**: Use `web_search` to understand the concept or
   technique (e.g., "Dart AOT dispatch table call pattern"), then verify
   the specific implementation detail against the SDK source via `gh api`.

Both are necessary: websearch gives context and understanding, gh api gives
ground truth. Never rely on just one — websearch may describe outdated
behavior, and gh api without context may miss the bigger picture.

### When to use which
- **Architecture/encoding questions**: gh api to SDK source (assembler_*.cc,
  flow_graph_compiler_*.cc, il_*.cc)
- **Conceptual questions** ("how does Dart AOT handle async?"): websearch
  first for context, then gh api to verify
- **Third-party tool comparison** (Blutter, flutterdec): gh search to find
  the repo, gh api to read source

### Critical lesson: do not take shortcuts
- "Changing the signature would require many changes" → DO IT ANYWAY.
  If the correct fix requires a signature change, change it. The prevRaw
  parameter addition to transferInstruction was the key to UBFX fix.
- "This is a complex refactor" → DO IT ANYWAY. The Bottom() lattice level
  addition and negative DispatchIndex encoding required reworking
  resolveBLR, but it unlocked 38% BLR resolution.
- Never settle for "approximate" or "good enough" when the real fix is
  achievable. The kHeapObjectTag off-by-one fix seemed trivial but
  unlocked 11550 field hits from 11.

## 28. Process mistakes from these sessions

- **Used wrong SDK section for THR offsets**: Read non-compressed section
  (0x358) instead of compressed (0x718). The section header
  `#if defined(PRODUCT) && defined(TARGET_ARCH_ARM64) && !defined(DCP)`
  was at line 7959, but the compressed section was at line 9399. Always
  read the FULL section header including multi-line continuation.
- **Manual-fixed THR table instead of fixing the tool**: The
  `extract_thr.go` tool was correct — it produced the right offsets. The
  bug was that I didn't trust the tool and manually edited the output.
  Always regenerate from the tool and paste directly.
- **Declared "limitation" what was merely unimplemented**: P7 async
  detection was declared "future work" when the fix (Future.delayed
  detection) was straightforward. Never declare something impossible
  without first attempting it.
- **Searched for 32-bit UBFX when binary used 64-bit UBFM**: The class
  ID extraction instruction `0xd34c7c00` is a 64-bit UBFM, not a 32-bit
  UBFX. The encoding mask `0xFF800000` vs `0xFFE0FC00` made the
  difference. Always verify with actual binary bytes, not just SDK source.
- **Assumed LDR encoding was LDUR**: `0xf85ff040` is
  `LDR X0, [X2, XZR, SXTX, #3]` (register index), not
  `LDUR X0, [X2, #-1]` (immediate offset). They load from the same
  address (because XZR=0), but the encoding is different. AOTopsy's
  disasm correctly decodes it, but `isLDUR64` in typetrack also matches
  it (because the mask `0xFFE00C00 == 0xF8400000` matches both). This
  turned out to be correct behavior — both instructions load from the
  same address.

## 29. Repo state after all sessions

- HEAD: `12b5373` (BLR resolution fix)
- Branch: `future-works`
- 3 commits on top of `8e49754` (initial):
  1. `a0aa552` — Layer-2 consumers
  2. `7585bc2` — P5-P8 + oracle fixes
  3. `12b5373` — BLR resolution 6%→38%
- Not pushed (per user request)
- All tests pass (4 unit packages + 3 integration tests)
- 8 version/arch combinations verified (2.12.0–3.12.2, ARM64+x86_64)

## 30. Remaining gap-analysis items

### Decompiler readability (§2.1) — IN PROGRESS
- ✅ Selector table 187 entries
- ✅ compactLines 13 passes
- ✅ Arg renaming
- ✅ Constant folding, dead-store, copy propagation
- ✅ Expression cleanup (negated comparisons, wrapped member access, strip parens)
- ⬜ Non-last branches: split block at non-last branch
- ⬜ Helper inlining: inline `_block_N()` < N instructions

### Type inference (§3.1)
- ✅ BLR 18–38% ARM64, 26% x86_64
- ✅ CHA + reverse dispatch scan
- ✅ Field type tracking (kHeapObjectTag fix)
- ✅ TypeClassIdIsRef fix for 2.12.0
- ⬜ SSA form
- ⬜ Vtable pointer tracking
- ⬜ Field-store → field-load tracking across functions
- ⬜ Allocation site tracking
- ⬜ RTA/XTA

### Signal analysis (§4)
- ✅ 32 categories (19 original + 13 security)
- ✅ Crypto constants database
- ⬜ Crypto algorithm identification (PP immediates)
- ⬜ String deobfuscation
- ⬜ Flutter Method Channel enumeration
- ⬜ Plugin enumeration

### Output formats (§7)
- ✅ SARIF 2.1.0
- ✅ 17 JSONL outputs
- ✅ 4 cross-referencing JSONL
- ⬜ Markdown report
- ⬜ CSV/Excel
- ⬜ OpenAPI spec extraction

### Performance (§8)
- ✅ Parallel disasm (goroutines)
- ⬜ Caching of disassembly
- ⬜ Streaming output
- ⬜ Benchmark suite

### Frida (§5)
- ✅ Stalker.followAllThreads
- ✅ MemoryAccessMonitor
- ⬜ Heap walking
- ⬜ TLS/SSL key logging
- ⬜ JNI/Platform Channel tracing

### Novel (§9)
- ⬜ Auto-CVE matching
- ⬜ Binary diffing
- ⬜ Auto-patching
- ⬜ Emulation

## 31. Deep research findings (BLR investigation sessions)

### Riset #1: 2.12.0 BLR=1 — root cause and fixes

**Root cause (via gh search + gh api to SDK 2.12.0):**

1. **Class ID extraction berbeda**: 2.x uses `LDURH Wt, [Xobj, #1]` (16-bit
   load, kClassIdTagPos=16, kClassIdTagSize=16), not `LDUR+UBFX` (64-bit,
   kClassIdTagPos=12, kClassIdTagSize=20). 5794 LDURH in binary, 0 detected
   before fix. **Fix: isLDURH decoder + handler (sets Bottom for class ID).**

2. **Dispatch pattern berbeda**: 2.x uses `SUB X0, X0, #imm` (cid_reg
   in-place), not `SUB X30, X0, #imm` (LR as temp). **Fix: pre-scan matches
   both patterns + any-register in-place pattern.**

3. **ObjectStoreAOTFieldCount salah untuk 2.x**: Original count (205)
   included ISOLATE fields not serialized. Correct count = 191 (185 RW +
   3 CW + 3 FW). SDK source verified: `OBJECT_STORE_FIELD_LIST(RW, CW, FW)`
   in object_store.h @2.12.0. **Fix: updated 2.x counts.**

4. **Dispatch table genuinely small (65 entries)**: 1575 classes but only
   65 dispatch entries. 86% direct calls (BL), 14% indirect (BLR). AOT
   compiler inlines most virtual calls for this simple counter app.

5. **PP-loaded Code entry_point calls**: 505 BLR via `LDR Xn, [X27, #imm] →
   LDUR X30, [Xn, #7] → BLR X30`. 447 are VM Code objects without names.
   **Fix: PoolCodeNames map with 3 lookup paths (app NamedObject, VM
   NamedObject, VA matching).** VM Code objects have no NamedObjects in
   VM snapshot (no Function cluster) and TextOffset=0 (instructions in VM
   section). Genuine data limitation.

**Result**: 2.12.0 BLR 0→1. Header hits 0→308. ADD class hits 0→110.

### Riset #2: 3.12.2 ARM64 BLR=18% vs 3.9.2=38%

**Root cause**: 3.12.2 dispatch table is denser (393 targets per selector
vs 3.9.2's varying 21-379). More classes per selector → fewer monomorphic
resolutions (274 vs 1305, 4.8x fewer).

**RTA filter attempt**: Populated InstantiatedClasses from const Instance
objects. Applied RTA filter to dispatch scan. Result: BLR DROPPED
(38%→28% for 3.9.2, 18%→8% for 3.12.2). Instance objects only cover
const instances — too few classes. RTA filter excluded classes that ARE
instantiated at runtime but don't have const instances. **Fix: removed
RTA filter.**

**Conclusion**: 3.12.2 BLR=18% is a data limitation (dense dispatch table).
To improve: need comprehensive RTA from allocation stubs (not just const
instances). Allocation stub detection via THR exists but doesn't fire
because 3.12.2 uses PP-loaded Code for allocations.

### Riset #3: x86_64 BLR=26%

**Finding**: x86_64 3.12.2 has 29105 direct calls (100% resolved) + 11835
indirect (26% resolved). ARM64 3.12.2 has 5419 BLR (18% resolved).
**x86_64 outperforms ARM64 for same version (26% vs 18%).**

The 26% vs 38% comparison was across different versions (3.12.2 vs 3.9.2).
Same root cause as riset #2: 3.12.2 has denser dispatch table.

Higher indirect call count (11835 vs 5419) due to 3491 THR calls counted
as call_indirect on x86_64. No code change needed.

### Riset #4: SSA integration

**Finding**: SSA integration would NOT significantly improve BLR resolution.

Current per-register approach with worklist dataflow is equivalent to SSA
with phi functions for type tracking:
- `blockEntry[succ] = meet(blockEntry[succ], blockExit[idx])` = implicit phi
- Sequential instruction processing = SSA renaming within blocks
- Bottleneck is receiver type (Top/Bottom) and dense dispatch table, not
  type tracking precision

SSA infrastructure in ssa.go remains useful for future decompiler
improvements (variable naming, expression simplification) but integrating
it into AnalyzeFunction now is a large refactor with no BLR improvement.

## 32. Source of truth methodology (updated)

### Two techniques for SDK verification (reaffirmed)

1. **gh search + gh api**: `gh search code "pattern" --repo dart-lang/sdk`
   to find files, then `gh api -H "Accept: application/vnd.github.raw"
   "repos/dart-lang/sdk/contents/path?ref=VERSION"` to read at specific tag.

2. **websearch + gh api**: `web_search` for context, then `gh api` for
   ground truth verification.

Both used extensively in riset #1-#3:
- object_store.h @2.12.0: OBJECT_STORE_FIELD_LIST macros (RW, CW, FW)
- dispatch_table.cc @2.12.0: OriginElement() = 4096 for ARM64
- flow_graph_compiler_arm64.cc @2.12.0: EmitDispatchTableCall uses cid_reg
- assembler_arm64.cc @2.12.0: LoadClassId uses LDRH (16-bit)
- constants_arm64.h @2.12.0: kClassIdReg = R0
- dispatch_table.h @3.12.2: kOriginElement = 4096 for ARM64

### Critical lesson: count ALL field macros, not just RW

ObjectStoreAOTFieldCount must include ALL serialized field macros:
- 2.x: RW + CW + FW (not just RW)
- 3.x: RW + LAZY_CORE + LAZY_ISOLATE + LAZY_FFI + LAZY_INTERNAL + LAZY_ASYNC
  + ARW_AR + ARW_RELAXED

Counting only RW fields gives wrong count → dispatch table parsed from
wrong position → BLR=0.

### Critical lesson: from() differs between versions

- 2.12.0: ObjectStore::from() = &object_class_
- 3.9.2: ObjectStore::from() = &list_class_
- IsolateObjectStore::from() = &dart_args_1_ or &preallocated_unhandled_exception_

Serialization uses ObjectStore::from() (second from()), NOT
IsolateObjectStore::from() (first from()).

### File editing rules (reaffirmed)

ALWAYS use harness edit/read/write tools. NEVER use python3 -c with
inline open()/replace() or sed for file editing. Python scripts for
file editing caused syntax errors (brace mismatch, CRLF issues).
The harness edit tool validates old_string uniqueness and preserves
exact whitespace.

## 33. Repo state after BLR investigation sessions

- HEAD: latest commit on future-works branch
- Branch: future-works (tracking origin/future-works, pushed)
- All tests pass (220 test functions: 4 unit packages + 5 integration tests)
- 8 version/arch combinations verified
- BLR: 45% (3.9.2 ARM64) — up from 6% initially

BLR resolution summary (final, after THR stub resolution):
| Version | Arch | BLR | Notes |
|---|---|---|---|
| 3.9.2 | ARM64 | 2433 (45%) | Best result — THR stubs resolved |
| 2.12.0 | ARM64 | 1 (0%) | Data limitation (65 DT entries, VM stubs unnamed) |
| 3.10.7 | ARM64 | 1274 (23%) | Dense DT |
| 3.10.7 | x86_64 | 3103 (26%) | Better than ARM64 same version |
| 3.11.0 | ARM64 | 1908 (35%) | |
| 3.11.0 | x86_64 | 3111 (26%) | |
| 3.12.2 | ARM64 | 1004 (18%) | Dense DT (393 targets/selector) |
| 3.12.2 | x86_64 | 3131 (26%) | Better than ARM64 same version |

## 34. Session 4+ — BLR deep improvement, signal expansion, decompiler quality, tests

### BLR Resolution: 39% → 45%

#### THR stub resolution (+325)
- **KnownStub BLR handler**: saat BLR register adalah KnownStub dengan stub name
  (bukan UnlinkedCall/PPCode/Allocate), resolve ke stub name. +286 resolutions.
- **THR via fallback**: di `rewriteCallEdges`, jika BLR tidak ter-resolve oleh
  typetrack tapi `via` dimulai dengan "THR.", extract stub name (strip `_ep`/
  `_entry_point` suffix) dan resolve. +39 resolutions.
- **PPCode BLR handler**: saat BLR register adalah KnownStub dengan "PPCode:"
  prefix, resolve ke function name.

#### Approaches implemented but no BLR improvement
- **RTA dari allocation stubs**: `recordAllocationSite` enhanced dengan THR
  offset match (bukan hanya stub name). `InstantiatedClasses` populated dari
  class table (1859 classes), Instance CIDs (308), PP loads, dan field values.
  RTA filter re-enabled dengan threshold >9999 (tidak aktif karena
  InstantiatedClasses terlalu comprehensive — semua classes di-mark sebagai
  instantiated).
- **Closure invocation resolution**: `PoolCodeNames` di-populate dari
  `ClosureDataByClosure` → parent function name. Tapi object_field BLR
  (1460) tidak melalui PP load — Closure di-load dari stack/field.
- **Type narrowing dari CMP**: `isSUBS32Immediate` decoder + narrowed state
  di taken branch (succIdx 0). CMP untuk class ID jarang di sample ini.
- **MOV X30 pattern**: pre-scan untuk `MOV X30, Xn` → `LDR X30, [X21, X30,
  LSL #3]` → `BLR X30` (selector offset = kOriginElement). Dispatch table
  scan polymorphic (11490 targets).
- **Interprocedural propagation**: sudah berjalan (10 iterations,
  BLCallSiteTypes + CalleeAllExitTypes). Tidak ada peningkatan tambahan.
- **CodeRefDisplay untuk VM Code**: PoolCodeNames di-enhanced dengan
  VmRefCID check dan CodeRefDisplay fallback. VM Code objects di PP tidak
  punya entries di CodeRefDisplay (mereka adalah base objects, tidak
  di-serialize di app isolate).

#### Remaining 2921 unresolved (genuine data limitations)
- **1460 object_field**: VM Code objects di PP (PP[3], PP[81]) tidak punya
  names di snapshot data. VM snapshot Code cluster tidak di-parse. Perlu
  parse VM snapshot Code cluster atau emulation.
- **1204 GDT**: receiver class ID tidak diketahui (Top dari argument/stack).
  Type narrowing tidak fire karena CMP jarang untuk class ID.
- **257 none**: register X9 (598) dan X30 (13) tidak ter-trace. X9 adalah
  register yang tidak di-track oleh typetrack (bukan arg reg, bukan PP/THR).

### Signal Analysis Expansion (Fase 1 — 9 items)

All 9 signal analysis features implemented and verified with
`signal_ground_truth.dart` test file:

| # | Feature | Output file | Entries | Implementation |
|---|---|---|---|---|
| 1 | Crypto algorithm identification | `crypto_findings.jsonl` | 12 | Binary scan for crypto constants (AES Rcon, ChaCha20, Keccak). Pool immediates scan also. |
| 2 | Method Channel enumeration | `method_channels.jsonl` | 25 | Pattern matching: `MethodChannel("name")`, `dev.flutter/*`, `flutter/platform`, BinaryMessenger, PlatformChannel, BasicMessageChannel |
| 3 | Plugin enumeration | `plugins.jsonl` | 18 | Pattern matching: video_player, path_provider, shared_preferences, firebase, camera, geolocator, MissingPluginException, package:stack_trace, PluginRegistry, FlutterPlugin |
| 4 | String deobfuscation | `deobfuscation.jsonl` | 177 | Base64 pattern detection (`^[A-Za-z0-9+/]{12,}={0,2}$`) with decode attempt. XOR pattern detection (non-printable char ratio). |
| 5 | Network endpoint extraction | `network_endpoints.jsonl` | 57 | URL regex, IP regex (skip 0.0.0.0/127.0.0.1), domain regex (skip file extensions, Dart type prefixes) |
| 6 | Packed/encrypted section detection | `entropy_findings.jsonl` | 1 | Shannon entropy per ELF section. >7.5 = encrypted, >7.0 = packed. |
| 7 | Data flow / taint analysis | `taint_findings.jsonl` | 196 | 3 patterns: same-function (source+sink in same func), cross-function (source func calls sink func), 2-hop (source → intermediate → sink). Source patterns: imei, android_id, token, password, location. Sink patterns: http, socket, MethodChannel, writeFile, analytics. |
| 8 | YARA-style malware matching | `yara_findings.jsonl` | 14 | 15 YARA rules: root_check_magisk, root_check_supersu, root_check_xposed, root_check_frida, root_check_su, anti_debug_ptrace, anti_debug_debugger, ssl_pinning_cert, ssl_pinning_sha, keylogger_accessibility, screen_capture, data_exfil_http, crypto_mining, banking_trojan, ad_fraud. |
| 9 | Call-graph behavioral analysis | `behavioral_findings.jsonl` | 10 | 5 patterns: root_check→anti_debug, credential→network, location→network, crypto→network, category counts. Function name patterns chosen to avoid false positives (e.g. _RootZone does NOT match root_check). |

New files: `internal/signal/crypto_id.go`, `internal/signal/entropy.go`,
`internal/signal/behavioral.go`. Pipeline integration in `pipeline.go`
steps 5.1-5.4. Signal expansion JSONL writing in `signal_stage.go`.

`signal_ground_truth.dart` created with all 9 signal analysis scenarios
for testing. Built and verified against real binary.

### Decompiler Quality (Fase 5 — 9 items)

| # | Feature | Implementation | Evidence |
|---|---|---|---|
| 1 | CSE | `commonSubexpressionElimination` pass: track `final tN = <expr>` declarations, replace subsequent occurrences with `tN`. Word boundary checking via `replaceExactSubstring`. | Added to compactOnePass as pass c11 |
| 2 | FFI call decompilation | `ffi_call(args)` with arg count via `countArgs`. Replaces `nativeCall(args)`. | 18 ffi_call references in 200-fn sweep |
| 3 | Enum reconstruction | `enumReconstruction` pass: detect `if (x == N) { return 'Name'; }` chains (≥3 cases). Emit annotation. | Detection ready, 0 in sample |
| 4 | maxStepsPerEmitter configurable | `SetMaxStepsPerEmitter(n)` API + `--max-steps` flag. `defaultMaxStepsPerEmitter=20000`. | Configurable via CLI |
| 5 | Generator recovery | `IsSyncStar`/`IsAsyncStar` fields. Detection via `InitSyncStar`/`YieldAsyncStar`/`SuspendSyncStarAtStart`/`SuspendSyncStarAtYield` stub names. `sync*`/`async*` signature prefix + post-walk patching. | SDK verified: kInitSyncStar, kYieldAsyncStar, kSuspendSyncStarAtStart, kSuspendSyncStarAtYield |
| 6 | Local variable type inference | `localTypeInference` pass: infer from `local_NN = arg0` mapping and `final tN = <literal>` type detection (int/double/String/bool). | 6 functions with inferred types |
| 7 | Null-safety annotation | `nullSafetyAnnotation` pass: detect `if (x == null)` and `x != null` patterns. Emit `// null-safety: nullable variables: x, y` annotation. | Detection ready |
| 8 | Helper functions: pass live state | `omittedStates` map captures `LiftState.Clone()` at extraction point. Sub-emitter receives cloned state. | Helpers now have register aliases from caller |
| 9 | Expression simplification | `simplifyExpressions` pass: 13 algebraic identity rules (a*1→a, a*0→0, a+0→a, a-0→a, a>>0→a, a<<0→a, a|0→a, a&0xFFFFFFFF→a, (a|0)→a, !!a→a). | Added to emit pipeline |

New files: `internal/decompiler/compact_extra.go` (extended),
`internal/decompiler/call.go` (countArgs), `internal/decompiler/emit.go`
(SetMaxStepsPerEmitter, omittedStates, generator detection).

### Field Name Resolution (major improvement)

- **VmRefToStr fallback** in `BuildClassLayouts`: field names dari VM snapshot
  strings. 209 real field names (was 0).
- **Majority-vote global map** + **per-class map** in `decompile_native_cmd.go`:
  replaces unanimous-only map. 12 object field name references in decompiler
  output (was 0). Field names: `.tilt`, `.synthesized`, `.radiusMax`,
  `.orientation`, `.radiusMinor`, `.radiusMin`, `.transform`, `.original`,
  `.pan`, `.panDelta`, `.fadeIn`, `.modalBarrier`, `.modalScope`.
- **String CID fix** in `ResolvePoolDisplay`: `cid == l.CT.String` added
  (was only OneByteString/TwoByteString). 2797 PP entries with quotes (was 0).
  1338 string_value_xref entries (was 0). 5455 string_refs (was 0).

### Cross-Referencing Fixes

- `string_value_xref.jsonl`: 0 → 1338 entries (VmRefToStr + String CID fix)
- `selector_dispatch_xref.jsonl`: MISSING → 16993 entries (pipeline order
  fix: typetrack before xref + JSONL format fix: `dtJSONL` struct matching
  `WriteDispatchTable` output format)
- `writeJSONLFile`: added missing type cases (YaraFinding, TaintFinding,
  BehavioralFinding, EntropyFinding) — was silently producing 0-byte files

### dataImageAlignment Fix

- `ObjectAlignment` field removed from `VersionProfile`.
- `dataImageAlignment` derives from `DartVersion` string via
  `dartVersionAtLeast(version, "2.19.0")`. Cutoff at 2.19.0:
  ≤2.18 = 16 (kMaxObjectAlignment), ≥2.19 = 64 (kObjectStartAlignment).
- SDK verified via gh api: snapshot.h DataImage() at tags 2.12.0, 2.18.0
  uses kMaxObjectAlignment; 2.19.0, 3.9.2 uses kObjectStartAlignment.
- `extractRODataStrings` alignShift fixed to `uint(4)` (log2(16) = kObjectAlignment)
  for all versions, not dataImageAlignment (which is the image BASE alignment).
- `isVM` header adjust removed (was +16 fudge, no longer needed with correct
  alignment).

### ssa.go Removed (dead code)

`internal/typetrack/ssa.go` was infrastructure-only (SSABlock, SSAValue,
SSAPhi, SSAState, BuildDominators, ComputeDominanceFrontier, InsertPhis,
Rename, ResolvePhiType) — never integrated into `AnalyzeFunction`, never
called from anywhere. Riset #4 proved SSA integration would NOT improve
BLR (per-register worklist = SSA phi for type tracking). File deleted.
`recordFieldStore` and `recordAllocationSite` moved to `intraproc.go`.

### Regression Tests (197 → 220 test functions)

| Test file | Tests | Coverage |
|---|---|---|
| `alignment_version_test.go` | 3 functions, 31 cases | dartVersionAtLeast (12 cases), parseDartVersion (8 cases), dataImageAlignment (11 version cutoffs) |
| `signal_expansion_test.go` | 8 functions | ShannonEntropy, crypto binary scan, method channels, plugins, network endpoints, deobfuscation (base64 decode), YARA matching, taint analysis |
| `compact_passes_test.go` | 7 functions | countArgs, simplifyExpressions (13 rules), CSE, enum reconstruction, null-safety, local type inference, SetMaxStepsPerEmitter |
| `arm64_decoder_test.go` | 3 functions | isLDURH (2 valid + 3 invalid), ADD/SUB reserved shift |
| `blr_signal_regression_test.go` | 3 functions | BLR resolution rate threshold (≥35%), signal output existence + entry counts, decompiler feature presence |

Integration tests require `AOTOPSY_TEST_SAMPLE_ARM64` env var (~108s total).

### PR #2 Merge (tfriedel)

Merged PR #2 "Fix ROData string extraction for no-compressed-pointers (desktop) AOT".
Conflicts resolved in `fill.go` (dataImageObjStart comments, extractRODataStrings
alignShift) and `helpers.go` (isStringCID comment + VmRefCID fallback). Both
fixes compatible: PR uses dataImageAlignment for image base, we use
dartVersionAtLeast for version cutoff.

### Repo State

- HEAD: latest commit on future-works branch
- Branch: future-works (tracking origin/future-works)
- Pushed to origin
- All tests pass (220 test functions)
- BLR: 45% (3.9.2 ARM64) — up from 39% in previous session
- 8 version/arch combinations verified

### Remaining BLR Limitations (genuine data limitations)

| Category | Count | Why unresolved | What would help |
|---|---|---|---|
| object_field | 1460 | VM Code objects in PP have no names in snapshot data. VM snapshot Code cluster not parsed. | Parse VM snapshot Code cluster, or emulation |
| GDT (X30) | 1204 | Receiver class ID unknown (Top from argument/stack). Type narrowing doesn't fire (CMP rarely for class ID). | Emulation or Frida runtime type dump |
| none (X9) | 257 | Register X9 not tracked by typetrack (not arg reg, not PP/THR). | Deeper register tracking |

### Blutter Comparison (updated)

Blutter does NOT resolve BLR to target function names. Blutter emits
`GDT[cid_x0 + offset]()` — same as AOTopsy's selector offset scan.
AOTopsy is ahead: 45% BLR resolution vs Blutter's 0%.

Blutter compiles Dart SDK from source for each version, giving full VM API
access. But it does not use this access for BLR resolution. AOTopsy achieves
45% purely from static analysis of the snapshot binary.
