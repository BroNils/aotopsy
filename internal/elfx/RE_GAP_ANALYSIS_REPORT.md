# RE Gap Analysis Report: internal/elfx

> **STATUS VERIFIKASI (2026-09-01)** — semua 11 gap CONFIRMED. Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`. API `elfx.File` memang
> hanya `Open/Close/FileSize/IsARM64/Symbol/VAToFileOffset/ReadAt/
> ReadBytesAtVA/LoadSegments/ByteOrder/Is64bit/FuncSymbols` — tidak ada
> `Sections()`, BSS, eh_frame, atau build-id; simbol yang dicari
> `snapshot.go:17-35` memang hanya 5+2 dan tak satupun `_kDart*SnapshotBss`.
> Satu perhalusan: klaim "Incomplete #2 — `VAToFileOffset` silent wrong answer
> untuk BSS" — ada guard `offset >= f.size` yang mengembalikan error; yang
> tersisa salah-diam hanyalah VA di `[Vaddr+Filesz, Vaddr+Memsz)` yang
> offset-nya masih di dalam file.

## Ringkasan

Folder `internal/elfx` berisi 4 file Go (`elfx.go`, `funcsyms.go`, `macho.go`, `elfx_test.go`) yang menyediakan abstraction loading ELF (dan Mach-O via `Container` interface) untuk Dart AOT `libapp.so`. Layer ini adalah pintu masuk seluruh pipeline AOTopsy: `Open` → `Symbol` → `VAToFileOffset` → `ReadBytesAtVA`.

Verifikasi terhadap Dart SDK (`dart-lang/sdk` @ tag 3.13.0, 3.12.2, 2.19.0 via `gh api` + grep MCP) menemukan **11 gap RE-signifikan**:

1. **Simbol BSS (`_kDartSnapshotBss` / `_kDartVmSnapshotBss` / `_kDartIsolateSnapshotBss`) tidak ditrack sama sekali** di semua versi Dart. BSS berisi relocation table (function pointers ke VM runtime) yang RE-critical.
2. **Text-section Image header (`UntaggedInstructionsSection`) tidak diparse** — berisi `bss_offset_`, `instructions_relocated_address_`, `build_id_offset_`, `payload_length_`, `image_size`. Ini adalah metadata RE kritis yang tertanam di awal `.text`.
3. **Section table ELF tidak diexpose** — `elfx.File` hanya expose `LoadSegments()`, tidak ada API untuk enumerate sections. Padahal Dart ELF punya `.note.gnu.build-id`, `.eh_frame`, `.dynsym`, `.dynstr`, `.hash`, `.dynamic`, `.rodata`, `.bss`, `.text`, dan (unstripped) `.debug_*`.
4. **`.eh_frame` (DWARF CFI) tidak diparse** — ada di production stripped builds, berisi frame unwind info (FDE/CIE) yang RE-useful untuk stack reconstruction & verifikasi call graph.
5. **Build-ID note parsing tidak ada di `elfx`** — hanya ada di package terpisah `internal/fingerprint`, tidak terintegrasi; `elfx` tidak expose build-id padahal ini adalah fingerprint utama Dart AOT snapshot.
6. **PT_NOTE / PT_DYNAMIC / PT_PHDR / PT_GNU_STACK segment tidak diexpose** — hanya `PT_LOAD` yang ditrack via `LoadSegments()`. PT_NOTE berisi build-id segment; segment lain berguna untuk validasi struktur.
7. **Mach-O `LC_DYSYMTAB` tidak diparse** — didefinisikan sebagai konstanta tapi tidak dibaca. Dart Mach-O loader (`macho_loader.cc`) menggunakan `iextdefsym`/`nextdefsym` dari LC_DYSYMTAB untuk menemukan exported symbols; AOTopsy `macho.go` malah scan semua simbol termasuk stab/local → potensi false match.
8. **Mach-O `LC_UUID` tidak diparse** — equivalent build-id di Mach-O (128-bit hash dari text+data). Konstanta didefinisikan tapi tidak dibaca.
9. **Mach-O `LC_CODE_SIGNATURE` / `LC_LOAD_DYLIB` / `LC_ID_DYLIB` / `LC_RPATH` tidak diparse** — `LC_LOAD_DYLIB`/`LC_ID_DYLIB` didefinisikan tapi tidak dibaca; code signature relevant untuk iOS RE.
10. **Mach-O sections (di dalam LC_SEGMENT_64) tidak diparse** — Dart Mach-O punya sections (`__text`, `__data`, `__bss`, `__unwind_info`, `_kDartMachOEhFrameSection`) yang tidak diexpose; `__unwind_info` adalah Mach-O equivalent dari `.eh_frame`.
11. **PE/COFF (Windows) tidak diimplementasi** — `OpenContainer` return error. Dart SDK mendukung PE/COFF untuk Windows x64 (`runtime/vm/coff.cc`), dengan CodeView debug info & `.pdata`/`.xdata` unwind.

Selain itu, **register tracking gaps** tidak applicable di layer `elfx` (register tracking ada di `internal/disasm`), tapi `elfx` gagal mengekspos info yang dibutuhkan downstream: `instructions_relocated_address_` (basis relokasi text) dan `bss_offset_` (lokasi BSS) yang dibutuhkan untuk koreksi relokasi saat disasm.

## Struktur Folder

```
internal/elfx/
├── elfx.go        (302 lines)  — ELF loader: Open, Symbol, VAToFileOffset, ReadBytesAtVA, LoadSegments, Container interface, OpenContainer
├── funcsyms.go    (48 lines)   — FuncSymbols: .symtab STT_FUNC → map[VA]name (last-resort naming)
├── macho.go       (333 lines)  — Mach-O loader: MachOContainer, openMachO, Symbol, VAToFileOffset, segment+symtab parsing
└── elfx_test.go   (200 lines)  — Tests: TestOpenValid, TestSymbolLookup, TestVAToFileOffset, TestLoadSegments, FuzzELFOpen
```

Pengguna `elfx` (9 import paths, ~20 call sites):
- `internal/snapshot/snapshot.go` — `Extract()` memakai `ef.Symbol()` untuk 4+2 simbol snapshot, `ef.VAToFileOffset()`, `ef.ReadBytesAtVA()`, `ef.LoadSegments()` (via `capRegionSize`).
- `internal/analysis/snapshot_loader.go` — `LoadSnapshot()` pipeline utama.
- `internal/analysis/inventory.go`, `findlibapp.go` — inventory scan & libapp detection.
- `cmd/aotopsy/cmd_doctor.go`, `cmd_ghidra.go`, `cmd_ida.go` — CLI commands (IsARM64 check).
- `internal/cluster/corpus_test.go`, `internal/naming/*_test.go`, `internal/samplecorpus/corpus.go`, `internal/snapshot/corpus_test.go` — tests & corpus.

## Gap Analysis

### Gap 1: Simbol BSS tidak ditrack di semua versi Dart

- **Deskripsi**: Dart AOT ELF mengekspor simbol BSS yang menunjuk ke BSS section berisi relocation table. AOTopsy `snapshot.go` hanya track 5 simbol (pre-3.13: `_kDartVmSnapshotData`, `_kDartVmSnapshotInstructions`, `_kDartIsolateSnapshotData`, `_kDartIsolateSnapshotInstructions`, `_kDartSnapshotBuildId`; 3.13+: `_kDartSnapshotData`, `_kDartSnapshotText`, `_kDartSnapshotBuildId`). Simbol BSS (`_kDartVmSnapshotBss`, `_kDartIsolateSnapshotBss` pre-3.13; `_kDartSnapshotBss` 3.13+) tidak pernah diquery.
- **Bukti SDK**:
  - `runtime/include/dart_api.h@3.12.2` lines 4025-4049: define `kVmSnapshotBssAsmSymbol = "_kDartVmSnapshotBss"`, `kIsolateSnapshotBssAsmSymbol = "_kDartIsolateSnapshotBss"`.
  - `runtime/include/dart_api.h@3.13.0` lines 4034-4037: define `kSnapshotBssAsmSymbol = "_kDartSnapshotBss"`.
  - `runtime/vm/elf.cc@3.13.0` line 1174: BSS section symbol ditambahkan ke static symtab (`{kSnapshotBssAsmSymbol, SymbolData::Type::Section, 0, size, kIsolateBssLabel}`).
  - `runtime/vm/bss_relocs.h@3.13.0`: BSS berisi `Relocation::DLRT_GetFfiCallbackMetadata` (3.13) atau `Relocation::InstructionsRelocatedAddress` + `DRT_GetThreadForNativeCallback` (2.19) — function pointers ke VM runtime.
  - `runtime/vm/image_snapshot.cc@3.13.0` line 702-710: `SectionSymbol(ProgramSection::Bss)` return `kSnapshotBssAsmSymbol`.
- **Dampak**: BSS adalah jembatan antara AOT snapshot dan VM runtime. Tanpa BSS, AOTopsy tidak bisa:
  - Mendapat `instructions_relocated_address_` (basis relokasi text) yang disimpan di BSS entry 0 pada assembly snapshots.
  - Mengidentifikasi entry points VM runtime yang dipanggil dari snapshot (FfiCallback, GetThreadForNativeCallback) — berguna untuk memahami FFI boundary.
  - Validasi konsistensi relokasi antara text dan BSS.
- **Usulan**: Tambah konstanta `SymVmSnapshotBss`, `SymIsolateSnapshotBss`, `SymUnifiedSnapshotBss` di `snapshot.go`. Tambah field `Bss Region` di `snapshot.Info`. Parse BSS contents (word-sized entries) sesuai `BSS::Relocation` enum per versi Dart. Expose via `elfx.File.Symbol()` (sudah support dynsym). Untuk static symtab (BSS di ELF adalah local symbol, bukan dynsym — perlu `FuncSymbols`-style `.symtab` scan atau section-based lookup).
- **Prioritas**: HIGH — BSS adalah info RE kritis yang ada di setiap build tapi sepenuhnya invisible.

### Gap 2: Text-section Image header (`UntaggedInstructionsSection`) tidak diparse

- **Deskripsi**: Awal `.text` (instruksi snapshot) berisi `Image` header (2 word: `image_size`, `instructions_section_offset`) diikuti `UntaggedInstructionsSection` object (5 field: tags, `payload_length_`, `bss_offset_`, `instructions_relocated_address_`, `build_id_offset_`). AOTopsy membaca `.text` sebagai blob mentah via `ReadBytesAtVA(va, size)` tanpa pernah parse header ini.
- **Bukti SDK**:
  - `runtime/vm/image_snapshot.h@3.13.0` lines 116-142: `Image::kHeaderSize = kObjectStartAlignment`; `HeaderField::ImageSize`, `HeaderField::InstructionsSectionOffset`.
  - `runtime/vm/raw_object.h@3.13.0` lines 2243-2250: `UntaggedInstructionsSection` fields: `payload_length_`, `bss_offset_`, `instructions_relocated_address_`, `build_id_offset_`.
  - `runtime/vm/image_snapshot.cc@3.13.0` lines 775-848: penulisan header — `WriteTargetWord(image_size)`, `WriteTargetWord(InstructionsSectionOffset)`, lalu `WriteTargetWord(tags)`, `WriteTargetWord(section_payload_length)`, `Relocation(bss_offset)`, `RelocatedAddress(instructions_relocated_address)`, `Relocation(build_id_offset)`.
- **Dampak**:
  - `instructions_relocated_address_` = basis VA text section di shared object — dibutuhkan untuk koreksi relokasi saat disasm (PC-relative address yang ditulis di snapshot perlu dikoreksi dengan basis ini).
  - `bss_offset_` = offset BSS dari text section — cross-reference ke Gap 1, alternatif path untuk lokasi BSS tanpa simbol.
  - `build_id_offset_` = offset GNU build-id note dari text section — alternatif path untuk build-id tanpa scan section table.
  - `payload_length_` = panjang payload instruksi (setelah header) — lebih akurat dari symbol size untuk menentukan batas code region.
  - `image_size` = total image size — cross-validasi dengan symbol size.
- **Usulan**: Tambah parser `ParseTextImageHeader(data []byte, byteOrder, is64bit) (*TextImageHeader, error)` di `elfx` atau `snapshot`. Baca 2 word pertama (Image header), lalu `UntaggedInstructionsSection` di offset `kHeaderSize`. Field layout arch-dependent (word size 4/8 byte). Expose via `snapshot.Info.IsolateInstructions.Header`.
- **Prioritas**: HIGH — `instructions_relocated_address_` dibutuhkan untuk relokasi-correct disasm; saat ini AOTopsy mengabaikan relokasi text section sepenuhnya.

### Gap 3: Section table ELF tidak diexpose

- **Deskripsi**: `elfx.File` hanya expose `LoadSegments()` (PT_LOAD) dan `FuncSymbols()` (.symtab). Tidak ada API untuk enumerate sections, lookup section by name, atau baca section data. Padahal `debug/elf.File` (yang di-wrap) punya `ef.Sections` slice lengkap.
- **Bukti SDK**:
  - `runtime/vm/elf.cc@3.13.0` lines 1148-1278: Dart ELF menulis sections: `.text`, `.rodata`, `.bss`, `.dynamic`, `.dynstr`, `.dynsym`, `.hash`, `.strtab`, `.symtab`, `.eh_frame`, `.note.gnu.build-id`, `.debug_abbrev`, `.debug_info`, `.debug_line`.
  - `runtime/bin/elf_loader.cc@3.13.0` lines 342-360: Dart VM loader sendiri membaca `.dynstr` dan `.dynsym` via section table (bukan via PT_DYNAMIC) untuk resolve symbols.
- **Dampak**:
  - Tidak bisa akses `.note.gnu.build-id` dari `elfx` (harus via package terpisah `fingerprint`).
  - Tidak bisa akses `.eh_frame` untuk unwind info.
  - Tidak bisa akses `.debug_*` untuk DWARF info (unstripped builds).
  - Tidak bisa validasi struktur ELF (section vs segment consistency).
  - `FuncSymbols` pakai `ef.ELF.Symbols()` (debug/elf helper) tapi tidak expose section index info yang ada di `elf.Symbol`.
- **Usulan**: Tambah `Sections() []SectionInfo` dan `Section(name string) *SectionInfo` di `elfx.File`. Wrap `ef.ELF.Sections` dengan field: Name, Type, Flags, Addr, Offset, Size, Link, Info, Addralign. Tambah `SectionData(name string) ([]byte, error)`.
- **Prioritas**: MEDIUM — foundational untuk gap lain (build-id, eh_frame, debug sections semua butuh ini).

### Gap 4: `.eh_frame` (DWARF CFI) tidak diparse

- **Deskripsi**: Dart ELF selalu menulis `.eh_frame` section (jika ada text section) berisi DWARF Call Frame Information records (CIE + FDE per function). Section ini ADA di production stripped builds (tidak dihapus oleh strip). AOTopsy tidak membacanya sama sekali.
- **Bukti SDK**:
  - `runtime/vm/elf.cc@3.13.0` lines 1258-1278: `FinalizeEhFrame()` selalu dipanggil di `Finalize()` (line 1556), mengumpulkan FDEs dari text section, menulis `.eh_frame` via `Dwarf::WriteCallFrameInformationRecords`.
  - `.eh_frame` ditambahkan ke section table (line 1278) dan masuk ke RO PT_LOAD segment (line 1398 comment: "RO (program header, .note.gnu.build-id, .dynstr, .dynsym, .hash, .rodata and .eh_frame)").
- **Dampak**:
  - FDE (Frame Description Entry) per function berisi: function start address, length, CFA (Canonical Frame Address) rule, register restore rules, return address location. Ini adalah ground-truth function boundaries yang TIDAK bergantung pada snapshot parsing.
  - Cross-validasi function boundaries dari snapshot cluster vs ground-truth ELF.
  - Stack unwinding reconstruction untuk crash analysis.
  - Info prologue/epilogue layout (stack frame size, saved registers) — RE-useful untuk memahami calling convention.
- **Usulan**: Tambah parser `.eh_frame` di package baru `internal/ehframe` (atau `internal/dwarf`). Gunakan library Go `debug/dwarf` (sudah ada di stdlib, support `.eh_frame` via `frame` package tidak ada — perlu hand-parse atau lib pihak ketiga seperti `github.com/loov/leakdi`). Expose FDE table: `[]FrameDescriptionEntry{Start, End, CFA, ReturnAddrReg, ...}`. Cross-reference dengan `cluster.CodeRange` untuk validasi.
- **Prioritas**: MEDIUM — ada di setiap build, ground-truth function boundaries, tapi butuh effort parsing DWARF CFI.

### Gap 5: Build-ID note parsing tidak terintegrasi di `elfx`

- **Deskripsi**: Build-ID (128-bit hash dari `.text` + `.rodata` contents) adalah fingerprint unik per Dart AOT build. Parsing ada di `internal/fingerprint/fingerprint.go` (`extractBuildID` + `parseBuildIDNotes`) tapi tidak di `elfx`. `elfx` tidak expose build-id sama sekali, padahal `snapshot.Info` punya `SnapshotHash` (dari snapshot header) yang berbeda dari ELF build-id.
- **Bukti SDK**:
  - `runtime/vm/elf.cc@3.13.0` lines 1710-1758: `GenerateBuildId()` — 128-bit hash, 64-bit dari `.text` (hash `kSnapshotTextAsmSymbol` portion) + 64-bit dari `.rodata` (hash `kSnapshotDataAsmSymbol` portion). Format note: `name_size=4, desc_size=16, type=NT_GNU_BUILD_ID=3, name="GNU\0", desc=16 bytes`.
  - `runtime/vm/elf.cc@3.13.0` line 1528: PT_NOTE segment ditambahkan untuk build-id.
  - `pkg/native_stack_traces/lib/src/constants.dart@3.13.0` lines 11-13: `buildIdSectionName = '.note.gnu.build-id'`, `buildIdNoteType = 3`, `buildIdNoteName = 'GNU'`.
- **Dampak**:
  - `elfx` tidak bisa fingerprint build tanpa package terpisah.
  - `snapshot.Info` tidak punya field `BuildID` (ELF-level) terpisah dari `SnapshotHash` (snapshot-level) — keduanya berbeda: BuildID hash text+rodata bytes, SnapshotHash hash snapshot version string.
  - Cross-build comparison (corpus dedup, version fingerprinting) terpisah dari `elfx`.
- **Usulan**: Pindahkan `extractBuildID` + `parseBuildIDNotes` dari `fingerprint` ke `elfx` (atau buat `elfx.BuildID()` method yang wrap). Tambah field `BuildID string` di `snapshot.Info`. Integrasi dengan `fingerprint` package (refactor `fingerprint` untuk pakai `elfx`).
- **Prioritas**: LOW-MEDIUM — sudah ada implementasi di `fingerprint`, hanya perlu integrasi.

### Gap 6: PT_NOTE / PT_DYNAMIC / PT_PHDR / PT_GNU_STACK segment tidak diexpose

- **Deskripsi**: `LoadSegments()` hanya return `PT_LOAD` segments. Segment type lain (`PT_NOTE`, `PT_DYNAMIC`, `PT_PHDR`, `PT_GNU_STACK`) tidak diexpose. Dart ELF menulis semua ini.
- **Bukti SDK**:
  - `runtime/vm/elf.cc@3.13.0` lines 1405-1542: `CreateProgramTable` menambahkan: `PT_PHDR` (line 1405), `PT_LOAD` (multiple, line 1411-1412), `PT_NOTE` (line 1528, untuk build-id), `PT_DYNAMIC` (line 1535, untuk dynamic table), `PT_GNU_STACK` (line 1541, non-exec stack marker).
- **Dampak**:
  - `PT_NOTE` segment adalah cara alternatif (lebih cepat) untuk lokasi build-id tanpa scan section table.
  - `PT_DYNAMIC` berguna untuk validasi dynamic linking info (DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT — semua ditulis Dart, line 696-706).
  - `PT_GNU_STACK` flag (PF_X absence) konfirmasi non-exec stack — minor RE signal.
  - `PT_PHDR` self-reference — validasi struktur ELF.
  - Tanpa expose ini, AOTopsy tidak bisa validasi struktur ELF lengkap.
- **Usulan**: Tambah `AllSegments() []SegmentInfo` yang return semua segment (bukan hanya PT_LOAD), dengan field `Type elf.ProgType`. Atau tambah method spesifik `NoteSegment()`, `DynamicSegment()`.
- **Prioritas**: LOW — PT_LOAD cukup untuk VA→offset translation (fungsi utama); segment lain hanya validasi/info.

### Gap 7: Mach-O `LC_DYSYMTAB` tidak diparse (symbol resolution salah)

- **Deskripsi**: `macho.go` line 22 define `LC_DYSYMTAB = 0x0B` tapi tidak pernah dibaca di `openMachO`. `Symbol()` scan SEMUA simbol di LC_SYMTAB (line 124-141), filter hanya stab + N_TYPE. Dart Mach-O loader menggunakan LC_DYSYMTAB untuk menemukan exported symbols via `iextdefsym` + `nextdefsym` indices.
- **Bukti SDK**:
  - `runtime/bin/macho_loader.cc@3.13.0` lines 431-470: `ReadDynamicSymbolTable()` baca LC_SYMTAB + LC_DYSYMTAB; `external_symbol_count_ = dysymtab->nextdefsym`; external symbols dimulai dari `symtab->symoff + dysymtab->iextdefsym * sizeof(nlist)`.
  - `runtime/bin/macho_loader.cc@3.13.0` lines 482-498: `ResolveSymbols()` hanya iterate `external_symbol_count_` symbols (exported), bukan semua simbol.
  - `runtime/vm/mach_o.cc@3.13.0` line 1389+: `LC_SYMTAB` dan `LC_DYSYMTAB` keduanya ditulis Dart.
- **Dampak**:
  - **False match risk**: scan semua simbol termasuk local/stab entries bisa match simbol lokal dengan nama sama persis (`_kDartSnapshotData` bisa ada sebagai local alias). Dart loader hanya pakai exported (extdef) symbols.
  - **Performance**: scan semua simbol (bisa ribuan stab entries di debug build) vs hanya exported (5-7 simbol).
  - **Koreksi bug lama**: comment di `macho.go` line 117-123 menyebut bug lama `NType&0x3E != 0` yang salah arah. Filter saat ini (`nStab` skip + `nSect`/`nAbs` accept) lebih baik tapi masih tidak filter `N_PEXT` (private external) yang seharusnya tidak dianggap exported.
- **Usulan**: Parse LC_DYSYMTAB di `openMachO`: baca `iextdefsym`, `nextdefsym`, `ilocalsym`, `nlocalsym`, `iextdefsym`, `nextdefsym`, `iundefsym`, `nundefsym`. Di `Symbol()`, iterate hanya range `[iextdefsym, iextdefsym+nextdefsym)`. Tambah field `Dysymtab` di `MachOFile`.
- **Prioritas**: HIGH (untuk Mach-O path) — correctness issue, bukan hanya missing feature. Tapi Mach-O path belum wired (`OpenContainer` belum dipanggil manapun, per comment line 80-85), jadi prioritas efektif MEDIUM.

### Gap 8: Mach-O `LC_UUID` tidak diparse (build-id equivalent miss)

- **Deskripsi**: `macho.go` line 25 define `LC_UUID = 0x1B` tapi tidak dibaca. LC_UUID berisi 128-bit UUID yang adalah Mach-O equivalent dari ELF build-id (hash dari text+data contents).
- **Bukti SDK**:
  - `runtime/vm/mach_o.cc@3.13.0` lines 1084-1107: `MachOUuid` class, `kCommandCode = mach_o::LC_UUID`, berisi 16-byte UUID.
  - `runtime/vm/mach_o.cc@3.13.0` lines 2470-2506: UUID generated dari 128-bit hash (64-bit text + 64-bit data), sama algoritma dengan ELF build-id.
  - `runtime/vm/mach_o.cc@3.13.0` lines 2203-2207: UUID offset digunakan untuk build-id lookup (`header.file_offset() + uuid->header_offset()`).
- **Dampak**: Mach-O path tidak bisa fingerprint build. Cross-platform build-id comparison (ELF vs Mach-O) tidak mungkin. iOS binary (Mach-O) tidak punya fingerprint equivalent.
- **Usulan**: Parse LC_UUID di `openMachO`: baca 16-byte UUID dari load command. Expose via `MachOContainer.BuildID() string` (hex) atau tambah method `BuildID()` ke `Container` interface. Refactor `fingerprint` untuk handle Mach-O via interface ini.
- **Prioritas**: MEDIUM — penting untuk iOS RE, tapi Mach-O path belum wired.

### Gap 9: Mach-O `LC_CODE_SIGNATURE` / `LC_LOAD_DYLIB` / `LC_ID_DYLIB` / `LC_RPATH` tidak diparse

- **Deskripsi**: `macho.go` define `LC_LOAD_DYLIB = 0x0C` dan `LC_ID_DYLIB = 0x0D` (line 23-24) tapi tidak dibaca. `LC_CODE_SIGNATURE` dan `LC_RPATH` tidak didefinisikan sama sekali.
- **Bukti SDK**:
  - `runtime/vm/mach_o.cc@3.13.0` line 117: `V(MachOCodeSignature)` — code signature command ditulis.
  - line 1166: `LC_ID_DYLIB` — dylib identifier (path, version) untuk MH_DYLIB filetype.
  - line 1187: `LC_LOAD_DYLIB` — dependency dylib list.
  - line 1351: `LC_RPATH` — runtime search path.
  - line 1706-1708: `MachOCodeSignature`, `kCommandCode = mach_o::LC_CODE_SIGNATURE` — iOS code signature (untuk App Store distribution).
- **Dampak**:
  - `LC_ID_DYLIB` berisi dylib install name & version — RE-useful untuk identifikasi binary.
  - `LC_LOAD_DYLIB` berisi dependency list (libsystem, libc++, dll) — konteks runtime environment.
  - `LC_CODE_SIGNATURE` berisi Apple code signature — verifikasi integritas & info signing identity (RE-relevant untuk iOS forensics).
  - `LC_RPATH` — runtime search path, konteks loading.
- **Usulan**: Tambah konstanta `LC_CODE_SIGNATURE = 0x1D`, `LC_RPATH = 0x8000001C`. Parse semua di `openMachO`. Expose via struct `MachOFile` fields: `IDDylib`, `LoadDylibs []MachODylibRef`, `CodeSignature`, `RPaths`.
- **Prioritas**: LOW — iOS-specific, Mach-O path belum wired.

### Gap 10: Mach-O sections (di dalam LC_SEGMENT_64) tidak diparse

- **Deskripsi**: `macho.go` parse `MachOSegment64` tapi tidak parse sections di dalamnya (`NSects` field dibaca line 274 tapi tidak digunakan). Dart Mach-O punya sections: `__text`, `__data`, `__bss`, `__unwind_info`, `_kDartMachOEhFrameSection`.
- **Bukti SDK**:
  - `runtime/bin/macho_loader.cc@3.13.0` lines 310-340: Dart Mach-O loader iterate sections di dalam LC_SEGMENT_64, cari `SECT_UNWIND_INFO` (`__unwind_info`) untuk unwind records.
  - `runtime/vm/mach_o.cc@3.13.0` line 2769: section `_kDartMachOEhFrameSection` ditambahkan (Mach-O eh_frame equivalent).
  - `runtime/vm/mach_o.cc@3.13.0` line 2544: BSS section symbol `kSnapshotBssAsmSymbol`.
- **Dampak**:
  - `__unwind_info` adalah Mach-O compact unwind format — equivalent `.eh_frame` di ELF, berisi function boundaries & frame info.
  - Tanpa section parsing, Mach-O path tidak bisa locate `__unwind_info`, `__text`, `__data` secara presisi (hanya segment-level granularity).
  - VA→offset translation Mach-O saat ini hanya segment-based; section-level lebih presisi.
- **Usulan**: Parse `section_64` struct (80 bytes) di dalam LC_SEGMENT_64 setelah segment header. Field: `sectname[16]`, `segname[16]`, `addr`, `size`, `offset`, `align`, `reloff`, `nreloc`, `flags`, `reserved1`, `reserved2`, `reserved3`. Expose via `MachOFile.Sections []MachOSection64`. Tambah `MachOContainer.SectionData(name string)`.
- **Prioritas**: MEDIUM — foundational untuk Mach-O RE features, tapi Mach-O path belum wired.

### Gap 11: PE/COFF (Windows) tidak diimplementasi

- **Deskripsi**: `OpenContainer` (elfx.go line 297-299) return error untuk PE: `"elfx: PE binary detected but PE support is not yet implemented"`. Dart SDK mendukung PE/COFF output untuk Windows x64.
- **Bukti SDK**:
  - `runtime/vm/coff.cc@3.13.0` (989 lines): full COFF writer — sections (`.text`, `.data`, `.bss`, `.rdata`, `.pdata`, `.xdata`), CodeView debug info (`.debug_*`), PE unwind info (`.pdata`/`.xdata`).
  - `runtime/include/dart_api.h@3.13.0` line ~4150: `Dart_AotBinaryFormat_PECoff_Obj = 3` — PE/COFF adalah format resmi untuk Windows x64.
  - `runtime/vm/coff.cc@3.13.0` line 493: BSS section dengan `kSnapshotBssAsmSymbol` static symbol.
- **Dampak**: AOTopsy tidak bisa analisa Windows Flutter apps (libapp.dll). Windows x64 Flutter apps ada di production (desktop Flutter).
- **Usulan**: Implementasi `PEContainer` mengikuti `MachOContainer` pattern. Parse PE header → section table → export symbol table. Gunakan `debug/pe` stdlib Go untuk parsing dasar. Implementasi `Container` interface methods.
- **Prioritas**: LOW — Windows Flutter market share kecil vs Android/iOS; butuh effort besar.

## Register Tracking Gaps

Layer `elfx` tidak melakukan register tracking (itu domain `internal/disasm`), tapi `elfx` gagal mengekspos info yang dibutuhkan downstream untuk register tracking yang relokasi-correct:

1. **`instructions_relocated_address_` tidak diekspos** — basis VA text section di shared object. Saat Dart VM me-load ELF, text section direlokasi ke alamat baru; PC-relative references di dalam instruksi ditulis relative ke `instructions_relocated_address_` (untuk assembly snapshots, ini disimpan di BSS entry 0). Tanpa ini, disasm PC-relative target (branch, ADRP) tidak bisa dikoreksi ke VA actual. **Dampak**: `internal/disasm` mengasumsikan VA = symbol VA + offset, yang benar untuk ELF (relokasi dilakukan linker) tapi salah untuk assembly snapshots. Untuk ELF, `instructions_relocated_address_` = symbol VA (relokasi sudah dilakukan), jadi gap ini efektif hanya untuk assembly snapshot path (tidak didukung AOTopsy saat ini).

2. **BSS relocation entries tidak diekspos** — BSS entry 0 (`InstructionsRelocatedAddress` di 2.19, atau via `instructions_relocated_address_` field di 3.13) berisi basis relokasi. Entry lain (`DRT_GetThreadForNativeCallback`, `DLRT_GetFfiCallbackMetadata`) adalah function pointers ke VM runtime — berguna untuk identifikasi FFI callback entry points di disasm (register yang hold callback trampoline target).

3. **Tidak ada info untuk koreksi `Thread` register (THR)** — `internal/disasm/dataflowarm64.go` track THR register, tapi `elfx` tidak expose info tentang Thread struct layout (itu di `internal/vmtables/thrfields.go`). Gap ini bukan di `elfx` tapi relevan: `elfx` tidak expose ELF-derived cross-check untuk THR offset validation.

**Konklusi register tracking**: Tidak ada register yang "tidak ditrack seharusnya ditrack" langsung di `elfx` (layer ini tidak track register). Tapi `elfx` miss mengekspos `instructions_relocated_address_` dan BSS entries yang dibutuhkan downstream untuk register tracking relokasi-correct.

## Fitur RE Missing/Incomplete

### Missing (tidak ada sama sekali)

1. **BSS section parsing** — relocation table VM runtime (Gap 1).
2. **Text Image header parsing** — `UntaggedInstructionsSection` metadata (Gap 2).
3. **Section table API** — enumerate/read sections by name (Gap 3).
4. **`.eh_frame` parsing** — DWARF CFI, function boundaries ground-truth (Gap 4).
5. **Build-ID di `elfx`** — terpisah di `fingerprint` (Gap 5).
6. **Non-PT_LOAD segment expose** — PT_NOTE, PT_DYNAMIC, PT_PHDR, PT_GNU_STACK (Gap 6).
7. **Mach-O LC_DYSYMTAB** — exported symbol resolution correct (Gap 7).
8. **Mach-O LC_UUID** — build-id equivalent (Gap 8).
9. **Mach-O LC_CODE_SIGNATURE / LC_LOAD_DYLIB / LC_ID_DYLIB / LC_RPATH** (Gap 9).
10. **Mach-O section parsing** — `__unwind_info`, `__text`, `__data` (Gap 10).
11. **PE/COFF support** — Windows Flutter (Gap 11).

### Incomplete (ada tapi tidak lengkap)

1. **`FuncSymbols()`** — hanya baca `.symtab` STT_FUNC, tidak expose section index, binding, size yang ada di `elf.Symbol`. Tidak filter by section (bisa match simbol dari section non-text). Tidak handle STT_OBJECT (data symbols seperti pool entries yang ada di `.rodata`).

2. **`VAToFileOffset()`** — hanya cek `va < p.Vaddr+p.Memsz` (line 122), tidak handle VA di `p.Vaddr+p.Filesz` s.d. `p.Vaddr+p.Memsz` (BSS region, file offset tidak valid untuk zero-filled). VA di BSS akan return offset yang point ke data setelah file content (atau padding) — silent wrong answer. Harus return error atau flag BSS.

3. **`Open()` machine validation** — accept `EM_AARCH64` dan `EM_X86_64` (line 71), tapi `IsARM64()` hanya check AARCH64. Tidak ada `IsX86_64()` helper — caller harus re-check `ef.ELF.Machine`. Tidak expose `Machine()` method umum.

4. **`OpenContainer()`** — detect Mach-O fat binary (line 282-285) tapi return error "extract the arm64 slice first". Tidak auto-extract slice (bisa dilakukan dengan parsing fat header + slice extraction). PE detect tapi error. Tidak detect ELF32 (32-bit ELF) — akan fail di `ErrNot64Bit` dengan pesan tidak spesifik.

5. **Mach-O `openMachO()`** — baca LC_SYMTAB tapi tidak validasi `nSyms` (line 293: `make([]byte, int(nSyms)*16)` — bisa OOM jika `nSyms` corrupt/huge). Tidak validasi `symOff`/`strOff` within file. Tidak baca `LC_DYSYMTAB` (Gap 7). Tidak handle fat binary (sudah reject di `openMachO` magic check, tapi pesan tidak actionable untuk automation).

6. **`SegmentInfo`** — tidak expose `Type` (selalu PT_LOAD), tidak expose `Align` (page alignment, berguna untuk memahami 16KB vs 64KB page — sinyal target platform Android vs Linux).

### Fitur RE Useful yang Bisa Ditambah

1. **ELF header flags expose** — `ef.ELF.EFlags` (ARM64: `EF_AARCH64_FLOAT_ABI_*`, BTI/PAC flags via `.note.gnu.property`). Berguna untuk deteksi hardening (PAC, BTI).
2. **`.note.gnu.property` parsing** — GNU property notes (AArch64 feature flags: BTI, PAC). Sinyal security hardening level.
3. **DWARF `.debug_info`/`.debug_line` parsing** (unstripped builds) — function names, source file/line mapping. Ground-truth untuk validasi naming recovery.
4. **`.dynsym` enumerate** — saat ini hanya `Symbol(name)` exact match. Tidak ada `AllDynamicSymbols()` untuk inspect semua exported symbols (berguna untuk deteksi non-standar symbols, loading unit markers).
5. **Loading unit detection** — Dart deferred loading split jadi multiple `.so` files (app.so, app-2.so, dst). `elfx` tidak punya API untuk detect loading unit ke-2 (simbol `_kDartSnapshotData` ada di setiap unit, tidak ada unit ID di ELF). Perlu cross-reference dengan `loading_units.jsonl` dari build.
6. **Relocation entries (`.rela.dyn`/`.rel.dyn`)** — Dart ELF tidak menulis ini (snapshot tidak pakai dynamic relocation), tapi validasi keberadaan bisa konfirmasi build type.
7. **`DT_FLAGS`/`DT_FLAGS_1` dynamic flags** — bind now, etc. Sinyal security hardening.

## Verifikasi SDK

Semua klaim diverifikasi via:
1. **grep MCP (`searchGitHub` by Vercel)** dengan `repo: "dart-lang/sdk"` (tanpa `repo:` di query, tanpa `path`):
   - Query `_kDartVmSnapshotData` → `pkg/native_stack_traces/lib/src/constants.dart` (konfirmasi simbol unified 3.13).
   - Query `_kDartSnapshotBuildId` → `pkg/native_compiler/lib/runtime/vm_defs.dart` + `runtime/include/dart_api.h` (konfirmasi 4 simbol 3.13).
   - Query `kSnapshotBss` → `runtime/include/dart_api.h`, `runtime/vm/coff.cc`, `runtime/vm/image_snapshot.cc`, `runtime/vm/elf.cc`, `runtime/vm/mach_o.cc` (konfirmasi BSS di semua format).
   - Query `UntaggedInstructionsSection` (via `instructions_relocated_address_`) → `runtime/vm/image_snapshot.cc`, `runtime/vm/raw_object.h` (konfirmasi header layout).
   - Query `kSnapshotTextAsmSymbol` → `runtime/bin/elf_loader.cc`, `runtime/bin/macho_loader.cc`, `runtime/vm/image_snapshot.cc`, `runtime/vm/elf.cc`, `runtime/vm/mach_o.cc` (konfirmasi symbol usage di loader).
   - Query `Dart_LoadingUnitLibraryUris` → `runtime/bin/dart_api_win.c`, `runtime/bin/gen_snapshot.cc`, `runtime/include/dart_api.h` (konfirmasi loading unit API).
   - Query `ElfLoader` → `runtime/vm/unwinding_records.cc` (konteks ELF loader usage).

2. **`gh api` @ version tag** (`Accept: application/vnd.github.raw`):
   - `runtime/include/dart_api.h@3.13.0` (lines 4020-4040): konfirmasi 4 simbol unified + BSS.
   - `runtime/include/dart_api.h@3.12.2` (lines 4022-4049): konfirmasi 7 simbol pre-unified (build-id + 4 snapshot + 2 BSS).
   - `runtime/include/dart_api.h@2.19.0` (lines 3944-3971): konfirmasi 7 simbol pre-unified (sama dengan 3.12.2).
   - `runtime/vm/elf.h@3.13.0`: konfirmasi section names (`kBuildIdNoteName`, `kTextName`, `kDataName`, `kBssName`, `kDynamicTableName`).
   - `runtime/vm/elf.cc@3.13.0` (1994 lines): konfirmasi section list, segment list, build-id generation, BSS symbol add, dynamic table entries.
   - `runtime/vm/so_writer.h@3.13.0`: konfirmasi `ReservedLabels` (kIsolateInstructionsLabel, kIsolateDataLabel, kIsolateBssLabel, kBuildIdLabel, kMachOEhFrameLabel).
   - `runtime/vm/image_snapshot.cc@3.13.0` (lines 700-985): konfirmasi `SectionSymbol` mapping, text section header write (5 field InstructionsSection).
   - `runtime/vm/image_snapshot.h@3.13.0` (lines 40-160): konfirmasi `Image` class, `kHeaderSize`, `HeaderField` enum, `ExtraInfo`.
   - `runtime/vm/raw_object.h@3.13.0` (lines 2220-2280): konfirmasi `UntaggedInstructionsSection` field layout.
   - `runtime/vm/bss_relocs.h@3.13.0`: konfirmasi BSS relocation entries (3.13: `DLRT_GetFfiCallbackMetadata`).
   - `runtime/vm/bss_relocs.h@2.19.0`: konfirmasi BSS relocation entries (2.19: `InstructionsRelocatedAddress`, `DRT_GetThreadForNativeCallback`).
   - `runtime/bin/elf_loader.cc@3.13.0` (482 lines): konfirmasi VM ELF loader logic (PT_LOAD only, `.dynstr`/`.dynsym` via section table, resolve `kSnapshotDataAsmSymbol`/`kSnapshotTextAsmSymbol`).
   - `runtime/bin/macho_loader.cc@3.13.0` (597 lines): konfirmasi VM Mach-O loader logic (LC_DYSYMTAB untuk exported symbols, `__unwind_info` section lookup).
   - `runtime/vm/mach_o.cc@3.13.0` (3654 lines): konfirmasi Mach-O load commands (LC_UUID, LC_ID_DYLIB, LC_LOAD_DYLIB, LC_RPATH, LC_SYMTAB, LC_DYSYMTAB, LC_CODE_SIGNATURE), UUID generation, BSS symbol.
   - `runtime/vm/coff.cc@3.13.0` (989 lines): konfirmasi PE/COFF support (sections, CodeView, BSS symbol).
   - `pkg/native_stack_traces/lib/src/constants.dart@3.13.0`: konfirmasi symbol name constants & build-id note format.

**Catatan**: Tidak ada build/test/run AOTopsy dijalankan (sesuai rule). Hanya baca kode AOTopsy + verifikasi SDK via grep MCP + gh api.
