# RE Gap Analysis Report: internal/dartfmt

> **STATUS VERIFIKASI (2026-09-01)** — semua 12 gap CONFIRMED sebagai
> deskripsi, semuanya kecil dan tidak ada yang salah. Detail:
> `docs/re-gap-analysis/reports/VERIFICATION_NOTES.md`.
> Dicek: `Stream` memang tidak punya `Read16/ReadTagged16`, `ReadLEB128/
> ReadSLEB128` (duplikatnya di `cluster/compressedstackmaps.go:177 readLEB128`
> dan `cluster/pcdescriptors.go:86 readSLEB128`), `ReadWordWith32BitReads`,
> `ReadFloat`, `Align(offset)`, peek; `ReadBytes` memang selalu `make`+`copy`;
> `Mode/Options` memang tidak dipakai `Stream`.

## Ringkasan

Folder `internal/dartfmt` berisi wire-encoding helpers untuk Dart AOT snapshot
format: sebuah `Stream` reader (varint marker-128 unsigned, marker-192 signed
untuk 32/64-bit, big-endian signed-byte `ReadRefId`, plus raw byte/LE/ CString
helpers) dan sebuah `Diag`/`Diags`/`Mode`/`Options` diagnostic layer.

Dibandingkan dengan sumber SDK Dart (`runtime/vm/datastream.h`, diverifikasi pada
tag `3.7.0` via `gh api`, dan `runtime/vm/app_snapshot.cc` / `module_snapshot.cc`
via grep MCP), AOTopsy mengimplementasikan subset wire format yang **fungsional
untuk decode cluster utama**, tetapi memiliki sejumlah gap signifikan untuk RE:

1. **Tidak ada `Read16`/`ReadTagged16`** — `OpUint16`/`OpInt16` di cluster
   memakai `ReadTagged32` (Read32). Tidak ada validasi rentang 16-bit, tidak ada
   pembedaan lebar tipe (RE forensik lemah).
2. **Tidak ada `ReadLEB128`/`ReadSLEB128` di Stream** — fungsi LEB128/SLEB128
   diduplikasi sebagai helper lokal di `cluster/pcdescriptors.go` dan
   `cluster/compressedstackmaps.go`, beroperasi pada raw slice + posisi manual,
   bukan pada `Stream`. Inkonsisten, rawan drift, tidak ada tracking offset
   terpadu.
3. **Tidak ada `ReadWordWith32BitReads`** — pola unboxed word (2× Read32) tidak
   diabstraksi; konsumen harus manual.
4. **Tidak ada `ReadFloat` (Read<float>)** — hanya `ReadDouble` (Read<double>).
   Float32 box (kFloat) tidak bisa didecode langsung.
5. **`Align` tidak mendukung `offset`** — SDK `Align(alignment, offset=0)`
   relatif terhadap offset non-zero; AOTopsy hanya offset=0.
6. **`ReadRefId` terlalu longgar** — SDK punya tepat 4 STAGE + `ASSERT(byte<0)`;
   AOTopsy loop 5 iterasi, menerima refid 5-byte yang SDK tolak. Tidak ada
   diag "refid terlalu panjang".
7. **Tidak ada `ReadUnsigned64` eksplisit** — SDK expose
   `ReadUnsigned<uint64_t>()` sebagai `ReadUnsigned64()`; AOTopsy hanya
   `ReadUnsigned() -> int64`.
8. **`ReadBytes` selalu alokasi copy** — tidak ada zero-copy view
   (`AddressOfCurrentPosition` analog). RE pada code body besar = copy mahal.
9. **Error stream tidak membawa offset** — `ErrStreamEOF`/`ErrStreamOverrun`
   generik; konsumen harus capture `s.Position()` manual sebelum call untuk
   membuat `Diag` dengan offset. Tidak ada integrasi `Stream`↔`Diags`.
10. **`Mode`/`Options` tidak dipakai Stream** — `ModeStrict`/`ModeBestEffort`
    didefinisikan tapi Stream selalu return error; tidak ada mode best-effort
    yang return placeholder + diag.
11. **`ReadTagged32` return `uint32` tapi dipakai untuk `int32_t`** — konsumen
    (`codesourcemap.go:129`) harus reinterpret manual. Tidak ada
    `ReadInt32`/`ReadTagged32Signed` yang langsung return `int32`.
12. **Tidak ada peek / `AddressOfCurrentPosition`** — SDK expose pointer ke
    posisi saat ini untuk akses raw; AOTopsy tidak. Membatasi RE pattern
    "scan-ahead" tanpa consume.

Struktur dasar varint (marker 128 unsigned, marker 192 signed, 7 data bits/byte,
big-endian RefId) **benar** dan diverifikasi sama dengan SDK. Gap utama adalah
**kelengkapan API surface** dan **kualitas diagnostik RE**, bukan kebenaran
decode.

## Struktur Folder

```
internal/dartfmt/
├── diag.go          (67 lines)  — Diag/Diags/Mode/Options/DefaultMaxSteps
├── stream.go        (295 lines) — Stream reader (varint, RefId, raw, CString, Align, Skip)
└── stream_test.go   (229 lines) — Unit tests untuk ReadUnsigned/Tagged32/Tagged64/RefId/CString/Double
```

Tidak ada subfolder. Tidak ada file writer (write-side) — AOTopsy hanya reader,
sesuai scope RE.

## Gap Analysis

### Gap 1: Tidak ada `Read16` / `ReadTagged16` — `OpUint16`/`OpInt16` memakai `ReadTagged32`

- **Deskripsi**: SDK `ReadStream` punya `Read16(uint8_t end_byte_marker)`
  terpisah (unrolled: INIT + BODY(7) + END(14), 2 stage data + 1 terminal).
  AOTopsy `dartfmt.Stream` tidak punya `Read16`. Di `cluster/fillspec.go:185-186`
  `OpUint16`/`OpInt16` didefinisikan sebagai "via ReadStream::Read16", tetapi
  implementasinya di `cluster/fill_refs.go:396-399` memanggil `s.ReadTagged32()`
  (yaitu Read32, 4 stage). Decode hasilnya **benar untuk nilai dalam rentang
  16-bit** (karena sign-extension bit-6 mengisi MSB sama), tetapi:
  - Tidak ada validasi rentang 16-bit → nilai 17-32 bit yang corrupt akan
    diterima tanpa diag.
  - Tidak ada pembedaan lebar → RE forensik tidak bisa membedakan field 16-bit
    vs 32-bit dari byte stream saat reconstructing struct layout.
  - Membaca lebih banyak byte dari seharusnya untuk data corrupt (SDK Read16
    fixed 3-byte max; AOTopsy ReadTagged32 bisa baca 5 byte).
- **Bukti SDK**: `runtime/vm/datastream.h` @3.7.0 (gh api):
  ```cpp
  uint16_t Read16(uint8_t end_byte_marker) {
    using T = uint16_t;
    UNROLLED_INIT();
    UNROLLED_BODY(7);
    UNROLLED_END(14);
  }
  ```
  vs `Read32` (4 BODY + END(28)). Terpisah, fixed-width.
- **Dampak**: RE forensik lemah — tidak bisa mendeteksi field 16-bit yang
  overflow (indikasi corrupt/tampered snapshot). Layout reconstruction tidak
  akurat.
- **Usulan**: Tambah `ReadTagged16() (uint16, error)` dan `ReadInt16() (int16, error)`
  di `stream.go`, dengan overflow guard `shift >= 14` (bukan 28). Rute
  `OpUint16`/`OpInt16` ke `ReadTagged16`. Tambah diag `DiagOverflow` saat nilai
  melebihi 16-bit.
- **Prioritas**: Tinggi — koreksi semantik + RE forensik.

### Gap 2: Tidak ada `ReadLEB128`/`ReadSLEB128` di `Stream` — duplikasi di cluster

- **Deskripsi**: SDK `ReadStream` punya `ReadLEB128<T>()` dan `ReadSLEB128<T>()`
  sebagai method stream (template, 7 bit/byte, high-bit=more, sign-extend dari
  bit-6 byte terakhir). AOTopsy `dartfmt.Stream` tidak punya. Implementasi
  terduplikasi:
  - `cluster/pcdescriptors.go:86` `readSLEB128(buf, pos)` — raw slice + pos
    manual.
  - `cluster/compressedstackmaps.go:177` `readLEB128(data, pos)` — raw slice +
    pos manual, **bug overflow**: `return 0, pos, nil` (silent, bukan error)
    saat shift>=64.
  Kedua helper bekerja di luar `Stream`, sehingga:
  - Tidak ada tracking offset terpadu via `Stream.Position()`.
  - Tidak ada integrasi dengan `Diags`.
  - Drift implementasi: `readLEB128` silent-overflow vs `readSLEB128` error.
  - Konsumen harus maintain posisi manual, rawan off-by-one.
- **Bukti SDK**: `runtime/vm/datastream.h` @3.7.0:
  ```cpp
  template <typename T = uintptr_t>
  C::only_if_unsigned<T, T> ReadLEB128() { ... b = ReadByte(); ... }
  template <typename T>
  C::only_if_signed<T, T> ReadSLEB128() {
    return bit_cast<T>(ReadSLEB128<typename std::make_unsigned<T>::type>());
  }
  ```
  Dipanggil di `clustered_snapshot`/`pcdescriptors` via `ReadSLEB128<int32_t>()`.
- **Dampak**: Inkonsistensi decode LEB128 antar konsumen. Bug silent-overflow
  di `readLEB128` CSM bisa menyembunyikan data corrupt. RE tidak bisa
  cross-check offset LEB128 vs cluster boundary.
- **Usulan**: Pindahkan `ReadLEB128() (uint64, error)` dan `ReadSLEB128() (int64, error)`
  ke `dartfmt.Stream` (consume via `ReadByte`, return error pada overflow).
  Refactor `pcdescriptors.go` & `compressedstackmaps.go` pakai `Stream`.
  Hapus duplikasi. Tambah test.
- **Prioritas**: Tinggi — bug silent-overflow + arsitektur.

### Gap 3: Tidak ada `ReadWordWith32BitReads` — pola unboxed word tidak diabstraksi

- **Deskripsi**: SDK `ReadStream::ReadWordWith32BitReads()` membaca `uword`
  sebagai 2× `Read32` (untuk kompat host 32-bit). AOTopsy mengomentari pola ini
  di `cluster/fill_instance.go:115` ("uword ReadWordWith32BitReads() {") tetapi
  tidak mengekspos helper. Konsumen harus manual 2× `ReadTagged32` + combine.
  Tidak ada validasi bahwa kedua half konsisten sebagai word.
- **Bukti SDK**: `runtime/vm/datastream.h` @3.7.0:
  ```cpp
  uword ReadWordWith32BitReads() {
    constexpr intptr_t kNumRead32PerWord = kBitsPerWord / kBitsPerInt32;
    uword value = 0;
    for (intptr_t j = 0; j < kNumRead32PerWord; j++) {
      const auto partial_value = Raw<kInt32Size, uint32_t>::Read(this);
      value |= (static_cast<uword>(partial_value) << (j * kBitsPerInt32));
    }
    return value;
  }
  ```
  Dipanggil di `app_snapshot.cc` (`uword ReadWordWith32BitReads() { return stream_.ReadWordWith32BitReads(); }`).
- **Dampak**: Pola unboxed word (instance fields unboxed, e.g. `uword`
  scalar) tidak terabstraksi → konsumen mudah salah urutan/gabungan half.
  RE tidak bisa membedakan "1 word 64-bit" vs "2 int32 terpisah".
- **Usulan**: Tambah `ReadWordWith32BitReads() (uint64, error)` di `stream.go`
  (2× `ReadTagged32`, combine LE). Ekspos `OpWord32x2` di fillspec.
- **Prioritas**: Sedang — abstraksi RE.

### Gap 4: Tidak ada `ReadFloat` (Read<float>) — hanya `ReadDouble`

- **Deskripsi**: SDK `Read<float>` = `Raw<4,float>::Read` = `Read32(marker192)`
  bit-cast ke `float`. AOTopsy punya `ReadDouble` (Read<double> via Tagged64
  bit-cast) tapi tidak ada `ReadFloat` (Read<float> via Tagged32 bit-cast).
  Float32 box (`kFloat` cid) dan field `float` tidak bisa didecode langsung;
  konsumen harus `ReadTagged32` + `math.Float32frombits` manual.
- **Bukti SDK**: `datastream.h` `Raw<4,T>::Read` generic — `T=float` valid.
  `Read<float>()` dipakai di clustered snapshot untuk Float box.
- **Dampak**: Float32 values (e.g. graphics/physics constants) tidak punya
  helper langsung → konsumen mudah lupa bit-cast, salah interpretasi sebagai
  int32.
- **Usulan**: Tambah `ReadFloat() (float32, error)` = `ReadTagged32` +
  `math.Float32frombits(uint32(v))`. Tambah `OpFloat` di fillspec.
- **Prioritas**: Sedang — kelengkapan RE.

### Gap 5: `Align` tidak mendukung parameter `offset`

- **Deskripsi**: SDK `Align(intptr_t alignment, intptr_t offset = 0)` memakai
  `Utils::RoundUp(position_before, alignment, offset)` — round-up relatif
  terhadap `offset` non-zero. AOTopsy `Align(alignment int)` hanya round-up
  relatif terhadap 0 (`s.pos % alignment`). Jika suatu titik deserialisasi
  memakai alignment relatif terhadap cluster start (bukan stream start), AOTopsy
  salah.
- **Bukti SDK**: `datastream.h` @3.7.0:
  ```cpp
  void Align(intptr_t alignment, intptr_t offset = 0) {
    intptr_t position_before = Position();
    intptr_t position_after = Utils::RoundUp(position_before, alignment, offset);
    Advance(position_after - position_before);
  }
  ```
- **Dampak**: Jika ada cluster yang align relatif terhadap offset non-zero
  (mis. instructions table base), AOTopsy salah hitung boundary → decode
  berikutnya misaligned. Saat ini tidak terlihat dipakai (grep `Align(` hanya
  di `stream.go` definisi), tetapi API tidak siap saat dibutuhkan.
- **Usulan**: Ubah signature `Align(alignment, offset int)` (offset default 0
  via caller). Implementasi `Utils.RoundUp(pos, align, offset)`:
  `((pos - offset + align - 1) / align) * align + offset`.
- **Prioritas**: Sedang — correctness latent.

### Gap 6: `ReadRefId` terlalu longgar — menerima refid 5-byte yang SDK tolak

- **Deskripsi**: SDK `ReadRefId` punya tepat 4 `STAGE` (0-7, 8-14, 15-21, 22-28)
  lalu `ASSERT(byte < 0)` — refid 5-byte (bit 29+) tidak mungkin (writer
  `WriteRefId` `ASSERT(IsUint(28, value))`). AOTopsy `ReadRefId` loop `i < 5`
  (5 iterasi), menerima byte ke-5 negatif → return value 29-35 bit. Tidak ada
  diag "refid terlalu panjang".
- **Bukti SDK**: `datastream.h` @3.7.0:
  ```cpp
  STAGE  STAGE  STAGE  STAGE
  ASSERT(byte < 0);  // 256MB is enough for anyone...
  ```
  `WriteRefId`: `ASSERT(Utils::IsUint(28, value));` — max 4 byte.
- **Dampak**: Snapshot corrupt/tampered dengan refid 5-byte diterima sebagai
  nilai besar nonsensikal, bukan ditolak/diag. RE forensik tidak bisa detect
  anomali.
- **Usulan**: Ubah loop jadi tepat 4 stage + cek byte ke-5 harus negatif (atau
  return `ErrStreamOverrun` + `DiagOverflow`). Tambah test refid 5-byte → error.
- **Prioritas**: Rendah — robustness RE.

### Gap 7: Tidak ada `ReadUnsigned64` eksplisit

- **Deskripsi**: SDK expose `ReadUnsigned<uint64_t>()` sebagai
  `ReadUnsigned64()` di `module_snapshot.cc`/`app_snapshot.cc`. AOTopsy
  `ReadUnsigned() -> int64` setara `ReadUnsigned<intptr_t>` (64-bit di host
  64-bit), tetapi tidak ada nama eksplisit untuk kontrak 64-bit. Konsumen yang
  butuh jaminan 64-bit (bukan intptr_t) tidak punya API jelas.
- **Bukti SDK**: grep MCP `ReadRefId()` → `module_snapshot.cc:165`:
  ```cpp
  uint64_t ReadUnsigned64() { return stream_.ReadUnsigned<uint64_t>(); }
  ```
- **Dampak**: Kebingungan kontrak — `ReadUnsigned` return `int64` tapi
  semantiknya `intptr_t`. Untuk host 64-bit sama, tapi tidak eksplisit.
- **Usulan**: Tambah `ReadUnsigned64() (uint64, error)` sebagai alias
  eksplisit. Dokumentasikan `ReadUnsigned` = `intptr_t`-equivalent.
- **Prioritas**: Rendah — kelengkapan API.

### Gap 8: `ReadBytes` selalu alokasi copy — tidak ada zero-copy view

- **Deskripsi**: SDK `ReadBytes(void* addr, len)` menulis ke buffer caller
  (memmove). SDK juga expose `AddressOfCurrentPosition()` untuk akses raw
  zero-copy. AOTopsy `ReadBytes(n) ([]byte, error)` selalu `make + copy`.
  Untuk RE pada code body besar (Instructions payload, ROData), setiap
  `ReadBytes` = alokasi + copy mahal, padahal data sudah di memori.
- **Bukti SDK**: `datastream.h`:
  ```cpp
  void ReadBytes(void* addr, intptr_t len) { memmove(addr, current_, len); ... }
  const uint8_t* AddressOfCurrentPosition() const { return current_; }
  ```
- **Dampak**: RE pada snapshot besar = overhead memori/CPU. Tidak bisa dapat
  view ke buffer asli untuk hashing/fingerprinting tanpa copy.
- **Usulan**: Tambah `ReadBytesView(n int) ([]byte, error)` return slice ke
  `s.data[s.pos:s.pos+n]` (no copy) + advance pos. Tambah `AddressOfCurrentPosition()`
  analog (return `&s.data[s.pos]` atau slice). Konsumen yang butuh immutability
  tetap pakai `ReadBytes`.
- **Prioritas**: Sedang — performa RE + fingerprinting.

### Gap 9: Error stream tidak membawa offset — `Diags` tidak terintegrasi

- **Deskripsi**: `ErrStreamEOF`/`ErrStreamOverrun` adalah sentinel generik tanpa
  offset. Konsumen (`cluster/cluster.go:271`, dll) harus capture
  `tagPos := s.Position()` **sebelum** call, lalu `diags.Addf(uint64(tagPos), ...)`
  manual. Pola ini rawan lupa, dan tidak ada cara untuk dapat offset dari error
  sendiri. `Diags` defined di `diag.go` tapi `Stream` tidak punya reference ke
  `*Diags` dan tidak auto-emit diag saat error/clamp.
- **Bukti SDK**: SDK pakai `ASSERT` (crash) — bukan model diag. AOTopsy model
  diag lebih RE-friendly tapi tidak terintegrasi.
- **Dampak**: RE diag tidak konsisten — beberapa call site lupa capture offset,
  diag jadi `offset=0` atau offset setelah-consume (salah). Tidak ada
  auto-diag untuk overflow/clamp.
- **Usulan**: Tambah `Stream.LastErrorOffset() int` atau wrap error dengan
  offset: `type StreamError struct{ Offset int; Kind DiagKind; Err error }`.
  Atau beri `Stream` field `Diags *Diags` + `Mode Mode` agar auto-emit.
  Refactor call site untuk pakai error offset bawaan.
- **Prioritas**: Sedang — kualitas RE diag.

### Gap 10: `Mode`/`Options` tidak dipakai `Stream` — tidak ada best-effort

- **Deskripsi**: `diag.go` define `ModeStrict`/`ModeBestEffort` dan
  `Options{Mode, MaxSteps, MaxBytes}`, tapi `Stream` tidak terima `Options`
  dan tidak implement best-effort (return placeholder + diag saat EOF/overflow).
  Konsumen (`cluster.ScanClusters`) terima `opts dartfmt.Options` tapi hanya
  pass `MaxSteps` ke loop, tidak ke Stream. `Mode` tidak berpengaruh apa pun
  di Stream.
- **Bukti SDK`: N/A (SDK crash via ASSERT). Ini fitur RE yang seharusnya
  melampaui SDK.
- **Dampak**: Mode best-effort tidak berfungsi di level stream — parse snapshot
  corrupt selalu stop di error pertama, tidak bisa lanjut dengan placeholder.
  RE pada snapshot partially-corrupt terhenti.
- **Usulan**: Tambah `NewStreamWithOpts(data, opts)` atau field `Opts` di
  `Stream`. Saat `ModeBestEffort` + EOF/overflow: return sentinel value
  (0 / NaN / "") + emit `DiagTruncated`/`DiagOverflow`. Konsumen baca
  `s.Diags()` setelah parse.
- **Prioritas**: Sedang — fitur RE advanced.

### Gap 11: `ReadTagged32` return `uint32` tapi dipakai untuk `int32_t` — tidak ada `ReadInt32`

- **Deskripsi**: SDK `Read<int32_t>` return `int32_t` (bit-cast dari
  `uint32_t` hasil `Read32`). AOTopsy `ReadTagged32() (uint32, error)` return
  unsigned. Konsumen yang butuh signed (`codesourcemap.go:129` "reinterpret as
  signed", `cluster_alloc.go:378` cid) harus manual `int32(v)`. Inkonsisten
  dengan `ReadTagged64() (int64, error)` yang return signed.
- **Bukti SDK**: `datastream.h` `Read<T>` return `T` (signed untuk int32_t).
- **Dampak**: Konsumen mudah lupa reinterpret → nilai negatif (cid < 0,
  offset negatif) salah interpretasi sebagai uint32 besar. RE bug halus.
- **Usulan**: Tambah `ReadInt32() (int32, error)` = `int32(ReadTagged32)`.
  Atau ubah `ReadTagged32` return `int32` (breaking — update konsumen).
  Konsistenkan: `ReadTagged16`→int16, `ReadTagged32`→int32, `ReadTagged64`→int64.
  Untuk uint variant, tambah `ReadUint32`/`ReadUint16` eksplisit.
- **Prioritas**: Sedang — konsistensi + RE correctness.

### Gap 12: Tidak ada peek / `AddressOfCurrentPosition` — tidak bisa scan-ahead tanpa consume

- **Deskripsi**: SDK expose `AddressOfCurrentPosition()` untuk dapat pointer
  raw ke posisi saat ini. AOTopsy `Stream` tidak punya peek/lookahead. RE
  pattern "peek byte berikutnya untuk tentukan branch" harus `ReadByte` +
  `SetPosition(pos-1)` manual. Tidak ada `PeekByte`/`PeekBytes`.
- **Bukti SDK**: `datastream.h`:
  ```cpp
  const uint8_t* AddressOfCurrentPosition() const { return current_; }
  ```
- **Dampak**: RE heuristic (sniff tag byte, detect padding) tidak elegan.
  Konsumen harus save/restore posisi manual.
- **Usulan**: Tambah `PeekByte() (byte, error)`, `PeekBytes(n) ([]byte, error)`
  (no advance), dan `AddressOfCurrentPosition() int` (return `s.pos` untuk
  indexing ke `s.data` via getter). Atau expose `Data() []byte` + `Position()`
  (sudah ada) — cukup untuk view, tapi tidak ada Peek helper.
- **Prioritas**: Rendah — convenience RE.

## Register Tracking Gaps

`internal/dartfmt` tidak punya konsep "register" (ini wire-encoding layer, bukan
CPU register tracker). Yang relevan adalah **state stream** yang tidak ditrack:

| State | AOTopsy | SDK | Gap |
|---|---|---|---|
| `Position()` | ✅ | ✅ | — |
| `Remaining()`/`PendingBytes()` | ✅ | ✅ | — |
| `AddressOfCurrentPosition()` | ❌ | ✅ | Gap 12 |
| `bytes_written()` (writer) | N/A (reader only) | ✅ | — (out of scope) |
| Last error offset | ❌ | N/A (ASSERT) | Gap 9 |
| Diag accumulation in-stream | ❌ | N/A | Gap 9, 10 |
| Mode/Options in-stream | ❌ (defined, unused) | N/A | Gap 10 |
| Alignment offset | ❌ | ✅ | Gap 5 |

Tidak ada register CPU yang ditrack di layer ini (bukan scope). Tidak ada
"cluster boundary" tracking di Stream — Stream tidak tahu cluster start/end,
jadi tidak bisa deteksi read melewati cluster boundary (RE forensik penting).
**Gap tambahan**: `Stream` tidak punya konsep `end` per-cluster — `end` selalu
`len(data)` (full snapshot). SDK juga tidak, tapi AOTopsy bisa tambah
`NewStreamBounded(data, start, end)` untuk deteksi over-read cluster.

## Fitur RE Missing/Incomplete

1. **Cluster boundary detection** — Stream tidak tahu batas cluster; over-read
   ke cluster berikutnya tidak terdeteksi. Usulan: `NewStreamBounded(data, start, end)`.
2. **Read counter / bytes-consumed metric** — tidak ada tracking "berapa byte
   dikonsumsi per call" untuk RE profiling. Usulan: `BytesConsumed() int` reset.
3. **Hex dump helper** — tidak ada `HexDump(n)` untuk RE debug visual.
   `fill_code.go:65` manual `hexBytes, _ := s.ReadBytes(30)` lalu format sendiri.
4. **Tag/byte annotation** — tidak ada way untuk tag offset dengan note
   ("cluster header start", "alloc section") untuk RE report. Hanya `Diag`
   error-centric, tidak ada info-centric annotation.
5. **Round-trip writer** — AOTopsy hanya reader. Untuk RE fuzzing/patching,
   writer (WriteUnsigned/WriteTagged/WriteRefId) berguna. SDK punya
   `BaseWriteStream`. Out of scope saat ini, tapi gap untuk tooling RE
   advanced (snapshot patcher).
6. **Version-aware decode** — `Stream` tidak tahu `snapshot.VersionProfile`.
   Beberapa encoding berubah antar versi (e.g. `FillRefUnsigned` ≤2.17 pakai
   `ReadUnsigned` untuk ref, ≥2.18 pakai `ReadRefId`). Logic versioning ada di
   konsumen (`fill.go:368`), bukan di Stream. Gap: tidak ada enkapsulasi.
7. **CSM `readLEB128` silent overflow bug** — `compressedstackmaps.go:189`
   `return 0, pos, nil` saat shift>=64. Harus error/diag. (Lihat Gap 2.)
8. **No `ReadBytes` length cap** — `ReadBytes(n)` dengan `n` dari input corrupt
   bisa alokasi besar. Tidak ada `MaxBytes` enforcement di Stream meski
   `Options.MaxBytes` defined. DoS risk + RE crash pada corrupt snapshot.

## Verifikasi SDK

### Sumber diverifikasi

| File SDK | Tag | Metode | Hasil |
|---|---|---|---|
| `runtime/vm/datastream.h` | `3.7.0` | `gh api ... contents/...?ref=3.7.0` | ✅ Konstanta, `ReadUnsigned`, `Read<T>`, `Read16/32/64`, `ReadRefId` (4 STAGE), `ReadLEB128/SLEB128`, `ReadWordWith32BitReads`, `Align(alignment, offset)`, `AddressOfCurrentPosition`, `ReadBytes(memmove)`, `BaseWriteStream::WriteRefId` (IsUint(28)) — semua diverifikasi |
| `runtime/vm/app_snapshot.cc` | `main` (grep MCP) | `searchGitHub` query `ReadRefId()` repo `dart-lang/sdk` | ✅ `ReadUnsigned64()`, `ReadWordWith32BitReads()`, `ReadRef()` = `Ref(ReadRefId())` |
| `runtime/vm/module_snapshot.cc` | `main` (grep MCP) | `searchGitHub` | ✅ Sama + konfirmasi `ReadUnsigned<uint64_t>()` template |

### Cross-check konstanta

| Konstanta | AOTopsy (`stream.go:114-128`) | SDK (`datastream.h` @3.7.0) | Match |
|---|---|---|---|
| `dataBitsPerByte` | 7 | `kDataBitsPerByte = 7` | ✅ |
| `byteMask` | 0x7f | `kByteMask = 0x7f` | ✅ |
| `maxUnsignedDataPerByte` | 127 | `kMaxUnsignedDataPerByte = 127` | ✅ |
| `endUnsignedByteMarker` | 128 | `kEndUnsignedByteMarker = 128` | ✅ |
| `minDataPerByte` | -64 | `kMinDataPerByte = -64` | ✅ |
| `maxDataPerByte` | 63 (`^byte(0x40) & 0x7f`) | `kMaxDataPerByte = (~-64 & 0x7f) = 63` | ✅ |
| `endByteMarker` | 192 | `kEndByteMarker = 192` | ✅ |

### Cross-check algoritma

| Fungsi | AOTopsy | SDK | Verdict |
|---|---|---|---|
| `ReadUnsigned` | loop, shift>=63 overrun | loop template, no overflow check | AOTopsy lebih ketat ✅ |
| `ReadTagged32` | loop uint32, shift>=28 overrun | unrolled 4 BODY + END(28), uint32 bit-cast | **Setara untuk valid input**; AOTopsy tidak fixed-width (bisa baca 5+ byte untuk corrupt) |
| `ReadTagged64` | loop int64, shift>=63 overrun | unrolled 8 BODY + END(63), int64 bit-cast | Setara untuk valid input |
| `ReadRefId` | loop 5 iter, +128 | 4 STAGE + ASSERT(byte<0), +128 | **AOTopsy lebih longgar** (Gap 6) |
| `ReadDouble` | Tagged64 + Float64frombits | `Raw<8,double>::Read` = Read64 bit-cast | ✅ |
| `Align` | round-up relatif 0 | round-up relatif offset | **Gap 5** |
| `ReadCString` | null-terminated | (SDK manual di deserializer) | AOTopsy helper, OK |
| `ReadLEB128/SLEB128` | ❌ tidak ada | ✅ method stream | **Gap 2** |
| `Read16` | ❌ → pakai Read32 | ✅ terpisah | **Gap 1** |
| `ReadWordWith32BitReads` | ❌ | ✅ | **Gap 3** |
| `ReadFloat` | ❌ | ✅ (Raw<4,float>) | **Gap 4** |
| `ReadUnsigned64` | ❌ (ReadUnsigned=int64) | ✅ eksplisit | **Gap 7** |
| `AddressOfCurrentPosition` | ❌ | ✅ | **Gap 12** |

### Catatan verifikasi

- `clustered_snapshot.cc` tidak ditemukan di tag `3.7.0` maupun `2.17.6`
  (kemungkinan dihapus/dipindah ke `app_snapshot.cc`/`module_snapshot.cc`).
  Verifikasi decode cluster utama via `app_snapshot.cc` (grep MCP) —
  `ReadRefId`/`ReadUnsigned`/`ReadWordWith32BitReads` confirmed dipakai.
- `datastream.h` @3.7.0 adalah sumber kanonik untuk wire encoding; semua
  konstanta dan algoritma utama diverifikasi via `gh api` raw fetch.
- Tidak ada build/test/run AOTopsy dijalankan (sesuai instruksi).
