package cluster

// CodeImage is the instructions image that CodeRanges are cut from: the
// raw bytes, the virtual address they load at, and the offset the
// snapshot's PCOffsets are measured from.
//
// The three-line arithmetic below -- subtract CodeOff, add CodeVA, clamp
// to len(Code) -- was written out by hand at nineteen call sites across
// six packages. Every copy was an opportunity to forget the clamp or the
// underflow check, and several did: the ones that only needed a VA
// skipped both, so a range starting before the image produced a wildly
// wrong address instead of being rejected.
//
// This lives in cluster rather than analysis because CodeRange lives
// here, so naming, funcdiff, frida and cmd/ can all reach it. An
// analysis-level CodeImage embeds this one and adds the naming lookups
// that need internal/naming.
type CodeImage struct {
	Code    []byte
	CodeVA  uint64
	CodeOff uint64
}

// FuncVA returns the virtual address r begins at.
//
// It reports false for a zero-size range and for one starting before
// CodeOff. That second case is why this returns a bool at all: PCOffset
// and CodeOff are unsigned, so the subtraction wraps rather than going
// negative, and an unchecked caller gets an address near 2^64 that will
// never match anything but also never announces itself.
func (im CodeImage) FuncVA(r CodeRange) (uint64, bool) {
	if r.Size == 0 {
		return 0, false
	}
	return im.VAAt(r.PCOffset)
}

// VAAt maps a bare PCOffset to its virtual address, for callers holding
// something other than a CodeRange -- InstrTableEntry, chiefly, which
// carries a PCOffset but no Size and so cannot use FuncVA.
func (im CodeImage) VAAt(pcOffset uint32) (uint64, bool) {
	if uint64(pcOffset) < im.CodeOff {
		return 0, false
	}
	return im.CodeVA + (uint64(pcOffset) - im.CodeOff), true
}

// Slice returns r's bytes, clamped to the end of the image, and its
// virtual address.
//
// Clamping is deliberate: the last range in an image routinely claims a
// size that runs past the bytes actually present, and the callers that
// disassemble want as much of the function as exists. Callers that must
// reject a partial range -- content hashing, where a short read produces
// a hash for something that is not the function -- want SliceExact.
func (im CodeImage) Slice(r CodeRange) (code []byte, va uint64, ok bool) {
	va, ok = im.FuncVA(r)
	if !ok {
		return nil, 0, false
	}
	if len(im.Code) == 0 {
		// A VA-only image (no bytes loaded). The address is still
		// meaningful; there is simply nothing to cut.
		return nil, va, true
	}
	start := uint64(r.PCOffset) - im.CodeOff
	if start >= uint64(len(im.Code)) {
		return nil, 0, false
	}
	end := start + uint64(r.Size)
	if end > uint64(len(im.Code)) {
		end = uint64(len(im.Code))
	}
	if start >= end {
		return nil, 0, false
	}
	return im.Code[start:end], va, true
}

// SliceExact returns r's bytes only when the whole range is present in
// the image, and false otherwise.
//
// This is the all-or-nothing counterpart to Slice, for callers whose
// result is meaningless on a partial range. funcdiff is the one: it
// SHA-256s the bytes, and hashing a truncated function yields a digest
// that differs from every other build for a reason that has nothing to
// do with the code changing.
func (im CodeImage) SliceExact(r CodeRange) (code []byte, va uint64, ok bool) {
	va, ok = im.FuncVA(r)
	if !ok || len(im.Code) == 0 {
		return nil, 0, false
	}
	start := uint64(r.PCOffset) - im.CodeOff
	end := start + uint64(r.Size)
	if end > uint64(len(im.Code)) {
		return nil, 0, false
	}
	return im.Code[start:end], va, true
}
