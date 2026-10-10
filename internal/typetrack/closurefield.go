package typetrack

import "aotopsy/internal/snapshot"

// closureFunctionOffset is the byte offset of UntaggedClosure.function
// from a TAGGED Closure pointer.
//
// Layout (exact SDK raw_object.h/runtime_offsets_extracted.h): an 8-byte
// header, then instantiator_type_arguments, function_type_arguments,
// delayed_type_arguments, function, context and hash. Dart 2.13 advertises
// compressed pointers for other object families but Closure still uses ordinary
// POINTER_FIELD slots there; Closure switches to COMPRESSED_POINTER_FIELD in
// 2.14. Dart 2.14 also adds ONLY_IN_PRECOMPILED(uword entry_point_). Dart 3.13
// redesigns Closure as a variable-length object: entry_point_ moves directly
// after the object header and function follows length_and_flags/hash.
//
//	2.13 compressed             function @ 8+24 = 32 untagged, 31 tagged
//	2.14+ compressed (4-byte)   function @ 8+12 = 20 untagged, 19 tagged
//	                             entry_point_ @ 8+24 = 32,      31 tagged
//	uncompressed (8-byte)        function @ 8+24 = 32,          31 tagged
//	                             entry_point_ @ 8+48 = 56,      55 tagged
//	3.13 compressed              function @ 28,                  27 tagged
//	3.13 uncompressed            function @ 32,                  31 tagged
//	3.13 both                    entry_point_ @ 8,                7 tagged
//
// So 31 means `function` in one build and `entry_point_` in the other.
// Accepting both 19 and 31 unconditionally -- which is what these
// handlers did -- reads the entry point as a Function in every compressed
// build and types the destination as the closure's owner class. That is a
// confident wrong answer, not a missing one.
func closureFunctionOffset(ctx *TypeContext) int {
	if ctx != nil && ctx.DartVersion != "" && snapshot.VersionAtLeast(ctx.DartVersion, "3.13.0") {
		if ctx.CompressedPointers {
			return 0x1c - 1
		}
		return 0x20 - 1
	}
	return 8 + 3*closureWordSize(ctx) - 1
}

// closureEntryPointOffset is the byte offset of
// ONLY_IN_PRECOMPILED(entry_point_) from a tagged Closure pointer.
func closureEntryPointOffset(ctx *TypeContext) int {
	if ctx != nil && ctx.DartVersion != "" && !snapshot.VersionAtLeast(ctx.DartVersion, "2.14.0") {
		return -1
	}
	if ctx != nil && ctx.DartVersion != "" && snapshot.VersionAtLeast(ctx.DartVersion, "3.13.0") {
		return 0x8 - 1
	}
	return 8 + 6*closureWordSize(ctx) - 1
}

func closureWordSize(ctx *TypeContext) int {
	if ctx != nil && ctx.CompressedPointers && ctx.DartVersion != "" &&
		!snapshot.VersionAtLeast(ctx.DartVersion, "2.14.0") {
		// Dart 2.13's UntaggedClosure still spells these fields POINTER_FIELD,
		// even though compressed pointers exist elsewhere in the same build.
		return 8
	}
	if ctx != nil && ctx.WordSize > 0 {
		return int(ctx.WordSize)
	}
	return 8
}

// ResolveClosureField types the destination of a field load whose base
// register holds a Closure, given the load's byte offset from the tagged
// pointer. It reports false when base is not a closure or the offset is
// not one of the two fields worth following.
//
// This was copy-pasted across three ARM64 load handlers (LDUR, LDUR32,
// LDR64-unsigned) and absent from the x86_64 transfer function entirely,
// so tear-off receivers resolved on ARM64 and went Top on x86_64 even
// though the x86 pool resolver already preserved the pool index the
// lookup needs. One implementation, called from both architectures.
func ResolveClosureField(ctx *TypeContext, base TypeLattice, byteOff int) (TypeLattice, bool) {
	if ctx == nil || base.Kind != LatticeKnownStub {
		return Top(), false
	}
	sn := base.StubName
	if sn != "Closure" && sn != "ClosureEntry" {
		return Top(), false
	}
	switch byteOff {
	case closureFunctionOffset(ctx):
		// The field contains a Function OBJECT. Its owner may be a Class, but
		// that does not make the Function object an instance of the owner class.
		// We do not currently carry an exact Function-object CID here, so fail
		// closed instead of fabricating the receiver/declaring class.
		return Top(), true
	case closureEntryPointOffset(ctx):
		// entry_point_ is the cached code address, not a Function. It is
		// what a closure call actually branches to, so carry it as a
		// stub name handleBLR can resolve -- rather than mistyping the
		// register as the closure's owner class, which is what matching
		// offset 31 unconditionally used to do.
		return KnownStub("ClosureEntry", base.StubOff), true
	}
	return Top(), false
}
