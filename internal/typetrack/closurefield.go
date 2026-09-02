package typetrack

import "strings"

// closureFunctionOffset is the byte offset of UntaggedClosure.function
// from a TAGGED Closure pointer.
//
// Layout (raw_object.h, verified via gh api at 3.9.2 and 3.12.2): an
// 8-byte header, then instantiator_type_arguments, function_type_arguments,
// delayed_type_arguments, function, context, hash -- all pointer-sized --
// and finally ONLY_IN_PRECOMPILED(uword entry_point_).
//
//	compressed (4-byte fields)   function @ 8+12 = 20 untagged, 19 tagged
//	                             entry_point_ @ 8+24 = 32,      31 tagged
//	uncompressed (8-byte)        function @ 8+24 = 32,          31 tagged
//	                             entry_point_ @ 8+48 = 56,      55 tagged
//
// So 31 means `function` in one build and `entry_point_` in the other.
// Accepting both 19 and 31 unconditionally -- which is what these
// handlers did -- reads the entry point as a Function in every compressed
// build and types the destination as the closure's owner class. That is a
// confident wrong answer, not a missing one.
func closureFunctionOffset(ctx *TypeContext) int {
	return 8 + 3*closureWordSize(ctx) - 1
}

// closureEntryPointOffset is the byte offset of
// ONLY_IN_PRECOMPILED(entry_point_) from a tagged Closure pointer.
func closureEntryPointOffset(ctx *TypeContext) int {
	return 8 + 6*closureWordSize(ctx) - 1
}

func closureWordSize(ctx *TypeContext) int {
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
	if !strings.HasPrefix(sn, "Closure:") {
		return Top(), false
	}
	switch byteOff {
	case closureFunctionOffset(ctx):
		// StubOff holds the PP index the closure came from; the pool
		// record maps it to the owner class ID, and a closure's
		// function field holds a Function whose owner IS that class.
		if ctx.PoolClosureClass != nil {
			if ownerCID, ok := ctx.PoolClosureClass[base.StubOff]; ok && ownerCID >= 0 {
				return KnownClass(ownerCID), true
			}
		}
	case closureEntryPointOffset(ctx):
		// entry_point_ is the cached code address, not a Function. It is
		// what a closure call actually branches to, so carry it as a
		// stub name handleBLR can resolve -- rather than mistyping the
		// register as the closure's owner class, which is what matching
		// offset 31 unconditionally used to do.
		return KnownStub("ClosureEntry:"+sn[len("Closure:"):], base.StubOff), true
	}
	return Top(), false
}
