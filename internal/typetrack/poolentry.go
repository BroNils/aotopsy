package typetrack

import "strconv"

// ResolvePoolEntry maps an object-pool slot to what a register holding it
// knows, in the order that matters.
//
// This was implemented twice. The ARM64 path checked four sources;
// the x86_64 path checked one and a half:
//
//	                        arm64   x86_64 (before)
//	PoolUnlinkedCallNames     yes     no
//	PoolCodeNames             yes     no
//	TypeTestingStubNames      yes     no
//	PoolClassByIndex          yes     yes
//	PoolClosureClass          yes     yes, but as KnownClass
//
// The missing three are all the ones that produce a NAME. Without them an
// x86_64 pool load of a Code object, an unlinked call or a type-testing
// stub typed the register as kCodeCid -- true and useless, because
// resolveBLR needs the function name, not the class of the object holding
// it.
//
// The closure difference is subtler and just as damaging: KnownClass
// loses the pool index, so a later Closure.function load has nothing to
// trace back to and cannot recover the owner class.
//
// byteOff is carried in the returned lattice for the stub forms because
// downstream field-load handlers match on it; the closure form carries
// the pool index instead, for the same reason.
func ResolvePoolEntry(ctx *TypeContext, poolIdx, byteOff int) (TypeLattice, bool) {
	if ctx == nil {
		return Top(), false
	}
	if name, ok := ctx.PoolUnlinkedCallNames[poolIdx]; ok && name != "" {
		return KnownStub("UnlinkedCall:"+name, byteOff), true
	}
	// Before PoolClassByIndex: a Code object in the pool should be named
	// (PPCode:funcName), not typed as KnownClass(kCodeCid).
	if name, ok := ctx.PoolCodeNames[poolIdx]; ok && name != "" {
		return KnownStub("PPCode:"+name, byteOff), true
	}
	if classID, ok := ctx.PoolClassByIndex[poolIdx]; ok && classID >= 0 {
		// A Type with a known type-testing stub is more useful as that
		// stub's name than as kTypeCid.
		if ttsName, ok := ctx.TypeTestingStubNames[poolIdx]; ok && ttsName != "" {
			return KnownStub("TTS:"+ttsName, byteOff), true
		}
		if ctx.InstantiatedClasses != nil {
			ctx.InstantiatedClasses[classID] = true
		}
		return KnownClass(classID), true
	}
	if classID, ok := ctx.PoolClosureClass[poolIdx]; ok && classID >= 0 {
		return KnownStub("Closure:"+strconv.Itoa(classID), poolIdx), true
	}
	return Top(), false
}
