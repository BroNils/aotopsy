package typetrack

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
//	PoolClosureFunctionNames  yes     yes
//
// Both then checked PoolClassByIndex before PoolClosureClass, which made
// the closure branch unreachable on either architecture -- see below.
//
// The missing three are all the ones that produce a NAME. Without them an
// x86_64 pool load of a Code object, an unlinked call or a type-testing
// stub typed the register as kCodeCid -- true and useless, because
// resolveBLR needs the function name, not the class of the object holding
// it.
//
// The closure difference is subtler and just as damaging: an object-class fact
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
	// (PPCode:funcName), not merely typed as an exact kCodeCid object.
	if name, ok := ctx.PoolCodeNames[poolIdx]; ok && name != "" {
		return KnownStub("PPCode:"+name, byteOff), true
	}
	// Before PoolClassByIndex: preserve the pool index for a Closure whose
	// exact Function identity is independently present in ClosureInfo. The owner
	// class is irrelevant to the value's runtime identity and is not carried.
	if name := ctx.PoolClosureFunctionNames[poolIdx]; name != "" {
		return KnownStub("Closure", poolIdx), true
	}
	if classID, ok := ctx.PoolClassByIndex[poolIdx]; ok && classID >= 0 {
		// A Type in the pool must NOT be typed as the class it describes.
		// The register holds a Type OBJECT; `PP[i] = Type(Iterable<X>)` is
		// not an Iterable. Field loads off it read the Type's own fields --
		// type_test_stub_entry_point_ at offset 7 and so on -- so
		// attributing them to Iterable invents accesses that never happen.
		//
		// The stub name is what the value is FOR, and it is also what keeps
		// this straight, so it wins.
		//
		if ttsName, ok := ctx.TypeTestingStubNames[poolIdx]; ok && ttsName != "" {
			return KnownStub("TTS:"+ttsName, byteOff), true
		}
		if ctx.InstantiatedClasses != nil {
			ctx.InstantiatedClasses[classID] = true
		}
		return ExactClass(classID), true
	}
	return Top(), false
}
