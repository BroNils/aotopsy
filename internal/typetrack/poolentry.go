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
// Both then checked PoolClassByIndex before PoolClosureClass, which made
// the closure branch unreachable on either architecture -- see below.
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
	// Before PoolClassByIndex, not after.
	//
	// A Closure pool entry also has a class -- kClosureCid -- so
	// PoolClassByIndex has an entry for it and, checked first, returned
	// KnownClass(kClosureCid) every single time. The branch below was
	// therefore unreachable, and with it the whole Closure.function /
	// entry_point_ field-load path in both architectures' load handlers:
	// dead code guarded by a stub name nothing ever produced.
	//
	// "It is a _Closure" is also the least useful true thing to say about
	// the slot. "Closure:<ownerCID>" carries the owner class AND keeps the
	// pool index, which is what the field load needs to name the tear-off.
	if classID, ok := ctx.PoolClosureClass[poolIdx]; ok && classID >= 0 {
		return KnownStub("Closure:"+strconv.Itoa(classID), poolIdx), true
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
		// This was nearly reversed on the strength of a metric. Turning
		// type-testing-stub naming on for Dart 2.x made this branch fire
		// there for the first time, and field_type_declared_hits fell by
		// exactly 1176 on dart-2.12.0-arm64. The comment then said the
		// branch was discarding "kTypeCid", which is false -- poolEntryClassID
		// takes an explicit hop to the DESCRIBED class -- so the drop read
		// like a real regression.
		//
		// It was not. Every one of the 22 field records that disappeared was
		// an offset-8 read attributed to an abstract or generic class that
		// only ever appears in the pool as a Type: Iterable, Stream,
		// Animation, Route, MapEntry, ModalRoute, StreamSubscription, most
		// of them labelled `type_arguments_field`. They were fabrications,
		// and losing them is the point. Preferring the class also measured
		// WORSE where the stub matters: 979 -> 892 resolved BLR and -66
		// instance-field hits on dart-3.3.0-gt-arm64.
		if ttsName, ok := ctx.TypeTestingStubNames[poolIdx]; ok && ttsName != "" {
			return KnownStub("TTS:"+ttsName, byteOff), true
		}
		if ctx.InstantiatedClasses != nil {
			ctx.InstantiatedClasses[classID] = true
		}
		return KnownClass(classID), true
	}
	return Top(), false
}
