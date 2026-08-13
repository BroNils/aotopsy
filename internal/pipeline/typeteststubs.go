package pipeline

import (
	"fmt"

	"aotopsy/internal/cluster"
	"aotopsy/internal/snapshot"
)

// Type-testing stubs.
//
// A Code whose owner is neither a Function nor a Class looked like corrupt
// data, and the residue was large: after every other naming path had run,
// 409 of 8045 Codes on the 3.9.2 ARM64 sample still had no name, and 100 %
// of them failed the same way -- no Function claimed their cluster index,
// and Code.OwnerRef pointed at an object that is not in RefToNamed.
//
// Measured rather than guessed, the OwnerRefs split cleanly in two:
//
//	324  point at a Type (CID 49), each at a DIFFERENT one
//	 85  all share ref 1, which is Object::null() in every version
//
// The first group is not corruption. dart-lang/sdk, verified at tag 3.9.2:
//
//	runtime/vm/type_testing_stubs.cc
//	  const char* name = namer_.StubNameForType(type);
//	  ...
//	  code.set_owner(type);              // <- the owner IS the type
//
// So these are type-testing stubs, and the SDK names them
// `TypeTestingStub_<library url>_<Class>[__<type argument>...]`
// (TypeTestingStubNamer::WriteStubNameForTypeTo). They were rendering as
// `sub_<pcOffset>`.
//
// The second group is a Code with a genuinely null owner. Nothing in the
// isolate snapshot names it, so it stays a placeholder -- an honest one.
//
// KNOWN LIMITATION, measured before shipping rather than discovered after.
// Naming these requires Type -> type_class_id, which only lands in
// Result.Types for the v3.x flags-packed encoding. On versions where
// type_class_id is its own ref (VersionProfile.TypeClassIdIsRef, v2.10-2.15)
// it is not resolved anywhere in this pipeline, and the failure is silent
// and total rather than partial: a real Dart 2.12.0 sample resolved 251 of
// 251 type-owned Codes to a real-looking name, but to a SINGLE distinct
// class ("TypeParameters") for all 251. That is worse than no name -- it
// invents 251 confident, wrong labels -- so this is switched off there and
// those Codes keep the `sub_` placeholder. The same 3.x samples resolve 260
// and 271 distinct classes out of 324 and 339, which is what working looks
// like.

// buildTypeTestingStubNames maps a Type's reference ID to the display name
// for the stub that tests it. Returns nil when the Dart version cannot
// resolve a Type to its class, in which case callers simply find nothing.
func buildTypeTestingStubNames(result *cluster.Result, l *PoolLookups, ct *snapshot.CIDTable, typeClassIDIsRef bool) map[int]string {
	if typeClassIDIsRef || len(result.Types) == 0 {
		return nil
	}
	classNames := make(map[int32]string)
	for i := range result.Classes {
		ci := result.Classes[i]
		no, ok := l.RefToNamed[ci.RefID]
		if !ok {
			continue
		}
		name := l.ResolveName(no)
		if name == "" {
			name = l.ResolveVMName(no)
		}
		if name != "" {
			classNames[ci.ClassID] = name
		}
	}
	out := make(map[int]string, len(result.Types))
	for _, t := range result.Types {
		name, ok := classNames[t.ClassID]
		if !ok && ct != nil {
			// Predefined/builtin classes have no snapshot-side Class record
			// name; the SDK's own table covers them.
			name = cluster.CidNameV(int(t.ClassID), ct)
		}
		if name == "" {
			continue
		}
		out[t.RefID] = fmt.Sprintf("TypeTestingStub_%s", name)
	}
	return out
}
