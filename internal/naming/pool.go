package naming

import (
	"fmt"

	"aotopsy/internal/cluster"
	"aotopsy/internal/vmtables"
	"aotopsy/internal/snapshot"
)

// CodeNameInfo holds resolved function and owner names for a code ref.
type CodeNameInfo struct {
	FuncName   string
	OwnerName  string
	ParamCount int // total visible parameters (fixed + optional, excluding implicit 'this')

	// FixedParamsWithReceiver is num_fixed_parameters as the SDK counts it:
	// the fixed parameters INCLUDING the implicit receiver, and excluding
	// optionals. It is what locates a parameter's stack slot on the Dart
	// versions that pass arguments on the stack -- parameter i of a function
	// with N fixed parameters sits at FP + (kParamEndSlotFromFp + N - i) *
	// wordSize, so the receiver is the highest slot. 0 when unknown.
	FixedParamsWithReceiver int
	// IsConstructor marks a generative constructor or factory, recovered
	// from UntaggedFunction::Kind. See cluster.NamedObject.IsConstructor.
	IsConstructor bool

	// IsAllocationStub marks a Code whose owner is a Class rather than a
	// Function. UntaggedCode.owner_ holds a Function, a Class, or an
	// AbstractType, and each spells its name differently; the Class case is
	// the per-class allocation stub. See isAllocationStubOwner.
	IsAllocationStub bool

	// EnclosingFunction is the class-qualified name of the function a closure
	// was declared inside, from ClosureData.parent_function. Empty for
	// non-closures. It, not OwnerName, qualifies a closure's displayed name --
	// see CodeNameInfo.Qualified and BuildClosureParents.
	EnclosingFunction string
}


// PoolLookups holds the lookup maps needed for pool entry resolution.
type PoolLookups struct {
	RefToStr       map[int]string
	RefToNamed     map[int]*cluster.NamedObject
	RefCID         map[int]int
	CodeRefDisplay map[int]string
	CodeNames      map[int]CodeNameInfo
	VmRefToStr     map[int]string // VM snapshot strings by ref ID
	VmRefCID       map[int]int    // VM snapshot CID by ref ID
	VmRefToNamed   map[int]*cluster.NamedObject
	CT             *snapshot.CIDTable
	BaseObjLimit   int
	// BaseObjectNames holds the SDK's own display names for the VM-isolate
	// base objects, indexed from 0 so entry i is reference ID i+1. Nil when
	// the Dart version is outside the verified table, in which case those
	// refs simply stay unnamed. See snapshot.BaseObjectNames.
	BaseObjectNames []string
	// TypeTestingStubNames maps a Type's reference ID to the display name of
	// the stub that tests it. Built once in BuildPoolLookups; used both to
	// name the stub Codes themselves and to resolve indirect calls that
	// invoke one. Nil on versions that cannot resolve a Type to its class.
	// See buildTypeTestingStubNames.
	TypeTestingStubNames map[int]string
	// ClosureParents maps a closure Function's ref ID to the name of the
	// function it was declared inside (BuildClosureParents). Both the
	// Code-name path and the pool-display path qualify a closure by its
	// enclosing function so that the SDK's own convention -- a non-implicit
	// closure prints as `parent.<anonymous closure>`, FunctionPrintNameHelper
	// -- is spoken consistently. Without it, every anonymous closure loaded
	// through the object pool renders as the bare, indistinguishable
	// `<anonymous closure>` (measured: 565 of them on 3.12.2, 362 on 2.17.6,
	// all identical). Implicit closures (tear-offs) are absent from this map
	// by construction, so they keep their single, un-doubled name.
	ClosureParents map[int]string
}

// BuildPoolLookups builds the lookup maps from a fill result.
// vmResult is optional — if non-nil, VM snapshot strings/names are used to resolve base object refs.
// codeIndexOneBased must be true for Dart ≥2.16 (see VersionProfile.CodeIndexOneBased).
// dartVersion selects the VM-isolate base object name table; pass "" to leave
// those references unnamed.
// typeClassIDIsRef must be VersionProfile.TypeClassIdIsRef: on those versions
// a Type cannot be resolved to its class, which disables type-testing-stub
// naming rather than letting it emit confidently wrong labels. See
// buildTypeTestingStubNames.
func BuildPoolLookups(result *cluster.Result, ct *snapshot.CIDTable, vmResult *cluster.Result, codeIndexOneBased bool, dartVersion string, typeClassIDIsRef bool) *PoolLookups {
	l := &PoolLookups{
		RefToStr:        make(map[int]string),
		RefToNamed:      make(map[int]*cluster.NamedObject),
		RefCID:          make(map[int]int),
		CodeRefDisplay:  make(map[int]string),
		VmRefToStr:      make(map[int]string),
		VmRefCID:        make(map[int]int),
		VmRefToNamed:    make(map[int]*cluster.NamedObject),
		CT:              ct,
		BaseObjLimit:    int(result.Header.NumBaseObjects) + 1,
		BaseObjectNames: snapshot.BaseObjectNames(dartVersion),
	}

	for _, ps := range result.Strings {
		l.RefToStr[ps.RefID] = ps.Value
	}
	for i := range result.Named {
		no := &result.Named[i]
		l.RefToNamed[no.RefID] = no
	}
	for _, cm := range result.Clusters {
		for ref := cm.StartRef; ref < cm.StopRef; ref++ {
			l.RefCID[ref] = cm.CID
		}
	}

	// Populate VM lookups from VM snapshot result.
	if vmResult != nil {
		for _, ps := range vmResult.Strings {
			l.VmRefToStr[ps.RefID] = ps.Value
		}
		for i := range vmResult.Named {
			no := &vmResult.Named[i]
			l.VmRefToNamed[no.RefID] = no
		}
		for _, cm := range vmResult.Clusters {
			for ref := cm.StartRef; ref < cm.StopRef; ref++ {
				l.VmRefCID[ref] = cm.CID
			}
		}
	}

	// Build FunctionType ref→info lookup for parameter count resolution.
	funcTypeByRef := make(map[int]*cluster.FuncTypeInfo, len(result.FuncTypes))
	for i := range result.FuncTypes {
		ft := &result.FuncTypes[i]
		funcTypeByRef[ft.RefID] = ft
	}

	// Closure Function ref → enclosing function name, so a closure's displayed
	// name is qualified by the function that declared it rather than only its
	// class. RefToNamed is fully populated above, which is all this needs.
	closureParents := BuildClosureParents(result, l)
	l.ClosureParents = closureParents

	byCodeIndex := CodeIndexToFunc(result, ct, codeIndexOneBased)

	// Build code ref→name.
	l.CodeNames = make(map[int]CodeNameInfo)
	ttsNames := buildTypeTestingStubNames(result, l, ct, typeClassIDIsRef)
	l.TypeTestingStubNames = ttsNames
	for _, ce := range result.Codes {
		owner, ok := ResolveCodeOwner(ce, l.RefToNamed, byCodeIndex)
		if !ok {
			// A Code with no Function owner is not necessarily anonymous:
			// the SDK gives a type-testing stub the tested Type as its
			// owner (type_testing_stubs.cc, `code.set_owner(type)`), which
			// is why these fail both the CodeIndex cross-reference and the
			// RefToNamed lookup. See buildTypeTestingStubNames.
			if name := ttsNames[ce.OwnerRef]; name != "" {
				l.CodeNames[ce.RefID] = CodeNameInfo{FuncName: name}
			}
			continue
		}
		// ResolveName only consults the app-isolate string table. A
		// Function's NameRefID can point into the VM-isolate base-object
		// region instead -- shared objects and strings common to every app
		// built with this Dart SDK -- and that is the SAME gap already
		// fixed in ResolvePoolDisplay below and in refinfo.go's
		// listToplevelFunctions, both of which try ResolveVMName second.
		// This call site never did, so those Codes fell through to the
		// `sub_<pcOffset>` placeholder in qualifiedCodeNameLocal.
		//
		// Measured before changing anything: of the ranges whose name came
		// back empty, the ones where an owner WAS resolved are 910 of 1335
		// on the 3.12 x86_64 sample and 877 of 1286 on 3.x ARM64 -- and
		// every single one of them, 910 of 910 and 877 of 877, resolves
		// through the VM table.
		funcName := l.ResolveName(owner)
		if funcName == "" {
			funcName = l.ResolveVMName(owner)
		}
		ci := CodeNameInfo{
			FuncName:          funcName,
			OwnerName:         l.ResolveOwnerName(owner),
			EnclosingFunction: closureParents[owner.RefID],
		}
		// Dart names a constructor after its class -- `Duration`,
		// `_GrowableList.of` -- so without UntaggedFunction::Kind it is
		// indistinguishable from an ordinary method. 1231 of the 8346
		// functions on the 3.12.2 x86_64 sample are constructors, and every
		// one of them read as a plain method. The SDK's own symbol names
		// spell it `new Duration`; this matches that.
		if owner.IsConstructor() && funcName != "" {
			ci.FuncName = "new " + funcName
			ci.IsConstructor = true
		}
		if isAllocationStubOwner(owner, l.CT) && funcName != "" {
			ci.FuncName = "new " + funcName
			ci.IsAllocationStub = true
		}
		// Follow Function→FunctionType chain for parameter count.
		if owner.SignatureRefID > 0 {
			if ft, ok := funcTypeByRef[owner.SignatureRefID]; ok {
				ci.ParamCount = ft.NumFixed + ft.NumOptional
				ci.FixedParamsWithReceiver = ft.NumFixed
				if ft.HasImplicit {
					ci.FixedParamsWithReceiver++
				}
			}
		}
		// Dart 2.x keeps arity on the Function object instead
		// (UntaggedFunction.packed_fields_), so the signature chain above
		// yields nothing there and ParamCount came out 0 for EVERY 2.x
		// function. num_fixed_parameters counts the implicit receiver, and
		// kind_tag_ says whether there is one, so the visible count is
		// fixed + optional minus the receiver for instance methods.
		if ci.ParamCount == 0 && owner.NumFixedParams >= 0 {
			visible := owner.NumFixedParams + owner.NumOptionalParams
			if owner.HasKindTag && !owner.IsStatic && visible > 0 {
				visible--
			}
			ci.ParamCount = visible
			// owner.NumFixedParams already counts the receiver.
			ci.FixedParamsWithReceiver = owner.NumFixedParams
		}
		l.CodeNames[ce.RefID] = ci
	}
	for _, ce := range result.Codes {
		ci := l.CodeNames[ce.RefID]
		if ci.FuncName != "" {
			if ci.OwnerName != "" {
				l.CodeRefDisplay[ce.RefID] = ci.OwnerName + "." + ci.FuncName
			} else {
				l.CodeRefDisplay[ce.RefID] = ci.FuncName
			}
		}
	}

	// Name VM stub Code objects by their cluster-order index.
	// VM stubs (WriteBarrier, AllocateObject, etc.) have no Function
	// owner — ResolveCodeOwner fails for them. Their names come from
	// VM_STUB_CODE_LIST + VM_TYPE_TESTING_STUB_CODE_LIST
	// (vmtables.VMStubNamesInClusterOrder), which is ordered by creation
	// order (VM_STUB_CODE_LIST order with TTS after Subtype7TestCache),
	// matching vmResult.Codes[i] cluster serialization order.
	//
	// This runs BEFORE the Function-owner resolution below so that stub
	// names take precedence over Function owner names. Without this
	// ordering, UnknownDartCode (which has a Function owner with a
	// null/empty name) gets named "<optimized out>" by the owner loop,
	// and the stub naming loop skips it — the correct name
	// "UnknownDartCode" is never assigned.
	//
	// X-2: Previously used VMStubNames (164 entries, no TTS), missing
	// the 9 type-testing stubs at indices 164-172. Now uses
	// VMStubNamesInClusterOrder (173 entries with TTS).
	if vmResult != nil {
		vmStubNames := vmtables.VMStubNamesInClusterOrder(dartVersion)
		if len(vmStubNames) > 0 {
			for i, ce := range vmResult.Codes {
				if i >= len(vmStubNames) {
					break
				}
				name := vmStubNames[i]
				l.CodeNames[ce.RefID] = CodeNameInfo{FuncName: name}
				l.CodeRefDisplay[ce.RefID] = name
			}
		}
	}

	// Also build CodeNames and CodeRefDisplay for VM Code objects.
	// VM Code objects (stubs, runtime entries) are referenced from the
	// app isolate's object pool but only exist in the VM snapshot.
	// Without this, PoolCodeNames has no entries for PP-loaded VM Code
	// objects, so BLR calls through them (LDR X24,[X27,PP] → LDUR
	// X30,[X24,#7] → BLR X30) are unresolved.
	//
	// This runs AFTER the stub naming loop above, so only VM Codes that
	// were NOT named by the stub list (i.e., not in
	// VM_STUB_CODE_LIST+TTS) get named via their Function owner. In
	// practice, all 173 VM Code objects are stubs, so this loop is a
	// no-op for VM snapshots — but it's kept as a safety net for any
	// future VM Code that isn't a stub.
	if vmResult != nil {
		vmByCodeIndex := CodeIndexToFunc(vmResult, ct, codeIndexOneBased)
		for _, ce := range vmResult.Codes {
			if _, exists := l.CodeNames[ce.RefID]; exists {
				continue
			}
			owner, ok := ResolveCodeOwner(ce, l.VmRefToNamed, vmByCodeIndex)
			if !ok {
				continue
			}
			funcName := l.ResolveVMName(owner)
			if funcName == "" {
				continue
			}
			ownerName := ""
			if owner.OwnerRefID >= 0 {
				if vmOwner, ok2 := l.VmRefToNamed[owner.OwnerRefID]; ok2 {
					// Route through resolveClassName, same as the isolate loop:
					// it strips the "::" top-level pseudo-class and hops a
					// PatchClass. A VM-snapshot function like dart:_runtime's
					// _runMain is owned by "::", so without this it rendered
					// `::._runMain`.
					ownerName = l.resolveClassName(vmOwner, 0)
				}
			}
			ci := CodeNameInfo{
				FuncName:  funcName,
				OwnerName: ownerName,
			}
			if owner.IsConstructor() && funcName != "" {
				ci.FuncName = "new " + funcName
				ci.IsConstructor = true
			}
			l.CodeNames[ce.RefID] = ci
			if ci.FuncName != "" {
				if ci.OwnerName != "" {
					l.CodeRefDisplay[ce.RefID] = ci.OwnerName + "." + ci.FuncName
				} else {
					l.CodeRefDisplay[ce.RefID] = ci.FuncName
				}
			}
		}
	}

	return l
}

// StringForRef resolves a ref ID to a string, falling back to the VM
// snapshot's strings for base-object refs.
//
// Both maps are needed. The app isolate's snapshot only holds strings the app
// itself introduced; short, universally-shared strings live in the VM isolate
// snapshot as base objects (ref < BaseObjLimit). Generic type parameter names
// are exactly that case -- dart:async's `runUnaryGuarded<T>` stores its name
// "T" at ref 450 on a compare_sample build whose BaseObjLimit is far above it,
// so an isolate-only lookup resolves 12 of 84 generic FunctionTypes while this
// resolves them all.
//
// VmRefCID is checked before trusting VmRefToStr, mirroring the H-4 fix in
// resolvePoolDisplay: a non-string VM base object can carry a VmRefToStr entry
// and must not be returned as a string.
func (l *PoolLookups) StringForRef(ref int) (string, bool) {
	if ref <= cluster.RefNull {
		return "", false
	}
	if s, ok := l.RefToStr[ref]; ok {
		return s, true
	}
	if ref < l.BaseObjLimit {
		if cid, ok := l.VmRefCID[ref]; ok && l.CT != nil && !isStringCID(cid, l.CT) {
			return "", false
		}
		if s, ok := l.VmRefToStr[ref]; ok {
			return s, true
		}
	}
	return "", false
}

// isStringCID reports whether a CID is one of the String subclasses.
func isStringCID(cid int, ct *snapshot.CIDTable) bool {
	return cid == ct.OneByteString || cid == ct.TwoByteString ||
		(ct.String != 0 && cid == ct.String)
}

func (l *PoolLookups) ResolveOwnerName(no *cluster.NamedObject) string {
	if no.OwnerRefID < 0 {
		return ""
	}
	owner, ok := l.RefToNamed[no.OwnerRefID]
	if !ok {
		return ""
	}
	return l.resolveClassName(owner, 0)
}

func (l *PoolLookups) ResolveName(no *cluster.NamedObject) string {
	if no.NameRefID >= 0 {
		if s, ok := l.RefToStr[no.NameRefID]; ok {
			return s
		}
	}
	return ""
}

func (l *PoolLookups) ResolveVMName(no *cluster.NamedObject) string {
	if no.NameRefID >= 0 {
		if s, ok := l.VmRefToStr[no.NameRefID]; ok {
			return s
		}
	}
	return ""
}

// resolveClassName turns a Class-or-PatchClass NamedObject into a class name,
// hopping through PatchClass and falling back to the VM string table.
//
// Two gaps this closes, both measured on the ground-truth twins where the ELF
// carries the owner and we did not (2.14.0/2.18.0/3.9.2 arm64):
//
//   - PatchClass. A function declared in a source-patched or mixin-applied
//     class has a PatchClass as its owner, and a PatchClass has no name of its
//     own -- its wrapped_class does (raw_object.h UntaggedPatchClass, ref 0,
//     captured as OwnerRefID by specPatchClass). This was the largest bucket:
//     917-1147 functions per sample whose owner is a PatchClass, every one of
//     them coming back nameless.
//   - VM base objects. A class name can live in the VM isolate snapshot rather
//     than the app's -- the same ResolveName-then-ResolveVMName gap already
//     fixed at other call sites. ~300 more per sample.
//
// depth guards against a malformed PatchClass chain pointing back at itself.
// topLevelClassName is Symbols::TopLevel -- the name of the invisible
// per-library class that owns top-level functions and fields.
const topLevelClassName = "::"

func (l *PoolLookups) resolveClassName(owner *cluster.NamedObject, depth int) string {
	if owner == nil || depth > 4 {
		return ""
	}
	// The top-level pseudo-class is named "::" (Symbols::TopLevel, verified in
	// symbol_list.h). It is not a real owner: the SDK scrubs it to "" and
	// PrintName skips it (`!cls.IsTopLevel()`), so a top-level function is
	// bare. Reporting `::._runMain` instead of `_runMain` disagreed with the
	// symbol table on ~390 functions per prose sample. The name can come from
	// EITHER string table -- a dart:_runtime function like _runMain resolves
	// its "::" owner through the VM table -- so the check must cover both.
	if n := l.ResolveName(owner); n != "" {
		if n == topLevelClassName {
			return ""
		}
		return n
	}
	if n := l.ResolveVMName(owner); n != "" {
		if n == topLevelClassName {
			return ""
		}
		return n
	}
	// A PatchClass wraps the real Class in its OwnerRefID; hop to it.
	if l.CT != nil && owner.CID == l.CT.PatchClass && owner.OwnerRefID >= 0 {
		if wrapped, ok := l.RefToNamed[owner.OwnerRefID]; ok {
			return l.resolveClassName(wrapped, depth+1)
		}
	}
	return ""
}

// QualifiedCodeName returns "Owner.Func_hexaddr" for a code refID using PoolLookups.
func QualifiedCodeName(refID int, pl *PoolLookups, pcOffset uint32) string {
	ci := pl.CodeNames[refID]
	return ci.Qualified(pcOffset)
}

// TypeParamResolver resolves a FunctionType's real per-parameter type
// names via its parameter_types Array (see cluster.FuncTypeInfo.
// ParamTypesArrayRefID's doc comment and snapshot.VersionProfile.
// FuncTypeParamTypesIdx for which Dart versions this is captured for).
// Caches Array/Type lookups once so repeated calls (e.g. once per
// top-level function) don't rebuild the same maps.
//
// KNOWN GAP, not silently papered over: an element ref only resolves to
// a real class name when it lands in Result.Types, which itself is only
// populated for the v3.x "flags-packed ClassID" Type encoding (see
// internal/cluster/fillspec.go's specType). Pre-3.x snapshots (where
// type_class_id is its own separate ref -- TypeClassIdIsRef=true in the
// version profile) have NO Type->ClassID resolution implemented
// anywhere in this pipeline yet. Confirmed empirically, not assumed: a
// real Dart 2.12.0 sample resolved 0/202 sampled parameter_types
// elements (Result.Types was simply empty for it, not an indexing
// mistake -- real Dart 3.7.0 and 3.10.7 samples resolved ~70% of
// theirs). Elements that don't resolve report "?" rather than silently
// omitting the parameter, so callers can tell "no type info" from "void
// parameter list" from "empty display".
type TypeParamResolver struct {
	arrayByRef map[int]*cluster.ArrayInfo
	typeByRef  map[int]int32
	result     *cluster.Result
	pl         *PoolLookups
}

// NewTypeParamResolver builds the resolver's caches once from an
// already-parsed Result/PoolLookups pair.
func NewTypeParamResolver(result *cluster.Result, pl *PoolLookups) *TypeParamResolver {
	r := &TypeParamResolver{result: result, pl: pl}
	r.arrayByRef = make(map[int]*cluster.ArrayInfo, len(result.Arrays))
	for i := range result.Arrays {
		r.arrayByRef[result.Arrays[i].RefID] = &result.Arrays[i]
	}
	r.typeByRef = make(map[int]int32, len(result.Types))
	for _, t := range result.Types {
		r.typeByRef[t.RefID] = t.ClassID
	}
	return r
}

// ParamTypeNames returns one display name per parameter in
// ft.ParamTypesArrayRefID's Array, or nil if ft has no captured
// parameter_types ref for this Dart version.
func (r *TypeParamResolver) ParamTypeNames(ft cluster.FuncTypeInfo) []string {
	if ft.ParamTypesArrayRefID < 0 {
		return nil
	}
	arr, ok := r.arrayByRef[ft.ParamTypesArrayRefID]
	if !ok {
		return nil
	}
	names := make([]string, len(arr.ElementRefIDs))
	for i, elemRef := range arr.ElementRefIDs {
		cid, ok := r.typeByRef[elemRef]
		if !ok {
			names[i] = "?"
			continue
		}
		names[i] = r.classDisplayName(cid)
	}
	return names
}

// classDisplayName resolves a ClassID to a name, trying (in order) the
// isolate string pool, the VM (core-library) string pool, then falling
// back to cluster.CidNameV for predefined/builtin classes with no
// snapshot-side Class record name -- mirrors cmd/aotopsy/refinfo.go's
// classNameByCID.
func (r *TypeParamResolver) classDisplayName(cid int32) string {
	for i := range r.result.Classes {
		if r.result.Classes[i].ClassID != cid {
			continue
		}
		ci := r.result.Classes[i]
		if no, ok := r.pl.RefToNamed[ci.RefID]; ok {
			if s := r.pl.ResolveName(no); s != "" {
				return s
			}
			if s := r.pl.ResolveVMName(no); s != "" {
				return s
			}
		}
		break
	}
	if r.pl.CT != nil {
		if s := cluster.CidNameV(int(cid), r.pl.CT); s != "" {
			return s
		}
	}
	return fmt.Sprintf("<cid:%d>", cid)
}

// NamedParamNames resolves a FunctionType's named_parameter_names Array
// ref to a list of parameter name strings (e.g. ["name", "age"] for
// foo({String? name, int? age})). Returns nil if the ref is null or
// unresolvable.
//
// The returned slice is aligned to the function's FULL parameter list, not
// just its named tail: positional slots are "" and only the named tail
// carries names. That is what makes it safe to index by argument position.
//
// SDK-verified: raw_object.h@3.12.2, UntaggedFunctionType has
// COMPRESSED_POINTER_FIELD(ArrayPtr, named_parameter_names) as the
// last ref in VISIT_TO. The Array's elements are String refs, resolved
// via ArrayInfo.ElementRefIDs → Strings (same chain as type parameter
// names in BuildFuncTypeParamNames).
//
// Three SDK facts shape this, and getting any of them wrong invents names:
//
//  1. The array is only populated when packed_parameter_counts'
//     HasNamedOptionalParameters bit is set. Optional POSITIONAL parameters
//     leave it as the empty array (object.cc@3.12.2 FinalizeNameArray
//     asserts exactly that when NumOptionalNamedParameters() == 0).
//
//  2. The array is LONGER than the name count. After the name Strings come
//     Smi slots holding the required-ness flag bits -- that is what
//     FunctionType::HasRequiredNamedParameters tests
//     (`parameter_names.Length() > num_named_params`). Only the first
//     NumOptional entries are names; the rest would resolve to "?" garbage.
//
//  3. Names are indexed by `index - num_fixed_parameters()`
//     (object.cc@3.12.2 FunctionType::ParameterNameAt), and the SDK's
//     num_fixed_parameters INCLUDES the implicit receiver, while
//     FuncTypeInfo.NumFixed has already subtracted it.
func (r *TypeParamResolver) NamedParamNames(ft cluster.FuncTypeInfo) []string {
	if !ft.HasNamedOptional || ft.NumOptional <= 0 {
		return nil
	}
	if ft.NamedParamNamesArrayRefID <= cluster.RefNull {
		return nil
	}
	arr, ok := r.arrayByRef[ft.NamedParamNamesArrayRefID]
	if !ok || len(arr.ElementRefIDs) < ft.NumOptional {
		return nil
	}
	// Fact 3: rebuild the SDK's num_fixed_parameters.
	numFixed := ft.NumFixed
	if ft.HasImplicit {
		numFixed++
	}
	names := make([]string, numFixed+ft.NumOptional)
	// Fact 2: only the first NumOptional elements are names.
	for i, elemRef := range arr.ElementRefIDs[:ft.NumOptional] {
		s, ok := r.pl.StringForRef(elemRef)
		if !ok || s == "" {
			names[numFixed+i] = "?"
			continue
		}
		names[numFixed+i] = s
	}
	return names
}

// baseObjectName returns the SDK display name for a base-object reference,
// or "" when the ref is not one or the Dart version is not in the table.
//
// `null` is ref 1 in every version from 2.12 to 3.12, so it resolves even
// without a table entry; everything else needs one, because the ordering
// shifts between versions.
func (l *PoolLookups) baseObjectName(refID int) string {
	if refID == 1 {
		return "null"
	}
	if refID < 1 || refID > len(l.BaseObjectNames) {
		return ""
	}
	return l.BaseObjectNames[refID-1]
}

// ResolvePoolDisplay builds a map from pool entry index to display string.
func ResolvePoolDisplay(pool []cluster.PoolEntry, l *PoolLookups) map[int]string {
	display := make(map[int]string, len(pool))
	for _, pe := range pool {
		switch pe.Kind {
		case cluster.PoolTagged:
			// Only quote as a string if the pool entry's actual object
			// type is a String (C-1 fix): previously any RefToStr match
			// was quoted, but a non-string object (Instance, Class, etc.)
			// can have a RefToStr entry at the same ref ID, producing
			// false positive string references that inflate signal
			// counts and mislead the signal report.
			isStringCID := false
			if l.CT != nil {
				if cid, ok := l.RefCID[pe.RefID]; ok {
					// Non-compressed-pointers snapshots store string refs under
					// the abstract kStringCid (ct.String) cluster, not the
					// OneByteString/TwoByteString subclass CIDs. Accept all three
					// so ROData strings (the common case for desktop AOT) resolve
					// to their actual value instead of a "<String>" placeholder.
					isStringCID = cid == l.CT.OneByteString || cid == l.CT.TwoByteString || cid == l.CT.String
				} else if cid, ok := l.VmRefCID[pe.RefID]; ok {
					isStringCID = cid == l.CT.OneByteString || cid == l.CT.TwoByteString || cid == l.CT.String
				}
			}
			if isStringCID {
				if s, ok := l.RefToStr[pe.RefID]; ok {
					display[pe.Index] = fmt.Sprintf("%q", s)
				} else if s, ok := l.VmRefToStr[pe.RefID]; ok {
					display[pe.Index] = fmt.Sprintf("%q", s)
				}
			} else if no, ok := l.RefToNamed[pe.RefID]; ok {
				name := l.ResolveName(no)
				if name == "" {
					// ResolveName only checks the app-isolate string table
					// (RefToStr). A NamedObject's NameRefID can just as
					// well point into the VM-isolate base-object region
					// instead (shared objects/strings common across every
					// app using this Dart SDK build) -- confirmed a real,
					// same-class gap as the one fixed in LoadContext/
					// decompile_native_cmd.go for pool-level VmRefToStr
					// lookups: this call site never tried ResolveVMName as
					// a fallback, so a resolvable name here still fell
					// through to a generic "<ClassName>" placeholder.
					// cmd/aotopsy/refinfo.go's listToplevelFunctions
					// already uses exactly this ResolveName-then-
					// ResolveVMName fallback pattern; mirrored here.
					name = l.ResolveVMName(no)
				}
				if name != "" {
					// Fields share leaf names across owners (e.g. uHb on Wja, Yja, aka).
					// Qualify with owner when available so pool dumps disambiguate them.
					if l.CT != nil && no.CID == l.CT.Field {
						if owner := l.ResolveOwnerName(no); owner != "" {
							name = owner + "." + name
						}
					}
					// A closure Function is qualified by the function it was
					// declared inside, the same as the Code-name path does via
					// CodeNameInfo.EnclosingFunction. Every anonymous closure's
					// own name is the bare, shared `<anonymous closure>`, so
					// without this the object pool renders hundreds of them
					// identically; the enclosing function is what tells them
					// apart. Gated on ClosureParents membership, which
					// BuildClosureParents populates only for non-implicit
					// closures that have a distinct parent -- so a tear-off or a
					// self-referential closure is left untouched.
					if parent := l.ClosureParents[pe.RefID]; parent != "" {
						name = parent + "." + name
					}
					display[pe.Index] = name
				} else {
					display[pe.Index] = fmt.Sprintf("<%s>", cluster.CidNameV(no.CID, l.CT))
				}
			} else if fn, ok := l.CodeRefDisplay[pe.RefID]; ok {
				display[pe.Index] = fn
			} else if cidNum, ok := l.RefCID[pe.RefID]; ok {
				cidName := cluster.CidNameV(cidNum, l.CT)
				if cidName != "" {
					display[pe.Index] = fmt.Sprintf("<%s>", cidName)
				} else {
					display[pe.Index] = fmt.Sprintf("<Instance_%d>", cidNum)
				}
			} else if name := l.baseObjectName(pe.RefID); name != "" {
				// A VM-isolate base object. These are never written into the
				// snapshot -- the deserializer assigns them reference IDs in
				// a fixed order first -- so the reference ID IS the identity,
				// and the SDK's AddBaseObjects supplies the display name.
				//
				// Only `null` (always ref 1) used to be handled here, which
				// is why x86_64 output contained zero `false`: on that
				// architecture bools reach the code through the object pool
				// rather than through a null-register offset.
				display[pe.Index] = name
			} else if pe.RefID > 0 && pe.RefID < l.BaseObjLimit {
				// Try resolving from VM snapshot lookups.
				// H-4 fix: check VmRefCID before quoting as string, same as
				// the app-isolate C-1 fix above. Without this, non-string VM
				// base objects (Instance, Class, etc.) that happen to have a
				// VmRefToStr entry get falsely quoted as strings.
				if s, ok := l.VmRefToStr[pe.RefID]; ok {
					isVMStringCID := false
					if l.CT != nil {
						if cid, ok2 := l.VmRefCID[pe.RefID]; ok2 {
							isVMStringCID = cid == l.CT.OneByteString || cid == l.CT.TwoByteString || cid == l.CT.String
						}
					}
					if isVMStringCID {
						display[pe.Index] = fmt.Sprintf("%q", s)
					} else {
						display[pe.Index] = s
					}
				} else if no, ok := l.VmRefToNamed[pe.RefID]; ok {
					name := l.ResolveVMName(no)
					if name != "" {
						display[pe.Index] = name
					} else {
						display[pe.Index] = fmt.Sprintf("<vm:%s>", cluster.CidNameV(no.CID, l.CT))
					}
				} else if cidNum, ok := l.VmRefCID[pe.RefID]; ok {
					cidName := cluster.CidNameV(cidNum, l.CT)
					if cidName != "" {
						display[pe.Index] = fmt.Sprintf("<vm:%s>", cidName)
					} else {
						display[pe.Index] = fmt.Sprintf("<vm:%d>", pe.RefID)
					}
				} else {
					display[pe.Index] = fmt.Sprintf("<vm:%d>", pe.RefID)
				}
			} else {
				display[pe.Index] = fmt.Sprintf("<ref:%d>", pe.RefID)
			}
		case cluster.PoolImmediate:
			// A pool immediate is a raw, UNTYPED 64-bit value; whether it is an
			// integer or an IEEE-754 double is only decided by the instruction
			// that consumes it (an FP load vs an integer load). The previous code
			// guessed "double" purely from the exponent-field bit pattern (audit
			// A7), which mis-renders any large integer whose bits happen to fall
			// in the exponent range as a bogus float -- in the SHARED pipeline
			// pool display, affecting every consumer. We render the raw value
			// here; float interpretation belongs in the decompiler's FP-load
			// operand path where the type is actually known.
			display[pe.Index] = fmt.Sprintf("0x%x", pe.Imm)
		}
	}
	return display
}

// DartClassLayout is a resolved class definition ready for export.
