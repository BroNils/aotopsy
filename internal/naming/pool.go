package naming

import (
	"fmt"

	"aotopsy/internal/cluster"
	"aotopsy/internal/sdk"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/vmtables"
)

// CodeNameInfo holds resolved function and owner names for a code ref.
type CodeNameInfo struct {
	FuncName   string
	OwnerName  string
	ParamCount int // total visible parameters (fixed + optional, excluding implicit 'this')
	// ParamCountKnown distinguishes a genuine zero-parameter declaration from
	// missing arity metadata. ParamCount alone cannot: zero was historically
	// used for both and downstream code silently treated "unknown" as no args.
	ParamCountKnown bool

	// FixedParamsWithReceiver is num_fixed_parameters as the SDK counts it:
	// the fixed parameters INCLUDING the implicit receiver, and excluding
	// optionals. 0 when unknown.
	//
	// On the Dart versions that pass arguments on the stack it is ONE of
	// three inputs that locate the receiver, not the whole answer: a
	// function with optional parameters or an async modifier copies its
	// parameters into the locals area instead, and its receiver is below FP
	// rather than above it. See cluster.ReceiverFrameSlot, which is the only
	// thing that should turn these fields into an offset.
	FixedParamsWithReceiver int
	// OptionalParams is NumOptionalParameters(). Nonzero means the function
	// copies its parameters -- the predicate is HasOptionalParameters() ||
	// IsSuspendableFunction() -- which moves the receiver below FP.
	OptionalParams int
	// IsSuspendable is modifier() != kNoModifier: async, sync* or async*.
	// The other half of the copy-parameters predicate.
	IsSuspendable bool
	// MayUseRegisterCC means the snapshot metadata does not itself rule out the
	// Dart register calling convention for this Function. It is deliberately
	// NOT the claim that the function actually uses registers: since 3.4.3 the
	// precompiler can force an otherwise eligible function back to the stack via
	// unboxing metadata, and that metadata is not serialized in a full AOT
	// snapshot. Consumers must require independent call-site evidence before
	// assigning parameters to registers.
	MayUseRegisterCC bool
	// MustUseStackCC is a stronger, source-grounded negative: versions before
	// 3.4.3, generics, closures/tear-offs and FFI trampolines cannot use the Dart
	// register calling convention. Unknown Function kinds leave both flags false.
	MustUseStackCC bool
	// ReceiverKnown/HasImplicitReceiver describe whether this Function has the
	// implicit `this` parameter. Class ownership alone is insufficient: static
	// methods are class-owned too, and seeding their arg0 with the owner class was
	// a confident false type. kind_tag_.is_static and FunctionType.HasImplicit are
	// independent sources; disagreement intentionally degrades to unknown.
	ReceiverKnown       bool
	HasImplicitReceiver bool
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

func functionCallConventionDisposition(dartVersion string, owner *cluster.NamedObject, ft *cluster.FuncTypeInfo) (mayRegister, mustStack bool) {
	if !sdk.HasDartRegisterCallingConvention(dartVersion) {
		return false, true
	}
	if owner != nil && owner.HasKindTag {
		switch owner.FuncKind {
		case cluster.FunctionKindClosure,
			cluster.FunctionKindImplicitClosure,
			cluster.FunctionKindFieldInitializer,
			cluster.FunctionKindMethodExtractor,
			cluster.FunctionKindNoSuchMethodDispatcher,
			cluster.FunctionKindInvokeFieldDispatcher,
			cluster.FunctionKindIrregexp,
			cluster.FunctionKindDynamicInvocationForwarder,
			cluster.FunctionKindFfiTrampoline:
			return false, true
		}
	}
	// Function::IsGeneric is derived from Function.signature(). The weak
	// signature is often absent from a full AOT snapshot, so lack of a captured
	// FunctionType is UNKNOWN, not evidence for stack calling. `mayRegister`
	// deliberately means "not ruled out by serialized metadata"; actual register
	// locations still require independent multi-call-site machine-code evidence.
	if ft != nil && ft.TypeParamsRefID > cluster.RefNull {
		return false, true
	}
	return true, false
}

func functionReceiverDisposition(owner *cluster.NamedObject, ft *cluster.FuncTypeInfo) (known, implicit bool) {
	if owner != nil && owner.HasKindTag {
		known = true
		implicit = !owner.IsStatic
	}
	if ft == nil {
		return known, implicit
	}
	if known && implicit != ft.HasImplicit {
		// Two independently-decoded metadata sources disagree. Do not pick one
		// and fabricate a receiver; make downstream analysis earn it elsewhere.
		return false, false
	}
	return true, ft.HasImplicit
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
	// TypeNames maps a Type's reference ID to its Dart-source display name,
	// type arguments included -- `List<int>`, not `TypeTestingStub_List<int>`.
	// Built once in BuildPoolLookups; nil on versions that cannot resolve a
	// Type to its class. See buildTypeNames.
	//
	// It used to hold only the PREFIXED stub spelling, which made it unusable
	// for the thing a Type in the object pool actually is: a type. 76% of the
	// pool entries that rendered as the bare placeholder `<Type>` (393 of 517
	// on dart-3.12.2, identical on both architectures) had their name computed
	// here and thrown away. Callers that want the stub spelling wrap this with
	// TypeTestingStubName.
	TypeNames map[int]string

	// TypeArgumentNames maps a TypeArguments object's ref ID to its rendered
	// argument list, `<int, Display>`. Several hundred pool slots per binary
	// hold one of these directly and rendered as the bare `<TypeArguments>`;
	// 82% of them (442 of 542 on dart-3.12.2, identical on both architectures)
	// were nameable from data already parsed. Built alongside TypeNames, from
	// the same lookups. All-or-nothing per list: see typeArgsListString.
	TypeArgumentNames map[int]string
	// TypeTestingStubNames is the exact readable identity of each statically
	// reproducible type-testing stub. Unlike TypeNames (a best-effort pool
	// display), this map never drops generic arguments or nullability and never
	// guesses across the Dart 3.1 argument-selection transition. It is therefore
	// the only Type-derived map safe for Code names and call targets.
	TypeTestingStubNames map[int]string

	// SourceTypeNames is the Dart-source spelling of each Type whose identity the
	// snapshot proves completely (List<int?>). It is what ExactTypeName serves to
	// signatures: unlike the stub identities it never contains a canonical
	// type-parameter name (X0, C1X0) and renders legacy nullability without `*`.
	SourceTypeNames map[int]string

	// TypeTestingStubSDKNames is the same stubs in the VM's OWN spelling --
	// `TypeTestingStub_dart_core__List__dart_core__int` where TypeNames plus
	// TypeTestingStubName gives `TypeTestingStub_List<int>`. Keyed the same
	// way, by the tested Type's ref ID.
	//
	// It exists for the symtab differential: the ELF's two assembly dialects
	// use this notation, so without it every type-testing stub scores as a
	// disagreement on every version. See buildTypeTestingStubSDKNames.
	TypeTestingStubSDKNames map[int]string
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
// firstEntryWithCode is the isolate InstructionsTable.FirstEntryWithCode, or -1
// when the table is unavailable. It is required to translate one-based
// Function.code_index values into Code.ClusterIndex values without confusing
// the table's discarded/stub prefix with the Code cluster.
// dartVersion selects the VM-isolate base object name table; pass "" to leave
// those references unnamed.
// dartVersion also decides whether type-testing-stub naming runs at all; see
// buildTypeNames.
//
// It used to take a separate typeClassIDIsRef bool for that. The two were
// different questions that happened to have the same answer, and coupling them
// broke as soon as one changed: correcting 2.15.0's Type layout (it is a
// scalar there, not a ref) silently switched TTS naming on for that version.
func BuildPoolLookups(result *cluster.Result, ct *snapshot.CIDTable, vmResult *cluster.Result, codeIndexOneBased bool, firstEntryWithCode int, dartVersion string) *PoolLookups {
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

	byCodeIndex := CodeIndexToFunc(result, ct, codeIndexOneBased, firstEntryWithCode)

	// Build code ref→name.
	l.CodeNames = make(map[int]CodeNameInfo)
	typeNames, typeArgNames := buildTypeNames(result, l, ct, dartVersion)
	l.TypeNames = typeNames
	l.TypeArgumentNames = typeArgNames
	l.TypeTestingStubNames = buildExactTypeTestingStubNames(result, l, ct, dartVersion)
	l.SourceTypeNames = buildExactSourceTypeNames(result, l, ct, dartVersion)
	l.TypeTestingStubSDKNames = buildTypeTestingStubSDKNames(result, l, ct, dartVersion)
	for _, ce := range result.Codes {
		owner, ok := ResolveCodeOwner(ce, l.RefToNamed, byCodeIndex, ct)
		if !ok {
			// A Code with no Function owner is not necessarily anonymous:
			// the SDK gives a type-testing stub the tested Type as its
			// owner (type_testing_stubs.cc, `code.set_owner(type)`), which
			// is why these fail both the CodeIndex cross-reference and the
			// RefToNamed lookup. See buildTypeNames.
			if name := l.TypeTestingStubNames[ce.OwnerRef]; name != "" {
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
		funcName := l.ResolveIsolateName(owner)
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
		ci.IsSuspendable = owner.IsSuspendable
		var signature *cluster.FuncTypeInfo
		if owner.SignatureRefID > 0 {
			if ft, ok := funcTypeByRef[owner.SignatureRefID]; ok {
				signature = ft
				ci.ParamCount = ft.NumFixed + ft.NumOptional
				ci.ParamCountKnown = true
				ci.FixedParamsWithReceiver = ft.NumFixed
				if ft.HasImplicit {
					ci.FixedParamsWithReceiver++
				}
				ci.OptionalParams = ft.NumOptional
			}
		}
		ci.ReceiverKnown, ci.HasImplicitReceiver = functionReceiverDisposition(owner, signature)
		// Dart 2.x keeps arity on the Function object instead
		// (UntaggedFunction.packed_fields_), so the signature chain above
		// yields nothing there and ParamCount came out 0 for EVERY 2.x
		// function. num_fixed_parameters counts the implicit receiver, and
		// kind_tag_ says whether there is one, so the visible count is
		// fixed + optional minus the receiver for instance methods.
		if !ci.ParamCountKnown && owner.NumFixedParams >= 0 {
			visible := owner.NumFixedParams + owner.NumOptionalParams
			if owner.HasKindTag && !owner.IsStatic && visible > 0 {
				visible--
			}
			ci.ParamCount = visible
			ci.ParamCountKnown = true
			// owner.NumFixedParams already counts the receiver.
			ci.FixedParamsWithReceiver = owner.NumFixedParams
			ci.OptionalParams = owner.NumOptionalParams
		}
		ci.MayUseRegisterCC, ci.MustUseStackCC = functionCallConventionDisposition(dartVersion, owner, signature)
		l.CodeNames[ce.RefID] = ci
	}
	for _, ce := range result.Codes {
		ci := l.CodeNames[ce.RefID]
		if name := ci.DisplayName(); name != "" {
			l.CodeRefDisplay[ce.RefID] = name
		}
	}

	// Name VM stub Code objects by their cluster-order index.
	// VM stubs (WriteBarrier, AllocateObject, etc.) have no Function
	// owner — ResolveCodeOwner fails for them. Their names come from
	// VM_STUB_CODE_LIST + VM_TYPE_TESTING_STUB_CODE_LIST
	// (vmtables.VMStubNamesInImageOrder): the VM Code cluster is written in
	// IMAGE order, which is the reverse of StubCode::Init emission order (see
	// that function for the evidence). Zipping the emission order here named
	// every VM Code in the pool by the stub at the opposite end of the list.
	//
	// This runs BEFORE the Function-owner resolution below so that stub
	// names take precedence over Function owner names. Without this
	// ordering, UnknownDartCode (which has a Function owner with a
	// null/empty name) gets named "<optimized out>" by the owner loop,
	// and the stub naming loop skips it — the correct name
	// "UnknownDartCode" is never assigned.
	//
	// The list includes the 9 type-testing stubs (173 entries on 3.12.2).
	if vmResult != nil {
		vmStubNames := vmtables.VMStubNamesInImageOrder(dartVersion)
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
		// We do not have the VM snapshot's InstructionsTable in this builder.
		// In the one-based era, passing -1 disables the cross-reference and
		// falls back to OwnerRef rather than applying the isolate table's FEC to
		// a different numbering domain. In practice VM stubs were already named
		// by the SDK stub table above.
		vmByCodeIndex := CodeIndexToFunc(vmResult, ct, codeIndexOneBased, -1)
		for _, ce := range vmResult.Codes {
			if _, exists := l.CodeNames[ce.RefID]; exists {
				continue
			}
			owner, ok := ResolveCodeOwner(ce, l.VmRefToNamed, vmByCodeIndex, ct)
			if !ok {
				continue
			}
			funcName := l.resolveVMName(owner)
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
					ownerName = l.resolveVMClassName(vmOwner, 0)
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
			if name := ci.DisplayName(); name != "" {
				l.CodeRefDisplay[ce.RefID] = name
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

// CIDForRef resolves the object CID in the namespace visible to the app
// snapshot. App/isolate refs win. VM refs are visible only in the base-object
// prefix assigned before isolate clusters are deserialized; above BaseObjLimit
// the two snapshots have independent numeric ref spaces.
func (l *PoolLookups) CIDForRef(ref int) (int, bool) {
	if l == nil || ref <= cluster.RefNull {
		return 0, false
	}
	if cid, ok := l.RefCID[ref]; ok {
		return cid, true
	}
	if ref < l.BaseObjLimit {
		cid, ok := l.VmRefCID[ref]
		return cid, ok
	}
	return 0, false
}

// NamedObjectForRef resolves a NamedObject in the namespace visible to the app
// snapshot. A VM object is eligible only when the ref is inside the shared
// base-object prefix. Callers that are explicitly traversing vmResult itself
// should stay inside package naming and use VmRefToNamed directly.
func (l *PoolLookups) NamedObjectForRef(ref int) (*cluster.NamedObject, bool) {
	if l == nil || ref <= cluster.RefNull {
		return nil, false
	}
	if no, ok := l.RefToNamed[ref]; ok {
		return no, no != nil
	}
	if ref < l.BaseObjLimit {
		no, ok := l.VmRefToNamed[ref]
		return no, ok && no != nil
	}
	return nil, false
}

// ResolveObjectName resolves the semantic name of an object ref visible from
// the app snapshot. Once a ref is proven to be a VM base object, its internal
// NameRefID belongs to the VM namespace and may legitimately be above the app's
// BaseObjLimit; resolveVMName handles that second hop.
func (l *PoolLookups) ResolveObjectName(ref int) string {
	if l == nil || ref <= cluster.RefNull {
		return ""
	}
	if no, ok := l.RefToNamed[ref]; ok && no != nil {
		return l.ResolveIsolateName(no)
	}
	if ref < l.BaseObjLimit {
		if no, ok := l.VmRefToNamed[ref]; ok && no != nil {
			return l.resolveVMName(no)
		}
	}
	return ""
}

// ResolveVMObjectName resolves a NamedObject that belongs to vmResult itself.
// Unlike ResolveObjectName, the reference is interpreted in the VM snapshot's
// own namespace and is therefore not restricted to the app-visible base prefix.
// Callers should use this only while explicitly traversing vmResult.
func (l *PoolLookups) ResolveVMObjectName(ref int) string {
	if l == nil || ref <= cluster.RefNull {
		return ""
	}
	no, ok := l.VmRefToNamed[ref]
	if !ok || no == nil {
		return ""
	}
	return l.resolveVMName(no)
}

// FunctionDisplayName returns the SDK-style semantic display name for an
// app/isolate Function ref. It deliberately operates before any filename or
// token sanitization so the same identity can be reused by analysis consumers.
func (l *PoolLookups) FunctionDisplayName(ref int) string {
	if l == nil || l.CT == nil {
		return ""
	}
	no, ok := l.RefToNamed[ref]
	if !ok || no == nil || no.CID != l.CT.Function {
		return ""
	}
	return l.functionDisplayName(no)
}

// functionDisplayName resolves an already-identified app Function without
// requiring that the caller re-find it in RefToNamed. This is needed for
// discarded Functions, whose NamedObject is already the authoritative object
// being traversed.
func (l *PoolLookups) functionDisplayName(no *cluster.NamedObject) string {
	if l == nil || l.CT == nil || no == nil || no.CID != l.CT.Function {
		return ""
	}
	leaf := l.ResolveIsolateName(no)
	if leaf == "" {
		return ""
	}
	ci := CodeNameInfo{
		FuncName:          leaf,
		OwnerName:         l.ResolveOwnerName(no),
		EnclosingFunction: l.ClosureParents[no.RefID],
	}
	if no.IsConstructor() {
		ci.FuncName = "new " + leaf
		ci.IsConstructor = true
	}
	return ci.DisplayName()
}

// ExactTypeName returns a Dart-source type name only when the snapshot data is
// sufficient to reconstruct the complete type identity. It deliberately does
// not fall back to TypeNames: that map is display-oriented and may omit generic
// arguments, which is acceptable for an object-pool annotation but would turn a
// function signature into a confident false claim.
//
// Ordinary Type objects reuse the exact-or-empty type-testing-stub namer. The
// two VM-isolate singleton types that have no TypeInfo in the older snapshot
// layouts (dynamic and void) are recognized from the SDK-versioned base-object
// table. Anything else stays unknown and callers should render `dynamic`.
func (l *PoolLookups) ExactTypeName(ref int) string {
	if l == nil || ref <= cluster.RefNull {
		return ""
	}
	if name := l.SourceTypeNames[ref]; name != "" {
		return name
	}
	if ref >= 1 && ref <= len(l.BaseObjectNames) {
		if name, ok := singletonTypeName(l.BaseObjectNames[ref-1]); ok {
			return name
		}
	}
	return ""
}

// isStringCID reports whether a CID is one of the String subclasses.
func isStringCID(cid int, ct *snapshot.CIDTable) bool {
	return (ct.OneByteString != 0 && cid == ct.OneByteString) ||
		(ct.TwoByteString != 0 && cid == ct.TwoByteString) ||
		(ct.String != 0 && cid == ct.String)
}

func (l *PoolLookups) ResolveOwnerName(no *cluster.NamedObject) string {
	if no == nil || no.OwnerRefID <= cluster.RefNull {
		return ""
	}
	owner, ok := l.RefToNamed[no.OwnerRefID]
	if !ok {
		// The app snapshot reuses VM snapshot references only for the base-object
		// prefix. Above BaseObjLimit the numeric ref spaces overlap but refer to
		// unrelated objects, so an unrestricted VM fallback can fabricate an owner
		// from a coincidentally-equal VM ref.
		if no.OwnerRefID < l.BaseObjLimit && l.VmRefToNamed != nil {
			if vmOwner, vmOK := l.VmRefToNamed[no.OwnerRefID]; vmOK {
				return l.resolveVMClassName(vmOwner, 0)
			}
		}
		return ""
	}
	return l.resolveIsolateClassName(owner, 0)
}

func (l *PoolLookups) resolveVMName(no *cluster.NamedObject) string {
	if no == nil {
		return ""
	}
	if no.NameRefID >= 0 {
		if s, ok := l.VmRefToStr[no.NameRefID]; ok {
			return s
		}
	}
	return ""
}

// resolveIsolateName resolves a name carried by an app/isolate object. Its
// NameRefID may point at an app string or at a VM-isolate base object, but may
// not fall through to an arbitrary VM ref above the base-object prefix: the two
// snapshots allocate independent ref spaces there.
func (l *PoolLookups) ResolveIsolateName(no *cluster.NamedObject) string {
	if no == nil || no.NameRefID <= cluster.RefNull {
		return ""
	}
	if s, ok := l.StringForRef(no.NameRefID); ok {
		return s
	}
	return ""
}

// resolveIsolateClassName turns an app Class-or-PatchClass NamedObject into a
// class name, hopping through PatchClass and using VM data only for shared base
// objects. resolveVMClassName handles genuine VM snapshot objects separately.
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

func (l *PoolLookups) resolveIsolateClassName(owner *cluster.NamedObject, depth int) string {
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
	if n := l.ResolveIsolateName(owner); n != "" {
		if n == topLevelClassName {
			return ""
		}
		return n
	}
	// A PatchClass wraps the real Class in its OwnerRefID; hop to it.
	if l.CT != nil && owner.CID == l.CT.PatchClass && owner.OwnerRefID >= 0 {
		if wrapped, ok := l.RefToNamed[owner.OwnerRefID]; ok {
			return l.resolveIsolateClassName(wrapped, depth+1)
		}
		if owner.OwnerRefID < l.BaseObjLimit {
			if wrapped, ok := l.VmRefToNamed[owner.OwnerRefID]; ok {
				return l.resolveVMClassName(wrapped, depth+1)
			}
		}
	}
	return ""
}

// resolveVMClassName is the VM-snapshot counterpart of resolveIsolateClassName.
// VM NamedObjects may legitimately refer to VM strings above the app snapshot's
// base-object prefix, so their namespace must remain unrestricted here.
func (l *PoolLookups) resolveVMClassName(owner *cluster.NamedObject, depth int) string {
	if owner == nil || depth > 4 {
		return ""
	}
	if n := l.resolveVMName(owner); n != "" {
		if n == topLevelClassName {
			return ""
		}
		return n
	}
	if l.CT != nil && owner.CID == l.CT.PatchClass && owner.OwnerRefID >= 0 {
		if wrapped, ok := l.VmRefToNamed[owner.OwnerRefID]; ok {
			return l.resolveVMClassName(wrapped, depth+1)
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
// anywhere in this analysis yet. Confirmed empirically, not assumed: a
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
			if s := r.pl.ResolveIsolateName(no); s != "" {
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
	if refID >= l.BaseObjLimit {
		return ""
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
			isString := false
			if l.CT != nil {
				if cid, ok := l.RefCID[pe.RefID]; ok {
					// Non-compressed-pointers snapshots store string refs under
					// the abstract kStringCid (ct.String) cluster, not the
					// OneByteString/TwoByteString subclass CIDs. Accept all three
					// so ROData strings (the common case for desktop AOT) resolve
					// to their actual value instead of a "<String>" placeholder.
					isString = isStringCID(cid, l.CT)
				} else if pe.RefID > cluster.RefNull && pe.RefID < l.BaseObjLimit {
					if cid, ok := l.VmRefCID[pe.RefID]; ok {
						isString = isStringCID(cid, l.CT)
					}
				}
			}
			if isString {
				if s, ok := l.RefToStr[pe.RefID]; ok {
					display[pe.Index] = fmt.Sprintf("%q", s)
				} else if pe.RefID > cluster.RefNull && pe.RefID < l.BaseObjLimit {
					if s, ok := l.VmRefToStr[pe.RefID]; ok {
						display[pe.Index] = fmt.Sprintf("%q", s)
					} else {
						display[pe.Index] = "<String>"
					}
				} else {
					display[pe.Index] = "<String>"
				}
			} else if no, ok := l.RefToNamed[pe.RefID]; ok {
				name := l.ResolveIsolateName(no)
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
			} else if name := l.TypeNames[pe.RefID]; name != "" {
				// A Type object: name it. The class and its type arguments are
				// already resolved for the type-testing stubs, and rendering
				// the bare CID name instead threw that away -- `<Type>` where
				// `EfficientLengthIterable` or `StringBuffer` was known.
				//
				// The name is the Dart-source spelling of the type, so it is
				// prefixed to say what the pool slot holds; an unprefixed
				// `List<int>` would read as a value of that type rather than
				// the type itself.
				display[pe.Index] = "Type: " + name
			} else if args := l.TypeArgumentNames[pe.RefID]; args != "" {
				// A bare TypeArguments object: render the list it holds.
				display[pe.Index] = "TypeArgs: " + args
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
							isVMStringCID = isStringCID(cid, l.CT)
						}
					}
					if isVMStringCID {
						display[pe.Index] = fmt.Sprintf("%q", s)
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
				} else if no, ok := l.VmRefToNamed[pe.RefID]; ok {
					name := l.resolveVMName(no)
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
			// in the exponent range as a bogus float -- in the SHARED analysis
			// pool display, affecting every consumer. We render the raw value
			// here; float interpretation belongs in the decompiler's FP-load
			// operand path where the type is actually known.
			display[pe.Index] = fmt.Sprintf("0x%x", pe.Imm)
		}
	}
	return display
}
