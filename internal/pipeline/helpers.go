package pipeline

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/strutil"
)

// CodeNameInfo holds resolved function and owner names for a code ref.
type CodeNameInfo struct {
	FuncName   string
	OwnerName  string
	ParamCount int // total visible parameters (fixed + optional, excluding implicit 'this')
	// IsConstructor marks a generative constructor or factory, recovered
	// from UntaggedFunction::Kind. See cluster.NamedObject.IsConstructor.
	IsConstructor bool
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
			FuncName:  funcName,
			OwnerName: l.ResolveOwnerName(owner),
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
		// Follow Function→FunctionType chain for parameter count.
		if owner.SignatureRefID > 0 {
			if ft, ok := funcTypeByRef[owner.SignatureRefID]; ok {
				ci.ParamCount = ft.NumFixed + ft.NumOptional
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

	return l
}

// CodeIndexToFunc maps a Code's ClusterIndex to its unambiguous owning
// Function NamedObject via the Function->CodeIndex direction (the
// REVERSE of Code.OwnerRef). This is the reliable cross-reference
// cmd/aotopsy/refinfo.go's findOwnerViaCodeIndex already validated by
// hand: Code.OwnerRef is confirmed unreliable for some real snapshots
// (e.g. Dart 3.7.0 x86_64 produces a bogus shared OwnerRef for ~5.4% of
// all functions, all resolving to CID 61/Mint, which is never a legal
// Code owner), while Function.CodeIndex == Code.ClusterIndex has not
// shown this failure mode. A ClusterIndex is dropped (left unmapped,
// not guessed) if more than one Function claims it, so ambiguous cases
// fall back to the OwnerRef-based lookup in ResolveCodeOwner instead of
// picking one arbitrarily. Exported so every direct Code.OwnerRef
// consumer in cmd/aotopsy (graph/parity/thr-audit/decompile-native's
// --from-main library classification) can share this same reliable
// cross-reference instead of trusting the buggy field directly.
//
// codeIndexOneBased must be true for Dart ≥2.16 (Function.code_index is
// 1-based: 0=LazyCompile stub, 1+=Code cluster index). For ≤2.15 it is
// 0-based (direct ref into Code cluster). See VersionProfile.CodeIndexOneBased.
func CodeIndexToFunc(result *cluster.Result, ct *snapshot.CIDTable, codeIndexOneBased bool) map[int]*cluster.NamedObject {
	if ct == nil {
		return nil
	}
	m := make(map[int]*cluster.NamedObject)
	ambiguous := make(map[int]bool)
	for i := range result.Named {
		no := &result.Named[i]
		if no.CID != ct.Function || no.CodeIndex < 0 {
			continue
		}
		// Convert Function.code_index (1-based for ≥2.16) to Code.ClusterIndex (0-based).
		clusterIdx := no.CodeIndex
		if codeIndexOneBased {
			clusterIdx = no.CodeIndex - 1
		}
		if clusterIdx < 0 {
			continue // code_index 0 = LazyCompile stub (≥2.16), no Code object
		}
		if _, exists := m[clusterIdx]; exists {
			ambiguous[clusterIdx] = true
			continue
		}
		m[clusterIdx] = no
	}
	for idx := range ambiguous {
		delete(m, idx)
	}
	return m
}

// ResolveCodeOwner finds the Function/Closure/FfiTrampolineData
// NamedObject that owns ce, preferring the reliable CodeIndex
// cross-reference (see CodeIndexToFunc's doc comment) over the
// documented-unreliable Code.OwnerRef, and falling back to OwnerRef
// only when no CodeIndex match exists (e.g. deferred code with
// ClusterIndex == -1, or Dart versions/architectures where the
// cross-reference wasn't populated) -- so this is a strict correctness
// improvement, never a regression versus the old OwnerRef-only lookup.
func ResolveCodeOwner(ce cluster.CodeEntry, refToNamed map[int]*cluster.NamedObject, byCodeIndex map[int]*cluster.NamedObject) (*cluster.NamedObject, bool) {
	if ce.ClusterIndex >= 0 {
		if owner, ok := byCodeIndex[ce.ClusterIndex]; ok {
			return owner, true
		}
	}
	if ce.OwnerRef <= 0 {
		return nil, false
	}
	owner, ok := refToNamed[ce.OwnerRef]
	return owner, ok
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
	if owner, ok := l.RefToNamed[no.OwnerRefID]; ok {
		return l.ResolveName(owner)
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
			display[pe.Index] = fmt.Sprintf("0x%x", pe.Imm)
		}
	}
	return display
}

// DartClassLayout is a resolved class definition ready for export.
type DartClassLayout struct {
	ClassName    string            `json:"class_name"`
	ClassID      int32             `json:"class_id"`
	InstanceSize int32             `json:"instance_size"`
	Fields       []DartFieldLayout `json:"fields"`
}

// DartFieldLayout is one field in a DartClassLayout.
type DartFieldLayout struct {
	Name       string `json:"name"`
	ByteOffset int32  `json:"byte_offset"`
}

// BuildClassLayouts joins ClassInfo + FieldInfo + string lookups into class layouts.
func BuildClassLayouts(result *cluster.Result, pl *PoolLookups, compressedPtrs bool) []DartClassLayout {
	var wordSize int32 = 8
	if compressedPtrs {
		wordSize = 4
	}

	classByRef := make(map[int]*cluster.ClassInfo, len(result.Classes))
	for i := range result.Classes {
		ci := &result.Classes[i]
		classByRef[ci.RefID] = ci
	}

	type resolvedField struct {
		nameRefID  int
		byteOffset int32
	}
	fieldsByOwner := make(map[int][]resolvedField)
	for _, fi := range result.Fields {
		if fi.OwnerRefID <= 0 || fi.HostOffset < 0 {
			continue
		}
		offsetRef := int(fi.HostOffset)
		wordOff, ok := result.MintValues[offsetRef]
		if !ok {
			continue
		}
		fieldsByOwner[fi.OwnerRefID] = append(fieldsByOwner[fi.OwnerRefID], resolvedField{
			nameRefID:  fi.NameRefID,
			byteOffset: int32(wordOff) * wordSize,
		})
	}

	var layouts []DartClassLayout
	for _, ci := range result.Classes {
		if ci.InstanceSize <= 0 {
			continue
		}
		className := ""
		if ci.NameRefID >= 0 {
			if s, ok := pl.RefToStr[ci.NameRefID]; ok {
				className = s
			}
		}
		if className == "" {
			continue
		}

		layout := DartClassLayout{
			ClassName:    className,
			ClassID:      ci.ClassID,
			InstanceSize: ci.InstanceSize * wordSize,
		}

		if rfs, ok := fieldsByOwner[ci.RefID]; ok {
			for _, rf := range rfs {
				fieldName := ""
				if rf.nameRefID >= 0 {
					if s, ok := pl.RefToStr[rf.nameRefID]; ok {
						fieldName = s
					}
				}
				if fieldName == "" {
					if s, ok := pl.VmRefToStr[rf.nameRefID]; ok {
						fieldName = s
					}
				}
				if fieldName == "" {
					fieldName = fmt.Sprintf("field_0x%x", rf.byteOffset)
				}
				layout.Fields = append(layout.Fields, DartFieldLayout{
					Name:       fieldName,
					ByteOffset: rf.byteOffset,
				})
			}
		} else {
			byteSize := ci.InstanceSize * wordSize
			for off := wordSize; off+wordSize <= byteSize; off += wordSize {
				layout.Fields = append(layout.Fields, DartFieldLayout{
					Name:       fmt.Sprintf("f_0x%x", off),
					ByteOffset: off,
				})
			}
		}

		sort.Slice(layout.Fields, func(i, j int) bool {
			return layout.Fields[i].ByteOffset < layout.Fields[j].ByteOffset
		})

		layouts = append(layouts, layout)
	}
	return layouts
}

// --- Phase 1: Captured data builders (Script, LoadingUnit, KernelProgramInfo) ---

// ScriptRecord is one Script entry in scripts.jsonl.
type ScriptRecord struct {
	RefID             int    `json:"ref_id"`
	URL               string `json:"url"`
	LineOffset        int32  `json:"line_offset,omitempty"`
	ColOffset         int32  `json:"col_offset,omitempty"`
	KernelScriptIndex int32  `json:"kernel_script_index,omitempty"`
}

// BuildScripts joins cluster.ScriptInfo + PoolLookups string table → script records.
func BuildScripts(result *cluster.Result, pl *PoolLookups) []ScriptRecord {
	var records []ScriptRecord
	for _, si := range result.Scripts {
		url := pl.RefToStr[si.URLRef]
		rec := ScriptRecord{
			RefID:             si.RefID,
			URL:               url,
			LineOffset:        si.LineOffset,
			ColOffset:         si.ColOffset,
			KernelScriptIndex: si.KernelScriptIndex,
		}
		records = append(records, rec)
	}
	return records
}

// RefNull re-exports cluster.RefNull for readability at call sites here.
const RefNull = cluster.RefNull

// LoadingUnitRecord is one LoadingUnit entry in loading_units.jsonl.
type LoadingUnitRecord struct {
	RefID     int   `json:"ref_id"`
	ParentRef int   `json:"parent_ref,omitempty"`
	UnitID    int32 `json:"unit_id,omitempty"`
	// IsRoot is true when parent_ is null, i.e. this is the base unit whose
	// Code objects live in the snapshot we just parsed.
	IsRoot bool `json:"is_root,omitempty"`
	// MainCodeCount / DeferredCodeCount describe the Code partition. Only set
	// on the root unit -- see PartitionCodesByLoadingUnit for why a non-root
	// unit's codes are not in this snapshot at all.
	MainCodeCount     int `json:"main_code_count,omitempty"`
	DeferredCodeCount int `json:"deferred_code_count,omitempty"`
}

// LoadingUnitPartition is the Code-to-loading-unit attribution for one snapshot.
//
// This implements the "partition Codes by loading unit" half of the LoadingUnit
// gap. What it can and cannot say is a property of split AOT, not a shortcut:
//
// Dart's deferred loading splits an app into a root unit plus one unit per
// deferred import, and each unit gets its OWN snapshot blob (app.so,
// app-2.part.so, ...). The Code cluster inside a single blob is written in two
// sections -- see CodeDeserializationCluster::ReadAlloc, which reads `count`
// main codes and then `deferred_count` deferred ones. The main section is the
// code this blob defines; the deferred section is a set of Code objects that
// this blob references but whose instructions live in another unit's blob
// (ReadInstructions early-returns for them, which is why our reader leaves
// ClusterIndex == -1).
//
// So per-blob the honest partition is exactly two buckets: "defined here"
// (root unit) and "defined in some other unit" (deferred). Attributing a
// deferred Code to a SPECIFIC unit id requires loading that unit's blob too,
// which is a multi-file input this tool does not take yet.
type LoadingUnitPartition struct {
	// RootUnitID is the id of the unit this snapshot defines, or 0 if no
	// LoadingUnit cluster was present.
	RootUnitID int32
	// UnitCount is the number of LoadingUnit objects described in this
	// snapshot (including non-root ones, which are metadata-only here).
	UnitCount int
	// MainCodeRefs are Code ref IDs defined by the root unit.
	MainCodeRefs []int
	// DeferredCodeRefs are Code ref IDs referenced here but defined in
	// another loading unit's blob.
	DeferredCodeRefs []int
	// Degenerate is true when there is at most one unit and no deferred
	// codes, i.e. the app uses no deferred imports and the partition carries
	// no information. Callers should say so rather than presenting a
	// single-bucket split as a result.
	Degenerate bool
}

// PartitionCodesByLoadingUnit splits result.Codes into root-unit and deferred
// buckets and pairs that with the LoadingUnit metadata.
func PartitionCodesByLoadingUnit(result *cluster.Result) *LoadingUnitPartition {
	p := &LoadingUnitPartition{UnitCount: len(result.LoadingUnits)}
	for _, lui := range result.LoadingUnits {
		if lui.ParentRef == RefNull {
			p.RootUnitID = lui.UnitID
			break
		}
	}
	for _, ce := range result.Codes {
		if ce.ClusterIndex >= 0 {
			p.MainCodeRefs = append(p.MainCodeRefs, ce.RefID)
		} else {
			p.DeferredCodeRefs = append(p.DeferredCodeRefs, ce.RefID)
		}
	}
	p.Degenerate = p.UnitCount <= 1 && len(p.DeferredCodeRefs) == 0
	return p
}

// UnitOf reports which bucket a Code ref belongs to: the root unit id when the
// Code is defined in this snapshot, or 0 with deferred=true when it is defined
// in another unit. found is false for a ref that is not a Code at all.
func (p *LoadingUnitPartition) UnitOf(codeRef int) (unitID int32, deferred, found bool) {
	for _, r := range p.MainCodeRefs {
		if r == codeRef {
			return p.RootUnitID, false, true
		}
	}
	for _, r := range p.DeferredCodeRefs {
		if r == codeRef {
			return 0, true, true
		}
	}
	return 0, false, false
}

// BuildLoadingUnits converts cluster.LoadingUnitInfo → output records, with the
// Code partition folded onto the root unit.
func BuildLoadingUnits(result *cluster.Result) []LoadingUnitRecord {
	part := PartitionCodesByLoadingUnit(result)
	var records []LoadingUnitRecord
	for _, lui := range result.LoadingUnits {
		rec := LoadingUnitRecord{
			RefID:     lui.RefID,
			ParentRef: lui.ParentRef,
			UnitID:    lui.UnitID,
			IsRoot:    lui.ParentRef == RefNull,
		}
		if rec.IsRoot {
			rec.MainCodeCount = len(part.MainCodeRefs)
			rec.DeferredCodeCount = len(part.DeferredCodeRefs)
		}
		records = append(records, rec)
	}
	return records
}

// KPIRecord is one KernelProgramInfo entry in kpi.jsonl.
type KPIRecord struct {
	RefID              int `json:"ref_id"`
	KernelComponentRef int `json:"kernel_component_ref,omitempty"`
	StringOffsetsRef   int `json:"string_offsets_ref,omitempty"`
	StringDataRef      int `json:"string_data_ref,omitempty"`
	CanonicalNamesRef  int `json:"canonical_names_ref,omitempty"`
	ConstantsRef       int `json:"constants_ref,omitempty"`
	ConstantsTableRef  int `json:"constants_table_ref,omitempty"`
}

// BuildKPI converts cluster.KernelProgramInfoRef → output records.
func BuildKPI(result *cluster.Result) []KPIRecord {
	var records []KPIRecord
	for _, kpi := range result.KernelProgramInfo {
		rec := KPIRecord{
			RefID:              kpi.RefID,
			KernelComponentRef: kpi.KernelComponentRef,
			StringOffsetsRef:   kpi.StringOffsetsRef,
			StringDataRef:      kpi.StringDataRef,
			CanonicalNamesRef:  kpi.CanonicalNamesRef,
			ConstantsRef:       kpi.ConstantsRef,
			ConstantsTableRef:  kpi.ConstantsTableRef,
		}
		records = append(records, rec)
	}
	return records
}

// InstanceFieldRecord is one captured pointer field of an instance.
type InstanceFieldRecord struct {
	Offset int    `json:"offset"`
	Ref    int    `json:"ref"`
	Name   string `json:"name,omitempty"` // field name when the offset maps to a known layout slot
}

// InstanceRecord is one Instance entry in instances.jsonl.
type InstanceRecord struct {
	RefID int `json:"ref_id"`
	CID   int `json:"cid"`
	// SlotCount is the number of field slots the object has, including unboxed
	// ones that produce no entry in Fields.
	SlotCount int                   `json:"slot_count,omitempty"`
	Fields    []InstanceFieldRecord `json:"fields,omitempty"`
}

// BuildInstances converts cluster.InstanceInfo → output records, naming each
// field offset via the class layout where possible.
//
// The old shape was a bare "field_refs":[...] list with no offsets, which was
// not usable: the position of a ref in that list is not its field index once
// any unboxed field is present. Offsets now come from the capture itself.
func BuildInstances(result *cluster.Result, layouts []DartClassLayout) []InstanceRecord {
	// classID -> byteOffset -> field name.
	nameByCIDOffset := make(map[int32]map[int32]string, len(layouts))
	for _, l := range layouts {
		m := make(map[int32]string, len(l.Fields))
		for _, f := range l.Fields {
			m[f.ByteOffset] = f.Name
		}
		nameByCIDOffset[l.ClassID] = m
	}

	records := make([]InstanceRecord, 0, len(result.Instances))
	for _, ii := range result.Instances {
		rec := InstanceRecord{
			RefID:     ii.RefID,
			CID:       ii.CID,
			SlotCount: ii.NumFieldSlots,
		}
		names := nameByCIDOffset[int32(ii.CID)]
		for _, f := range ii.Fields {
			fr := InstanceFieldRecord{Offset: int(f.ByteOffset), Ref: f.Ref}
			if names != nil {
				fr.Name = names[f.ByteOffset]
			}
			rec.Fields = append(rec.Fields, fr)
		}
		records = append(records, rec)
	}
	return records
}

// ContextRecord is one Context entry in contexts.jsonl.
type ContextRecord struct {
	RefID     int   `json:"ref_id"`
	ParentRef int   `json:"parent_ref,omitempty"`
	VarRefs   []int `json:"var_refs,omitempty"`
}

// BuildContexts converts cluster.ContextInfo → output records.
func BuildContexts(result *cluster.Result) []ContextRecord {
	var records []ContextRecord
	for _, ci := range result.Contexts {
		rec := ContextRecord{
			RefID:     ci.RefID,
			ParentRef: ci.ParentRef,
			VarRefs:   ci.VarRefs,
		}
		records = append(records, rec)
	}
	return records
}

// TypeArgumentsRecord is one TypeArguments entry in type_arguments.jsonl.
type TypeArgumentsRecord struct {
	RefID          int   `json:"ref_id"`
	Length         int   `json:"length"`
	TypeRefs       []int `json:"type_refs,omitempty"`
	Instantiations int   `json:"instantiations_ref,omitempty"`
	Hash           int32 `json:"hash,omitempty"`
	Nullability    int   `json:"nullability,omitempty"`
}

// BuildTypeArguments converts cluster.TypeArgumentsInfo → output records.
func BuildTypeArguments(result *cluster.Result) []TypeArgumentsRecord {
	var records []TypeArgumentsRecord
	for _, ta := range result.TypeArguments {
		rec := TypeArgumentsRecord{
			RefID:          ta.RefID,
			Length:         ta.Length,
			TypeRefs:       ta.TypeRefs,
			Instantiations: ta.Instantiations,
			Hash:           ta.Hash,
			Nullability:    ta.Nullability,
		}
		records = append(records, rec)
	}
	return records
}

// ExceptionHandlerRecord is one ExceptionHandlers entry in exception_handlers.jsonl.
type ExceptionHandlerRecord struct {
	RefID           int                     `json:"ref_id"`
	HandledTypesRef int                     `json:"handled_types_ref,omitempty"`
	Handlers        []ExceptionHandlerEntry `json:"handlers,omitempty"`
}

// ExceptionHandlerEntry is one handler in an ExceptionHandlerRecord.
type ExceptionHandlerEntry struct {
	PCOffset        int32 `json:"pc_offset"`
	OuterTryIndex   int16 `json:"outer_try_index,omitempty"`
	NeedsStacktrace bool  `json:"needs_stacktrace,omitempty"`
	HasCatchAll     bool  `json:"has_catch_all,omitempty"`
	IsGenerated     bool  `json:"is_generated,omitempty"`
}

// BuildExceptionHandlers converts cluster.ExceptionHandlerInfo → output records.
func BuildExceptionHandlers(result *cluster.Result) []ExceptionHandlerRecord {
	var records []ExceptionHandlerRecord
	for _, eh := range result.ExceptionHandlers {
		rec := ExceptionHandlerRecord{
			RefID:           eh.RefID,
			HandledTypesRef: eh.HandledTypesRef,
		}
		for _, h := range eh.Handlers {
			rec.Handlers = append(rec.Handlers, ExceptionHandlerEntry{
				PCOffset:        h.PCOffset,
				OuterTryIndex:   h.OuterTryIndex,
				NeedsStacktrace: h.NeedsStacktrace,
				HasCatchAll:     h.HasCatchAll,
				IsGenerated:     h.IsGenerated,
			})
		}
		records = append(records, rec)
	}
	return records
}

// ICDataRecord is one ICData entry in icdata.jsonl.
//
// Emitted only if an ICData cluster is ever present; AOT snapshots have none
// (see cluster.ICDataInfo). The fields track ICData's ReadFromTo order --
// the old single "owner_ref" field did not correspond to any ICData ref slot.
type ICDataRecord struct {
	RefID         int `json:"ref_id"`
	TargetNameRef int `json:"target_name_ref,omitempty"`
	ArgsDescRef   int `json:"args_desc_ref,omitempty"`
	EntriesRef    int `json:"entries_ref,omitempty"`
}

// BuildICData converts cluster.ICDataInfo → output records.
func BuildICData(result *cluster.Result) []ICDataRecord {
	var records []ICDataRecord
	for _, icd := range result.ICData {
		rec := ICDataRecord{
			RefID:         icd.RefID,
			TargetNameRef: icd.TargetNameRef,
			ArgsDescRef:   icd.ArgsDescRef,
			EntriesRef:    icd.EntriesRef,
		}
		records = append(records, rec)
	}
	return records
}

// ClosureDataRecord is one ClosureData entry in closure_data.jsonl.
type ClosureDataRecord struct {
	RefID             int `json:"ref_id"`
	ParentFunctionRef int `json:"parent_function_ref,omitempty"`
	ClosureRef        int `json:"closure_ref,omitempty"`
}

// BuildClosureData converts cluster.ClosureDataInfo → output records.
func BuildClosureData(result *cluster.Result) []ClosureDataRecord {
	var records []ClosureDataRecord
	for _, cd := range result.ClosureData {
		rec := ClosureDataRecord{
			RefID:             cd.RefID,
			ParentFunctionRef: cd.ParentFunctionRef,
			ClosureRef:        cd.ClosureRef,
		}
		records = append(records, rec)
	}
	return records
}

// Qualified renders this code's display name.
//
// A constructor's Function name already carries the class -- Dart names them
// `_GrowableList.of`, `Duration`, `PlatformDispatcher._` -- so prepending the
// owner as well produces `_GrowableList.new _GrowableList.of`. The owner is
// still reported separately in functions.jsonl; it is only the qualified name
// that must not repeat it.
func (ci CodeNameInfo) Qualified(pcOffset uint32) string {
	if ci.IsConstructor {
		return QualifiedName("", ci.FuncName, pcOffset)
	}
	return QualifiedName(ci.OwnerName, ci.FuncName, pcOffset)
}

// QualifiedName builds "Owner.FuncName_hexaddr" like blutter.
func QualifiedName(ownerName, funcName string, pcOffset uint32) string {
	suffix := fmt.Sprintf("_%x", pcOffset)
	if funcName == "" {
		return "sub" + suffix
	}
	if ownerName != "" {
		return ownerName + "." + funcName + suffix
	}
	return funcName + suffix
}

// SanitizeFilename makes a string safe for use as a filename.
// Strips non-printable runes and replaces filesystem-unsafe characters.
// SanitizeFilename delegates to the shared strutil.SanitizeFilename.
// Kept for backward compatibility — all callers should eventually use
// strutil.SanitizeFilename directly. (P4-5)
func SanitizeFilename(name string) string {
	return strutil.SanitizeFilename(name)
}

// FuncRelPath returns a relative path like "OwnerClass/funcName_hex" for functions
// with an owner, or "funcName_hex" for ownerless functions.
func FuncRelPath(ownerName, funcName string, pcOffset uint32) string {
	suffix := fmt.Sprintf("_%x", pcOffset)
	var fpart string
	if funcName == "" {
		fpart = "sub" + suffix
	} else {
		fpart = SanitizeFilename(funcName + suffix)
	}
	if ownerName != "" {
		return SanitizeFilename(ownerName) + "/" + fpart
	}
	return fpart
}

// FuncRelPathFromQualified reconstructs the relative path from a qualified name
// and its owner. Used by post-disasm commands (signal, decompile).
func FuncRelPathFromQualified(qualifiedName, owner string) string {
	if owner != "" {
		prefix := owner + "."
		funcPart := qualifiedName
		if strings.HasPrefix(qualifiedName, prefix) {
			funcPart = qualifiedName[len(prefix):]
		}
		return SanitizeFilename(owner) + "/" + SanitizeFilename(funcPart)
	}
	return SanitizeFilename(qualifiedName)
}

// ReadJSONL reads a JSONL file into a slice of T.
func ReadJSONL[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var records []T
	dec := json.NewDecoder(f)
	for dec.More() {
		var rec T
		if err := dec.Decode(&rec); err != nil {
			return records, fmt.Errorf("line %d: %w", len(records)+1, err)
		}
		records = append(records, rec)
	}

	return records, nil
}

// DisasmIndexEntry is the per-function index record written to index.jsonl.
type DisasmIndexEntry struct {
	Name      string `json:"name"`
	OwnerName string `json:"owner_name,omitempty"`
	RefID     int    `json:"ref_id"`
	OwnerRef  int    `json:"owner_ref,omitempty"`
	PCOffset  uint32 `json:"pc_offset"`
	Size      uint32 `json:"size"`
	File      string `json:"file"`
}

// DartMetaJSON is the structure written to dart_meta.json.
type DartMetaJSON struct {
	DartVersion        string             `json:"dart_version"`
	CompressedPointers bool               `json:"compressed_pointers"`
	PointerSize        int                `json:"pointer_size"`
	THRFields          []DartMetaTHRField `json:"thr_fields"`
}

// DartMetaTHRField is a THR field entry for dart_meta.json.
type DartMetaTHRField struct {
	Offset int    `json:"offset"`
	Name   string `json:"name"`
}

// WriteDartMeta writes dart_meta.json with snapshot metadata.
func WriteDartMeta(outDir, dartVersion string, compressed bool, ptrSize int, thrFields map[int]string) error {
	fields := make([]DartMetaTHRField, 0, len(thrFields))
	for off, name := range thrFields {
		fields = append(fields, DartMetaTHRField{Offset: off, Name: name})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Offset < fields[j].Offset })

	meta := DartMetaJSON{
		DartVersion:        dartVersion,
		CompressedPointers: compressed,
		PointerSize:        ptrSize,
		THRFields:          fields,
	}

	f, err := os.Create(filepath.Join(outDir, "dart_meta.json"))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(meta); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// NormalizeHexAddr strips leading zeros: "0x000652e4" → "0x652e4".
func NormalizeHexAddr(s string) string {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return s
	}
	v, err := strconv.ParseUint(s[2:], 16, 64)
	if err != nil {
		return s
	}
	return fmt.Sprintf("0x%x", v)
}

// ParseHexAddr parses "0x..." hex address strings. Returns 0 on failure.
func ParseHexAddr(s string) uint64 {
	s = strings.TrimPrefix(s, "0x")
	v, _ := strconv.ParseUint(s, 16, 64)
	return v
}

// AsmCommentRe matches annotated asm lines: address + instruction + "; comment"
var AsmCommentRe = regexp.MustCompile(`^(0x[0-9a-fA-F]+)\s+.*;\s+(.+)$`)

// ExtractAsmComments parses all .txt files in asmDir for instruction-level annotations.
func ExtractAsmComments(asmDir string) ([]FlutterMetaComment, error) {
	entries, err := os.ReadDir(asmDir)
	if err != nil {
		return nil, err
	}

	var comments []FlutterMetaComment
	seen := make(map[string]bool)

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		path := filepath.Join(asmDir, entry.Name())
		fc, err := extractFileComments(path, seen)
		if err != nil {
			continue
		}
		comments = append(comments, fc...)
	}

	return comments, nil
}

func extractFileComments(path string, seen map[string]bool) ([]FlutterMetaComment, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var comments []FlutterMetaComment
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		m := AsmCommentRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		addr := NormalizeHexAddr(m[1])
		text := strings.TrimSpace(m[2])

		if strings.HasPrefix(text, "<") && strings.HasSuffix(text, ">") {
			continue
		}

		if seen[addr] {
			continue
		}
		seen[addr] = true

		comments = append(comments, FlutterMetaComment{
			Addr: addr,
			Text: text,
		})
	}

	return comments, scanner.Err()
}

// IsInterestingCallee returns true if the callee name represents a real named
// function rather than VM internals, stubs, or dispatch noise.
func IsInterestingCallee(name string) bool {
	if name == "" {
		return false
	}
	switch {
	case len(name) > 4 && name[:4] == "sub_":
		return false
	case len(name) > 2 && name[0] == '0' && name[1] == 'x':
		return false
	case name == "dispatch_table" || name == "object_field":
		return false
	case len(name) > 4 && name[:4] == "THR.":
		return false
	case len(name) > 3 && name[:3] == "PP[":
		return false
	}
	return true
}

// FlutterMetaComment is a comment entry for flutter_meta.json.
type FlutterMetaComment struct {
	Addr string `json:"addr"`
	Text string `json:"text"`
}
