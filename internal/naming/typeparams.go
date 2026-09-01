package naming

import (
	"strings"

	"aotopsy/internal/cluster"
)

// Generic type parameter reconstruction: the consumer for the TypeParameters /
// FunctionType capture, covering the gap-analysis §2.3 row "No generic type
// parameter reconstruction".
//
// What this resolves is a function's declared type PARAMETERS -- the `<T>` in
//
//	void runUnaryGuarded<T>(void f(T arg), T arg)
//
// which is what belongs in a signature. It is deliberately NOT
// TypeArguments: an earlier attempt read the TypeArguments hanging off the
// FunctionType's parameter_types ARRAY and printed those, which is a different
// object entirely (it describes the array, not the function) and would have
// printed type *arguments* where type *parameters* belong, i.e. invalid Dart
// like `foo<int, String>(...)` as a declaration. That attempt also produced
// nothing on every function measured.
//
// The resolution chain, all from data captured during fill:
//
//	FunctionType.type_parameters -> TypeParameters.names (an Array)
//	                            -> Array.ElementRefIDs   -> Strings

// TypeParam is one declared generic parameter: its name and, when it is not the
// implicit default, its bound.
type TypeParam struct {
	Name string
	// Bound is the class name from `<T extends Bound>`, or "" when the bound is
	// absent or is the implicit `Object`/`Object?` that every unbounded
	// parameter carries. Emitting "extends Object?" on every parameter would be
	// noise, so the implicit case is deliberately reported as no bound.
	Bound string
}

// String renders the parameter as Dart source: "T" or "T extends Bound".
func (p TypeParam) String() string {
	if p.Bound == "" {
		return p.Name
	}
	return p.Name + " extends " + p.Bound
}

// FormatTypeParams renders a parameter list as "<T, U extends V>", or "" when
// there are none.
func FormatTypeParams(params []TypeParam) string {
	if len(params) == 0 {
		return ""
	}
	parts := make([]string, len(params))
	for i, p := range params {
		parts[i] = p.String()
	}
	return "<" + strings.Join(parts, ", ") + ">"
}

// BuildFuncTypeParamNames maps a FunctionType's ref ID to its declared generic
// parameters, in declaration order.
//
// FunctionTypes with no type parameters are absent from the map rather than
// present-with-empty, so callers can use plain lookup. Returns nil if this Dart
// version has no verified type_parameters index (see
// cluster.FuncTypeInfo.TypeParamsRefID).
//
// Bounds come from TypeParameters.bounds (ref 2), a TypeArguments whose i-th
// type is the i-th parameter's bound; each Type resolves to a ClassID and from
// there to a class name.
func BuildFuncTypeParamNames(result *cluster.Result, pl *PoolLookups) map[int][]TypeParam {
	if pl == nil || len(result.TypeParameters) == 0 {
		return nil
	}

	tpByRef := make(map[int]*cluster.TypeParametersInfo, len(result.TypeParameters))
	for i := range result.TypeParameters {
		tpByRef[result.TypeParameters[i].RefID] = &result.TypeParameters[i]
	}
	arrByRef := make(map[int]*cluster.ArrayInfo, len(result.Arrays))
	for i := range result.Arrays {
		arrByRef[result.Arrays[i].RefID] = &result.Arrays[i]
	}
	taByRef := make(map[int]*cluster.TypeArgumentsInfo, len(result.TypeArguments))
	for i := range result.TypeArguments {
		taByRef[result.TypeArguments[i].RefID] = &result.TypeArguments[i]
	}
	typeByRef := make(map[int]*cluster.TypeInfo, len(result.Types))
	for i := range result.Types {
		typeByRef[result.Types[i].RefID] = &result.Types[i]
	}
	nameByClassID := make(map[int32]string, len(result.Classes))
	for _, ci := range result.Classes {
		if n, ok := pl.StringForRef(ci.NameRefID); ok && n != "" {
			nameByClassID[ci.ClassID] = n
		}
	}
	// boundName resolves the i-th bound of a bounds TypeArguments to a class
	// name, or "" when it is absent or the implicit Object bound.
	boundName := func(boundsRef, i int) string {
		ta, ok := taByRef[boundsRef]
		if !ok || i >= len(ta.TypeRefs) {
			return ""
		}
		ti, ok := typeByRef[ta.TypeRefs[i]]
		if !ok || ti.ClassID <= 0 {
			return ""
		}
		n := nameByClassID[ti.ClassID]
		// Every unbounded parameter is implicitly bounded by Object; reporting
		// that adds no information.
		if n == "Object" {
			return ""
		}
		return n
	}

	out := make(map[int][]TypeParam)
	for i := range result.FuncTypes {
		ft := &result.FuncTypes[i]
		// RefNull means the function declares no type parameters, which is the
		// common case; -1 means the capture is not available for this version.
		if ft.TypeParamsRefID <= cluster.RefNull {
			continue
		}
		tp, ok := tpByRef[ft.TypeParamsRefID]
		if !ok || tp.NamesArrayRef <= cluster.RefNull {
			continue
		}
		arr, ok := arrByRef[tp.NamesArrayRef]
		if !ok {
			continue
		}
		var params []TypeParam
		for idx, elemRef := range arr.ElementRefIDs {
			// StringForRef, not RefToStr: type parameter names are short,
			// heavily shared strings ("T", "K", "V") that live in the VM
			// snapshot as base objects, so an isolate-only lookup misses most
			// of them (measured: 12 of 84 generic FunctionTypes).
			name, ok := pl.StringForRef(elemRef)
			if !ok || name == "" {
				continue
			}
			params = append(params, TypeParam{
				Name:  name,
				Bound: boundName(tp.BoundsRef, idx),
			})
		}
		if len(params) > 0 {
			out[ft.RefID] = params
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// BuildClosureParents maps a closure Function's ref ID to the name of the
// function it was declared inside.
//
// This is the consumer for the ClosureData capture. Chain:
//
//	Function.data (ref 3) -> ClosureData.parent_function -> Function -> name
//
// It exists because OwnerRefID only reaches the owning CLASS, so every
// anonymous closure in a class renders identically ("Foo.<anonymous closure>")
// regardless of which method declared it. parent_function distinguishes them.
//
// ClosureData is also the only AOT-available substitute for Context, which the
// gap analysis assumed would carry closure information: Context is never
// serialized in AOT, while ClosureData always is.
func BuildClosureParents(result *cluster.Result, pl *PoolLookups) map[int]string {
	if pl == nil || pl.CT == nil || len(result.ClosureData) == 0 {
		return nil
	}
	// ClosureData ref -> parent function ref.
	parentByData := make(map[int]int, len(result.ClosureData))
	for i := range result.ClosureData {
		cd := &result.ClosureData[i]
		if cd.ParentFunctionRef > cluster.RefNull {
			parentByData[cd.RefID] = cd.ParentFunctionRef
		}
	}
	if len(parentByData) == 0 {
		return nil
	}

	out := make(map[int]string)
	for i := range result.Named {
		no := &result.Named[i]
		if no.CID != pl.CT.Function || no.DataRefID <= cluster.RefNull {
			continue
		}
		// Tear-offs (implicit closures) are NOT qualified by their enclosing
		// function: the SDK prepends the parent name only for non-implicit
		// closures (FunctionPrintNameHelper, IsNonImplicitClosureFunction in
		// object.cc). A tear-off of `_throwNew` is named `_throwNew`, not
		// `_throwNew._throwNew`. This is by kind, not by ref equality: the
		// tear-off and the method it tears off are DISTINCT NamedObjects that
		// merely share a name, so the old self-reference guard below never
		// caught them -- it left 288 doubled names (30% of the residual
		// disagreements on 3.9.2) like `StateError._throwNew._throwNew`.
		if no.IsImplicitClosure() {
			continue
		}
		parentRef, ok := parentByData[no.DataRefID]
		if !ok {
			continue
		}
		// Self-references still skipped: a ClosureData whose parent_function is
		// the very function owning it carries no information.
		if parentRef == no.RefID {
			continue
		}
		parent, ok := pl.RefToNamed[parentRef]
		if !ok && pl.VmRefToNamed != nil {
			parent, ok = pl.VmRefToNamed[parentRef]
		}
		if !ok {
			continue
		}
		name := pl.ResolveName(parent)
		if name == "" {
			name = pl.ResolveVMName(parent)
		}
		if name == "" {
			continue
		}
		if owner := pl.ResolveOwnerName(parent); owner != "" {
			name = owner + "." + name
		}
		out[no.RefID] = name
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
