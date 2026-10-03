package naming

import (
	"fmt"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/vmtables"
)

// ttsNameContext contains the snapshot facts needed to reproduce a
// type-testing stub identity without shortening it. TypeNames is deliberately
// more forgiving because it is also used for human-oriented pool display;
// this context is for identities that become Code names and call targets.
type ttsNameContext struct {
	pl          *PoolLookups
	ct          *snapshot.CIDTable
	dartVersion string
	// forSource renders a type as Dart SOURCE rather than as a stub identity: a
	// type that mentions a type parameter is refused (the VM's canonical X0/Y0/
	// C1X0 spelling is an identity, not a declared identifier) and a legacy
	// nullability marker is dropped (`String*` is not Dart syntax; a legacy
	// library simply writes `String`).
	forSource            bool
	classNames           map[int32]string
	typeByRef            map[int]*cluster.TypeInfo
	recordTypeByRef      map[int]*cluster.RecordTypeInfo
	typeArgsByRef        map[int]*cluster.TypeArgumentsInfo
	arrayByRef           map[int]*cluster.ArrayInfo
	mintValues           map[int]int64
	recordFieldNamesRoot int
	ownParamsByCID       map[int32]int
}

func newTTSNameContext(result *cluster.Result, pl *PoolLookups, ct *snapshot.CIDTable, dartVersion string) *ttsNameContext {
	c := &ttsNameContext{
		pl:              pl,
		ct:              ct,
		dartVersion:     dartVersion,
		classNames:      make(map[int32]string, len(result.Classes)),
		typeByRef:       make(map[int]*cluster.TypeInfo, len(result.Types)),
		recordTypeByRef: make(map[int]*cluster.RecordTypeInfo, len(result.RecordTypes)),
		typeArgsByRef:   make(map[int]*cluster.TypeArgumentsInfo, len(result.TypeArguments)),
		arrayByRef:      make(map[int]*cluster.ArrayInfo, len(result.Arrays)),
		mintValues:      result.MintValues,
		ownParamsByCID:  make(map[int32]int, len(result.Classes)),
	}
	for i := range result.Types {
		t := &result.Types[i]
		c.typeByRef[t.RefID] = t
	}
	for i := range result.TypeArguments {
		ta := &result.TypeArguments[i]
		c.typeArgsByRef[ta.RefID] = ta
	}
	for i := range result.RecordTypes {
		rt := &result.RecordTypes[i]
		c.recordTypeByRef[rt.RefID] = rt
	}
	tpByRef := make(map[int]*cluster.TypeParametersInfo, len(result.TypeParameters))
	for i := range result.TypeParameters {
		tp := &result.TypeParameters[i]
		tpByRef[tp.RefID] = tp
	}
	for i := range result.Arrays {
		a := &result.Arrays[i]
		c.arrayByRef[a.RefID] = a
	}
	if idx, ok := vmtables.ObjectStoreRecordFieldNamesIndex(dartVersion); ok && idx >= 0 && idx < len(result.ObjectStoreRefs) {
		c.recordFieldNamesRoot = result.ObjectStoreRefs[idx]
	}
	for i := range result.Classes {
		ci := &result.Classes[i]
		if pl != nil {
			if no, ok := pl.RefToNamed[ci.RefID]; ok {
				name := ScrubDartPrivateKeys(pl.ResolveIsolateName(no))
				if name != "" {
					c.classNames[ci.ClassID] = name
				}
			}
		}

		// Before Dart 3.1 TypeTestingStubNamer calls Class::NumTypeParameters
		// and takes only that many trailing entries from Type.arguments(). The
		// class field changed representation over time: older snapshots point
		// directly at a TypeArguments, newer ones at TypeParameters whose names
		// Array has the declaration arity. Both are already captured here.
		ref := ci.TypeParamsRefID
		switch {
		case ref == cluster.RefNull:
			c.ownParamsByCID[ci.ClassID] = 0
		case ref > cluster.RefNull:
			if tp, ok := tpByRef[ref]; ok {
				if names, ok := c.arrayByRef[tp.NamesArrayRef]; ok {
					c.ownParamsByCID[ci.ClassID] = len(names.ElementRefIDs)
				}
			} else if ta, ok := c.typeArgsByRef[ref]; ok {
				if ta.Length == len(ta.TypeRefs) {
					c.ownParamsByCID[ci.ClassID] = ta.Length
				}
			}
		}
	}
	return c
}

func (c *ttsNameContext) className(cid int32) string {
	if name := c.classNames[cid]; name != "" {
		return name
	}
	if c.ct != nil {
		return cluster.CidNameV(int(cid), c.ct)
	}
	return ""
}

// argumentRefs returns exactly the argument refs the VM's TTS namer uses.
// Dart <=3.0 uses only the class's own trailing parameters; Dart >=3.1 uses
// the complete Type.arguments vector. Missing serialized data is a hard
// failure because callers use the result as an identity, not a hint.
func (c *ttsNameContext) argumentRefs(t *cluster.TypeInfo) ([]int, bool) {
	if t == nil {
		return nil, false
	}
	if t.ArgumentsRef == cluster.RefNull {
		return nil, true
	}
	if t.ArgumentsRef <= 0 {
		return nil, false
	}
	ta, ok := c.typeArgsByRef[t.ArgumentsRef]
	if !ok || ta.Length != len(ta.TypeRefs) {
		return nil, false
	}
	refs := ta.TypeRefs
	if snapshot.VersionAtLeast(c.dartVersion, "3.1.0") {
		return refs, true
	}
	n, ok := c.ownParamsByCID[t.ClassID]
	if !ok || n < 0 || n > len(refs) {
		return nil, false
	}
	return refs[len(refs)-n:], true
}

func canonicalTypeParameterName(no *cluster.NamedObject) (string, bool) {
	if no == nil || !no.HasTypeParamMetadata || no.TypeParamBase < 0 || no.TypeParamIndex < no.TypeParamBase {
		return "", false
	}
	basePrefix, indexPrefix := "C", "X"
	if no.TypeParamIsFunction {
		basePrefix, indexPrefix = "F", "Y"
	}
	var b strings.Builder
	if no.TypeParamBase != 0 {
		fmt.Fprintf(&b, "%s%d", basePrefix, no.TypeParamBase)
	}
	fmt.Fprintf(&b, "%s%d", indexPrefix, no.TypeParamIndex-no.TypeParamBase)
	return b.String(), true
}

// typeParameterTTSName mirrors the versioned TypeTestingStubNamer branch.
// Dart <=2.13 serialized and printed TypeParameter.name() (for example T/U).
// Dart >=2.14 removed that name from the TypeParameter layout and prints the
// CanonicalNameCString spelling (C/F + X/Y indices) instead. When an old
// snapshot did not expose the serialized name to this package, refusing the
// identity is the only exact answer; synthesizing X0 would name a different VM
// stub than the SDK did.
func (c *ttsNameContext) typeParameterTTSName(no *cluster.NamedObject) (string, bool) {
	if snapshot.VersionAtLeast(c.dartVersion, "2.14.0") {
		return canonicalTypeParameterName(no)
	}
	if c.pl == nil || no == nil || no.NameRefID <= cluster.RefNull {
		return "", false
	}
	name := c.pl.ResolveIsolateName(no)
	return name, name != ""
}

// ScrubDartPrivateKeys is the private-key portion of String::ScrubName used by
// Class::ScrubbedNameCString: each private suffix `@<digits>` is removed, even
// when a generated name contains several of them. It deliberately does not
// perform the getter/setter/constructor spelling rewrites that ScrubName also
// performs; callers choose those separately according to their identity model.
func ScrubDartPrivateKeys(name string) string {
	first := -1
	for i := 0; i+1 < len(name); i++ {
		if name[i] == '@' && name[i+1] >= '0' && name[i+1] <= '9' {
			first = i
			break
		}
	}
	if first < 0 {
		return name
	}
	var b strings.Builder
	b.Grow(len(name))
	b.WriteString(name[:first])
	for i := first; i < len(name); {
		if name[i] == '@' && i+1 < len(name) && name[i+1] >= '0' && name[i+1] <= '9' {
			i += 2
			for i < len(name) && name[i] >= '0' && name[i] <= '9' {
				i++
			}
			continue
		}
		b.WriteByte(name[i])
		i++
	}
	return b.String()
}

func readableNullabilitySuffix(n cluster.TypeNullability, baseName string) (string, bool) {
	// AbstractType::NullabilitySuffix deliberately hides the suffix for these
	// three special types.
	if baseName == "dynamic" || baseName == "void" || baseName == "Null" {
		return "", n != cluster.TypeNullabilityUnknown
	}
	switch n {
	case cluster.TypeNullabilityNullable:
		return "?", true
	case cluster.TypeNullabilityNonNullable:
		return "", true
	case cluster.TypeNullabilityLegacy:
		return "*", true
	default:
		return "", false
	}
}

// nullabilitySuffix is readableNullabilitySuffix with the source-mode rule for
// legacy types applied.
func (c *ttsNameContext) nullabilitySuffix(n cluster.TypeNullability, baseName string) (string, bool) {
	if c.forSource && n == cluster.TypeNullabilityLegacy {
		return "", true
	}
	return readableNullabilitySuffix(n, baseName)
}

func (c *ttsNameContext) typeParameterForRef(ref int) (*cluster.NamedObject, bool) {
	if c.pl == nil || c.ct == nil || c.ct.TypeParameter == 0 || ref <= cluster.RefNull {
		return nil, false
	}
	if no, ok := c.pl.RefToNamed[ref]; ok && no != nil && no.CID == c.ct.TypeParameter {
		return no, true
	}
	// VM and isolate ref spaces overlap above the base-object prefix. Only a
	// base-object ref is allowed to fall back into VmRefToNamed, matching the
	// StringForRef rule used elsewhere in naming.
	if ref < c.pl.BaseObjLimit {
		if no, ok := c.pl.VmRefToNamed[ref]; ok && no != nil && no.CID == c.ct.TypeParameter {
			return no, true
		}
	}
	return nil, false
}

func (c *ttsNameContext) readableRef(ref int, path map[int]bool) (string, bool) {
	if t, ok := c.typeByRef[ref]; ok {
		return c.readableType(t, path)
	}
	if rt, ok := c.recordTypeByRef[ref]; ok {
		return c.readableRecordType(rt, path)
	}
	if no, ok := c.typeParameterForRef(ref); ok {
		if c.forSource {
			return "", false
		}
		name, ok := c.typeParameterTTSName(no)
		if !ok {
			return "", false
		}
		suffix, ok := readableNullabilitySuffix(no.TypeParamNullability, name)
		if !ok {
			return "", false
		}
		return name + suffix, true
	}
	// dynamic and void are VM-isolate base objects on the versions where they
	// can appear here, so they have no TypeInfo in the app snapshot.
	return singletonTypeName(snapshot.BaseObjectName(c.dartVersion, ref))
}

// recordComponents resolves the two pieces encoded by RecordShape: the exact
// field type refs and the ordered named-field strings. SDK 3.0+ reserves shape
// index 0 for records without named fields; non-zero indices address
// ObjectStore.record_field_names, whose serialized root index is generated
// from the exact SDK ObjectStore field list.
func (c *ttsNameContext) recordComponents(rt *cluster.RecordTypeInfo) ([]int, []string, bool) {
	if c == nil || rt == nil || rt.ShapeRef <= cluster.RefNull || rt.FieldTypesArrayRef <= cluster.RefNull {
		return nil, nil, false
	}
	shape, ok := c.mintValues[rt.ShapeRef]
	if !ok || shape < 0 {
		return nil, nil, false
	}
	numFields := int(uint64(shape) & 0xffff)
	fieldNamesIndex := int(uint64(shape) >> 16)
	fields, ok := c.arrayByRef[rt.FieldTypesArrayRef]
	if !ok || fields == nil || len(fields.ElementRefIDs) != numFields {
		return nil, nil, false
	}
	types := append([]int(nil), fields.ElementRefIDs...)
	if fieldNamesIndex == 0 {
		return types, nil, true
	}
	if c.recordFieldNamesRoot <= cluster.RefNull {
		return nil, nil, false
	}
	table, ok := c.arrayByRef[c.recordFieldNamesRoot]
	if !ok || table == nil || fieldNamesIndex >= len(table.ElementRefIDs) {
		return nil, nil, false
	}
	nameArrayRef := table.ElementRefIDs[fieldNamesIndex]
	nameArray, ok := c.arrayByRef[nameArrayRef]
	if !ok || nameArray == nil || len(nameArray.ElementRefIDs) > numFields {
		return nil, nil, false
	}
	names := make([]string, 0, len(nameArray.ElementRefIDs))
	for _, ref := range nameArray.ElementRefIDs {
		name, ok := c.pl.StringForRef(ref)
		if !ok || name == "" {
			return nil, nil, false
		}
		names = append(names, name)
	}
	return types, names, true
}

func (c *ttsNameContext) readableRecordType(rt *cluster.RecordTypeInfo, path map[int]bool) (string, bool) {
	if rt == nil || path[rt.RefID] {
		return "", false
	}
	path[rt.RefID] = true
	defer delete(path, rt.RefID)
	fieldRefs, fieldNames, ok := c.recordComponents(rt)
	if !ok {
		return "", false
	}
	positional := len(fieldRefs) - len(fieldNames)
	if positional < 0 {
		return "", false
	}
	pos := make([]string, 0, positional)
	named := make([]string, 0, len(fieldNames))
	for i, ref := range fieldRefs {
		name, ok := c.readableRef(ref, path)
		if !ok {
			return "", false
		}
		if i < positional {
			pos = append(pos, name)
			continue
		}
		named = append(named, name+" "+fieldNames[i-positional])
	}
	var body string
	switch {
	case len(named) == 0:
		body = strings.Join(pos, ", ")
	case len(pos) == 0:
		body = "{" + strings.Join(named, ", ") + "}"
	default:
		body = strings.Join(pos, ", ") + ", {" + strings.Join(named, ", ") + "}"
	}
	name := "(" + body + ")"
	suffix, ok := c.nullabilitySuffix(rt.Nullability, name)
	if !ok {
		return "", false
	}
	return name + suffix, true
}

// singletonTypeName maps the VM-isolate base-object labels of the two singleton
// types that have no TypeInfo (dynamic, void) to their Dart spelling.
func singletonTypeName(baseObjectName string) (string, bool) {
	switch baseObjectName {
	case "<dynamic type>":
		return "dynamic", true
	case "<void type>":
		return "void", true
	}
	return "", false
}

func (c *ttsNameContext) readableType(t *cluster.TypeInfo, path map[int]bool) (string, bool) {
	if t == nil || path[t.RefID] {
		return "", false
	}
	path[t.RefID] = true
	defer delete(path, t.RefID)
	name := c.className(t.ClassID)
	if name == "" {
		return "", false
	}
	refs, ok := c.argumentRefs(t)
	if !ok {
		return "", false
	}
	if len(refs) > 0 {
		parts := make([]string, 0, len(refs))
		for _, ref := range refs {
			arg, ok := c.readableRef(ref, path)
			if !ok {
				return "", false
			}
			parts = append(parts, arg)
		}
		name += "<" + strings.Join(parts, ", ") + ">"
	}
	suffix, ok := c.nullabilitySuffix(t.Nullability, name)
	if !ok {
		return "", false
	}
	return name + suffix, true
}

// buildExactSourceTypeNames renders every Type whose complete identity the
// snapshot proves as the Dart source spelling of that type (List<int?>,
// Map<String, Foo>?). It is exact-or-absent like the stub identities, but a type
// that mentions a type parameter is absent: a signature cannot name X0.
func buildExactSourceTypeNames(result *cluster.Result, pl *PoolLookups, ct *snapshot.CIDTable, dartVersion string) map[int]string {
	if result == nil || (len(result.Types) == 0 && len(result.RecordTypes) == 0) {
		return nil
	}
	c := newTTSNameContext(result, pl, ct, dartVersion)
	c.forSource = true
	out := make(map[int]string, len(result.Types))
	for i := range result.Types {
		t := &result.Types[i]
		if name, ok := c.readableType(t, make(map[int]bool)); ok {
			out[t.RefID] = name
		}
	}
	for i := range result.RecordTypes {
		rt := &result.RecordTypes[i]
		if name, ok := c.readableRecordType(rt, make(map[int]bool)); ok {
			out[rt.RefID] = name
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func buildExactTypeTestingStubNames(result *cluster.Result, pl *PoolLookups, ct *snapshot.CIDTable, dartVersion string) map[int]string {
	if result == nil || (len(result.Types) == 0 && len(result.RecordTypes) == 0) {
		return nil
	}
	c := newTTSNameContext(result, pl, ct, dartVersion)
	out := make(map[int]string, len(result.Types))
	for i := range result.Types {
		t := &result.Types[i]
		if name, ok := c.readableType(t, make(map[int]bool)); ok {
			out[t.RefID] = "TypeTestingStub_" + name
		}
	}
	for i := range result.RecordTypes {
		rt := &result.RecordTypes[i]
		if name, ok := c.readableRecordType(rt, make(map[int]bool)); ok {
			out[rt.RefID] = "TypeTestingStub_" + name
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
