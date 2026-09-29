package naming

import (
	"fmt"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/snapshot"
)

// ttsNameContext contains the snapshot facts needed to reproduce a
// type-testing stub identity without shortening it. TypeNames is deliberately
// more forgiving because it is also used for human-oriented pool display;
// this context is for identities that become Code names and call targets.
type ttsNameContext struct {
	pl             *PoolLookups
	ct             *snapshot.CIDTable
	dartVersion    string
	classNames     map[int32]string
	typeByRef      map[int]*cluster.TypeInfo
	typeArgsByRef  map[int]*cluster.TypeArgumentsInfo
	ownParamsByCID map[int32]int
}

func newTTSNameContext(result *cluster.Result, pl *PoolLookups, ct *snapshot.CIDTable, dartVersion string) *ttsNameContext {
	c := &ttsNameContext{
		pl:             pl,
		ct:             ct,
		dartVersion:    dartVersion,
		classNames:     make(map[int32]string, len(result.Classes)),
		typeByRef:      make(map[int]*cluster.TypeInfo, len(result.Types)),
		typeArgsByRef:  make(map[int]*cluster.TypeArgumentsInfo, len(result.TypeArguments)),
		ownParamsByCID: make(map[int32]int, len(result.Classes)),
	}
	for i := range result.Types {
		t := &result.Types[i]
		c.typeByRef[t.RefID] = t
	}
	for i := range result.TypeArguments {
		ta := &result.TypeArguments[i]
		c.typeArgsByRef[ta.RefID] = ta
	}
	tpByRef := make(map[int]*cluster.TypeParametersInfo, len(result.TypeParameters))
	for i := range result.TypeParameters {
		tp := &result.TypeParameters[i]
		tpByRef[tp.RefID] = tp
	}
	arrayByRef := make(map[int]*cluster.ArrayInfo, len(result.Arrays))
	for i := range result.Arrays {
		a := &result.Arrays[i]
		arrayByRef[a.RefID] = a
	}
	for i := range result.Classes {
		ci := &result.Classes[i]
		if pl != nil {
			if no, ok := pl.RefToNamed[ci.RefID]; ok {
				name := scrubDartPrivateKeys(pl.resolveIsolateName(no))
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
				if names, ok := arrayByRef[tp.NamesArrayRef]; ok {
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
	name := c.pl.resolveIsolateName(no)
	return name, name != ""
}

// scrubDartPrivateKeys is the class-name part of String::ScrubName used by
// Class::ScrubbedNameCString: each private suffix `@<digits>` is removed, even
// when a generated class name contains several of them. Class names do not use
// the getter/setter/constructor spellings that String::ScrubName also handles.
func scrubDartPrivateKeys(name string) string {
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
	if no, ok := c.typeParameterForRef(ref); ok {
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
	switch snapshot.BaseObjectName(c.dartVersion, ref) {
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
	suffix, ok := readableNullabilitySuffix(t.Nullability, name)
	if !ok {
		return "", false
	}
	return name + suffix, true
}

func buildExactTypeTestingStubNames(result *cluster.Result, pl *PoolLookups, ct *snapshot.CIDTable, dartVersion string) map[int]string {
	if result == nil || len(result.Types) == 0 {
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
	if len(out) == 0 {
		return nil
	}
	return out
}
