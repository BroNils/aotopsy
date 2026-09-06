package naming

import (
	"fmt"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/snapshot"
)

// SDK-format type-testing-stub names.
//
// The readable name this project shows an analyst is Dart source form,
// `TypeTestingStub_List<int>`. The ELF symbol table's two assembly dialects
// spell the same stub the way the VM's own namer does, which is a different
// convention entirely:
//
//	TypeTestingStub_dart_core__List__dart_core__int
//
// Neither is more correct; they are the same claim in two notations. But a
// comparison that only sees the readable one scores every type-testing stub as
// a disagreement on every version -- 293 on dart-2.16.0-gt-arm64, 320 on
// 2.18.0 -- and, worse, made it look as though naming these stubs at all was a
// regression (see docs/findings-repo/012 and 015).
//
// So the SDK spelling is generated alongside the readable one, and the symtab
// differential compares against whichever notation the symbol is written in.
// Generating it is exact; parsing THEIR flattened string back into class and
// arguments is not, because a library URL and a class name are both just
// underscore-separated tokens once the SDK has scrubbed them.
//
// TypeTestingStubNamer::StringifyType (type_testing_stubs.cc, read at 2.18.0
// and 3.3.0):
//
//	curl = OS::SCreate(Z, "%s_", lib.url())            // "dart:core_"
//	name = AssemblerSafeName(SCreate("%s_%s", curl, klass.ScrubbedNameCString()))
//	for i in 0..klass.NumTypeParameters()-1:
//	    name = SCreate("%s__%s", name, StringifyType(args[len(args)-n+i]))
//
// Note the doubled separator: curl already ends in '_' and the format adds
// another, which is why `dart:core` + `List` comes out as `dart_core__List`
// and the private `_List` as `dart_core___List`.
//
// AssemblerSafeName folds every byte that is not [A-Za-z0-9_] to '_'.

// buildTypeTestingStubSDKNames returns the VM's own spelling of each
// type-testing stub name, keyed by the tested Type's ref ID.
//
// Empty when the Dart version's Types cannot be resolved to a class, matching
// buildTypeNames -- the two are built from the same inputs and must
// agree on which Types they can name.
func buildTypeTestingStubSDKNames(result *cluster.Result, l *PoolLookups, ct *snapshot.CIDTable, dartVersion string) map[int]string {
	if len(result.Types) == 0 {
		return nil
	}
	b := newTTSSDKBuilder(result, l, ct)
	out := make(map[int]string, len(result.Types))
	for i := range result.Types {
		t := &result.Types[i]
		if s := b.stringifyType(t, 0); s != "" {
			out[t.RefID] = "TypeTestingStub_" + s
		}
	}
	return out
}

type ttsSDKBuilder struct {
	classByCID map[int32]*cluster.ClassInfo
	classNames map[int32]string
	libURLs    map[int32]string
	typeByRef  map[int]*cluster.TypeInfo
	taByRef    map[int]*cluster.TypeArgumentsInfo
	ct         *snapshot.CIDTable
}

func newTTSSDKBuilder(result *cluster.Result, l *PoolLookups, ct *snapshot.CIDTable) *ttsSDKBuilder {
	b := &ttsSDKBuilder{
		classByCID: make(map[int32]*cluster.ClassInfo, len(result.Classes)),
		classNames: make(map[int32]string, len(result.Classes)),
		libURLs:    make(map[int32]string, len(result.Classes)),
		typeByRef:  make(map[int]*cluster.TypeInfo, len(result.Types)),
		taByRef:    make(map[int]*cluster.TypeArgumentsInfo, len(result.TypeArguments)),
		ct:         ct,
	}
	for i := range result.Classes {
		ci := &result.Classes[i]
		b.classByCID[ci.ClassID] = ci
		no, ok := l.RefToNamed[ci.RefID]
		if ok {
			name := l.ResolveName(no)
			if name == "" {
				name = l.ResolveVMName(no)
			}
			if name != "" {
				b.classNames[ci.ClassID] = name
			}
		}
		if ci.LibraryRefID >= 0 {
			if lo, ok := l.RefToNamed[ci.LibraryRefID]; ok {
				url := l.ResolveName(lo)
				if url == "" {
					url = l.ResolveVMName(lo)
				}
				if url != "" {
					b.libURLs[ci.ClassID] = url
				}
			}
		}
	}
	for i := range result.Types {
		b.typeByRef[result.Types[i].RefID] = &result.Types[i]
	}
	for i := range result.TypeArguments {
		b.taByRef[result.TypeArguments[i].RefID] = &result.TypeArguments[i]
	}
	return b
}

// stringifyType mirrors TypeTestingStubNamer::StringifyType. Returns "" when
// the class cannot be resolved, so a partial name is never invented.
func (b *ttsSDKBuilder) stringifyType(t *cluster.TypeInfo, depth int) string {
	if t == nil || depth > 4 {
		return ""
	}
	name, ok := b.classNames[t.ClassID]
	if !ok {
		if b.ct == nil {
			return ""
		}
		if name = cluster.CidNameV(int(t.ClassID), b.ct); name == "" {
			return ""
		}
	}
	// `curl` already ends in '_', and the format string adds another.
	curl := ""
	if u, ok := b.libURLs[t.ClassID]; ok {
		curl = u + "_"
	} else {
		// The SDK emits `nolib<n>_` here, with a counter we cannot
		// reproduce, so a class whose library is unknown gets no prefix
		// rather than a fabricated one.
		curl = ""
	}
	s := assemblerSafeName(fmt.Sprintf("%s_%s", curl, name))

	// Only the trailing NumTypeParameters() arguments are named, and only
	// when the type actually carries arguments.
	if t.ArgumentsRef > 0 {
		if ta, ok := b.taByRef[t.ArgumentsRef]; ok && len(ta.TypeRefs) > 0 {
			n := b.numTypeParameters(t.ClassID, len(ta.TypeRefs))
			start := len(ta.TypeRefs) - n
			for i := start; i < len(ta.TypeRefs); i++ {
				arg := b.stringifyType(b.typeByRef[ta.TypeRefs[i]], depth+1)
				if arg == "" {
					// A type parameter (`X0`) or an unresolved class. The
					// SDK would print something; we cannot, so the name
					// stops being reproducible and is dropped entirely
					// rather than emitted short.
					return ""
				}
				s += "__" + arg
			}
		}
	}
	return s
}

// numTypeParameters is Class::NumTypeParameters, which the snapshot does not
// carry directly. The SDK names the LAST n arguments, where n is the class's
// own parameter count; a superclass's arguments come first in the vector.
//
// Without the count, the whole vector is used. That is exact for a class whose
// superclass is non-generic -- the common case -- and over-long otherwise, so
// such a name simply fails to match rather than matching something wrong.
func (b *ttsSDKBuilder) numTypeParameters(cid int32, have int) int {
	return have
}

// assemblerSafeName is TypeTestingStubNamer::AssemblerSafeName: every byte
// outside [A-Za-z0-9_] becomes '_'.
func assemblerSafeName(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			sb.WriteByte(c)
			continue
		}
		sb.WriteByte('_')
	}
	return sb.String()
}
