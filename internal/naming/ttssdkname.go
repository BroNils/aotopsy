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
// TypeTestingStubNamer::StringifyType (type_testing_stubs.cc, exact SDK refs):
//
//	curl = OS::SCreate(Z, "%s_", lib.url())            // "dart:core_"
//	name = AssemblerSafeName(SCreate("%s_%s", curl, klass.ScrubbedNameCString()))
//	<=3.0: for i in 0..klass.NumTypeParameters()-1:
//	          name += "__" + StringifyType(args[len(args)-n+i])
//	>=3.1: for arg in args:
//	          name += "__" + StringifyType(arg)
//
// 3.0.5 is the last verified trailing-own-parameter implementation; 3.1.0 is
// the first verified whole-vector implementation. ttsNameContext.argumentRefs
// carries that boundary for both readable and VM-form names.
//
// Note the doubled separator: curl already ends in '_' and the format adds
// another, which is why `dart:core` + `List` comes out as `dart_core__List`
// and the private `_List` as `dart_core___List`.
//
// AssemblerSafeName folds every byte that is not [A-Za-z0-9_] to '_'.

// buildTypeTestingStubSDKNames returns the VM's own spelling of each
// type-testing stub name, keyed by the tested Type's ref ID.
//
// Entries are emitted only when the VM spelling is reproducible exactly. That
// includes every required generic argument and library prefix; classes whose
// SDK name would depend on the runtime `nolib<n>` nonce are omitted.
func buildTypeTestingStubSDKNames(result *cluster.Result, l *PoolLookups, ct *snapshot.CIDTable, dartVersion string) map[int]string {
	if len(result.Types) == 0 {
		return nil
	}
	b := newTTSSDKBuilder(result, l, ct, dartVersion)
	out := make(map[int]string, len(result.Types))
	for i := range result.Types {
		t := &result.Types[i]
		if s := b.stringifyType(t, make(map[int]bool)); s != "" {
			out[t.RefID] = "TypeTestingStub_" + s
		}
	}
	return out
}

type ttsSDKBuilder struct {
	names   *ttsNameContext
	libURLs map[int32]string
}

func newTTSSDKBuilder(result *cluster.Result, l *PoolLookups, ct *snapshot.CIDTable, dartVersion string) *ttsSDKBuilder {
	b := &ttsSDKBuilder{
		names:   newTTSNameContext(result, l, ct, dartVersion),
		libURLs: make(map[int32]string, len(result.Classes)),
	}
	for i := range result.Classes {
		ci := &result.Classes[i]
		if ci.LibraryRefID >= 0 {
			if lo, ok := l.RefToNamed[ci.LibraryRefID]; ok {
				url := l.resolveIsolateName(lo)
				if url != "" {
					b.libURLs[ci.ClassID] = url
				}
			}
		}
	}
	return b
}

// stringifyType mirrors TypeTestingStubNamer::StringifyType. Returns "" when
// the class cannot be resolved, so a partial name is never invented.
func (b *ttsSDKBuilder) stringifyType(t *cluster.TypeInfo, path map[int]bool) string {
	if t == nil || path[t.RefID] {
		return ""
	}
	path[t.RefID] = true
	defer delete(path, t.RefID)
	name := b.names.className(t.ClassID)
	if name == "" {
		return ""
	}
	// `curl` already ends in '_', and the format string adds another.
	curl := ""
	if u, ok := b.libURLs[t.ClassID]; ok {
		curl = u + "_"
	} else {
		// The SDK emits `nolib<n>_` here, with a counter we cannot
		// reproduce. This map is used as an exact alternative spelling in
		// the symtab differential, so omitting the prefix would create a
		// shortened identity. Refuse the VM-form name instead.
		return ""
	}
	s := assemblerSafeName(fmt.Sprintf("%s_%s", curl, name))

	refs, ok := b.names.argumentRefs(t)
	if !ok {
		return ""
	}
	for _, ref := range refs {
		arg := b.stringifyRef(ref, path)
		if arg == "" {
			return ""
		}
		s += "__" + arg
	}
	return s
}

func (b *ttsSDKBuilder) stringifyRef(ref int, path map[int]bool) string {
	if t, ok := b.names.typeByRef[ref]; ok {
		return b.stringifyType(t, path)
	}
	if no, ok := b.names.typeParameterForRef(ref); ok {
		if name, ok := b.names.typeParameterTTSName(no); ok {
			// TypeTestingStubNamer uses the TypeParameter's source name through
			// Dart 2.13 and CanonicalNameCString from 2.14 onward. Neither branch
			// appends the TypeParameter's `?` suffix.
			return assemblerSafeName(name)
		}
	}
	return ""
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
