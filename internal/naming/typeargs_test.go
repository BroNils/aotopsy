package naming

import (
	"testing"

	"aotopsy/internal/cluster"
)

// TestTypeArgsListIsAllOrNothing pins the rule that makes rendering a bare
// TypeArguments object safe.
//
// A partially-rendered argument list is a name that looks precise and is not:
// `<int, ?>` silently drops a parameter, and `<int>` for a two-argument list
// claims the wrong arity. One unresolvable element must make the whole list
// unavailable, leaving the honest `<TypeArguments>` placeholder.
func TestTypeArgsListIsAllOrNothing(t *testing.T) {
	types := map[int]*cluster.TypeInfo{
		10: {RefID: 10, ClassID: 1},
		11: {RefID: 11, ClassID: 2},
	}
	names := map[int32]string{1: "int", 2: "String"}
	nameOfClass := func(cid int32) string { return names[cid] }
	tas := map[int]*cluster.TypeArgumentsInfo{}

	t.Run("all resolvable", func(t *testing.T) {
		ta := &cluster.TypeArgumentsInfo{RefID: 1, Length: 2, TypeRefs: []int{10, 11}}
		got, ok := typeArgsListString(ta, types, tas, nameOfClass, 0)
		if !ok || got != "<int, String>" {
			t.Errorf("got %q ok=%v, want %q true", got, ok, "<int, String>")
		}
	})

	t.Run("one element has no captured Type", func(t *testing.T) {
		ta := &cluster.TypeArgumentsInfo{RefID: 2, Length: 2, TypeRefs: []int{10, 999}}
		if got, ok := typeArgsListString(ta, types, tas, nameOfClass, 0); ok {
			t.Errorf("rendered %q from a partially-unresolvable list", got)
		}
	})

	t.Run("one element's class is unnamed", func(t *testing.T) {
		types[12] = &cluster.TypeInfo{RefID: 12, ClassID: 77} // 77 not in names
		ta := &cluster.TypeArgumentsInfo{RefID: 3, Length: 2, TypeRefs: []int{10, 12}}
		if got, ok := typeArgsListString(ta, types, tas, nameOfClass, 0); ok {
			t.Errorf("rendered %q with an unnamed class", got)
		}
	})

	t.Run("empty and nil refuse", func(t *testing.T) {
		if _, ok := typeArgsListString(nil, types, tas, nameOfClass, 0); ok {
			t.Error("nil TypeArguments rendered")
		}
		ta := &cluster.TypeArgumentsInfo{RefID: 4, Length: 0}
		if _, ok := typeArgsListString(ta, types, tas, nameOfClass, 0); ok {
			t.Error("empty TypeArguments rendered")
		}
	})

	t.Run("depth is bounded", func(t *testing.T) {
		ta := &cluster.TypeArgumentsInfo{RefID: 5, Length: 1, TypeRefs: []int{10}}
		if _, ok := typeArgsListString(ta, types, tas, nameOfClass, 5); ok {
			t.Error("rendered past the recursion bound")
		}
	})
}
