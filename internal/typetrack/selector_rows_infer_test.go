package typetrack

import (
	"reflect"
	"testing"
)

// A method declared in an ABSTRACT class and inherited by two concrete
// subclasses has no slot at the owner's own cid, so `slot - ownerCID` (the old
// formula) is wrong for every slot; the row offset must come from the
// descendants. The same leaf in an unrelated hierarchy is a separate row
// (table_selector_assigner.dart assigns selector ids per class-hierarchy member).
func TestInferSelectorRowImmsAbstractOwnerAndUnrelatedSameNameRows(t *testing.T) {
	ctx := minimalTypeContext()
	// 1 Object; 10 abstract A; 11,12 concrete subclasses of A; 20 unrelated B; 21 B's subclass.
	ctx.SuperClass = map[int]int{1: -1, 10: 1, 11: 10, 12: 10, 20: 1, 21: 20}
	ctx.DispatchSlotMeta = map[int]DispatchSlotMeta{}
	put := func(key, owner int, leaf string) {
		ctx.DispatchSlotMeta[key] = DispatchSlotMeta{Owner: owner, Leaf: leaf}
	}
	// Row "run" in hierarchy A: imm 500, slots for concrete 11 and 12, owner A(10).
	put(500+11, 10, "run")
	put(500+12, 10, "run")
	// Row "run" in unrelated hierarchy B: imm 800, slots for 20 and 21, owner B(20).
	put(800+20, 20, "run")
	put(800+21, 20, "run")
	// A different leaf with an Object-declared implementation: every class is a
	// candidate receiver, exactly one row must come out.
	put(300+1, 1, "toString")

	got := ctx.inferSelectorRowImms()
	if want := []int{500, 800}; !reflect.DeepEqual(got["run"], want) {
		t.Fatalf("run imms = %v, want %v", got["run"], want)
	}
	if len(got["toString"]) != 1 {
		t.Fatalf("toString imms = %v, want exactly one row", got["toString"])
	}
}
