package typetrack

import "testing"

// The stack seed holds the receiver's owner class AND every stack-passed
// parameter's declared class; a parameter never overrides the receiver slot and a
// class-less parameter (dynamic, a type parameter) is not seeded.
func TestEntryStackSeedCarriesStackParameters(t *testing.T) {
	ctx := minimalTypeContext()
	ctx.FuncOwnerClass = map[string]int{}
	ctx.FuncReceiverStackSlot = map[string]int{}
	ctx.FuncStackParams = map[string][]StackParam{}
	ctx.FuncOwnerClass["A.f"] = 10
	ctx.FuncReceiverStackSlot["A.f"] = 24
	ctx.FuncStackParams["A.f"] = []StackParam{
		{Slot: 24, Class: 99}, // would collide with the receiver: ignored
		{Slot: 16, Class: 20},
		{Slot: 8, Class: -1},
	}
	seed := entryStackSeed(ctx, "A.f")
	if got := seed[24]; got.Kind != LatticeClassBound || got.ClassID != 10 {
		t.Errorf("receiver slot = %+v, want ClassBound(10)", got)
	}
	if got := seed[16]; got.Kind != LatticeClassBound || got.ClassID != 20 {
		t.Errorf("param slot = %+v, want ClassBound(20)", got)
	}
	if _, ok := seed[8]; ok {
		t.Error("a parameter without a class was seeded")
	}
	// A function with nothing to seed yields no map at all.
	if entryStackSeed(ctx, "none") != nil {
		t.Error("seed for an unknown function")
	}
	// A static function (no receiver) is seeded from its parameters alone.
	ctx.FuncStackParams["S.g"] = []StackParam{{Slot: 16, Class: 30}}
	if got := entryStackSeed(ctx, "S.g")[16]; got.ClassID != 30 {
		t.Errorf("static param seed = %+v", got)
	}
}
