package pipeline

import "testing"

// Dart names a constructor after its class -- `Duration`,
// `_GrowableList.of`, `PlatformDispatcher._` -- so the Function name already
// carries the class and prepending the owner repeats it. The first version of
// this produced `_GrowableList.new _GrowableList.of`.
func TestConstructorNameDoesNotRepeatTheClass(t *testing.T) {
	ci := CodeNameInfo{FuncName: "new _GrowableList.of", OwnerName: "_GrowableList", IsConstructor: true}
	if got, want := ci.Qualified(0x1d8), "new _GrowableList.of_1d8"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// An ordinary method still gets the owner.
	m := CodeNameInfo{FuncName: "compareTo", OwnerName: "Duration"}
	if got, want := m.Qualified(0x80), "Duration.compareTo_80"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// And a nameless Code keeps the placeholder.
	e := CodeNameInfo{}
	if got, want := e.Qualified(0x10), "sub_10"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
