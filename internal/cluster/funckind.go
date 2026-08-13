package cluster

// UntaggedFunction::Kind, the low field of kind_tag_.
//
// Function::KindTagBits (object.h @3.12.2) lays kind_tag_ out as
//
//	KindBits        at bit 0, width Utils::BitLength(<last kind>)
//	RecognizedBits  next
//	ModifierBits    next
//	single-bit flags (is_static first) after those
//
// so the kind is always at bit 0 but its WIDTH depends on how many kinds the
// version declares -- FOR_EACH_RAW_FUNCTION_KIND in raw_object.h. Counted
// directly from the SDK at three tags:
//
//	3.12.2   17 kinds, last RecordFieldGetter   -> BitLength(16) = 5 bits
//	3.9.2    17 kinds, last RecordFieldGetter   -> BitLength(16) = 5 bits
//	2.12.0   16 kinds, last FfiTrampoline       -> BitLength(15) = 4 bits
//
// Reading one bit too many would fold the low bit of RecognizedBits into the
// kind; one bit too few would alias the highest kind onto RegularFunction.
// Both failures are silent, which is why the widths above are measured rather
// than assumed, and why the masks are separate constants instead of one
// "wide enough" value.
const (
	funcKindMask2x = 0x0F // 16 kinds  (2.10 - 2.17)
	funcKindMask3x = 0x1F // 17 kinds  (3.x)
)

// Function kinds this project acts on. The ordinal is the position in
// FOR_EACH_RAW_FUNCTION_KIND, which is identical at 2.12.0, 3.9.2 and 3.12.2
// for every value below -- the list has only ever been appended to.
const (
	FunctionKindRegular     = 0
	FunctionKindClosure     = 1
	FunctionKindGetter      = 3
	FunctionKindSetter      = 4
	FunctionKindConstructor = 5
)

// IsConstructor reports whether a Function object is a generative constructor
// or a factory. Dart names both after the class -- `Duration`,
// `_GrowableList.of` -- so without the kind they are indistinguishable from
// an ordinary method, which is how 1231 of the 8346 functions on the 3.12.2
// x86_64 sample came out unmarked.
// HasKindTag is required, not decorative: NamedObject is also built for
// clusters that are not Functions, and there the zero value of FuncKind would
// otherwise read as FunctionKindRegular rather than "unknown".
func (n *NamedObject) IsConstructor() bool {
	return n.HasKindTag && n.FuncKind == FunctionKindConstructor
}
