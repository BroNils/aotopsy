package cluster

import "aotopsy/internal/snapshot"

// UntaggedFunction::Kind, the low field of kind_tag_.
//
// Two things vary by Dart version and BOTH were got wrong by keying off the
// wrong axis. Function::KindTagBits (object.h) lays kind_tag_ out as
//
//	KindBits        at bit 0, width Utils::BitLength(<last kind>)
//	RecognizedBits  next
//	ModifierBits    next
//	single-bit flags (is_static first) after those
//
// so the kind sits at bit 0, but its WIDTH is derived from how many kinds
// FOR_EACH_RAW_FUNCTION_KIND declares -- and the ORDINAL of any particular
// kind moves whenever one is inserted before it. Counted from the SDK at
// every version this project supports:
//
//	tag       kinds  last kind          width  Constructor
//	2.10.0      17   FfiTrampoline        5        6
//	2.12.0      16   FfiTrampoline        4        5
//	2.15.0      16   FfiTrampoline        4        5
//	2.17.6      16   FfiTrampoline        4        5
//	2.18.0      16   FfiTrampoline        4        5
//	2.19.0      17   RecordFieldGetter    5        5
//	3.0.5 ..    17   RecordFieldGetter    5        5
//	3.12.2      17   RecordFieldGetter    5        5
//
// 2.10 carries `SignatureFunction` at index 3, which every later version
// dropped; that is what shifts Constructor to 6 there.
//
// The previous version of this file had one mask for "2.x" and one for
// "3.x", chosen by VersionProfile.FillRefUnsigned -- which describes the
// SCALAR LAYOUT of the Function fill, an entirely different axis. It
// therefore got both boundaries wrong:
//
//	2.10  read 4 bits of a 5-bit field, and compared against ordinal 5 --
//	      which is SetterFunction there, so setters were labelled `new X`.
//	      A false positive, the worse kind.
//	2.18  read 5 bits of a 4-bit field, folding in the low bit of
//	      RecognizedBits, so constructors with that bit set were missed.
//
// Neither shows up on the corpus, which has no 2.10 or 2.18 sample. The SDK
// drift gate in funckind_sdk_test.go is what catches this class of error.

// FunctionKind is a canonical, version-independent function kind. Raw
// ordinals are normalised at parse time so nothing downstream has to know
// which version's numbering it is looking at.
type FunctionKind int

const (
	FunctionKindUnknown FunctionKind = iota
	FunctionKindRegular
	FunctionKindClosure
	FunctionKindImplicitClosure
	FunctionKindSignature // 2.10 only; removed afterwards
	FunctionKindGetter
	FunctionKindSetter
	FunctionKindConstructor
	FunctionKindImplicitGetter
	FunctionKindImplicitSetter
	FunctionKindOther // a kind past the ones this project acts on
)

func (k FunctionKind) String() string {
	switch k {
	case FunctionKindRegular:
		return "regular"
	case FunctionKindClosure:
		return "closure"
	case FunctionKindImplicitClosure:
		return "implicit-closure"
	case FunctionKindSignature:
		return "signature"
	case FunctionKindGetter:
		return "getter"
	case FunctionKindSetter:
		return "setter"
	case FunctionKindConstructor:
		return "constructor"
	case FunctionKindImplicitGetter:
		return "implicit-getter"
	case FunctionKindImplicitSetter:
		return "implicit-setter"
	case FunctionKindOther:
		return "other"
	}
	return "unknown"
}

// funcKindLayout is one version's raw ordinal numbering.
type funcKindLayout struct {
	mask  uint32 // (1 << BitLength(numKinds-1)) - 1
	order []FunctionKind
}

// The prefix of FOR_EACH_RAW_FUNCTION_KIND that this project distinguishes.
// Anything past it normalises to FunctionKindOther, which is correct: no
// caller acts on those, and listing them would be extra surface to keep in
// sync for no gain.
var (
	// 2.10.0 -- SignatureFunction present at index 3.
	layout210 = funcKindLayout{
		mask: 0x1F,
		order: []FunctionKind{
			FunctionKindRegular, FunctionKindClosure, FunctionKindImplicitClosure,
			FunctionKindSignature, FunctionKindGetter, FunctionKindSetter,
			FunctionKindConstructor, FunctionKindImplicitGetter, FunctionKindImplicitSetter,
		},
	}
	// 2.12.0 - 2.18.0 -- SignatureFunction gone, still 16 kinds so 4 bits.
	layout212 = funcKindLayout{
		mask: 0x0F,
		order: []FunctionKind{
			FunctionKindRegular, FunctionKindClosure, FunctionKindImplicitClosure,
			FunctionKindGetter, FunctionKindSetter, FunctionKindConstructor,
			FunctionKindImplicitGetter, FunctionKindImplicitSetter,
		},
	}
	// 2.19.0 onward -- RecordFieldGetter added, 17 kinds so 5 bits. Same
	// ordinals as layout212 for everything below it.
	layout219 = funcKindLayout{
		mask:  0x1F,
		order: layout212.order,
	}
)

// funcKindLayouts is the whole verified range, one entry per supported Dart
// version. A map rather than a switch so the SDK drift gate can iterate it:
// adding a version here without checking it against the SDK fails the gate.
var funcKindLayouts = map[string]*funcKindLayout{
	"2.10.0": &layout210,
	"2.12.0": &layout212,
	"2.13.0": &layout212,
	"2.14.0": &layout212,
	"2.15.0": &layout212,
	"2.16.0": &layout212,
	"2.17.6": &layout212,
	"2.18.0": &layout212,
	"2.19.0": &layout219,
	"3.0.5":  &layout219,
	"3.1.0":  &layout219,
	"3.2.5":  &layout219,
	"3.3.0":  &layout219,
	"3.4.3":  &layout219,
	"3.5.0":  &layout219,
	"3.6.2":  &layout219,
	"3.7.0":  &layout219,
	"3.8.1":  &layout219,
	"3.9.2":  &layout219,
	"3.10.7": &layout219,
	"3.11.0": &layout219,
	"3.12.2": &layout219,
	"3.13.0": &layout219, // 30 kinds, but first 8 (RegularFunction..ImplicitSetter) unchanged, mask 0x1F still valid
}

// funcKindLayoutFor returns the raw-ordinal numbering for a Dart version, or
// nil when the version is outside the verified range -- in which case the
// kind stays FunctionKindUnknown rather than being guessed from a neighbour.
// Guessing is exactly how 2.10 came to label setters as constructors.
func funcKindLayoutFor(profile *snapshot.VersionProfile) *funcKindLayout {
	if profile == nil {
		return nil
	}
	return funcKindLayouts[profile.DartVersion]
}

// decodeFunctionKind extracts and normalises the kind from a raw kind_tag_.
func decodeFunctionKind(kindTag uint32, profile *snapshot.VersionProfile) FunctionKind {
	layout := funcKindLayoutFor(profile)
	if layout == nil {
		return FunctionKindUnknown
	}
	ordinal := int(kindTag & layout.mask)
	if ordinal < len(layout.order) {
		return layout.order[ordinal]
	}
	return FunctionKindOther
}

// IsConstructor reports whether a Function object is a generative constructor
// or a factory. Dart names both after the class -- `Duration`,
// `_GrowableList.of` -- so without the kind they are indistinguishable from
// an ordinary method.
//
// The SDK spells factories with `new` too (`new String.fromCharCodes` in the
// ELF symbol table), so both belong here.
func (n *NamedObject) IsConstructor() bool {
	return n.FuncKind == FunctionKindConstructor
}
