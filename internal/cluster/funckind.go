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
// so the kind sits at bit 0 and the ORDINAL of any particular kind moves
// whenever one is inserted before it.
//
// The WIDTH does NOT move, contrary to what this comment used to claim.
// object.h hardcodes `kKindTagSize = 5` at every version from 2.10.0 through
// 3.4.3 (checked at each; the enum only becomes computed from
// `Utils::BitLength(kRecordFieldGetter)` -- still 5 -- somewhere after 3.4.3).
// The narrower masks in the table below therefore read a 5-bit field with 4
// bits at 2.12..2.18, which happens to be harmless because the last kind there
// is FfiTrampoline = 15 and fits. The ordinals are the part that matters, and
// they are what the table is really for. Counted from the SDK at every version
// this project supports:
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
	FunctionKindImplicitStaticGetter
	FunctionKindFieldInitializer
	FunctionKindMethodExtractor
	FunctionKindNoSuchMethodDispatcher
	FunctionKindInvokeFieldDispatcher
	FunctionKindIrregexp
	FunctionKindDynamicInvocationForwarder
	FunctionKindFfiTrampoline
	FunctionKindRecordFieldGetter
	FunctionKindOther // a future/otherwise-unmodelled kind
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
	case FunctionKindImplicitStaticGetter:
		return "implicit-static-getter"
	case FunctionKindFieldInitializer:
		return "field-initializer"
	case FunctionKindMethodExtractor:
		return "method-extractor"
	case FunctionKindNoSuchMethodDispatcher:
		return "no-such-method-dispatcher"
	case FunctionKindInvokeFieldDispatcher:
		return "invoke-field-dispatcher"
	case FunctionKindIrregexp:
		return "irregexp"
	case FunctionKindDynamicInvocationForwarder:
		return "dynamic-invocation-forwarder"
	case FunctionKindFfiTrampoline:
		return "ffi-trampoline"
	case FunctionKindRecordFieldGetter:
		return "record-field-getter"
	case FunctionKindOther:
		return "other"
	}
	return "unknown"
}

// funcKindLayout is one version's raw ordinal numbering.
type funcKindLayout struct {
	mask  uint32 // (1 << BitLength(numKinds-1)) - 1
	known map[int]FunctionKind
}

// Keep every SDK kind whose calling-convention behaviour matters. A sparse
// prefix was sufficient while kind was only used to identify constructors and
// FFI trampolines; it became actively unsafe once Function::Kind started
// gating register-vs-stack parameter recovery because several stack-only kinds
// (MethodExtractor, dispatchers, FieldInitializer, Irregexp) collapsed into
// `Other` and could not be distinguished from register-eligible kinds.
var (
	// 2.10.0 -- SignatureFunction present at index 3.
	layout210 = funcKindLayout{
		mask: 0x1F,
		known: map[int]FunctionKind{
			0: FunctionKindRegular, 1: FunctionKindClosure, 2: FunctionKindImplicitClosure,
			3: FunctionKindSignature, 4: FunctionKindGetter, 5: FunctionKindSetter,
			6: FunctionKindConstructor, 7: FunctionKindImplicitGetter, 8: FunctionKindImplicitSetter,
			9: FunctionKindImplicitStaticGetter, 10: FunctionKindFieldInitializer,
			11: FunctionKindMethodExtractor, 12: FunctionKindNoSuchMethodDispatcher,
			13: FunctionKindInvokeFieldDispatcher, 14: FunctionKindIrregexp,
			15: FunctionKindDynamicInvocationForwarder,
			16: FunctionKindFfiTrampoline,
		},
	}
	// 2.12.0 - 2.18.0 -- SignatureFunction gone, still 16 kinds so 4 bits.
	layout212 = funcKindLayout{
		mask: 0x0F,
		known: map[int]FunctionKind{
			0: FunctionKindRegular, 1: FunctionKindClosure, 2: FunctionKindImplicitClosure,
			3: FunctionKindGetter, 4: FunctionKindSetter, 5: FunctionKindConstructor,
			6: FunctionKindImplicitGetter, 7: FunctionKindImplicitSetter,
			8: FunctionKindImplicitStaticGetter, 9: FunctionKindFieldInitializer,
			10: FunctionKindMethodExtractor, 11: FunctionKindNoSuchMethodDispatcher,
			12: FunctionKindInvokeFieldDispatcher, 13: FunctionKindIrregexp,
			14: FunctionKindDynamicInvocationForwarder,
			15: FunctionKindFfiTrampoline,
		},
	}
	// 2.19.0 onward -- RecordFieldGetter added, 17 kinds so 5 bits. Same
	// ordinals as layout212 for everything below it.
	layout219 = funcKindLayout{
		mask: 0x1F,
		known: map[int]FunctionKind{
			0: FunctionKindRegular, 1: FunctionKindClosure, 2: FunctionKindImplicitClosure,
			3: FunctionKindGetter, 4: FunctionKindSetter, 5: FunctionKindConstructor,
			6: FunctionKindImplicitGetter, 7: FunctionKindImplicitSetter,
			8: FunctionKindImplicitStaticGetter, 9: FunctionKindFieldInitializer,
			10: FunctionKindMethodExtractor, 11: FunctionKindNoSuchMethodDispatcher,
			12: FunctionKindInvokeFieldDispatcher, 13: FunctionKindIrregexp,
			14: FunctionKindDynamicInvocationForwarder, 15: FunctionKindFfiTrampoline,
			16: FunctionKindRecordFieldGetter,
		},
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
	"3.13.0": &layout219,
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

// kindTagModifierMask selects UntaggedFunction::ModifierBits in kind_tag_:
// kModifierPos = 14, kModifierSize = 2.
//
// Unlike the kind ordinal above, this position does NOT move between versions.
// object.h's KindTagBits enum hardcodes kKindTagSize = 5 and
// kRecognizedTagSize = 9 -- read at 2.10.0, 2.12.0, 2.17.6, 2.19.0, 3.0.5,
// 3.1.0, 3.2.5, 3.3.0 and 3.4.3, identical at every one. The single-bit flags
// begin at bit 16, which is where IsStatic reads is_static; that agreement is
// a second, independent confirmation of the position.
//
// AsyncModifier is kNoModifier=0, kAsync=1, kSyncGen=2, kAsyncGen=3, so a
// nonzero field means suspendable.
const kindTagModifierMask uint32 = 0b11 << 14

// FunctionModifier is UntaggedFunction::AsyncModifier normalized directly from
// kind_tag_. Unlike FunctionKind, these ordinals and their two-bit position are
// stable across every supported SDK release:
//
//	kNoModifier = 0, kAsync = 1, kSyncGen = 2, kAsyncGen = 3
//
// Verified in raw_object.h/object.h at 2.10.0, 2.17.6, 2.18.0 and 3.13.0;
// Function::IsAsyncFunction/IsSyncGenerator/IsAsyncGenerator compare the field
// to exactly these values. HasKindTag on NamedObject distinguishes a genuine
// FunctionModifierNone from metadata that was not captured.
type FunctionModifier uint8

const (
	FunctionModifierNone FunctionModifier = iota
	FunctionModifierAsync
	FunctionModifierSyncStar
	FunctionModifierAsyncStar
)

func decodeFunctionModifier(kindTag uint32) FunctionModifier {
	return FunctionModifier((kindTag & kindTagModifierMask) >> 14)
}

type functionKindTagFlagLayout struct {
	staticBit   uint
	nativeBit   uint
	externalBit uint
}

// functionKindTagFlagLayoutFor returns the exact SDK bit positions of the
// stable Function flags we expose. The positions changed before Dart 2.13 as
// Redirecting was removed and Inlinable moved to the volatile flag list.
// TestFunctionKindTagFlagLayoutsMatchSDK derives every row from the exact-tag
// FOR_EACH_FUNCTION_KIND_BIT macro.
func functionKindTagFlagLayoutFor(profile *snapshot.VersionProfile) (functionKindTagFlagLayout, bool) {
	if profile == nil {
		return functionKindTagFlagLayout{}, false
	}
	if _, ok := funcKindLayouts[profile.DartVersion]; !ok {
		return functionKindTagFlagLayout{}, false
	}
	switch profile.DartVersion {
	case "2.10.0":
		return functionKindTagFlagLayout{staticBit: 16, nativeBit: 24, externalBit: 26}, true
	case "2.12.0":
		return functionKindTagFlagLayout{staticBit: 16, nativeBit: 24, externalBit: 25}, true
	default:
		return functionKindTagFlagLayout{staticBit: 16, nativeBit: 23, externalBit: 24}, true
	}
}

// decodeFunctionKind extracts and normalises the kind from a raw kind_tag_.
func decodeFunctionKind(kindTag uint32, profile *snapshot.VersionProfile) FunctionKind {
	layout := funcKindLayoutFor(profile)
	if layout == nil {
		return FunctionKindUnknown
	}
	ordinal := int(kindTag & layout.mask)
	if kind, ok := layout.known[ordinal]; ok {
		return kind
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

// IsImplicitClosure reports whether a Function is an implicit closure -- a
// tear-off. Unlike a real (non-implicit) closure, the SDK does NOT qualify it
// with its enclosing function: FunctionPrintNameHelper prepends the parent
// name only under IsNonImplicitClosureFunction (object.cc), so a tear-off of
// `_throwNew` is named `_throwNew`, not `_throwNew._throwNew`. Callers that add
// the enclosing name must skip these.
func (n *NamedObject) IsImplicitClosure() bool {
	return n.FuncKind == FunctionKindImplicitClosure
}
