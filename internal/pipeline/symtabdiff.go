package pipeline

import (
	"regexp"
	"sort"
	"strings"
)

// Comparing recovered names against the ELF symbol table.
//
// On a build that kept a `.symtab`, the linker already knows every function's
// Dart name. That makes it the only ground truth available to this project
// that is not its own previous output: golden files compare hashes of what we
// produced last time, so they notice a change but have no opinion on whether
// the new text is right.
//
// This is a CHECK, never a source. Recovering names without symbols is the
// whole point of the tool and production builds are stripped -- the corpus
// has symbols on one of four builds and none of the gopay ones. Nothing here
// feeds a name back into the pipeline.
//
// The two sides spell the same name differently on purpose, and those
// differences must be normalised away or the comparison is noise:
//
//	ours                              ELF                      why
//	Duration.compareTo_80             Duration.compareTo       our pcOffset suffix
//	Duration.dyn:*_210                Duration.*               ours marks the
//	                                                           dynamic-invocation
//	                                                           forwarder
//	FocusManager.get:instance_5bc     FocusManager.instance    ours marks the getter
//	_ViewState@141024595.didChange    _ViewState.didChange     ours keeps the
//	                                                           private-library mangling
//
// In each case ours carries MORE information, so the normalisation strips our
// side down to the ELF's shape rather than the reverse. The one exception is
// the private-library suffix, where the ELF is more readable and ours
// disambiguates same-named private classes from different libraries -- kept,
// and normalised away only here.

var (
	// Trailing `_<hex>` pcOffset suffix that QualifiedName appends.
	reNameSuffix = regexp.MustCompile(`_[0-9a-f]+$`)
	// Private-library mangling: `@` followed by digits.
	reLibMangle = regexp.MustCompile(`@\d+`)
	// Marker prefixes on the member part.
	memberMarkers = []string{"dyn:", "get:", "set:"}
)

// NormalizeRecoveredName reduces one of our names to the shape the ELF symbol
// table uses, so the two can be compared for agreement.
func NormalizeRecoveredName(name string) string {
	n := reNameSuffix.ReplaceAllString(name, "")
	n = reLibMangle.ReplaceAllString(n, "")
	// Markers sit on the member, which is after the last '.' -- except for a
	// bare top-level function, where there is no dot at all.
	if i := strings.LastIndex(n, "."); i >= 0 {
		owner, member := n[:i+1], n[i+1:]
		for _, m := range memberMarkers {
			member = strings.TrimPrefix(member, m)
		}
		n = owner + member
	} else {
		for _, m := range memberMarkers {
			n = strings.TrimPrefix(n, m)
		}
	}
	// An unnamed constructor's Function name is the class followed by a bare
	// `.` -- `_GrowableList@0150898.` -- so stripping the mangling leaves a
	// trailing dot that the ELF does not have.
	return strings.TrimSuffix(n, ".")
}

// NormalizeSymbolName reduces an ELF symbol to comparable shape.
//
// The names are Dart-side prose rather than identifiers, and two of the
// shapes carry a prefix we do not:
//
//	stub EnsureDeeplyImmutable        we name VM stubs bare
//	assert type is HitTestTarget      we name these TypeTestingStub_<Class>
//
// Both are the same thing said differently, so both are folded here. Getting
// this wrong makes a correct fix look like no improvement: reversing the VM
// stub order fixed all 173 of them and the agreement rate did not move,
// because every one still carried `stub ` on the ELF side.
func NormalizeSymbolName(sym string) string {
	s := strings.TrimSpace(sym)
	s = strings.TrimPrefix(s, "stub ")
	if rest, ok := strings.CutPrefix(s, "assert type is "); ok {
		s = "TypeTestingStub_" + rest
	}
	return reLibMangle.ReplaceAllString(strings.ReplaceAll(s, " ", "_"), "")
}

// NameDisagreement is one function where the two sides disagree after
// normalisation.
type NameDisagreement struct {
	VA   uint64
	Ours string
	ELF  string
}

// NameComparison is the result of checking recovered names against `.symtab`.
type NameComparison struct {
	Compared     int // functions present in both
	Agree        int
	OnlyOurs     int // we named a VA the symbol table does not describe
	OnlySymbols  int // the symbol table describes a VA we produced no name for
	Disagreement []NameDisagreement
}

// AgreementRate is Agree/Compared, or 1 when there was nothing to compare.
func (c NameComparison) AgreementRate() float64 {
	if c.Compared == 0 {
		return 1
	}
	return float64(c.Agree) / float64(c.Compared)
}

// CompareNamesToSymbols checks every name the pipeline recovered against the
// ELF symbol table. symbols is elfx.File.FuncSymbols(); a nil or empty map
// means the build is stripped, which is not an error and yields an empty
// comparison.
//
// Disagreements are returned sorted by address so a failing gate prints the
// same list every run.
func CompareNamesToSymbols(recovered map[uint64]string, symbols map[uint64]string) NameComparison {
	var c NameComparison
	if len(symbols) == 0 {
		return c
	}
	for va, ours := range recovered {
		sym, ok := symbols[va]
		if !ok {
			c.OnlyOurs++
			continue
		}
		c.Compared++
		if NormalizeRecoveredName(ours) == NormalizeSymbolName(sym) {
			c.Agree++
			continue
		}
		c.Disagreement = append(c.Disagreement, NameDisagreement{VA: va, Ours: ours, ELF: sym})
	}
	for va := range symbols {
		if _, ok := recovered[va]; !ok {
			c.OnlySymbols++
		}
	}
	sort.Slice(c.Disagreement, func(i, j int) bool {
		return c.Disagreement[i].VA < c.Disagreement[j].VA
	})
	return c
}
