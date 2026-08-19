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
	return normalizeRecovered(name, true)
}

// normalizeRecovered is NormalizeRecoveredName with the private-library
// mangling optionally KEPT. The 2.x assembly dialect preserves it (as
// `_4048458`), so stripping it there turns matching names into disagreements.
func normalizeRecovered(name string, stripMangle bool) string {
	n := reNameSuffix.ReplaceAllString(name, "")
	if stripMangle {
		n = reLibMangle.ReplaceAllString(n, "")
	}
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
	n = strings.TrimSuffix(n, ".")
	// Fold spaces to underscores, exactly as NormalizeSymbolName does.
	//
	// This side did not, and the asymmetry made an entire category
	// structurally incapable of agreeing: every `new X` we produce became
	// "new X" here while the ELF's became "new_X" there, so all 1231
	// constructor and allocation-stub symbols on the 3.12.2 arm64 sample
	// counted as disagreements no matter how right the name was. It hid both
	// the 306 constructors that were already correct and the 918 allocation
	// stubs fixed alongside this -- the agreement rate did not move by a
	// single tenth when those were added, which is what exposed it.
	return strings.ReplaceAll(n, " ", "_")
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
		if NamesAgree(ours, sym) {
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

// NamesAgree reports whether a recovered name and an ELF symbol describe the
// same function, after folding away the conventions that differ between them.
//
// The ELF side speaks TWO dialects, and which one decides how the comparison
// has to be done:
//
//	3.x   Dart-side prose:  "new StateError", "assert type is String?"
//	2.x   assembly identifiers: "Precompiled_List_List_of_127"
//
// The 2.x form is produced by SnapshotTextObjectNamer::SnapshotNameFor
// (image_snapshot.cc), which builds
//
//	Precompiled_<body>_<code_index>
//
// with body one of Stub_<name>, AllocationStub_<Class>, a type-testing stub
// name, or Function::ToQualifiedCString() -- and then runs
// EnsureAssemblerIdentifier over it, which replaces EVERY non-alphanumeric
// byte with '_'.
//
// That last step is why the two sides cannot be normalised independently. Our
// `new _List@0150898.of` and its `_List_0150898__List_0150898_of` differ in
// separators the ELF has already destroyed, so the only sound comparison is to
// destroy the same information on our side and compare what survives. Doing it
// per-pair rather than per-side is the point: applied unconditionally it would
// blind the 3.x comparison, where the separators are still intact and carry
// real signal.
//
// Measured before this existed: the 2.x ground-truth twins scored 0.0% -- 6830
// compared, 0 agreeing -- purely because every symbol was in the other dialect.
func NamesAgree(ours, sym string) bool {
	if body, allocStub, ok := assemblerBody(sym); ok {
		mine := normalizeRecovered(ours, false)
		if !allocStub {
			// An allocation stub is spelled `new <Class>` on both sides, so it
			// must NOT go through the constructor expansion -- doing so turned
			// `new _ZoneFunction@4048458` into `_ZoneFunction._ZoneFunction`
			// and made every one of them disagree.
			mine = qualifiedCString(mine)
		}
		return asmFold(mine) == asmFold(body)
	}
	if body, allocStub, ok := scrubbedAsmBody(sym); ok {
		mine := NormalizeRecoveredName(ours)
		if !allocStub {
			mine = qualifiedScrubbed(mine)
		}
		return addAssemblerIdentifier(mine) == addAssemblerIdentifier(body)
	}
	return NormalizeRecoveredName(ours) == NormalizeSymbolName(sym)
}

// reAsmIndex is the `_<code_index>` SnapshotNameFor appends to every name.
var reAsmIndex = regexp.MustCompile(`_\d+$`)

// precompiledBody strips the 2.x assembly wrapper and folds its stub shapes
// onto the ones we produce, returning false when the symbol is not in that
// dialect.
func assemblerBody(sym string) (body string, allocStub, ok bool) {
	s, ok := strings.CutPrefix(strings.TrimSpace(sym), "Precompiled_")
	if !ok {
		return "", false, false
	}
	s = reAsmIndex.ReplaceAllString(s, "")
	// Same two foldings NormalizeSymbolName does for the 3.x dialect, in the
	// spelling this one uses: an allocation stub is our `new <Class>`, and a
	// plain stub is bare on our side.
	if rest, ok := strings.CutPrefix(s, "AllocationStub_"); ok {
		return "new_" + rest, true, true
	}
	if rest, ok := strings.CutPrefix(s, "Stub_"); ok {
		return rest, false, true
	}
	return s, false, true
}

// asmIdentifier applies EnsureAssemblerIdentifier's transformation: every byte
// that is not [A-Za-z0-9] becomes '_'.
func asmIdentifier(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		default:
			b[i] = '_'
		}
	}
	return string(b)
}

// qualifiedCString rewrites one of our names into the shape
// Function::ToQualifiedCString() produces, which is what the 2.x assembly
// dialect is built from.
//
// The one systematic difference is constructors. We write `new List.of`; the
// SDK writes the owner and then the qualified member, i.e. `List.List.of`, so
// the class name appears twice. Same for an unnamed constructor: `new Offset`
// against `Offset.Offset`.
func qualifiedCString(n string) string {
	rest, ok := strings.CutPrefix(n, "new_")
	if !ok {
		return n
	}
	owner := rest
	if i := strings.Index(rest, "."); i >= 0 {
		owner = rest[:i]
	}
	return owner + "." + rest
}

// asmFold applies EnsureAssemblerIdentifier and then collapses runs of '_' and
// trims them at the ends.
//
// The collapsing is not cosmetic. ToQualifiedCString renders an absent name
// component as nothing, so a top-level function arrives as `____makeListFixed
// Length` -- four underscores standing in for the empty owner. Ours has no
// such component at all. Since the assembler transformation has already made
// every separator indistinguishable, the run length carries no information
// either side can be held to.
func asmFold(s string) string {
	b := asmIdentifier(s)
	var out []byte
	prevUnderscore := false
	for i := 0; i < len(b); i++ {
		if b[i] == '_' {
			if !prevUnderscore {
				out = append(out, '_')
			}
			prevUnderscore = true
			continue
		}
		prevUnderscore = false
		out = append(out, b[i])
	}
	return strings.Trim(string(out), "_")
}

// scrubbedAsmBody recognises the THIRD ELF dialect, introduced at 2.18.0.
//
// SnapshotTextObjectNamer::SnapshotNameFor dropped the "Precompiled_" prefix
// there and switched from EnsureAssemblerIdentifier to AddAssemblerIdentifier,
// which keeps '.' as itself, spells operators out as words, and works from the
// SCRUBBED name -- so the private-library mangling is gone rather than folded
// to underscores (image_snapshot.cc @2.18.0).
//
// Measured before this existed: the 2.18.0 and 2.19.0 twins scored 0.0%, all
// 7587 and 7878 comparisons disagreeing, because every symbol was in a dialect
// neither of the other two branches recognised.
func scrubbedAsmBody(sym string) (body string, allocStub, ok bool) {
	s := strings.TrimSpace(sym)
	if s == "" || strings.ContainsAny(s, " ") {
		return "", false, false // prose dialect
	}
	if rest, cut := strings.CutPrefix(s, "Stub_"); cut {
		// A null-owner stub carries no code index.
		return rest, false, true
	}
	s = reAsmIndex.ReplaceAllString(s, "")
	if rest, cut := strings.CutPrefix(s, "AllocationStub_"); cut {
		return "new_" + rest, true, true
	}
	return s, false, true
}

// qualifiedScrubbed is qualifiedCString for the scrubbed dialect: same
// constructor doubling, but the separator that survives is '.', not '_'.
func qualifiedScrubbed(n string) string {
	rest, ok := strings.CutPrefix(n, "new_")
	if !ok {
		return n
	}
	owner := rest
	if i := strings.Index(rest, "."); i >= 0 {
		owner = rest[:i]
	}
	return owner + "." + rest
}

// asmOperatorNames is AddAssemblerIdentifier's operator table, in the SDK's
// own order -- longest first, so `~/` is not read as `~` and `>>>` is not read
// as `>>` (image_snapshot.cc).
var asmOperatorNames = [][2]string{
	{"~/", "operator_truncdiv"},
	{"<<", "operator_sll"},
	{">>>", "operator_srl"},
	{">>", "operator_sra"},
	{"[]=", "operator_set"},
	{"[]", "operator_get"},
	{"unary-", "operator_neg"},
	{"==", "operator_eq"},
	{"<anonymous closure>", "anonymous_closure"},
	{"<=", "operator_le"},
	{">=", "operator_ge"},
	{"+", "operator_add"},
	{"-", "operator_sub"},
	{"*", "operator_mul"},
	{"/", "operator_div"},
	{"%", "operator_mod"},
	{"~", "operator_not"},
	{"&", "operator_and"},
	{"|", "operator_or"},
	{"^", "operator_xor"},
	{"<", "operator_lt"},
	{">", "operator_gt"},
}

// addAssemblerIdentifier mirrors AddAssemblerIdentifier: spell the operators
// out, keep [A-Za-z0-9.], turn everything else into '_', then collapse runs.
func addAssemblerIdentifier(s string) string {
	for _, op := range asmOperatorNames {
		s = strings.ReplaceAll(s, op[0], op[1])
	}
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.':
		default:
			b[i] = '_'
		}
	}
	out := make([]byte, 0, len(b))
	prev := false
	for _, c := range b {
		if c == '_' {
			if !prev {
				out = append(out, c)
			}
			prev = true
			continue
		}
		prev = false
		out = append(out, c)
	}
	return strings.Trim(string(out), "_")
}
