package snapshot

import (
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"aotopsy/internal/cmacro"
	"aotopsy/internal/sdktest"
)

// SDK drift gate for the per-version CID tables.
//
// Every cluster in a snapshot is dispatched on its class id, so a single
// wrong CID does not degrade an annotation -- it sends the deserializer
// into the wrong reader and desynchronises the stream from that point on.
// The 3.13.0 LocalVarDescriptors case in version.go's comments is exactly
// that: one unmapped id consumed one value where the SDK writes two, and
// two later clusters decoded with CID 0xFFFFF.
//
// The numbers cannot be checked locally -- a wrong id that happens to
// name a real class parses into plausible garbage. They come from the
// position of a class in runtime/vm/class_id.h's ClassId enum, so that
// enum is what this re-derives.
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/snapshot/ -run CIDTablesMatchSDK

// cidEnum reproduces the ClassId enum's ordering for one SDK tag and
// returns name -> id.
//
// The enum is a mix of literal entries and X-macro expansions whose
// per-entry template changes between versions -- CLASS_LIST_TYPED_DATA
// emitted three ids per class before the unmodifiable views landed and
// four after -- so the template is read from the header rather than
// assumed. Assuming it is how a table silently gains a constant offset
// across an entire tail.
func cidEnum(tag string) (map[string]int, int, error) {
	src, err := sdktest.GHFileAtTag("runtime/vm/class_id.h", tag)
	if err != nil {
		return nil, 0, err
	}
	macros := cmacro.ParseMacros(src)

	body, err := enumBody(src)
	if err != nil {
		return nil, 0, err
	}
	// typedDataStride is how many ids CLASS_LIST_TYPED_DATA emits per
	// class. It went from 3 to 4 when the unmodifiable views landed, and
	// version.go's TypedDataCidStride has to follow.
	typedDataStride := 0

	out := map[string]int{}
	next := 0
	add := func(name string) {
		if _, dup := out[name]; !dup {
			out[name] = next
		}
		next++
	}

	// templates holds per-entry macros as they are defined, tracked
	// positionally rather than read from the file-wide macro table: the
	// pre-3.13 enum redefines DEFINE_OBJECT_KIND three times, so the
	// file-wide table only ever has the last one.
	templates := map[string]string{}

	var walk func(text string, depth int) error
	walk = func(text string, depth int) error {
		if depth > 8 {
			return cidError("macro nesting too deep at " + tag)
		}
		for i := 0; i < len(text); {
			// A #define inside the region installs a template and runs to
			// end of line (continuations are already joined). Whichever of
			// the two patterns starts first wins -- anchoring the define
			// check at the scan position instead skips every define that is
			// not exactly there, and then the template is never installed.
			d := reInlineDefine.FindStringSubmatchIndex(text[i:])
			loc := reToken.FindStringSubmatchIndex(text[i:])
			if d != nil && (loc == nil || d[0] <= loc[0]) {
				templates[text[i+d[2]:i+d[3]]] = text[i+d[8] : i+d[9]]
				i += d[1]
				continue
			}
			if loc == nil {
				return nil
			}
			tok := text[i+loc[0] : i+loc[1]]
			i += loc[1]

			// Literal enum entry: kFooCid, or kFoo,
			if strings.HasPrefix(tok, "k") && strings.HasSuffix(tok, ",") {
				if m := reEnumEntry.FindStringSubmatch(tok); m != nil {
					add(m[1])
				}
				continue
			}
			name, arg, isCall := splitCall(tok)
			if !isCall {
				// A bare object-like list macro (3.13's CLASS_ID_LIST).
				if body, ok := macros[name]; ok && strings.Contains(body, "(") {
					if err := walk(body, depth+1); err != nil {
						return err
					}
				}
				continue
			}
			// NAME(ARG) where NAME is a per-entry template: substitute and
			// re-walk, because the substitution may itself be a call
			// (3.13's DEFINE_CLASS_ID(clazz) expands to CID(clazz##Cid)).
			if tmpl, ok := templates[name]; ok {
				if err := walk(substParam(tmpl, arg), depth+1); err != nil {
					return err
				}
				continue
			}
			// LIST(TEMPLATE): expand the list, apply the template per class.
			if _, ok := macros[name]; ok && strings.HasPrefix(name, "CLASS_LIST") {
				tmpl, ok := templates[arg]
				if !ok {
					tmpl, ok = macros[arg]
				}
				if !ok {
					return cidError("no template " + arg + " for " + name + " at " + tag)
				}
				classes, err := cmacro.Expand(macros, name)
				if err != nil {
					return err
				}
				if name == "CLASS_LIST_TYPED_DATA" {
					before := next
					if err := walk(substParam(tmpl, "Probe"), depth+1); err != nil {
						return err
					}
					typedDataStride = next - before
					next = before
					for k, v := range out {
						if v >= before {
							delete(out, k)
						}
					}
				}
				for _, c := range classes {
					if err := walk(substParam(tmpl, c), depth+1); err != nil {
						return err
					}
				}
				continue
			}
		}
		return nil
	}

	if err := walk(body, 0); err != nil {
		return nil, 0, err
	}
	if len(out) < 50 {
		return nil, 0, cidError("class_id.h@" + tag + " yielded too few ids to be the ClassId enum")
	}
	if typedDataStride == 0 {
		return nil, 0, cidError("CLASS_LIST_TYPED_DATA not expanded at " + tag)
	}
	return out, typedDataStride, nil
}

// splitCall recognises NAME(ARG) with a single argument.
func splitCall(tok string) (name, arg string, ok bool) {
	open := strings.IndexByte(tok, '(')
	if open < 0 || !strings.HasSuffix(tok, ")") {
		return strings.TrimSuffix(tok, ","), "", false
	}
	return tok[:open], strings.TrimSpace(tok[open+1 : len(tok)-1]), true
}

// substParam replaces a macro's single parameter with an argument,
// honouring the ## paste operator.
func substParam(tmpl, arg string) string {
	t := strings.ReplaceAll(tmpl, "##", "\x00")
	for _, p := range []string{"clazz", "cid", "class"} {
		t = regexp.MustCompile(`\b`+p+`\b`).ReplaceAllString(t, arg)
	}
	return strings.ReplaceAll(t, "\x00", "")
}

var (
	reEnumOpen = regexp.MustCompile(`enum\s+ClassId[^{]*\{`)
	// A #define inside the walked region: name, optional parameter list, body.
	reInlineDefine = regexp.MustCompile(`#define\s+(\w+)(\(\s*(\w+)\s*\))?([^\n]*)`)
	// One token: a call NAME(ARG), a literal enum entry kFoo, or a bare
	// identifier (an object-like list macro reference).
	reToken = regexp.MustCompile(`(\w+\([^()]*\))|(k\w+\s*(?:=\s*\d+\s*)?,)|(\w+)`)
	// An enum entry is kFooCid or kFoo (kNativePointer, kFreeListElement).
	// The trailing "= 0" on kIllegalCid is ignored: position is what counts,
	// and the enum starts at 0 anyway.
	reEnumEntry = regexp.MustCompile(`\bk(\w+?)(?:Cid)?\s*(?:=\s*\d+\s*)?,`)
	reBlockCmt  = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reLineCmt   = regexp.MustCompile(`//[^\n]*`)
)

// enumBody returns the ClassId enum's contents with comments stripped and
// line continuations joined.
func enumBody(src string) (string, error) {
	loc := reEnumOpen.FindStringIndex(src)
	if loc == nil {
		return "", cidError("enum ClassId not found")
	}
	rest := src[loc[1]:]
	end := strings.Index(rest, "};")
	if end < 0 {
		return "", cidError("unterminated enum ClassId")
	}
	body := rest[:end]
	body = strings.ReplaceAll(body, "\\\r\n", "")
	body = strings.ReplaceAll(body, "\\\n", "")
	body = reBlockCmt.ReplaceAllString(body, "")
	body = reLineCmt.ReplaceAllString(body, "")
	return body, nil
}

// applyKindTemplate substitutes the macro parameter into a
// DEFINE_OBJECT_KIND body and returns the ids it emits, in order.
func applyKindTemplate(template, class string) []string {
	t := strings.ReplaceAll(template, "##", "\x00")
	t = strings.ReplaceAll(t, "clazz", class)
	t = strings.ReplaceAll(t, "\x00", "")
	var out []string
	for _, m := range reEnumEntry.FindAllStringSubmatch(t, -1) {
		out = append(out, m[1])
	}
	return out
}

type cidError string

func (e cidError) Error() string { return string(e) }

// cidTags maps each committed table to the SDK tag it was derived from.
// Every table gets probed: a row nobody checked is the whole failure mode.
var cidTags = []struct {
	tag   string
	table *CIDTable
}{
	{"2.10.0", &cidsV210},
	{"2.12.0", &cidsV212},
	{"2.13.0", &cidsV213},
	{"2.14.0", &cidsV214},
	{"2.15.0", &cidsV215},
	{"2.16.0", &cidsV216},
	{"2.17.6", &cidsV217},
	{"2.18.0", &cidsV218},
	{"2.19.0", &cidsV219},
	{"3.0.5", &cidsV305},
	{"3.2.5", &cidsV325},
	{"3.4.3", &cidsV343},
	{"3.6.2", &cidsV362},
	{"3.9.2", &cidsV392},
	{"3.13.0", &cidsV3130},
}

// cidFieldClass maps a CIDTable field to the SDK class whose enum
// position gives its value, where the two names differ.
//
// Anything absent from this map uses the field name itself. A zero field
// means "not present in this version" and is skipped -- version.go's
// comments record why for each.
var cidFieldClass = map[string]string{
	// The map/set classes were renamed when the const variants landed.
	// Older tables carry the LinkedHashMap ids under the new field names,
	// so the lookup tries the modern name first and falls back.
	"Map":      "Map",
	"ConstMap": "ConstMap",
	"Set":      "Set",
	"ConstSet": "ConstSet",
}

// cidFieldFallback lists alternative SDK names per field, tried in order
// when the primary name is absent from the enum at that tag.
var cidFieldFallback = map[string][]string{
	"Map":      {"LinkedHashMap"},
	"ConstMap": {"ImmutableLinkedHashMap"},
	"Set":      {"LinkedHashSet"},
	"ConstSet": {"ImmutableLinkedHashSet"},
	// The typed-data range bases. CLASS_LIST_TYPED_DATA's first entry is
	// Int8Array, so kTypedDataInt8ArrayCid is the base of each range and
	// what version.go's TypedData / TypedDataView / ExternalTypedData hold.
	"TypedData":         {"TypedDataInt8Array"},
	"TypedDataView":     {"TypedDataInt8ArrayView"},
	"ExternalTypedData": {"ExternalTypedDataInt8Array"},
}

func TestCIDTablesMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	for _, c := range cidTags {
		t.Run(c.tag, func(t *testing.T) {
			enum, stride, err := cidEnum(c.tag)
			if err != nil {
				t.Fatalf("derive ClassId enum @%s: %v", c.tag, err)
			}
			if c.table.TypedDataCidStride != stride {
				t.Errorf("%s: TypedDataCidStride = %d, CLASS_LIST_TYPED_DATA emits %d ids per class\n"+
					"  The stride is what turns a CID back into a typed-data element type;\n"+
					"  wrong, and every typed-data class reads as a different one.",
					c.tag, c.table.TypedDataCidStride, stride)
			}

			v := reflect.ValueOf(*c.table)
			ty := v.Type()
			checked, skipped := 0, 0
			for i := 0; i < ty.NumField(); i++ {
				f := ty.Field(i)
				if f.Type.Kind() != reflect.Int {
					continue
				}
				got := int(v.Field(i).Int())
				if got == 0 {
					skipped++ // recorded as absent for this version
					continue
				}
				if f.Name == "TypedDataCidStride" {
					continue // checked above, against the macro template
				}
				want, ok := lookupCID(enum, f.Name)
				if !ok {
					t.Errorf("%s: field %s = %d, but no matching class in class_id.h@%s\n"+
						"  Either the field names a class that does not exist at this version\n"+
						"  (then the table should hold 0), or cidFieldFallback needs the SDK name.",
						c.tag, f.Name, got, c.tag)
					continue
				}
				checked++
				if got != want {
					t.Errorf("%s: %s = %d, SDK ClassId enum says %d (delta %+d)\n"+
						"  A wrong CID does not mislabel a cluster, it dispatches the wrong reader\n"+
						"  and desynchronises the stream from that cluster onward.",
						c.tag, f.Name, got, want, want-got)
				}
			}
			if checked < 30 {
				t.Errorf("%s: only %d fields checked; the mapping is not covering the table", c.tag, checked)
			}
			t.Logf("%s: %d fields verified, %d recorded absent", c.tag, checked, skipped)
		})
	}
}

func lookupCID(enum map[string]int, field string) (int, bool) {
	name := field
	if alt, ok := cidFieldClass[field]; ok {
		name = alt
	}
	if id, ok := enum[name]; ok {
		return id, true
	}
	// Several fields spell out the enum constant (NativePointerCid,
	// ByteDataViewCid, TypedDataInt8ArrayCid); the enum key drops the
	// suffix.
	if trimmed := strings.TrimSuffix(name, "Cid"); trimmed != name {
		if id, ok := enum[trimmed]; ok {
			return id, true
		}
	}
	for _, alt := range cidFieldFallback[field] {
		if id, ok := enum[alt]; ok {
			return id, true
		}
	}
	return 0, false
}

// TestNumPredefinedCidsMatchSDK checks the derived enum terminates where
// the SDK says it does, which is the one number every range check and the
// TagStyle probe depend on.
func TestNumPredefinedCidsMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	for _, c := range cidTags {
		t.Run(c.tag, func(t *testing.T) {
			enum, _, err := cidEnum(c.tag)
			if err != nil {
				t.Fatalf("derive ClassId enum @%s: %v", c.tag, err)
			}
			// The terminator is spelled kNumPredefinedCids -- plural, so the
			// "Cid" suffix strip does not apply and the key keeps it.
			n, ok := enum["NumPredefinedCids"]
			if !ok {
				t.Fatalf("%s: kNumPredefinedCids missing from the derived enum", c.tag)
			}
			if c.table.NumPredefinedCids != n {
				t.Errorf("%s: NumPredefinedCids = %d, SDK enum terminates at %d",
					c.tag, c.table.NumPredefinedCids, n)
			}
			// Every id the table holds must be inside the predefined range.
			// NumPredefinedCids is the bound itself, and TypedDataCidStride
			// is a step, not an id.
			v := reflect.ValueOf(*c.table)
			ty := v.Type()
			for i := 0; i < ty.NumField(); i++ {
				f := ty.Field(i)
				if f.Type.Kind() != reflect.Int ||
					f.Name == "NumPredefinedCids" || f.Name == "TypedDataCidStride" {
					continue
				}
				if got := int(v.Field(i).Int()); got >= n {
					t.Errorf("%s: %s = %d is at or past kNumPredefinedCids (%d)",
						c.tag, f.Name, got, n)
				}
			}
			t.Logf("%s: kNumPredefinedCids = %d", c.tag, n)
		})
	}
}

// TestCIDTablesAreInjective is a local invariant needing no network: two
// fields holding the same non-zero id means one was copied onto the other,
// and the cluster dispatch then reads the wrong one for both.
func TestCIDTablesAreInjective(t *testing.T) {
	for _, c := range cidTags {
		v := reflect.ValueOf(*c.table)
		ty := v.Type()
		seen := map[int]string{}
		var dups []string
		for i := 0; i < ty.NumField(); i++ {
			if ty.Field(i).Type.Kind() != reflect.Int {
				continue
			}
			got := int(v.Field(i).Int())
			if got == 0 {
				continue
			}
			if prev, dup := seen[got]; dup {
				dups = append(dups, prev+" and "+ty.Field(i).Name+" both = "+itoa(got))
				continue
			}
			seen[got] = ty.Field(i).Name
		}
		sort.Strings(dups)
		for _, d := range dups {
			t.Errorf("%s: %s", c.tag, d)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
