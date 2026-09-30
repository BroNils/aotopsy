package cluster

import (
	"regexp"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
	"aotopsy/internal/snapshot"
)

// SDK drift gate for the fill layouts whose shape is decided per version.
//
// A wrong ref count or scalar width does not mislabel one object: it moves the
// stream position, and every later cluster decodes from the wrong place while
// looking plausible. The corpus only proves the layouts the sample binaries
// use, so these facts are re-derived from the SDK itself for every profile.
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/cluster/ -run FillLayoutsMatchSDK
//
// Everything below comes from runtime/vm/raw_object.h (pointer-field extents)
// and the serializer source (scalar widths, which clusters exist).

var fillLayoutTags = []string{
	"2.10.0", "2.12.0", "2.13.0", "2.14.0", "2.15.0", "2.16.0", "2.17.6",
	"2.18.0", "2.19.0", "3.0.5", "3.1.0", "3.2.5", "3.3.0", "3.4.3", "3.5.0",
	"3.6.2", "3.7.0", "3.8.1", "3.9.2", "3.10.7", "3.11.0", "3.12.2", "3.13.0",
}

// sdkSerializerSource returns the file holding the snapshot clusters: it was
// clustered_snapshot.cc up to 2.14 and app_snapshot.cc from 2.15.
func sdkSerializerSource(t *testing.T, tag string) string {
	t.Helper()
	for _, name := range []string{"runtime/vm/app_snapshot.cc", "runtime/vm/clustered_snapshot.cc"} {
		if src, err := sdktest.SDKFileAtTag(name, tag); err == nil {
			return src
		}
	}
	t.Fatalf("no snapshot serializer source at %s", tag)
	return ""
}

// sdkClassBody returns the text of `class <one of names> ... };` at column 0.
func sdkClassBody(t *testing.T, src, what string, names ...string) string {
	t.Helper()
	for _, n := range names {
		re := regexp.MustCompile(`(?s)\nclass ` + regexp.QuoteMeta(n) + `\b[^\n]*\{.*?\n\};`)
		if m := re.FindString(src); m != "" {
			return m
		}
	}
	t.Fatalf("class %s (%s) not found", strings.Join(names, "|"), what)
	return ""
}

var (
	// A pointer field is declared either through the POINTER_FIELD macros
	// (2.12+; the first field may be declared *before* the VISIT_FROM line) or
	// as a plain `SomethingPtr name_;` member (2.10).
	rePtrField  = regexp.MustCompile(`(?:COMPRESSED_)?POINTER_FIELD\(\s*[\w:<>]+\s*,\s*(\w+)\s*\)|\b\w+Ptr\s+(\w+?)_?;`)
	reVisitFrom = regexp.MustCompile(`VISIT_FROM\(([^)]*)\)`)
	reVisitTo   = regexp.MustCompile(`VISIT_TO\(([^)]*)\)`)
	// `union { A a; B b; };` or a named `union { ... } name_;` -- one slot.
	reUnion = regexp.MustCompile(`union \{[^}]*\}\s*\w*;`)
)

// visitArg returns the field a VISIT_FROM/VISIT_TO marker names: its last
// argument, without the trailing underscore the 2.10 spelling carries.
func visitArg(arg string) string {
	parts := strings.Split(arg, ",")
	return strings.TrimSuffix(strings.TrimSpace(parts[len(parts)-1]), "_")
}

// classPointerFields lists every pointer field of a class in declaration order.
// An anonymous `union { ... };` (2.10's RegExp keeps a Function-or-TypedData
// pair per entry) occupies one pointer slot, however many members it names.
func classPointerFields(body string) []string {
	body = reUnion.ReplaceAllString(body, "ObjectPtr union_slot_;")
	var out []string
	for _, m := range rePtrField.FindAllStringSubmatch(body, -1) {
		if m[1] != "" {
			out = append(out, m[1])
		} else {
			out = append(out, m[2])
		}
	}
	return out
}

// fieldsBetweenVisitMarkers lists the pointer fields from the one VISIT_FROM
// names to the one VISIT_TO names, inclusive, in declaration order.
func fieldsBetweenVisitMarkers(t *testing.T, body, what string) []string {
	t.Helper()
	from := reVisitFrom.FindStringSubmatch(body)
	to := reVisitTo.FindStringSubmatch(body)
	if from == nil || to == nil {
		t.Fatalf("%s: VISIT_FROM/VISIT_TO not found", what)
	}
	all := classPointerFields(body)
	first, last := -1, -1
	for i, f := range all {
		if f == visitArg(from[1]) && first < 0 {
			first = i
		}
		if f == visitArg(to[1]) {
			last = i
		}
	}
	if first < 0 || last < first {
		t.Fatalf("%s: VISIT_FROM(%s)..VISIT_TO(%s) not found among fields %v", what, from[1], to[1], all)
	}
	return all[first : last+1]
}

func TestFillLayoutsMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	for _, tag := range fillLayoutTags {
		t.Run(tag, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tag)
			if profile == nil || profile.CIDs == nil {
				t.Fatalf("no profile for %s", tag)
			}
			ct := profile.CIDs
			raw, err := sdktest.SDKFileAtTag("runtime/vm/raw_object.h", tag)
			if err != nil {
				t.Fatal(err)
			}
			ser := sdkSerializerSource(t, tag)
			spec := func(cid int) FillSpec { return GetFillSpec(cid, &ClusterMeta{CID: cid}, profile) }

			// RegExp: ReadFromTo covers VISIT_FROM..VISIT_TO.
			re := sdkClassBody(t, raw, "RegExp", "UntaggedRegExp", "RegExpLayout")
			wantRefs := len(fieldsBetweenVisitMarkers(t, re, "RegExp"))
			if got := spec(ct.RegExp).NumRefs; got != wantRefs {
				t.Errorf("RegExp refs = %d, SDK VISIT_FROM..VISIT_TO has %d", got, wantRefs)
			}

			// RegExp flags width from WriteFill.
			reSer := sdkClassBody(t, ser, "RegExp serializer", "RegExpSerializationCluster")
			m := regexp.MustCompile(`Write<(\w+)>\(regexp->(?:untag|ptr)\(\)->(?:type_)?flags_\)`).FindStringSubmatch(reSer)
			if m == nil {
				t.Fatal("RegExp flags Write<> not found")
			}
			wantOp := map[string]ScalarOp{"int8_t": OpInt8, "uint32_t": OpTagged32}[m[1]]
			if sc := spec(ct.RegExp).Scalars; len(sc) != 3 || sc[2] != wantOp {
				t.Errorf("RegExp flags scalar = %v, SDK writes %s", sc, m[1])
			}

			// Namespace: ReadFromTo runs to whatever to_snapshot(kFullAOT) returns.
			ns := sdkClassBody(t, raw, "Namespace", "UntaggedNamespace", "NamespaceLayout")
			nsFields := fieldsBetweenVisitMarkers(t, ns, "Namespace")
			wantNS := len(nsFields)
			if aot := regexp.MustCompile(`kFullAOT:\s*return[^&]*&(\w+)_\)`).FindStringSubmatch(ns); aot != nil {
				wantNS = 0
				for i, f := range nsFields {
					if f == aot[1] {
						wantNS = i + 1
					}
				}
			}
			if got := spec(ct.Namespace).NumRefs; got != wantNS {
				t.Errorf("Namespace refs = %d, SDK to_snapshot(kFullAOT) covers %d", got, wantNS)
			}

			// StackTrace: ReadFromTo, always VISIT_FROM..VISIT_TO here.
			st := sdkClassBody(t, raw, "StackTrace", "UntaggedStackTrace", "StackTraceLayout")
			if want, got := len(fieldsBetweenVisitMarkers(t, st, "StackTrace")), spec(ct.StackTrace).NumRefs; got != want {
				t.Errorf("StackTrace refs = %d, SDK has %d", got, want)
			}

			// Field kind_bits width (the layout with a scalar spec starts at 2.18).
			if !profile.FillRefUnsigned {
				fs := sdkClassBody(t, ser, "Field serializer", "FieldSerializationCluster")
				fm := regexp.MustCompile(`Write<(\w+)>\(field->(?:untag|ptr)\(\)->kind_bits_\)`).FindStringSubmatch(fs)
				if fm == nil {
					t.Fatal("Field kind_bits Write<> not found")
				}
				want := map[string]ScalarOp{"uint16_t": OpUint16, "uint32_t": OpTagged32}[fm[1]]
				if sc := spec(ct.Field).Scalars; len(sc) < 1 || sc[0] != want {
					t.Errorf("Field kind_bits scalar = %v, SDK writes %s", sc, fm[1])
				}
			}

			// LoadingUnit id width.
			lu := sdkClassBody(t, ser, "LoadingUnit serializer", "LoadingUnitSerializationCluster")
			lm := regexp.MustCompile(`Write<(int32_t|intptr_t)>\(`).FindStringSubmatch(lu)
			if lm == nil {
				t.Fatal("LoadingUnit id Write<> not found")
			}
			luWant := map[string]ScalarOp{"int32_t": OpTagged32, "intptr_t": OpTagged64}[lm[1]]
			if sc := spec(ct.LoadingUnit).Scalars; len(sc) != 1 || sc[0] != luWant {
				t.Errorf("LoadingUnit id scalar = %v, SDK writes %s", sc, lm[1])
			}

			// SIMD: a Full-AOT cluster exists only where NewClusterForClass has the case.
			hasSimd := strings.Contains(ser, "Simd128SerializationCluster(cid")
			if got := spec(ct.Int32x4).Kind == FillSimd128; got != hasSimd {
				t.Errorf("SIMD cluster supported = %v, SDK NewClusterForClass has the case = %v", got, hasSimd)
			}

			// ContextScope: pointer slots of one VariableDesc, a union counting once.
			cs := sdkClassBody(t, raw, "ContextScope", "UntaggedContextScope", "ContextScopeLayout")
			vd := regexp.MustCompile(`(?s)struct VariableDesc \{.*?\n  \};`).FindString(cs)
			if vd == "" {
				t.Fatal("VariableDesc not found")
			}
			vd = reUnion.ReplaceAllString(vd, "CompressedObjectPtr union_slot;")
			slots := len(regexp.MustCompile(`\b(?:Compressed)?\w+Ptr\s+\w+;`).FindAllString(vd, -1))
			if got := contextScopeRefsPerVariable(profile); got != slots {
				t.Errorf("ContextScope refs per variable = %d, SDK VariableDesc has %d pointer slots", got, slots)
			}
		})
	}
}
