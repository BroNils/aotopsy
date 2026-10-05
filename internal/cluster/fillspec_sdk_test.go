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

var fillLayoutTags = snapshot.SupportedVersions()

// sdkSerializerSource returns the file holding the snapshot clusters: it was
// clustered_snapshot.cc up to 2.14 and app_snapshot.cc from 2.15.
func sdkSerializerSource(t *testing.T, tag string) string {
	t.Helper()
	src, err := sdktest.SDKFileAtTagAny(tag,
		"runtime/vm/app_snapshot.cc",
		"runtime/vm/clustered_snapshot.cc",
	)
	if err != nil {
		t.Fatalf("snapshot serializer source at %s: %v", tag, err)
	}
	return src
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
	// ClosureData's context_scope field is written only outside Full-AOT. Remove
	// that exact guarded block before counting the Full-AOT Write*Field calls.
	reNonFullAOTWriteBlock = regexp.MustCompile(`(?s)if\s*\(\s*s->kind\(\)\s*!=\s*Snapshot::kFullAOT\s*\)\s*\{.*?\}`)
	reClosureWriteField    = regexp.MustCompile(`Write(?:Compressed)?Field\(\s*data\s*,\s*[A-Za-z0-9_]+\s*\)`)
	reScalarWrite          = regexp.MustCompile(`\b(WriteUnsigned|WriteCid|WriteTokenPosition|Write<\s*([A-Za-z0-9_:]+)\s*>)\s*\(`)
	reSerializerHelperCall = regexp.MustCompile(`\b(Write[A-Za-z0-9_]+)\s*\(\s*s\s*,`)
)

func serializerScalarOps(t *testing.T, body, what string) []ScalarOp {
	t.Helper()
	fill := sdkFunctionBody(t, body, "void WriteFill")
	return serializerScalarOpsFromBody(t, body, fill, what, map[string]bool{})
}

func serializerScalarOpsFromBody(t *testing.T, classBody, methodBody, what string, seen map[string]bool) []ScalarOp {
	t.Helper()
	var out []ScalarOp
	for _, m := range reScalarWrite.FindAllStringSubmatch(methodBody, -1) {
		var op ScalarOp
		switch m[1] {
		case "WriteUnsigned":
			op = OpUnsigned
		case "WriteCid", "WriteTokenPosition":
			op = OpTagged32
		default:
			switch m[2] {
			case "bool":
				op = OpBool
			case "uint8_t":
				op = OpUint8
			case "int8_t":
				op = OpInt8
			case "uint16_t":
				op = OpUint16
			case "int16_t":
				op = OpInt16
			case "int32_t", "uint32_t":
				op = OpTagged32
			case "int64_t", "uint64_t", "intptr_t", "uintptr_t":
				op = OpTagged64
			default:
				t.Fatalf("%s: unrecognized serializer scalar Write<%s>", what, m[2])
			}
		}
		out = append(out, op)
	}
	// Older serializers commonly keep WriteFill as a loop that delegates the
	// actual wire writes to a private Write<Type>(s, object) helper. Follow only
	// helpers called from this method and declared inside the same cluster class;
	// do not scan the whole class, because WriteAlloc's count/CID writes are a
	// different stream phase and must not contaminate the fill shape.
	for _, m := range reSerializerHelperCall.FindAllStringSubmatch(methodBody, -1) {
		name := m[1]
		if name == "WriteFill" || name == "WriteFromTo" || seen[name] {
			continue
		}
		marker := "void " + name
		if !strings.Contains(classBody, marker) {
			continue
		}
		seen[name] = true
		helperBody := sdkFunctionBody(t, classBody, marker)
		out = append(out, serializerScalarOpsFromBody(t, classBody, helperBody, what+"."+name, seen)...)
	}
	return out
}

func equalScalarOps(a, b []ScalarOp) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

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

// typeParameterRefCountFromSDK handles the older layout where TypeParameter's
// VISIT_FROM deliberately starts at AbstractType::type_test_stub, the final
// pointer field declared by its parent class. The generic helper above only
// sees fields physically declared in the child and therefore cannot derive the
// 2.10/2.12 five-reference range without following the inheritance boundary.
func typeParameterRefCountFromSDK(t *testing.T, raw, child string) int {
	t.Helper()
	from := reVisitFrom.FindStringSubmatch(child)
	to := reVisitTo.FindStringSubmatch(child)
	if from == nil || to == nil {
		t.Fatal("TypeParameter: VISIT_FROM/VISIT_TO not found")
	}
	wantFrom, wantTo := visitArg(from[1]), visitArg(to[1])
	childFields := classPointerFields(child)
	first, last := -1, -1
	for i, f := range childFields {
		if f == wantFrom && first < 0 {
			first = i
		}
		if f == wantTo {
			last = i
		}
	}
	if first >= 0 && last >= first {
		return last - first + 1
	}
	if last < 0 {
		t.Fatalf("TypeParameter: VISIT_TO(%s) not found among child fields %v", to[1], childFields)
	}

	parent := sdkClassBody(t, raw, "AbstractType", "UntaggedAbstractType", "AbstractTypeLayout")
	parentFields := classPointerFields(parent)
	parentFirst := -1
	for i, f := range parentFields {
		if f == wantFrom {
			parentFirst = i
			break
		}
	}
	if parentFirst < 0 {
		t.Fatalf("TypeParameter: inherited VISIT_FROM(%s) not found among AbstractType fields %v", from[1], parentFields)
	}
	return len(parentFields[parentFirst:]) + last + 1
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

			// ClosureData: its Full-AOT pointer count changed 3 -> 4 -> 3 -> 2,
			// and 2.13 added one trailing WriteUnsigned scalar. Derive both from
			// the exact serializer body so future field/layout changes cannot be
			// hidden by a copied version switch in specClosureData.
			closureSer := sdkClassBody(t, ser, "ClosureData serializer", "ClosureDataSerializationCluster")
			closureFill := sdkFunctionBody(t, closureSer, "void WriteFill")
			closureFill = reNonFullAOTWriteBlock.ReplaceAllString(closureFill, "")
			wantClosureRefs := len(reClosureWriteField.FindAllString(closureFill, -1))
			wantClosureUnsigned := strings.Count(closureFill, "s->WriteUnsigned(")
			closureSpec := spec(ct.ClosureData)
			if closureSpec.NumRefs != wantClosureRefs {
				t.Errorf("ClosureData refs = %d, SDK Full-AOT Write*Field count = %d", closureSpec.NumRefs, wantClosureRefs)
			}
			if wantClosureUnsigned > 1 {
				t.Fatalf("ClosureData SDK WriteFill has %d WriteUnsigned calls; gate needs an explicit scalar-shape update", wantClosureUnsigned)
			}
			if wantClosureUnsigned == 0 {
				if len(closureSpec.Scalars) != 0 {
					t.Errorf("ClosureData scalars = %v, SDK writes no trailing unsigned scalar", closureSpec.Scalars)
				}

				// TypeParameter: both the visited pointer range and every scalar
				// write changed repeatedly across 2.10 -> 3.1. Derive both from this
				// tag's raw layout/serializer instead of trusting the profile flags.
				tpRaw := sdkClassBody(t, raw, "TypeParameter", "UntaggedTypeParameter", "TypeParameterLayout")
				tpRefs := typeParameterRefCountFromSDK(t, raw, tpRaw)
				tpSer := sdkClassBody(t, ser, "TypeParameter serializer", "TypeParameterSerializationCluster")
				tpOps := serializerScalarOps(t, tpSer, "TypeParameter")
				tpSpec := spec(ct.TypeParameter)
				if tpSpec.NumRefs != tpRefs || !equalScalarOps(tpSpec.Scalars, tpOps) {
					t.Errorf("TypeParameter spec refs/scalars = %d/%v, SDK = %d/%v", tpSpec.NumRefs, tpSpec.Scalars, tpRefs, tpOps)
				}

				// FfiTrampolineData: four references are stable, while callback_id
				// and ffi_function_kind widths/presence changed at version boundaries.
				ffiRaw := sdkClassBody(t, raw, "FfiTrampolineData", "UntaggedFfiTrampolineData", "FfiTrampolineDataLayout")
				ffiRefs := len(fieldsBetweenVisitMarkers(t, ffiRaw, "FfiTrampolineData"))
				ffiSer := sdkClassBody(t, ser, "FfiTrampolineData serializer", "FfiTrampolineDataSerializationCluster")
				ffiOps := serializerScalarOps(t, ffiSer, "FfiTrampolineData")
				ffiSpec := spec(ct.FfiTrampolineData)
				if ffiSpec.NumRefs != ffiRefs || !equalScalarOps(ffiSpec.Scalars, ffiOps) {
					t.Errorf("FfiTrampolineData spec refs/scalars = %d/%v, SDK = %d/%v", ffiSpec.NumRefs, ffiSpec.Scalars, ffiRefs, ffiOps)
				}

				if ct.RecordType != 0 {
					rtRaw := sdkClassBody(t, raw, "RecordType", "UntaggedRecordType", "RecordTypeLayout")
					rtRefs := len(fieldsBetweenVisitMarkers(t, rtRaw, "RecordType"))
					rtSer := sdkClassBody(t, ser, "RecordType serializer", "RecordTypeSerializationCluster")
					rtOps := serializerScalarOps(t, rtSer, "RecordType")
					rtSpec := spec(ct.RecordType)
					if rtSpec.NumRefs != rtRefs || !equalScalarOps(rtSpec.Scalars, rtOps) {
						t.Errorf("RecordType spec refs/scalars = %d/%v, SDK = %d/%v", rtSpec.NumRefs, rtSpec.Scalars, rtRefs, rtOps)
					}
				}

				// WeakSerializationReference used a one-CID fill through 2.12 and
				// became a forwarded/no-payload cluster from 2.13. Source presence and
				// WriteFill itself prove which shape this exact tag has.
				wsrSpec := spec(ct.WeakSerializationReference)
				wsrClass := regexp.MustCompile(`(?s)class WeakSerializationReferenceSerializationCluster\b.*?\n\};`).FindString(ser)
				if wsrClass != "" {
					wsrOps := serializerScalarOps(t, wsrClass, "WeakSerializationReference")
					if wsrSpec.Kind != FillRefs || !equalScalarOps(wsrSpec.Scalars, wsrOps) {
						t.Errorf("WeakSerializationReference spec = kind %v scalars %v, SDK WriteFill scalars %v", wsrSpec.Kind, wsrSpec.Scalars, wsrOps)
					}
				} else if wsrSpec.Kind != FillNone {
					t.Errorf("WeakSerializationReference has no serialization class but spec kind=%v", wsrSpec.Kind)
				}
			} else if len(closureSpec.Scalars) != 1 || closureSpec.Scalars[0] != OpUnsigned {
				t.Errorf("ClosureData scalars = %v, SDK writes one trailing unsigned scalar", closureSpec.Scalars)
			}

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

			// Variable-length special clusters are gated by their exact serializer
			// algorithms, not only by NewClusterForClass case presence.
			deltaPresent := strings.Contains(ser, "class DeltaEncodedTypedDataSerializationCluster")
			deltaKind := FillUnknown
			if ct.NativePointerCid != 0 {
				deltaKind = spec(ct.NativePointerCid).Kind
			}
			if deltaPresent {
				deltaBody := sdkClassBody(t, ser, "DeltaEncodedTypedData serializer", "DeltaEncodedTypedDataSerializationCluster")
				deltaFill := sdkFunctionBody(t, deltaBody, "void WriteFill")
				if !strings.Contains(deltaFill, "encoded_length") || strings.Count(deltaFill, "WriteUnsigned(") < 2 || deltaKind != FillDeltaEncodedTypedData {
					t.Errorf("DeltaEncodedTypedData parser/source mismatch: kind=%v", deltaKind)
				}
			} else if deltaKind == FillDeltaEncodedTypedData {
				t.Error("parser accepts DeltaEncodedTypedData but SDK has no serialization cluster")
			}

			localPresent := strings.Contains(ser, "class LocalVarDescriptorsSerializationCluster")
			if ct.LocalVarDescriptors != 0 {
				localKind := spec(ct.LocalVarDescriptors).Kind
				if localPresent {
					localBody := sdkClassBody(t, ser, "LocalVarDescriptors serializer", "LocalVarDescriptorsSerializationCluster")
					localFill := sdkFunctionBody(t, localBody, "void WriteFill")
					wantTokenPositions := strings.Count(localFill, "WriteTokenPosition(")
					if localKind != FillLocalVarDescriptors || wantTokenPositions != 3 ||
						!strings.Contains(localFill, "Write<int32_t>(entry.index_kind)") ||
						!strings.Contains(localFill, "Write<int64_t>(entry.scope_id)") ||
						!strings.Contains(localFill, "WriteFromTo(desc, length)") {
						t.Errorf("LocalVarDescriptors parser/source mismatch: kind=%v token_positions=%d", localKind, wantTokenPositions)
					}
				} else if localKind == FillLocalVarDescriptors {
					t.Error("parser accepts LocalVarDescriptors but SDK has no serialization cluster")
				}
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
