package cluster

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"aotopsy/internal/cmacro"
	"aotopsy/internal/sdktest"
	"aotopsy/internal/snapshot"
)

type serializerSDKRoute struct {
	category string
	name     string
}

var serializerCaseRe = regexp.MustCompile(`\bcase\s+k([A-Za-z0-9_]+)\s*:`)

// TestSerializerCaseSetMatchesSDK is the fail-closed drift gate for the
// predefined-CID half of Serializer::NewClusterForClass. It derives every
// supported route from the exact SDK tag instead of copying cid.go's allowlist.
//
// Route categories are deliberately explicit. A predefined CID is accepted
// only when the SDK reaches it through one of: a productive direct switch case,
// the typed-data predicates, ReadOnlyObjectType, kInstanceCid, or the FFI marker
// macro. Conversely every predefined CID that aotopsy accepts must be present
// in one of those SDK-derived categories.
func TestSerializerCaseSetMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	for _, tag := range snapshot.SupportedVersions() {
		t.Run(tag, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tag)
			if profile == nil || profile.CIDs == nil {
				t.Fatalf("supported Dart %s has no CID profile", tag)
			}

			enum, stride, err := sdktest.CIDEnumAtTag(tag)
			if err != nil {
				t.Fatalf("derive ClassId enum @%s: %v", tag, err)
			}
			ser := sdkSerializerSource(t, tag)
			routes, exclusions := deriveSerializerSDKRoutes(t, tag, ser, enum, stride)

			for cid, route := range routes {
				if cid >= profile.CIDs.NumPredefinedCids {
					t.Errorf("SDK-derived %s route %s has CID %d at/past kNumPredefinedCids=%d",
						route.category, route.name, cid, profile.CIDs.NumPredefinedCids)
					continue
				}
				if !repoAcceptsSerializerCID(cid, profile) {
					t.Errorf("%s: SDK routes CID %d (%s) via %s, but repo fails closed (alloc=%v fill=%v)",
						tag, cid, route.name, route.category,
						ClassifyAlloc(cid, profile.CIDs),
						GetFillSpec(cid, &ClusterMeta{CID: cid}, profile).Kind)
				}
			}

			nameByCID := make(map[int]string, len(enum))
			for name, cid := range enum {
				nameByCID[cid] = name
			}
			for cid := 0; cid < profile.CIDs.NumPredefinedCids; cid++ {
				if !repoAcceptsSerializerCID(cid, profile) {
					continue
				}
				if _, ok := routes[cid]; ok {
					continue
				}
				name := nameByCID[cid]
				if name == "" {
					name = fmt.Sprintf("CID_%d", cid)
				}
				t.Errorf("%s: repo accepts predefined CID %d (%s), but exact SDK NewClusterForClass has no productive route for it",
					tag, cid, name)
			}

			// A switch label is not automatically a Full-AOT route. These explicit
			// source-derived exclusions cover UNREACHABLE arms and narrowly named
			// build/snapshot-kind cases; they must stay rejected by the repo.
			for cid, reason := range exclusions {
				if repoAcceptsSerializerCID(cid, profile) {
					t.Errorf("%s: repo accepts SDK-excluded predefined CID %d (%s): %s",
						tag, cid, nameByCID[cid], reason)
				}
			}
		})
	}
}

func deriveSerializerSDKRoutes(t *testing.T, tag, ser string, enum map[string]int, stride int) (map[int]serializerSDKRoute, map[int]string) {
	t.Helper()
	body := sdkFunctionBody(t, ser, "Serializer::NewClusterForClass")
	routes := make(map[int]serializerSDKRoute)
	exclusions := make(map[int]string)
	add := func(cid int, category, name string) {
		if prior, ok := routes[cid]; ok {
			// Some CIDs are reachable through both ReadOnlyObjectType and a direct
			// case depending on compressed-pointer/image mode. Either path proves
			// the serializer owns the CID, so retain a readable combined category.
			if prior.category != category {
				prior.category += "+" + category
				routes[cid] = prior
			}
			return
		}
		routes[cid] = serializerSDKRoute{category: category, name: name}
	}

	caseMatches := serializerCaseRe.FindAllStringSubmatchIndex(body, -1)
	for i, m := range caseMatches {
		token := body[m[2]:m[3]]
		armEnd := len(body)
		if i+1 < len(caseMatches) {
			armEnd = caseMatches[i+1][0]
		} else if d := strings.Index(body[m[1]:], "default:"); d >= 0 {
			armEnd = m[1] + d
		}
		arm := body[m[1]:armEnd]
		name := strings.TrimSuffix(token, "Cid")
		cid, ok := serializerCaseCID(enum, name)
		if !ok {
			t.Fatalf("%s: NewClusterForClass direct case k%s has no ClassId enum identity", tag, token)
		}

		switch {
		case strings.Contains(arm, "UNREACHABLE()"):
			exclusions[cid] = "direct switch arm is UNREACHABLE"
		case name == "KernelProgramInfo":
			// The factory has a dormant cluster class, but Full-AOT deliberately
			// does not write KernelProgramInfo; cid.go must not treat its mere
			// factory presence as a valid Full-AOT stream cluster.
			exclusions[cid] = "KernelProgramInfo is not written into Full-AOT snapshots"
		case name == "Bytecode":
			// Older sources retain a bytecode factory and 3.13 guards it behind
			// DART_DYNAMIC_MODULES. Aotopsy's supported input is precompiled
			// Full-AOT machine code, not the bytecode/dynamic-module snapshot path.
			exclusions[cid] = "Bytecode is outside the supported Full-AOT machine-code route"
		default:
			add(cid, "direct-case", name)
		}
	}

	if !strings.Contains(body, "cid >= kNumPredefinedCids") || !strings.Contains(body, "cid == kInstanceCid") {
		t.Fatalf("%s: Instance/app-defined NewClusterForClass route not found", tag)
	}
	instance, ok := enum["Instance"]
	if !ok {
		t.Fatalf("%s: kInstanceCid missing from ClassId enum", tag)
	}
	add(instance, "instance", "Instance")

	for _, predicate := range []string{"IsTypedDataViewClassId(cid)", "IsExternalTypedDataClassId(cid)", "IsTypedDataClassId(cid)"} {
		if !strings.Contains(body, predicate) {
			t.Fatalf("%s: expected typed-data route %s missing from NewClusterForClass", tag, predicate)
		}
	}
	firstTD, ok := enum["TypedDataInt8Array"]
	if !ok {
		t.Fatalf("%s: kTypedDataInt8ArrayCid missing from ClassId enum", tag)
	}
	byteView, ok := enum["ByteDataView"]
	if !ok {
		t.Fatalf("%s: kByteDataViewCid missing from ClassId enum", tag)
	}
	if stride <= 0 || byteView <= firstTD {
		t.Fatalf("%s: invalid SDK typed-data range first=%d byte-view=%d stride=%d", tag, firstTD, byteView, stride)
	}
	for cid := firstTD; cid < byteView; cid++ {
		rem := (cid - firstTD) % stride
		if rem <= 2 { // internal, view, external; unmodifiable (remainder 3) is not routed here.
			add(cid, "typed-data-predicate", fmt.Sprintf("typed-data-remainder-%d", rem))
		}
	}
	add(byteView, "typed-data-predicate", "ByteDataView")

	roBody := sdkFunctionBody(t, ser, "Serializer::ReadOnlyObjectType")
	for _, m := range serializerCaseRe.FindAllStringSubmatch(roBody, -1) {
		name := strings.TrimSuffix(m[1], "Cid")
		cid, ok := serializerCaseCID(enum, name)
		if !ok {
			t.Fatalf("%s: ReadOnlyObjectType case k%s has no ClassId enum identity", tag, m[1])
		}
		add(cid, "rodata", name)
	}

	if strings.Contains(body, "CLASS_LIST_FFI_TYPE_MARKER(") {
		classIDHeader, err := sdktest.SDKFileAtTag("runtime/vm/class_id.h", tag)
		if err != nil {
			t.Fatalf("%s: read class_id.h for FFI marker route: %v", tag, err)
		}
		macros, err := cmacro.ParseMacros(classIDHeader)
		if err != nil {
			t.Fatalf("%s: parse class_id.h macros: %v", tag, err)
		}
		classes, err := cmacro.Expand(macros, "CLASS_LIST_FFI_TYPE_MARKER")
		if err != nil {
			t.Fatalf("%s: expand CLASS_LIST_FFI_TYPE_MARKER: %v", tag, err)
		}
		if len(classes) == 0 {
			t.Fatalf("%s: CLASS_LIST_FFI_TYPE_MARKER route expands to no CIDs", tag)
		}
		for _, class := range classes {
			name := "Ffi" + class
			cid, ok := enum[name]
			if !ok {
				t.Fatalf("%s: FFI marker route k%sCid missing from ClassId enum", tag, name)
			}
			add(cid, "ffi-marker", name)
		}
	}

	return routes, exclusions
}

// DeltaEncodedTypedData is a serializer-only name for the kNativePointer CID;
// it is intentionally not a second ClassId enum entry.
func serializerCaseCID(enum map[string]int, name string) (int, bool) {
	if cid, ok := enum[name]; ok {
		return cid, true
	}
	if name == "DeltaEncodedTypedData" {
		cid, ok := enum["NativePointer"]
		return cid, ok
	}
	return 0, false
}

func repoAcceptsSerializerCID(cid int, profile *snapshot.VersionProfile) bool {
	ct := profile.CIDs
	if ct == nil {
		return false
	}
	// ClassifyAlloc has no VersionProfile argument, so the two source-version
	// gates enforced immediately by skipAllocV must be represented here too.
	if ct.NativePointerCid != 0 && cid == ct.NativePointerCid &&
		!snapshot.VersionAtLeast(profile.DartVersion, "2.19.0") {
		return false
	}
	if !snapshot.VersionAtLeast(profile.DartVersion, "3.4.0") &&
		(cid == ct.Float32x4 || cid == ct.Int32x4 || cid == ct.Float64x2) {
		return false
	}
	if ClassifyAlloc(cid, ct) == AllocUnknown {
		return false
	}
	return GetFillSpec(cid, &ClusterMeta{CID: cid}, profile).Kind != FillUnknown
}

// sdkFunctionBody extracts one C++ function definition while respecting nested
// braces, comments and quoted literals. NewClusterForClass contains nested
// switch/if/preprocessor regions, so a `.*?\n}` regexp silently truncates it.
func sdkFunctionBody(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, name)
	if start < 0 {
		t.Fatalf("SDK function %s not found", name)
	}
	openRel := strings.IndexByte(src[start:], '{')
	if openRel < 0 {
		t.Fatalf("SDK function %s has no body", name)
	}
	open := start + openRel
	depth := 0
	inLineComment, inBlockComment := false, false
	var quote byte
	escaped := false
	for i := open; i < len(src); i++ {
		c := src[i]
		if inLineComment {
			if c == '\n' {
				inLineComment = false
			}
			continue
		}
		if inBlockComment {
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				inBlockComment = false
				i++
			}
			continue
		}
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '/' && i+1 < len(src) {
			switch src[i+1] {
			case '/':
				inLineComment = true
				i++
				continue
			case '*':
				inBlockComment = true
				i++
				continue
			}
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open : i+1]
			}
		}
	}
	t.Fatalf("SDK function %s has unterminated body", name)
	return ""
}
