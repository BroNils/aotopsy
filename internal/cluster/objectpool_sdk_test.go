package cluster

import (
	"regexp"
	"strings"
	"testing"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/sdktest"
	"aotopsy/internal/snapshot"
)

var (
	objectPoolEntryTypeRe = regexp.MustCompile(`(?s)struct\s+ObjectPoolBuilderEntry\s*\{.*?enum\s+EntryType\s*\{(.*?)\};`)
	objectPoolBehaviorRe  = regexp.MustCompile(`(?s)struct\s+ObjectPoolBuilderEntry\s*\{.*?enum\s+SnapshotBehavior\s*\{(.*?)\};`)
	objectPoolEnumItemRe  = regexp.MustCompile(`\bk([A-Za-z0-9_]+)\s*(?:=\s*\d+)?\s*,`)
	objectPoolBlockCmtRe  = regexp.MustCompile(`(?s)/\*.*?\*/`)
	objectPoolLineCmtRe   = regexp.MustCompile(`//[^\n]*`)
)

// TestObjectPoolEntryBoundariesMatchSDK ties the profile switches used by
// readFillObjectPool to ObjectPoolBuilderEntry itself. The ordinary regression
// tests pin copied version expectations; this gate makes the exact SDK release
// prove where the old/new bit layout and type-4 payload boundaries actually are.
func TestObjectPoolEntryBoundariesMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	for _, tag := range snapshot.SupportedVersions() {
		t.Run(tag, func(t *testing.T) {
			profile := snapshot.ProfileForVersion(tag)
			if profile == nil {
				t.Fatalf("missing profile %s", tag)
			}
			src, err := sdktest.SDKFileAtTag("runtime/vm/compiler/assembler/object_pool_builder.h", tag)
			if err != nil {
				t.Fatal(err)
			}

			entryTypes := sdkEnumItems(t, src, objectPoolEntryTypeRe, "ObjectPoolBuilderEntry::EntryType")
			behaviorMatch := objectPoolBehaviorRe.FindStringSubmatch(src)
			oldFormat := behaviorMatch == nil
			if profile.OldPoolFormat != oldFormat {
				t.Errorf("OldPoolFormat=%v, SDK SnapshotBehavior enum present=%v", profile.OldPoolFormat, !oldFormat)
			}

			immediate := enumItemIndex(entryTypes, "Immediate")
			tagged := enumItemIndex(entryTypes, "TaggedObject")
			if immediate < 0 || tagged < 0 {
				t.Fatalf("EntryType lacks Immediate/TaggedObject: %v", entryTypes)
			}
			wantSwapped := oldFormat && immediate < tagged
			if profile.PoolTypeSwapped != wantSwapped {
				t.Errorf("PoolTypeSwapped=%v, SDK old-format EntryType order=%v", profile.PoolTypeSwapped, entryTypes)
			}

			if oldFormat {
				checkOldPoolType4AgainstSDK(t, profile, entryTypes)
				return
			}

			if len(entryTypes) < 3 || entryTypes[0] != "Immediate" || entryTypes[1] != "TaggedObject" || entryTypes[2] != "NativeFunction" {
				t.Fatalf("modern EntryType prefix = %v, want Immediate/TaggedObject/NativeFunction", entryTypes)
			}
			behaviors := sdkEnumItemsFromBody(behaviorMatch[1])
			wantBehaviorPrefix := []string{
				"Snapshotable",
				"NotSnapshotable",
				"ResetToBootstrapNative",
				"ResetToSwitchableCallMissEntryPoint",
				"SetToZero",
			}
			if len(behaviors) < len(wantBehaviorPrefix) {
				t.Fatalf("SnapshotBehavior enum too short: %v", behaviors)
			}
			for i, want := range wantBehaviorPrefix {
				if behaviors[i] != want {
					t.Fatalf("SnapshotBehavior[%d]=%s, want %s; parser behavior-bit switch needs review", i, behaviors[i], want)
				}
			}
		})
	}
}

func checkOldPoolType4AgainstSDK(t *testing.T, profile *snapshot.VersionProfile, entryTypes []string) {
	t.Helper()
	cm := &ClusterMeta{Count: 1, Lengths: []int64{1}}
	data := append(encUnsigned(1), byte(4))

	if len(entryTypes) <= 4 {
		if _, err := readFillObjectPool(dartfmt.NewStream(data), cm, profile, profile.FillRefUnsigned); err == nil {
			t.Fatalf("SDK EntryType has no type 4 (%v), but parser accepts one", entryTypes)
		}
		return
	}

	switch entryTypes[4] {
	case "NativeEntryData":
		data = append(data, encUnsigned(7)...)
		data = append(data, 0x5a)
	case "MegamorphicCallEntryPoint":
		data = append(data, 0x5a)
	default:
		t.Fatalf("SDK old-format EntryType[4]=%s; parser needs an explicit payload rule", entryTypes[4])
	}
	s := dartfmt.NewStream(data)
	if _, err := readFillObjectPool(s, cm, profile, profile.FillRefUnsigned); err != nil {
		t.Fatalf("parser rejected SDK EntryType[4]=%s: %v", entryTypes[4], err)
	}
	marker, err := s.ReadByte()
	if err != nil || marker != 0x5a {
		t.Fatalf("SDK EntryType[4]=%s consumed wrong payload boundary: marker=%#x err=%v", entryTypes[4], marker, err)
	}
}

func sdkEnumItems(t *testing.T, src string, re *regexp.Regexp, what string) []string {
	t.Helper()
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("%s enum not found", what)
	}
	return sdkEnumItemsFromBody(m[1])
}

func sdkEnumItemsFromBody(body string) []string {
	body = objectPoolBlockCmtRe.ReplaceAllString(body, "")
	body = objectPoolLineCmtRe.ReplaceAllString(body, "")
	var out []string
	for _, m := range objectPoolEnumItemRe.FindAllStringSubmatch(body, -1) {
		out = append(out, strings.TrimSpace(m[1]))
	}
	return out
}

func enumItemIndex(items []string, want string) int {
	for i, item := range items {
		if item == want {
			return i
		}
	}
	return -1
}
