package strutil

import (
	"regexp"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
	"aotopsy/internal/snapshot"
)

var sdkFrontendKeywordRE = regexp.MustCompile(`(?s)static const Keyword\s+[A-Z_]+\s*=\s*(?:const\s+)?Keyword\(\s*(?:/\*.*?\*/\s*\d+\s*,\s*)?"([^"]+)"`)
var sdkIdentifierCharRE = regexp.MustCompile(`(?s)bool\s+_?isIdentifierChar\(int next, bool allowDollar\)\s*\{(.*?)\n\}`)

// TestDartKeywordUnionMatchesSDK re-derives the declaration-sanitizer keyword
// union from every exact supported frontend scanner. Contextual keyword sets
// changed at 2.17.6, 2.19.0 and 3.0.5; a hand-written "usual Dart keywords"
// list silently misses valid release boundaries.
func TestDartKeywordUnionMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	union := make(map[string]struct{})
	for _, version := range snapshot.SupportedVersions() {
		src, err := sdktest.SDKFileAtTag("pkg/_fe_analyzer_shared/lib/src/scanner/token.dart", version)
		if err != nil {
			t.Fatalf("read frontend token.dart @%s: %v", version, err)
		}
		matches := sdkFrontendKeywordRE.FindAllStringSubmatch(src, -1)
		if len(matches) == 0 {
			t.Fatalf("no frontend Keyword declarations found @%s", version)
		}
		for _, m := range matches {
			union[m[1]] = struct{}{}
		}
	}
	if len(union) != len(dartKeywords) {
		t.Fatalf("Dart keyword union size = %d, committed sanitizer has %d", len(union), len(dartKeywords))
	}
	for keyword := range union {
		if _, ok := dartKeywords[keyword]; !ok {
			t.Errorf("SDK frontend keyword %q missing from sanitizer", keyword)
		}
	}
	for keyword := range dartKeywords {
		if _, ok := union[keyword]; !ok {
			t.Errorf("sanitizer keyword %q is not present in any supported SDK frontend", keyword)
		}
	}
}

func TestDartIdentifierAlphabetMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	for _, version := range snapshot.SupportedVersions() {
		abstract, err := sdktest.SDKFileAtTag("pkg/_fe_analyzer_shared/lib/src/scanner/abstract_scanner.dart", version)
		if err != nil {
			t.Fatalf("read frontend abstract_scanner.dart @%s: %v", version, err)
		}
		src := abstract
		match := sdkIdentifierCharRE.FindStringSubmatch(src)
		if match == nil {
			// Newer frontends moved the same hot predicate to internal_utils.dart.
			src, err = sdktest.SDKFileAtTag("pkg/_fe_analyzer_shared/lib/src/scanner/internal_utils.dart", version)
			if err != nil {
				t.Fatalf("read frontend identifier predicate @%s: %v", version, err)
			}
			match = sdkIdentifierCharRE.FindStringSubmatch(src)
		}
		if match == nil {
			t.Fatalf("frontend identifier predicate not found @%s", version)
		}
		body := strings.Join(strings.Fields(match[1]), "")
		for _, fragment := range []string{"$a<=next&&next<=$z", "$A<=next&&next<=$Z", "$0<=next&&next<=$9", "$_", "$$", "allowDollar"} {
			if !strings.Contains(body, fragment) {
				t.Errorf("frontend identifier predicate @%s no longer contains %q: %s", version, fragment, body)
			}
		}
		if strings.Contains(body, "currentAsUnicode") || strings.Contains(body, ">127") || strings.Contains(body, "unicode") {
			t.Errorf("frontend identifier predicate @%s gained non-ASCII handling: %s", version, body)
		}
		// The top-level scanner dispatch must also accept '$' as an identifier
		// start, not merely as a continuation character.
		if !strings.Contains(abstract, "tokenizeKeywordOrIdentifier(next, /* allowDollar = */ true)") || !strings.Contains(abstract, "$$") {
			t.Errorf("frontend scanner @%s no longer proves '$' can start an identifier", version)
		}
	}
}

func TestScrubDartPrivateKeysMatchesSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)
	for _, version := range snapshot.SupportedVersions() {
		src, err := sdktest.SDKFileAtTag("runtime/vm/object.cc", version)
		if err != nil {
			t.Fatalf("read runtime/vm/object.cc @%s: %v", version, err)
		}
		for _, fragment := range []string{
			"(cname[i] == '@')",
			"(cname[i + 1] >= '0')",
			"(cname[i + 1] <= '9')",
			"(name.CharAt(i) >= '0')",
			"(name.CharAt(i) <= '9')",
		} {
			if !strings.Contains(src, fragment) {
				t.Errorf("String::ScrubName private-key predicate @%s no longer contains %q", version, fragment)
			}
		}
	}
}
