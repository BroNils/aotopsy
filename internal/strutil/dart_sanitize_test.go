package strutil

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeLibraryPathCommonURLs(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"package:app/src/main.dart", filepath.Join("package", "app", "src", "main_"+shortIdentityHash("package:app/src/main.dart")+".dart")},
		{"dart:core", filepath.Join("dart", "core_"+shortIdentityHash("dart:core")+".dart")},
		{"file:///tmp/project/main.dart", filepath.Join("file", "tmp", "project", "main_"+shortIdentityHash("file:///tmp/project/main.dart")+".dart")},
	}
	for _, tt := range tests {
		if got := SanitizeLibraryPath(tt.in); got != tt.want {
			t.Errorf("SanitizeLibraryPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSanitizeLibraryPathPreservesSchemeIdentity(t *testing.T) {
	dartCore := SanitizeLibraryPath("dart:core")
	packageCore := SanitizeLibraryPath("package:core")
	if dartCore == packageCore {
		t.Fatalf("distinct library schemes collided: %q", dartCore)
	}
	if got := SanitizeLibraryPath("package:../../outside"); !strings.HasPrefix(got, "package"+string(filepath.Separator)) {
		t.Fatalf("scheme-relative traversal escaped package namespace: %q", got)
	}
}

func TestSanitizeLibraryPathDistinguishesCleanedPathAliases(t *testing.T) {
	a := SanitizeLibraryPath("package:a/../b.dart")
	b := SanitizeLibraryPath("package:b.dart")
	if a == b {
		t.Fatalf("distinct raw library URLs collided after path.Clean: %q", a)
	}
}

func TestSanitizeDartIdentIsKeywordAndCollisionSafe(t *testing.T) {
	for _, keyword := range []string{"class", "dynamic", "get", "Function", "augment", "when", "base", "sealed"} {
		got := SanitizeDartIdent(keyword)
		if got == keyword || got == "" {
			t.Errorf("Dart keyword %q was not made declaration-safe: %q", keyword, got)
		}
	}
	for _, pair := range [][2]string{{"a-b", "a_b"}, {"class", "_class"}, {"new Foo", "Foo"}, {"é", "_"}} {
		if a, b := SanitizeDartIdent(pair[0]), SanitizeDartIdent(pair[1]); a == b {
			t.Errorf("distinct identifiers collapsed: %q and %q -> %q", pair[0], pair[1], a)
		}
	}
	if got := SanitizeDartIdent("simple_$Name9"); got != "simple_$Name9" {
		t.Fatalf("already-valid identifier changed: %q", got)
	}
	generated := SanitizeDartIdent("a-b")
	if literal := SanitizeDartIdent(generated); literal == generated {
		t.Fatalf("generated Dart identifier namespace collides with literal raw input %q", generated)
	}
}

func TestScrubDartPrivateKeysMatchesSDKSemantics(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"_ReceivePortImpl@709387912", "_ReceivePortImpl"},
		{"_ReceivePortImpl@709387912._internal@709387912", "_ReceivePortImpl._internal"},
		{"_C@6328321&_E@6328321&_F@6328321", "_C&_E&_F"},
		{"not@private", "not@private"},
		{"trailing@", "trailing@"},
		{"at@12x", "atx"},
	}
	for _, tt := range tests {
		if got := ScrubDartPrivateKeys(tt.in); got != tt.want {
			t.Errorf("ScrubDartPrivateKeys(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSanitizeLibraryPathCannotEscapeOutputDirectory(t *testing.T) {
	inputs := []string{
		"package:../../outside",
		"../../outside.dart",
		`..\\..\\outside.dart`,
		"/absolute/outside.dart",
		`C:\\absolute\\outside.dart`,
	}
	root := t.TempDir()
	for _, in := range inputs {
		rel := SanitizeLibraryPath(in)
		if filepath.IsAbs(rel) || filepath.VolumeName(rel) != "" {
			t.Errorf("SanitizeLibraryPath(%q) returned absolute/volume path %q", in, rel)
			continue
		}
		joined := filepath.Join(root, rel)
		back, err := filepath.Rel(root, joined)
		if err != nil {
			t.Fatalf("filepath.Rel(%q, %q): %v", root, joined, err)
		}
		if back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) {
			t.Errorf("SanitizeLibraryPath(%q) escaped root: rel=%q joined=%q", in, rel, joined)
		}
	}
}

func TestSanitizeDartBodyPreservesLiteralAndCommentContents(t *testing.T) {
	body := "dynamic f() {\n" +
		"  var a = \"user@123 .[](<Instance_2300>) .( /* cond */\";\n" +
		"  var b = r'raw@456 .[](<TypeArguments>) .(';\n" +
		"  var c = \"\"\"triple@789 .[](<Instance_7>) .(\"\"\";\n" +
		"  // comment@321 .[](<Instance_8>) .(\n" +
		"  return method@999(<Instance_2300>);\n" +
		"}"

	got := SanitizeDartBody(body)
	for _, unchanged := range []string{
		`"user@123 .[](<Instance_2300>) .( /* cond */"`,
		`r'raw@456 .[](<TypeArguments>) .('`,
		`"""triple@789 .[](<Instance_7>) .("""`,
		`// comment@321 .[](<Instance_8>) .(`,
	} {
		if !strings.Contains(got, unchanged) {
			t.Fatalf("SanitizeDartBody changed literal/comment %q:\n%s", unchanged, got)
		}
	}
	if !strings.Contains(got, "return method(unresolved_Instance_2300);") {
		t.Fatalf("SanitizeDartBody stopped sanitizing code expressions:\n%s", got)
	}
}

func TestSanitizeDartBodyRewritesOnlyConditionSentinelComment(t *testing.T) {
	body := `if (/* cond */) { print("/* cond */"); } /* keep @123 .[] */`
	got := SanitizeDartBody(body)
	want := `if (unresolved_cond) { print("/* cond */"); } /* keep @123 .[] */`
	if got != want {
		t.Fatalf("SanitizeDartBody() = %q, want %q", got, want)
	}
}
