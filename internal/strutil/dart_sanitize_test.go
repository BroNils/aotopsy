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
		{"package:app/src/main.dart", filepath.Join("app", "src", "main.dart")},
		{"dart:core", "core.dart"},
		{"file:///tmp/project/main.dart", filepath.Join("tmp", "project", "main.dart")},
	}
	for _, tt := range tests {
		if got := SanitizeLibraryPath(tt.in); got != tt.want {
			t.Errorf("SanitizeLibraryPath(%q) = %q, want %q", tt.in, got, tt.want)
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
