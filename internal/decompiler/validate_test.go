package decompiler

import (
	"os"
	"strings"
	"testing"
)

// Each case here is a shape that actually shipped, with the count it reached
// before anyone noticed.
func TestValidateSourceCatchesShippedDefects(t *testing.T) {
	cases := []struct {
		name, src, rule string
	}{
		{
			// 28148 sites on the Dart 2.12 sample. B.AL is unconditional, but
			// it was decoded as a conditional branch and arm64CondOp mapped
			// the "always" condition to the string "true", which
			// buildCondition then spliced into its "%s %s %s" template.
			name: "keyword spliced in as a binary operator",
			src:  "void f() {\n  if ((x15 - 16) true THR.f64) {\n    a();\n  }\n}",
			rule: "keyword-as-operator",
		},
		{
			// 1830 sites. The expression parser split the operator method
			// name off the member chain and re-printed the call as an
			// addition.
			name: "operator method name lost from a member access",
			src:  "void f() {\n  final t1 = _StringBase@0150898. + (a, b);\n}",
			rule: "spaced-member-operator",
		},
		{
			// The class of failure the statement tree was built to make
			// impossible; kept as a check because it is catastrophic and
			// cheap to detect.
			name: "unbalanced braces",
			src:  "void f() {\n  if (a) {\n    b();\n}",
			rule: "brace-unbalanced",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateSource(tc.src)
			if len(got) == 0 {
				t.Fatalf("no problem reported for a known-bad shape:\n%s", tc.src)
			}
			found := false
			for _, p := range got {
				if p.Rule == tc.rule {
					found = true
				}
			}
			if !found {
				t.Errorf("expected rule %q, got %v", tc.rule, got)
			}
		})
	}
}

// The emitter legitimately prints things a Dart parser would reject --
// register names, synthetic locals, goto labels, braces inside string
// literals. Flagging those would make the check useless, so they must pass.
func TestValidateSourceAcceptsLegitimateOutput(t *testing.T) {
	src := strings.Join([]string{
		"dynamic foo(dynamic arg0) {",
		"  x15.m16 = framePointer;",
		"  [SP-16] = returnAddress;",
		"  local_m24 = THR.heap_base;",
		"  final t1 = _StringBase@0150898.+(a, b);",
		"  final t2 = Offset.unary-(p);",
		"  var s = \"{\";",
		"  if ((w0 & 1) == 0) {",
		"    goto block_3;",
		"  } else if (arg0 == null) {",
		"    return null;",
		"  }",
		"  block_3:;",
		"  return t1;",
		"}",
	}, "\n")
	if got := ValidateSource(src); len(got) != 0 {
		t.Errorf("legitimate output was flagged: %v", got)
	}
}

// TestDecompiledCorpusIsWellFormed runs the check over real decompiled
// output. Point it at a combined.dart produced by
// `aotopsy _debug decompile-native --all`:
//
//	AOTOPSY_VALIDATE_DART=/path/to/combined.dart[,more.dart] go test ./internal/decompiler/ -run CorpusIsWellFormed -v
//
// Opt-in because it needs a sample sweep, which is expensive. This is the
// gate the golden files cannot be: they compare hashes, so they notice that
// output changed but have no opinion on whether it is coherent.
func TestDecompiledCorpusIsWellFormed(t *testing.T) {
	list := os.Getenv("AOTOPSY_VALIDATE_DART")
	if list == "" {
		t.Skip("AOTOPSY_VALIDATE_DART not set")
	}
	for _, path := range strings.Split(list, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		t.Run(path, func(t *testing.T) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			src := string(b)
			problems := ValidateSource(src)
			t.Logf("%d lines, %d placeholders, %d problems",
				strings.Count(src, "\n")+1, CountPlaceholders(src), len(problems))
			for i, p := range problems {
				if i >= 10 {
					t.Errorf("... and %d more", len(problems)-10)
					break
				}
				t.Errorf("%s", p)
			}
		})
	}
}
