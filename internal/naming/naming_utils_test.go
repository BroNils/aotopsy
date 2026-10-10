package naming

import (
	"strings"
	"testing"
)

func TestFuncRelPathLongNamesRemainUnique(t *testing.T) {
	name := strings.Repeat("very_long_function_name_", 20)
	a := FuncRelPath("Owner", name, 0x1000)
	b := FuncRelPath("Owner", name, 0x2000)
	if a == b {
		t.Fatalf("distinct functions collided after filename sanitization: %q", a)
	}
}

func TestFuncRelPathOwnerComponentsStayPortableAndDistinct(t *testing.T) {
	a := FuncRelPath("CON", "method", 0x1000)
	b := FuncRelPath("con", "method", 0x1000)
	if strings.EqualFold(a, b) {
		t.Fatalf("Windows-reserved/case-folded owners collided: %q / %q", a, b)
	}
}
