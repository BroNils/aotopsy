package decompiler

import (
	"strings"
	"testing"
)

// TestSynthesizeClass verifies Phase 9: class declarations with inheritance, mixins, fields, and methods.
func TestSynthesizeClass(t *testing.T) {
	c := &ClassDecl{
		Name:       "UserModel",
		SuperClass: "BaseModel",
		Mixins:     []string{"JsonSerializable", "Observable"},
		Interfaces: []string{"Comparable", "Printable"},
		Fields: []FieldDecl{
			{Name: "id", Type: "int", IsFinal: true},
			{Name: "name", Type: "String"},
			{Name: "defaultRole", Type: "String", IsStatic: true, Value: `"USER"`},
		},
		Methods: []MethodDecl{
			{
				Name:       "getName",
				ReturnType: "String",
				Parameters: "",
				Body:       "return name;",
			},
			{
				Name:       "fetchDetails",
				ReturnType: "Future<void>",
				Parameters: "int timeout",
				IsAsync:    true,
				Body:       "final res = await api.get(id);\nprint(res);",
			},
		},
	}

	dartSrc := SynthesizeClass(c)

	if !strings.Contains(dartSrc, "class UserModel extends BaseModel with JsonSerializable, Observable implements Comparable, Printable {") {
		t.Errorf("expected class header with extends, with, and implements, got:\n%s", dartSrc)
	}
	if !strings.Contains(dartSrc, "final int id;") || !strings.Contains(dartSrc, "String name;") || !strings.Contains(dartSrc, `static String defaultRole = "USER";`) {
		t.Errorf("expected class fields, got:\n%s", dartSrc)
	}
	if !strings.Contains(dartSrc, "String getName() {") || !strings.Contains(dartSrc, "Future<void> fetchDetails(int timeout) async {") {
		t.Errorf("expected method signatures, got:\n%s", dartSrc)
	}
}

// TestSynthesizeLibrary verifies Phase 9: multi-class and top-level member module synthesis.
func TestSynthesizeLibrary(t *testing.T) {
	lib := NewLibraryDecl("package:example/services.dart")
	lib.TopLevelFields = []FieldDecl{
		{Name: "apiVersion", Type: "String", IsFinal: true, Value: `"v1"`},
	}
	lib.TopLevelMethods = []MethodDecl{
		{
			Name:       "initializeService",
			ReturnType: "void",
			Parameters: "",
			Body:       `print("Initialized " + apiVersion);`,
		},
	}
	lib.Classes["AuthService"] = &ClassDecl{
		Name: "AuthService",
		Methods: []MethodDecl{
			{
				Name:       "login",
				ReturnType: "bool",
				Parameters: "String user, String pass",
				Body:       "return user == pass;",
			},
		},
	}

	dartSrc := SynthesizeLibrary(lib)

	if !strings.Contains(dartSrc, "// Library: package:example/services.dart") {
		t.Errorf("expected library header comment, got:\n%s", dartSrc)
	}
	if !strings.Contains(dartSrc, `final String apiVersion = "v1";`) {
		t.Errorf("expected top level field, got:\n%s", dartSrc)
	}
	if !strings.Contains(dartSrc, "void initializeService() {") {
		t.Errorf("expected top level method, got:\n%s", dartSrc)
	}
	if !strings.Contains(dartSrc, "class AuthService {") || !strings.Contains(dartSrc, "bool login(String user, String pass) {") {
		t.Errorf("expected class and method inside library, got:\n%s", dartSrc)
	}
}
