package decompiler

import (
	"fmt"
	"sort"
	"strings"
)

// FieldDecl represents a field declaration in a Dart class or library.
type FieldDecl struct {
	Name     string
	Type     string
	IsStatic bool
	IsFinal  bool
	Value    string
}

// MethodDecl represents a method or function declaration.
type MethodDecl struct {
	Name       string
	ReturnType string
	Parameters string
	IsStatic   bool
	IsGetter   bool
	IsSetter   bool
	IsAsync    bool
	Body       string // formatted body inside braces
}

// ClassDecl represents a reconstructed Dart class.
type ClassDecl struct {
	Name        string
	LibraryURL  string
	SuperClass  string
	Interfaces  []string
	Mixins      []string
	IsAbstract  bool
	Fields      []FieldDecl
	Methods     []MethodDecl
}

// LibraryDecl represents a reconstructed Dart library or module file.
type LibraryDecl struct {
	URL             string
	Classes         map[string]*ClassDecl
	TopLevelMethods []MethodDecl
	TopLevelFields  []FieldDecl
}

// NewLibraryDecl creates an empty LibraryDecl.
func NewLibraryDecl(url string) *LibraryDecl {
	return &LibraryDecl{
		URL:     url,
		Classes: make(map[string]*ClassDecl),
	}
}

// SynthesizeClass renders a ClassDecl as complete, authentic Dart source code.
func SynthesizeClass(c *ClassDecl) string {
	var sb strings.Builder

	if c.IsAbstract {
		sb.WriteString("abstract ")
	}
	sb.WriteString("class ")
	sb.WriteString(c.Name)

	if c.SuperClass != "" && c.SuperClass != "Object" && c.SuperClass != "_Object" {
		sb.WriteString(" extends ")
		sb.WriteString(c.SuperClass)
	}

	if len(c.Mixins) > 0 {
		sb.WriteString(" with ")
		sb.WriteString(strings.Join(c.Mixins, ", "))
	}

	if len(c.Interfaces) > 0 {
		sb.WriteString(" implements ")
		sb.WriteString(strings.Join(c.Interfaces, ", "))
	}

	sb.WriteString(" {\n")

	// Render Fields
	if len(c.Fields) > 0 {
		for _, f := range c.Fields {
			sb.WriteString("  ")
			if f.IsStatic {
				sb.WriteString("static ")
			}
			if f.IsFinal {
				sb.WriteString("final ")
			}
			t := f.Type
			if t == "" {
				if !f.IsFinal {
					t = "dynamic"
				}
			}
			if t != "" {
				sb.WriteString(t)
				sb.WriteString(" ")
			}
			sb.WriteString(f.Name)
			if f.Value != "" {
				sb.WriteString(" = ")
				sb.WriteString(f.Value)
			}
			sb.WriteString(";\n")
		}
		sb.WriteString("\n")
	}

	// Render Methods
	for i, m := range c.Methods {
		if i > 0 {
			sb.WriteString("\n")
		}
		renderMethod(&sb, m, "  ")
	}

	sb.WriteString("}\n")
	return sb.String()
}

// SynthesizeLibrary renders a full Dart library file containing top-level declarations and classes.
func SynthesizeLibrary(lib *LibraryDecl) string {
	var sb strings.Builder

	if lib.URL != "" {
		sb.WriteString(fmt.Sprintf("// Library: %s\n\n", lib.URL))
	}

	// Top-level fields
	if len(lib.TopLevelFields) > 0 {
		for _, f := range lib.TopLevelFields {
			if f.IsFinal {
				sb.WriteString("final ")
			}
			t := f.Type
			if t == "" && !f.IsFinal {
				t = "dynamic"
			}
			if t != "" {
				sb.WriteString(t)
				sb.WriteString(" ")
			}
			sb.WriteString(f.Name)
			if f.Value != "" {
				sb.WriteString(" = ")
				sb.WriteString(f.Value)
			}
			sb.WriteString(";\n")
		}
		sb.WriteString("\n")
	}

	// Top-level methods
	if len(lib.TopLevelMethods) > 0 {
		for _, m := range lib.TopLevelMethods {
			renderMethod(&sb, m, "")
			sb.WriteString("\n")
		}
	}

	// Sort class names deterministically
	var classNames []string
	for name := range lib.Classes {
		classNames = append(classNames, name)
	}
	sort.Strings(classNames)

	for i, name := range classNames {
		if i > 0 || len(lib.TopLevelMethods) > 0 || len(lib.TopLevelFields) > 0 {
			sb.WriteString("\n")
		}
		c := lib.Classes[name]
		sb.WriteString(SynthesizeClass(c))
	}

	return sb.String()
}

func renderMethod(sb *strings.Builder, m MethodDecl, indent string) {
	sb.WriteString(indent)
	if m.IsStatic {
		sb.WriteString("static ")
	}
	retType := m.ReturnType
	if retType == "" {
		retType = "dynamic"
	}
	if m.IsGetter {
		sb.WriteString(fmt.Sprintf("%s get %s", retType, m.Name))
	} else if m.IsSetter {
		sb.WriteString(fmt.Sprintf("set %s(%s)", m.Name, m.Parameters))
	} else {
		sb.WriteString(fmt.Sprintf("%s %s(%s)", retType, m.Name, m.Parameters))
	}

	if m.IsAsync {
		sb.WriteString(" async")
	}

	body := strings.TrimSpace(m.Body)
	if body == "" {
		sb.WriteString(" {}\n")
		return
	}

	// If body is already braced, adjust indentation
	if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
		inner := strings.TrimSpace(body[1 : len(body)-1])
		if inner == "" {
			sb.WriteString(" {}\n")
			return
		}
		sb.WriteString(" {\n")
		lines := strings.Split(inner, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				sb.WriteString("\n")
				continue
			}
			sb.WriteString(indent + "  " + strings.TrimSpace(line) + "\n")
		}
		sb.WriteString(indent + "}\n")
	} else {
		// Single expression or body lines
		sb.WriteString(" {\n")
		lines := strings.Split(body, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				sb.WriteString("\n")
				continue
			}
			sb.WriteString(indent + "  " + strings.TrimSpace(line) + "\n")
		}
		sb.WriteString(indent + "}\n")
	}
}
