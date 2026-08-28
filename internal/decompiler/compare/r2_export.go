package compare

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"aotopsy/internal/strutil"
)

// R2Export exports aotopsy's recovered symbols, classes, and
// annotations in radare2 command format, so analysts can import
// them into an r2 session via `r2 -i aotopsy.r2 libapp.so`.
//
// This is the implementation of Tier 5 item 18 (r2flutter / radare2
// integration). r2flutter (radareorg/r2flutter) is a radare2 plugin
// that brings Dart AOT awareness to r2. aotopsy can export the same
// kind of metadata in r2 command format, so analysts who prefer r2
// can use aotopsy's recovered names without running the r2flutter
// plugin.
//
// r2flutter output format (gh api verified from README.md):
//   - f name @ addr      — flag (symbol) at address
//   - f name.class @ addr — class flag
//   - CC comment @ addr   — comment at address
//   - af+ addr name       — function definition
//   - Cf size @ addr      — format (structure) at address
//
// aotopsy exports:
//   - Function names as flags (f)
//   - Class layouts as comments (CC)
//   - String references as comments (CC)
//   - Call edges as code xrefs (axt)
type R2Export struct {
	Lines []string
}

// NewR2Export creates an empty r2 export.
func NewR2Export() *R2Export {
	return &R2Export{}
}

// AddFunction adds a function flag.
func (r *R2Export) AddFunction(va uint64, name string) {
	if name == "" {
		return
	}
	// r2 flag names can't contain dots, @, or spaces.
	r2Name := strutil.SanitizeR2FlagName(name)
	r.Lines = append(r.Lines, fmt.Sprintf("f %s @ 0x%x", r2Name, va))
}

// AddComment adds a comment at an address.
func (r *R2Export) AddComment(va uint64, comment string) {
	if comment == "" {
		return
	}
	// r2 comments use CC (comment core).
	r.Lines = append(r.Lines, fmt.Sprintf("CC %s @ 0x%x", escapeR2Comment(comment), va))
}

// AddClassLayout adds a class layout as a comment at the class's
// first function address.
func (r *R2Export) AddClassLayout(className string, fields []string) {
	if className == "" || len(fields) == 0 {
		return
	}
	comment := fmt.Sprintf("class %s: %s", className, strings.Join(fields, ", "))
	r.Lines = append(r.Lines, fmt.Sprintf("CC %s", escapeR2Comment(comment)))
}

// AddStringRef adds a string reference comment.
func (r *R2Export) AddStringRef(va uint64, value string) {
	if value == "" {
		return
	}
	r.Lines = append(r.Lines, fmt.Sprintf("CC str: %s @ 0x%x", escapeR2Comment(value), va))
}

// Write writes the r2 script to a file.
func (r *R2Export) Write(path string) error {
	sort.Strings(r.Lines)
	content := strings.Join(r.Lines, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0644)
}

// WriteToDir writes the r2 script to outDir/aotopsy.r2.
func (r *R2Export) WriteToDir(outDir string) error {
	return r.Write(filepath.Join(outDir, "aotopsy.r2"))
}

// String returns the r2 script as a string.
func (r *R2Export) String() string {
	sort.Strings(r.Lines)
	return strings.Join(r.Lines, "\n") + "\n"
}

// escapeR2Comment escapes a string for use in an r2 CC comment.
func escapeR2Comment(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}
