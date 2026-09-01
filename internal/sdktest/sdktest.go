// Package sdktest provides shared helpers for SDK drift gate tests.
//
// Each version-keyed table in this project (THR fields, thread stub
// offsets, runtime entries, base objects, ObjectStoreAOTFieldCount,
// FunctionKindLayouts, CID tables) cannot be validated by local testing:
// a wrong offset or wrong row produces a plausible-looking result that is
// simply wrong, and nothing downstream can tell. The only ground truth is
// the Dart SDK source the table was derived from.
//
// These helpers fetch files from dart-lang/sdk via the GitHub API
// (gh CLI), so tests using them are network-dependent and opt-in via
// the AOTOPSY_TEST_SDK environment variable.
//
// Environment:
//
//	AOTOPSY_TEST_SDK          set to anything to enable the gates
//	AOTOPSY_SDK_CACHE_DIR     where to cache fetched files
//	                          (default $XDG_CACHE_HOME or ~/.cache, /aotopsy/sdk)
//	AOTOPSY_TEST_SDK_OFFLINE  set to anything to forbid network entirely;
//	                          a cache miss then fails instead of fetching
package sdktest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// SkipIfNoSDKTools skips the calling test unless the SDK gates are
// enabled and the tooling they need is present.
//
// This replaces the SkipIfNoSDK + HasGH pair that every gate used to
// repeat. Offline mode needs no gh, so the gh check is conditional --
// a warm cache is enough to run the gates on a machine without gh auth.
func SkipIfNoSDKTools(t *testing.T) {
	t.Helper()
	if os.Getenv("AOTOPSY_TEST_SDK") == "" {
		t.Skip("AOTOPSY_TEST_SDK not set (needs network + gh auth, or a warm cache), skipping SDK drift check")
	}
	if offline() {
		return
	}
	if _, err := exec.LookPath("gh"); err != nil {
		t.Skip("gh not on PATH and AOTOPSY_TEST_SDK_OFFLINE not set, skipping SDK drift check")
	}
}

func offline() bool { return os.Getenv("AOTOPSY_TEST_SDK_OFFLINE") != "" }

// CacheDir is where GHFileAtTag stores fetched SDK files.
func CacheDir() string {
	if d := os.Getenv("AOTOPSY_SDK_CACHE_DIR"); d != "" {
		return d
	}
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join(os.TempDir(), "aotopsy-sdk-cache")
		}
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "aotopsy", "sdk")
}

var (
	memMu    sync.Mutex
	memCache = map[string]string{}
)

// GHFileAtTag reads a file from dart-lang/sdk at a specific git tag via
// the GitHub API. Returns the raw file content as a string.
//
// Always use a tag (e.g. "3.12.2") -- never "main" -- because snapshot
// layout changes between versions and reading main gives you the future,
// not the version the table was derived from.
//
// Results are cached in-process and on disk. Without the disk cache a
// full gate sweep issues hundreds of requests and trips the 60/hour
// unauthenticated rate limit, at which point every gate calls t.Skipf
// and the whole suite reports "no drift" while having checked nothing.
func GHFileAtTag(path, tag string) (string, error) {
	if tag == "" || tag == "main" || tag == "master" {
		return "", fmt.Errorf("sdktest: refusing to read %s at %q; SDK gates must pin a version tag", path, tag)
	}
	key := path + "\x00" + tag

	memMu.Lock()
	if s, ok := memCache[key]; ok {
		memMu.Unlock()
		return s, nil
	}
	memMu.Unlock()

	diskPath := filepath.Join(CacheDir(), tag, filepath.FromSlash(path))
	if data, err := os.ReadFile(diskPath); err == nil {
		s := string(data)
		memMu.Lock()
		memCache[key] = s
		memMu.Unlock()
		return s, nil
	}

	if offline() {
		return "", fmt.Errorf("sdktest: %s@%s not in cache at %s and AOTOPSY_TEST_SDK_OFFLINE is set", path, tag, diskPath)
	}

	// Accept: raw asks the API for file bytes directly. The default JSON
	// response base64-encodes the content and truncates above 1 MB, which
	// silently returns an empty body for the larger runtime headers.
	cmd := exec.Command("gh", "api",
		"-H", "Accept: application/vnd.github.raw",
		fmt.Sprintf("repos/dart-lang/sdk/contents/%s?ref=%s", path, tag))
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("gh api %s@%s: %w", path, tag, err)
	}
	s := string(out)

	if err := os.MkdirAll(filepath.Dir(diskPath), 0o755); err == nil {
		// A cache write failure is not a test failure; the fetch succeeded.
		_ = os.WriteFile(diskPath, out, 0o644)
	}
	memMu.Lock()
	memCache[key] = s
	memMu.Unlock()
	return s, nil
}

// --- C preprocessor list-macro expansion ---
//
// The SDK expresses most of the tables this project mirrors as X-macro
// lists: `#define SOME_LIST(V) V(A) V(B) ...`. They nest -- VM_STUB_CODE_LIST
// expands PROBE_POINT_STUBS_LIST and VM_TYPE_TESTING_STUB_CODE_LIST inline --
// and several take multiple arguments per entry.
//
// A naive `V\((\w+)\)` scan silently drops the nested lists and every
// multi-argument entry, which is an excellent way to "verify" a table
// against a list that is missing rows. One expander, used by every gate.

var (
	macroDefRe   = regexp.MustCompile(`(?m)^#define\s+(\w+)\(V[^)]*\)(.*)$`)
	blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineComment  = regexp.MustCompile(`//[^\n]*`)
	identRe = regexp.MustCompile(`\w+`)
)

// ParseMacros returns every `#define NAME(V) ...` body in a C header,
// with line continuations joined and comments stripped.
func ParseMacros(src string) map[string]string {
	src = strings.ReplaceAll(src, "\\\r\n", "")
	src = strings.ReplaceAll(src, "\\\n", "")
	src = blockComment.ReplaceAllString(src, "")
	src = lineComment.ReplaceAllString(src, "")
	out := map[string]string{}
	for _, m := range macroDefRe.FindAllStringSubmatch(src, -1) {
		out[m[1]] = m[2]
	}
	return out
}

// ExpandMacroRaw expands one list macro, recursing into nested list
// macros, and returns each entry's arguments split and trimmed.
//
// `V(Name)` yields ["Name"]; `V(Type, name, expr, default)` yields all
// four. Use this when the position of an argument matters.
func ExpandMacroRaw(macros map[string]string, name string) ([][]string, error) {
	body, ok := macros[name]
	if !ok {
		return nil, macroError("macro " + name + " not found")
	}
	return expandBody(macros, body, map[string]bool{name: true})
}

// ExpandMacro expands one list macro and returns the first argument of
// each entry, which for the single-argument lists is the whole entry.
func ExpandMacro(macros map[string]string, name string) ([]string, error) {
	rows, err := ExpandMacroRaw(macros, name)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if len(r) == 0 {
			continue
		}
		out = append(out, r[0])
	}
	return out, nil
}

// ExpandMacroColumn expands a list macro and returns argument i of each
// entry. Entries with fewer arguments are skipped.
func ExpandMacroColumn(macros map[string]string, name string, i int) ([]string, error) {
	rows, err := ExpandMacroRaw(macros, name)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rows {
		if i < len(r) {
			out = append(out, r[i])
		}
	}
	return out, nil
}

// expandBody walks `IDENT( ... )` calls with a paren-depth scan rather
// than a regex. Entries carry initialiser expressions -- CACHED_VM_OBJECTS_LIST
// has V(ObjectPtr, object_null_, Object::null()) -- so a regex that stops
// at the first ')' truncates the row and one that forbids nested parens
// drops it entirely. Both read downstream as a short list.
func expandBody(macros map[string]string, body string, seen map[string]bool) ([][]string, error) {
	var out [][]string
	for i := 0; i < len(body); {
		loc := identRe.FindStringIndex(body[i:])
		if loc == nil {
			break
		}
		name := body[i+loc[0] : i+loc[1]]
		j := i + loc[1]
		if j >= len(body) || body[j] != '(' {
			i = i + loc[1]
			continue
		}
		inner, end, ok := balanced(body, j)
		if !ok {
			break
		}
		i = end

		if name != "V" {
			// A nested list is invoked as NAME(V); anything else with
			// arguments is an ordinary call, not part of the list.
			if strings.TrimSpace(inner) != "V" || seen[name] {
				continue
			}
			sub, ok := macros[name]
			if !ok {
				return nil, macroError("nested macro " + name + " not found")
			}
			seen[name] = true
			vals, err := expandBody(macros, sub, seen)
			delete(seen, name)
			if err != nil {
				return nil, err
			}
			out = append(out, vals...)
			continue
		}

		args := splitTopLevel(inner)
		// V() with an empty body is a list terminator in some headers,
		// not an entry.
		if len(args) == 1 && args[0] == "" {
			continue
		}
		out = append(out, args)
	}
	return out, nil
}

// balanced returns the contents between body[open] == '(' and its
// matching ')', plus the index just past that ')'.
func balanced(body string, open int) (string, int, bool) {
	depth := 0
	for k := open; k < len(body); k++ {
		switch body[k] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return body[open+1 : k], k + 1, true
			}
		}
	}
	return "", 0, false
}

// splitTopLevel splits on commas that are not inside parentheses or
// angle brackets, so `Array<int, int>` and `f(a, b)` stay one argument.
func splitTopLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	for k := 0; k < len(s); k++ {
		switch s[k] {
		case '(', '<':
			depth++
		case ')', '>':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:k]))
				start = k + 1
			}
		}
	}
	out = append(out, strings.TrimSpace(s[start:]))
	return out
}

type macroError string

func (e macroError) Error() string { return string(e) }
