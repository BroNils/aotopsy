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
// the AOTOPSY_TEST_SDK environment variable. The macro expansion the
// gates need lives in internal/cmacro, which tools/extract_thr.go shares.
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
