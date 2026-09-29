// Package sdktest provides shared helpers for SDK drift gate tests.
//
// Each version-keyed table in this project (THR fields, thread stub
// offsets, runtime entries, base objects, ObjectStoreAOTFieldCount,
// FunctionKindLayouts, CID tables) cannot be validated by local testing:
// a wrong offset or wrong row produces a plausible-looking result that is
// simply wrong, and nothing downstream can tell. The only ground truth is
// the Dart SDK source the table was derived from.
//
// These helpers resolve exact-tag files from a local dart-lang/sdk checkout
// first, then the shared on-disk cache, and only then the GitHub API (gh CLI).
// That ordering matters for release QA: a local pulled SDK is the primary
// source of truth, while network access is only a bounded fallback for blobs
// absent from a partial clone. Tests using these helpers are opt-in via the
// AOTOPSY_TEST_SDK environment variable. The macro expansion the gates need
// lives in internal/cmacro, which tools/extract_thr.go shares.
//
// Environment:
//
//	AOTOPSY_TEST_SDK          set to anything to enable the gates
//	AOTOPSY_DART_SDK_REPO     optional exact local dart-lang/sdk checkout;
//	                          ~/dev/dartsdk-research is also probed
//	AOTOPSY_SDK_CACHE_DIR     where to cache fetched files
//	                          (default $XDG_CACHE_HOME or ~/.cache, /aotopsy/sdk)
//	AOTOPSY_TEST_SDK_OFFLINE  set to anything to forbid network entirely;
//	                          local repo/cache misses then fail instead of fetching
package sdktest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// SkipIfNoSDKTools skips the calling test unless the SDK gates are enabled.
// Tool availability is intentionally resolved lazily by SDKFileAtTag: a local
// checkout or warm cache is sufficient even when gh is absent.
func SkipIfNoSDKTools(t *testing.T) {
	t.Helper()
	if os.Getenv("AOTOPSY_TEST_SDK") == "" {
		t.Skip("AOTOPSY_TEST_SDK not set, skipping SDK drift check")
	}
}

func offline() bool { return os.Getenv("AOTOPSY_TEST_SDK_OFFLINE") != "" }

// CacheDir is where SDKFileAtTag stores resolved SDK files.
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

const (
	maxSDKSourceBytes  = 8 << 20
	maxMemCacheEntries = 64
	localGitTimeout    = 10 * time.Second
	ghTimeout          = 30 * time.Second
	ghAttempts         = 3
)

var exactReleaseTag = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$`)

func validateRequest(filePath, tag string) error {
	if !exactReleaseTag.MatchString(tag) {
		return fmt.Errorf("sdktest: refusing floating/non-release ref %q; use an exact Dart release tag", tag)
	}
	if filePath == "" || strings.Contains(filePath, `\`) || strings.ContainsAny(filePath, "?#") || path.IsAbs(filePath) {
		return fmt.Errorf("sdktest: unsafe SDK path %q", filePath)
	}
	clean := path.Clean(filePath)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != filePath {
		return fmt.Errorf("sdktest: unsafe SDK path %q", filePath)
	}
	return nil
}

// SDKFileAtTag reads a file from dart-lang/sdk at a specific release tag.
// Source precedence is deliberately local checkout -> disk cache -> GitHub.
// Returns the raw file content as a string.
//
// Always use a tag (e.g. "3.12.2") -- never "main" -- because snapshot
// layout changes between versions and reading main gives you the future,
// not the version the table was derived from.
//
// Results are cached in-process and on disk. Without the disk cache a
// full gate sweep issues hundreds of requests and trips the 60/hour
// unauthenticated rate limit. A partial local clone is never allowed to
// lazy-fetch: if the exact blob is not already local, the explicit GitHub
// fallback below owns all network behavior, timeouts, and retries.
func SDKFileAtTag(filePath, tag string) (string, error) {
	if err := validateRequest(filePath, tag); err != nil {
		return "", err
	}
	cacheDir := CacheDir()
	key := cacheDir + "\x00sdk\x00" + filePath + "\x00" + tag
	diskPath := filepath.Join(cacheDir, tag, filepath.FromSlash(filePath))

	// Local source truth has precedence over every cache. Exact release tags are
	// immutable; if a pulled checkout contains the blob, use it and refresh the
	// shared cache so all subsequent gates observe the same bytes.
	for _, repo := range localSDKRepos() {
		out, ok := readLocalSDKFile(repo, filePath, tag)
		if !ok {
			continue
		}
		if err := writeCacheAtomic(diskPath, out); err != nil {
			return "", fmt.Errorf("sdktest: cache local %s@%s: %w", filePath, tag, err)
		}
		s := string(out)
		remember(key, s)
		return s, nil
	}

	memMu.Lock()
	if s, ok := memCache[key]; ok {
		memMu.Unlock()
		return s, nil
	}
	memMu.Unlock()

	if data, err := readBoundedFile(diskPath); err == nil {
		s := string(data)
		remember(key, s)
		return s, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("sdktest: read cache %s: %w", diskPath, err)
	}

	if offline() {
		return "", fmt.Errorf("sdktest: %s@%s not available locally or in cache at %s and AOTOPSY_TEST_SDK_OFFLINE is set", filePath, tag, diskPath)
	}

	out, err := fetchGitHubSDKFile(filePath, tag)
	if err != nil {
		return "", err
	}
	if err := writeCacheAtomic(diskPath, out); err != nil {
		return "", fmt.Errorf("sdktest: cache fetched %s@%s: %w", filePath, tag, err)
	}
	s := string(out)
	remember(key, s)
	return s, nil
}

func localSDKRepos() []string {
	if repo := strings.TrimSpace(os.Getenv("AOTOPSY_DART_SDK_REPO")); repo != "" {
		// An explicit source root is an override, not merely an additional
		// candidate. Besides being the least surprising environment-variable
		// contract, this lets drift-gate tests prove that an empty/invalid local
		// source fails instead of silently falling through to the developer's
		// ~/dev tree.
		return []string{filepath.Clean(repo)}
	}
	var repos []string
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		repos = append(repos, filepath.Join(home, "dev", "dartsdk-research"))
	}
	seen := make(map[string]struct{}, len(repos))
	out := repos[:0]
	for _, repo := range repos {
		if _, ok := seen[repo]; ok {
			continue
		}
		seen[repo] = struct{}{}
		out = append(out, repo)
	}
	return out
}

func readLocalSDKFile(repo, filePath, tag string) ([]byte, bool) {
	if st, err := os.Stat(repo); err != nil || !st.IsDir() {
		return nil, false
	}
	// The QA corpus keeps one authoritative working tree per exact release at
	// <root>/<version>/. Prefer that layout directly: it avoids resolving tags
	// through a parent Git checkout and, critically, prevents an exact local
	// source tree from being missed and replaced by cache/network fallback.
	versionTreePath := filepath.Join(repo, tag, filepath.FromSlash(filePath))
	if out, err := readBoundedFile(versionTreePath); err == nil {
		return out, true
	} else if !os.IsNotExist(err) {
		return nil, false
	}

	if _, err := exec.LookPath("git"); err != nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), localGitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", repo, "show", tag+":"+filePath)
	cmd.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1")
	out, err := runBoundedCommand(cmd, maxSDKSourceBytes)
	if err != nil {
		return nil, false
	}
	return out, true
}

func fetchGitHubSDKFile(filePath, tag string) ([]byte, error) {
	// Accept: raw asks the API for file bytes directly. The default JSON
	// response base64-encodes the content and truncates above 1 MB, which can
	// silently return an empty body for larger runtime headers.
	escapedParts := strings.Split(filePath, "/")
	for i := range escapedParts {
		escapedParts[i] = url.PathEscape(escapedParts[i])
	}
	endpoint := fmt.Sprintf("repos/dart-lang/sdk/contents/%s?ref=%s",
		strings.Join(escapedParts, "/"), url.QueryEscape(tag))

	var lastErr error
	for attempt := 1; attempt <= ghAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), ghTimeout)
		cmd := exec.CommandContext(ctx, "gh", "api",
			"-H", "Accept: application/vnd.github.raw",
			endpoint)
		out, err := runBoundedCommand(cmd, maxSDKSourceBytes)
		cancel()
		if err == nil {
			return out, nil
		}
		lastErr = err
		if attempt < ghAttempts {
			time.Sleep(time.Duration(attempt) * 250 * time.Millisecond)
		}
	}
	return nil, fmt.Errorf("gh api %s@%s after %d attempts: %w", filePath, tag, ghAttempts, lastErr)
}

func runBoundedCommand(cmd *exec.Cmd, maxBytes int64) ([]byte, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}
	out, readErr := io.ReadAll(io.LimitReader(stdout, maxBytes+1))
	if int64(len(out)) > maxBytes {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("output exceeded %d-byte source limit", maxBytes)
	}
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, fmt.Errorf("read stdout: %w", readErr)
	}
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("%w: %s", waitErr, msg)
		}
		return nil, waitErr
	}
	return out, nil
}

func remember(key, value string) {
	memMu.Lock()
	if len(memCache) >= maxMemCacheEntries {
		memCache = make(map[string]string, maxMemCacheEntries)
	}
	memCache[key] = value
	memMu.Unlock()
}

func readBoundedFile(filePath string) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxSDKSourceBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSDKSourceBytes {
		return nil, fmt.Errorf("cached SDK source exceeds %d bytes", maxSDKSourceBytes)
	}
	return b, nil
}

func writeCacheAtomic(filePath string, data []byte) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sdk-cache-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(0o644); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, filePath)
}
