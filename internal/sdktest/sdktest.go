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
// That ordering matters for release QA: an exact local SDK is the primary
// source of truth. Once an authoritative local release tree/tag is found, a
// missing/dirty blob is fatal and is never "healed" from cache or network;
// bounded network access is only a fallback when no exact local source handles
// that release. Tests using these helpers are opt-in via the
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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	memMu         sync.Mutex
	memCache      = map[string]string{}
	memCacheBytes int
)

const (
	maxSDKSourceBytes    = 8 << 20
	maxSDKPathBytes      = 4096
	maxSDKTagBytes       = 128
	maxCacheMetadataSize = 8 << 10
	maxCommandStderr     = 32 << 10
	maxMemCacheEntries   = 64
	maxMemCacheBytes     = 32 << 20
	localGitTimeout      = 10 * time.Second
	ghTimeout            = 8 * time.Second
	ghAttempts           = 3
	cacheMetadataVersion = 2
	cacheEnvelopeMagic   = "AOTOPSY-SDK-CACHE-V2\n"
)

var exactReleaseTag = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$`)
var gitObjectID = regexp.MustCompile(`^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$`)

// ErrSDKFileNotFound means the requested path is absent from the exact,
// immutable release source. Callers that intentionally support historical
// filename moves may try another known path only for this error. Identity,
// integrity, cache, and transport failures must remain fatal.
var ErrSDKFileNotFound = errors.New("sdktest: file absent from exact release")

func validateRequest(filePath, tag string) error {
	if len(tag) == 0 || len(tag) > maxSDKTagBytes {
		return fmt.Errorf("sdktest: invalid release tag length %d", len(tag))
	}
	if !exactReleaseTag.MatchString(tag) {
		return fmt.Errorf("sdktest: refusing floating/non-release ref %q; use an exact Dart release tag", tag)
	}
	if len(filePath) == 0 || len(filePath) > maxSDKPathBytes || strings.Contains(filePath, `\`) ||
		strings.ContainsAny(filePath, "?#:\x00") || path.IsAbs(filePath) || hasControlByte(filePath) {
		return fmt.Errorf("sdktest: unsafe SDK path %q", filePath)
	}
	clean := path.Clean(filePath)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != filePath {
		return fmt.Errorf("sdktest: unsafe SDK path %q", filePath)
	}
	return nil
}

func hasControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

type cacheMetadata struct {
	Version int    `json:"version"`
	Tag     string `json:"tag"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Source  string `json:"source"`
	Commit  string `json:"commit"`
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
	cacheDir := filepath.Clean(CacheDir())
	if !filepath.IsAbs(cacheDir) {
		return "", fmt.Errorf("sdktest: cache directory must be absolute, got %q", cacheDir)
	}
	key := cacheDir + "\x00sdk\x00" + filePath + "\x00" + tag
	cacheRel := filepath.Join(tag, filepath.FromSlash(filePath))
	diskPath := filepath.Join(cacheDir, cacheRel)
	if err := ensureWithin(cacheDir, diskPath); err != nil {
		return "", err
	}
	if err := rejectSymlinkedCachePath(cacheDir, diskPath); err != nil {
		return "", err
	}

	// Local source truth has precedence over every cache. A <root>/<tag> working
	// tree is authoritative when present: if its identity or requested file is
	// wrong, fail closed instead of silently accepting a stale cache/network copy.
	repos, err := localSDKRepos()
	if err != nil {
		return "", err
	}
	for _, repo := range repos {
		out, handled, source, commit, err := readLocalSDKFile(repo, filePath, tag)
		if err != nil {
			return "", err
		}
		if !handled {
			continue
		}
		if err := writeCacheEntryAtomic(cacheDir, cacheRel, filePath, tag, source, commit, out); err != nil {
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

	if data, err := readCacheEntry(cacheDir, cacheRel, filePath, tag); err == nil {
		s := string(data)
		remember(key, s)
		return s, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("sdktest: read cache %s: %w", diskPath, err)
	}

	if offline() {
		return "", fmt.Errorf("sdktest: %s@%s not available locally or in cache at %s and AOTOPSY_TEST_SDK_OFFLINE is set", filePath, tag, diskPath)
	}

	out, commit, err := fetchGitHubSDKFile(filePath, tag)
	if err != nil {
		return "", err
	}
	if err := writeCacheEntryAtomic(cacheDir, cacheRel, filePath, tag, "github-exact-commit", commit, out); err != nil {
		return "", fmt.Errorf("sdktest: cache fetched %s@%s: %w", filePath, tag, err)
	}
	s := string(out)
	remember(key, s)
	return s, nil
}

// SDKFileAtTagAny resolves the first path that exists at the exact release.
// It is deliberately strict: only ErrSDKFileNotFound advances to the next
// historical filename. Every other error is source-integrity failure and is
// returned immediately instead of being hidden by a fallback path.
func SDKFileAtTagAny(tag string, filePaths ...string) (string, error) {
	if len(filePaths) == 0 {
		return "", fmt.Errorf("sdktest: no SDK paths supplied for %s", tag)
	}
	var missing []string
	for _, filePath := range filePaths {
		out, err := SDKFileAtTag(filePath, tag)
		if err == nil {
			return out, nil
		}
		if !errors.Is(err, ErrSDKFileNotFound) {
			return "", err
		}
		missing = append(missing, filePath)
	}
	return "", fmt.Errorf("%w: none of %s exist at %s", ErrSDKFileNotFound, strings.Join(missing, ", "), tag)
}

func ensureWithin(root, candidate string) error {
	rel, err := filepath.Rel(root, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("sdktest: cache path %q escapes root %q", candidate, root)
	}
	return nil
}

// rejectSymlinkedCachePath prevents a pre-existing cache component from
// redirecting reads/writes outside the configured cache root. Lexical
// filepath.Rel checks stop `..` traversal but do not stop `root/tag -> /tmp/x`.
// The cache is verifier state, so following such a link would let unrelated
// bytes masquerade as an exact-tag fixture.
func rejectSymlinkedCachePath(root, candidate string) error {
	if err := ensureWithin(root, candidate); err != nil {
		return err
	}
	cur := filepath.Clean(root)
	if st, err := os.Lstat(cur); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("sdktest: cache root %q is a symlink", cur)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("sdktest: inspect cache root %q: %w", cur, err)
	}
	rel, _ := filepath.Rel(cur, filepath.Dir(candidate))
	if rel == "." {
		return nil
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		st, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			// No deeper component can exist beneath a missing directory.
			return nil
		}
		if err != nil {
			return fmt.Errorf("sdktest: inspect cache path %q: %w", cur, err)
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("sdktest: cache path component %q is a symlink", cur)
		}
		if !st.IsDir() {
			return fmt.Errorf("sdktest: cache path component %q is not a directory", cur)
		}
	}
	return nil
}

func localSDKRepos() ([]string, error) {
	if repo := strings.TrimSpace(os.Getenv("AOTOPSY_DART_SDK_REPO")); repo != "" {
		// An explicit source root is an override, not merely an additional
		// candidate. Besides being the least surprising environment-variable
		// contract, this lets drift-gate tests prove that an empty/invalid local
		// source fails instead of silently falling through to the developer's
		// ~/dev tree.
		repo = filepath.Clean(repo)
		if !filepath.IsAbs(repo) {
			return nil, fmt.Errorf("sdktest: AOTOPSY_DART_SDK_REPO must be absolute, got %q", repo)
		}
		return []string{repo}, nil
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
	return out, nil
}

// readLocalSDKFile returns handled=true once an exact local source identity has
// been found. From that point any error is authoritative and MUST NOT fall
// through to cache/network: doing so lets a broken/wrong local release produce
// a green drift gate from unrelated bytes.
func readLocalSDKFile(repo, filePath, tag string) (out []byte, handled bool, source, commit string, err error) {
	if st, err := os.Stat(repo); err != nil || !st.IsDir() {
		return nil, false, "", "", nil
	}
	// The QA corpus keeps one authoritative working tree per exact release at
	// <root>/<version>/. Prove both repository identity and file identity rather
	// than trusting the directory name: HEAD must equal refs/tags/<tag>, and the
	// checked-out file must byte-match that immutable tag blob.
	versionTree := filepath.Join(repo, tag)
	if st, statErr := os.Stat(versionTree); statErr == nil && st.IsDir() {
		out, commit, err := readVerifiedVersionTreeFile(versionTree, filePath, tag)
		if err != nil {
			return nil, true, "local-version-tree", "", err
		}
		return out, true, "local-version-tree", commit, nil
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return nil, true, "local-version-tree", "", fmt.Errorf("sdktest: stat exact local tree %s: %w", versionTree, statErr)
	}

	// A conventional single Git checkout is a secondary local form. Resolve an
	// explicit tag ref, never the ambiguous bare name: a branch named "3.12.2"
	// must not masquerade as the immutable release tag.
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, false, "", "", nil
	}
	ref := "refs/tags/" + tag
	commit, found, err := gitExactTagCommit(gitPath, repo, ref)
	if err != nil {
		return nil, true, "local-git-tag", "", err
	}
	if !found {
		return nil, false, "", "", nil
	}
	exists, err := gitPathExistsAtRef(gitPath, repo, ref, filePath)
	if err != nil {
		return nil, true, "local-git-tag", "", err
	}
	if !exists {
		return nil, true, "local-git-tag", commit, fmt.Errorf("%w: %s:%s", ErrSDKFileNotFound, ref, filePath)
	}
	out, err = gitOutput(gitPath, repo, maxSDKSourceBytes, "show", ref+":"+filePath)
	if err != nil {
		return nil, true, "local-git-tag", commit, fmt.Errorf("sdktest: exact local tag %s does not provide %s: %w", tag, filePath, err)
	}
	return out, true, "local-git-tag", commit, nil
}

func readVerifiedVersionTreeFile(versionTree, filePath, tag string) ([]byte, string, error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, "", fmt.Errorf("sdktest: cannot prove exact local tree %s without git: %w", versionTree, err)
	}
	ref := "refs/tags/" + tag
	ids, err := gitOutput(gitPath, versionTree, 1024, "rev-parse", "HEAD", ref+"^{commit}")
	if err != nil {
		return nil, "", fmt.Errorf("sdktest: verify exact local tree %s at %s: %w", versionTree, tag, err)
	}
	lines := strings.Fields(string(ids))
	if len(lines) != 2 || lines[0] != lines[1] || !gitObjectID.MatchString(lines[0]) {
		return nil, "", fmt.Errorf("sdktest: exact local tree %s is not checked out at immutable tag %s (HEAD/tag=%q)", versionTree, tag, lines)
	}
	commit := strings.ToLower(lines[0])
	workingPath := filepath.Join(versionTree, filepath.FromSlash(filePath))
	working, err := readBoundedFile(workingPath)
	if err != nil {
		if os.IsNotExist(err) {
			exists, existsErr := gitPathExistsAtRef(gitPath, versionTree, ref, filePath)
			if existsErr != nil {
				return nil, "", existsErr
			}
			if !exists {
				return nil, commit, fmt.Errorf("%w: %s:%s", ErrSDKFileNotFound, ref, filePath)
			}
		}
		return nil, commit, fmt.Errorf("sdktest: read authoritative %s@%s from %s: %w", filePath, tag, versionTree, err)
	}
	tagged, err := gitOutput(gitPath, versionTree, maxSDKSourceBytes, "show", ref+":"+filePath)
	if err != nil {
		return nil, commit, fmt.Errorf("sdktest: read immutable blob %s:%s: %w", ref, filePath, err)
	}
	if !bytes.Equal(working, tagged) {
		return nil, commit, fmt.Errorf("sdktest: authoritative working-tree file %s@%s differs from immutable tag blob", filePath, tag)
	}
	return working, commit, nil
}

func gitExactTagCommit(gitPath, repo, ref string) (string, bool, error) {
	if _, err := gitOutput(gitPath, repo, 1024, "show-ref", "--verify", "--quiet", ref); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return "", false, nil
		}
		if _, statErr := os.Lstat(filepath.Join(repo, ".git")); os.IsNotExist(statErr) {
			// A version-root directory such as ~/dev/dartsdk-research is not
			// itself a checkout. Its <tag>/ children are handled above.
			return "", false, nil
		}
		return "", false, fmt.Errorf("sdktest: inspect exact local tag %s in %s: %w", ref, repo, err)
	}
	out, err := gitOutput(gitPath, repo, 1024, "rev-parse", "--verify", ref+"^{commit}")
	if err != nil {
		return "", false, fmt.Errorf("sdktest: peel exact local tag %s in %s: %w", ref, repo, err)
	}
	commit := strings.TrimSpace(string(out))
	if !gitObjectID.MatchString(commit) {
		return "", false, fmt.Errorf("sdktest: exact local tag %s returned malformed commit id %q", ref, commit)
	}
	return strings.ToLower(commit), true, nil
}

func gitPathExistsAtRef(gitPath, repo, ref, filePath string) (bool, error) {
	out, err := gitOutput(gitPath, repo, maxSDKPathBytes+2, "ls-tree", "--name-only", ref, "--", filePath)
	if err != nil {
		return false, fmt.Errorf("sdktest: inspect immutable path %s:%s: %w", ref, filePath, err)
	}
	name := strings.TrimSpace(string(out))
	if name == "" {
		return false, nil
	}
	if name != filePath {
		return false, fmt.Errorf("sdktest: git ls-tree returned unexpected path %q for %s:%s", name, ref, filePath)
	}
	return true, nil
}

func gitOutput(gitPath, repo string, maxBytes int64, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), localGitTimeout)
	defer cancel()
	cmdArgs := append([]string{"-C", repo}, args...)
	cmd := exec.CommandContext(ctx, gitPath, cmdArgs...)
	cmd.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1")
	return runBoundedCommand(cmd, maxBytes)
}

func fetchGitHubSDKFile(filePath, tag string) ([]byte, string, error) {
	commit, err := resolveGitHubTagCommit(tag)
	if err != nil {
		return nil, "", err
	}
	// Accept: raw asks the API for file bytes directly. The default JSON
	// response base64-encodes the content and truncates above 1 MB, which can
	// silently return an empty body for larger runtime headers.
	escapedParts := strings.Split(filePath, "/")
	for i := range escapedParts {
		escapedParts[i] = url.PathEscape(escapedParts[i])
	}
	endpoint := fmt.Sprintf("repos/dart-lang/sdk/contents/%s?ref=%s",
		strings.Join(escapedParts, "/"), url.QueryEscape(commit))
	out, err := ghAPI(endpoint, "application/vnd.github.raw", maxSDKSourceBytes)
	if err != nil {
		if strings.Contains(err.Error(), "HTTP 404") {
			return nil, commit, fmt.Errorf("%w: %s@%s (%s)", ErrSDKFileNotFound, filePath, tag, commit)
		}
		return nil, commit, fmt.Errorf("gh api %s@%s (%s): %w", filePath, tag, commit, err)
	}
	return out, commit, nil
}

type ghGitObject struct {
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	} `json:"object"`
}

func resolveGitHubTagCommit(tag string) (string, error) {
	endpoint := "repos/dart-lang/sdk/git/ref/tags/" + url.PathEscape(tag)
	out, err := ghAPI(endpoint, "application/vnd.github+json", maxCacheMetadataSize)
	if err != nil {
		return "", fmt.Errorf("sdktest: resolve immutable GitHub tag %s: %w", tag, err)
	}
	var ref ghGitObject
	if err := json.Unmarshal(out, &ref); err != nil {
		return "", fmt.Errorf("sdktest: malformed GitHub tag response for %s: %w", tag, err)
	}
	for depth := 0; depth < 4; depth++ {
		if !gitObjectID.MatchString(ref.Object.SHA) {
			return "", fmt.Errorf("sdktest: malformed GitHub object id %q for tag %s", ref.Object.SHA, tag)
		}
		switch ref.Object.Type {
		case "commit":
			return strings.ToLower(ref.Object.SHA), nil
		case "tag":
			out, err = ghAPI("repos/dart-lang/sdk/git/tags/"+ref.Object.SHA, "application/vnd.github+json", maxCacheMetadataSize)
			if err != nil {
				return "", fmt.Errorf("sdktest: resolve annotated GitHub tag %s: %w", tag, err)
			}
			if err := json.Unmarshal(out, &ref); err != nil {
				return "", fmt.Errorf("sdktest: malformed annotated GitHub tag response for %s: %w", tag, err)
			}
		default:
			return "", fmt.Errorf("sdktest: GitHub tag %s resolves to unsupported object type %q", tag, ref.Object.Type)
		}
	}
	return "", fmt.Errorf("sdktest: annotated GitHub tag %s exceeds dereference depth", tag)
}

func ghAPI(endpoint, accept string, maxBytes int64) ([]byte, error) {

	var lastErr error
	attempts := 0
	for attempt := 1; attempt <= ghAttempts; attempt++ {
		attempts = attempt
		ctx, cancel := context.WithTimeout(context.Background(), ghTimeout)
		cmd := exec.CommandContext(ctx, "gh", "api",
			"-H", "Accept: "+accept,
			endpoint)
		out, err := runBoundedCommand(cmd, maxBytes)
		cancel()
		if err == nil {
			return out, nil
		}
		lastErr = err
		if !retryableGHError(err) {
			break
		}
		if attempt < ghAttempts {
			time.Sleep(time.Duration(attempt) * 250 * time.Millisecond)
		}
	}
	return nil, fmt.Errorf("gh api %s after %d attempt(s): %w", endpoint, attempts, lastErr)
}

func retryableGHError(err error) bool {
	if err == nil || errors.Is(err, exec.ErrNotFound) {
		return false
	}
	msg := err.Error()
	// 408 and 429 can be transient. Other 4xx responses describe a bad
	// request/ref/auth state; retrying them only multiplies latency and cannot
	// make a verifier more correct.
	if strings.Contains(msg, "HTTP 4") &&
		!strings.Contains(msg, "HTTP 408") &&
		!strings.Contains(msg, "HTTP 429") {
		return false
	}
	return true
}

func runBoundedCommand(cmd *exec.Cmd, maxBytes int64) ([]byte, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr := &boundedBuffer{max: maxCommandStderr}
	cmd.Stderr = stderr
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

type boundedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.max - b.buf.Len()
	if remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		_, _ = b.buf.Write(p[:remaining])
	}
	if remaining < len(p) {
		b.truncated = true
	}
	return n, nil
}

func (b *boundedBuffer) String() string {
	s := b.buf.String()
	if b.truncated {
		s += "\n[stderr truncated]"
	}
	return s
}

func remember(key, value string) {
	memMu.Lock()
	defer memMu.Unlock()
	if len(value) > maxMemCacheBytes {
		return
	}
	if old, ok := memCache[key]; ok {
		memCacheBytes -= len(old)
	}
	if len(memCache) >= maxMemCacheEntries || memCacheBytes+len(value) > maxMemCacheBytes {
		memCache = make(map[string]string, maxMemCacheEntries)
		memCacheBytes = 0
	}
	memCache[key] = value
	memCacheBytes += len(value)
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
		return nil, fmt.Errorf("SDK source %s exceeds %d bytes", filePath, maxSDKSourceBytes)
	}
	return b, nil
}

func readCacheEntry(cacheDir, cacheRel, sdkPath, tag string) ([]byte, error) {
	root, err := openCacheRoot(cacheDir, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	if err := rejectRootSymlinkComponents(root, cacheRel); err != nil {
		return nil, err
	}
	entry, err := readBoundedRootFile(root, cacheRel, maxSDKSourceBytes+maxCacheMetadataSize+int64(len(cacheEnvelopeMagic))+1)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(entry, []byte(cacheEnvelopeMagic)) {
		return nil, fmt.Errorf("sdktest: cache entry %s has no provenance metadata envelope", filepath.Join(cacheDir, cacheRel))
	}
	rest := entry[len(cacheEnvelopeMagic):]
	newline := bytes.IndexByte(rest, '\n')
	if newline < 0 || newline > maxCacheMetadataSize {
		return nil, fmt.Errorf("sdktest: cache entry %s has malformed provenance metadata envelope", filepath.Join(cacheDir, cacheRel))
	}
	metaBytes := rest[:newline]
	data := rest[newline+1:]
	if len(data) > maxSDKSourceBytes {
		return nil, fmt.Errorf("sdktest: cache SDK source exceeds %d bytes", maxSDKSourceBytes)
	}
	var meta cacheMetadata
	dec := json.NewDecoder(bytes.NewReader(metaBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&meta); err != nil {
		return nil, fmt.Errorf("sdktest: decode cache metadata: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("sdktest: cache metadata has trailing JSON value")
		}
		return nil, fmt.Errorf("sdktest: cache metadata has trailing data: %w", err)
	}
	if meta.Version != cacheMetadataVersion || meta.Tag != tag || meta.Path != sdkPath || meta.Source == "" || !gitObjectID.MatchString(meta.Commit) {
		return nil, fmt.Errorf("sdktest: cache provenance mismatch for %s@%s", sdkPath, tag)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, meta.SHA256) {
		return nil, fmt.Errorf("sdktest: cache digest mismatch for %s@%s", sdkPath, tag)
	}
	return data, nil
}

func readBoundedRootFile(root *os.Root, filePath string, maxBytes int64) ([]byte, error) {
	f, err := root.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("file %s exceeds %d-byte limit", filePath, maxBytes)
	}
	return b, nil
}

func writeCacheEntryAtomic(cacheDir, cacheRel, sdkPath, tag, source, commit string, data []byte) error {
	if len(data) > maxSDKSourceBytes {
		return fmt.Errorf("SDK source exceeds %d bytes", maxSDKSourceBytes)
	}
	if !gitObjectID.MatchString(commit) {
		return fmt.Errorf("sdktest: refusing cache entry with malformed immutable commit id %q", commit)
	}
	sum := sha256.Sum256(data)
	meta, err := json.Marshal(cacheMetadata{
		Version: cacheMetadataVersion,
		Tag:     tag,
		Path:    sdkPath,
		SHA256:  hex.EncodeToString(sum[:]),
		Source:  source,
		Commit:  strings.ToLower(commit),
	})
	if err != nil {
		return err
	}
	if len(meta) > maxCacheMetadataSize {
		return fmt.Errorf("sdktest: cache provenance metadata exceeds %d bytes", maxCacheMetadataSize)
	}
	entry := make([]byte, 0, len(cacheEnvelopeMagic)+len(meta)+1+len(data))
	entry = append(entry, cacheEnvelopeMagic...)
	entry = append(entry, meta...)
	entry = append(entry, '\n')
	entry = append(entry, data...)
	return writeRootFileAtomic(cacheDir, cacheRel, entry)
}

func openCacheRoot(cacheDir string, create bool) (*os.Root, error) {
	if create {
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return nil, err
		}
	}
	st, err := os.Lstat(cacheDir)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("sdktest: cache root %q is a symlink", cacheDir)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("sdktest: cache root %q is not a directory", cacheDir)
	}
	root, err := os.OpenRoot(cacheDir)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	if !os.SameFile(st, opened) {
		_ = root.Close()
		return nil, fmt.Errorf("sdktest: cache root %q changed while opening it", cacheDir)
	}
	return root, nil
}

func rejectRootSymlinkComponents(root *os.Root, rel string) error {
	cur := "."
	parts := strings.Split(filepath.Clean(rel), string(filepath.Separator))
	for i, part := range parts {
		cur = filepath.Join(cur, part)
		st, err := root.Lstat(cur)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("sdktest: inspect rooted cache path %q: %w", cur, err)
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("sdktest: rooted cache path component %q is a symlink", cur)
		}
		if i < len(parts)-1 && !st.IsDir() {
			return fmt.Errorf("sdktest: rooted cache path component %q is not a directory", cur)
		}
	}
	return nil
}

func writeRootFileAtomic(cacheDir, cacheRel string, data []byte) error {
	root, err := openCacheRoot(cacheDir, true)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	dir := filepath.Dir(cacheRel)
	if err := root.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := rejectRootSymlinkComponents(root, dir); err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return err
	}
	tmpRel := filepath.Join(dir, ".sdk-cache-"+hex.EncodeToString(nonce[:]))
	tmp, err := root.OpenFile(tmpRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = root.Remove(tmpRel)
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := rejectRootSymlinkComponents(root, dir); err != nil {
		return err
	}
	return root.Rename(tmpRel, cacheRel)
}
