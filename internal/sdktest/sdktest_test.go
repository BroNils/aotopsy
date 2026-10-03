package sdktest

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func resetMemCache() {
	memMu.Lock()
	memCache = map[string]string{}
	memCacheBytes = 0
	memMu.Unlock()
}

func TestMemoryCacheHasByteBudget(t *testing.T) {
	resetMemCache()
	chunk := strings.Repeat("x", maxMemCacheBytes/2+1)
	remember("first", chunk)
	remember("second", chunk)
	memMu.Lock()
	defer memMu.Unlock()
	if memCacheBytes > maxMemCacheBytes {
		t.Fatalf("memory cache retained %d bytes, limit %d", memCacheBytes, maxMemCacheBytes)
	}
	if len(memCache) != 1 || memCache["second"] != chunk {
		t.Fatalf("memory cache budget did not evict/reset atomically; entries=%d bytes=%d", len(memCache), memCacheBytes)
	}
}

func writeCacheFixture(t *testing.T, dir, sdkPath, tag, body string) string {
	t.Helper()
	rel := filepath.Join(tag, filepath.FromSlash(sdkPath))
	full := filepath.Join(dir, rel)
	if err := writeCacheEntryAtomic(dir, rel, sdkPath, tag, "test-fixture", strings.Repeat("a", 40), []byte(body)); err != nil {
		t.Fatal(err)
	}
	return full
}

func initTaggedRepo(t *testing.T, repo, tag, sdkPath, body string) string {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git unavailable")
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(git, append([]string{"-C", repo}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "sdk-test@example.invalid")
	run("config", "user.name", "SDK Test")
	full := filepath.Join(repo, filepath.FromSlash(sdkPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", sdkPath)
	run("commit", "-q", "-m", "fixture")
	run("tag", tag)
	return git
}

// SDKFileAtTag must refuse a floating ref. Reading main gives the future,
// not the version a table was derived from, and the resulting "no drift"
// is meaningless.
func TestSDKFileAtTagRefusesFloatingRef(t *testing.T) {
	for _, ref := range []string{"", "main", "master", "HEAD", "refs/heads/main", "3.12", "v3.12.2"} {
		if _, err := SDKFileAtTag("runtime/vm/thread.h", ref); err == nil {
			t.Errorf("SDKFileAtTag(..., %q) succeeded, want refusal", ref)
		}
	}
}

func TestSDKFileAtTagRejectsCacheTraversal(t *testing.T) {
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", t.TempDir())
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	for _, p := range []string{
		"../secret", "runtime/../secret", "/absolute", `runtime\vm\thread.h`,
		"runtime/vm/thread.h?x=1", "runtime/vm/thread.h:evil", "runtime/vm/thread.h\x00evil",
		"runtime/vm/thread.h\nnext",
	} {
		if _, err := SDKFileAtTag(p, "3.12.2"); err == nil {
			t.Errorf("SDKFileAtTag(%q) accepted unsafe path", p)
		}
	}
	if _, err := SDKFileAtTag(strings.Repeat("a", maxSDKPathBytes+1), "3.12.2"); err == nil {
		t.Error("overlong SDK path was accepted")
	}
	if _, err := SDKFileAtTag("runtime/vm/thread.h", "3."+strings.Repeat("1", maxSDKTagBytes)); err == nil {
		t.Error("overlong SDK tag was accepted")
	}
}

// A cached file must be served without invoking gh at all, which is what
// makes a full gate sweep survive the API rate limit.
func TestSDKFileAtTagUsesDiskCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", dir)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	t.Setenv("PATH", "") // no gh reachable: a fetch would fail loudly

	const path, tag, body = "runtime/vm/thread.h", "9.9.9", "cached contents\n"
	writeCacheFixture(t, dir, path, tag, body)
	resetMemCache()

	got, err := SDKFileAtTag(path, tag)
	if err != nil {
		t.Fatalf("cached read: %v", err)
	}
	if got != body {
		t.Errorf("got %q, want %q", got, body)
	}
}

func TestSDKFileAtTagPrefersExactLocalRepoOverStaleCache(t *testing.T) {
	repo := t.TempDir()
	const sdkPath, tag = "runtime/vm/thread.h", "9.9.9"
	initTaggedRepo(t, repo, tag, sdkPath, "local exact-tag source\n")

	cacheDir := t.TempDir()
	writeCacheFixture(t, cacheDir, sdkPath, tag, "stale cached source\n")

	t.Setenv("AOTOPSY_DART_SDK_REPO", repo)
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", cacheDir)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	resetMemCache()

	got, err := SDKFileAtTag(sdkPath, tag)
	if err != nil {
		t.Fatalf("SDKFileAtTag: %v", err)
	}
	if got != "local exact-tag source\n" {
		t.Fatalf("got %q, want exact local repo contents", got)
	}
	refreshed, err := readCacheEntry(cacheDir, filepath.Join(tag, filepath.FromSlash(sdkPath)), sdkPath, tag)
	if err != nil {
		t.Fatal(err)
	}
	if string(refreshed) != got {
		t.Fatalf("cache was not refreshed from local ground truth: got %q", refreshed)
	}
}

func TestSDKFileAtTagReadsProvableExactVersionWorkingTree(t *testing.T) {
	root := t.TempDir()
	cacheDir := t.TempDir()
	const sdkPath, tag, body = "runtime/vm/thread.h", "3.12.2", "exact version working tree\n"
	versionTree := filepath.Join(root, tag)
	if err := os.MkdirAll(versionTree, 0o755); err != nil {
		t.Fatal(err)
	}
	initTaggedRepo(t, versionTree, tag, sdkPath, body)

	t.Setenv("AOTOPSY_DART_SDK_REPO", root)
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", cacheDir)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	resetMemCache()

	got, err := SDKFileAtTag(sdkPath, tag)
	if err != nil {
		t.Fatalf("SDKFileAtTag: %v", err)
	}
	if got != body {
		t.Fatalf("got %q, want exact working-tree source %q", got, body)
	}
}

func TestExplicitSDKRepoOverridesDefaultDiscovery(t *testing.T) {
	repo := t.TempDir()
	t.Setenv("AOTOPSY_DART_SDK_REPO", repo)
	got, err := localSDKRepos()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != filepath.Clean(repo) {
		t.Fatalf("localSDKRepos() = %q, want only explicit repo %q", got, repo)
	}
}

func TestSDKSourceAndCacheOverridesMustBeAbsolute(t *testing.T) {
	t.Setenv("AOTOPSY_DART_SDK_REPO", "relative-sdk")
	if _, err := localSDKRepos(); err == nil {
		t.Fatal("relative SDK source root accepted")
	}
	t.Setenv("AOTOPSY_DART_SDK_REPO", "")
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", "relative-cache")
	if _, err := SDKFileAtTag("runtime/vm/thread.h", "3.12.2"); err == nil {
		t.Fatal("relative SDK cache root accepted")
	}
}

func TestSDKFileAtTagOfflineMissFails(t *testing.T) {
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", t.TempDir())
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	resetMemCache()
	if _, err := SDKFileAtTag("runtime/vm/nothing_here.h", "9.9.9"); err == nil {
		t.Error("offline cache miss must fail; a silent empty result reads as no drift")
	}
}

func TestMemoryCacheIncludesCacheConfiguration(t *testing.T) {
	const path, tag = "runtime/vm/thread.h", "9.9.9"
	memMu.Lock()
	memCache = map[string]string{}
	memMu.Unlock()
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")

	dir1 := t.TempDir()
	dir2 := t.TempDir()
	write := func(dir, body string) {
		t.Helper()
		writeCacheFixture(t, dir, path, tag, body)
	}
	write(dir1, "one")
	write(dir2, "two")

	t.Setenv("AOTOPSY_SDK_CACHE_DIR", dir1)
	if got, err := SDKFileAtTag(path, tag); err != nil || got != "one" {
		t.Fatalf("cache one: got %q err %v", got, err)
	}
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", dir2)
	if got, err := SDKFileAtTag(path, tag); err != nil || got != "two" {
		t.Fatalf("cache two: got %q err %v (memory cache ignored source configuration)", got, err)
	}
}

func TestCachedSDKSourceIsSizeBounded(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", dir)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	const path, tag = "runtime/vm/thread.h", "9.9.9"
	full := filepath.Join(dir, tag, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(full)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxSDKSourceBytes + 1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	memMu.Lock()
	memCache = map[string]string{}
	memMu.Unlock()
	if _, err := SDKFileAtTag(path, tag); err == nil {
		t.Fatal("oversized cached SDK source was accepted")
	}
}

func TestUnprovenLegacyCacheEntryIsRejected(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", dir)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	const sdkPath, tag = "runtime/vm/thread.h", "9.9.9"
	rel := filepath.Join(tag, filepath.FromSlash(sdkPath))
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("unproven stale bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	resetMemCache()
	if _, err := SDKFileAtTag(sdkPath, tag); err == nil || !strings.Contains(err.Error(), "no provenance metadata") {
		t.Fatalf("legacy cache entry result = %v, want provenance refusal", err)
	}
}

func TestExactVersionTreeMismatchCannotFallBackToStaleCache(t *testing.T) {
	root, tag := t.TempDir(), "3.12.2"
	const sdkPath = "runtime/vm/thread.h"
	versionTree := filepath.Join(root, tag)
	if err := os.MkdirAll(versionTree, 0o755); err != nil {
		t.Fatal(err)
	}
	initTaggedRepo(t, versionTree, tag, sdkPath, "tagged source\n")
	full := filepath.Join(versionTree, filepath.FromSlash(sdkPath))
	if err := os.WriteFile(full, []byte("dirty source\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cacheDir := t.TempDir()
	writeCacheFixture(t, cacheDir, sdkPath, tag, "stale cached source\n")
	t.Setenv("AOTOPSY_DART_SDK_REPO", root)
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", cacheDir)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	resetMemCache()
	if _, err := SDKFileAtTag(sdkPath, tag); err == nil || !strings.Contains(err.Error(), "differs from immutable tag blob") {
		t.Fatalf("dirty authoritative source result = %v, want fail-closed identity error", err)
	}
}

func TestExactVersionTreeWrongHEADCannotFallBackToStaleCache(t *testing.T) {
	root, tag := t.TempDir(), "3.12.2"
	const sdkPath = "runtime/vm/thread.h"
	versionTree := filepath.Join(root, tag)
	if err := os.MkdirAll(versionTree, 0o755); err != nil {
		t.Fatal(err)
	}
	git := initTaggedRepo(t, versionTree, tag, sdkPath, "tagged source\n")
	if err := os.WriteFile(filepath.Join(versionTree, "extra.txt"), []byte("later commit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "extra.txt"}, {"commit", "-q", "-m", "move HEAD past release"}} {
		cmd := exec.Command(git, append([]string{"-C", versionTree}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	cacheDir := t.TempDir()
	writeCacheFixture(t, cacheDir, sdkPath, tag, "stale cached source\n")
	t.Setenv("AOTOPSY_DART_SDK_REPO", root)
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", cacheDir)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	resetMemCache()
	if got, err := SDKFileAtTag(sdkPath, tag); err == nil || !strings.Contains(err.Error(), "not checked out at immutable tag") {
		t.Fatalf("wrong-HEAD authoritative tree result = %q, %v", got, err)
	}
}

func TestExactVersionTreeMissingFileCannotFallBackToStaleCache(t *testing.T) {
	root, tag := t.TempDir(), "3.12.2"
	const committedPath = "runtime/vm/present.h"
	const requestedPath = "runtime/vm/missing.h"
	versionTree := filepath.Join(root, tag)
	if err := os.MkdirAll(versionTree, 0o755); err != nil {
		t.Fatal(err)
	}
	initTaggedRepo(t, versionTree, tag, committedPath, "present\n")
	cacheDir := t.TempDir()
	writeCacheFixture(t, cacheDir, requestedPath, tag, "wrong cached fallback\n")
	t.Setenv("AOTOPSY_DART_SDK_REPO", root)
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", cacheDir)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	resetMemCache()
	if got, err := SDKFileAtTag(requestedPath, tag); err == nil {
		t.Fatalf("missing authoritative file fell through to cache: %q", got)
	} else if !errors.Is(err, ErrSDKFileNotFound) {
		t.Fatalf("missing authoritative file error = %v, want ErrSDKFileNotFound", err)
	}
}

func TestSDKFileAtTagAnyOnlyFallsThroughExactNotFound(t *testing.T) {
	root, tag := t.TempDir(), "3.12.2"
	const presentPath = "runtime/vm/clustered_snapshot.cc"
	versionTree := filepath.Join(root, tag)
	if err := os.MkdirAll(versionTree, 0o755); err != nil {
		t.Fatal(err)
	}
	initTaggedRepo(t, versionTree, tag, presentPath, "historical source\n")
	t.Setenv("AOTOPSY_DART_SDK_REPO", root)
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", t.TempDir())
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	resetMemCache()

	got, err := SDKFileAtTagAny(tag, "runtime/vm/app_snapshot.cc", presentPath)
	if err != nil || got != "historical source\n" {
		t.Fatalf("historical fallback = %q, %v", got, err)
	}

	full := filepath.Join(versionTree, filepath.FromSlash(presentPath))
	if err := os.WriteFile(full, []byte("dirty working source\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resetMemCache()
	if _, err := SDKFileAtTagAny(tag, presentPath, "runtime/vm/other.cc"); err == nil || !strings.Contains(err.Error(), "differs from immutable tag blob") {
		t.Fatalf("integrity error was hidden by alternate path: %v", err)
	}
}

func TestBareVersionBranchDoesNotMasqueradeAsReleaseTag(t *testing.T) {
	repo := t.TempDir()
	const sdkPath, tag = "runtime/vm/thread.h", "9.9.9"
	git := initTaggedRepo(t, repo, "8.8.8", sdkPath, "branch-only source\n")
	cmd := exec.Command(git, "-C", repo, "branch", tag)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create branch: %v\n%s", err, out)
	}
	t.Setenv("AOTOPSY_DART_SDK_REPO", repo)
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", t.TempDir())
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	resetMemCache()
	if got, err := SDKFileAtTag(sdkPath, tag); err == nil {
		t.Fatalf("branch named like version was accepted as immutable tag: %q", got)
	}
}

func TestCorruptExplicitGitRepoCannotFallBackToCache(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, ".git"), []byte("not a gitdir\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cacheDir := t.TempDir()
	const sdkPath, tag = "runtime/vm/thread.h", "9.9.9"
	writeCacheFixture(t, cacheDir, sdkPath, tag, "stale cached source\n")
	t.Setenv("AOTOPSY_DART_SDK_REPO", repo)
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", cacheDir)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	resetMemCache()

	got, err := SDKFileAtTag(sdkPath, tag)
	if err == nil {
		t.Fatalf("corrupt explicit git repo fell through to stale cache: %q", got)
	}
	if !strings.Contains(err.Error(), "inspect exact local tag") {
		t.Fatalf("corrupt git repo error = %v, want fail-closed exact-tag inspection error", err)
	}
}

func TestOfflineModeNeverInvokesGH(t *testing.T) {
	binDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "gh-called")
	ghPath := filepath.Join(binDir, "gh")
	script := "#!/bin/sh\nprintf called > \"$AOTOPSY_GH_MARKER\"\nexit 99\n"
	if err := os.WriteFile(ghPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("AOTOPSY_GH_MARKER", marker)
	t.Setenv("AOTOPSY_DART_SDK_REPO", t.TempDir())
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", t.TempDir())
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	resetMemCache()
	if _, err := SDKFileAtTag("runtime/vm/thread.h", "9.9.9"); err == nil {
		t.Fatal("offline miss unexpectedly succeeded")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("offline resolution invoked gh; marker stat = %v", err)
	}
}

func TestGitHubFallbackUsesExactRefAndCachesForOfflineUse(t *testing.T) {
	binDir := t.TempDir()
	argsPath := filepath.Join(t.TempDir(), "gh-args")
	ghPath := filepath.Join(binDir, "gh")
	const body = "exact gh bytes\n"
	const commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const tagObject = "cccccccccccccccccccccccccccccccccccccccc"
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$AOTOPSY_GH_ARGS"
case "$*" in
  *"repos/dart-lang/sdk/git/ref/tags/9.9.9"*)
	printf '{"object":{"type":"tag","sha":"cccccccccccccccccccccccccccccccccccccccc"}}'
	;;
  *"repos/dart-lang/sdk/git/tags/cccccccccccccccccccccccccccccccccccccccc"*)
	printf '{"object":{"type":"commit","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}'
	;;
  *"repos/dart-lang/sdk/contents/runtime/vm/thread.h?ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"*)
    printf 'exact gh bytes\n'
    ;;
  *)
    printf 'unexpected gh call: %s\n' "$*" >&2
    exit 2
    ;;
esac
`
	if err := os.WriteFile(ghPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cacheDir := t.TempDir()
	t.Setenv("PATH", binDir)
	t.Setenv("AOTOPSY_GH_ARGS", argsPath)
	t.Setenv("AOTOPSY_DART_SDK_REPO", t.TempDir())
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", cacheDir)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "")
	resetMemCache()

	got, err := SDKFileAtTag("runtime/vm/thread.h", "9.9.9")
	if err != nil || got != body {
		t.Fatalf("gh fallback = %q, %v", got, err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	argText := string(args)
	if !strings.Contains(argText, "repos/dart-lang/sdk/git/ref/tags/9.9.9") ||
		!strings.Contains(argText, "repos/dart-lang/sdk/git/tags/"+tagObject) ||
		!strings.Contains(argText, "Accept: application/vnd.github.raw") ||
		!strings.Contains(argText, "repos/dart-lang/sdk/contents/runtime/vm/thread.h?ref="+commit) ||
		strings.Contains(argText, "contents/runtime/vm/thread.h?ref=9.9.9") {
		t.Fatalf("gh args did not resolve exact tag then bind raw fetch to immutable commit: %q", argText)
	}

	// A network result must become a provenance-bound cache entry that works
	// with network forbidden on the next process-equivalent read.
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	t.Setenv("PATH", "")
	resetMemCache()
	got, err = SDKFileAtTag("runtime/vm/thread.h", "9.9.9")
	if err != nil || got != body {
		t.Fatalf("offline read of gh-provenance cache = %q, %v", got, err)
	}
}

func TestGitHubFallbackRetriesBoundedAttempts(t *testing.T) {
	binDir := t.TempDir()
	state := filepath.Join(t.TempDir(), "attempts")
	ghPath := filepath.Join(binDir, "gh")
	script := `#!/bin/sh
case "$*" in
  *"repos/dart-lang/sdk/git/ref/tags/9.9.9"*)
    printf '{"object":{"type":"commit","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}'
    exit 0
    ;;
esac
n=0
if [ -f "$AOTOPSY_GH_STATE" ]; then read n < "$AOTOPSY_GH_STATE"; fi
n=$((n + 1))
printf '%s' "$n" > "$AOTOPSY_GH_STATE"
if [ "$n" -lt 3 ]; then printf 'temporary failure' >&2; exit 1; fi
printf 'eventual success'
`
	if err := os.WriteFile(ghPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("AOTOPSY_GH_STATE", state)
	t.Setenv("AOTOPSY_DART_SDK_REPO", t.TempDir())
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", t.TempDir())
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "")
	resetMemCache()
	got, err := SDKFileAtTag("runtime/vm/thread.h", "9.9.9")
	if err != nil || got != "eventual success" {
		t.Fatalf("retry result = %q, %v", got, err)
	}
	attempts, err := os.ReadFile(state)
	if err != nil || string(attempts) != "3" {
		t.Fatalf("gh attempts = %q, %v, want 3", attempts, err)
	}
}

func TestGHAPIDoesNotRetryPermanent404(t *testing.T) {
	binDir := t.TempDir()
	state := filepath.Join(t.TempDir(), "attempts")
	ghPath := filepath.Join(binDir, "gh")
	script := `#!/bin/sh
n=0
if [ -f "$AOTOPSY_GH_STATE" ]; then read n < "$AOTOPSY_GH_STATE"; fi
n=$((n + 1))
printf '%s' "$n" > "$AOTOPSY_GH_STATE"
printf 'gh: Not Found (HTTP 404)' >&2
exit 1
`
	if err := os.WriteFile(ghPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("AOTOPSY_GH_STATE", state)
	if _, err := ghAPI("repos/dart-lang/sdk/contents/missing", "application/vnd.github.raw", 1024); err == nil || !strings.Contains(err.Error(), "after 1 attempt(s)") {
		t.Fatalf("permanent 404 retry result = %v, want one-attempt failure", err)
	}
	b, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "1" {
		t.Fatalf("permanent 404 invoked gh %s times, want 1", b)
	}
}

func TestGitHubFallbackRejectsMalformedTagIdentity(t *testing.T) {
	binDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "content-called")
	ghPath := filepath.Join(binDir, "gh")
	script := `#!/bin/sh
case "$*" in
  *"repos/dart-lang/sdk/git/ref/tags/9.9.9"*)
    printf '{"object":{"type":"commit","sha":"not-an-object-id"}}'
    ;;
  *)
    printf called > "$AOTOPSY_GH_MARKER"
    printf 'unexpected content fetch' >&2
    exit 2
    ;;
esac
`
	if err := os.WriteFile(ghPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("AOTOPSY_GH_MARKER", marker)
	t.Setenv("AOTOPSY_DART_SDK_REPO", t.TempDir())
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", t.TempDir())
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "")
	resetMemCache()

	if _, err := SDKFileAtTag("runtime/vm/thread.h", "9.9.9"); err == nil || !strings.Contains(err.Error(), "malformed GitHub object id") {
		t.Fatalf("malformed tag identity result = %v, want refusal", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("malformed tag identity still reached content fetch; marker stat = %v", err)
	}
}

func TestCacheDigestTamperingIsRejected(t *testing.T) {
	dir := t.TempDir()
	const sdkPath, tag = "runtime/vm/thread.h", "9.9.9"
	full := writeCacheFixture(t, dir, sdkPath, tag, "trusted bytes\n")
	entry, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	entry[len(entry)-2] ^= 0x01
	if err := os.WriteFile(full, entry, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AOTOPSY_DART_SDK_REPO", t.TempDir())
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", dir)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	resetMemCache()
	if _, err := SDKFileAtTag(sdkPath, tag); err == nil || !strings.Contains(err.Error(), "cache digest mismatch") {
		t.Fatalf("tampered cache result = %v, want digest mismatch", err)
	}
}

func TestSymlinkedCacheComponentIsRejected(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("symlink creation requires platform-specific privileges on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "9.9.9")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	t.Setenv("AOTOPSY_DART_SDK_REPO", t.TempDir())
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", root)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	resetMemCache()
	if _, err := SDKFileAtTag("runtime/vm/thread.h", "9.9.9"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked cache component result = %v, want refusal", err)
	}
}

func TestCacheMetadataRejectsTrailingData(t *testing.T) {
	dir := t.TempDir()
	const sdkPath, tag = "runtime/vm/thread.h", "9.9.9"
	full := writeCacheFixture(t, dir, sdkPath, tag, "trusted bytes\n")
	entry, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	headerEnd := bytes.IndexByte(entry[len(cacheEnvelopeMagic):], '\n')
	if headerEnd < 0 {
		t.Fatal("cache fixture has no metadata delimiter")
	}
	headerEnd += len(cacheEnvelopeMagic)
	corrupt := append([]byte{}, entry[:headerEnd]...)
	corrupt = append(corrupt, []byte("{}")...)
	corrupt = append(corrupt, entry[headerEnd:]...)
	if err := os.WriteFile(full, corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AOTOPSY_DART_SDK_REPO", t.TempDir())
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", dir)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	resetMemCache()
	if _, err := SDKFileAtTag(sdkPath, tag); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("cache metadata trailing-data result = %v, want refusal", err)
	}
}

func TestCacheWritesAreAtomicUnderConcurrency(t *testing.T) {
	dir := t.TempDir()
	const sdkPath, tag = "runtime/vm/thread.h", "9.9.9"
	rel := filepath.Join(tag, filepath.FromSlash(sdkPath))
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		body := fmt.Sprintf("exact bytes from writer %02d\n", i)
		wg.Add(1)
		go func(body string) {
			defer wg.Done()
			errs <- writeCacheEntryAtomic(dir, rel, sdkPath, tag, "concurrency-fixture", strings.Repeat("b", 40), []byte(body))
		}(body)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := readCacheEntry(dir, rel, sdkPath, tag)
	if err != nil || !strings.HasPrefix(string(got), "exact bytes from writer ") {
		t.Fatalf("concurrent cache result = %q, %v; want one complete writer envelope", got, err)
	}
}

func TestBoundedBufferCapsSubprocessStderr(t *testing.T) {
	b := &boundedBuffer{max: 8}
	if _, err := b.Write([]byte("0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	if got := b.buf.Len(); got != 8 {
		t.Fatalf("bounded stderr retained %d bytes, want 8", got)
	}
	if !strings.Contains(b.String(), "truncated") {
		t.Fatalf("bounded stderr did not report truncation: %q", b.String())
	}
}
