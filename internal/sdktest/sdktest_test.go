package sdktest

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

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
	for _, p := range []string{"../secret", "runtime/../secret", "/absolute", `runtime\vm\thread.h`, "runtime/vm/thread.h?x=1"} {
		if _, err := SDKFileAtTag(p, "3.12.2"); err == nil {
			t.Errorf("SDKFileAtTag(%q) accepted unsafe path", p)
		}
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
	full := filepath.Join(dir, tag, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	memMu.Lock()
	memCache = map[string]string{}
	memMu.Unlock()

	got, err := SDKFileAtTag(path, tag)
	if err != nil {
		t.Fatalf("cached read: %v", err)
	}
	if got != body {
		t.Errorf("got %q, want %q", got, body)
	}
}

func TestSDKFileAtTagPrefersExactLocalRepoOverStaleCache(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git unavailable")
	}

	repo := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command(git, append([]string{"-C", repo}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	runGit("init", "-q")
	runGit("config", "user.email", "sdk-test@example.invalid")
	runGit("config", "user.name", "SDK Test")

	const sdkPath, tag = "runtime/vm/thread.h", "9.9.9"
	full := filepath.Join(repo, filepath.FromSlash(sdkPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("local exact-tag source\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit("add", sdkPath)
	runGit("commit", "-q", "-m", "fixture")
	runGit("tag", tag)

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, tag, filepath.FromSlash(sdkPath))
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("stale cached source\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("AOTOPSY_DART_SDK_REPO", repo)
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", cacheDir)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	memMu.Lock()
	memCache = map[string]string{}
	memMu.Unlock()

	got, err := SDKFileAtTag(sdkPath, tag)
	if err != nil {
		t.Fatalf("SDKFileAtTag: %v", err)
	}
	if got != "local exact-tag source\n" {
		t.Fatalf("got %q, want exact local repo contents", got)
	}
	refreshed, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(refreshed) != got {
		t.Fatalf("cache was not refreshed from local ground truth: got %q", refreshed)
	}
}

func TestSDKFileAtTagReadsExactVersionWorkingTreeWithoutGitOrCache(t *testing.T) {
	root := t.TempDir()
	cacheDir := t.TempDir()
	const sdkPath, tag, body = "runtime/vm/thread.h", "3.12.2", "exact version working tree\n"
	full := filepath.Join(root, tag, filepath.FromSlash(sdkPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("AOTOPSY_DART_SDK_REPO", root)
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", cacheDir)
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	t.Setenv("PATH", "") // direct working-tree resolution must not require git or gh
	memMu.Lock()
	memCache = map[string]string{}
	memMu.Unlock()

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
	got := localSDKRepos()
	if len(got) != 1 || got[0] != filepath.Clean(repo) {
		t.Fatalf("localSDKRepos() = %q, want only explicit repo %q", got, repo)
	}
}

func TestSDKFileAtTagOfflineMissFails(t *testing.T) {
	t.Setenv("AOTOPSY_SDK_CACHE_DIR", t.TempDir())
	t.Setenv("AOTOPSY_TEST_SDK_OFFLINE", "1")
	memMu.Lock()
	memCache = map[string]string{}
	memMu.Unlock()
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
		full := filepath.Join(dir, tag, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
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
