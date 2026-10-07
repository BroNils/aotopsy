package sdktest

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// The GitHub-fallback tests need a `gh` executable on PATH whose behaviour they
// control. A shell script cannot be that executable on Windows (no shebang, no
// sh), so the test binary itself plays `gh`: installFakeGH copies it to
// <dir>/gh[.exe], and TestMain turns that copy into the fake when
// fakeGHModeEnv is set. Same code path on every OS.
const fakeGHModeEnv = "AOTOPSY_FAKE_GH_MODE"

const (
	fakeGHOffline   = "offline"   // records that it was called, fails
	fakeGHExact     = "exact"     // annotated tag -> commit -> raw content, logs its argv
	fakeGHRetry     = "retry"     // content fetch fails twice, then succeeds
	fakeGHNotFound  = "notfound"  // always HTTP 404
	fakeGHMalformed = "malformed" // tag resolves to a malformed object id
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(fakeGHModeEnv); mode != "" {
		os.Exit(runFakeGH(mode, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// installFakeGH installs the fake in a fresh directory, makes it the only
// thing on PATH, and returns nothing: the tests read what they need from the
// files named by the env vars they set.
func installFakeGH(t *testing.T, mode string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	name := "gh"
	if runtime.GOOS == "windows" {
		name = "gh.exe"
	}
	binDir := t.TempDir()
	dst := filepath.Join(binDir, name)
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv(fakeGHModeEnv, mode)
}

func runFakeGH(mode string, args []string) int {
	argv := strings.Join(args, " ")
	reply := func(s string) int { fmt.Print(s); return 0 }
	fail := func(code int, s string) int { fmt.Fprint(os.Stderr, s); return code }
	mark := func(envName string) {
		if p := os.Getenv(envName); p != "" {
			_ = os.WriteFile(p, []byte("called"), 0o644)
		}
	}

	switch mode {
	case fakeGHOffline:
		mark("AOTOPSY_GH_MARKER")
		return 99

	case fakeGHExact:
		if p := os.Getenv("AOTOPSY_GH_ARGS"); p != "" {
			f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err == nil {
				fmt.Fprintln(f, argv)
				f.Close()
			}
		}
		switch {
		case strings.Contains(argv, "repos/dart-lang/sdk/git/ref/tags/9.9.9"):
			return reply(`{"object":{"type":"tag","sha":"cccccccccccccccccccccccccccccccccccccccc"}}`)
		case strings.Contains(argv, "repos/dart-lang/sdk/git/tags/cccccccccccccccccccccccccccccccccccccccc"):
			return reply(`{"object":{"type":"commit","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`)
		case strings.Contains(argv, "repos/dart-lang/sdk/contents/runtime/vm/thread.h?ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"):
			return reply("exact gh bytes\n")
		}
		return fail(2, "unexpected gh call: "+argv+"\n")

	case fakeGHRetry:
		if strings.Contains(argv, "repos/dart-lang/sdk/git/ref/tags/9.9.9") {
			return reply(`{"object":{"type":"commit","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}`)
		}
		if n := bumpFakeGHCounter(); n < 3 {
			return fail(1, "temporary failure")
		}
		return reply("eventual success")

	case fakeGHNotFound:
		bumpFakeGHCounter()
		return fail(1, "gh: Not Found (HTTP 404)")

	case fakeGHMalformed:
		if strings.Contains(argv, "repos/dart-lang/sdk/git/ref/tags/9.9.9") {
			return reply(`{"object":{"type":"commit","sha":"not-an-object-id"}}`)
		}
		mark("AOTOPSY_GH_MARKER")
		return fail(2, "unexpected content fetch")
	}
	return fail(3, "unknown fake gh mode "+mode+"\n")
}

// bumpFakeGHCounter increments the attempt counter kept in the file named by
// AOTOPSY_GH_STATE and returns the new value.
func bumpFakeGHCounter() int {
	p := os.Getenv("AOTOPSY_GH_STATE")
	n := 0
	if b, err := os.ReadFile(p); err == nil {
		n, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	n++
	_ = os.WriteFile(p, []byte(strconv.Itoa(n)), 0o644)
	return n
}
