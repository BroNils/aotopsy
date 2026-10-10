package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testApplySHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func writeApplySentinel(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadApplyResultRequiresConsistentCompletionHandshake(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "one.c"), []byte("ok"), 0o600); err != nil {
			t.Fatal(err)
		}
		writeApplySentinel(t, dir, ApplyOKFileName, `{"functions":3,"decompiled":1,"failed":1,"focus":2,"binary_sha256":"`+testApplySHA+`"}`)
		got, err := ReadApplyResult(dir)
		if err != nil {
			t.Fatalf("ReadApplyResult: %v", err)
		}
		if got.Decompiled != 1 || got.Failed != 1 || got.Focus != 2 {
			t.Fatalf("result = %+v", got)
		}
	})

	for _, tc := range []struct {
		name string
		ok   string
		file bool
		want string
	}{
		{name: "missing sentinel", want: "did not write completion sentinel"},
		{name: "logical count mismatch", ok: `{"functions":3,"decompiled":1,"failed":0,"focus":2,"binary_sha256":"` + testApplySHA + `"}`, file: true, want: "completion count mismatch"},
		{name: "all focus failed", ok: `{"functions":3,"decompiled":0,"failed":2,"focus":2,"binary_sha256":"` + testApplySHA + `"}`, want: "without decompiling any"},
		{name: "file count mismatch", ok: `{"functions":3,"decompiled":1,"failed":0,"focus":1,"binary_sha256":"` + testApplySHA + `"}`, want: "output count mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.file {
				if err := os.WriteFile(filepath.Join(dir, "one.c"), []byte("ok"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.ok != "" {
				writeApplySentinel(t, dir, ApplyOKFileName, tc.ok)
			}
			if _, err := ReadApplyResult(dir); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ReadApplyResult error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestReadApplyResultFailureSentinelWins(t *testing.T) {
	dir := t.TempDir()
	writeApplySentinel(t, dir, ApplyOKFileName, `{"functions":0,"decompiled":0,"failed":0,"focus":0,"binary_sha256":"`+testApplySHA+`"}`)
	writeApplySentinel(t, dir, ApplyFailedFileName, `{"error":"no Hex-Rays"}`)
	if _, err := ReadApplyResult(dir); err == nil || !strings.Contains(err.Error(), "no Hex-Rays") {
		t.Fatalf("ReadApplyResult error = %v, want failure sentinel message", err)
	}
}
