// Package sdktest provides shared helpers for SDK drift gate tests.
//
// Each version-keyed table in this project (THR fields, base objects,
// ObjectStoreAOTFieldCount, FunctionKindLayouts, CID tables) cannot
// be validated by local testing: a wrong offset or wrong row produces
// a plausible-looking result that is simply wrong, and nothing
// downstream can tell. The only ground truth is the Dart SDK source
// the table was derived from.
//
// These helpers fetch files from dart-lang/sdk via the GitHub API
// (gh CLI), so tests using them are network-dependent and opt-in via
// the AOTOPSY_TEST_SDK environment variable.
package sdktest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// SkipIfNoSDK skips the calling test if AOTOPSY_TEST_SDK is not set or
// gh is not on PATH. Every SDK drift gate test should call this first.
func SkipIfNoSDK() bool {
	return os.Getenv("AOTOPSY_TEST_SDK") == ""
}

// HasGH reports whether the gh CLI is available on PATH.
func HasGH() bool {
	_, err := exec.LookPath("gh")
	return err == nil
}

// GHFileAtTag reads a file from dart-lang/sdk at a specific git tag
// via the GitHub API (gh api). Returns the raw file content as a string.
//
// Always use a tag (e.g. "3.12.2") — never "main" — because snapshot
// layout changes between versions and reading main gives you the
// future, not the version the table was derived from.
func GHFileAtTag(path, tag string) (string, error) {
	cmd := exec.Command("gh", "api",
		fmt.Sprintf("repos/dart-lang/sdk/contents/%s?ref=%s", path, tag))
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("gh api %s@%s: %w", path, tag, err)
	}
	var payload struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return "", fmt.Errorf("unmarshal gh response for %s@%s: %w", path, tag, err)
	}
	dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(payload.Content, "\n", ""))
	if err != nil {
		return "", fmt.Errorf("base64 decode %s@%s: %w", path, tag, err)
	}
	return string(dec), nil
}
