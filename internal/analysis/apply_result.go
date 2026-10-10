package analysis

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	ApplyOKFileName     = ".aotopsy-apply-ok"
	ApplyFailedFileName = ".aotopsy-apply-failed"
)

// ApplyResult is the completion handshake written by the external Ghidra/IDA
// scripts. The sentinel is written only after every requested focus function
// has either produced a .c file or a recorded decompilation failure.
type ApplyResult struct {
	Functions    int    `json:"functions"`
	Decompiled   int    `json:"decompiled"`
	Failed       int    `json:"failed"`
	Focus        int    `json:"focus"`
	BinarySHA256 string `json:"binary_sha256"`
}

type applyFailure struct {
	Error string `json:"error"`
}

// ReadApplyResult requires an explicit successful completion sentinel and
// cross-checks its counts against the staged generation. A child process exit
// status is insufficient because both integration runtimes can finish with
// status 0 after a script-level failure.
func ReadApplyResult(stageDir string) (ApplyResult, error) {
	failedPath := filepath.Join(stageDir, ApplyFailedFileName)
	if _, err := os.Lstat(failedPath); err == nil {
		failure, decodeErr := readJSONBounded[applyFailure](failedPath, maxMetadataArtifactBytes)
		if decodeErr != nil {
			return ApplyResult{}, fmt.Errorf("apply failure sentinel is malformed: %w", decodeErr)
		}
		if strings.TrimSpace(failure.Error) == "" {
			return ApplyResult{}, fmt.Errorf("apply failure sentinel has empty error")
		}
		return ApplyResult{}, fmt.Errorf("apply script failed: %s", failure.Error)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ApplyResult{}, fmt.Errorf("inspect apply failure sentinel: %w", err)
	}

	result, err := readJSONBounded[ApplyResult](filepath.Join(stageDir, ApplyOKFileName), maxMetadataArtifactBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ApplyResult{}, fmt.Errorf("apply script did not write completion sentinel")
		}
		return ApplyResult{}, fmt.Errorf("read apply completion sentinel: %w", err)
	}
	if result.Functions < 0 || result.Focus < 0 || result.Decompiled < 0 || result.Failed < 0 {
		return ApplyResult{}, fmt.Errorf("apply completion sentinel contains negative counts")
	}
	if result.Focus > result.Functions {
		return ApplyResult{}, fmt.Errorf("apply completion count mismatch: focus=%d functions=%d", result.Focus, result.Functions)
	}
	if result.Failed > result.Focus || result.Decompiled > result.Focus || result.Decompiled != result.Focus-result.Failed {
		return ApplyResult{}, fmt.Errorf("apply completion count mismatch: decompiled=%d failed=%d focus=%d", result.Decompiled, result.Failed, result.Focus)
	}
	if result.Focus > 0 && result.Decompiled == 0 {
		return ApplyResult{}, fmt.Errorf("apply completed without decompiling any of %d focus functions", result.Focus)
	}
	if len(result.BinarySHA256) != 64 || result.BinarySHA256 != strings.ToLower(result.BinarySHA256) {
		return ApplyResult{}, fmt.Errorf("apply completion sentinel has invalid binary_sha256")
	}
	if _, err := hex.DecodeString(result.BinarySHA256); err != nil {
		return ApplyResult{}, fmt.Errorf("apply completion sentinel has invalid binary_sha256: %w", err)
	}

	actualC := 0
	if err := filepath.WalkDir(stageDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".c" {
			actualC++
		}
		return nil
	}); err != nil {
		return ApplyResult{}, fmt.Errorf("count staged decompiler outputs: %w", err)
	}
	if actualC != result.Decompiled {
		return ApplyResult{}, fmt.Errorf("apply output count mismatch: sentinel=%d staged_c_files=%d", result.Decompiled, actualC)
	}

	return result, nil
}
