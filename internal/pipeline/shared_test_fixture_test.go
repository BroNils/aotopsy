package pipeline

import (
	"os"
	"sync"
	"testing"
)

// sharedPipelineOnce ensures the full pipeline Run() is executed only once
// per `go test` invocation for the ARM64 sample, no matter how many tests
// need its output. Each Run() takes ~90s on the 3.9.2 ARM64 sample, and
// running 14 of them serially exceeds any reasonable test timeout.
//
// Tests that need pipeline output should call sharedPipelineOutDir(t)
// instead of calling Run() directly.
var (
	sharedPipelineOnce  sync.Once
	sharedPipelineDir   string
	sharedPipelineFatal error
)

// sharedPipelineOutDir returns the output directory of a single shared
// pipeline Run() on AOTOPSY_TEST_SAMPLE_ARM64. The first caller pays the
// ~90s cost; subsequent callers get the cached directory instantly.
//
// If the env var is not set, the test is skipped. If Run() fails, the
// error is cached and all subsequent callers get the same fatal error.
func sharedPipelineOutDir(t *testing.T) string {
	t.Helper()
	libPath := os.Getenv("AOTOPSY_TEST_SAMPLE_ARM64")
	if libPath == "" {
		t.Skip("AOTOPSY_TEST_SAMPLE_ARM64 not set")
	}
	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		t.Skipf("sample binary not found at %s", libPath)
	}
	sharedPipelineOnce.Do(func() {
		outDir, err := os.MkdirTemp("", "aotopsy-shared-pipeline-*")
		if err != nil {
			sharedPipelineFatal = err
			return
		}
		_, err = Run(Opts{
			LibPath:  libPath,
			OutDir:   outDir,
			Signal:   true,
			Quiet:    true,
			MaxSteps: 100000,
		})
		if err != nil {
			sharedPipelineFatal = err
			return
		}
		sharedPipelineDir = outDir
	})
	if sharedPipelineFatal != nil {
		t.Fatalf("shared pipeline failed: %v", sharedPipelineFatal)
	}
	return sharedPipelineDir
}
