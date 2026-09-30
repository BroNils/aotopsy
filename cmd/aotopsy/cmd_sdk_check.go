package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"aotopsy/internal/cli"
)

// cmdSDKCheck runs all SDK verification gates (THR, ObjectStore, stubs, roots)
// in one command. It wraps the existing tools/extract_thr.go -check* flags
// into a user-friendly CLI command.
//
// Usage:
//
//	aotopsy sdk-check              # run all checks
//	aotopsy sdk-check --thr        # THR field tables only
//	aotopsy sdk-check --objectstore # ObjectStore field count only
//	aotopsy sdk-check --stubs      # VM stub names only
//	aotopsy sdk-check --roots      # Roots prefix count only
func cmdSDKCheck(args []string) error {
	fs := flag.NewFlagSet("sdk-check", flag.ExitOnError)
	thrOnly := fs.Bool("thr", false, "check THR field tables only")
	objectStoreOnly := fs.Bool("objectstore", false, "check ObjectStore field count only")
	stubsOnly := fs.Bool("stubs", false, "check VM stub names only")
	rootsOnly := fs.Bool("roots", false, "check roots prefix count only")
	classIDOnly := fs.Bool("classid-tag", false, "check versioned object-header class-id layout only")
	runtimeEntriesOnly := fs.Bool("runtime-entries", false, "check runtime-entry THR naming coverage only")
	stubOffsetsOnly := fs.Bool("stub-offsets", false, "check Thread-cached stub offsets only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("sdk-check does not accept positional arguments")
	}

	all := !*thrOnly && !*objectStoreOnly && !*stubsOnly && !*rootsOnly && !*classIDOnly && !*runtimeEntriesOnly && !*stubOffsetsOnly
	failed := false
	root, err := sdkCheckSourceRoot()
	if err != nil {
		return err
	}
	tool := filepath.Join(root, "tools", "extract_thr.go")

	runCheck := func(name, checkFlag string) {
		cli.Errf("=== %s ===\n", name)
		cmd := exec.Command("go", "run", tool, checkFlag)
		cmd.Dir = root
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			cli.Errf("FAIL: %s\n", name)
			failed = true
		} else {
			cli.Errf("PASS: %s\n\n", name)
		}
	}

	if all || *thrOnly {
		runCheck("THR field tables", "-check")
	}
	if all || *objectStoreOnly {
		runCheck("ObjectStore field count", "-check-objectstore")
	}
	if all || *stubsOnly {
		runCheck("VM stub names", "-check-stubs")
	}
	if all || *rootsOnly {
		runCheck("Roots prefix count", "-check-roots")
	}
	if all || *classIDOnly {
		runCheck("ClassIdTag layout", "-check-classid-tag")
	}
	if all || *runtimeEntriesOnly {
		runCheck("Runtime entry coverage", "-check-runtime-entries")
	}
	if all || *stubOffsetsOnly {
		runCheck("Thread-cached stub offsets", "-check-stub-offsets")
	}

	if failed {
		return fmt.Errorf("one or more SDK checks failed")
	}
	cli.Errf("All SDK checks passed.\n")
	return nil
}

func sdkCheckSourceRoot() (string, error) {
	var starts []string
	if cwd, err := os.Getwd(); err == nil {
		starts = append(starts, cwd)
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		starts = append(starts, filepath.Dir(file))
	}
	if exe, err := os.Executable(); err == nil {
		starts = append(starts, filepath.Dir(exe))
	}
	seen := make(map[string]bool)
	for _, start := range starts {
		abs, err := filepath.Abs(start)
		if err != nil {
			continue
		}
		for dir := abs; ; dir = filepath.Dir(dir) {
			if !seen[dir] {
				seen[dir] = true
				if regularFile(filepath.Join(dir, "go.mod")) && regularFile(filepath.Join(dir, "tools", "extract_thr.go")) {
					return dir, nil
				}
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
		}
	}
	return "", fmt.Errorf("sdk-check requires the aotopsy source tree (go.mod + tools/extract_thr.go); none found from cwd, compiled source path, or executable path")
}

func regularFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}
