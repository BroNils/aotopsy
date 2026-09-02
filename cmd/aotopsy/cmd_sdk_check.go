package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
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
	if err := fs.Parse(args); err != nil {
		return err
	}

	all := !*thrOnly && !*objectStoreOnly && !*stubsOnly && !*rootsOnly
	failed := false

	runCheck := func(name, flag string) {
		fmt.Fprintf(os.Stderr, "=== %s ===\n", name)
		cmd := exec.Command("go", "run", "tools/extract_thr.go", flag)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %s\n", name)
			failed = true
		} else {
			fmt.Fprintf(os.Stderr, "PASS: %s\n\n", name)
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

	if failed {
		return fmt.Errorf("one or more SDK checks failed")
	}
	fmt.Fprintf(os.Stderr, "All SDK checks passed.\n")
	return nil
}
