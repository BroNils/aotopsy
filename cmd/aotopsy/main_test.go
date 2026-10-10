package main

import (
	"errors"
	"flag"
	"testing"
)

func TestCommandRegistriesHaveUniqueReachableHandlers(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range primaryCommands {
		if c.Name == "" || c.Run == nil || c.Usage == "" || c.Short == "" {
			t.Fatalf("incomplete primary command registration: %+v", c)
		}
		if seen[c.Name] {
			t.Fatalf("duplicate primary command %q", c.Name)
		}
		seen[c.Name] = true
	}
	for _, c := range debugCommands {
		if c.Name == "" || c.Run == nil || c.Short == "" || !c.Debug {
			t.Fatalf("incomplete debug command registration: %+v", c)
		}
		if seen[c.Name] {
			t.Fatalf("duplicate command name across registries: %q", c.Name)
		}
		seen[c.Name] = true
	}
}

func TestCommandErrorExitCodeDistinguishesUsageErrors(t *testing.T) {
	if got := commandErrorExitCode(nil); got != 0 {
		t.Fatalf("nil error exit code = %d, want 0", got)
	}
	if got := commandErrorExitCode(flag.ErrHelp); got != 0 {
		t.Fatalf("help exit code = %d, want 0", got)
	}
	if got := commandErrorExitCode(errors.New("semantic failure")); got != 1 {
		t.Fatalf("semantic error exit code = %d, want 1", got)
	}
	if got := commandErrorExitCode(&cliUsageError{err: errors.New("bad flag")}); got != 2 {
		t.Fatalf("usage error exit code = %d, want 2", got)
	}
}

func TestDebugHelpAliasesAreHandledWithoutDispatch(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		if err := cmdDebug([]string{arg}); err != nil {
			t.Fatalf("cmdDebug(%q) = %v", arg, err)
		}
	}
}
