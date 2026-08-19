package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		printPrimaryUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	rest := os.Args[2:]

	// Help flags.
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		printPrimaryUsage()
		os.Exit(0)
	}

	// Look up in the primary command registry.
	if c := findCommand(primaryCommands, cmd); c != nil {
		var err error
		if c.Special != nil {
			var handled bool
			handled, err = c.Special(cmd, os.Args[1:])
			if !handled {
				err = fmt.Errorf("command %s did not handle its args", cmd)
			}
		} else {
			if c.Deprecated {
				deprecationWarning(c.Name, c.DeprecatedRepl)
			}
			err = c.Run(rest)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Default: if the first arg is a file on disk, treat as "aotopsy <libapp.so>".
	if resolvePositionalLib(cmd) != "" {
		err := cmdRun(os.Args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Flags before file path: pass all args to cmdRun which will reorder.
	if strings.HasPrefix(cmd, "-") {
		err := cmdRun(os.Args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
	printPrimaryUsage()
	os.Exit(1)
}

func deprecationWarning(old, new string) {
	fmt.Fprintf(os.Stderr, "warning: '%s' is deprecated, use '%s' instead\n\n", old, new)
}

// hasFlag checks if any arg matches one of the given flag names.
func hasFlag(args []string, names ...string) bool {
	for _, a := range args {
		for _, n := range names {
			if a == n {
				return true
			}
		}
	}
	return false
}
