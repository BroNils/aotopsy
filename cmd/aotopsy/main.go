package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"aotopsy/internal/cli"
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
		if len(rest) != 0 {
			cli.Errf("error: top-level help does not accept positional arguments: %q\n", rest)
			os.Exit(2)
		}
		printPrimaryUsage()
		os.Exit(0)
	}

	// Version flags.
	if cmd == "version" || cmd == "--version" || cmd == "-V" {
		if len(rest) != 0 {
			cli.Errf("error: version does not accept positional arguments: %q\n", rest)
			os.Exit(2)
		}
		fmt.Printf("aotopsy %s (commit %s, built %s)\n",
			cli.SafeLine(cli.Version), cli.SafeLine(cli.Commit), cli.SafeLine(cli.Date))
		os.Exit(0)
	}

	// Look up in the primary command registry.
	if c := findCommand(primaryCommands, cmd); c != nil {
		err := c.Run(rest)
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		if err != nil {
			cli.Errf("error: %s\n", err)
			os.Exit(commandErrorExitCode(err))
		}
		return
	}

	// Default: if the first arg is a file on disk, treat as "aotopsy <libapp.so>".
	if resolvePositionalLib(cmd) != "" {
		err := cmdRun(os.Args[1:])
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		if err != nil {
			cli.Errf("error: %s\n", err)
			os.Exit(commandErrorExitCode(err))
		}
		return
	}

	// Flags before file path: pass all args to cmdRun which will reorder.
	if strings.HasPrefix(cmd, "-") {
		err := cmdRun(os.Args[1:])
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		if err != nil {
			cli.Errf("error: %s\n", err)
			os.Exit(commandErrorExitCode(err))
		}
		return
	}

	cli.Errf("unknown command: %s\n", cmd)
	printPrimaryUsage()
	os.Exit(1)
}

func commandErrorExitCode(err error) int {
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return 0
	}
	var usageErr *cliUsageError
	if errors.As(err, &usageErr) {
		return 2
	}
	return 1
}
