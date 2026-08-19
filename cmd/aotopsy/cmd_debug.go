package main

import (
	"fmt"
)

// cmdDebug handles "aotopsy _debug <cmd>" — internal/debug commands.
func cmdDebug(args []string) error {
	if len(args) < 1 {
		printDebugUsage()
		return nil
	}

	cmd := args[0]
	subArgs := args[1:]

	if c := findCommand(debugCommands, cmd); c != nil {
		return c.Run(subArgs)
	}

	return fmt.Errorf("unknown debug command: %s", cmd)
}
