package cli

// Build metadata is injected by GoReleaser. Keeping the values in an internal
// package lets reports and subcommands describe the same binary version instead
// of each caller inventing or hardcoding its own string.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)
