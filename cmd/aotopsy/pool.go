package main

import "aotopsy/internal/naming"

// poolLookups is a type alias for naming.PoolLookups, used across
// cmd/aotopsy function signatures. The wrapper functions that used to
// live here (buildPoolLookups, resolvePoolDisplay, etc.) have been
// removed: callers now use naming.BuildPoolLookups etc. directly.
type poolLookups = naming.PoolLookups
