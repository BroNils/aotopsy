package main

import "aotopsy/internal/pipeline"

// poolLookups is a type alias for pipeline.PoolLookups, used across
// cmd/aotopsy function signatures. The wrapper functions that used to
// live here (buildPoolLookups, resolvePoolDisplay, etc.) have been
// removed: callers now use pipeline.BuildPoolLookups etc. directly.
type poolLookups = pipeline.PoolLookups
