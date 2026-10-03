package sdk

import "aotopsy/internal/snapshot"

// isSupportedDartVersion is deliberately exact. VM facts must never be chosen
// by treating an unknown/future version as "close enough" to a supported one.
func isSupportedDartVersion(version string) bool {
	p := snapshot.ProfileForVersion(version)
	return p != nil && p.Supported
}
