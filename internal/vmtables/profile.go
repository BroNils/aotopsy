package vmtables

import "aotopsy/internal/snapshot"

// Architecture identifies the machine architecture of a VM offset table.
// Keep this explicit rather than passing an isARM64 bool through several
// layers: selecting the wrong architecture is a correctness failure, not a
// harmless formatting difference.
type Architecture uint8

const (
	ArchitectureUnknown Architecture = iota
	ArchitectureARM64
	ArchitectureX64
)

// TargetProfile is the complete set of snapshot properties that select VM
// Thread layout data. Offset lookup must never guess any of these dimensions.
type TargetProfile struct {
	DartVersion        string
	Architecture       Architecture
	CompressedPointers bool
	BuildMode          snapshot.BuildMode
}

// TargetProfileFromVersion converts the parsed snapshot profile plus the ELF
// architecture into the selector used by this package. A nil version profile
// is deliberately rejected: falling back to a default compression mode was
// the source of confident-but-wrong THR annotations on desktop x64 AOT.
func TargetProfileFromVersion(profile *snapshot.VersionProfile, isARM64 bool) (TargetProfile, bool) {
	if profile == nil || profile.DartVersion == "" {
		return TargetProfile{}, false
	}
	arch := ArchitectureX64
	if isARM64 {
		arch = ArchitectureARM64
	}
	return TargetProfile{
		DartVersion:        profile.DartVersion,
		Architecture:       arch,
		CompressedPointers: profile.CompressedPointers,
		BuildMode:          profile.BuildMode,
	}, true
}

func (p TargetProfile) supportedProduct() bool {
	return p.DartVersion != "" &&
		(p.Architecture == ArchitectureARM64 || p.Architecture == ArchitectureX64) &&
		p.BuildMode == snapshot.BuildProduct
}
