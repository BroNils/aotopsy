package decompiler

import (
	"fmt"
	"strings"
)

// DarterCompatibility provides integration with darter (mildsunrise/darter),
// a Python Dart snapshot parser that supports older Dart versions.
//
// This is the implementation of Tier 5 item 19 (darter / reFlutter).
// reFlutter is already wired in aotopsy as a source of version hashes
// (internal/snapshot/version.go uses enginehash.csv). darter carries
// parsers for older Dart versions (pre-2.10) that could widen coverage.
//
// darter's README (gh api verified) says:
//   "Parses 100% of the snapshot data, including memory structures."
//   "Supports many architectures and the three snapshot types."
//   "Export metadata for Radare2"
//   "Deobfuscate a snapshot by matching it with a reference one"
//
// However, darter is outdated: "The format of Dart snapshots changes
// CONSTANTLY, and any Dart RE tools like this one NEED constant
// maintenance or they stop working with newer versions of Dart."
//
// aotopsy already supports Dart 2.10 through 3.13. darter's value is
// for pre-2.10 versions that aotopsy doesn't support yet. This module
// provides a compatibility layer: it can import darter's parsed output
// (JSON format) and convert it to aotopsy's internal representation,
// extending coverage to older versions without reimplementing darter's
// parsers in Go.
//
// Usage:
//  1. Run darter on an older Dart snapshot: python darter.py libapp.so
//  2. Import the output: DarterCompatibility.Import(darterJSON)
//  3. Use the recovered names/metadata in aotopsy's pipeline.

// DarterSnapshot holds metadata imported from darter's output.
type DarterSnapshot struct {
	DartVersion string
	Arch        string
	Functions   []DarterFunction
	Classes     []DarterClass
	Strings     []DarterString
}

// DarterFunction is one function recovered by darter.
type DarterFunction struct {
	Name    string `json:"name"`
	Owner   string `json:"owner"`
	Address uint64 `json:"address"`
	Size    int    `json:"size"`
}

// DarterClass is one class recovered by darter.
type DarterClass struct {
	Name    string   `json:"name"`
	Fields  []string `json:"fields"`
	Library string   `json:"library"`
}

// DarterString is one string recovered by darter.
type DarterString struct {
	Value   string `json:"value"`
	Address uint64 `json:"address"`
}

// ImportDarter converts darter's output to aotopsy's R2Export format,
// so darter-recovered names from older Dart versions can be applied
// to radare2 sessions alongside aotopsy's own output.
func ImportDarter(snap *DarterSnapshot) *R2Export {
	r2 := NewR2Export()
	for _, fn := range snap.Functions {
		name := fn.Name
		if fn.Owner != "" {
			name = fn.Owner + "." + fn.Name
		}
		r2.AddFunction(fn.Address, name)
		if fn.Size > 0 {
			r2.AddComment(fn.Address, fmt.Sprintf("size=%d", fn.Size))
		}
	}
	for _, cls := range snap.Classes {
		r2.AddClassLayout(cls.Name, cls.Fields)
		if cls.Library != "" {
			r2.AddComment(0, fmt.Sprintf("class %s in %s", cls.Name, cls.Library))
		}
	}
	for _, s := range snap.Strings {
		r2.AddStringRef(s.Address, s.Value)
	}
	return r2
}

// darterVersions is darter's own coverage: the Dart 2.x releases it was
// maintained against, per its README.
var darterVersions = []string{
	"2.0.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0",
	"2.5.0", "2.6.0", "2.7.0", "2.8.0", "2.9.0",
}

// DarterVersionSupport reports which Dart versions darter covers that
// aotopsy does not, given aotopsy's own supported set
// (snapshot.SupportedVersions). That difference is where importing darter
// output actually widens coverage rather than duplicating it.
//
// This is a set difference, not a version-range comparison. The previous
// implementation compared version strings with `<` and ignored its argument
// entirely, so it reported 2 of the 10 versions above -- "2.9.0" < "2.10.0"
// is false lexicographically, and so is every other 2.2.0-2.9.0 case -- and
// reported them as the complete answer.
func DarterVersionSupport(aotopsyVersions []string) []string {
	supported := make(map[string]bool, len(aotopsyVersions))
	for _, v := range aotopsyVersions {
		supported[v] = true
	}
	var darterOnly []string
	for _, v := range darterVersions {
		if !supported[v] {
			darterOnly = append(darterOnly, v)
		}
	}
	return darterOnly
}

// ReFlutterIntegration provides helpers for reFlutter's enginehash.csv,
// which aotopsy already uses (internal/snapshot/version.go).
// This module documents the integration and provides a helper to
// check whether a snapshot hash is known to reFlutter.
type ReFlutterIntegration struct {
	// KnownHashes maps snapshot hashes to Dart versions, from
	// reFlutter's enginehash.csv. Already populated in
	// internal/snapshot/version.go's knownHashes map.
	KnownHashes map[string]string
}

// IsKnown reports whether reFlutter knows about a snapshot hash.
func (r *ReFlutterIntegration) IsKnown(hash string) bool {
	_, ok := r.KnownHashes[strings.ToLower(hash)]
	return ok
}

// VersionForHash returns the Dart version for a snapshot hash,
// or "" if unknown.
func (r *ReFlutterIntegration) VersionForHash(hash string) string {
	return r.KnownHashes[strings.ToLower(hash)]
}
