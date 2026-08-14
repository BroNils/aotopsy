package pipeline

import (
	"fmt"
	"os"
	"sort"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/disasm"
	"aotopsy/internal/snapshot"
)

// BuildVMStubSymbols parses the VM-isolate snapshot region (info.VmData,
// a separate stream from the app's own isolate snapshot -- see
// ARCHITECTURE.md's "Stub naming" section) and returns a VA->name map for
// stub Code objects with a known name (disasm.VMStubNames). The VM
// isolate's Code cluster order matches VM_STUB_CODE_LIST's macro
// expansion order exactly (verified against two real compiled samples:
// index 0 is always a ~12-byte function, consistent with the trivially
// small GetCStackPointer), so result.Codes[i] (in its ORIGINAL,
// creation-order slice position -- NOT cluster.ResolveCodeRanges' output,
// which is sorted by PCOffset instead) is named names[i].
//
// Returns an empty map (never nil) on any failure or unverified version --
// this is a best-effort convenience layered on top of the existing
// stub_<hex>/sub_<hex> fallback, not a required pipeline step.
func BuildVMStubSymbols(info *snapshot.Info, opts dartfmt.Options) map[uint64]string {
	debug := os.Getenv("AOTOPSY_DEBUG_VMSTUBS") != ""
	out := make(map[uint64]string)
	names := disasm.VMStubNamesInImageOrder(info.Version.DartVersion)
	if names == nil || len(info.VmData.Data) == 0 || info.VmHeader == nil || len(info.VmInstructions.Data) == 0 {
		if debug {
			fmt.Fprintf(os.Stderr, "vmstubs: names=%v vmDataLen=%d vmHeader=%v vmInstrLen=%d\n", names != nil, len(info.VmData.Data), info.VmHeader != nil, len(info.VmInstructions.Data))
		}
		return out
	}

	clusterStart, err := cluster.FindClusterDataStart(info.VmData.Data)
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "vmstubs: FindClusterDataStart: %v\n", err)
		}
		return out
	}
	result, err := cluster.ScanClusters(info.VmData.Data, clusterStart, info.Version, true, opts)
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "vmstubs: ScanClusters: %v\n", err)
		}
		return out
	}
	if err := cluster.ReadFill(info.VmData.Data, result, info.Version, true, 0); err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "vmstubs: ReadFill: %v\n", err)
		}
		return out
	}
	table, err := cluster.ParseInstructionsTable(info.VmData.Data, &result.Header, info.Version, info.VmHeader)
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "vmstubs: ParseInstructionsTable: %v\n", err)
		}
		return out
	}
	ranges, err := cluster.ResolveCodeRanges(result.Codes, table)
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "vmstubs: ResolveCodeRanges: %v\n", err)
		}
		return out
	}
	_, codeOff, payloadLen, err := snapshot.CodeRegion(info.VmInstructions.Data)
	if err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "vmstubs: CodeRegion: %v\n", err)
		}
		return out
	}
	if debug {
		fmt.Fprintf(os.Stderr, "vmstubs: codes=%d ranges=%d names=%d\n", len(result.Codes), len(ranges), len(names))
	}
	codeEndOffset := uint32(codeOff) + uint32(payloadLen) //nolint:gosec // codeOff/payloadLen are offsets within one already-loaded snapshot payload, always well under 2^32
	cluster.SetLastRangeSize(ranges, codeEndOffset)
	codeVA := info.VmInstructions.VA + codeOff

	// Zip names against ranges sorted by ADDRESS, not by Code-cluster index.
	//
	// This used to walk result.Codes in cluster order and assign names[i],
	// which put VM_STUB_CODE_LIST entry 0 (`JumpToFrame`) at the lowest
	// address. The symbol table of a 3.12.2 build says `JumpToFrame` is at
	// the HIGHEST: the image is laid out in reverse, and the 9
	// type-testing stubs sit in the middle rather than in an unnamed tail.
	// Every name was wrong. See disasm.VMStubNamesInImageOrder for the
	// derivation and the ground truth it came from.
	sorted := make([]cluster.CodeRange, len(ranges))
	copy(sorted, ranges)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PCOffset < sorted[j].PCOffset })

	if len(sorted) != len(names) && debug {
		// A mismatch means the composed list and the image disagree about
		// how many stubs exist, so the zip is offset and every name after
		// the divergence is wrong. Report it rather than emit them.
		fmt.Fprintf(os.Stderr, "vmstubs: %d ranges but %d composed names -- refusing to name\n",
			len(sorted), len(names))
	}
	if len(sorted) != len(names) {
		return out
	}

	for i, r := range sorted {
		funcVA := codeVA + uint64(r.PCOffset) - codeOff
		out[funcVA] = names[i]
	}
	return out
}
