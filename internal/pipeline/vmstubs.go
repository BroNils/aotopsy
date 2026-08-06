package pipeline

import (
	"fmt"
	"os"

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
	names := disasm.VMStubNames(info.Version.DartVersion)
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

	pcOffByRef := make(map[int]uint32, len(ranges))
	for _, r := range ranges {
		pcOffByRef[r.RefID] = r.PCOffset
	}

	for i, c := range result.Codes {
		if i >= len(names) {
			break // the +9 unnamed tail (see disasm.VMStubNames doc comment) -- don't guess
		}
		pcOff, ok := pcOffByRef[c.RefID]
		if !ok {
			continue
		}
		funcVA := codeVA + uint64(pcOff) - codeOff
		out[funcVA] = names[i]
	}
	return out
}
