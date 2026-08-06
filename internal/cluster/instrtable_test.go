package cluster

import (
	"testing"
)

func TestInstructionsTable_AllSamples(t *testing.T) {
	tests := []struct {
		sample        string
		wantLength    uint32
		wantFirstCode uint32
		wantMainCodes int
	}{
		{"evil-patched.so", 1465, 0, 1465},
		{"blutter-lce.so", 10113, 0, 10113},
		{"newandromo.so", 21627, 17475, 4152},
	}
	for _, tt := range tests {
		t.Run(tt.sample, func(t *testing.T) {
			info := extractSnapshot(t, tt.sample)
			data := info.IsolateData.Data
			result := scanSnapshot(t, info, data, false)
			if err := ReadFill(data, result, info.Version, false, 0); err != nil {
				t.Fatalf("ReadFill: %v", err)
			}

			table, err := ParseInstructionsTable(data, &result.Header, info.Version, info.IsolateHeader)
			if err != nil {
				t.Fatalf("ParseInstructionsTable: %v", err)
			}

			if table.Length != tt.wantLength {
				t.Errorf("Length = %d, want %d", table.Length, tt.wantLength)
			}
			if table.FirstEntryWithCode != tt.wantFirstCode {
				t.Errorf("FirstEntryWithCode = %d, want %d", table.FirstEntryWithCode, tt.wantFirstCode)
			}

			// Verify entry count matches.
			if int(table.Length) != len(table.Entries) {
				t.Errorf("len(Entries) = %d, want %d", len(table.Entries), table.Length)
			}

			// Verify code entry count.
			codeEntries := int(table.Length) - int(table.FirstEntryWithCode)
			if codeEntries != tt.wantMainCodes {
				t.Errorf("code entries = %d, want %d", codeEntries, tt.wantMainCodes)
			}

			// Verify first code entry has non-zero PCOffset.
			if table.FirstEntryWithCode < table.Length {
				first := table.Entries[table.FirstEntryWithCode]
				if first.PCOffset == 0 {
					t.Error("first code entry has PCOffset=0")
				}
			}

			// Resolve code ranges.
			ranges, err := ResolveCodeRanges(result.Codes, table)
			if err != nil {
				t.Fatalf("ResolveCodeRanges: %v", err)
			}
			if len(ranges) != tt.wantMainCodes {
				t.Errorf("len(ranges) = %d, want %d", len(ranges), tt.wantMainCodes)
			}

			// All ranges except last should have non-zero size.
			for i := 0; i < len(ranges)-1; i++ {
				if ranges[i].Size == 0 {
					t.Errorf("range[%d] (ref %d) has size 0", i, ranges[i].RefID)
					break
				}
			}

			// Ranges should be sorted by PCOffset.
			for i := 1; i < len(ranges); i++ {
				if ranges[i].PCOffset <= ranges[i-1].PCOffset {
					t.Errorf("ranges not sorted: [%d].PCOffset=%d <= [%d].PCOffset=%d",
						i, ranges[i].PCOffset, i-1, ranges[i-1].PCOffset)
					break
				}
			}
		})
	}
}
