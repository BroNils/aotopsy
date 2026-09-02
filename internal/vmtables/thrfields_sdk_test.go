package vmtables

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"aotopsy/internal/sdktest"
)

// TestThreadFieldNamesMatchSDK checks every committed Thread field table
// against runtime/vm/compiler/runtime_offsets_extracted.h, the header the
// SDK generates for exactly this purpose.
//
// There was no gate on these tables, only on Thread-cached STUB offsets,
// stub names and runtime entries. That gap is the whole story of the bug
// it was written for: thrV350_x64 was derived, committed, and never wired
// into the switch, which sent 3.5.0 to thrV343_x64 instead. thread.h at
// 3.5.0 adds shared_field_table_values at 0x70, shifting every field after
// it by one slot, so the two tables agreed on 5 of 89 shared offsets.
//
// That is the failure mode worth gating: not a missing name, which shows
// up as an unnamed THR.fNN, but a name taken from the neighbouring field.
// Every Thread access on 3.5.0 was annotated, confidently, with the wrong
// field -- and the only reason it surfaced at all is that staticcheck
// noticed the table was an unused variable. ARM64 3.5.0 had the same
// aliasing with no dedicated table at all.
//
//	AOTOPSY_TEST_SDK=1 go test ./internal/vmtables/ -run ThreadFieldNamesMatchSDK
func TestThreadFieldNamesMatchSDK(t *testing.T) {
	sdktest.SkipIfNoSDKTools(t)

	for _, v := range threadFieldVersions {
		t.Run(v, func(t *testing.T) {
			src, err := sdktest.GHFileAtTag("runtime/vm/compiler/runtime_offsets_extracted.h", v)
			if err != nil {
				t.Skipf("cannot fetch runtime_offsets_extracted.h@%s: %v", v, err)
			}
			for _, arch := range []struct {
				name    string
				isARM64 bool
			}{{"arm64", true}, {"x64", false}} {
				sdk := sdkThreadFieldOffsets(src, arch.isARM64)
				if len(sdk) == 0 {
					t.Fatalf("%s/%s: no AOT_Thread_*_offset found in the SDK header; "+
						"the section guard this parser looks for has moved", v, arch.name)
				}
				got := THRFields(v, arch.isARM64)
				if len(got) == 0 {
					t.Errorf("%s/%s: no committed table", v, arch.name)
					continue
				}
				var wrong []string
				shared := 0
				for off, want := range sdk {
					have, ok := got[off]
					if !ok {
						// A missing offset renders as THR.fNN. That is a gap
						// that says so, and is not what this gate is for.
						continue
					}
					shared++
					if have != want {
						wrong = append(wrong, fmt.Sprintf("    0x%x: table says %q, SDK says %q", off, have, want))
					}
				}
				if len(wrong) > 0 {
					sort.Strings(wrong)
					if len(wrong) > 12 {
						wrong = append(wrong[:12], fmt.Sprintf("    ... and %d more", len(wrong)-12))
					}
					t.Errorf("%s/%s: %d of %d shared offsets carry the wrong field name.\n"+
						"A wrong name is worse than none: it is reported with the same confidence\n"+
						"as a correct one. Usually this means the version is aliased to a\n"+
						"neighbour's table and a field was inserted between them.\n%s",
						v, arch.name, len(wrong), shared, strings.Join(wrong, "\n"))
				}
			}
		})
	}
}

// threadFieldVersions are the versions to check. A version answered by
// ThreadFieldNames but absent here is unverified.
var threadFieldVersions = []string{
	"3.0.5", "3.1.0", "3.2.5", "3.3.0", "3.4.3", "3.5.0",
	"3.6.2", "3.7.0", "3.8.1", "3.9.2", "3.10.7", "3.11.0", "3.12.2",
}

// The value may sit on the next line, and older tags emit it in decimal
// where newer ones use hex.
var aotThreadOffsetRe = regexp.MustCompile(`AOT_Thread_(\w+?)_offset =\s*(0x[0-9a-fA-F]+|\d+);`)

var archGuardRe = regexp.MustCompile(`#if [^\n]*TARGET_ARCH_(ARM64|X64)[^\n]*\n`)

// sdkThreadFieldOffsets pulls the AOT Thread field offsets for one
// architecture out of the SDK's generated header.
//
// The header repeats the whole constant set once per
// (mode, arch, pointer width) combination. The tables in this package are
// all PRODUCT + AOT + compressed pointers, so the section guard must
// match that exactly -- picking the !defined(DART_COMPRESSED_POINTERS)
// neighbour by accident would report every offset as wrong.
func sdkThreadFieldOffsets(src string, isARM64 bool) map[int]string {
	arch := "X64"
	if isARM64 {
		arch = "ARM64"
	}
	var fallback map[int]string
	for _, loc := range archGuardRe.FindAllStringIndex(src, -1) {
		head := src[loc[0]:min(loc[0]+220, len(src))]
		if !strings.Contains(head, "TARGET_ARCH_"+arch+")") {
			continue
		}
		// Compressed pointers only, and never the negated variant.
		if !strings.Contains(head, "defined(DART_COMPRESSED_POINTERS)") ||
			strings.Contains(head, "!defined(DART_COMPRESSED_POINTERS)") {
			continue
		}
		end := strings.Index(src[loc[0]:], "#endif")
		if end < 0 {
			continue
		}
		sec := src[loc[0] : loc[0]+end]
		if !strings.Contains(sec, "AOT_Thread_") {
			continue
		}
		found := map[int]string{}
		for _, m := range aotThreadOffsetRe.FindAllStringSubmatch(sec, -1) {
			var off int64
			var err error
			if strings.HasPrefix(m[2], "0x") {
				off, err = strconv.ParseInt(m[2][2:], 16, 64)
			} else {
				off, err = strconv.ParseInt(m[2], 10, 64)
			}
			if err != nil {
				continue
			}
			found[int(off)] = m[1]
		}
		if len(found) == 0 {
			continue
		}
		// Prefer the PRODUCT block. Tags from 3.2 onwards name it in the
		// guard; older ones (3.0.5, 3.1.0) put PRODUCT in an enclosing #if
		// this scan cannot see, but there the two blocks are byte-identical,
		// so either is correct.
		if strings.Contains(head, "defined(PRODUCT)") && !strings.Contains(head, "!defined(PRODUCT)") {
			return found
		}
		fallback = found
	}
	return fallback
}
