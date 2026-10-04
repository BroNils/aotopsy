package elfx

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func testBuildIDNote(desc []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(4))
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(desc)))
	_ = binary.Write(&b, binary.LittleEndian, uint32(3))
	b.Write([]byte{'G', 'N', 'U', 0})
	b.Write(desc)
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
	return b.Bytes()
}

func TestBuildIDEvidenceConflictAcrossSourcesIsNotChosen(t *testing.T) {
	id, source, conflicts := resolveBuildIDEvidence(
		map[string]bool{"01020304": true},
		map[string]bool{"05060708": true},
	)
	if id != "" || source != "" || len(conflicts) != 1 {
		t.Fatalf("cross-source build-id conflict = id=%q source=%q conflicts=%q", id, source, conflicts)
	}
}

func TestBuildIDNotesRequireExactGNUOwnerAndRejectTrailingGarbage(t *testing.T) {
	note := testBuildIDNote([]byte{1, 2, 3, 4})
	binary.LittleEndian.PutUint32(note[0:4], 3)
	ids, err := parseBuildIDNotes(note, binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("malformed GNU owner produced build IDs %q", ids)
	}

	bad := append(testBuildIDNote([]byte{1, 2, 3, 4}), []byte{1, 2, 3}...)
	if ids, err := parseBuildIDNotes(bad, binary.LittleEndian); err == nil {
		t.Fatalf("trailing malformed note was ignored after build-id %q", ids)
	}
}

func TestDuplicateBuildIDsCollapseWithoutConflict(t *testing.T) {
	notes := append(testBuildIDNote([]byte{1, 2, 3, 4}), testBuildIDNote([]byte{1, 2, 3, 4})...)
	ids, err := parseBuildIDNotes(notes, binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "01020304" {
		t.Fatalf("duplicate build IDs = %q, want one 01020304", ids)
	}
}
