package jsonutil

import (
	"path/filepath"
	"testing"
)

type sampleRecord struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func TestJSONLWriterAndReader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "records.jsonl")

	records := []sampleRecord{
		{ID: 1, Name: "alpha"},
		{ID: 2, Name: "beta"},
		{ID: 3, Name: "gamma"},
	}

	w, err := NewJSONLWriter[sampleRecord](path)
	if err != nil {
		t.Fatalf("NewJSONLWriter failed: %v", err)
	}
	for _, r := range records {
		if err := w.Write(r); err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	read, err := ReadJSONL[sampleRecord](path)
	if err != nil {
		t.Fatalf("ReadJSONL failed: %v", err)
	}
	if len(read) != len(records) {
		t.Fatalf("Read %d records, want %d", len(read), len(records))
	}
	for i, r := range read {
		if r != records[i] {
			t.Errorf("Record %d = %+v, want %+v", i, r, records[i])
		}
	}
}
