package jsonutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type sampleRecord struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Note string `json:"note,omitempty"`
}

func TestJSONLWriterAndReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	records := []sampleRecord{{ID: 1, Name: "alpha"}, {ID: 2, Name: "beta"}, {ID: 3, Name: "gamma"}}

	w, err := NewJSONLWriter[sampleRecord](path)
	if err != nil {
		t.Fatalf("NewJSONLWriter failed: %v", err)
	}
	for i := range records {
		if err := w.Write(&records[i]); err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	read, err := ReadJSONL[sampleRecord](path, StandardLimits)
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

func TestReadJSONLRejectsNonJSONLAndSchemaDrift(t *testing.T) {
	cases := map[string]string{
		"multiline":        "{\n\"id\":1,\"name\":\"x\"}\n",
		"array":            "[{\"id\":1,\"name\":\"x\"}]\n",
		"duplicate":        "{\"id\":1,\"id\":2,\"name\":\"x\"}\n",
		"unknown":          "{\"id\":1,\"name\":\"x\",\"stale\":1}\n",
		"missing-required": "{\"id\":1}\n",
		"two-values":       "{\"id\":1,\"name\":\"x\"} {\"id\":2,\"name\":\"y\"}\n",
		"truncated":        "{\"id\":1,\"name\":\"x\"\n",
		"blank-record":     "{\"id\":1,\"name\":\"x\"}\n\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bad.jsonl")
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadJSONL[sampleRecord](path, StandardLimits); err == nil {
				t.Fatalf("accepted malformed/non-conforming JSONL: %q", body)
			}
		})
	}
}

func TestReadJSONLHonorsBudgets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	body := "{\"id\":1,\"name\":\"alpha\"}\n{\"id\":2,\"name\":\"beta\"}\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadJSONL[sampleRecord](path, Limits{MaxBytes: 10, MaxRecords: 10, MaxRecordBytes: 100}); err == nil {
		t.Fatal("byte budget was not enforced")
	}
	if _, err := ReadJSONL[sampleRecord](path, Limits{MaxBytes: 1000, MaxRecords: 1, MaxRecordBytes: 100}); err == nil {
		t.Fatal("record budget was not enforced")
	}
	if _, err := ReadJSONL[sampleRecord](path, Limits{MaxBytes: 1000, MaxRecords: 10, MaxRecordBytes: 8}); err == nil {
		t.Fatal("record-size budget was not enforced")
	}
}

func TestReadJSONLAllowsRecordAtExactLimitWithCRLF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	line := `{"id":1,"name":"alpha"}`
	body := line + "\r\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	limits := Limits{
		MaxBytes:       int64(len(body)),
		MaxRecords:     1,
		MaxRecordBytes: len(line),
	}
	records, err := ReadJSONL[sampleRecord](path, limits)
	if err != nil {
		t.Fatalf("ReadJSONL rejected %d-byte record at exact limit with CRLF: %v", len(line), err)
	}
	if len(records) != 1 || records[0].ID != 1 || records[0].Name != "alpha" {
		t.Fatalf("ReadJSONL = %+v, want one alpha record", records)
	}
}

func TestReadJSONLAllowsExactByteBudgetWithoutFinalNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	body := `{"id":1,"name":"alpha"}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	limits := Limits{
		MaxBytes:       int64(len(body)),
		MaxRecords:     1,
		MaxRecordBytes: len(body),
	}
	records, err := ReadJSONL[sampleRecord](path, limits)
	if err != nil {
		t.Fatalf("ReadJSONL rejected exact byte budget without final newline: %v", err)
	}
	if len(records) != 1 || records[0].Name != "alpha" {
		t.Fatalf("ReadJSONL = %+v, want one alpha record", records)
	}
}

func TestReadJSONLDoesNotReturnPartialRecordsOnScannerError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	first := `{"id":1,"name":"alpha"}`
	second := `{"id":2,"name":"this record is deliberately too large"}`
	body := first + "\n" + second + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	records, err := ReadJSONL[sampleRecord](path, Limits{
		MaxBytes:       int64(len(body)),
		MaxRecords:     10,
		MaxRecordBytes: len(first),
	})
	if err == nil {
		t.Fatal("expected scanner error for oversized second record")
	}
	if records != nil {
		t.Fatalf("ReadJSONL returned %d partially validated records with error", len(records))
	}
}

func TestReadJSONFileIsStrictAndBounded(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte("{\n  \"id\": 1,\n  \"name\": \"alpha\"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadJSONFile[sampleRecord](good, 1024)
	if err != nil || got.ID != 1 || got.Name != "alpha" {
		t.Fatalf("ReadJSONFile = %+v, %v", got, err)
	}
	for name, body := range map[string]string{
		"duplicate": `{"id":1,"id":2,"name":"x"}`,
		"unknown":   `{"id":1,"name":"x","stale":true}`,
		"missing":   `{"id":1}`,
		"two":       `{"id":1,"name":"x"} {"id":2,"name":"y"}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name+".json")
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadJSONFile[sampleRecord](p, 1024); err == nil {
				t.Fatalf("accepted invalid JSON object: %s", body)
			}
		})
	}
	if _, err := ReadJSONFile[sampleRecord](good, 8); err == nil {
		t.Fatal("byte budget was not enforced")
	}
}

type failingRecord struct {
	Value string `json:"value"`
}

func (r *failingRecord) MarshalJSON() ([]byte, error) {
	if r.Value == "fail" {
		return nil, errors.New("intentional marshal failure")
	}
	return []byte(fmt.Sprintf(`{"value":%q,"ptr":true}`, r.Value)), nil
}

func TestWriteJSONLFileIsTransactionalAndUsesPointerMarshaler(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	const old = "old artifact\n"
	if err := os.WriteFile(path, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteJSONLFile(path, []failingRecord{{Value: "ok"}, {Value: "fail"}}); err == nil {
		t.Fatal("expected marshal failure")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != old {
		t.Fatalf("failed write destroyed old artifact: %q", got)
	}

	if _, err := WriteJSONLFile(path, []failingRecord{{Value: "ok"}}); err != nil {
		t.Fatalf("successful replace: %v", err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"ptr":true`) {
		t.Fatalf("pointer-receiver MarshalJSON was bypassed: %s", got)
	}
}

func TestJSONLWriterAbortPreservesCloseErrorWhenTempAlreadyRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	w, err := NewJSONLWriter[sampleRecord](path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.file.Close(); err != nil {
		t.Fatalf("pre-close temp: %v", err)
	}
	if err := os.Remove(w.tempPath); err != nil {
		t.Fatalf("remove temp: %v", err)
	}

	if err := w.Abort(); err == nil {
		t.Fatal("Abort swallowed close error because temp file was already absent")
	}
}

func TestWriteJSONFileReplacesCompleteObject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meta.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	value := map[string]any{"name": "new", "count": 3}
	if err := WriteJSONFile(path, value); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"name": "new"`) || strings.Contains(string(b), "old") {
		t.Fatalf("unexpected JSON object: %s", b)
	}
}
