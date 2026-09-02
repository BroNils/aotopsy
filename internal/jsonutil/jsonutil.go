// Package jsonutil provides generic JSONL I/O: reading and writing
// line-delimited JSON records. Extracted from internal/naming so that
// naming only contains name resolution and these generic helpers are
// available to any package without importing naming.
package jsonutil

import (
	"encoding/json"
	"fmt"
	"os"
)

// ReadJSONL reads a JSONL file into a slice of T.
func ReadJSONL[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var records []T
	dec := json.NewDecoder(f)
	for dec.More() {
		var rec T
		if err := dec.Decode(&rec); err != nil {
			return records, fmt.Errorf("line %d: %w", len(records)+1, err)
		}
		records = append(records, rec)
	}

	return records, nil
}

// WriteJSONLFile writes a slice of records as JSONL to path. Each record
// is encoded on its own line. Returns the number of records written.
func WriteJSONLFile[T any](path string, records []T) (int, error) {
	w, err := NewJSONLWriter[T](path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = w.Close() }()

	for i := range records {
		if err := w.Write(records[i]); err != nil {
			return i, fmt.Errorf("encode %s record %d: %w", path, i, err)
		}
	}
	return len(records), nil
}

// JSONLWriter provides buffered streaming serialization of records into JSONL format.
type JSONLWriter[T any] struct {
	file *os.File
	enc  *json.Encoder
}

// NewJSONLWriter creates a new streaming JSONL writer for the specified file path.
func NewJSONLWriter[T any](path string) (*JSONLWriter[T], error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", path, err)
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	return &JSONLWriter[T]{
		file: f,
		enc:  enc,
	}, nil
}

// Write encodes and appends one record as a single JSON line.
func (w *JSONLWriter[T]) Write(rec T) error {
	return w.enc.Encode(rec)
}

// Close closes the underlying file handle.
func (w *JSONLWriter[T]) Close() error {
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}
