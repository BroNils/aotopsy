// Package jsonutil provides strict, bounded, transactional JSONL I/O.
package jsonutil

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Limits bounds hostile or accidentally huge artifact inputs before they can
// turn a convenience reader into an unbounded allocation primitive.
type Limits struct {
	MaxBytes       int64
	MaxRecords     int
	MaxRecordBytes int
}

// StandardLimits are deliberately generous for normal aotopsy artifacts while
// still fitting below the repository's 2.5 GiB per-process WSL safety cap.
var StandardLimits = Limits{
	MaxBytes:       256 << 20,
	MaxRecords:     2_000_000,
	MaxRecordBytes: 4 << 20,
}

func (l Limits) normalized() Limits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = StandardLimits.MaxBytes
	}
	if l.MaxRecords <= 0 {
		l.MaxRecords = StandardLimits.MaxRecords
	}
	if l.MaxRecordBytes <= 0 {
		l.MaxRecordBytes = StandardLimits.MaxRecordBytes
	}
	return l
}

// ReadJSONL reads strict line-delimited JSON objects. Each non-empty record must
// occupy exactly one physical line. Unknown, duplicate and missing required
// top-level keys are rejected so schema drift cannot silently decode to zero
// values. Limits are enforced before and during decoding.
func ReadJSONL[T any](path string, limits Limits) ([]T, error) {
	limits = limits.normalized()
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	} else if st.Size() > limits.MaxBytes {
		return nil, fmt.Errorf("jsonl: %s is %d bytes, exceeds limit %d", path, st.Size(), limits.MaxBytes)
	}

	required, err := requiredJSONKeys[T]()
	if err != nil {
		return nil, fmt.Errorf("jsonl: derive schema: %w", err)
	}

	var scanReader io.Reader = f
	var inputLimit *io.LimitedReader
	if limits.MaxBytes < (1<<63)-1 {
		inputLimit = &io.LimitedReader{R: f, N: limits.MaxBytes + 1}
		scanReader = inputLimit
	}
	s := bufio.NewScanner(scanReader)
	initial := 64 << 10
	if limits.MaxRecordBytes < initial {
		initial = limits.MaxRecordBytes
	}
	if initial < 1 {
		initial = 1
	}
	// ScanLines needs room for the line delimiter in addition to the record.
	// Reserve two bytes so a record exactly at MaxRecordBytes remains valid with
	// either LF or CRLF framing; the explicit len(line) check below still
	// enforces the payload limit.
	maxScanBytes := limits.MaxRecordBytes
	if maxInt := int(^uint(0) >> 1); maxScanBytes <= maxInt-2 {
		maxScanBytes += 2
	}
	s.Buffer(make([]byte, initial), maxScanBytes)
	var records []T
	lineNo := 0
	for s.Scan() {
		lineNo++
		if inputLimit != nil && inputLimit.N == 0 {
			return nil, fmt.Errorf("jsonl: input exceeds byte limit %d at line %d", limits.MaxBytes, lineNo)
		}
		line := s.Bytes()
		if len(line) > limits.MaxRecordBytes {
			return nil, fmt.Errorf("jsonl: record at line %d is %d bytes, exceeds limit %d", lineNo, len(line), limits.MaxRecordBytes)
		}
		if len(bytes.TrimSpace(line)) == 0 {
			return nil, fmt.Errorf("jsonl: blank record at line %d", lineNo)
		}
		if len(records) >= limits.MaxRecords {
			return nil, fmt.Errorf("jsonl: record limit %d exceeded at line %d", limits.MaxRecords, lineNo)
		}
		keys, err := objectKeys(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		for key := range required {
			if !keys[key] {
				return nil, fmt.Errorf("line %d: missing required key %q", lineNo, key)
			}
		}

		var rec T
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if err := requireDecoderEOF(dec); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		records = append(records, rec)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("jsonl: read line %d: %w", lineNo+1, err)
	}
	if inputLimit != nil && inputLimit.N == 0 {
		return nil, fmt.Errorf("jsonl: input exceeds byte limit %d", limits.MaxBytes)
	}
	return records, nil
}

// ReadJSONFile reads one strict JSON object under a byte budget. Like ReadJSONL,
// it rejects unknown, duplicate, and missing required top-level keys so a
// reused artifact cannot silently drift schemas. Multiline/pretty-printed JSON
// is allowed because this is an object file, not JSONL.
func ReadJSONFile[T any](path string, maxBytes int64) (T, error) {
	var out T
	if maxBytes <= 0 {
		return out, fmt.Errorf("json: invalid byte limit %d", maxBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil {
		return out, fmt.Errorf("stat %s: %w", path, err)
	} else if st.Size() > maxBytes {
		return out, fmt.Errorf("json: %s is %d bytes, exceeds limit %d", path, st.Size(), maxBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return out, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(b)) > maxBytes {
		return out, fmt.Errorf("json: %s exceeds byte limit %d", path, maxBytes)
	}
	out, err = DecodeStrictObject[T](b)
	if err != nil {
		return out, fmt.Errorf("json: %s: %w", path, err)
	}
	return out, nil
}

// DecodeStrictObject decodes one schema-exact JSON object. It is useful for
// framed wire records (for example tagged runtime events) that cannot be read
// directly from a standalone JSON/JSONL file.
func DecodeStrictObject[T any](b []byte) (T, error) {
	var out T
	required, err := requiredJSONKeys[T]()
	if err != nil {
		return out, fmt.Errorf("derive schema: %w", err)
	}
	keys, err := objectKeys(b)
	if err != nil {
		return out, err
	}
	for key := range required {
		if !keys[key] {
			return out, fmt.Errorf("missing required key %q", key)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, err
	}
	if err := requireDecoderEOF(dec); err != nil {
		return out, err
	}
	return out, nil
}

func objectKeys(line []byte) (map[string]bool, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return nil, fmt.Errorf("record must be a JSON object")
	}
	keys := make(map[string]bool)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("object key is not a string")
		}
		if keys[key] {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		keys[key] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
	}
	if _, err := dec.Token(); err != nil { // closing }
		return nil, err
	}
	if err := requireDecoderEOF(dec); err != nil {
		return nil, err
	}
	return keys, nil
}

func requireDecoderEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("multiple JSON values in one record")
	}
	return err
}

func requiredJSONKeys[T any]() (map[string]bool, error) {
	var zero T
	b, err := json.Marshal(zero)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("record type does not encode as an object: %w", err)
	}
	if m == nil {
		return nil, fmt.Errorf("record type does not encode as a JSON object")
	}
	required := make(map[string]bool, len(m))
	for k := range m {
		required[k] = true
	}
	return required, nil
}

// WriteJSONLFile atomically replaces path only after every record and the final
// fsync/close succeed. The pre-existing artifact survives any partial failure.
func WriteJSONLFile[T any](path string, records []T) (int, error) {
	w, err := NewJSONLWriter[T](path)
	if err != nil {
		return 0, err
	}
	for i := range records {
		if err := w.Write(&records[i]); err != nil {
			_ = w.Abort()
			return i, fmt.Errorf("encode %s record %d: %w", path, i, err)
		}
	}
	if err := w.Close(); err != nil {
		return len(records), fmt.Errorf("commit %s: %w", path, err)
	}
	return len(records), nil
}

// WriteJSONFile atomically replaces path with one indented JSON value. Like
// WriteJSONLFile, it syncs and closes the same-directory temporary file before
// publishing it, so callers never expose a truncated object after a failed
// encode/write.
func WriteJSONFile(path string, value any) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir for %s: %w", path, err)
	}
	f, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmp := f.Name()
	committed := false
	defer func() {
		_ = f.Close()
		if !committed {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o644); err != nil {
		return fmt.Errorf("chmod temp for %s: %w", path, err)
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("publish %s: %w", path, err)
	}
	committed = true
	return nil
}

// JSONLWriter streams records into a same-directory temporary file and commits
// by rename on Close. Write takes a pointer so pointer-receiver MarshalJSON /
// TextMarshaler methods are never accidentally bypassed.
type JSONLWriter[T any] struct {
	file      *os.File
	enc       *json.Encoder
	path      string
	tempPath  string
	failed    bool
	committed bool
}

func NewJSONLWriter[T any](path string) (*JSONLWriter[T], error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	f, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("create temp for %s: %w", path, err)
	}
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, fmt.Errorf("chmod temp for %s: %w", path, err)
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	return &JSONLWriter[T]{file: f, enc: enc, path: path, tempPath: f.Name()}, nil
}

func (w *JSONLWriter[T]) Write(rec *T) error {
	if w == nil || w.file == nil || w.committed {
		return fmt.Errorf("jsonl writer is closed")
	}
	if w.failed {
		return fmt.Errorf("jsonl writer is failed")
	}
	if rec == nil {
		w.failed = true
		return fmt.Errorf("nil record")
	}
	if err := w.enc.Encode(rec); err != nil {
		w.failed = true
		return err
	}
	return nil
}

func (w *JSONLWriter[T]) Abort() error {
	if w == nil {
		return nil
	}
	w.failed = true
	var err error
	if w.file != nil {
		err = w.file.Close()
		w.file = nil
	}
	if w.tempPath != "" {
		removeErr := os.Remove(w.tempPath)
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		err = errors.Join(err, removeErr)
	}
	return err
}

func (w *JSONLWriter[T]) Close() error {
	if w == nil || w.committed {
		return nil
	}
	if w.failed {
		return w.Abort()
	}
	if w.file == nil {
		return fmt.Errorf("jsonl writer has no file")
	}
	if err := w.file.Sync(); err != nil {
		w.failed = true
		_ = w.Abort()
		return err
	}
	if err := w.file.Close(); err != nil {
		w.file = nil
		w.failed = true
		_ = os.Remove(w.tempPath)
		return err
	}
	w.file = nil
	if err := os.Rename(w.tempPath, w.path); err != nil {
		w.failed = true
		_ = os.Remove(w.tempPath)
		return err
	}
	w.committed = true
	return nil
}
