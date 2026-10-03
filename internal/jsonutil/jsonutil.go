// Package jsonutil provides strict, bounded, transactional JSONL I/O.
package jsonutil

import (
	"bufio"
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"unicode/utf8"
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
const (
	hardMaxBytes        int64 = 256 << 20
	hardMaxRecords            = 2_000_000
	hardMaxRecordBytes        = 4 << 20
	maxJSONNestingDepth       = 256
)

var StandardLimits = Limits{
	MaxBytes:       hardMaxBytes,
	MaxRecords:     hardMaxRecords,
	MaxRecordBytes: hardMaxRecordBytes,
}

func (l Limits) normalized() (Limits, error) {
	if l.MaxBytes < 0 || l.MaxRecords < 0 || l.MaxRecordBytes < 0 {
		return Limits{}, fmt.Errorf("jsonl: limits must not be negative: bytes=%d records=%d record_bytes=%d", l.MaxBytes, l.MaxRecords, l.MaxRecordBytes)
	}
	if l.MaxBytes == 0 {
		l.MaxBytes = hardMaxBytes
	}
	if l.MaxRecords == 0 {
		l.MaxRecords = hardMaxRecords
	}
	if l.MaxRecordBytes == 0 {
		l.MaxRecordBytes = hardMaxRecordBytes
	}
	if l.MaxBytes > hardMaxBytes || l.MaxRecords > hardMaxRecords || l.MaxRecordBytes > hardMaxRecordBytes {
		return Limits{}, fmt.Errorf("jsonl: limits exceed hard ceiling: bytes<=%d records<=%d record_bytes<=%d", hardMaxBytes, hardMaxRecords, hardMaxRecordBytes)
	}
	return l, nil
}

// ReadJSONL reads strict line-delimited JSON objects. Each non-empty record must
// occupy exactly one physical line. Unknown, duplicate and missing required
// keys at every statically-typed object level are rejected so schema drift
// cannot silently decode to zero values. Duplicate keys at any nesting depth and
// malformed UTF-8 are also rejected before encoding/json can apply last-wins or
// replacement-rune recovery. Limits are enforced before and during decoding.
func ReadJSONL[T any](path string, limits Limits) ([]T, error) {
	var err error
	limits, err = limits.normalized()
	if err != nil {
		return nil, err
	}
	f, st, err := openPinnedRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if st.Size() > limits.MaxBytes {
		return nil, fmt.Errorf("jsonl: %s is %d bytes, exceeds limit %d", path, st.Size(), limits.MaxBytes)
	}
	return decodeJSONLReader[T](f, limits, path)
}

// DecodeJSONL applies the same strict schema and resource policy as ReadJSONL
// to an already-bounded in-memory artifact. It exists for callers that pin and
// digest a file before decoding it; they must not reimplement Scanner behavior
// and drift away from the canonical parser.
func DecodeJSONL[T any](b []byte, limits Limits) ([]T, error) {
	var err error
	limits, err = limits.normalized()
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limits.MaxBytes {
		return nil, fmt.Errorf("jsonl: input is %d bytes, exceeds limit %d", len(b), limits.MaxBytes)
	}
	return decodeJSONLReader[T](bytes.NewReader(b), limits, "input")
}

func decodeJSONLReader[T any](r io.Reader, limits Limits, source string) ([]T, error) {
	inputLimit := &io.LimitedReader{R: r, N: limits.MaxBytes + 1}
	var scanReader io.Reader = inputLimit
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
		if inputLimit.N == 0 {
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
		rec, err := DecodeStrictObject[T](line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		records = append(records, rec)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("jsonl: read %s line %d: %w", source, lineNo+1, err)
	}
	if inputLimit.N == 0 {
		return nil, fmt.Errorf("jsonl: input exceeds byte limit %d", limits.MaxBytes)
	}
	return records, nil
}

// ReadJSONFile reads one strict JSON object under a byte budget. Like ReadJSONL,
// it rejects unknown, duplicate, and missing required keys recursively so a
// reused artifact cannot silently drift schemas. Multiline/pretty-printed JSON
// is allowed because this is an object file, not JSONL. maxBytes can tighten,
// but never relax, the repository-wide artifact ceiling.
func ReadJSONFile[T any](path string, maxBytes int64) (T, error) {
	var out T
	if maxBytes <= 0 || maxBytes > hardMaxBytes {
		return out, fmt.Errorf("json: invalid byte limit %d", maxBytes)
	}
	f, st, err := openPinnedRegularFile(path)
	if err != nil {
		return out, err
	}
	defer func() { _ = f.Close() }()
	if st.Size() > maxBytes {
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
	if !utf8.Valid(b) {
		return out, fmt.Errorf("invalid UTF-8")
	}
	if err := validateJSONStringUnicodeEscapes(b); err != nil {
		return out, err
	}
	if err := validateJSONSyntax(b); err != nil {
		return out, err
	}
	rootType := reflect.TypeOf((*T)(nil)).Elem()
	if err := validateRequiredValue(b, rootType, "$", 0, true); err != nil {
		return out, err
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

func validateJSONStringUnicodeEscapes(b []byte) error {
	for i := 0; i < len(b); i++ {
		if b[i] != '"' {
			continue
		}
		for i++; i < len(b); i++ {
			switch b[i] {
			case '"':
				goto nextString
			case '\\':
				if i+1 >= len(b) {
					return nil // the JSON syntax pass reports the truncated escape.
				}
				i++
				if b[i] != 'u' {
					continue
				}
				code, ok := decodeHex4(b, i+1)
				if !ok {
					return nil // the JSON syntax pass reports malformed hex/length.
				}
				i += 4
				switch {
				case code >= 0xD800 && code <= 0xDBFF:
					if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
						return fmt.Errorf("invalid Unicode surrogate pair in JSON string")
					}
					low, ok := decodeHex4(b, i+3)
					if !ok || low < 0xDC00 || low > 0xDFFF {
						return fmt.Errorf("invalid Unicode surrogate pair in JSON string")
					}
					i += 6
				case code >= 0xDC00 && code <= 0xDFFF:
					return fmt.Errorf("unpaired low Unicode surrogate in JSON string")
				}
			}
		}
		return nil // syntax pass reports an unterminated string.
	nextString:
	}
	return nil
}

func decodeHex4(b []byte, start int) (uint16, bool) {
	if start < 0 || start+4 > len(b) {
		return 0, false
	}
	var out uint16
	for i := start; i < start+4; i++ {
		out <<= 4
		switch c := b[i]; {
		case c >= '0' && c <= '9':
			out |= uint16(c - '0')
		case c >= 'a' && c <= 'f':
			out |= uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			out |= uint16(c-'A') + 10
		default:
			return 0, false
		}
	}
	return out, true
}

func validateJSONSyntax(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := walkJSONValue(dec, 0, "$", true); err != nil {
		return err
	}
	return requireDecoderEOF(dec)
}

func walkJSONValue(dec *json.Decoder, depth int, path string, root bool) error {
	if depth > maxJSONNestingDepth {
		return fmt.Errorf("JSON nesting exceeds limit %d at %s", maxJSONNestingDepth, path)
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, isDelim := tok.(json.Delim)
	if root && (!isDelim || delim != '{') {
		return fmt.Errorf("record must be a JSON object")
	}
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("object key is not a string at %s", path)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate key %q at %s", key, path)
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(dec, depth+1, jsonPath(path, key), false); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("malformed object at %s", path)
		}
		return nil
	case '[':
		index := 0
		for dec.More() {
			if err := walkJSONValue(dec, depth+1, fmt.Sprintf("%s[%d]", path, index), false); err != nil {
				return err
			}
			index++
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("malformed array at %s", path)
		}
		return nil
	default:
		return fmt.Errorf("unexpected delimiter %q at %s", delim, path)
	}
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

var (
	jsonUnmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	textUnmarshalerType = reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()
	rawMessageType      = reflect.TypeOf(json.RawMessage{})
	structSchemaCache   sync.Map // reflect.Type -> *strictStructSchema
)

type strictStructSchema struct {
	required map[string]struct{}
	fields   map[string]reflect.Type
	err      error
}

func validateRequiredValue(raw []byte, t reflect.Type, path string, depth int, root bool) error {
	if depth > maxJSONNestingDepth {
		return fmt.Errorf("JSON nesting exceeds limit %d at %s", maxJSONNestingDepth, path)
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return fmt.Errorf("empty JSON value at %s", path)
	}
	for t.Kind() == reflect.Pointer {
		if bytes.Equal(raw, []byte("null")) {
			if root {
				return fmt.Errorf("record must be a JSON object")
			}
			return nil
		}
		t = t.Elem()
	}
	if root && t.Kind() != reflect.Struct {
		return fmt.Errorf("record type %s does not encode as a JSON object", t)
	}
	if bytes.Equal(raw, []byte("null")) {
		switch t.Kind() {
		case reflect.Interface, reflect.Map, reflect.Slice:
			return nil
		default:
			return fmt.Errorf("null is not valid for required %s at %s", t, path)
		}
	}
	if isOpaqueJSONType(t) {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
			if err == nil {
				err = fmt.Errorf("expected object")
			}
			return fmt.Errorf("%s: %w", path, err)
		}
		schema := strictSchemaForType(t)
		if schema.err != nil {
			return fmt.Errorf("derive schema for %s: %w", path, schema.err)
		}
		for key := range schema.required {
			if _, ok := obj[key]; !ok {
				return fmt.Errorf("missing required key %q at %s", key, path)
			}
		}
		for key, value := range obj {
			if ft, ok := schema.fields[key]; ok {
				if err := validateRequiredValue(value, ft, jsonPath(path, key), depth+1, false); err != nil {
					return err
				}
			}
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return nil // encoding/json treats []byte as base64 text, not a JSON array.
		}
		fallthrough
	case reflect.Array:
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for i := range values {
			if err := validateRequiredValue(values[i], t.Elem(), fmt.Sprintf("%s[%d]", path, i), depth+1, false); err != nil {
				return err
			}
		}
	case reflect.Map:
		var values map[string]json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for key, value := range values {
			if err := validateRequiredValue(value, t.Elem(), jsonPath(path, key), depth+1, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func isOpaqueJSONType(t reflect.Type) bool {
	if t == rawMessageType || t.Implements(jsonUnmarshalerType) || t.Implements(textUnmarshalerType) {
		return true
	}
	return reflect.PointerTo(t).Implements(jsonUnmarshalerType) || reflect.PointerTo(t).Implements(textUnmarshalerType)
}

func requiredJSONKeysForType(t reflect.Type) (map[string]struct{}, error) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("%s is not a struct", t)
	}
	b, err := json.Marshal(reflect.Zero(t).Interface())
	if err != nil {
		return nil, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil || obj == nil {
		if err == nil {
			err = fmt.Errorf("zero value does not encode as object")
		}
		return nil, err
	}
	out := make(map[string]struct{}, len(obj))
	for key := range obj {
		out[key] = struct{}{}
	}
	return out, nil
}

func strictSchemaForType(t reflect.Type) *strictStructSchema {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if cached, ok := structSchemaCache.Load(t); ok {
		return cached.(*strictStructSchema)
	}
	required, err := requiredJSONKeysForType(t)
	schema := &strictStructSchema{
		required: required,
		fields:   jsonFieldTypes(t),
		err:      err,
	}
	actual, _ := structSchemaCache.LoadOrStore(t, schema)
	return actual.(*strictStructSchema)
}

func jsonFieldTypes(t reflect.Type) map[string]reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	out := make(map[string]reflect.Type)
	if t.Kind() != reflect.Struct {
		return out
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" && !f.Anonymous {
			continue
		}
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if f.Anonymous && name == "" {
			embedded := f.Type
			for embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct && !isOpaqueJSONType(embedded) {
				for key, ft := range jsonFieldTypes(embedded) {
					if _, exists := out[key]; !exists {
						out[key] = ft
					}
				}
				continue
			}
		}
		if name == "" {
			name = f.Name
		}
		if _, exists := out[name]; !exists {
			out[name] = f.Type
		}
	}
	return out
}

func jsonPath(parent, key string) string {
	if key == "" {
		return parent
	}
	return parent + "." + key
}

func openPinnedRegularFile(path string) (*os.File, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("json: %s is not a regular non-symlink file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	opened, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("stat opened %s: %w", path, err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = f.Close()
		return nil, nil, fmt.Errorf("json: %s changed while being opened", path)
	}
	return f, opened, nil
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
	tmpInfo, err := f.Stat()
	if err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("stat temp for %s: %w", path, err)
	}
	committed := false
	defer func() {
		_ = f.Close()
		if !committed {
			_, _ = removeFileIfSame(tmp, tmpInfo)
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
	exists, same, err := filePathHasIdentity(tmp, tmpInfo)
	if err != nil {
		return fmt.Errorf("verify temp for %s: %w", path, err)
	}
	if !exists || !same {
		return fmt.Errorf("temp for %s changed before publication", path)
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
	tempInfo  os.FileInfo
	failed    bool
	committed bool
}

func NewJSONLWriter[T any](path string) (*JSONLWriter[T], error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir for %s: %w", path, err)
	}
	f, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("create temp for %s: %w", path, err)
	}
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, fmt.Errorf("chmod temp for %s: %w", path, err)
	}
	tempInfo, err := f.Stat()
	if err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, fmt.Errorf("stat temp for %s: %w", path, err)
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	return &JSONLWriter[T]{file: f, enc: enc, path: path, tempPath: f.Name(), tempInfo: tempInfo}, nil
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
		_, removeErr := removeFileIfSame(w.tempPath, w.tempInfo)
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
		_, _ = removeFileIfSame(w.tempPath, w.tempInfo)
		return err
	}
	w.file = nil
	exists, same, err := filePathHasIdentity(w.tempPath, w.tempInfo)
	if err != nil {
		w.failed = true
		return err
	}
	if !exists || !same {
		w.failed = true
		return fmt.Errorf("jsonl writer temp changed before publication")
	}
	if err := os.Rename(w.tempPath, w.path); err != nil {
		w.failed = true
		_, _ = removeFileIfSame(w.tempPath, w.tempInfo)
		return err
	}
	w.committed = true
	return nil
}

func filePathHasIdentity(path string, want os.FileInfo) (exists bool, same bool, err error) {
	if path == "" || want == nil {
		return false, false, nil
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return true, false, nil
	}
	return true, os.SameFile(info, want), nil
}

func removeFileIfSame(path string, want os.FileInfo) (bool, error) {
	exists, same, err := filePathHasIdentity(path, want)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	if !same {
		return false, fmt.Errorf("refusing to remove changed temp file %s", path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return true, nil
}
