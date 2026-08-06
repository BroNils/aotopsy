package pipeline

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/snapshot"
	"aotopsy/internal/strutil"
)

// CodeNameInfo holds resolved function and owner names for a code ref.
type CodeNameInfo struct {
	FuncName   string
	OwnerName  string
	ParamCount int // total visible parameters (fixed + optional, excluding implicit 'this')
}

// PoolLookups holds the lookup maps needed for pool entry resolution.
type PoolLookups struct {
	RefToStr       map[int]string
	RefToNamed     map[int]*cluster.NamedObject
	RefCID         map[int]int
	CodeRefDisplay map[int]string
	CodeNames      map[int]CodeNameInfo
	VmRefToStr     map[int]string // VM snapshot strings by ref ID
	VmRefCID       map[int]int    // VM snapshot CID by ref ID
	VmRefToNamed   map[int]*cluster.NamedObject
	CT             *snapshot.CIDTable
	BaseObjLimit   int
}

// BuildPoolLookups builds the lookup maps from a fill result.
// vmResult is optional — if non-nil, VM snapshot strings/names are used to resolve base object refs.
// codeIndexOneBased must be true for Dart ≥2.16 (see VersionProfile.CodeIndexOneBased).
func BuildPoolLookups(result *cluster.Result, ct *snapshot.CIDTable, vmResult *cluster.Result, codeIndexOneBased bool) *PoolLookups {
	l := &PoolLookups{
		RefToStr:       make(map[int]string),
		RefToNamed:     make(map[int]*cluster.NamedObject),
		RefCID:         make(map[int]int),
		CodeRefDisplay: make(map[int]string),
		VmRefToStr:     make(map[int]string),
		VmRefCID:       make(map[int]int),
		VmRefToNamed:   make(map[int]*cluster.NamedObject),
		CT:             ct,
		BaseObjLimit:   int(result.Header.NumBaseObjects) + 1,
	}

	for _, ps := range result.Strings {
		l.RefToStr[ps.RefID] = ps.Value
	}
	for i := range result.Named {
		no := &result.Named[i]
		l.RefToNamed[no.RefID] = no
	}
	for _, cm := range result.Clusters {
		for ref := cm.StartRef; ref < cm.StopRef; ref++ {
			l.RefCID[ref] = cm.CID
		}
	}

	// Populate VM lookups from VM snapshot result.
	if vmResult != nil {
		for _, ps := range vmResult.Strings {
			l.VmRefToStr[ps.RefID] = ps.Value
		}
		for i := range vmResult.Named {
			no := &vmResult.Named[i]
			l.VmRefToNamed[no.RefID] = no
		}
		for _, cm := range vmResult.Clusters {
			for ref := cm.StartRef; ref < cm.StopRef; ref++ {
				l.VmRefCID[ref] = cm.CID
			}
		}
	}

	// Build FunctionType ref→info lookup for parameter count resolution.
	funcTypeByRef := make(map[int]*cluster.FuncTypeInfo, len(result.FuncTypes))
	for i := range result.FuncTypes {
		ft := &result.FuncTypes[i]
		funcTypeByRef[ft.RefID] = ft
	}

	byCodeIndex := CodeIndexToFunc(result, ct, codeIndexOneBased)

	// Build code ref→name.
	l.CodeNames = make(map[int]CodeNameInfo)
	for _, ce := range result.Codes {
		owner, ok := ResolveCodeOwner(ce, l.RefToNamed, byCodeIndex)
		if !ok {
			continue
		}
		ci := CodeNameInfo{
			FuncName:  l.ResolveName(owner),
			OwnerName: l.ResolveOwnerName(owner),
		}
		// Follow Function→FunctionType chain for parameter count.
		if owner.SignatureRefID > 0 {
			if ft, ok := funcTypeByRef[owner.SignatureRefID]; ok {
				ci.ParamCount = ft.NumFixed + ft.NumOptional
			}
		}
		l.CodeNames[ce.RefID] = ci
	}
	for _, ce := range result.Codes {
		ci := l.CodeNames[ce.RefID]
		if ci.FuncName != "" {
			if ci.OwnerName != "" {
				l.CodeRefDisplay[ce.RefID] = ci.OwnerName + "." + ci.FuncName
			} else {
				l.CodeRefDisplay[ce.RefID] = ci.FuncName
			}
		}
	}

	return l
}

// CodeIndexToFunc maps a Code's ClusterIndex to its unambiguous owning
// Function NamedObject via the Function->CodeIndex direction (the
// REVERSE of Code.OwnerRef). This is the reliable cross-reference
// cmd/aotopsy/refinfo.go's findOwnerViaCodeIndex already validated by
// hand: Code.OwnerRef is confirmed unreliable for some real snapshots
// (e.g. Dart 3.7.0 x86_64 produces a bogus shared OwnerRef for ~5.4% of
// all functions, all resolving to CID 61/Mint, which is never a legal
// Code owner), while Function.CodeIndex == Code.ClusterIndex has not
// shown this failure mode. A ClusterIndex is dropped (left unmapped,
// not guessed) if more than one Function claims it, so ambiguous cases
// fall back to the OwnerRef-based lookup in ResolveCodeOwner instead of
// picking one arbitrarily. Exported so every direct Code.OwnerRef
// consumer in cmd/aotopsy (graph/parity/thr-audit/decompile-native's
// --from-main library classification) can share this same reliable
// cross-reference instead of trusting the buggy field directly.
//
// codeIndexOneBased must be true for Dart ≥2.16 (Function.code_index is
// 1-based: 0=LazyCompile stub, 1+=Code cluster index). For ≤2.15 it is
// 0-based (direct ref into Code cluster). See VersionProfile.CodeIndexOneBased.
func CodeIndexToFunc(result *cluster.Result, ct *snapshot.CIDTable, codeIndexOneBased bool) map[int]*cluster.NamedObject {
	if ct == nil {
		return nil
	}
	m := make(map[int]*cluster.NamedObject)
	ambiguous := make(map[int]bool)
	for i := range result.Named {
		no := &result.Named[i]
		if no.CID != ct.Function || no.CodeIndex < 0 {
			continue
		}
		// Convert Function.code_index (1-based for ≥2.16) to Code.ClusterIndex (0-based).
		clusterIdx := no.CodeIndex
		if codeIndexOneBased {
			clusterIdx = no.CodeIndex - 1
		}
		if clusterIdx < 0 {
			continue // code_index 0 = LazyCompile stub (≥2.16), no Code object
		}
		if _, exists := m[clusterIdx]; exists {
			ambiguous[clusterIdx] = true
			continue
		}
		m[clusterIdx] = no
	}
	for idx := range ambiguous {
		delete(m, idx)
	}
	return m
}

// ResolveCodeOwner finds the Function/Closure/FfiTrampolineData
// NamedObject that owns ce, preferring the reliable CodeIndex
// cross-reference (see CodeIndexToFunc's doc comment) over the
// documented-unreliable Code.OwnerRef, and falling back to OwnerRef
// only when no CodeIndex match exists (e.g. deferred code with
// ClusterIndex == -1, or Dart versions/architectures where the
// cross-reference wasn't populated) -- so this is a strict correctness
// improvement, never a regression versus the old OwnerRef-only lookup.
func ResolveCodeOwner(ce cluster.CodeEntry, refToNamed map[int]*cluster.NamedObject, byCodeIndex map[int]*cluster.NamedObject) (*cluster.NamedObject, bool) {
	if ce.ClusterIndex >= 0 {
		if owner, ok := byCodeIndex[ce.ClusterIndex]; ok {
			return owner, true
		}
	}
	if ce.OwnerRef <= 0 {
		return nil, false
	}
	owner, ok := refToNamed[ce.OwnerRef]
	return owner, ok
}

func (l *PoolLookups) ResolveName(no *cluster.NamedObject) string {
	if no.NameRefID >= 0 {
		if s, ok := l.RefToStr[no.NameRefID]; ok {
			return s
		}
	}
	return ""
}

func (l *PoolLookups) ResolveVMName(no *cluster.NamedObject) string {
	if no.NameRefID >= 0 {
		if s, ok := l.VmRefToStr[no.NameRefID]; ok {
			return s
		}
	}
	return ""
}

func (l *PoolLookups) ResolveOwnerName(no *cluster.NamedObject) string {
	if no.OwnerRefID < 0 {
		return ""
	}
	if owner, ok := l.RefToNamed[no.OwnerRefID]; ok {
		return l.ResolveName(owner)
	}
	return ""
}

// QualifiedCodeName returns "Owner.Func_hexaddr" for a code refID using PoolLookups.
func QualifiedCodeName(refID int, pl *PoolLookups, pcOffset uint32) string {
	ci := pl.CodeNames[refID]
	return QualifiedName(ci.OwnerName, ci.FuncName, pcOffset)
}

// TypeParamResolver resolves a FunctionType's real per-parameter type
// names via its parameter_types Array (see cluster.FuncTypeInfo.
// ParamTypesArrayRefID's doc comment and snapshot.VersionProfile.
// FuncTypeParamTypesIdx for which Dart versions this is captured for).
// Caches Array/Type lookups once so repeated calls (e.g. once per
// top-level function) don't rebuild the same maps.
//
// KNOWN GAP, not silently papered over: an element ref only resolves to
// a real class name when it lands in Result.Types, which itself is only
// populated for the v3.x "flags-packed ClassID" Type encoding (see
// internal/cluster/fillspec.go's specType). Pre-3.x snapshots (where
// type_class_id is its own separate ref -- TypeClassIdIsRef=true in the
// version profile) have NO Type->ClassID resolution implemented
// anywhere in this pipeline yet. Confirmed empirically, not assumed: a
// real Dart 2.12.0 sample resolved 0/202 sampled parameter_types
// elements (Result.Types was simply empty for it, not an indexing
// mistake -- real Dart 3.7.0 and 3.10.7 samples resolved ~70% of
// theirs). Elements that don't resolve report "?" rather than silently
// omitting the parameter, so callers can tell "no type info" from "void
// parameter list" from "empty display".
type TypeParamResolver struct {
	arrayByRef map[int]*cluster.ArrayInfo
	typeByRef  map[int]int32
	result     *cluster.Result
	pl         *PoolLookups
}

// NewTypeParamResolver builds the resolver's caches once from an
// already-parsed Result/PoolLookups pair.
func NewTypeParamResolver(result *cluster.Result, pl *PoolLookups) *TypeParamResolver {
	r := &TypeParamResolver{result: result, pl: pl}
	r.arrayByRef = make(map[int]*cluster.ArrayInfo, len(result.Arrays))
	for i := range result.Arrays {
		r.arrayByRef[result.Arrays[i].RefID] = &result.Arrays[i]
	}
	r.typeByRef = make(map[int]int32, len(result.Types))
	for _, t := range result.Types {
		r.typeByRef[t.RefID] = t.ClassID
	}
	return r
}

// ParamTypeNames returns one display name per parameter in
// ft.ParamTypesArrayRefID's Array, or nil if ft has no captured
// parameter_types ref for this Dart version.
func (r *TypeParamResolver) ParamTypeNames(ft cluster.FuncTypeInfo) []string {
	if ft.ParamTypesArrayRefID < 0 {
		return nil
	}
	arr, ok := r.arrayByRef[ft.ParamTypesArrayRefID]
	if !ok {
		return nil
	}
	names := make([]string, len(arr.ElementRefIDs))
	for i, elemRef := range arr.ElementRefIDs {
		cid, ok := r.typeByRef[elemRef]
		if !ok {
			names[i] = "?"
			continue
		}
		names[i] = r.classDisplayName(cid)
	}
	return names
}

// classDisplayName resolves a ClassID to a name, trying (in order) the
// isolate string pool, the VM (core-library) string pool, then falling
// back to cluster.CidNameV for predefined/builtin classes with no
// snapshot-side Class record name -- mirrors cmd/aotopsy/refinfo.go's
// classNameByCID.
func (r *TypeParamResolver) classDisplayName(cid int32) string {
	for i := range r.result.Classes {
		if r.result.Classes[i].ClassID != cid {
			continue
		}
		ci := r.result.Classes[i]
		if no, ok := r.pl.RefToNamed[ci.RefID]; ok {
			if s := r.pl.ResolveName(no); s != "" {
				return s
			}
			if s := r.pl.ResolveVMName(no); s != "" {
				return s
			}
		}
		break
	}
	if r.pl.CT != nil {
		if s := cluster.CidNameV(int(cid), r.pl.CT); s != "" {
			return s
		}
	}
	return fmt.Sprintf("<cid:%d>", cid)
}

// ResolvePoolDisplay builds a map from pool entry index to display string.
func ResolvePoolDisplay(pool []cluster.PoolEntry, l *PoolLookups) map[int]string {
	display := make(map[int]string, len(pool))
	for _, pe := range pool {
		switch pe.Kind {
		case cluster.PoolTagged:
			// Only quote as a string if the pool entry's actual object
			// type is a String (C-1 fix): previously any RefToStr match
			// was quoted, but a non-string object (Instance, Class, etc.)
			// can have a RefToStr entry at the same ref ID, producing
			// false positive string references that inflate signal
			// counts and mislead the signal report.
			isStringCID := false
			if l.CT != nil {
				if cid, ok := l.RefCID[pe.RefID]; ok {
					isStringCID = cid == l.CT.OneByteString || cid == l.CT.TwoByteString
				}
			}
			if isStringCID {
				if s, ok := l.RefToStr[pe.RefID]; ok {
					display[pe.Index] = fmt.Sprintf("%q", s)
				}
			} else if no, ok := l.RefToNamed[pe.RefID]; ok {
				name := l.ResolveName(no)
				if name == "" {
					// ResolveName only checks the app-isolate string table
					// (RefToStr). A NamedObject's NameRefID can just as
					// well point into the VM-isolate base-object region
					// instead (shared objects/strings common across every
					// app using this Dart SDK build) -- confirmed a real,
					// same-class gap as the one fixed in LoadContext/
					// decompile_native_cmd.go for pool-level VmRefToStr
					// lookups: this call site never tried ResolveVMName as
					// a fallback, so a resolvable name here still fell
					// through to a generic "<ClassName>" placeholder.
					// cmd/aotopsy/refinfo.go's listToplevelFunctions
					// already uses exactly this ResolveName-then-
					// ResolveVMName fallback pattern; mirrored here.
					name = l.ResolveVMName(no)
				}
				if name != "" {
					// Fields share leaf names across owners (e.g. uHb on Wja, Yja, aka).
					// Qualify with owner when available so pool dumps disambiguate them.
					if l.CT != nil && no.CID == l.CT.Field {
						if owner := l.ResolveOwnerName(no); owner != "" {
							name = owner + "." + name
						}
					}
					display[pe.Index] = name
				} else {
					display[pe.Index] = fmt.Sprintf("<%s>", cluster.CidNameV(no.CID, l.CT))
				}
			} else if fn, ok := l.CodeRefDisplay[pe.RefID]; ok {
				display[pe.Index] = fn
			} else if cidNum, ok := l.RefCID[pe.RefID]; ok {
				cidName := cluster.CidNameV(cidNum, l.CT)
				if cidName != "" {
					display[pe.Index] = fmt.Sprintf("<%s>", cidName)
				} else {
					display[pe.Index] = fmt.Sprintf("<Instance_%d>", cidNum)
				}
			} else if pe.RefID == 1 {
				display[pe.Index] = "null"
			} else if pe.RefID > 0 && pe.RefID < l.BaseObjLimit {
				// Try resolving from VM snapshot lookups.
				// H-4 fix: check VmRefCID before quoting as string, same as
				// the app-isolate C-1 fix above. Without this, non-string VM
				// base objects (Instance, Class, etc.) that happen to have a
				// VmRefToStr entry get falsely quoted as strings.
				if s, ok := l.VmRefToStr[pe.RefID]; ok {
					isVMStringCID := false
					if l.CT != nil {
						if cid, ok2 := l.VmRefCID[pe.RefID]; ok2 {
							isVMStringCID = cid == l.CT.OneByteString || cid == l.CT.TwoByteString
						}
					}
					if isVMStringCID {
						display[pe.Index] = fmt.Sprintf("%q", s)
					} else {
						display[pe.Index] = s
					}
				} else if no, ok := l.VmRefToNamed[pe.RefID]; ok {
					name := l.ResolveVMName(no)
					if name != "" {
						display[pe.Index] = name
					} else {
						display[pe.Index] = fmt.Sprintf("<vm:%s>", cluster.CidNameV(no.CID, l.CT))
					}
				} else if cidNum, ok := l.VmRefCID[pe.RefID]; ok {
					cidName := cluster.CidNameV(cidNum, l.CT)
					if cidName != "" {
						display[pe.Index] = fmt.Sprintf("<vm:%s>", cidName)
					} else {
						display[pe.Index] = fmt.Sprintf("<vm:%d>", pe.RefID)
					}
				} else {
					display[pe.Index] = fmt.Sprintf("<vm:%d>", pe.RefID)
				}
			} else {
				display[pe.Index] = fmt.Sprintf("<ref:%d>", pe.RefID)
			}
		case cluster.PoolImmediate:
			display[pe.Index] = fmt.Sprintf("0x%x", pe.Imm)
		}
	}
	return display
}

// DartClassLayout is a resolved class definition ready for export.
type DartClassLayout struct {
	ClassName    string            `json:"class_name"`
	ClassID      int32             `json:"class_id"`
	InstanceSize int32             `json:"instance_size"`
	Fields       []DartFieldLayout `json:"fields"`
}

// DartFieldLayout is one field in a DartClassLayout.
type DartFieldLayout struct {
	Name       string `json:"name"`
	ByteOffset int32  `json:"byte_offset"`
}

// BuildClassLayouts joins ClassInfo + FieldInfo + string lookups into class layouts.
func BuildClassLayouts(result *cluster.Result, pl *PoolLookups, compressedPtrs bool) []DartClassLayout {
	var wordSize int32 = 8
	if compressedPtrs {
		wordSize = 4
	}

	classByRef := make(map[int]*cluster.ClassInfo, len(result.Classes))
	for i := range result.Classes {
		ci := &result.Classes[i]
		classByRef[ci.RefID] = ci
	}

	type resolvedField struct {
		nameRefID  int
		byteOffset int32
	}
	fieldsByOwner := make(map[int][]resolvedField)
	for _, fi := range result.Fields {
		if fi.OwnerRefID <= 0 || fi.HostOffset < 0 {
			continue
		}
		offsetRef := int(fi.HostOffset)
		wordOff, ok := result.MintValues[offsetRef]
		if !ok {
			continue
		}
		fieldsByOwner[fi.OwnerRefID] = append(fieldsByOwner[fi.OwnerRefID], resolvedField{
			nameRefID:  fi.NameRefID,
			byteOffset: int32(wordOff) * wordSize,
		})
	}

	var layouts []DartClassLayout
	for _, ci := range result.Classes {
		if ci.InstanceSize <= 0 {
			continue
		}
		className := ""
		if ci.NameRefID >= 0 {
			if s, ok := pl.RefToStr[ci.NameRefID]; ok {
				className = s
			}
		}
		if className == "" {
			continue
		}

		layout := DartClassLayout{
			ClassName:    className,
			ClassID:      ci.ClassID,
			InstanceSize: ci.InstanceSize * wordSize,
		}

		if rfs, ok := fieldsByOwner[ci.RefID]; ok {
			for _, rf := range rfs {
				fieldName := ""
				if rf.nameRefID >= 0 {
					if s, ok := pl.RefToStr[rf.nameRefID]; ok {
						fieldName = s
					}
				}
				if fieldName == "" {
					fieldName = fmt.Sprintf("field_0x%x", rf.byteOffset)
				}
				layout.Fields = append(layout.Fields, DartFieldLayout{
					Name:       fieldName,
					ByteOffset: rf.byteOffset,
				})
			}
		} else {
			byteSize := ci.InstanceSize * wordSize
			for off := wordSize; off+wordSize <= byteSize; off += wordSize {
				layout.Fields = append(layout.Fields, DartFieldLayout{
					Name:       fmt.Sprintf("f_0x%x", off),
					ByteOffset: off,
				})
			}
		}

		sort.Slice(layout.Fields, func(i, j int) bool {
			return layout.Fields[i].ByteOffset < layout.Fields[j].ByteOffset
		})

		layouts = append(layouts, layout)
	}
	return layouts
}

// QualifiedName builds "Owner.FuncName_hexaddr" like blutter.
func QualifiedName(ownerName, funcName string, pcOffset uint32) string {
	suffix := fmt.Sprintf("_%x", pcOffset)
	if funcName == "" {
		return "sub" + suffix
	}
	if ownerName != "" {
		return ownerName + "." + funcName + suffix
	}
	return funcName + suffix
}

// SanitizeFilename makes a string safe for use as a filename.
// Strips non-printable runes and replaces filesystem-unsafe characters.
// SanitizeFilename delegates to the shared strutil.SanitizeFilename.
// Kept for backward compatibility — all callers should eventually use
// strutil.SanitizeFilename directly. (P4-5)
func SanitizeFilename(name string) string {
	return strutil.SanitizeFilename(name)
}

// FuncRelPath returns a relative path like "OwnerClass/funcName_hex" for functions
// with an owner, or "funcName_hex" for ownerless functions.
func FuncRelPath(ownerName, funcName string, pcOffset uint32) string {
	suffix := fmt.Sprintf("_%x", pcOffset)
	var fpart string
	if funcName == "" {
		fpart = "sub" + suffix
	} else {
		fpart = SanitizeFilename(funcName + suffix)
	}
	if ownerName != "" {
		return SanitizeFilename(ownerName) + "/" + fpart
	}
	return fpart
}

// FuncRelPathFromQualified reconstructs the relative path from a qualified name
// and its owner. Used by post-disasm commands (signal, decompile).
func FuncRelPathFromQualified(qualifiedName, owner string) string {
	if owner != "" {
		prefix := owner + "."
		funcPart := qualifiedName
		if strings.HasPrefix(qualifiedName, prefix) {
			funcPart = qualifiedName[len(prefix):]
		}
		return SanitizeFilename(owner) + "/" + SanitizeFilename(funcPart)
	}
	return SanitizeFilename(qualifiedName)
}

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

// DisasmIndexEntry is the per-function index record written to index.jsonl.
type DisasmIndexEntry struct {
	Name      string `json:"name"`
	OwnerName string `json:"owner_name,omitempty"`
	RefID     int    `json:"ref_id"`
	OwnerRef  int    `json:"owner_ref,omitempty"`
	PCOffset  uint32 `json:"pc_offset"`
	Size      uint32 `json:"size"`
	File      string `json:"file"`
}

// DartMetaJSON is the structure written to dart_meta.json.
type DartMetaJSON struct {
	DartVersion        string             `json:"dart_version"`
	CompressedPointers bool               `json:"compressed_pointers"`
	PointerSize        int                `json:"pointer_size"`
	THRFields          []DartMetaTHRField `json:"thr_fields"`
}

// DartMetaTHRField is a THR field entry for dart_meta.json.
type DartMetaTHRField struct {
	Offset int    `json:"offset"`
	Name   string `json:"name"`
}

// WriteDartMeta writes dart_meta.json with snapshot metadata.
func WriteDartMeta(outDir, dartVersion string, compressed bool, ptrSize int, thrFields map[int]string) error {
	fields := make([]DartMetaTHRField, 0, len(thrFields))
	for off, name := range thrFields {
		fields = append(fields, DartMetaTHRField{Offset: off, Name: name})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Offset < fields[j].Offset })

	meta := DartMetaJSON{
		DartVersion:        dartVersion,
		CompressedPointers: compressed,
		PointerSize:        ptrSize,
		THRFields:          fields,
	}

	f, err := os.Create(filepath.Join(outDir, "dart_meta.json"))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(meta); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// NormalizeHexAddr strips leading zeros: "0x000652e4" → "0x652e4".
func NormalizeHexAddr(s string) string {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return s
	}
	v, err := strconv.ParseUint(s[2:], 16, 64)
	if err != nil {
		return s
	}
	return fmt.Sprintf("0x%x", v)
}

// ParseHexAddr parses "0x..." hex address strings. Returns 0 on failure.
func ParseHexAddr(s string) uint64 {
	s = strings.TrimPrefix(s, "0x")
	v, _ := strconv.ParseUint(s, 16, 64)
	return v
}

// AsmCommentRe matches annotated asm lines: address + instruction + "; comment"
var AsmCommentRe = regexp.MustCompile(`^(0x[0-9a-fA-F]+)\s+.*;\s+(.+)$`)

// ExtractAsmComments parses all .txt files in asmDir for instruction-level annotations.
func ExtractAsmComments(asmDir string) ([]FlutterMetaComment, error) {
	entries, err := os.ReadDir(asmDir)
	if err != nil {
		return nil, err
	}

	var comments []FlutterMetaComment
	seen := make(map[string]bool)

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		path := filepath.Join(asmDir, entry.Name())
		fc, err := extractFileComments(path, seen)
		if err != nil {
			continue
		}
		comments = append(comments, fc...)
	}

	return comments, nil
}

func extractFileComments(path string, seen map[string]bool) ([]FlutterMetaComment, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var comments []FlutterMetaComment
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		m := AsmCommentRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		addr := NormalizeHexAddr(m[1])
		text := strings.TrimSpace(m[2])

		if strings.HasPrefix(text, "<") && strings.HasSuffix(text, ">") {
			continue
		}

		if seen[addr] {
			continue
		}
		seen[addr] = true

		comments = append(comments, FlutterMetaComment{
			Addr: addr,
			Text: text,
		})
	}

	return comments, scanner.Err()
}

// IsInterestingCallee returns true if the callee name represents a real named
// function rather than VM internals, stubs, or dispatch noise.
func IsInterestingCallee(name string) bool {
	if name == "" {
		return false
	}
	switch {
	case len(name) > 4 && name[:4] == "sub_":
		return false
	case len(name) > 2 && name[0] == '0' && name[1] == 'x':
		return false
	case name == "dispatch_table" || name == "object_field":
		return false
	case len(name) > 4 && name[:4] == "THR.":
		return false
	case len(name) > 3 && name[:3] == "PP[":
		return false
	}
	return true
}

// FlutterMetaComment is a comment entry for flutter_meta.json.
type FlutterMetaComment struct {
	Addr string `json:"addr"`
	Text string `json:"text"`
}
