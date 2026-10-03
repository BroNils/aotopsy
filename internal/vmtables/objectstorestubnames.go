package vmtables

// ObjectStoreStubField is one `RW(Code, <name>_stub)` entry in the isolate
// roots section: its index among the serialized ObjectStore fields, and the
// field's name.
type ObjectStoreStubField = objectStoreStubField

// ObjectStoreStubFields returns the isolate stub fields for a Dart version,
// or nil when the version has no verified table -- in which case callers must
// name nothing rather than guess, exactly as VMStubNamesInImageOrder does.
//
// The index is a position in cluster.Result.ObjectStoreRefs, so
// `ObjectStoreRefs[f.Index]` is the ref of the Code implementing `f.Name`.
//
// This is the only place an isolate stub's identity survives an AOT snapshot.
// Their Code objects have a null owner -- verified on dart-3.9.2-gt-arm64,
// where all 85 unnamed ranges are `_iso_stub_*` in the ELF symbol table and
// none of them has an owner the cluster parser captured.
func ObjectStoreStubFields(dartVersion string) []ObjectStoreStubField {
	return objectStoreStubFields[dartVersion]
}

// ObjectStoreRecordFieldNamesIndex returns the root index of ObjectStore's
// record_field_names array for a Dart version. The table is generated from the
// exact serialized from()..to_snapshot(kFullAOT) field range; false means the
// field is absent or outside that range and callers must not guess an index.
func ObjectStoreRecordFieldNamesIndex(dartVersion string) (int, bool) {
	idx, ok := objectStoreRecordFieldNamesIndex[dartVersion]
	return idx, ok
}
