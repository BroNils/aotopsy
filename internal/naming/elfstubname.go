package naming

import "strings"

// ElfStubName is the last naming attempt for a Code the snapshot could not
// name at all.
//
// After every snapshot-side path has run, what is left are Codes whose owner
// is genuinely null: 86 on the 3.12.2 x86_64 sample and 85 on its ARM64
// twin, all of them VM or isolate stubs. dart-lang/sdk only names those by
// matching an entry point against a table compiled into the VM
// (StubCode::NameOfStub, stub_code.cc), and that table is not in the
// snapshot. Worth checking before assuming otherwise: the stub Codes ARE
// added as base objects -- but only under
//
//	if (!Snapshot::IncludesCode(d->kind())) {          // app_snapshot.cc
//	  for (...) d->AddBaseObject(StubCode::EntryAt(i).ptr());
//	}
//
// and an AOT snapshot includes code, so that branch never runs for these
// samples. The base-object name table cannot reach them.
//
// The ELF symbol table can, when the build kept one. Every one of the 86
// has an exact `.symtab` entry.
//
// This is a last resort on purpose. Recovering names without symbols is what
// the tool is for, and production builds are stripped -- so a symbol-derived
// name must never stand in for a snapshot-derived one, or the corpus numbers
// would silently start measuring the linker instead of the analysis. It is
// therefore reached only when funcName is empty, never to override or
// "improve" a name the snapshot produced.
func ElfStubName(syms map[uint64]string, funcVA uint64, fallback string) string {
	if len(syms) == 0 {
		return fallback
	}
	name, ok := syms[funcVA]
	if !ok {
		return fallback
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return fallback
	}
	// These names are Dart-side prose, not identifiers: "stub AwaitStub",
	// "assert type is HitTestTarget", "new Duration". Spaces would break
	// consumers that treat a function name as one token, so they become
	// underscores -- the text is preserved, only the separator changes.
	return strings.ReplaceAll(name, " ", "_")
}
