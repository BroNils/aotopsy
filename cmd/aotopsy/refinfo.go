package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/elfx"
	"aotopsy/internal/pipeline"
	"aotopsy/internal/snapshot"
)

// cmdRefInfo is a diagnostic-only tool: given raw ref IDs (the same
// ref-ID space used internally by cluster.Result / pipeline.PoolLookups,
// i.e. what shows up as ref_id/owner_ref in index.jsonl), print the CID,
// resolved name, and owner chain for each. Built to investigate why some
// Code objects (e.g. sub_18761cc, owner_ref=106414) have no resolvable
// "owner" in functions.jsonl -- walks NamedObject.OwnerRefID one hop at
// a time instead of assuming the owner is always a Class.
func cmdRefInfo(args []string) error {
	fs := flag.NewFlagSet("refinfo", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so")
	refsFlag := fs.String("refs", "", "comma-separated ref IDs to inspect")
	codeRefFlag := fs.Int("find-owner-of-code-ref", -1, "given a Code cluster's own ref ID, find its owning Function via code_index cross-reference (bypasses Code.OwnerRef, which is buggy for some Dart versions)")
	siblingsOfFlag := fs.Int("siblings-of-owner", -1, "list all Function/Field NamedObjects whose OwnerRefID equals this ref")
	listToplevel := fs.Bool("list-toplevel", false, "list every Function whose effective owner is a \"::\" (top-level scope) class, with param count + code size, for cross-arch structural matching")
	fieldsOfCID := fs.Int("fields-of-instance-cid", -1, "find the Class whose instances have this CID, then list its Field records (host offset + initializer_function ref) -- for locating a specific field's lazy initializer")
	walk := fs.Bool("walk", true, "follow OwnerRefID chain until it terminates")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *libapp == "" || (*refsFlag == "" && *codeRefFlag < 0 && *siblingsOfFlag < 0 && !*listToplevel && *fieldsOfCID < 0) {
		return fmt.Errorf("--lib and one of --refs/--find-owner-of-code-ref/--siblings-of-owner/--list-toplevel/--fields-of-instance-cid are required")
	}

	var refs []int
	for _, s := range strings.Split(*refsFlag, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("bad ref %q: %w", s, err)
		}
		refs = append(refs, n)
	}

	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}

	ef, err := elfx.Open(*libapp)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = ef.Close() }()

	info, err := snapshot.Extract(ef, opts)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Dart SDK version: %s\n", info.Version.DartVersion)

	data := info.IsolateData.Data
	clusterStart, err := cluster.FindClusterDataStart(data)
	if err != nil {
		return fmt.Errorf("cluster start: %w", err)
	}
	result, err := cluster.ScanClusters(data, clusterStart, info.Version, false, opts)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	if err := cluster.ReadFill(data, result, info.Version, false, info.IsolateHeader.TotalSize); err != nil {
		return fmt.Errorf("fill: %w", err)
	}

	var vmResult *cluster.Result
	vmData := info.VmData.Data
	if len(vmData) >= 64 && info.VmHeader != nil {
		vmStart, err := cluster.FindClusterDataStart(vmData)
		if err == nil {
			vmRes, err := cluster.ScanClusters(vmData, vmStart, info.Version, true, opts)
			if err == nil {
				_ = cluster.ReadFill(vmData, vmRes, info.Version, true, info.VmHeader.TotalSize)
				vmResult = vmRes
			}
		}
	}

	pl := buildPoolLookups(result, info.Version.CIDs, vmResult, info.Version.CodeIndexOneBased, info.Version.DartVersion)
	ct := info.Version.CIDs

	// RefCID only covers Named/Class clusters via cm.StartRef..StopRef in
	// BuildPoolLookups; that's exactly what we want here (raw CID lookup
	// by ref, independent of whether it resolved to a name).
	for _, r := range refs {
		printRefChain(r, pl, ct, *walk, make(map[int]bool))
	}

	if *codeRefFlag >= 0 {
		if err := findOwnerViaCodeIndex(*codeRefFlag, result, pl, ct, *walk, info.Version.CodeIndexOneBased); err != nil {
			return err
		}
	}

	if *siblingsOfFlag >= 0 {
		findSiblingsByOwner(*siblingsOfFlag, result, pl, ct)
	}

	if *listToplevel {
		listToplevelFunctions(result, pl, ct)
	}

	if *fieldsOfCID >= 0 {
		findFieldsOfInstanceCID(*fieldsOfCID, result, pl, ct)
	}
	return nil
}

// findFieldsOfInstanceCID finds the Class whose ClassInfo.ClassID matches
// targetCID (e.g. a class ID for an object of interest found empirically
// via live Frida hooking), then lists every Field whose
// OwnerRefID is that Class's ref, printing host offset + the
// initializer_function ref (added this session -- see
// internal/cluster/fillspec.go's specField SignatureIdx and
// FieldInfo.InitializerRefID, previously read from the stream but
// discarded). This is how a specific lazy ("late") field's own
// initializer function is located directly from snapshot metadata,
// instead of more manual disassembly.
// classNameByCID resolves a class's display name, trying (in order): the
// isolate string pool, the VM (core-library) string pool, then falling back
// to cluster.CidNameV for genuinely predefined/builtin classes that have no
// snapshot-side Class record name at all (e.g. Type, Instance). Needed
// because obfuscated app classes' superclass chains bottom out in
// core-library classes (Object, Type, etc.) whose names live in the VM
// snapshot's string pool, not the isolate's -- ResolveName alone (isolate
// pool only) prints "<unnamed>" for those, which looked like a resolver bug
// until cross-checked here.
func classNameByCID(cid int32, result *cluster.Result, pl *poolLookups, ct *snapshot.CIDTable) string {
	for i := range result.Classes {
		if result.Classes[i].ClassID != cid {
			continue
		}
		ci := result.Classes[i]
		if no, ok := pl.RefToNamed[ci.RefID]; ok {
			if s := pl.ResolveName(no); s != "" {
				return s
			}
			if s := pl.ResolveVMName(no); s != "" {
				return s
			}
		}
		break
	}
	if ct != nil {
		if s := cluster.CidNameV(int(cid), ct); s != "" {
			return s
		}
	}
	return "<unnamed>"
}

func findFieldsOfInstanceCID(targetCID int, result *cluster.Result, pl *poolLookups, ct *snapshot.CIDTable) {
	var classRef = -1
	var superTypeRef = -1
	for i := range result.Classes {
		if result.Classes[i].ClassID == int32(targetCID) {
			classRef = result.Classes[i].RefID
			superTypeRef = result.Classes[i].SuperTypeRefID
			fmt.Printf("class ref=%d matches instance cid=%d (instanceSize=%d, nextFieldOff=%d)\n",
				classRef, targetCID, result.Classes[i].InstanceSize, result.Classes[i].NextFieldOff)
			break
		}
	}
	if classRef < 0 {
		fmt.Printf("no Class found with instance cid=%d\n", targetCID)
		return
	}
	fmt.Printf("class name=%q\n", classNameByCID(int32(targetCID), result, pl, ct))
	if superTypeRef >= 0 {
		printSuperclassChain(superTypeRef, result, pl, ct, 1)
	} else {
		fmt.Printf("  (super_type not resolved for this class -- fill spec.NumRefs mismatch, see ClassInfo.SuperTypeRefID doc)\n")
	}
	count := 0
	for _, f := range result.Fields {
		effectiveOwner := f.OwnerRefID
		if owner, ok := pl.RefToNamed[f.OwnerRefID]; ok && owner.CID == pl.CT.PatchClass {
			effectiveOwner = owner.OwnerRefID
		}
		if effectiveOwner != classRef {
			continue
		}
		count++
		name := ""
		if no, ok := pl.RefToNamed[f.RefID]; ok {
			name = pl.ResolveName(no)
		}
		fmt.Printf("  field ref=%d name=%q hostOffset=0x%x kindBits=0x%x initializerRefID=%d\n",
			f.RefID, name, f.HostOffset, f.KindBits, f.InitializerRefID)
	}
	fmt.Printf("total fields: %d\n", count)
}

// printSuperclassChain resolves a Class's super_type ref (Class.SuperTypeRefID)
// to the Type object's decoded type_class_id (result.Types, populated only
// for the v3.x fill shape -- see cluster.TypeInfo), prints the superclass
// name, then recurses on THAT class's own super_type. Capped at depth 10 as
// a cycle/runaway guard (Dart class hierarchies are never anywhere near
// that deep). Built to answer "what does this obfuscated class actually
// extend" without needing blutter's live-VM introspection -- e.g. confirming
// whether a GDT-dispatched class like "Da" extends something Map-like.
func printSuperclassChain(typeRef int, result *cluster.Result, pl *poolLookups, ct *snapshot.CIDTable, depth int) {
	if depth > 10 {
		fmt.Printf("  (superclass chain truncated at depth %d -- possible cycle or bad ref)\n", depth)
		return
	}
	if typeRef < 0 {
		fmt.Printf("  (chain ends at depth %d: no further super_type, e.g. Object or non-v3.x Type)\n", depth)
		return
	}
	var superCID int32 = -1
	found := false
	for _, t := range result.Types {
		if t.RefID == typeRef {
			superCID = t.ClassID
			found = true
			break
		}
	}
	if !found {
		fmt.Printf("  (super_type ref=%d not found in result.Types -- not a v3.x-shaped Type object)\n", typeRef)
		return
	}
	name := classNameByCID(superCID, result, pl, ct)
	fmt.Printf("  extends (depth %d): cid=%d name=%q\n", depth, superCID, name)
	if name == "Object" {
		return
	}
	for i := range result.Classes {
		if result.Classes[i].ClassID == superCID {
			printSuperclassChain(result.Classes[i].SuperTypeRefID, result, pl, ct, depth+1)
			return
		}
	}
}

// listToplevelFunctions prints every Function whose effective owner
// (following one PatchClass->Class hop if needed) is a "::"-named class
// -- Dart's synthetic top-level scope -- along with its param count and
// Code size. Built for cross-architecture structural correlation: since
// x86_64's Code.OwnerRef is unreliable (see findOwnerViaCodeIndex) AND
// its disassembler can't reliably annotate pool-offset comments (only
// 255/13309 functions get any "[pp+0x...]" comment at all, confirmed
// separately), we can't find the x86_64 equivalent of a known ARM64
// top-level function (e.g. sub_18761cc, param count + size known) by
// searching code text. Listing every top-level function's structural
// signature (param count, code size) on both architectures instead lets
// candidates be narrowed by matching those fields directly -- no
// disassembly needed at all.
func listToplevelFunctions(result *cluster.Result, pl *poolLookups, ct *snapshot.CIDTable) {
	funcTypeByRef := make(map[int]*cluster.FuncTypeInfo, len(result.FuncTypes))
	for i := range result.FuncTypes {
		funcTypeByRef[result.FuncTypes[i].RefID] = &result.FuncTypes[i]
	}
	// Real per-parameter type names (pipeline.TypeParamResolver), where
	// this Dart version's FunctionType ref layout has been verified (see
	// snapshot.VersionProfile.FuncTypeParamTypesIdx's doc comment) --
	// strengthens exactly the cross-architecture structural correlation
	// this function exists for: two candidates with the same param COUNT
	// can now also be told apart by param TYPES when both resolve.
	typeParams := pipeline.NewTypeParamResolver(result, pl)

	count := 0
	for _, no := range result.Named {
		if no.CID != ct.Function {
			continue
		}
		effectiveClass := no.OwnerRefID
		ownerName := ""
		if owner, ok := pl.RefToNamed[no.OwnerRefID]; ok {
			if owner.CID == ct.PatchClass {
				effectiveClass = owner.OwnerRefID
			}
		}
		if classObj, ok := pl.RefToNamed[effectiveClass]; ok {
			ownerName = pl.ResolveName(classObj)
			if ownerName == "" {
				// Synthetic top-level classes ("::") are named via the VM
				// base-object string table, not the isolate snapshot's own
				// strings -- ResolveName alone misses them.
				ownerName = pl.ResolveVMName(classObj)
			}
		}
		if ownerName != "::" {
			continue
		}
		count++
		paramFixed, paramOptional := -1, -1
		var paramTypes []string
		if ft, ok := funcTypeByRef[no.SignatureRefID]; ok {
			paramFixed, paramOptional = ft.NumFixed, ft.NumOptional
			paramTypes = typeParams.ParamTypeNames(*ft)
		}
		name := pl.ResolveName(&no)
		if paramTypes != nil {
			fmt.Printf("toplevel-fn ref=%d name=%q codeIndex=%d paramFixed=%d paramOptional=%d paramTypes=%v\n",
				no.RefID, name, no.CodeIndex, paramFixed, paramOptional, paramTypes)
		} else {
			fmt.Printf("toplevel-fn ref=%d name=%q codeIndex=%d paramFixed=%d paramOptional=%d\n",
				no.RefID, name, no.CodeIndex, paramFixed, paramOptional)
		}
	}
	fmt.Printf("total top-level (\"::\"-owned) functions: %d\n", count)
}

// findSiblingsByOwner lists every Function/Field whose EFFECTIVE owning
// Class equals classRef, following one extra PatchClass->Class hop when
// the immediate OwnerRefID is a PatchClass (multiple PatchClass instances
// -- one per source/part file -- can all wrap the same Class, especially
// the synthetic "::" top-level class, so grouping by the immediate owner
// alone undercounts siblings).
func findSiblingsByOwner(classRef int, result *cluster.Result, pl *poolLookups, ct *snapshot.CIDTable) {
	count := 0
	for _, no := range result.Named {
		if no.CID != ct.Function && no.CID != ct.Field {
			continue
		}
		effectiveClass := no.OwnerRefID
		if owner, ok := pl.RefToNamed[no.OwnerRefID]; ok && owner.CID == ct.PatchClass {
			effectiveClass = owner.OwnerRefID
		}
		if effectiveClass != classRef {
			continue
		}
		count++
		name := pl.ResolveName(&no)
		kind := "Field"
		if no.CID == ct.Function {
			kind = "Function"
		}
		fmt.Printf("  sibling %s ref=%d name=%q codeIndex=%d immediateOwner=%d\n", kind, no.RefID, name, no.CodeIndex, no.OwnerRefID)
	}
	fmt.Printf("total siblings of class %d: %d\n", classRef, count)
}

// findOwnerViaCodeIndex looks up the CodeEntry for codeRef, then searches
// all Function NamedObjects for one whose CodeIndex matches the code's
// ClusterIndex -- this is the Function->Code direction of the link, which
// bypasses Code.OwnerRef entirely (confirmed unreliable for some Dart
// versions: e.g. Dart 3.7.0 produces a bogus shared owner_ref for ~5.4%
// of all functions in this snapshot, all resolving to CID 61/Mint, which
// is never a legal Code owner).
func findOwnerViaCodeIndex(codeRef int, result *cluster.Result, pl *poolLookups, ct *snapshot.CIDTable, walk bool, codeIndexOneBased bool) error {
	var target *cluster.CodeEntry
	for i := range result.Codes {
		if result.Codes[i].RefID == codeRef {
			target = &result.Codes[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("no CodeEntry with ref %d", codeRef)
	}
	fmt.Printf("code ref %d: ClusterIndex=%d (buggy OwnerRef=%d)\n", codeRef, target.ClusterIndex, target.OwnerRef)

	// Function.CodeIndex is 1-based for Dart >=2.16 (0=LazyCompile stub),
	// 0-based for <=2.15. Code.ClusterIndex is always 0-based.
	// Compare after converting CodeIndex to the same 0-based domain.
	var matches []cluster.NamedObject
	for _, no := range result.Named {
		if no.CID != ct.Function {
			continue
		}
		clusterIdx := no.CodeIndex
		if codeIndexOneBased {
			clusterIdx = no.CodeIndex - 1
		}
		if clusterIdx == target.ClusterIndex {
			matches = append(matches, no)
		}
	}
	fmt.Printf("Function(s) with CodeIndex==%d: %d match(es)\n", target.ClusterIndex, len(matches))
	if len(matches) == 0 {
		// Exact match failed -- small numbering discrepancies between
		// architectures have been observed elsewhere (e.g. same-named
		// functions off by a handful of CodeIndex units), so widen the
		// search window rather than giving up.
		const window = 5
		fmt.Printf("no exact match; scanning CodeIndex in [%d, %d]:\n", target.ClusterIndex-window, target.ClusterIndex+window)
		for _, no := range result.Named {
			if no.CID != ct.Function {
				continue
			}
			d := no.CodeIndex - target.ClusterIndex
			if d >= -window && d <= window {
				fmt.Printf("  candidate ref=%d name=%q codeIndex=%d (delta=%d) ownerRefID=%d\n",
					no.RefID, pl.ResolveName(&no), no.CodeIndex, d, no.OwnerRefID)
			}
		}
	}
	for _, no := range matches {
		fmt.Printf("  Function ref=%d name=%q ownerRefID=%d\n", no.RefID, pl.ResolveName(&no), no.OwnerRefID)
		if walk && no.OwnerRefID >= 0 {
			printRefChain(no.OwnerRefID, pl, ct, walk, make(map[int]bool))
		}
	}
	return nil
}

func printRefChain(ref int, pl *poolLookups, ct *snapshot.CIDTable, walk bool, seen map[int]bool) {
	if seen[ref] {
		fmt.Printf("ref %d: <cycle, already visited>\n", ref)
		return
	}
	seen[ref] = true

	cid, hasCID := pl.RefCID[ref]
	cidName := cluster.CidNameV(cid, ct)
	no, hasNamed := pl.RefToNamed[ref]

	fmt.Printf("ref %d: cid=%d(%s) hasCID=%v hasNamedObject=%v\n", ref, cid, cidName, hasCID, hasNamed)
	if !hasNamed {
		fmt.Printf("  (not in RefToNamed -- this ref's cluster type doesn't carry a resolvable name/owner)\n")
		return
	}
	name := pl.ResolveName(no)
	rawStr, hasRawStr := pl.RefToStr[no.NameRefID]
	vmStr, hasVmStr := pl.VmRefToStr[no.NameRefID]
	fmt.Printf("  name=%q nameRefID=%d (isolateStr hit=%v val=%q) (vmStr hit=%v val=%q) ownerRefID=%d signatureRefID=%d objCID=%d baseObjLimit=%d\n",
		name, no.NameRefID, hasRawStr, rawStr, hasVmStr, vmStr, no.OwnerRefID, no.SignatureRefID, no.CID, pl.BaseObjLimit)

	if walk && no.OwnerRefID >= 0 {
		fmt.Printf("  -> following ownerRefID=%d:\n", no.OwnerRefID)
		printRefChain(no.OwnerRefID, pl, ct, walk, seen)
	}
}
