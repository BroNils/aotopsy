package analysis

import (
	"fmt"
	"strconv"

	"aotopsy/internal/cluster"
	"aotopsy/internal/naming"
	"aotopsy/internal/snapshot"
)

// ClassNameByCID resolves a class's display name, trying (in order): the
// isolate string pool, the VM (core-library) string pool, then falling back
// to cluster.CidNameV for genuinely predefined/builtin classes.
func ClassNameByCID(cid int32, result *cluster.Result, pl *naming.PoolLookups, ct *snapshot.CIDTable) string {
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

// FindFieldsOfInstanceCID finds the Class whose ClassInfo.ClassID matches
// targetCID, then lists every Field whose OwnerRefID is that Class's ref.
func FindFieldsOfInstanceCID(targetCID int, result *cluster.Result, pl *naming.PoolLookups, ct *snapshot.CIDTable) {
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
	fmt.Printf("class name=%q\n", ClassNameByCID(int32(targetCID), result, pl, ct))
	if superTypeRef >= 0 {
		PrintSuperclassChain(superTypeRef, result, pl, ct, 1)
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

// PrintSuperclassChain resolves a Class's super_type ref to the Type object's
// decoded type_class_id, prints the superclass name, then recurses.
func PrintSuperclassChain(typeRef int, result *cluster.Result, pl *naming.PoolLookups, ct *snapshot.CIDTable, depth int) {
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
	name := ClassNameByCID(superCID, result, pl, ct)
	fmt.Printf("  extends (depth %d): cid=%d name=%q\n", depth, superCID, name)
	if name == "Object" {
		return
	}
	for i := range result.Classes {
		if result.Classes[i].ClassID == superCID {
			PrintSuperclassChain(result.Classes[i].SuperTypeRefID, result, pl, ct, depth+1)
			return
		}
	}
}

// ListToplevelFunctions prints every Function whose effective owner is a
// "::"-named class (Dart's synthetic top-level scope).
func ListToplevelFunctions(result *cluster.Result, pl *naming.PoolLookups, ct *snapshot.CIDTable) {
	funcTypeByRef := make(map[int]*cluster.FuncTypeInfo, len(result.FuncTypes))
	for i := range result.FuncTypes {
		funcTypeByRef[result.FuncTypes[i].RefID] = &result.FuncTypes[i]
	}
	typeParams := naming.NewTypeParamResolver(result, pl)

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

// FindSiblingsByOwner lists every Function/Field whose EFFECTIVE owning
// Class equals classRef.
func FindSiblingsByOwner(classRef int, result *cluster.Result, pl *naming.PoolLookups, ct *snapshot.CIDTable) {
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

// FindOwnerViaCodeIndex looks up the CodeEntry for codeRef, then searches
// all Function NamedObjects for one whose CodeIndex matches the code's
// ClusterIndex — bypasses Code.OwnerRef entirely.
func FindOwnerViaCodeIndex(codeRef int, result *cluster.Result, pl *naming.PoolLookups, ct *snapshot.CIDTable, walk bool, codeIndexOneBased bool) error {
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
			PrintRefChain(no.OwnerRefID, pl, ct, walk, make(map[int]bool))
		}
	}
	return nil
}

// PrintRefChain walks a ref's CID, name, and owner chain.
func PrintRefChain(ref int, pl *naming.PoolLookups, ct *snapshot.CIDTable, walk bool, seen map[int]bool) {
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
		PrintRefChain(no.OwnerRefID, pl, ct, walk, seen)
	}
}

// ParseRefIDs parses a comma-separated list of ref IDs.
func ParseRefIDs(s string) ([]int, error) {
	var refs []int
	for _, part := range splitCommas(s) {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("bad ref %q: %w", part, err)
		}
		refs = append(refs, n)
	}
	return refs, nil
}

func splitCommas(s string) []string {
	var out []string
	for _, part := range splitString(s, ",") {
		part = trimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
