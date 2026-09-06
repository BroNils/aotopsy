package analysis

import (
	"fmt"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/naming"
)

// DecompileNativeDeps bundles everything the decompile-native command
// needs from the already-parsed Context, so the CLI handler can be thin.
type DecompileNativeDeps struct {
	Ctx                  *AnalysisContext
	Libapp               string
	IsARM64              bool
	SymbolNames          map[uint64]string
	SymbolSizes          map[uint64]uint32
	PoolDisplay          map[int]string
	BuildFuncIR          func(cluster.CodeRange) (*decompiler.FuncIR, error)
	SymbolLookup         decompiler.SymbolLookup
	PoolLookup           decompiler.PoolLookup
	DecompileRangeWithIR func(cluster.CodeRange) (*decompiler.FuncIR, decompiler.Artifact, error)
	// Library classification for --from-main
	LibraryURLForCodeRef      func(int) string
	LibraryURLForClassRef     func(int) string
	IsFrameworkLibraryURL     func(string) bool
	FunctionsByOwnerClassRef  map[int][]uint64
	ClassRefTouchedByPoolLoad func(poolIndex int) int
}

// BuildDecompileNativeDeps loads a Context and builds all the closures
// and lookup maps the decompile-native command needs.
func BuildDecompileNativeDeps(libapp string) (*DecompileNativeDeps, error) {
	ctx, err := LoadContext(libapp)
	if err != nil {
		return nil, err
	}

	ctx.BuildArgRegMasks()

	info := ctx.Info
	result := ctx.Result
	ranges := ctx.Ranges
	codeOff := ctx.CodeOff
	codeVA := ctx.CodeVA
	pl := ctx.Pool
	symbolNames := ctx.SymbolNames
	symbolSizes := ctx.SymbolSizes

	symbolLookup := func(va uint64) (string, bool) {
		if n, ok := symbolNames[va]; ok && n != "" {
			return n, true
		}
		return "", false
	}
	poolLookup := func(off int) (string, bool) {
		if ctx.PoolDisplay != nil {
			if s, ok := ctx.PoolDisplay[off]; ok {
				return s, true
			}
		}
		return "", false
	}
	buildFuncIR := ctx.FuncIRFor

	// Reachability/pool helpers used by --from-main.
	ctEarly := info.Version.CIDs
	classByRef := make(map[int]cluster.ClassInfo, len(result.Classes))
	for _, ci := range result.Classes {
		classByRef[ci.RefID] = ci
	}
	effectiveOwnerClassRef := func(funcObj *cluster.NamedObject) int {
		effectiveClass := funcObj.OwnerRefID
		if owner, ok := pl.RefToNamed[effectiveClass]; ok && owner.CID == ctEarly.PatchClass {
			effectiveClass = owner.OwnerRefID
		}
		return effectiveClass
	}
	poolByIndex := make(map[int]cluster.PoolEntry, len(result.Pool))
	for _, pe := range result.Pool {
		poolByIndex[pe.Index] = pe
	}

	decompileRangeWithIR := func(r cluster.CodeRange) (*decompiler.FuncIR, decompiler.Artifact, error) {
		fir, err := buildFuncIR(r)
		if err != nil {
			return nil, decompiler.Artifact{}, err
		}
		artifact := decompiler.EmitPseudocode(fir, symbolLookup, poolLookup)
		verification := decompiler.VerifyCFG(fir, artifact)
		if verification.MismatchedBranches > 0 || verification.MismatchedReturns > 0 {
			artifact.Source += fmt.Sprintf("\n// CFG verification: %s\n", verification.Summary())
		}
		return fir, artifact, nil
	}

	// Library classification for --from-main.
	ct := info.Version.CIDs
	byCodeIndex := naming.CodeIndexToFunc(result, ct, info.Version.CodeIndexOneBased)
	codeOwnerFunc := make(map[int]int, len(result.Codes))
	for _, ce := range result.Codes {
		if owner, ok := naming.ResolveCodeOwner(ce, pl.RefToNamed, byCodeIndex); ok {
			codeOwnerFunc[ce.RefID] = owner.RefID
		}
	}
	libraryURLForClassRef := func(classRef int) string {
		classInfo, ok := classByRef[classRef]
		if !ok || classInfo.LibraryRefID < 0 {
			return ""
		}
		libObj, ok := pl.RefToNamed[classInfo.LibraryRefID]
		if !ok {
			return ""
		}
		if url := pl.ResolveName(libObj); url != "" {
			return url
		}
		return pl.ResolveVMName(libObj)
	}
	libraryURLForCodeRef := func(codeRef int) string {
		funcRef, ok := codeOwnerFunc[codeRef]
		if !ok {
			return ""
		}
		funcObj, ok := pl.RefToNamed[funcRef]
		if !ok {
			return ""
		}
		return libraryURLForClassRef(effectiveOwnerClassRef(funcObj))
	}

	// Class-touch expansion support.
	classIDToClassRef := make(map[int32]int, len(result.Classes))
	for _, ci := range result.Classes {
		classIDToClassRef[ci.ClassID] = ci.RefID
	}
	functionsByOwnerClassRef := make(map[int][]uint64, len(result.Classes))
	for _, r := range ranges {
		if r.Size == 0 || r.RefID < 0 {
			continue
		}
		funcRef, ok := codeOwnerFunc[r.RefID]
		if !ok {
			continue
		}
		funcObj, ok := pl.RefToNamed[funcRef]
		if !ok {
			continue
		}
		classRef := effectiveOwnerClassRef(funcObj)
		funcVA, ok := cluster.CodeImage{CodeVA: codeVA, CodeOff: codeOff}.FuncVA(r)
		if !ok {
			continue
		}
		functionsByOwnerClassRef[classRef] = append(functionsByOwnerClassRef[classRef], funcVA)
	}
	classRefTouchedByPoolLoad := func(poolIndex int) int {
		if poolIndex < 0 {
			return -1
		}
		pe, ok := poolByIndex[poolIndex]
		if !ok || pe.Kind != cluster.PoolTagged {
			return -1
		}
		cid, ok := pl.RefCID[pe.RefID]
		if !ok {
			return -1
		}
		classRef, ok := classIDToClassRef[int32(cid)]
		if !ok {
			return -1
		}
		return classRef
	}

	return &DecompileNativeDeps{
		Ctx:                       ctx,
		Libapp:                    libapp,
		IsARM64:                   ctx.IsARM64,
		SymbolNames:               symbolNames,
		SymbolSizes:               symbolSizes,
		PoolDisplay:               ctx.PoolDisplay,
		BuildFuncIR:               buildFuncIR,
		SymbolLookup:              symbolLookup,
		PoolLookup:                poolLookup,
		DecompileRangeWithIR:      decompileRangeWithIR,
		LibraryURLForCodeRef:      libraryURLForCodeRef,
		LibraryURLForClassRef:     libraryURLForClassRef,
		IsFrameworkLibraryURL:     IsFrameworkLibraryURL,
		FunctionsByOwnerClassRef:  functionsByOwnerClassRef,
		ClassRefTouchedByPoolLoad: classRefTouchedByPoolLoad,
	}, nil
}

// FindFunctionsByName searches symbolNames for entries containing substr,
// printing VA + name + size for each match.
func FindFunctionsByName(symbolNames map[uint64]string, symbolSizes map[uint64]uint32, substr string) int {
	hits := 0
	for va, name := range symbolNames {
		if strings.Contains(name, substr) {
			fmt.Printf("0x%x  size=%d  %s\n", va, symbolSizes[va], name)
			hits++
		}
	}
	return hits
}
