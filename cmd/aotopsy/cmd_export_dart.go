package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/pipeline"
)

// cmdExportDart implements "aotopsy export-dart --lib <libapp.so> --out <dir>":
// Synthesizes the full decompiled project into organized, idiomatic .dart files
// grouped by class, library, and package hierarchy.
func cmdExportDart(args []string) error {
	fs := flag.NewFlagSet("export-dart", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so (ARM64 or x86_64)")
	outDir := fs.String("out", "", "output directory for synthesized Dart source files")
	appOnly := fs.Bool("app-only", false, "export only user app code (skip dart:* and package:flutter* libraries)")
	filterSubstr := fs.String("filter", "", "filter to classes or methods matching this substring")
	maxFuncs := fs.Int("max", 500, "max methods/functions to decompile (0 = unlimited)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	posArgs := fs.Args()
	if *libapp == "" && len(posArgs) > 0 {
		*libapp = posArgs[0]
	}
	if *outDir == "" && len(posArgs) > 1 {
		*outDir = posArgs[1]
	}

	if *libapp == "" {
		return fmt.Errorf("--lib <path> (or first positional arg) is required")
	}
	if *outDir == "" {
		*outDir = "decompiled_dart"
	}

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}
	sc, err := pipeline.LoadSnapshot(*libapp, opts)
	if err != nil {
		return err
	}
	defer func() { _ = sc.Close() }()

	info := sc.Info
	result := sc.Result
	ranges := sc.Ranges
	code := sc.Code
	codeOff := sc.CodeOff
	codeVA := sc.CodeVA
	isARM64 := sc.IsARM64
	pl := sc.Pool

	fmt.Printf("[export-dart] Loaded %s (Dart %s, %s)\n", *libapp, info.Version.DartVersion, map[bool]string{true: "ARM64", false: "x86_64"}[isARM64])
	fmt.Printf("[export-dart] Total code entries: %d\n", len(ranges))

	// Build symbols map for name resolution
	symbolNames := make(map[uint64]string, len(ranges))
	ctEarly := info.Version.CIDs
	paramTypeByCodeIndex := pipeline.CodeIndexToFunc(result, ctEarly, info.Version.CodeIndexOneBased)
	for _, r := range ranges {
		if r.Size == 0 {
			continue
		}
		funcStart := uint64(r.PCOffset) - codeOff
		funcVA := codeVA + funcStart
		if r.RefID >= 0 {
			symbolNames[funcVA] = qualifiedCodeNameLocal(r.RefID, pl, r.PCOffset)
		} else {
			symbolNames[funcVA] = fmt.Sprintf("stub_%x", r.PCOffset)
		}
	}

	classLayouts := pipeline.BuildClassLayouts(result, pl, info.Version.CompressedPointers)
	perClassFieldNames := map[int32]map[int32]string{}
	offsetNames := map[int32]map[string]bool{}
	for _, cl := range classLayouts {
		if perClassFieldNames[cl.ClassID] == nil {
			perClassFieldNames[cl.ClassID] = map[int32]string{}
		}
		for _, f := range cl.Fields {
			if strings.HasPrefix(f.Name, "f_0x") || strings.HasPrefix(f.Name, "field_0x") {
				continue
			}
			perClassFieldNames[cl.ClassID][f.ByteOffset] = f.Name
			if offsetNames[f.ByteOffset] == nil {
				offsetNames[f.ByteOffset] = map[string]bool{}
			}
			offsetNames[f.ByteOffset][f.Name] = true
		}
	}

	globalFieldNames := map[int32]string{}
	for off, names := range offsetNames {
		if len(names) == 1 {
			for name := range names {
				globalFieldNames[off] = name
			}
		}
	}

	fieldNameResolver := func(classID int, byteOffset int64) string {
		if classID > 0 {
			if classFields, ok := perClassFieldNames[int32(classID)]; ok {
				if name, ok2 := classFields[int32(byteOffset)]; ok2 {
					return name
				}
			}
		}
		if name, ok := globalFieldNames[int32(byteOffset)]; ok {
			return name
		}
		return ""
	}

	closureParents := pipeline.BuildClosureParents(result, pl)
	classByRef := make(map[int]*cluster.ClassInfo, len(result.Classes))
	for i := range result.Classes {
		classByRef[result.Classes[i].RefID] = &result.Classes[i]
	}

	effectiveOwnerClassRef := func(funcObj *cluster.NamedObject) int {
		effectiveClass := funcObj.OwnerRefID
		if owner, ok := pl.RefToNamed[effectiveClass]; ok && owner.CID == ctEarly.PatchClass {
			effectiveClass = owner.OwnerRefID
		}
		return effectiveClass
	}
	codeRefToReceiverClassID := make(map[int]int, len(result.Codes))
	for _, ce := range result.Codes {
		if owner, ok := pipeline.ResolveCodeOwner(ce, pl.RefToNamed, paramTypeByCodeIndex); ok && owner != nil {
			classRef := effectiveOwnerClassRef(owner)
			if classRef > 0 {
				if ci, ok2 := classByRef[classRef]; ok2 {
					codeRefToReceiverClassID[ce.RefID] = int(ci.ClassID)
				}
			}
		}
	}

	funcIRBld := &funcIRBuilder{
		code:                   code,
		codeOff:                codeOff,
		codeVA:                 codeVA,
		symbolNames:            symbolNames,
		isARM64:                isARM64,
		info:                   info,
		fieldNameResolver:      fieldNameResolver,
		closureParents:         closureParents,
		pl:                     pl,
		paramTypeByCodeIndex:   paramTypeByCodeIndex,
		codeRefToReceiverClass: codeRefToReceiverClassID,
	}

	symbolLookup := func(va uint64) (string, bool) {
		if name, ok := symbolNames[va]; ok && name != "" {
			return name, true
		}
		return "", false
	}

	poolLookup := func(offset int) (string, bool) {
		if sc.PoolDisplay != nil {
			if str, ok := sc.PoolDisplay[offset]; ok {
				return str, true
			}
		}
		return "", false
	}

	libraries := make(map[string]*decompiler.LibraryDecl)
	getOrCreateLib := func(url string) *decompiler.LibraryDecl {
		if url == "" {
			url = "package:app/main.dart"
		}
		if lib, ok := libraries[url]; ok {
			return lib
		}
		lib := decompiler.NewLibraryDecl(url)
		libraries[url] = lib
		return lib
	}

	exportedMethods := 0
	exportedClasses := make(map[string]bool)

	for _, r := range ranges {
		if *maxFuncs > 0 && exportedMethods >= *maxFuncs {
			break
		}

		funcVA := codeVA + (uint64(r.PCOffset) - codeOff)
		funcName := symbolNames[funcVA]
		if funcName == "" || strings.HasPrefix(funcName, "stub_") || strings.HasPrefix(funcName, "Stub_") {
			continue
		}

		if *filterSubstr != "" && !strings.Contains(funcName, *filterSubstr) {
			continue
		}

		ownerClass := ""
		methodName := funcName
		libURL := "package:app/app.dart"

		if idx := strings.Index(funcName, "."); idx > 0 {
			ownerClass = funcName[:idx]
			methodName = funcName[idx+1:]
		}

		if *appOnly {
			if strings.HasPrefix(ownerClass, "dart:") || strings.HasPrefix(ownerClass, "_") ||
				strings.HasPrefix(funcName, "package:flutter") || strings.HasPrefix(funcName, "dart:") {
				continue
			}
		}

		fir, err := funcIRBld.Build(r)
		if err != nil || fir == nil {
			continue
		}

		art := decompiler.EmitPseudocode(fir, symbolLookup, poolLookup)
		body := art.Source

		if idx := strings.Index(body, "{"); idx >= 0 {
			body = body[idx:]
		}

		lib := getOrCreateLib(libURL)
		mDecl := decompiler.MethodDecl{
			Name:       methodName,
			ReturnType: fir.ReturnType,
			IsAsync:    fir.IsAsync,
			Body:       body,
		}

		if ownerClass != "" {
			cDecl, ok := lib.Classes[ownerClass]
			if !ok {
				cDecl = &decompiler.ClassDecl{
					Name:       ownerClass,
					LibraryURL: libURL,
				}
				lib.Classes[ownerClass] = cDecl
				exportedClasses[ownerClass] = true
			}
			cDecl.Methods = append(cDecl.Methods, mDecl)
		} else {
			lib.TopLevelMethods = append(lib.TopLevelMethods, mDecl)
		}
		exportedMethods++
	}

	totalFiles := 0
	for url, lib := range libraries {
		if len(lib.Classes) == 0 && len(lib.TopLevelMethods) == 0 && len(lib.TopLevelFields) == 0 {
			continue
		}

		relPath := sanitizeLibraryPath(url)
		fullPath := filepath.Join(*outDir, relPath)

		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			return fmt.Errorf("creating directory for %s: %w", fullPath, err)
		}

		content := decompiler.SynthesizeLibrary(lib)
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("writing library %s: %w", fullPath, err)
		}
		totalFiles++
	}

	fmt.Printf("[export-dart] Successfully exported %d methods across %d classes into %d .dart files under %s/\n",
		exportedMethods, len(exportedClasses), totalFiles, *outDir)
	return nil
}

func sanitizeLibraryPath(url string) string {
	url = strings.TrimPrefix(url, "package:")
	url = strings.TrimPrefix(url, "dart:")
	url = strings.TrimPrefix(url, "file:///")
	url = strings.ReplaceAll(url, ":", "/")

	if !strings.HasSuffix(url, ".dart") {
		url += ".dart"
	}
	return filepath.Clean(url)
}
