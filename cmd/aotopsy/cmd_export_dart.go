package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	// Resolve each function's OWNING LIBRARY URL from its owner class (audit E2).
	// Previously every function was dumped into one hardcoded
	// "package:app/app.dart" file; now files are mapped by the real library URI
	// so the export is genuinely modular. Uses the shared LibraryResolver so the
	// mapping matches the rest of the pipeline.
	libResolver := pipeline.NewLibraryResolver(result, pl)
	codeRefToReceiverClassID := make(map[int]int, len(result.Codes))
	codeRefToLibURL := make(map[int]string, len(result.Codes))
	for _, ce := range result.Codes {
		if owner, ok := pipeline.ResolveCodeOwner(ce, pl.RefToNamed, paramTypeByCodeIndex); ok && owner != nil {
			classRef := effectiveOwnerClassRef(owner)
			if classRef > 0 {
				if ci, ok2 := classByRef[classRef]; ok2 {
					codeRefToReceiverClassID[ce.RefID] = int(ci.ClassID)
				}
				if url := libResolver.LibraryURLForClassRef(classRef); url != "" {
					codeRefToLibURL[ce.RefID] = url
				}
			}
			// Top-level functions have no class owner but their owner ref may be
			// the library (or a PatchClass onto it); try that too.
			if _, seen := codeRefToLibURL[ce.RefID]; !seen {
				if url := libResolver.LibraryURLForClassRef(effectiveOwnerClassRef(owner)); url != "" {
					codeRefToLibURL[ce.RefID] = url
				}
			}
		}
	}

	// Ground-truth try/catch: map each Code to its ExceptionHandlers entries and
	// decoded PcDescriptors, so the builder recovers exact try-region extents
	// (via cluster.BuildTryRegions + ExpandOuterTryRegions) instead of guessing
	// from branches. This mirrors decompile-native; export-dart previously lacked
	// it entirely, so reconstructed source had no try/catch (audit E1).
	excHandlersByRef := make(map[int][]cluster.ExceptionHandlerEntry, len(result.ExceptionHandlers))
	for i := range result.ExceptionHandlers {
		excHandlersByRef[result.ExceptionHandlers[i].RefID] = result.ExceptionHandlers[i].Handlers
	}
	codeRefToExcHandlers := make(map[int][]cluster.ExceptionHandlerEntry)
	pcDescByRef := make(map[int][]cluster.PcDescriptorEntry, len(result.PcDescriptors))
	for i := range result.PcDescriptors {
		pcDescByRef[result.PcDescriptors[i].RefID] = result.PcDescriptors[i].Entries
	}
	codeRefToPcDesc := make(map[int][]cluster.PcDescriptorEntry)
	for _, ce := range result.Codes {
		if ce.ExceptionHandlersRef >= 0 {
			if handlers, ok := excHandlersByRef[ce.ExceptionHandlersRef]; ok {
				codeRefToExcHandlers[ce.RefID] = handlers
			}
		}
		if ce.PcDescriptorsRef >= 0 {
			if entries, ok := pcDescByRef[ce.PcDescriptorsRef]; ok {
				codeRefToPcDesc[ce.RefID] = entries
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
		codeRefToExcHandlers:   codeRefToExcHandlers,
		codeRefToPcDesc:        codeRefToPcDesc,
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
		// Real owning library URL (audit E2); fall back to a single app bucket
		// only when it genuinely could not be resolved.
		libURL := codeRefToLibURL[r.RefID]
		if libURL == "" {
			libURL = "package:app/app.dart"
		}

		if idx := strings.Index(funcName, "."); idx > 0 {
			ownerClass = funcName[:idx]
			methodName = funcName[idx+1:]
		}

		// --app-only skips SDK/Flutter framework code, classified by the RESOLVED
		// library URL (dart:* / package:flutter*), not by a name-prefix heuristic.
		// The old code also dropped every `_`-prefixed owner, which threw away the
		// app's own private classes (audit E2).
		if *appOnly && pipeline.IsFrameworkLibraryURL(libURL) {
			continue
		}

		fir, err := funcIRBld.Build(r)
		if err != nil || fir == nil {
			continue
		}

		art := decompiler.EmitPseudocode(fir, symbolLookup, poolLookup)
		body := sanitizeDartBody(art.Source)

		if idx := strings.Index(body, "{"); idx >= 0 {
			body = body[idx:]
		}

		// Declaration names must be valid Dart identifiers, or the emitted file
		// does not even parse. Recovered names carry keyword prefixes (a discarded
		// constructor is "new X"), mixin `&`, dots, `@hash`, etc. Sanitize before
		// emitting the class/method declaration. Verified against the real Dart
		// analyzer: `dynamic new Size_25c()` -> `dynamic Size_25c()`.
		methodName = sanitizeDartIdent(methodName)
		if ownerClass != "" {
			ownerClass = sanitizeDartIdent(ownerClass)
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

// dartReservedWords are keywords that cannot appear as a bare identifier in a
// declaration. Recovered names that collide with one are prefixed so the emitted
// Dart parses.
var dartReservedWords = map[string]bool{
	"new": true, "class": true, "return": true, "if": true, "else": true, "for": true,
	"while": true, "do": true, "switch": true, "case": true, "default": true, "break": true,
	"continue": true, "var": true, "final": true, "const": true, "void": true, "null": true,
	"true": true, "false": true, "this": true, "super": true, "is": true, "as": true,
	"in": true, "assert": true, "async": true, "await": true, "yield": true, "try": true,
	"catch": true, "finally": true, "throw": true, "rethrow": true, "with": true,
	"extends": true, "implements": true, "abstract": true, "static": true, "operator": true,
	"typedef": true, "enum": true, "mixin": true, "extension": true, "factory": true,
	"external": true, "part": true, "import": true, "export": true, "library": true,
	"deferred": true, "covariant": true, "late": true, "required": true,
}

// sanitizeDartIdent turns a recovered function/class name into a valid Dart
// identifier for a declaration: it drops the `new ` constructor-marker prefix,
// replaces every non-identifier rune with `_`, avoids a leading digit, and
// prefixes reserved words. Without this the exported .dart does not parse.
func sanitizeDartIdent(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "new ")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '_' || r == '$' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		return "_anon"
	}
	if out[0] >= '0' && out[0] <= '9' {
		out = "_" + out
	}
	if dartReservedWords[out] {
		out = "_" + out
	}
	return out
}

// placeholderRe matches a standalone honest placeholder like `<TypeArguments>` or
// `<Instance_2300>` (a value the decompiler could not resolve), but NOT a real
// generic `List<int>` (which is preceded by an identifier).
var placeholderRe = regexp.MustCompile(`(^|[^\w])<([A-Za-z][^>]*)>`)

// sanitizeDartBody makes an emitted pseudocode body parse as Dart without
// changing its meaning: standalone `<X>` placeholders become a valid (but
// undefined) `unresolved_X` identifier — an honest "unknown value" that the
// analyzer flags as undefined rather than a hard syntax error — and an
// empty named-constructor call `Name.(` becomes `Name(`.
func sanitizeDartBody(body string) string {
	body = placeholderRe.ReplaceAllStringFunc(body, func(m string) string {
		sub := placeholderRe.FindStringSubmatch(m)
		prefix, inner := sub[1], sub[2]
		var b strings.Builder
		b.WriteString(prefix)
		b.WriteString("unresolved_")
		for _, r := range inner {
			switch {
			case r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
				b.WriteRune(r)
			default:
				b.WriteRune('_')
			}
		}
		return b.String()
	})
	body = strings.ReplaceAll(body, ".(", "(")
	return body
}
