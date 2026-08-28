package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/naming"
	"aotopsy/internal/analysis"
	"aotopsy/internal/strutil"
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

	ctx, err := analysis.LoadContext(*libapp)
	if err != nil {
		return err
	}
	defer func() { _ = ctx.Close() }()

	result := ctx.Result
	pl := ctx.Pool
	info := ctx.Info
	ranges := ctx.Ranges
	codeOff := ctx.CodeOff
	codeVA := ctx.CodeVA
	symbolNames := ctx.SymbolNames

	fmt.Printf("[export-dart] Loaded %s (Dart %s, %s)\n", *libapp, info.Version.DartVersion, map[bool]string{true: "ARM64", false: "x86_64"}[ctx.IsARM64])
	fmt.Printf("[export-dart] Total code entries: %d\n", len(ranges))

	// Library-URL mapping (export-specific): map each Code to its owning library
	// URI for file placement. The FuncIR itself now comes from the shared,
	// fully-enriched Context.FuncIRFor -- export-dart no longer builds its own
	// (previously partial) FuncIR builder, so its output matches decompile-native.
	ctEarly := info.Version.CIDs
	paramTypeByCodeIndex := naming.CodeIndexToFunc(result, ctEarly, info.Version.CodeIndexOneBased)
	effectiveOwnerClassRef := func(funcObj *cluster.NamedObject) int {
		effectiveClass := funcObj.OwnerRefID
		if owner, ok := pl.RefToNamed[effectiveClass]; ok && owner.CID == ctEarly.PatchClass {
			effectiveClass = owner.OwnerRefID
		}
		return effectiveClass
	}
	libResolver := analysis.NewLibraryResolver(result, pl)
	codeRefToLibURL := make(map[int]string, len(result.Codes))
	for _, ce := range result.Codes {
		owner, ok := naming.ResolveCodeOwner(ce, pl.RefToNamed, paramTypeByCodeIndex)
		if !ok || owner == nil {
			continue
		}
		if url := libResolver.LibraryURLForClassRef(effectiveOwnerClassRef(owner)); url != "" {
			codeRefToLibURL[ce.RefID] = url
		}
	}

	symbolLookup := func(va uint64) (string, bool) {
		if name, ok := symbolNames[va]; ok && name != "" {
			return name, true
		}
		return "", false
	}
	poolLookup := func(offset int) (string, bool) {
		if ctx.PoolDisplay != nil {
			if str, ok := ctx.PoolDisplay[offset]; ok {
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
		if *appOnly && analysis.IsFrameworkLibraryURL(libURL) {
			continue
		}

		fir, err := ctx.FuncIRFor(r)
		if err != nil || fir == nil {
			continue
		}

		art := decompiler.EmitPseudocode(fir, symbolLookup, poolLookup)
		body := strutil.SanitizeDartBody(art.Source)

		if idx := strings.Index(body, "{"); idx >= 0 {
			body = body[idx:]
		}

		// Declaration names must be valid Dart identifiers, or the emitted file
		// does not even parse. Recovered names carry keyword prefixes (a discarded
		// constructor is "new X"), mixin `&`, dots, `@hash`, etc. Sanitize before
		// emitting the class/method declaration. Verified against the real Dart
		// analyzer: `dynamic new Size_25c()` -> `dynamic Size_25c()`.
		methodName = strutil.SanitizeDartIdent(methodName)
		if ownerClass != "" {
			ownerClass = strutil.SanitizeDartIdent(ownerClass)
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

		relPath := strutil.SanitizeLibraryPath(url)
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
