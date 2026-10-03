package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cluster"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/naming"
	"aotopsy/internal/output"
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
	strict := fs.Bool("strict", false, "abort on the first function that cannot be decompiled (default: skip it and list it in "+analysis.DecompileFailuresFile+")")

	if err := fs.Parse(args); err != nil {
		return err
	}

	posArgs := fs.Args()
	consumed := 0
	if *libapp == "" && consumed < len(posArgs) {
		*libapp = posArgs[consumed]
		consumed++
	}
	if *outDir == "" && consumed < len(posArgs) {
		*outDir = posArgs[consumed]
		consumed++
	}
	if consumed != len(posArgs) {
		return fmt.Errorf("unexpected positional arguments: %v", posArgs[consumed:])
	}

	if *libapp == "" {
		return fmt.Errorf("--lib <path> (or first positional arg) is required")
	}
	if *outDir == "" {
		*outDir = "decompiled_dart"
	}

	contains, err := output.ContainsPath(*outDir, *libapp)
	if err != nil {
		return fmt.Errorf("compare export/source paths: %w", err)
	}
	if contains {
		return fmt.Errorf("export-dart output directory %s contains source binary %s", *outDir, *libapp)
	}

	ctx, err := analysis.LoadContext(*libapp)
	if err != nil {
		return err
	}
	defer func() { _ = ctx.Close() }()
	tx, err := output.BeginDirTransaction(*outDir)
	if err != nil {
		return fmt.Errorf("begin export-dart generation: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Abort()
		}
	}()
	stageOutDir := tx.StageDir()

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
	firstEntryWithCode := -1
	if ctx.InstrTable != nil {
		firstEntryWithCode = int(ctx.InstrTable.FirstEntryWithCode)
	}
	paramTypeByCodeIndex := naming.CodeIndexToFunc(result, ctEarly, info.Version.CodeIndexOneBased, firstEntryWithCode)
	effectiveOwnerClassRef := func(funcObj *cluster.NamedObject) int {
		effectiveClass := funcObj.OwnerRefID
		if ctEarly != nil && ctEarly.PatchClass != 0 {
			if owner, ok := pl.RefToNamed[effectiveClass]; ok && owner.CID == ctEarly.PatchClass {
				effectiveClass = owner.OwnerRefID
			}
		}
		return effectiveClass
	}
	libResolver := analysis.NewLibraryResolver(result, pl)
	codeRefToLibURL := make(map[int]string, len(result.Codes))
	for _, ce := range result.Codes {
		owner, ok := naming.ResolveCodeOwner(ce, pl.RefToNamed, paramTypeByCodeIndex, ctEarly)
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
	failures := analysis.FailureLog{Strict: *strict}

	for _, r := range ranges {
		if *maxFuncs > 0 && exportedMethods >= *maxFuncs {
			break
		}

		funcVA, ok := cluster.CodeImage{CodeVA: codeVA, CodeOff: codeOff}.FuncVA(r)
		if !ok {
			continue
		}
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

		fir, art, err := func() (fir *decompiler.FuncIR, art decompiler.Artifact, err error) {
			defer func() {
				if rec := recover(); rec != nil {
					err = fmt.Errorf("panic: %v", rec)
				}
			}()
			fir, err = ctx.FuncIRFor(r)
			if err != nil {
				return nil, art, fmt.Errorf("build IR: %w", err)
			}
			if fir == nil {
				return nil, art, fmt.Errorf("build IR: no IR produced")
			}
			return fir, decompiler.EmitPseudocode(fir, symbolLookup, poolLookup), nil
		}()
		if err != nil {
			// One broken function must not discard the rest of the export.
			if ferr := failures.Record(funcVA, r.RefID, funcName, err); ferr != nil {
				return ferr
			}
			continue
		}
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
		fullPath := filepath.Join(stageOutDir, relPath)

		content := decompiler.SynthesizeLibrary(lib)
		if err := output.WriteArtifactFile(stageOutDir, filepath.ToSlash(relPath), []byte(content), 0o644); err != nil {
			return fmt.Errorf("writing library %s: %w", fullPath, err)
		}
		totalFiles++
	}
	if err := failures.Finish(stageOutDir, os.Stderr); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("publish export-dart generation: %w", err)
	}
	committed = true

	fmt.Printf("[export-dart] Successfully exported %d methods across %d classes into %d .dart files under %s/\n",
		exportedMethods, len(exportedClasses), totalFiles, *outDir)
	return nil
}
