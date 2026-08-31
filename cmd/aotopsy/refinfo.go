package main

import (
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/analysis"
	"aotopsy/internal/dartfmt"
)

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
	if *refsFlag != "" {
		var err error
		refs, err = analysis.ParseRefIDs(*refsFlag)
		if err != nil {
			return err
		}
	}

	opts := dartfmt.Options{Mode: dartfmt.ModeBestEffort}
	sc, err := analysis.LoadSnapshot(*libapp, opts)
	if err != nil {
		return err
	}
	defer func() { _ = sc.Close() }()

	info := sc.Info
	result := sc.Result
	pl := sc.Pool
	ct := info.Version.CIDs

	fmt.Fprintf(os.Stderr, "Dart SDK version: %s\n", info.Version.DartVersion)

	for _, r := range refs {
		analysis.PrintRefChain(r, pl, ct, *walk, make(map[int]bool))
	}

	if *codeRefFlag >= 0 {
		if err := analysis.FindOwnerViaCodeIndex(*codeRefFlag, result, pl, ct, *walk, info.Version.CodeIndexOneBased); err != nil {
			return err
		}
	}

	if *siblingsOfFlag >= 0 {
		analysis.FindSiblingsByOwner(*siblingsOfFlag, result, pl, ct)
	}

	if *listToplevel {
		analysis.ListToplevelFunctions(result, pl, ct)
	}

	if *fieldsOfCID >= 0 {
		analysis.FindFieldsOfInstanceCID(*fieldsOfCID, result, pl, ct)
	}
	return nil
}
