package main

import (
	"flag"
	"fmt"
	"os"

	"aotopsy/internal/analysis"
)

func cmdReflutterImport(args []string) error {
	fs := flag.NewFlagSet("reflutter-import", flag.ExitOnError)
	dumpPath := fs.String("dump", "", "path to reFlutter's dump.dart")
	staticDir := fs.String("static", "", "aotopsy static output directory")
	libPath := fs.String("lib", "", "path to the original libapp.so (needed to convert reFlutter's snapshot-relative offsets to aotopsy's absolute VAs)")
	outDir := fs.String("out", "", "output directory for merged results (default: <static>_reflutter)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	result, err := analysis.RunReFlutterImport(analysis.ReFlutterImportOptions{
		DumpPath:  *dumpPath,
		StaticDir: *staticDir,
		LibPath:   *libPath,
		OutDir:    *outDir,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "reFlutter import complete: %s\n", result.OutputDir)
	fmt.Fprintf(os.Stderr, "  Libraries: %d\n", result.Libraries)
	fmt.Fprintf(os.Stderr, "  Functions: %d\n", result.Functions)
	fmt.Fprintf(os.Stderr, "  Classes with fields: %d\n", result.ClassesFields)
	return nil
}
