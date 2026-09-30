package main

import (
	"flag"

	"aotopsy/internal/analysis"
	"aotopsy/internal/cli"
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

	cli.Errf("reFlutter import complete: %s\n", result.OutputDir)
	cli.Errf("  Libraries: %d\n", result.Libraries)
	cli.Errf("  Functions: %d\n", result.Functions)
	cli.Errf("  Classes with fields: %d\n", result.ClassesFields)
	return nil
}
