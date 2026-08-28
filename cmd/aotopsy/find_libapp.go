package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aotopsy/internal/analysis"
)

func cmdFindLibapp(args []string) error {
	fs := flag.NewFlagSet("find-libapp", flag.ExitOnError)
	apk := fs.String("apk", "", "Path to APK/zip file")
	outDir := fs.String("out", "", "Output directory for find_libapp.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *apk == "" {
		return fmt.Errorf("--apk is required")
	}

	result, err := analysis.FindLibappInZip(*apk)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			return err
		}
		base := strings.TrimSuffix(filepath.Base(*apk), filepath.Ext(*apk))
		outPath := filepath.Join(*outDir, base+"_find_libapp.json")
		if err := os.WriteFile(outPath, data, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", outPath)
	} else {
		fmt.Println(string(data))
	}
	return nil
}
