package analysis

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"aotopsy/internal/cli"
	"aotopsy/internal/disasm"
	"aotopsy/internal/jsonutil"
	"aotopsy/internal/signal"
	"aotopsy/internal/strutil"
)

// RunMetaStage generates flutter_meta.json from existing disasm output.
func RunMetaStage(inDir, outPath string, decompAll bool, quiet bool, log io.Writer) (string, error) {
	if log == nil {
		log = os.Stderr
	}
	logf := cli.MakeLogf(quiet, log)
	stagef := cli.MakeStagef(quiet, log)

	if outPath == "" {
		outPath = filepath.Join(inDir, "flutter_meta.json")
	}

	// 1. Read functions.jsonl.
	funcs, err := jsonutil.ReadJSONL[disasm.FuncRecord](filepath.Join(inDir, "functions.jsonl"))
	if err != nil {
		return "", fmt.Errorf("read functions.jsonl: %w", err)
	}
	stagef("meta", "%s%d%s functions", cli.Gold, len(funcs), cli.Reset)

	metaFuncs := make([]strutil.FlutterMetaFunc, len(funcs))
	for i, f := range funcs {
		metaFuncs[i] = strutil.FlutterMetaFunc{
			Addr:       f.PC,
			Name:       f.Name,
			Size:       f.Size,
			Owner:      f.Owner,
			ParamCount: f.ParamCount,
		}
	}

	// 2. Determine which functions to decompile.
	var focusFuncs []string
	if decompAll {
		for _, f := range funcs {
			focusFuncs = append(focusFuncs, f.PC)
		}
		logf("  %sfocus:%s ALL %d functions\n", cli.Muted, cli.Reset, len(focusFuncs))
	} else {
		sgPath := filepath.Join(inDir, "signal_graph.json")
		if data, err := os.ReadFile(sgPath); err == nil {
			var sg signal.SignalGraph
			if err := json.Unmarshal(data, &sg); err == nil {
				for _, sf := range sg.Funcs {
					if sf.Role == "signal" {
						focusFuncs = append(focusFuncs, sf.PC)
					}
				}
			}
		}
		logf("  %sfocus:%s %d signal functions %s(use --all for everything)%s\n",
			cli.Muted, cli.Reset, len(focusFuncs), cli.Muted, cli.Reset)
	}

	// 2b. Read dart_meta.json for pointer size and THR fields.
	var pointerSize int
	var dartVersion string
	var thrFields []strutil.FlutterMetaTHRField
	dmPath := filepath.Join(inDir, "dart_meta.json")
	if dmData, err := os.ReadFile(dmPath); err == nil {
		var dm struct {
			DartVersion string `json:"dart_version"`
			PointerSize int    `json:"pointer_size"`
			THRFields   []struct {
				Offset int    `json:"offset"`
				Name   string `json:"name"`
			} `json:"thr_fields"`
		}
		if err := json.Unmarshal(dmData, &dm); err == nil {
			dartVersion = dm.DartVersion
			pointerSize = dm.PointerSize
			for _, f := range dm.THRFields {
				thrFields = append(thrFields, strutil.FlutterMetaTHRField{Offset: f.Offset, Name: f.Name})
			}
			logf("  %sdart:%s %s  %sptr_size:%s %d  %sthr_fields:%s %d\n",
				cli.Muted, cli.Reset, dartVersion, cli.Muted, cli.Reset, pointerSize, cli.Muted, cli.Reset, len(thrFields))
		}
	} else {
		logf("  %s! dart_meta.json: %v (ptr_size defaults to 8)%s\n", cli.Red, err, cli.Reset)
		pointerSize = 8
	}

	// 2c. Read class layouts.
	classLayouts, err := jsonutil.ReadJSONL[strutil.FlutterMetaJSONClass](filepath.Join(inDir, "classes.jsonl"))
	if err != nil {
		logf("  %s! classes.jsonl: %v%s\n", cli.Red, err, cli.Reset)
		classLayouts = nil
	} else {
		logf("  %sclasses:%s %d layouts\n", cli.Muted, cli.Reset, len(classLayouts))
	}

	// 3. Extract comments from asm/*.txt files.
	asmDir := filepath.Join(inDir, "asm")
	comments, err := strutil.ExtractAsmComments(asmDir)
	if err != nil {
		logf("  %s! asm comments: %v%s\n", cli.Red, err, cli.Reset)
		comments = nil
	}
	logf("  %scomments:%s %d from asm files\n", cli.Muted, cli.Reset, len(comments))

	// 3b. Merge string references as comments.
	stringRefs, err := jsonutil.ReadJSONL[disasm.StringRefRecord](filepath.Join(inDir, "string_refs.jsonl"))
	if err != nil {
		logf("  %s! string_refs.jsonl: %v%s\n", cli.Red, err, cli.Reset)
	} else {
		seen := make(map[string]bool, len(comments))
		for _, c := range comments {
			seen[c.Addr] = true
		}
		strAdded := 0
		for _, sr := range stringRefs {
			addr := strutil.NormalizeHexAddr(sr.PC)
			if seen[addr] {
				continue
			}
			seen[addr] = true
			val := sr.Value
			if len(val) > 80 {
				val = val[:77] + "..."
			}
			comments = append(comments, strutil.FlutterMetaComment{
				Addr: addr,
				Text: fmt.Sprintf("str: %q", val),
			})
			strAdded++
		}
		logf("  %sstring refs:%s +%d comments\n", cli.Muted, cli.Reset, strAdded)
	}

	// 4. Write flutter_meta.json.
	meta := strutil.FlutterMetaJSON{
		Version:        "1",
		DartVersion:    dartVersion,
		PointerSize:    pointerSize,
		Functions:      metaFuncs,
		Comments:       comments,
		FocusFunctions: focusFuncs,
		Classes:        classLayouts,
		THRFields:      thrFields,
	}

	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("create output: %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(meta); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write json: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close output: %w", err)
	}

	logf("  %s->%s %s%s%s (%d bytes)\n", cli.Muted, cli.Reset, cli.Blue, outPath, cli.Reset, strutil.FileSize(outPath))

	return outPath, nil
}
