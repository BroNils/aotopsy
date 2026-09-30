package analysis

import (
	"errors"
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

// dartMetaFile is the subset of dart_meta.json (strutil.WriteDartMeta) the meta
// stage consumes. It is decoded with DisallowUnknownFields, so it must list
// every key the writer can emit.
type dartMetaFile struct {
	Architecture       string `json:"arch"`
	DartVersion        string `json:"dart_version"`
	CompressedPointers bool   `json:"compressed_pointers"`
	PointerSize        int    `json:"pointer_size"`
	THRFields          []struct {
		Offset int    `json:"offset"`
		Name   string `json:"name"`
	} `json:"thr_fields"`
}

// RunMetaStage reads existing disassembly artifacts from inDir and writes
// flutter_meta.json under outDir. signal_graph.json, when present, is read from
// outDir because a preceding RunSignalStage may have regenerated it there.
// targetArch is explicit because the current schema is ARM64-specific and must
// never be inferred from disassembly bytes or a stale artifact name.
func RunMetaStage(inDir, outDir, targetArch string, decompAll bool, quiet bool, log io.Writer) (string, error) {
	if targetArch != "arm64" {
		return "", fmt.Errorf("flutter_meta.json is ARM64-only, got architecture %q", targetArch)
	}
	if log == nil {
		log = os.Stderr
	}
	logger := cli.NewLogger(log, quiet)
	logf := logger.Printf
	stagef := logger.Stage

	if outDir == "" {
		outDir = inDir
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir meta output: %w", err)
	}
	outPath := filepath.Join(outDir, "flutter_meta.json")

	// 1. Read functions.jsonl.
	funcs, err := jsonutil.ReadJSONL[disasm.FuncRecord](filepath.Join(inDir, "functions.jsonl"), jsonutil.StandardLimits)
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
		sgPath := filepath.Join(outDir, "signal_graph.json")
		sg, err := readJSONBounded[signal.SignalGraph](sgPath, maxMetadataArtifactBytes)
		if errors.Is(err, os.ErrNotExist) && filepath.Clean(outDir) != filepath.Clean(inDir) {
			sgPath = filepath.Join(inDir, "signal_graph.json")
			sg, err = readJSONBounded[signal.SignalGraph](sgPath, maxMetadataArtifactBytes)
		}
		if err != nil {
			return "", fmt.Errorf("read signal graph for focus set: %w", err)
		}
		for _, sf := range sg.Funcs {
			if sf.Role == "signal" {
				focusFuncs = append(focusFuncs, sf.PC)
			}
		}
		logf("  %sfocus:%s %d signal functions %s(use --all for everything)%s\n",
			cli.Muted, cli.Reset, len(focusFuncs), cli.Muted, cli.Reset)
	}

	// 2b. Read dart_meta.json for pointer size and THR fields.
	var pointerSize int
	var dartVersion string
	var compressedPointers bool
	var thrFields []strutil.FlutterMetaTHRField
	dmPath := filepath.Join(inDir, "dart_meta.json")
	dm, err := readJSONBounded[dartMetaFile](dmPath, maxMetadataArtifactBytes)
	if err != nil {
		return "", fmt.Errorf("read dart_meta.json: %w", err)
	}
	if dm.DartVersion == "" {
		return "", fmt.Errorf("dart_meta.json: missing dart_version")
	}
	if dm.Architecture != targetArch {
		return "", fmt.Errorf("dart_meta.json: architecture %q does not match requested %q", dm.Architecture, targetArch)
	}
	if dm.PointerSize != 4 && dm.PointerSize != 8 {
		return "", fmt.Errorf("dart_meta.json: invalid pointer_size %d", dm.PointerSize)
	}
	if dm.CompressedPointers && dm.PointerSize != 4 {
		return "", fmt.Errorf("dart_meta.json: compressed pointers require pointer_size 4, got %d", dm.PointerSize)
	}
	dartVersion = dm.DartVersion
	compressedPointers = dm.CompressedPointers
	pointerSize = dm.PointerSize
	for _, f := range dm.THRFields {
		thrFields = append(thrFields, strutil.FlutterMetaTHRField{Offset: f.Offset, Name: f.Name})
	}
	logf("  %sdart:%s %s  %sptr_size:%s %d  %sthr_fields:%s %d\n",
		cli.Muted, cli.Reset, dartVersion, cli.Muted, cli.Reset, pointerSize, cli.Muted, cli.Reset, len(thrFields))

	// 2c. Read class layouts.
	classLayouts, err := jsonutil.ReadJSONL[strutil.FlutterMetaJSONClass](filepath.Join(inDir, "classes.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		return "", fmt.Errorf("read classes.jsonl: %w", err)
	}
	logf("  %sclasses:%s %d layouts\n", cli.Muted, cli.Reset, len(classLayouts))

	// 3. Extract comments from asm/*.txt files.
	asmDir := filepath.Join(inDir, "asm")
	comments, err := strutil.ExtractAsmComments(asmDir)
	if err != nil {
		return "", fmt.Errorf("asm comments: %w", err)
	}
	logf("  %scomments:%s %d from asm files\n", cli.Muted, cli.Reset, len(comments))

	// 3b. Merge string references as comments.
	stringRefs, err := jsonutil.ReadJSONL[disasm.StringRefRecord](filepath.Join(inDir, "string_refs.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		return "", fmt.Errorf("read string_refs.jsonl: %w", err)
	}
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
		val := truncateMetaComment(sr.Value, 80)
		comments = append(comments, strutil.FlutterMetaComment{
			Addr: addr,
			Text: fmt.Sprintf("str: %q", val),
		})
		strAdded++
	}
	logf("  %sstring refs:%s +%d comments\n", cli.Muted, cli.Reset, strAdded)

	// 4. Write flutter_meta.json.
	meta := strutil.FlutterMetaJSON{
		Version:            "2",
		Architecture:       targetArch,
		DartVersion:        dartVersion,
		CompressedPointers: compressedPointers,
		PointerSize:        pointerSize,
		Functions:          metaFuncs,
		Comments:           comments,
		FocusFunctions:     focusFuncs,
		Classes:            classLayouts,
		THRFields:          thrFields,
	}

	if err := jsonutil.WriteJSONFile(outPath, meta); err != nil {
		return "", fmt.Errorf("write json: %w", err)
	}

	logf("  %s->%s %s%s%s (%d bytes)\n", cli.Muted, cli.Reset, cli.Blue, outPath, cli.Reset, strutil.FileSize(outPath))

	return outPath, nil
}

func truncateMetaComment(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	if maxRunes <= 3 {
		return string(runes[:maxRunes])
	}
	return string(runes[:maxRunes-3]) + "..."
}
