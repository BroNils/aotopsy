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

	// Meta is a semantic import artifact, so it must stay bound to the exact ELF
	// generation that produced all addresses, names and layouts below. Every real
	// meta entry point already has provenance; accepting a legacy anonymous
	// directory here merely turns stale metadata into plausible wrong renames.
	prov, ok, err := ReadProvenance(inDir)
	if err != nil {
		return "", fmt.Errorf("read metadata provenance: %w", err)
	}
	if !ok {
		return "", fmt.Errorf("metadata generation requires complete binary provenance")
	}
	if prov.Arch != targetArch {
		return "", fmt.Errorf("metadata provenance architecture %q does not match requested %q", prov.Arch, targetArch)
	}

	// 1. Read functions.jsonl.
	funcs, err := jsonutil.ReadJSONL[disasm.FuncRecord](filepath.Join(inDir, "functions.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		return "", fmt.Errorf("read functions.jsonl: %w", err)
	}
	stagef("meta", "%s%d%s functions", cli.Gold, len(funcs), cli.Reset)

	metaFuncs := make([]strutil.FlutterMetaFunc, 0, len(funcs))
	functionPCs := make(map[string]int, len(funcs))
	for i, f := range funcs {
		addr, err := strutil.NormalizeHexAddr(f.PC)
		if err != nil {
			return "", fmt.Errorf("functions.jsonl record %d PC %q: %w", i, f.PC, err)
		}
		if f.Name == "" {
			return "", fmt.Errorf("functions.jsonl record %d at %s has empty name", i, addr)
		}
		if f.Size <= 0 || int64(f.Size) > maxFunctionBinBytes {
			return "", fmt.Errorf("functions.jsonl record %d at %s has invalid size %d", i, addr, f.Size)
		}
		if f.ParamCount < 0 {
			return "", fmt.Errorf("functions.jsonl record %d at %s has negative param_count %d", i, addr, f.ParamCount)
		}
		mf := strutil.FlutterMetaFunc{
			Addr:       addr,
			Name:       f.Name,
			Size:       f.Size,
			Owner:      f.Owner,
			ParamCount: f.ParamCount,
		}
		if priorIndex, exists := functionPCs[addr]; exists {
			prior := metaFuncs[priorIndex]
			// Pre-InstructionsTable snapshots can have many Function/Code aliases
			// sharing one deduplicated instructions payload. The disassembly stage
			// resolves all aliases at that VA to the same canonical display name,
			// while owner/arity metadata remains row-specific. Keep the final alias:
			// BuildSymbolNames uses the same last-write rule for a shared VA, so this
			// row is the metadata that corresponds to the canonical name. A duplicate
			// address with a different canonical name or size is not a code alias and
			// stays a hard error rather than being silently collapsed.
			if prior.Name != mf.Name || prior.Size != mf.Size {
				return "", fmt.Errorf("functions.jsonl contains duplicate function address %s with conflicting identity", addr)
			}
			metaFuncs[priorIndex] = mf
			continue
		}
		functionPCs[addr] = len(metaFuncs)
		metaFuncs = append(metaFuncs, mf)
	}

	// 2. Determine which functions to decompile.
	var focusFuncs []string
	if decompAll {
		for _, f := range metaFuncs {
			focusFuncs = append(focusFuncs, f.Addr)
		}
		logf("  %sfocus:%s ALL %d functions\n", cli.Muted, cli.Reset, len(focusFuncs))
	} else {
		sgPath := filepath.Join(outDir, "signal_graph.json")
		sg, err := readJSONBounded[signal.SignalGraph](sgPath, maxSignalGraphBytes)
		if errors.Is(err, os.ErrNotExist) && filepath.Clean(outDir) != filepath.Clean(inDir) {
			sgPath = filepath.Join(inDir, "signal_graph.json")
			sg, err = readJSONBounded[signal.SignalGraph](sgPath, maxSignalGraphBytes)
		}
		if err != nil {
			return "", fmt.Errorf("read signal graph for focus set: %w", err)
		}
		focusSeen := make(map[string]struct{})
		for _, sf := range sg.Funcs {
			if sf.Role == "signal" {
				addr, err := strutil.NormalizeHexAddr(sf.PC)
				if err != nil {
					return "", fmt.Errorf("signal graph function PC %q: %w", sf.PC, err)
				}
				if _, ok := functionPCs[addr]; !ok {
					return "", fmt.Errorf("signal graph focus address %s is not present in functions.jsonl", addr)
				}
				if _, seen := focusSeen[addr]; !seen {
					focusSeen[addr] = struct{}{}
					focusFuncs = append(focusFuncs, addr)
				}
			}
		}
		logf("  %sfocus:%s %d signal functions %s(use --all for everything)%s\n",
			cli.Muted, cli.Reset, len(focusFuncs), cli.Muted, cli.Reset)
	}

	// 2b. Read dart_meta.json for pointer size and THR fields.
	dmPath := filepath.Join(inDir, "dart_meta.json")
	dm, err := readJSONBounded[strutil.DartMetaJSON](dmPath, maxMetadataArtifactBytes)
	if err != nil {
		return "", fmt.Errorf("read dart_meta.json: %w", err)
	}
	if dm.Architecture != targetArch {
		return "", fmt.Errorf("dart_meta.json: architecture %q does not match requested %q", dm.Architecture, targetArch)
	}
	if _, err := strutil.ValidateDartMeta(dm); err != nil {
		return "", fmt.Errorf("dart_meta.json: %w", err)
	}
	if prov.DartVersion != dm.DartVersion || prov.CompressedPointers != dm.CompressedPointers {
		return "", fmt.Errorf("dart_meta.json identity disagrees with provenance: dart=%q/%q compressed=%v/%v",
			dm.DartVersion, prov.DartVersion, dm.CompressedPointers, prov.CompressedPointers)
	}
	logf("  %sdart:%s %s  %sptr_size:%s %d  %sthr_fields:%s %d\n",
		cli.Muted, cli.Reset, dm.DartVersion, cli.Muted, cli.Reset, dm.PointerSize, cli.Muted, cli.Reset, len(dm.THRFields))

	// 2c. Read class layouts.
	classLayouts, err := jsonutil.ReadJSONL[strutil.FlutterMetaJSONClass](filepath.Join(inDir, "classes.jsonl"), jsonutil.StandardLimits)
	if err != nil {
		return "", fmt.Errorf("read classes.jsonl: %w", err)
	}
	classIDs := make(map[int32]struct{}, len(classLayouts))
	for i, class := range classLayouts {
		if class.ClassName == "" || class.ClassID <= 0 || class.InstanceSize < 8 || class.InstanceSize%int32(dm.PointerSize) != 0 {
			return "", fmt.Errorf("classes.jsonl record %d has invalid identity/layout: name=%q cid=%d size=%d",
				i, class.ClassName, class.ClassID, class.InstanceSize)
		}
		if _, exists := classIDs[class.ClassID]; exists {
			return "", fmt.Errorf("classes.jsonl contains duplicate class_id %d", class.ClassID)
		}
		classIDs[class.ClassID] = struct{}{}
		offsets := make(map[int32]struct{}, len(class.Fields))
		for j, field := range class.Fields {
			if field.Name == "" || field.ByteOffset < 8 || field.ByteOffset%int32(dm.PointerSize) != 0 ||
				int64(field.ByteOffset)+int64(dm.PointerSize) > int64(class.InstanceSize) {
				return "", fmt.Errorf("classes.jsonl class %q field %d has invalid name/offset %q@%d for size %d",
					class.ClassName, j, field.Name, field.ByteOffset, class.InstanceSize)
			}
			switch field.SlotType {
			case "type_arguments_field":
				if !field.IsReference {
					return "", fmt.Errorf("classes.jsonl class %q field %d marks type_arguments_field as non-reference", class.ClassName, j)
				}
			case "instance_field", "unknown_slot":
			default:
				return "", fmt.Errorf("classes.jsonl class %q field %d has unknown slot_type %q", class.ClassName, j, field.SlotType)
			}
			if _, exists := offsets[field.ByteOffset]; exists {
				return "", fmt.Errorf("classes.jsonl class %q has duplicate field offset %d", class.ClassName, field.ByteOffset)
			}
			offsets[field.ByteOffset] = struct{}{}
		}
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
		addr, err := strutil.NormalizeHexAddr(sr.PC)
		if err != nil {
			return "", fmt.Errorf("string ref PC %q: %w", sr.PC, err)
		}
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
		Version:            "3",
		Architecture:       targetArch,
		DartVersion:        dm.DartVersion,
		BinarySHA256:       prov.SHA256,
		BinarySize:         prov.Size,
		CompressedPointers: dm.CompressedPointers,
		PointerSize:        dm.PointerSize,
		Functions:          metaFuncs,
		Comments:           comments,
		FocusFunctions:     focusFuncs,
		Classes:            classLayouts,
		THRFields:          dm.THRFields,
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
