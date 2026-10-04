package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"aotopsy/internal/analysis"
	"aotopsy/internal/arch/x86"
	"aotopsy/internal/cli"
	"aotopsy/internal/dartfmt"
	"aotopsy/internal/disasm"
	"aotopsy/internal/output"
	"aotopsy/internal/snapshot"
)

// cmdDump handles "aotopsy _debug dump" for low-level sequential disassembly and placeholder symbol dumping.
func cmdDump(args []string) error {
	fs := flag.NewFlagSet("dump", flag.ContinueOnError)
	libapp := fs.String("lib", "", "path to libapp.so")
	outDir := fs.String("out", "", "output directory")
	strict := fs.Bool("strict", false, "fail on first structural error")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")

	if err := parseNoPositionals(fs, args); err != nil {
		return err
	}
	if err := requireNonNegativeFlag("max-steps", *maxSteps); err != nil {
		return err
	}

	if *libapp == "" || *outDir == "" {
		return fmt.Errorf("--lib and --out are required")
	}

	opts := dartfmt.Options{
		Mode:     dartfmt.ModeBestEffort,
		MaxSteps: *maxSteps,
	}
	if *strict {
		opts.Mode = dartfmt.ModeStrict
	}

	containsSource, err := output.ContainsPath(*outDir, *libapp)
	if err != nil {
		return fmt.Errorf("compare dump output/source paths: %w", err)
	}
	if containsSource {
		return fmt.Errorf("dump output directory must not contain the source binary")
	}
	tx, err := output.BeginDirTransaction(*outDir)
	if err != nil {
		return fmt.Errorf("begin dump generation: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Abort()
		}
	}()
	stageOutDir := tx.StageDir()

	// Open ELF + extract snapshots.
	ef, info, err := analysis.LoadSnapshotRaw(*libapp, opts)
	if err != nil {
		return err
	}
	defer func() { _ = ef.Close() }()
	isARM64 := ef.IsARM64()
	logger := cli.NewLogger(os.Stderr, false)
	if info.Version == nil {
		return fmt.Errorf("HALT_UNKNOWN_VERSION: snapshot hash %s has no verified parser profile", info.SnapshotHash())
	}
	if !info.Version.Supported {
		return fmt.Errorf("HALT_UNSUPPORTED_VERSION: Dart %s (hash %s)", info.Version.DartVersion, info.SnapshotHash())
	}

	// Write parser/debug snapshot metadata separately from pipeline provenance.
	if err := output.WriteSnapshotInfoJSON(stageOutDir, info); err != nil {
		return fmt.Errorf("write snapshot_info.json: %w", err)
	}
	logger.Printf("wrote %s/snapshot_info.json\n", *outDir)

	// Generate placeholder symbols from instruction region.
	symbols := make(map[uint64]string)
	var symList []output.SymbolEntry

	// Generate sub_<addr> entries at the start of each region.
	if info.IsolateInstructions.VA != 0 {
		name := fmt.Sprintf("sub_%x", info.IsolateInstructions.VA)
		symbols[info.IsolateInstructions.VA] = name
		symList = append(symList, output.SymbolEntry{
			Address: info.IsolateInstructions.VA,
			Name:    name,
			Size:    info.IsolateInstructions.DataSize,
		})
	}
	if info.VmInstructions.VA != 0 {
		name := fmt.Sprintf("sub_%x", info.VmInstructions.VA)
		symbols[info.VmInstructions.VA] = name
		symList = append(symList, output.SymbolEntry{
			Address: info.VmInstructions.VA,
			Name:    name,
			Size:    info.VmInstructions.DataSize,
		})
	}

	// Write symbols.json.
	if err := output.WriteSymbolsJSON(stageOutDir, symList); err != nil {
		return fmt.Errorf("write symbols.json: %w", err)
	}
	logger.Printf("wrote %s/symbols.json (%d entries)\n", *outDir, len(symList))

	lookup := disasm.PlaceholderLookup(symbols)

	if isARM64 {
		if len(info.IsolateInstructions.Data) > 0 {
			code, codeOff, payloadLen, err := snapshot.CodeRegion(info.IsolateInstructions.Data, info.Version)
			if err != nil {
				return fmt.Errorf("parse isolate instructions image: %w", err)
			}
			codeVA := info.IsolateInstructions.VA + codeOff
			logger.Printf("disassembling isolate code (%d bytes, VA=0x%x, payload=%d)...\n",
				len(code), codeVA, payloadLen)
			insts := disasm.Disassemble(code, disasm.Options{
				BaseAddr: codeVA,
				MaxSteps: opts.EffectiveMaxSteps(),
				Symbols:  lookup,
			})
			if err := output.WriteASMSingle(stageOutDir, insts, lookup); err != nil {
				return fmt.Errorf("write asm.txt: %w", err)
			}
			logger.Printf("wrote %s/asm.txt (%d instructions)\n", *outDir, len(insts))
		}

		if len(info.VmInstructions.Data) > 0 {
			code, codeOff, _, err := snapshot.CodeRegion(info.VmInstructions.Data, info.Version)
			if err != nil {
				return fmt.Errorf("parse VM instructions image: %w", err)
			}
			codeVA := info.VmInstructions.VA + codeOff
			insts := disasm.Disassemble(code, disasm.Options{
				BaseAddr: codeVA,
				MaxSteps: opts.EffectiveMaxSteps(),
			})
			if err := output.WriteASM(stageOutDir, "vm_stubs", insts, lookup); err != nil {
				return fmt.Errorf("write asm/vm_stubs.txt: %w", err)
			}
			logger.Printf("wrote %s/asm/vm_stubs.txt (%d instructions)\n", *outDir, len(insts))
		}
	} else {
		if len(info.IsolateInstructions.Data) > 0 {
			code, codeOff, payloadLen, err := snapshot.CodeRegion(info.IsolateInstructions.Data, info.Version)
			if err != nil {
				return fmt.Errorf("parse isolate instructions image: %w", err)
			}
			codeVA := info.IsolateInstructions.VA + codeOff
			logger.Printf("disassembling isolate code (%d bytes, VA=0x%x, payload=%d)...\n",
				len(code), codeVA, payloadLen)
			n, err := writeX86ASMBlob(filepath.Join(stageOutDir, "asm.txt"), code, codeVA, lookup, opts.EffectiveMaxSteps())
			if err != nil {
				return fmt.Errorf("write asm.txt: %w", err)
			}
			logger.Printf("wrote %s/asm.txt (%d instructions)\n", *outDir, n)
		}

		if len(info.VmInstructions.Data) > 0 {
			code, codeOff, _, err := snapshot.CodeRegion(info.VmInstructions.Data, info.Version)
			if err != nil {
				return fmt.Errorf("parse VM instructions image: %w", err)
			}
			codeVA := info.VmInstructions.VA + codeOff
			if err := os.MkdirAll(filepath.Join(stageOutDir, "asm"), 0o755); err != nil {
				return fmt.Errorf("mkdir asm: %w", err)
			}
			n, err := writeX86ASMBlob(filepath.Join(stageOutDir, "asm", "vm_stubs.txt"), code, codeVA, lookup, opts.EffectiveMaxSteps())
			if err != nil {
				return fmt.Errorf("write asm/vm_stubs.txt: %w", err)
			}
			logger.Printf("wrote %s/asm/vm_stubs.txt (%d instructions)\n", *outDir, n)
		}
	}

	if len(info.Diags) > 0 {
		logger.Printf("\ndiagnostics: %d issues\n", len(info.Diags))
		for _, d := range info.Diags {
			logger.Printf("  %s\n", d)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("publish dump generation: %w", err)
	}
	committed = true

	return nil
}

func writeX86ASMBlob(path string, code []byte, baseVA uint64, lookup disasm.SymbolLookup, maxSteps int) (int, error) {
	n := 0
	err := output.WriteAtomic(path, 0o644, func(w io.Writer) error {
		var writeErr error
		x86.Walk(code, baseVA, func(d x86.Decoded) bool {
			if maxSteps > 0 && n >= maxSteps {
				return false
			}
			if d.Bad {
				_, writeErr = fmt.Fprintf(w, "0x%x: <bad>\n", d.VA)
				n++
				return writeErr == nil
			}
			line := x86.InstText(d.Inst)
			if target, ok := x86.RelTarget(d.Inst, d.VA, d.Len); ok {
				if name, ok := lookup(target); ok {
					line += fmt.Sprintf("  ; -> %s", name)
				} else {
					line += fmt.Sprintf("  ; -> 0x%x", target)
				}
			}
			_, writeErr = fmt.Fprintf(w, "0x%x: %s\n", d.VA, line)
			n++
			return writeErr == nil
		})
		return writeErr
	})
	return n, err
}
