package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"aotopsy/internal/dartfmt"
	"aotopsy/internal/disasm"
	"aotopsy/internal/output"
	"aotopsy/internal/pipeline"
	"aotopsy/internal/sdk"
	"aotopsy/internal/snapshot"
)

func cmdDump(args []string) error {
	fs := flag.NewFlagSet("dump", flag.ExitOnError)
	libapp := fs.String("lib", "", "path to libapp.so")
	outDir := fs.String("out", "", "output directory")
	_ = fs.String("profile", "", "override version profile (not yet implemented)")
	strict := fs.Bool("strict", false, "fail on first structural error")
	maxSteps := fs.Int("max-steps", 0, "global loop cap")

	if err := fs.Parse(args); err != nil {
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

	// Create output directory.
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Open ELF + extract snapshots.
	ef, info, err := pipeline.LoadSnapshotRaw(*libapp, opts)
	if err != nil {
		return err
	}
	defer func() { _ = ef.Close() }()
	isARM64 := ef.IsARM64()

	// Write snapshot.json.
	if err := output.WriteSnapshotJSON(*outDir, info); err != nil {
		return fmt.Errorf("write snapshot.json: %w", err)
	}
	_, _ = fmt.Fprintf(os.Stderr, "wrote %s/snapshot.json\n", *outDir)

	// Generate placeholder symbols from instruction region.
	symbols := make(map[uint64]string)
	var symList []output.SymbolEntry

	// For now, generate sub_<addr> entries at the start of each region.
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
	if err := output.WriteSymbolsJSON(*outDir, symList); err != nil {
		return fmt.Errorf("write symbols.json: %w", err)
	}
	_, _ = fmt.Fprintf(os.Stderr, "wrote %s/symbols.json (%d entries)\n", *outDir, len(symList))

	lookup := disasm.PlaceholderLookup(symbols)

	if isARM64 {
		// Extract actual code region from isolate instructions (skip Image + InstructionsSection headers).
		if len(info.IsolateInstructions.Data) > 0 {
			code, codeOff, payloadLen, err := snapshot.CodeRegion(info.IsolateInstructions.Data)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "warning: could not parse isolate instructions image header: %v\n", err)
				// Fall back to raw disassembly.
				code = info.IsolateInstructions.Data
				codeOff = 0
				payloadLen = uint64(len(code))
			}
			codeVA := info.IsolateInstructions.VA + codeOff
			_, _ = fmt.Fprintf(os.Stderr, "disassembling isolate code (%d bytes, VA=0x%x, payload=%d)...\n",
				len(code), codeVA, payloadLen)
			insts := disasm.Disassemble(code, disasm.Options{
				BaseAddr: codeVA,
				MaxSteps: opts.EffectiveMaxSteps(),
				Symbols:  lookup,
			})
			if err := output.WriteASMSingle(*outDir, insts, lookup); err != nil {
				return fmt.Errorf("write asm.txt: %w", err)
			}
			_, _ = fmt.Fprintf(os.Stderr, "wrote %s/asm.txt (%d instructions)\n", *outDir, len(insts))
		}

		// Extract code from VM instructions.
		if len(info.VmInstructions.Data) > 0 {
			code, codeOff, _, err := snapshot.CodeRegion(info.VmInstructions.Data)
			if err != nil {
				code = info.VmInstructions.Data
				codeOff = 0
			}
			codeVA := info.VmInstructions.VA + codeOff
			insts := disasm.Disassemble(code, disasm.Options{
				BaseAddr: codeVA,
				MaxSteps: opts.EffectiveMaxSteps(),
			})
			if err := output.WriteASM(*outDir, "vm_stubs", insts, lookup); err != nil {
				return fmt.Errorf("write asm/vm_stubs.txt: %w", err)
			}
			_, _ = fmt.Fprintf(os.Stderr, "wrote %s/asm/vm_stubs.txt (%d instructions)\n", *outDir, len(insts))
		}
	} else {
		if len(info.IsolateInstructions.Data) > 0 {
			code, codeOff, payloadLen, err := snapshot.CodeRegion(info.IsolateInstructions.Data)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "warning: could not parse isolate instructions image header: %v\n", err)
				code = info.IsolateInstructions.Data
				codeOff = 0
				payloadLen = uint64(len(code))
			}
			codeVA := info.IsolateInstructions.VA + codeOff
			_, _ = fmt.Fprintf(os.Stderr, "disassembling isolate code (%d bytes, VA=0x%x, payload=%d)...\n",
				len(code), codeVA, payloadLen)
			n, err := writeX86ASMBlob(filepath.Join(*outDir, "asm.txt"), code, codeVA, lookup, opts.EffectiveMaxSteps())
			if err != nil {
				return fmt.Errorf("write asm.txt: %w", err)
			}
			_, _ = fmt.Fprintf(os.Stderr, "wrote %s/asm.txt (%d instructions)\n", *outDir, n)
		}

		if len(info.VmInstructions.Data) > 0 {
			code, codeOff, _, err := snapshot.CodeRegion(info.VmInstructions.Data)
			if err != nil {
				code = info.VmInstructions.Data
				codeOff = 0
			}
			codeVA := info.VmInstructions.VA + codeOff
			if err := os.MkdirAll(filepath.Join(*outDir, "asm"), 0o755); err != nil {
				return fmt.Errorf("mkdir asm: %w", err)
			}
			n, err := writeX86ASMBlob(filepath.Join(*outDir, "asm", "vm_stubs.txt"), code, codeVA, lookup, opts.EffectiveMaxSteps())
			if err != nil {
				return fmt.Errorf("write asm/vm_stubs.txt: %w", err)
			}
			_, _ = fmt.Fprintf(os.Stderr, "wrote %s/asm/vm_stubs.txt (%d instructions)\n", *outDir, n)
		}
	}

	if len(info.Diags) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "\ndiagnostics: %d issues\n", len(info.Diags))
		for _, d := range info.Diags {
			_, _ = fmt.Fprintf(os.Stderr, "  %s\n", d)
		}
	}

	return nil
}

// writeX86ASMBlob disassembles a flat x86_64 code region (not per-function
// -- dump's whole point is a single raw sequential pass) and writes an
// annotated listing, mirroring internal/pipeline/disasm_stage_x86.go's
// writeX86ASM but for one large blob instead of many small function
// ranges, matching this command's own ARM64 path (disasm.Disassemble +
// output.WriteASM/WriteASMSingle over the whole region).
func writeX86ASMBlob(path string, code []byte, baseVA uint64, lookup disasm.SymbolLookup, maxSteps int) (int, error) {
	f, err := os.Create(path) //nolint:gosec // path is built from this run's own --out directory, not untrusted input
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	n := 0
	sdk.WalkX86(code, baseVA, func(d sdk.X86Decoded) bool {
		if maxSteps > 0 && n >= maxSteps {
			return false
		}
		if d.Bad {
			_, _ = fmt.Fprintf(f, "0x%x: <bad>\n", d.VA)
			n++
			return true
		}
		line := d.Inst.String()
		if target, ok := sdk.X86RelTarget(d.Inst, d.VA, d.Len); ok {
			if name, ok := lookup(target); ok {
				line += fmt.Sprintf("  ; -> %s", name)
			} else {
				line += fmt.Sprintf("  ; -> 0x%x", target)
			}
		}
		_, _ = fmt.Fprintf(f, "0x%x: %s\n", d.VA, line)
		n++
		return true
	})
	return n, nil
}
