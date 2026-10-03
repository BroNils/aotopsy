package analysis

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"aotopsy/internal/cli"
	"aotopsy/internal/decompiler"
	"aotopsy/internal/naming"
	"aotopsy/internal/output"
)

// RunDecompileStage writes one .dart pseudocode file per function under
// <out>/dart/, mirroring the asm/ layout.
//
// The pipeline wrote 8049 .txt disassembly listings and not one line of
// decompiled Dart: EmitPseudocode was reachable only from `export-dart`
// and `_debug decompile-native`, so the tool's most useful output was
// invisible to anyone running the tool the documented way.
//
// It is behind a flag rather than on by default because it is genuinely
// expensive, not because it is optional in spirit: a full run over a real
// app roughly triples the output directory (127 MB -> ~370 MB measured on
// dart-3.9.2-gt-arm64). Run() says so on every run that does not use it,
// so the capability is discoverable instead of merely present.
func RunDecompileStage(opts *Opts, ctx *AnalysisContext) (int, error) {
	if ctx == nil || ctx.EF == nil {
		return 0, fmt.Errorf("decompile: missing analysis context")
	}
	dartDir := filepath.Join(opts.OutDir, "dart")
	if err := os.MkdirAll(dartDir, 0o755); err != nil {
		return 0, fmt.Errorf("mkdir dart: %w", err)
	}

	symLk := func(va uint64) (string, bool) {
		s, ok := ctx.SymbolNames[va]
		return s, ok && s != ""
	}
	poolLk := func(i int) (string, bool) {
		s, ok := ctx.PoolDisplay[i]
		return s, ok
	}

	n := len(ctx.Ranges)
	if opts.Limit > 0 && opts.Limit < n {
		n = opts.Limit
	}

	written, orphanBlocks, orphanFuncs := 0, 0, 0
	for i := 0; i < n; i++ {
		r := ctx.Ranges[i]
		if r.Size == 0 {
			continue
		}
		fir, err := ctx.FuncIRFor(r)
		if err != nil {
			return written, fmt.Errorf("decompile pc=0x%x ref=%d: %w", r.PCOffset, r.RefID, err)
		}
		if fir == nil {
			return written, fmt.Errorf("decompile pc=0x%x ref=%d: FuncIRFor returned nil IR without error", r.PCOffset, r.RefID)
		}
		if len(fir.Blocks) == 0 {
			continue
		}
		art := decompiler.EmitPseudocode(fir, symLk, poolLk)
		if art.Stats.OrphanBlocks > 0 {
			orphanFuncs++
			orphanBlocks += art.Stats.OrphanBlocks
		}

		var ownerName, funcName string
		if r.RefID >= 0 {
			ci := ctx.Pool.CodeNames[r.RefID]
			ownerName, funcName = ci.OwnerName, ci.FuncName
		}
		if funcName == "" {
			funcName = fmt.Sprintf("stub_%x", r.PCOffset)
		}
		rel := naming.FuncRelPath(ownerName, funcName, r.PCOffset)
		if err := writeDartFile(opts.OutDir, "dart/"+rel+".dart", art.Source); err != nil {
			return written, err
		}
		written++
	}

	opts.stagef("decompile", "%s%d%s functions -> %s%s%s",
		cli.Gold, written, cli.Reset, cli.Blue, dartDir, cli.Reset)
	if orphanFuncs > 0 {
		opts.logf("  %sorphan blocks:%s %d across %d functions (code the structured walk would otherwise have dropped)\n",
			cli.Muted, cli.Reset, orphanBlocks, orphanFuncs)
	}
	return written, nil
}

func writeDartFile(root, rel, source string) error {
	return output.WriteArtifactAtomic(root, rel, 0o644, func(w io.Writer) error {
		_, err := io.WriteString(w, source)
		return err
	})
}
