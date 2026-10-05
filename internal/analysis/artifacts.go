package analysis

import (
	"fmt"
	"os"
	"path/filepath"

	"aotopsy/internal/cli"
	"aotopsy/internal/output"
)

func augmentOutputGeneration(outDir string, mutate func(stage string) error) error {
	if mutate == nil {
		return fmt.Errorf("nil output generation mutator")
	}
	tx, err := output.BeginDirTransaction(outDir)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			tx.Abort()
		}
	}()
	if err := tx.CloneFrom(outDir); err != nil {
		return fmt.Errorf("clone current output generation: %w", err)
	}
	if err := mutate(tx.StageDir()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

// CopyGhidraArtifacts copies Ghidra scripts into outDir/ghidra/ and returns
// the absolute path of that directory. Callers run Ghidra against the returned
// path, never against the install location the scripts came from: the artifact
// directory is what stays valid when the output is moved or reused via --from.
func CopyGhidraArtifacts(outDir string) (string, error) {
	scriptDir, err := FindScriptPath()
	if err != nil {
		return "", err
	}

	ghidraDir, err := filepath.Abs(filepath.Join(outDir, "ghidra"))
	if err != nil {
		return "", fmt.Errorf("resolve ghidra artifacts dir: %w", err)
	}
	scripts := []string{"aotopsy_apply.py", "aotopsy_prescript.py"}
	payloads := make(map[string][]byte, len(scripts))
	for _, name := range scripts {
		src := filepath.Join(scriptDir, name)
		data, err := os.ReadFile(src)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", name, err)
		}
		payloads[name] = data
	}
	if err := augmentOutputGeneration(outDir, func(stage string) error {
		for _, name := range scripts {
			if err := output.WriteArtifactFile(stage, "ghidra/"+name, payloads[name], 0o644); err != nil {
				return fmt.Errorf("write %s: %w", name, err)
			}
		}
		return nil
	}); err != nil {
		return "", fmt.Errorf("publish Ghidra artifacts: %w", err)
	}

	cli.Errf("copied Ghidra scripts → %s\n", ghidraDir)
	return ghidraDir, nil
}

// CopyIDAArtifacts copies the IDA script into outDir/ida/ and returns the
// absolute path of the copy, which is the one callers execute.
func CopyIDAArtifacts(outDir string) (string, error) {
	scriptPath, err := FindIDAScript()
	if err != nil {
		return "", err
	}

	idaDir, err := filepath.Abs(filepath.Join(outDir, "ida"))
	if err != nil {
		return "", fmt.Errorf("resolve ida artifacts dir: %w", err)
	}
	dst := filepath.Join(idaDir, "aotopsy_apply.py")
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		return "", fmt.Errorf("read ida script: %w", err)
	}
	if err := augmentOutputGeneration(outDir, func(stage string) error {
		return output.WriteArtifactFile(stage, "ida/aotopsy_apply.py", data, 0o644)
	}); err != nil {
		return "", fmt.Errorf("publish IDA script: %w", err)
	}

	cli.Errf("copied IDA script → %s\n", idaDir)
	return dst, nil
}
