package analysis

import (
	"fmt"
	"os"
	"path/filepath"
)

// CopyGhidraArtifacts copies Ghidra scripts into outDir/ghidra/.
func CopyGhidraArtifacts(outDir string) error {
	scriptDir, err := FindScriptPath()
	if err != nil {
		return err
	}

	ghidraDir := filepath.Join(outDir, "ghidra")
	if err := os.MkdirAll(ghidraDir, 0755); err != nil {
		return fmt.Errorf("mkdir ghidra artifacts: %w", err)
	}

	scripts := []string{"aotopsy_apply.py", "aotopsy_prescript.py"}
	for _, name := range scripts {
		src := filepath.Join(scriptDir, name)
		dst := filepath.Join(ghidraDir, name)
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if err := os.WriteFile(dst, data, 0644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}

	fmt.Fprintf(os.Stderr, "copied Ghidra scripts → %s\n", ghidraDir)
	return nil
}

// CopyIDAArtifacts copies IDA scripts into outDir/ida/.
func CopyIDAArtifacts(outDir string) error {
	scriptPath, err := FindIDAScript()
	if err != nil {
		return err
	}

	idaDir := filepath.Join(outDir, "ida")
	if err := os.MkdirAll(idaDir, 0755); err != nil {
		return fmt.Errorf("mkdir ida artifacts: %w", err)
	}

	dst := filepath.Join(idaDir, "aotopsy_apply.py")
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("read ida script: %w", err)
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		return fmt.Errorf("write ida script: %w", err)
	}

	fmt.Fprintf(os.Stderr, "copied IDA script → %s\n", idaDir)
	return nil
}
