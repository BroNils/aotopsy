package analysis

import (
	"fmt"
	"os"
	"path/filepath"
)

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
	if err := os.MkdirAll(ghidraDir, 0755); err != nil {
		return "", fmt.Errorf("mkdir ghidra artifacts: %w", err)
	}

	scripts := []string{"aotopsy_apply.py", "aotopsy_prescript.py"}
	for _, name := range scripts {
		src := filepath.Join(scriptDir, name)
		dst := filepath.Join(ghidraDir, name)
		data, err := os.ReadFile(src)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", name, err)
		}
		if err := os.WriteFile(dst, data, 0644); err != nil {
			return "", fmt.Errorf("write %s: %w", name, err)
		}
	}

	fmt.Fprintf(os.Stderr, "copied Ghidra scripts → %s\n", ghidraDir)
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
	if err := os.MkdirAll(idaDir, 0755); err != nil {
		return "", fmt.Errorf("mkdir ida artifacts: %w", err)
	}

	dst := filepath.Join(idaDir, "aotopsy_apply.py")
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		return "", fmt.Errorf("read ida script: %w", err)
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		return "", fmt.Errorf("write ida script: %w", err)
	}

	fmt.Fprintf(os.Stderr, "copied IDA script → %s\n", idaDir)
	return dst, nil
}
