package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// findPython locates a python3 binary that can import idapro.
// Search order: explicit flag, PATH candidates, conda base, IDA bundled.
func findPython(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err == nil {
			return explicit, nil
		}
		return "", fmt.Errorf("python not found at %s", explicit)
	}

	// Candidates: PATH first, then conda base, then common IDA-adjacent locations.
	var candidates []string

	// PATH lookup.
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			candidates = append(candidates, p)
		}
	}

	// Conda base environment.
	condaPaths := []string{
		"/opt/homebrew/Caskroom/miniconda/base/bin/python3",
		filepath.Join(os.Getenv("HOME"), "miniconda3", "bin", "python3"),
		filepath.Join(os.Getenv("HOME"), "anaconda3", "bin", "python3"),
		filepath.Join(os.Getenv("CONDA_PREFIX"), "bin", "python3"),
	}
	for _, p := range condaPaths {
		if p != "/bin/python3" { // skip if env var was empty
			candidates = append(candidates, p)
		}
	}

	// Test each candidate for idapro importability.
	for _, p := range candidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		_, err := exec.Command(p, "-c", "import idapro").CombinedOutput()
		if err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf(`no python3 with idapro found

Install idapro into your Python:
  pip3 install /Applications/IDA*/Contents/MacOS/idalib/python
  python3 /Applications/IDA*/Contents/MacOS/idalib/python/py-activate-idalib.py -d /Applications/IDA*/Contents/MacOS

Or specify a python that has it:
  aotopsy ida --python /path/to/python3 --in <dir>`)
}

// findIDAScript locates ida_scripts/aotopsy_apply.py.
func findIDAScript() (string, error) {
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)
	homeDir, _ := os.UserHomeDir()

	candidates := []string{
		filepath.Join(homeDir, ".aotopsy", "ida_scripts", "aotopsy_apply.py"),
		filepath.Join(homeDir, ".aotopsy", "aotopsy_apply.py"),
		filepath.Join(exeDir, "ida_scripts", "aotopsy_apply.py"),
		"ida_scripts/aotopsy_apply.py",
		filepath.Join(exeDir, "..", "ida_scripts", "aotopsy_apply.py"),
	}

	for _, c := range candidates {
		abs, _ := filepath.Abs(c)
		if _, err := os.Stat(abs); err == nil {
			return abs, nil
		}
	}

	return "", fmt.Errorf("cannot find ida_scripts/aotopsy_apply.py; run from the aotopsy project root or install with 'make install'")
}

// countDecompiledFiles counts .c files in a directory tree.
func countDecompiledFiles(dir string) int {
	count := 0
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(d.Name(), ".c") {
			count++
		}
		return nil
	})
	return count
}
