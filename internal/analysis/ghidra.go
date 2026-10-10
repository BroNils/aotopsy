// Package analysis contains business logic extracted from cmd/aotopsy
// that is not CLI plumbing: Ghidra/IDA launcher discovery, artifact
// copying, find-libapp, inventory, reflutter import, parity, refinfo,
// x64refs, graph, strings/clusters/objects, thr-audit, decompile-native
// loop/reachability, and export-dart sanitization.
package analysis

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// GhidraLauncher holds the command and any prefix args needed to run Ghidra headless.
// For Ghidra <12 (Jython): cmd=analyzeHeadless, prefix=nil.
// For Ghidra 12+ (PyGhidra): cmd=pyghidraRun, prefix=["-H"].
type GhidraLauncher struct {
	Cmd    string   // path to the launcher binary
	Prefix []string // args inserted before analyzeHeadless args (e.g. ["-H"])
}

// FindGhidra locates the Ghidra installation and returns a launcher.
// Search order:
//  1. --ghidra-home flag
//  2. GHIDRA_HOME or AOTOPSY_GHIDRA_HOME environment variable
//  3. analyzeHeadless in PATH
//  4. ghidraRun in PATH → derive installation directory
//  5. brew --prefix ghidra
func FindGhidra(explicitHome string) (launcher GhidraLauncher, ghidraHome string, err error) {
	// 1. Explicit --ghidra-home.
	if explicitHome != "" {
		if l, home, ok := probeGhidraHome(explicitHome); ok {
			return l, home, nil
		}
		return GhidraLauncher{}, "", fmt.Errorf("analyzeHeadless not found in %s", explicitHome)
	}

	// 2. GHIDRA_HOME or AOTOPSY_GHIDRA_HOME environment variable.
	for _, env := range []string{"GHIDRA_HOME", "AOTOPSY_GHIDRA_HOME"} {
		if gh := os.Getenv(env); gh != "" {
			if l, home, ok := probeGhidraHome(gh); ok {
				return l, home, nil
			}
		}
	}

	// 3. analyzeHeadless in PATH.
	for _, name := range launcherNames("analyzeHeadless") {
		if ah, err := exec.LookPath(name); err == nil {
			home := filepath.Dir(filepath.Dir(ah))
			return GhidraLauncher{Cmd: ah}, home, nil
		}
	}

	// 4. ghidraRun in PATH → parse to find install dir.
	for _, name := range launcherNames("ghidraRun") {
		if gr, err := exec.LookPath(name); err == nil {
			home := deriveGhidraHome(gr)
			if home != "" {
				if l, h, ok := probeGhidraHome(home); ok {
					return l, h, nil
				}
			}
		}
	}

	// 5. brew --prefix ghidra.
	if out, err := exec.Command("brew", "--prefix", "ghidra").Output(); err == nil {
		prefix := strings.TrimSpace(string(out))
		if l, home, ok := probeGhidraHome(prefix); ok {
			return l, home, nil
		}
		// Cellar layout: prefix/libexec is the real Ghidra home.
		if l, home, ok := probeGhidraHome(filepath.Join(prefix, "libexec")); ok {
			return l, home, nil
		}
	}

	return GhidraLauncher{}, "", fmt.Errorf(`ghidra not found

Install Ghidra:
  brew install ghidra

Or set GHIDRA_HOME:
  export GHIDRA_HOME=/path/to/ghidra

Or pass --ghidra-home:
  aotopsy decompile --ghidra-home /path/to/ghidra --in <dir>`)
}

// probeGhidraHome checks if a directory contains analyzeHeadless.
// Handles both direct layout (home/support/analyzeHeadless) and
// Caskroom layout (home/ghidra_*/support/analyzeHeadless).
// For Ghidra 12+ with pyghidraRun, returns a launcher that uses it
// so Python scripts work (PyGhidra replaces Jython).
func probeGhidraHome(home string) (launcher GhidraLauncher, ghidraHome string, ok bool) {
	// Direct: home/support/analyzeHeadless[.bat]
	for _, name := range launcherNames("analyzeHeadless") {
		ah := filepath.Join(home, "support", name)
		if regularExecutableFile(ah) {
			return makeLauncher(home, ah), home, true
		}
	}
	// Caskroom: home/ghidra_*_PUBLIC/support/analyzeHeadless
	if subs, err := os.ReadDir(home); err == nil {
		for _, sub := range subs {
			if !sub.IsDir() {
				continue
			}
			subHome := filepath.Join(home, sub.Name())
			for _, name := range launcherNames("analyzeHeadless") {
				ah := filepath.Join(subHome, "support", name)
				if regularExecutableFile(ah) {
					return makeLauncher(subHome, ah), subHome, true
				}
			}
		}
	}
	return GhidraLauncher{}, "", false
}

// makeLauncher returns a GhidraLauncher for the given Ghidra home.
// If pyghidraRun exists (Ghidra 12+), uses it with -H flag so Python scripts work.
// Otherwise falls back to analyzeHeadless directly.
func makeLauncher(home, analyzeHeadless string) GhidraLauncher {
	for _, name := range launcherNames("pyghidraRun") {
		pyghidra := filepath.Join(home, "support", name)
		if regularExecutableFile(pyghidra) {
			return GhidraLauncher{Cmd: pyghidra, Prefix: []string{"-H"}}
		}
	}
	return GhidraLauncher{Cmd: analyzeHeadless}
}

func launcherNames(base string) []string {
	if filepath.Ext(base) != "" {
		return []string{base}
	}
	if runtime.GOOS == "windows" {
		return []string{base + ".bat", base}
	}
	return []string{base, base + ".bat"}
}

func regularExecutableFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// FindGhidraGUI locates the interactive launcher in a resolved Ghidra home.
func FindGhidraGUI(home string) (string, error) {
	for _, name := range launcherNames("ghidraRun") {
		path := filepath.Join(home, name)
		if regularExecutableFile(path) {
			return path, nil
		}
	}
	return "", fmt.Errorf("ghidraRun launcher not found in %s", home)
}

// deriveGhidraHome reads the ghidraRun shell script to find the real install path.
// Brew's ghidraRun wrapper contains: exec "/opt/homebrew/Cellar/ghidra/X.Y.Z/libexec/ghidraRun"
func deriveGhidraHome(ghidraRunPath string) string {
	data, err := os.ReadFile(ghidraRunPath)
	if err != nil {
		return ""
	}
	// Look for exec "..." pattern pointing to the real ghidraRun.
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// exec "/opt/homebrew/Cellar/ghidra/12.0.2/libexec/ghidraRun"
		if strings.Contains(line, "exec") && strings.Contains(line, "ghidraRun") {
			// Extract the quoted path.
			idx := strings.Index(line, `"`)
			if idx < 0 {
				continue
			}
			rest := line[idx+1:]
			end := strings.Index(rest, `"`)
			if end < 0 {
				continue
			}
			realPath := rest[:end]
			// ghidraRun is at <home>/ghidraRun, so home = dirname.
			home := filepath.Dir(realPath)
			if _, err := os.Stat(filepath.Join(home, "support")); err == nil {
				return home
			}
		}
	}
	return ""
}

// FindScriptPath returns the path to the ghidra_scripts directory.
// Validates that ALL required scripts exist, not just one.
func FindScriptPath() (string, error) {
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)

	homeDir, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(homeDir, ".aotopsy", "ghidra_scripts"),
		filepath.Join(homeDir, ".aotopsy"),
		filepath.Join(exeDir, "ghidra_scripts"),
		"ghidra_scripts",
		filepath.Join(exeDir, "..", "ghidra_scripts"),
	}

	required := []string{"aotopsy_apply.py", "aotopsy_prescript.py"}

	for _, c := range candidates {
		abs, _ := filepath.Abs(c)
		allFound := true
		for _, req := range required {
			if _, err := os.Stat(filepath.Join(abs, req)); err != nil {
				allFound = false
				break
			}
		}
		if allFound {
			return abs, nil
		}
	}

	return "", fmt.Errorf("cannot find ghidra_scripts/ with both aotopsy_apply.py and aotopsy_prescript.py\n  checked: %s\n  fix: run 'make install' or run from the aotopsy project root", strings.Join(candidates, ", "))
}

// FindJavaHome tries to locate a suitable JDK for Ghidra.
func FindJavaHome(ghidraHome string) string {
	// Check if the ghidraRun wrapper sets JAVA_HOME.
	gr := filepath.Join(ghidraHome, "ghidraRun")
	if data, err := os.ReadFile(gr); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "JAVA_HOME") && strings.Contains(line, ":-") {
				// JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@21/...}"
				idx := strings.Index(line, ":-")
				if idx >= 0 {
					rest := line[idx+2:]
					end := strings.IndexAny(rest, `}"`)
					if end > 0 {
						jh := rest[:end]
						if _, err := os.Stat(jh); err == nil {
							return jh
						}
					}
				}
			}
		}
	}

	// Common brew JDK paths.
	jdks := []string{
		"/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
		"/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home",
		"/usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
	}
	for _, jh := range jdks {
		if _, err := os.Stat(jh); err == nil {
			return jh
		}
	}

	return ""
}

// SanitizeProjectName builds a Ghidra project name from a directory basename.
// Strips characters that Java/Ghidra reject in project names (colon, etc.).
func SanitizeProjectName(base string) string {
	if base == "" || base == "." {
		return "aotopsy_decompile"
	}
	clean := strings.Map(func(r rune) rune {
		if r == ':' || r == '\\' || r == '"' || r == '<' || r == '>' || r == '|' || r == '?' || r == '*' {
			return '_'
		}
		return r
	}, base)
	return "aotopsy_" + clean
}

// GhidraProjectName derives a collision-resistant project identity from the
// analysed binary rather than from the parent directory chosen for artifacts.
func GhidraProjectName(sourceName, sha256 string) (string, error) {
	if sourceName == "" {
		return "", fmt.Errorf("empty source name")
	}
	if len(sha256) != 64 {
		return "", fmt.Errorf("invalid source sha256 length %d", len(sha256))
	}
	if _, err := hex.DecodeString(sha256); err != nil {
		return "", fmt.Errorf("invalid source sha256: %w", err)
	}
	base := strings.TrimSuffix(filepath.Base(sourceName), filepath.Ext(sourceName))
	return SanitizeProjectName(base + "_" + strings.ToLower(sha256[:12])), nil
}

// SanitizeGhidraPath returns an absolute path safe for Java/Ghidra.
// If the resolved path contains ':', relocates to ~/.aotopsy/ghidra-projects/.
func SanitizeGhidraPath(projectDir string) string {
	abs, _ := filepath.Abs(projectDir)
	if !strings.Contains(abs, ":") {
		return abs
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".aotopsy", "ghidra-projects")
}
