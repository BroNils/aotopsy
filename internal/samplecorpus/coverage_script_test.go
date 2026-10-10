package samplecorpus_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"aotopsy/internal/samplecorpus"
)

// repoRoot walks up from the package directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the working directory")
		}
		dir = parent
	}
}

// censusRows fabricates one COVROW-shaped row per manifest entry:
// version, arch, status, functions, symtab, file name (tab separated).
func censusRows(t *testing.T) []string {
	t.Helper()
	var rows []string
	for _, name := range samplecorpus.ExpectedFiles() {
		parts := strings.Split(strings.TrimSuffix(name, ".so"), "-")
		if len(parts) < 3 {
			t.Fatalf("unexpected manifest name %q", name)
		}
		rows = append(rows, fmt.Sprintf("%s\t%s\tOK\t100\t50\t%s", parts[1], parts[len(parts)-1], name))
	}
	return rows
}

func runCoverageScript(t *testing.T, rows []string) (string, error) {
	t.Helper()
	root := repoRoot(t)
	tmp := t.TempDir()
	rowsFile := filepath.Join(tmp, "rows.tsv")
	if err := os.WriteFile(rowsFile, []byte(strings.Join(rows, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "scripts/gen_coverage.sh", filepath.Join(tmp, "COVERAGE.md"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "COVROWS_FILE="+rowsFile)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// scripts/gen_coverage.sh runs under `set -u`: it once read $total before
// assigning it, so `make coverage` died with "unbound variable" no matter what
// the census said. These cases pin the publish/refuse decisions end to end.
func TestGenCoverageScriptPublishesOnlyCompleteCleanCensus(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("scripts/gen_coverage.sh needs GNU coreutils (sort -V)")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	rows := censusRows(t)

	if out, err := runCoverageScript(t, rows); err != nil {
		t.Fatalf("complete clean census was refused: %v\n%s", err, out)
	}

	cases := []struct {
		name string
		rows []string
		want string
	}{
		{"missing sample", rows[:len(rows)-1], "expected exactly"},
		{"duplicate file name", append(append([]string(nil), rows[:len(rows)-1]...), rows[0]), "duplicate or missing sample filenames"},
		{"failed sample", append([]string{strings.Replace(rows[0], "\tOK\t", "\tFAIL\t", 1)}, rows[1:]...), "FAIL rows"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runCoverageScript(t, tc.rows)
			if err == nil {
				t.Fatalf("census was published despite: %s\n%s", tc.name, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("refusal did not explain itself (want %q):\n%s", tc.want, out)
			}
		})
	}
}
