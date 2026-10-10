package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProbeGhidraHomeAcceptsWindowsBatchLaunchers(t *testing.T) {
	home := t.TempDir()
	support := filepath.Join(home, "support")
	if err := os.MkdirAll(support, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"analyzeHeadless.bat", "pyghidraRun.bat"} {
		if err := os.WriteFile(filepath.Join(support, name), []byte("@echo off\r\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "ghidraRun.bat"), []byte("@echo off\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	launcher, gotHome, ok := probeGhidraHome(home)
	if !ok || gotHome != home {
		t.Fatalf("probeGhidraHome = %+v, %q, %v", launcher, gotHome, ok)
	}
	if filepath.Base(launcher.Cmd) != "pyghidraRun.bat" || len(launcher.Prefix) != 1 || launcher.Prefix[0] != "-H" {
		t.Fatalf("Windows PyGhidra launcher = %+v", launcher)
	}
	gui, err := FindGhidraGUI(home)
	if err != nil || filepath.Base(gui) != "ghidraRun.bat" {
		t.Fatalf("FindGhidraGUI = %q, %v", gui, err)
	}
}

func TestGhidraProjectNameIsSourceIdentityBound(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	nameA, err := GhidraProjectName("libapp.so", a)
	if err != nil {
		t.Fatal(err)
	}
	nameB, err := GhidraProjectName("libapp.so", b)
	if err != nil {
		t.Fatal(err)
	}
	if nameA == nameB || !strings.Contains(nameA, a[:12]) || !strings.Contains(nameB, b[:12]) {
		t.Fatalf("project names are not source-identity-bound: %q %q", nameA, nameB)
	}
	if _, err := GhidraProjectName("libapp.so", "not-a-sha"); err == nil {
		t.Fatal("invalid source SHA accepted for project identity")
	}
}
