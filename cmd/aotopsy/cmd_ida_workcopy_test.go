package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStageIDAWorkBinaryLeavesSourceDatabaseUntouched(t *testing.T) {
	sourceDir := t.TempDir()
	stageDir := t.TempDir()
	source := filepath.Join(sourceDir, "libapp.so")
	wantBinary := []byte("private ida work copy")
	if err := os.WriteFile(source, wantBinary, 0o600); err != nil {
		t.Fatal(err)
	}
	userDB := source + ".i64"
	wantDB := []byte("user annotations")
	if err := os.WriteFile(userDB, wantDB, 0o600); err != nil {
		t.Fatal(err)
	}

	workDir, workBinary, err := stageIDAWorkBinary(stageDir, source)
	if err != nil {
		t.Fatalf("stageIDAWorkBinary: %v", err)
	}
	if filepath.Dir(workBinary) != workDir || filepath.Dir(workDir) != stageDir {
		t.Fatalf("work copy escaped stage: workDir=%q workBinary=%q stage=%q", workDir, workBinary, stageDir)
	}
	gotBinary, err := os.ReadFile(workBinary)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotBinary, wantBinary) {
		t.Fatalf("work binary = %q, want %q", gotBinary, wantBinary)
	}
	gotDB, err := os.ReadFile(userDB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotDB, wantDB) {
		t.Fatalf("user database changed: got %q want %q", gotDB, wantDB)
	}
}
