package main

import (
	"os"
	"path/filepath"
	"testing"

	"aotopsy/internal/analysis"
	"aotopsy/internal/jsonutil"
)

func TestDart2BucketsRejectsMalformedInventoryWithoutPublishing(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "inventory.jsonl")
	out := filepath.Join(dir, "buckets.jsonl")
	const old = "old artifact\n"
	if err := os.WriteFile(out, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	body := "{\"sample_id\":\"a\",\"apk_path\":\"a.apk\",\"abi\":\"arm64-v8a\",\"declared_libapp\":true,\"snapshot_hash\":\"h\",\"dart_version\":\"2.19.0\",\"features\":\"x\"}\n" +
		"{\"sample_id\":\"b\",\"apk_path\":\"b.apk\",\"abi\":\"arm64-v8a\",\"declared_libapp\":true,\"snapshot_hash\":\"h2\",\"dart_version\":\"2.19.0\",\"features\":\"x\",\"stale\":true}\n"
	if err := os.WriteFile(in, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdDart2Buckets([]string{"--inventory", in, "--out", out}); err == nil {
		t.Fatal("stale inventory schema was accepted")
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != old {
		t.Fatalf("failed import published partial/replacement artifact: %q", got)
	}
}

func TestDart2BucketsWritesDeterministicStrictJSONL(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "inventory.jsonl")
	out := filepath.Join(dir, "buckets.jsonl")
	producerRows := []analysis.InventoryRow{
		{SampleID: "b", APKPath: "b.apk", ABI: "arm64-v8a", DeclaredLibapp: true, SnapshotHash: "h2", DartVersion: "2.19.0", Features: "f2"},
		{SampleID: "a", APKPath: "a.apk", ABI: "arm64-v8a", DeclaredLibapp: true, SnapshotHash: "h1", DartVersion: "2.12.0", Features: "f1"},
		{SampleID: "c", APKPath: "c.apk", ABI: "arm64-v8a", DeclaredLibapp: true, SnapshotHash: "h1", DartVersion: "2.12.0", Features: "f1"},
		{SampleID: "no-lib", APKPath: "no-lib.apk", DeclaredLibapp: false},
		{SampleID: "bad", APKPath: "bad.apk", ABI: "arm64-v8a", DeclaredLibapp: true, Error: "scan failed"},
	}
	if _, err := jsonutil.WriteJSONLFile(in, producerRows); err != nil {
		t.Fatal(err)
	}
	if err := cmdDart2Buckets([]string{"--inventory", in, "--out", out}); err != nil {
		t.Fatal(err)
	}
	rows, err := jsonutil.ReadJSONL[dart2Bucket](out, jsonutil.StandardLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].DartVersion != "2.12.0" || rows[0].Hash != "h1" || rows[0].Count != 2 || rows[1].Hash != "h2" {
		t.Fatalf("unexpected deterministic buckets: %+v", rows)
	}
}

func TestDart2BucketsRejectsIncompleteSuccessfulInventoryRow(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "inventory.jsonl")
	out := filepath.Join(dir, "buckets.jsonl")
	body := "{\"sample_id\":\"a\",\"apk_path\":\"a.apk\",\"abi\":\"arm64-v8a\",\"declared_libapp\":true}\n"
	if err := os.WriteFile(in, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdDart2Buckets([]string{"--inventory", in, "--out", out}); err == nil {
		t.Fatal("successful inventory row without snapshot identity was accepted")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("failed import published output: %v", err)
	}
}

func TestImportDarterRejectsStaleSchemaWithoutTouchingOutput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "darter.json")
	out := filepath.Join(dir, "out.r2")
	const old = "old r2\n"
	if err := os.WriteFile(out, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	body := `{"DartVersion":"2.9.0","Arch":"arm64","Functions":[],"Classes":[],"Strings":[],"stale":true}`
	if err := os.WriteFile(in, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdImportDarter([]string{in, out}); err == nil {
		t.Fatal("stale darter schema was accepted")
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != old {
		t.Fatalf("failed darter import changed output: %q", got)
	}
}
