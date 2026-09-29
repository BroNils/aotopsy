package main

import "testing"

func TestHasFlagRecognizesEqualsForm(t *testing.T) {
	for _, args := range [][]string{
		{"--in", "artifact"},
		{"--in=artifact"},
		{"-in=artifact"},
	} {
		if !hasFlag(args, "-in", "--in") {
			t.Fatalf("hasFlag(%q) did not recognize signal input flag", args)
		}
	}
	if hasFlag([]string{"--input=artifact"}, "-in", "--in") {
		t.Fatal("prefix lookalike was accepted as --in")
	}
}
