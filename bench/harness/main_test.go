package main

import (
	"slices"
	"testing"
)

func TestPlenoDetectionOnlyArgsDisableVerification(t *testing.T) {
	args := plenoDetectionOnlyArgs("/synthetic/corpus")
	if !slices.Contains(args, "--no-verify") {
		t.Fatalf("detection-only benchmark args = %v, want --no-verify", args)
	}
	if !slices.Contains(args, "/synthetic/corpus") {
		t.Fatalf("detection-only benchmark args = %v, want corpus path", args)
	}
}
