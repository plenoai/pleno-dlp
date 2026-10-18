package main

import "testing"

func TestBuildInfoVersionKeepsLdflagsValues(t *testing.T) {
	v, c := buildInfoVersion("v1.2.3", "abcdef0")
	if v != "v1.2.3" || c != "abcdef0" {
		t.Fatalf("ldflags values must win: got %s %s", v, c)
	}
}

func TestBuildInfoVersionNeverReturnsDevel(t *testing.T) {
	// Under `go test` the main module reports "(devel)", which must not
	// replace the "dev" placeholder with an equally meaningless string.
	v, _ := buildInfoVersion("dev", "none")
	if v == "(devel)" || v == "" {
		t.Fatalf("got %q", v)
	}
}
