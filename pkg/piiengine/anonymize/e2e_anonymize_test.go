//go:build e2e_anonymize

// Package anonymize end-to-end test that drives a real
// pleno-anonymize server. Gated behind the `e2e_anonymize` build tag
// so default `go test ./...` runs (and CI without Docker) stay green.
//
// Run locally with:
//
//	go test -tags=e2e_anonymize ./pkg/piiengine/anonymize -run TestE2E_Anonymize
//
// The test honours the documented default supervisor command — Docker
// running ghcr.io/plenoai/pleno-anonymize:latest — but lets operators
// override the spawn argv via the PLENO_DLP_E2E_ANONYMIZE_CMD env var
// (whitespace-split), e.g. for a local `uv run` checkout.
//
// If the chosen command's binary (the first argv token) is not on
// PATH the test calls t.Skip — a clean checkout with neither Docker
// nor a local pleno-anonymize must remain runnable.
package anonymize

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestE2E_Anonymize spins up the real pleno-anonymize HTTP server,
// asks it to analyze a fixture that contains one PERSON, one
// PHONE_NUMBER, and one EMAIL_ADDRESS, then asserts each entity
// surfaces exactly once.
//
// Skip semantics:
//
//   - binary on first argv token missing on PATH → t.Skip (CI-friendly)
//   - ready-timeout / spawn failure → t.Fatal (the binary IS available
//     but the engine is broken — that is a real regression)
func TestE2E_Anonymize(t *testing.T) {
	cmd := resolveE2ECmd()
	bin := cmd[0]
	if _, err := exec.LookPath(bin); err != nil {
		t.Skipf("e2e: %q not on PATH (set PLENO_DLP_E2E_ANONYMIZE_CMD to override): %v", bin, err)
	}

	// Generous ReadyTimeout: the documented default pulls a multi-GB
	// Docker image plus loads spaCy + ja_ner_ja on first run. Operators
	// can pre-pull to keep this snappy on subsequent runs.
	cfg := Config{
		Cmd:            cmd,
		ReadyTimeout:   180 * time.Second,
		RequestTimeout: 30 * time.Second,
		Stderr:         testWriter{t},
	}

	sup, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := sup.Stop(); err != nil {
			t.Logf("Stop: %v", err)
		}
	})

	const fixture = "山田太郎 090-1234-5678 yamada@example.com"
	findings, err := sup.Analyze(ctx, fixture, "ja")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	// Count distinct entity types. We assert each of the three
	// expected kinds lands at least once and never more than once
	// (the engine occasionally emits redundant matches across
	// detectors; one is the contract we hold the engine to).
	counts := make(map[string]int, len(findings))
	for _, f := range findings {
		counts[f.EntityType]++
		t.Logf("finding: type=%s text=%q score=%.3f", f.EntityType, f.Text, f.Score)
	}
	for _, want := range []string{"PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS"} {
		got := counts[want]
		switch {
		case got == 0:
			t.Errorf("expected %s finding, got none. all findings: %v", want, counts)
		case got > 1:
			t.Errorf("expected exactly one %s finding, got %d. all findings: %v", want, got, counts)
		}
	}
}

// resolveE2ECmd picks the spawn argv. Operator override via env wins;
// otherwise the documented Docker default. The {PORT} placeholder
// stays literal — the supervisor substitutes it at exec time.
func resolveE2ECmd() []string {
	if v := strings.TrimSpace(os.Getenv("PLENO_DLP_E2E_ANONYMIZE_CMD")); v != "" {
		return strings.Fields(v)
	}
	return []string{
		"docker", "run", "--rm",
		"-p", "{PORT}:8080",
		"ghcr.io/plenoai/pleno-anonymize:latest",
	}
}

// testWriter forwards child-process stderr lines to t.Logf so spawn
// failures surface in `go test -v` output without bloating non-verbose
// runs.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("engine stderr: %s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
