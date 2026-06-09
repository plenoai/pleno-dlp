//go:build e2e_anonymize

// Package anonymize end-to-end test that drives a real
// pleno-anonymize server through the documented spawn chain:
//
//	pleno-dlp pii-server --port {PORT}
//	  └─ uvx --from git+https://github.com/plenoai/pleno-anonymize.git#subdirectory=server uvicorn server.src.app:app
//
// Per ADR-0003 the runtime prerequisite is `uvx` on PATH plus
// Python 3.12+ — Docker is not used. The test is gated behind the
// `e2e_anonymize` build tag so default `go test ./...` runs (and CI
// hosts without `uvx`) stay green.
//
// Run locally with:
//
//	go test -tags=e2e_anonymize ./pkg/piiengine/anonymize -run TestE2E_Anonymize
//
// First run is slow (~30–60s for uv resolve+build); subsequent runs
// hit the uv cache. Operators with a local pleno-anonymize checkout
// can shortcut both the network fetch and the version pin via
// `PLENO_DLP_E2E_ANONYMIZE_CMD`, e.g.
//
//	PLENO_DLP_E2E_ANONYMIZE_CMD="uv run --directory /path/to/pleno-anonymize/server uvicorn server.src.app:app --host 127.0.0.1 --port {PORT}"
//
// In that mode the test bypasses the pleno-dlp build step and uses
// the supervised argv verbatim.
package anonymize

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
//   - `uvx` not on PATH → t.Skip (CI-friendly per ADR-0003 prerequisite)
//   - the env-override binary missing → t.Skip
//   - ready-timeout / spawn failure → t.Fatal (the toolchain IS available
//     but the engine is broken — that is a real regression)
func TestE2E_Anonymize(t *testing.T) {
	if _, err := exec.LookPath("uvx"); err != nil {
		t.Skipf("e2e: uvx not on PATH (install uv: https://docs.astral.sh/uv/): %v", err)
	}

	cmd, ephemeralBuild := resolveE2ECmd(t)
	bin := cmd[0]
	if _, err := exec.LookPath(bin); err != nil && !filepath.IsAbs(bin) {
		t.Skipf("e2e: %q (argv[0]) not on PATH: %v", bin, err)
	}
	t.Logf("e2e: spawn argv = %v (ephemeralBuild=%v)", cmd, ephemeralBuild)

	// Generous ReadyTimeout: first run resolves the uvx environment
	// and warms spaCy + pleno_anonymize_ja on the engine. Subsequent runs hit
	// the uv cache and complete in a few seconds.
	cfg := Config{
		Cmd:            cmd,
		ReadyTimeout:   240 * time.Second,
		RequestTimeout: 30 * time.Second,
		Stderr:         testWriter{t},
	}

	sup, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
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

// resolveE2ECmd picks the spawn argv. The override env var wins; in
// its absence we drive the documented default chain by building the
// pleno-dlp binary into a temp dir and asking the supervisor to
// invoke its `pii-server` subcommand. The boolean return reports
// whether we built an ephemeral binary (true) or used an externally-
// supplied argv (false).
//
// We intentionally use the absolute path of the freshly-built binary
// (rather than the literal "pleno-dlp" sentinel that the CLI layer's
// resolveExecutable() handles) because this test imports only the
// supervisor package — it does not link the cmd package's argv[0]
// rewrite. Passing an absolute path makes the spawn deterministic
// and keeps the test self-contained.
func resolveE2ECmd(t *testing.T) (argv []string, ephemeralBuild bool) {
	t.Helper()
	if v := strings.TrimSpace(os.Getenv("PLENO_DLP_E2E_ANONYMIZE_CMD")); v != "" {
		return strings.Fields(v), false
	}
	bin := buildPlenoDLP(t)
	return []string{bin, "pii-server", "--port", "{PORT}"}, true
}

// buildPlenoDLP builds cmd/pleno-dlp into a temp directory and
// returns the absolute path. Each test gets its own binary so
// parallel runs cannot fight over an output path.
//
// The repo root is located via runtime.Caller — this test file lives
// at <repo>/pkg/piiengine/anonymize/e2e_anonymize_test.go, so the
// module root is three parents up. We resolve the path that way
// rather than via `go env GOMOD` to avoid an extra subprocess.
func buildPlenoDLP(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
	out := filepath.Join(t.TempDir(), "pleno-dlp")
	build := exec.Command("go", "build", "-o", out, "./cmd/pleno-dlp")
	build.Dir = repoRoot
	build.Stderr = testWriter{t}
	if err := build.Run(); err != nil {
		t.Fatalf("go build pleno-dlp: %v", err)
	}
	return out
}

// testWriter forwards child-process stderr lines to t.Logf so spawn
// failures surface in `go test -v` output without bloating non-verbose
// runs.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("engine stderr: %s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
