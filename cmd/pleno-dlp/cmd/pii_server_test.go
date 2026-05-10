package cmd

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestValidatePIIServerHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		host string
		ok   bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"localhost", true},
		{"LOCALHOST", true},
		{"10.0.0.5", true},     // RFC1918
		{"172.16.5.1", true},   // RFC1918
		{"192.168.1.1", true},  // RFC1918
		{"fe80::1", true},      // link-local
		{"fd00::1", true},      // ULA — IsPrivate true
		{"0.0.0.0", false},     // unspecified — explicit reject
		{"::", false},          // unspecified IPv6
		{"8.8.8.8", false},     // public
		{"1.1.1.1", false},     // public
		{"2606:4700::1", false},// public IPv6
		{"example.com", false}, // hostname (we don't resolve)
		{"", false},
	}
	for _, c := range cases {
		err := validatePIIServerHost(c.host)
		got := err == nil
		if got != c.ok {
			t.Errorf("validatePIIServerHost(%q) ok=%v err=%v; want ok=%v", c.host, got, err, c.ok)
		}
	}
}

func TestApplyGitRef(t *testing.T) {
	t.Parallel()
	cases := []struct {
		source string
		ref    string
		want   string
	}{
		// no ref → unchanged
		{"git+https://host/p.git", "", "git+https://host/p.git"},
		// bare git URL
		{"git+https://host/p.git", "v1.0", "git+https://host/p.git@v1.0"},
		// fragment preserved
		{"git+https://host/p.git#subdirectory=server", "v1.0", "git+https://host/p.git@v1.0#subdirectory=server"},
		// local path: ref dropped silently
		{"/abs/path", "v1.0", "/abs/path"},
		{"./rel", "v1.0", "./rel"},
		// already pinned: replace
		{"git+https://host/p.git@oldref#subdirectory=server", "newref", "git+https://host/p.git@newref#subdirectory=server"},
		// scheme @ vs path-segment @ — only the post-:// @ is treated as a ref
		{"git+https://user@host/p.git", "v1.0", "git+https://user@host/p.git@v1.0"},
	}
	for _, c := range cases {
		got := applyGitRef(c.source, c.ref)
		if got != c.want {
			t.Errorf("applyGitRef(%q,%q) = %q; want %q", c.source, c.ref, got, c.want)
		}
	}
}

func TestBuildPIIServerArgv(t *testing.T) {
	t.Parallel()
	got := buildPIIServerArgv("uvx", "git+https://host/p.git#subdirectory=server", "127.0.0.1", 41234)
	want := []string{
		"uvx",
		"--from", "git+https://host/p.git#subdirectory=server",
		"uvicorn",
		"server.src.app:app",
		"--host", "127.0.0.1",
		"--port", "41234",
	}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %d want %d (%v)", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("argv[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestPickEphemeralPort(t *testing.T) {
	t.Parallel()
	p, err := pickEphemeralPort("127.0.0.1")
	if err != nil {
		t.Fatalf("pickEphemeralPort: %v", err)
	}
	if p == 0 {
		t.Errorf("pickEphemeralPort returned 0")
	}
}

// TestRunPIIServer_FakeUvx exercises the full subcommand RunE with a
// fake uvx binary that prints its argv and exits. This lets us verify
// the pre-flight + argv assembly + signal wiring without depending
// on the real uv toolchain.
//
// Skipped on platforms where building a shebang script at test time
// is awkward (notably Windows). The team's CI is Linux/macOS, so the
// skip is not a coverage gap.
func TestRunPIIServer_FakeUvx(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-script test relies on POSIX exec semantics")
	}
	dir := t.TempDir()
	fakeUvx := filepath.Join(dir, "uvx")
	// The fake prints its argv to stdout (so the test can assert
	// the supervisor's argv shape) and exits 0 immediately. A
	// successful uvx normally blocks on uvicorn; we don't need
	// that here because we're testing the wiring up to exec, not
	// the long-running server.
	body := "#!/bin/sh\necho \"FAKE_UVX_ARGS:$*\"\nexit 0\n"
	if err := os.WriteFile(fakeUvx, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake uvx: %v", err)
	}

	prevBin := uvxBin
	uvxBin = fakeUvx
	defer func() { uvxBin = prevBin }()

	// Reset flag state between tests in this package.
	prevOpts := piiServerOpts
	piiServerOpts = piiServerFlags{
		port:   41234,
		host:   "127.0.0.1",
		source: "git+https://host/p.git#subdirectory=server",
	}
	defer func() { piiServerOpts = prevOpts }()

	cmd := piiServerCmd
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetContext(context.Background())

	if err := runPIIServer(cmd, nil); err != nil {
		t.Fatalf("runPIIServer: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "pii-server: listening on 127.0.0.1:41234") {
		t.Errorf("stdout missing listening line: %q", out)
	}
	if !strings.Contains(out, "FAKE_UVX_ARGS:--from git+https://host/p.git#subdirectory=server uvicorn server.src.app:app --host 127.0.0.1 --port 41234") {
		t.Errorf("stdout missing fake-uvx argv echo: %q", out)
	}
}

// TestRunPIIServer_RejectsPublicHost verifies the host gate fires
// before any spawn attempt — important so a misconfigured CI
// surfaces a clear error instead of binding a public listener.
func TestRunPIIServer_RejectsPublicHost(t *testing.T) {
	prevOpts := piiServerOpts
	piiServerOpts = piiServerFlags{port: 12345, host: "0.0.0.0"}
	defer func() { piiServerOpts = prevOpts }()

	cmd := piiServerCmd
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetContext(context.Background())
	err := runPIIServer(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "0.0.0.0") {
		t.Errorf("expected refusal for 0.0.0.0, got %v", err)
	}
}

// TestRunPIIServer_MissingUvx verifies the pre-flight emits a
// targeted install-uv message when the binary is not on PATH.
func TestRunPIIServer_MissingUvx(t *testing.T) {
	prevBin := uvxBin
	uvxBin = "definitely-not-on-path-xyzzy-uvx"
	defer func() { uvxBin = prevBin }()
	prevOpts := piiServerOpts
	piiServerOpts = piiServerFlags{port: 12345, host: "127.0.0.1"}
	defer func() { piiServerOpts = prevOpts }()

	cmd := piiServerCmd
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetContext(context.Background())
	err := runPIIServer(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "uvx") {
		t.Errorf("expected uvx-missing error, got %v", err)
	}
}

// TestRealUvxAvailable is a smoke test that runs only when uvx is
// genuinely on PATH. It verifies the version flag works — enough to
// catch a regression in our argv construction without paying the
// cost of a full `uvx --from <git>` cold start in unit tests.
func TestRealUvxAvailable(t *testing.T) {
	if _, err := exec.LookPath("uvx"); err != nil {
		t.Skip("uvx not on PATH; skipping real-uvx smoke test")
	}
	out, err := exec.Command("uvx", "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("uvx --version: %v (%s)", err, out)
	}
	if !strings.Contains(strings.ToLower(string(out)), "uv") {
		t.Errorf("uvx --version output unexpected: %s", out)
	}
}
