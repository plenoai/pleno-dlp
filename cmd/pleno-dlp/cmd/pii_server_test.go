package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
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
		{"10.0.0.5", true},      // RFC1918
		{"172.16.5.1", true},    // RFC1918
		{"192.168.1.1", true},   // RFC1918
		{"fe80::1", true},       // link-local
		{"fd00::1", true},       // ULA — IsPrivate true
		{"0.0.0.0", false},      // unspecified — explicit reject
		{"::", false},           // unspecified IPv6
		{"8.8.8.8", false},      // public
		{"1.1.1.1", false},      // public
		{"2606:4700::1", false}, // public IPv6
		{"example.com", false},  // hostname (we don't resolve)
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

func TestStripGitURLPrefix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"git+https://github.com/plenoai/pleno-anonymize.git", "https://github.com/plenoai/pleno-anonymize.git", false},
		// #subdirectory fragment dropped (legacy uvx form)
		{"git+https://host/p.git#subdirectory=server", "https://host/p.git", false},
		// @ref dropped (--git-ref is the sole ref control surface now)
		{"git+https://host/p.git@v1.0", "https://host/p.git", false},
		{"git+https://host/p.git@v1.0#subdirectory=server", "https://host/p.git", false},
		// userinfo @ preserved (sits before the last /)
		{"git+https://user@host/p.git", "https://user@host/p.git", false},
		// non-git+ refused
		{"https://host/p.git", "", true},
		{"/local/path", "", true},
	}
	for _, c := range cases {
		got, err := stripGitURLPrefix(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("stripGitURLPrefix(%q) succeeded; want error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("stripGitURLPrefix(%q) err=%v; want nil", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("stripGitURLPrefix(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestBuildPIIServerArgv(t *testing.T) {
	t.Parallel()
	got := buildPIIServerArgv("uv", "127.0.0.1", 41234)
	want := []string{
		"uv",
		"run",
		"--no-sync",
		"--package", "pleno-anonymize-server",
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

func TestResolveCacheDir(t *testing.T) {
	// Flag wins over env wins over UserCacheDir. The fallback path
	// always lands inside whatever os.UserCacheDir returns; we
	// don't second-guess it because that would mean reimplementing
	// stdlib platform logic.
	t.Setenv("PLENO_DLP_ANONYMIZE_CACHE", "/tmp/env-cache")

	got, err := resolveCacheDir("/explicit/flag")
	if err != nil {
		t.Fatalf("resolveCacheDir flag: %v", err)
	}
	if got != "/explicit/flag" {
		t.Errorf("flag override: got %q", got)
	}

	got, err = resolveCacheDir("")
	if err != nil {
		t.Fatalf("resolveCacheDir env: %v", err)
	}
	if got != "/tmp/env-cache" {
		t.Errorf("env override: got %q", got)
	}

	t.Setenv("PLENO_DLP_ANONYMIZE_CACHE", "")
	got, err = resolveCacheDir("")
	if err != nil {
		t.Fatalf("resolveCacheDir default: %v", err)
	}
	if !strings.HasSuffix(filepath.ToSlash(got), "/pleno-dlp/pleno-anonymize") {
		t.Errorf("default suffix: got %q", got)
	}
}

func TestPrepareWorkdir_LocalPath(t *testing.T) {
	dir := t.TempDir()
	workdir, fresh, err := prepareWorkdir(context.Background(), prepareInput{
		source: dir,
	})
	if err != nil {
		t.Fatalf("prepareWorkdir: %v", err)
	}
	abs, _ := filepath.Abs(dir)
	if workdir != abs {
		t.Errorf("workdir=%q want %q", workdir, abs)
	}
	if fresh {
		t.Errorf("fresh should be false for local path")
	}
}

func TestPrepareWorkdir_LocalPathMustExist(t *testing.T) {
	_, _, err := prepareWorkdir(context.Background(), prepareInput{
		source: "/definitely/not/a/real/path/xyzzy",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent local source")
	}
}

// TestPrepareWorkdir_GitClone_FakeGit drives the clone path with a
// fake `git` binary. The fake records its argv to a file inside the
// target cache dir AND creates the `.git` subdir so the warm-cache
// branch fires correctly on a second invocation.
func TestPrepareWorkdir_GitClone_FakeGit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-script test relies on POSIX exec semantics")
	}
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache")

	fakeGit := filepath.Join(dir, "git")
	// `git clone --depth 1 [--branch ref] url dst` → mkdir dst/.git, drop a marker.
	// `git fetch ...`  → record argv.
	// `git checkout ...` → record argv.
	body := `#!/bin/sh
set -e
sub="$1"
case "$sub" in
clone)
  # last arg is destination
  for a in "$@"; do dst="$a"; done
  mkdir -p "$dst/.git"
  echo "FAKE_GIT_CLONE: $*" > "$dst/.git/last-clone"
  ;;
fetch|checkout)
  echo "FAKE_GIT_$sub: $*" >> .git/last-args 2>/dev/null || true
  ;;
esac
exit 0
`
	if err := os.WriteFile(fakeGit, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake git: %v", err)
	}
	prevGit := gitBin
	gitBin = fakeGit
	t.Cleanup(func() { gitBin = prevGit })

	// First call: cold cache → clone → freshCheckout=true.
	work, fresh, err := prepareWorkdir(context.Background(), prepareInput{
		source:   "git+https://example.com/p.git",
		gitRef:   "v1.2.3",
		cacheDir: cache,
		stderr:   &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("prepareWorkdir cold: %v", err)
	}
	if work != cache {
		// resolveCacheDir abs-converts; on macOS /tmp resolves through /private/tmp.
		absCache, _ := filepath.Abs(cache)
		if work != absCache {
			t.Errorf("workdir=%q want %q (or %q)", work, cache, absCache)
		}
	}
	if !fresh {
		t.Errorf("expected fresh=true on cold clone")
	}
	marker, err := os.ReadFile(filepath.Join(cache, ".git", "last-clone"))
	if err != nil {
		t.Fatalf("clone marker: %v", err)
	}
	if !strings.Contains(string(marker), "--branch v1.2.3") {
		t.Errorf("expected --branch in fake git invocation, got %q", marker)
	}

	// Second call without --no-fetch: warm cache → fetch+checkout.
	_, fresh2, err := prepareWorkdir(context.Background(), prepareInput{
		source:   "git+https://example.com/p.git",
		gitRef:   "main",
		cacheDir: cache,
		stderr:   &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("prepareWorkdir warm: %v", err)
	}
	if !fresh2 {
		// Per the contract, every successful fetch counts as fresh
		// because we can't cheaply detect whether HEAD actually moved.
		t.Errorf("expected fresh=true after fetch")
	}

	// Third call with --no-fetch: warm cache → no-op.
	_, fresh3, err := prepareWorkdir(context.Background(), prepareInput{
		source:   "git+https://example.com/p.git",
		cacheDir: cache,
		noFetch:  true,
		stderr:   &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("prepareWorkdir no-fetch: %v", err)
	}
	if fresh3 {
		t.Errorf("expected fresh=false with --no-fetch")
	}
}

// TestRunPIIServer_FakeUv exercises the full subcommand RunE with
// fake `uv` and `git` binaries. This lets us verify the pre-flight +
// argv assembly + workdir + signal wiring without depending on the
// real uv toolchain.
func TestRunPIIServer_FakeUv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-script test relies on POSIX exec semantics")
	}
	dir := t.TempDir()
	fakeUv := filepath.Join(dir, "uv")
	fakeGit := filepath.Join(dir, "git")

	// Fake `uv` records every argv to stdout and exits 0. uvicorn
	// would normally block on serving, but we don't need it to —
	// we're testing wiring up to exec, not the long-running server.
	uvBody := "#!/bin/sh\necho \"FAKE_UV_ARGS:$*\"\nexit 0\n"
	if err := os.WriteFile(fakeUv, []byte(uvBody), 0o755); err != nil {
		t.Fatalf("write fake uv: %v", err)
	}
	gitBody := "#!/bin/sh\nfor a in \"$@\"; do dst=\"$a\"; done\n[ \"$1\" = clone ] && mkdir -p \"$dst/.git\"\nexit 0\n"
	if err := os.WriteFile(fakeGit, []byte(gitBody), 0o755); err != nil {
		t.Fatalf("write fake git: %v", err)
	}

	prevUv, prevGit := uvBin, gitBin
	uvBin, gitBin = fakeUv, fakeGit
	t.Cleanup(func() { uvBin, gitBin = prevUv, prevGit })

	// This test exercises server wiring (argv assembly, workdir, signal
	// plumbing), not NER wheel installation — nil out nerWheels so
	// runPIIServer's wheel step performs zero real HTTP downloads.
	// downloadAndVerifyWheel and runUVPipInstallNERWheels have their
	// own dedicated tests below via httptest.
	prevWheels := nerWheels
	nerWheels = nil
	t.Cleanup(func() { nerWheels = prevWheels })

	cache := filepath.Join(dir, "cache")
	prevOpts := piiServerOpts
	piiServerOpts = piiServerFlags{
		port:     41234,
		host:     "127.0.0.1",
		source:   "git+https://example.com/p.git",
		cacheDir: cache,
	}
	t.Cleanup(func() { piiServerOpts = prevOpts })

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
	// The final exec'd command should be the `uv run` invocation —
	// fake-uv echoes the argv to stdout, so we can grep for the
	// uvicorn target shape.
	if !strings.Contains(out, "FAKE_UV_ARGS:run --no-sync --package pleno-anonymize-server uvicorn server.src.app:app --host 127.0.0.1 --port 41234") {
		t.Errorf("stdout missing fake-uv argv echo: %q", out)
	}
}

// TestRunPIIServer_RejectsPublicHost verifies the host gate fires
// before any spawn attempt — important so a misconfigured CI
// surfaces a clear error instead of binding a public listener.
func TestRunPIIServer_RejectsPublicHost(t *testing.T) {
	prevOpts := piiServerOpts
	piiServerOpts = piiServerFlags{port: 12345, host: "0.0.0.0"}
	t.Cleanup(func() { piiServerOpts = prevOpts })

	cmd := piiServerCmd
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetContext(context.Background())
	err := runPIIServer(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "0.0.0.0") {
		t.Errorf("expected refusal for 0.0.0.0, got %v", err)
	}
}

// TestRunPIIServer_MissingUv verifies the pre-flight emits a
// targeted install-uv message when the binary is not on PATH.
func TestRunPIIServer_MissingUv(t *testing.T) {
	prevBin := uvBin
	uvBin = "definitely-not-on-path-xyzzy-uv"
	t.Cleanup(func() { uvBin = prevBin })
	prevOpts := piiServerOpts
	piiServerOpts = piiServerFlags{port: 12345, host: "127.0.0.1"}
	t.Cleanup(func() { piiServerOpts = prevOpts })

	cmd := piiServerCmd
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetContext(context.Background())
	err := runPIIServer(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "uv") {
		t.Errorf("expected uv-missing error, got %v", err)
	}
}

// TestDownloadAndVerifyWheel_Success serves known-good content over a
// local httptest server (no real network) and checks that the sha256
// gate accepts a matching hash, writes the file under the upstream
// wheel's own filename, and that the on-disk content matches exactly.
func TestDownloadAndVerifyWheel_Success(t *testing.T) {
	t.Parallel()
	content := []byte("fake-wheel-bytes-for-testing")
	sum := sha256.Sum256(content)
	wantHash := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	wheel := nerWheel{url: srv.URL + "/some_model-1.0.0-py3-none-any.whl", sha256: wantHash}

	got, err := downloadAndVerifyWheel(context.Background(), wheel, dir)
	if err != nil {
		t.Fatalf("downloadAndVerifyWheel: %v", err)
	}
	if filepath.Base(got) != "some_model-1.0.0-py3-none-any.whl" {
		t.Errorf("local path base = %q, want the upstream wheel filename", filepath.Base(got))
	}
	onDisk, err := os.ReadFile(got)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("downloaded content mismatch: got %q want %q", onDisk, content)
	}
}

// TestDownloadAndVerifyWheel_HashMismatch is the acceptance-criteria
// test from issue #248: a tampered/wrong-hash artifact must cause a
// clear abort error, and must not be left installable on disk. No
// network — httptest serves the (deliberately mismatched) content.
func TestDownloadAndVerifyWheel_HashMismatch(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("this is NOT what the hash below expects"))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	wrongHash := strings.Repeat("0", 64)
	wheel := nerWheel{url: srv.URL + "/tampered-1.0.0-py3-none-any.whl", sha256: wrongHash}

	_, err := downloadAndVerifyWheel(context.Background(), wheel, dir)
	if err == nil {
		t.Fatal("expected sha256 mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") || !strings.Contains(err.Error(), "aborting pii-server setup") {
		t.Errorf("error should clearly report a sha256 mismatch and abort, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "tampered-1.0.0-py3-none-any.whl")); !os.IsNotExist(statErr) {
		t.Errorf("tampered artifact should not be left on disk, stat err = %v", statErr)
	}
}

// TestRunUVPipInstallNERWheels_AbortsOnHashMismatch drives the full
// wiring: nerWheels overridden to a single httptest-served, wrong-hash
// entry, and a fake `uv` that would leave a marker file if invoked.
// The mismatch must abort before uv is ever called, satisfying the
// "fail closed" requirement — a tampered wheel never reaches
// `uv pip install`.
func TestRunUVPipInstallNERWheels_AbortsOnHashMismatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-script test relies on POSIX exec semantics")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("tampered-content"))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	marker := filepath.Join(dir, "uv-was-invoked")
	fakeUv := filepath.Join(dir, "uv")
	uvBody := "#!/bin/sh\ntouch '" + marker + "'\nexit 0\n"
	if err := os.WriteFile(fakeUv, []byte(uvBody), 0o755); err != nil {
		t.Fatalf("write fake uv: %v", err)
	}
	prevUv := uvBin
	uvBin = fakeUv
	t.Cleanup(func() { uvBin = prevUv })

	prevWheels := nerWheels
	nerWheels = []nerWheel{
		{url: srv.URL + "/tampered-1.0.0-py3-none-any.whl", sha256: strings.Repeat("0", 64)},
	}
	t.Cleanup(func() { nerWheels = prevWheels })

	err := runUVPipInstallNERWheels(context.Background(), dir, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error from hash mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("expected sha256 mismatch error, got: %v", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Errorf("uv must never be invoked on a hash mismatch, but marker file exists (stat err = %v)", statErr)
	}
}

// TestRunUVPipInstallNERWheels_InstallsOnMatch is the mirror success
// case: a correct hash must reach `uv pip install <local-file>` with a
// real (verified) file on disk, not the remote URL.
func TestRunUVPipInstallNERWheels_InstallsOnMatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-script test relies on POSIX exec semantics")
	}
	content := []byte("good-wheel-content")
	sum := sha256.Sum256(content)
	wantHash := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	argsFile := filepath.Join(dir, "uv-args")
	fakeUv := filepath.Join(dir, "uv")
	uvBody := "#!/bin/sh\necho \"$*\" >> '" + argsFile + "'\nexit 0\n"
	if err := os.WriteFile(fakeUv, []byte(uvBody), 0o755); err != nil {
		t.Fatalf("write fake uv: %v", err)
	}
	prevUv := uvBin
	uvBin = fakeUv
	t.Cleanup(func() { uvBin = prevUv })

	prevWheels := nerWheels
	nerWheels = []nerWheel{
		{url: srv.URL + "/good_model-1.0.0-py3-none-any.whl", sha256: wantHash},
	}
	t.Cleanup(func() { nerWheels = prevWheels })

	if err := runUVPipInstallNERWheels(context.Background(), dir, &bytes.Buffer{}); err != nil {
		t.Fatalf("runUVPipInstallNERWheels: %v", err)
	}
	got, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read uv args log: %v", err)
	}
	if !strings.Contains(string(got), "pip install") || !strings.Contains(string(got), "good_model-1.0.0-py3-none-any.whl") {
		t.Errorf("expected uv pip install invocation naming the local wheel file, got: %q", got)
	}
	if strings.Contains(string(got), srv.URL) {
		t.Errorf("uv must be given the local verified file, not the remote URL; got: %q", got)
	}
}

// TestRealUvAvailable is a smoke test that runs only when uv is
// genuinely on PATH. It verifies the version flag works — enough to
// catch a regression in our argv construction without paying the
// cost of a full `uv sync` cold start in unit tests.
func TestRealUvAvailable(t *testing.T) {
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv not on PATH; skipping real-uv smoke test")
	}
	out, err := exec.Command("uv", "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("uv --version: %v (%s)", err, out)
	}
	if !strings.Contains(strings.ToLower(string(out)), "uv") {
		t.Errorf("uv --version output unexpected: %s", out)
	}
}
