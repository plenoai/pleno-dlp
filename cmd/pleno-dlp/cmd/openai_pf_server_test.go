package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// validateOpenAIPFHost is the gate that prevents a misconfigured
// openai-pf-server from binding a public interface. The matrix below
// is intentionally identical to the pii-server tests — same hard
// rule, same audience — but exercised directly so a regression in
// one engine's gate doesn't depend on the other engine's tests for
// coverage.
func TestValidateOpenAIPFHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		host string
		ok   bool
	}{
		{"loopback v4", "127.0.0.1", true},
		{"loopback v6", "::1", true},
		{"localhost literal", "localhost", true},
		{"rfc1918 10/8", "10.0.0.1", true},
		{"rfc1918 192.168/16", "192.168.5.10", true},
		{"link-local 169.254/16", "169.254.1.1", true},
		{"unspecified", "0.0.0.0", false},
		{"unspecified v6", "::", false},
		{"public v4", "8.8.8.8", false},
		{"hostname", "example.com", false},
		{"empty", "", false},
		{"garbage", "not-an-ip", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateOpenAIPFHost(c.host)
			if c.ok && err != nil {
				t.Errorf("validateOpenAIPFHost(%q): unexpected error %v", c.host, err)
			}
			if !c.ok && err == nil {
				t.Errorf("validateOpenAIPFHost(%q): expected error, got nil", c.host)
			}
		})
	}
}

func TestValidateOpenAIPFDevice(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"auto", "cpu", "cuda", "mps"} {
		if err := validateOpenAIPFDevice(ok); err != nil {
			t.Errorf("device %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "GPU", "rocm", "auto "} {
		if err := validateOpenAIPFDevice(bad); err == nil {
			t.Errorf("device %q accepted; expected rejection", bad)
		}
	}
}

// TestResolveOpenAIPFSource pins the @ref splice behaviour for every
// shape the operator might supply --source in. The fragment
// (#subdirectory=...) must survive the splice; URL userinfo "@"
// must not be confused with a ref "@".
func TestResolveOpenAIPFSource(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		source string
		ref    string
		want   string
	}{
		{
			name:   "no ref returns source untouched",
			source: defaultOpenAIPFSource,
			ref:    "",
			want:   defaultOpenAIPFSource,
		},
		{
			name:   "ref appended before fragment",
			source: "git+https://github.com/plenoai/pleno-dlp.git#subdirectory=python/openaipf-server",
			ref:    "v0.1.0",
			want:   "git+https://github.com/plenoai/pleno-dlp.git@v0.1.0#subdirectory=python/openaipf-server",
		},
		{
			name:   "ref replaces existing ref",
			source: "git+https://github.com/plenoai/pleno-dlp.git@old#subdirectory=python/openaipf-server",
			ref:    "v0.2.0",
			want:   "git+https://github.com/plenoai/pleno-dlp.git@v0.2.0#subdirectory=python/openaipf-server",
		},
		{
			name:   "ref appended when no fragment present",
			source: "git+https://github.com/plenoai/pleno-dlp.git",
			ref:    "main",
			want:   "git+https://github.com/plenoai/pleno-dlp.git@main",
		},
		{
			name:   "local path source passes through unchanged",
			source: "/abs/path/openaipf-server",
			ref:    "v0.1.0",
			want:   "/abs/path/openaipf-server",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resolveOpenAIPFSource(c.source, c.ref)
			if got != c.want {
				t.Errorf("resolveOpenAIPFSource(%q, %q) = %q; want %q", c.source, c.ref, got, c.want)
			}
		})
	}
}

func TestBuildOpenAIPFServerArgv(t *testing.T) {
	t.Parallel()
	argv := buildOpenAIPFServerArgv("uv", defaultOpenAIPFSource, "127.0.0.1", 12345, "auto", "info")
	want := []string{
		"uv", "tool", "run",
		"--from", defaultOpenAIPFSource,
		"python", "-m", "openaipf_server",
		"--host", "127.0.0.1",
		"--port", "12345",
		"--device", "auto",
		"--log-level", "info",
	}
	if len(argv) != len(want) {
		t.Fatalf("argv len = %d, want %d (%v)", len(argv), len(want), argv)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, argv[i], want[i])
		}
	}
}

// TestPiiEngineCmdValue_PerEngineDefault exercises the conditional-
// default logic: cobra holds the anonymize argv as the static default,
// startPIIEngine must substitute the openai-pf default when the
// operator selects openai-pf without overriding --pii-engine-cmd.
func TestPiiEngineCmdValue_PerEngineDefault(t *testing.T) {
	// Synthesize a minimal cobra command with the same flag shape
	// the scan command uses. We can't reuse scanCmd here because its
	// init() side-effects bind to a global flag set we'd then have
	// to mutate per-case.
	mk := func(set bool, raw string) *cobra.Command {
		c := &cobra.Command{}
		var dst string
		c.Flags().StringVar(&dst, "pii-engine-cmd", "pleno-dlp pii-server --port {PORT}", "")
		// Mirror the cobra default into scanOpts so piiEngineCmdValue's
		// fallback path sees the same string when Changed=false.
		scanOpts.piiEngineCmd = "pleno-dlp pii-server --port {PORT}"
		if set {
			// Simulate the operator supplying --pii-engine-cmd on the
			// command line. cobra's Flag().Changed flips on Set().
			if err := c.Flags().Set("pii-engine-cmd", raw); err != nil {
				t.Fatalf("flag set: %v", err)
			}
			scanOpts.piiEngineCmd = raw
		}
		return c
	}

	t.Cleanup(func() { scanOpts.piiEngineCmd = "" })

	if got := piiEngineCmdValue(mk(false, ""), "anonymize"); got != defaultAnonymizeCmd {
		t.Errorf("anonymize default: got %q want %q", got, defaultAnonymizeCmd)
	}
	if got := piiEngineCmdValue(mk(false, ""), "openai-pf"); got != defaultOpenAIPFCmd {
		t.Errorf("openai-pf default: got %q want %q", got, defaultOpenAIPFCmd)
	}
	// Operator override beats both defaults.
	custom := "uv run /local/openaipf --port {PORT}"
	if got := piiEngineCmdValue(mk(true, custom), "openai-pf"); got != custom {
		t.Errorf("operator override: got %q want %q", got, custom)
	}
}

// TestUnknownPIIEngine asserts the error message lists all three
// valid values. Operators rely on the error message to discover the
// flag's accepted set; dropping a value here silently regresses
// discoverability.
func TestUnknownPIIEngine(t *testing.T) {
	prev := scanOpts.piiEngine
	defer func() { scanOpts.piiEngine = prev }()
	scanOpts.piiEngine = "presidio"
	_, err := startPIIEngine(t.Context(), nil, nil)
	if err == nil {
		t.Fatalf("expected error for unknown engine")
	}
	for _, want := range []string{"off", "anonymize", "openai-pf"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message %q missing valid value %q", err.Error(), want)
		}
	}
}
