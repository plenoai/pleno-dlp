package cmd

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"

	// Blank imports mirror main.go so unit tests on the scan command
	// exercise the same registry the binary does. Without these,
	// runScanFilesystem returns "filesystem source is not registered".
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
	_ "github.com/plenoai/pleno-dlp/pkg/sources/all"
)

// TestScanHelp confirms the scan subcommand is wired into Root and renders
// help with the expected flags. Real e2e coverage (with a fixture filesystem
// and a stub source) is qa's job — this test only guards the wiring.
func TestScanHelp(t *testing.T) {
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "--help"})

	if err := Root.Execute(); err != nil {
		t.Fatalf("scan --help: %v", err)
	}

	got := out.String()
	for _, want := range []string{"--format", "--verify", "--concurrency", "scan"} {
		if !strings.Contains(got, want) {
			t.Errorf("help missing %q in:\n%s", want, got)
		}
	}
}

func TestScanFilesystemRequiresPath(t *testing.T) {
	// Args validation runs before RunE, so we can drive it without exercising
	// the source registry. Using cobra.Command.Args directly avoids state
	// bleed from sibling tests that may have flipped help flags on Root.
	if err := scanFilesystemCmd.Args(scanFilesystemCmd, []string{}); err == nil {
		t.Errorf("expected error when no path given to scan filesystem")
	}
}

func TestScanGitHelp(t *testing.T) {
	// `scan git --help` must mention every git-specific flag so users can
	// discover them without reading the README.
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "git", "--help"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("scan git --help: %v", err)
	}
	got := out.String()
	for _, want := range []string{"--repo", "--branch", "--since", "--max-depth", "--include", "--exclude"} {
		if !strings.Contains(got, want) {
			t.Errorf("scan git help missing %q in:\n%s", want, got)
		}
	}
}

func TestIsFindingsError(t *testing.T) {
	if !IsFindingsError(errFindingsFound) {
		t.Errorf("sentinel must match itself")
	}
	if IsFindingsError(nil) {
		t.Errorf("nil must not match")
	}
}

// TestParseFailOn covers the --fail-on parser. Unknown values must
// fail loudly so a typo in CI config doesn't silently downgrade the
// gate (`--fail-on critcal` would otherwise pass through unchecked).
func TestParseFailOn(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"any", false},
		{"", false},
		{"info", false},
		{"low", false},
		{"medium", false},
		{"high", false},
		{"critical", false},
		{"CRITICAL", false},
		{" critical ", false},
		{"extreme", true},
		{"verified", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			_, err := parseFailOn(tc.in)
			if (err != nil) != tc.wantErr {
				t.Errorf("parseFailOn(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
		})
	}
}

// TestScanFailOnGate asserts --fail-on=critical does NOT exit non-zero
// when only High findings are present (custom rule severity=high).
// Today's behaviour without --fail-on still trips on any finding.
func TestScanFailOnGate(t *testing.T) {
	t.Cleanup(resetScanOpts) // global flag state is shared across tests
	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "ACME_QWERTYUIOPASDFGHJKLZ\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rules := dir + "/rules.json"
	if err := writeFile(rules, `[{
		"name":"ACME Token",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"severity":"high"
	}]`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "--rules", rules, "--fail-on", "critical", "--format", "json", "filesystem", target})

	err := Root.Execute()
	// High finding under a Critical gate should NOT trip findings error.
	if IsFindingsError(err) {
		t.Fatalf("--fail-on=critical should not trip on High; output:\n%s", out.String())
	}
}

// resetScanOpts restores the default values cobra wired up at init() so
// flag state set by one test doesn't leak into the next. Cobra's
// PersistentFlags retains the last value seen — without this reset the
// next test runs with whatever --fail-on the previous test set.
func resetScanOpts() {
	scanOpts.format = "table"
	scanOpts.verify = false
	scanOpts.verifyRPS = 10
	scanOpts.concurrency = 8
	scanOpts.rulesPath = ""
	scanOpts.failOn = "any"
	scanOpts.allowlistPath = ""
	scanOpts.includeDetectors = nil
	scanOpts.excludeDetectors = nil
	scanOpts.quiet = false
}

// TestScanFilesystemWithCustomRules drives the full CLI with a custom
// rules JSON and asserts the rule's regex matches a fixture file. Catches
// regressions where --rules is silently ignored or the loader crashes.
func TestScanFilesystemWithCustomRules(t *testing.T) {
	// Build a fixture with a non-default secret pattern that no built-in
	// detector matches. Using a custom prefix proves the hit comes from
	// the custom rule.
	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "config:\n  acme_token: ACME_QWERTYUIOPASDFGHJKLZ\n"); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}
	rules := dir + "/rules.json"
	if err := writeFile(rules, `[{
		"name":"ACME Token",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"severity":"high"
	}]`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "--rules", rules, "--format", "json", "filesystem", target})

	err := Root.Execute()
	// Findings present → expected to return errFindingsFound, not nil.
	if !IsFindingsError(err) {
		t.Fatalf("expected findings error; got %v\noutput: %s", err, out.String())
	}
	if !strings.Contains(out.String(), "ACME_QWERTYUIOPASDFGHJKLZ") &&
		!strings.Contains(out.String(), "ACME Token") &&
		!strings.Contains(out.String(), "ACME") {
		t.Errorf("output missing custom rule hit:\n%s", out.String())
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// TestScanStdin_FindsSecretFromPipe drives the stdin subcommand end-to-end
// by injecting a Buffer for cobra's input. Confirms that a piped secret
// surfaces a finding (errFindingsFound), and that StdinMeta.Label rides
// through to the JSON output via --label.
func TestScanStdin_FindsSecretFromPipe(t *testing.T) {
	resetScanOpts() // pre-emptive: cobra persistent flags retain prior --rules
	t.Cleanup(resetScanOpts)
	t.Cleanup(func() {
		stdinOpts.label = ""
		stdinOpts.maxBytes = 0
	})

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	// AKIAIOSFODNN7EXAMPLE is the canonical AWS dummy access key — the
	// AWS detector's keyword + regex should match it without verification.
	Root.SetIn(strings.NewReader("aws_access_key=AKIAIOSFODNN7EXAMPLE\n"))
	Root.SetArgs([]string{"scan", "--format", "json", "stdin", "--label", "test-pipe"})

	err := Root.Execute()
	if !IsFindingsError(err) {
		t.Fatalf("expected findings error from stdin scan; got %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "test-pipe") {
		t.Errorf("expected --label to ride through to output:\n%s", out.String())
	}
}

// TestScanFilesystemWithAllowlist proves a leaked AKIAIOSFODNN7EXAMPLE
// fixture is muted by an allowlist file pointed at via --allowlist.
// Without the allowlist this would trip errFindingsFound.
func TestScanFilesystemWithAllowlist(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	allow := dir + "/.pleno-allow.json"
	// Path-based allowlist — covers AWS plus any generic high-entropy
	// hits the catch-all detector raises against the same fixture.
	if err := writeFile(allow, `{"entries":[{"path":"leak.txt","reason":"trufflehog dummies"}]}`); err != nil {
		t.Fatalf("seed allow: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--allowlist", allow, "--format", "json", "filesystem", target})

	err := Root.Execute()
	if IsFindingsError(err) {
		t.Fatalf("allowlist should suppress AWS finding; output:\n%s\nstderr:\n%s", out.String(), errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "allowlist: suppressed") {
		t.Errorf("expected suppression notice on stderr; got:\n%s", errBuf.String())
	}
}

func TestScanStdin_NoFindingsExitsZero(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)
	t.Cleanup(func() {
		stdinOpts.label = ""
		stdinOpts.maxBytes = 0
	})

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetIn(strings.NewReader("nothing secret here, just plain text\n"))
	Root.SetArgs([]string{"scan", "--format", "json", "stdin"})

	if err := Root.Execute(); err != nil {
		t.Fatalf("clean stdin scan should succeed; got %v\noutput:\n%s", err, out.String())
	}
}

// TestFilterDetectors_Include narrows the registry by include list.
// Case-insensitive matching is exercised here by passing lowercase names.
func TestFilterDetectors_Include(t *testing.T) {
	in := []detectors.Detector{stubDet{detectors.AWS}, stubDet{detectors.GitHub}, stubDet{detectors.OpenAI}}
	got, err := filterDetectors(in, []string{"aws", "github"}, nil)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 detectors, got %d", len(got))
	}
}

func TestFilterDetectors_Exclude(t *testing.T) {
	in := []detectors.Detector{stubDet{detectors.AWS}, stubDet{detectors.GitHub}, stubDet{detectors.OpenAI}}
	got, err := filterDetectors(in, nil, []string{"AWS"})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 after excluding AWS, got %d", len(got))
	}
	for _, d := range got {
		if d.Type() == detectors.AWS {
			t.Errorf("AWS slipped past exclude")
		}
	}
}

func TestFilterDetectors_IncludeThenExclude(t *testing.T) {
	in := []detectors.Detector{stubDet{detectors.AWS}, stubDet{detectors.GitHub}, stubDet{detectors.OpenAI}}
	got, err := filterDetectors(in, []string{"aws", "github"}, []string{"github"})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(got) != 1 || got[0].Type() != detectors.AWS {
		t.Fatalf("want only AWS after include={aws,github} exclude={github}, got %+v", got)
	}
}

func TestFilterDetectors_UnknownNameErrors(t *testing.T) {
	in := []detectors.Detector{stubDet{detectors.AWS}}
	if _, err := filterDetectors(in, []string{"awz"}, nil); err == nil {
		t.Errorf("typo should error, not silently match nothing")
	}
	if _, err := filterDetectors(in, nil, []string{"awz"}); err == nil {
		t.Errorf("typo in exclude should error")
	}
}

func TestFilterDetectors_NoFlagsPassthrough(t *testing.T) {
	in := []detectors.Detector{stubDet{detectors.AWS}, stubDet{detectors.GitHub}}
	got, err := filterDetectors(in, nil, nil)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(got) != len(in) {
		t.Errorf("no-op filter mutated slice: %d -> %d", len(in), len(got))
	}
}

// TestScanFilesystemFiltersDetectors drives the full CLI: --exclude-detectors
// must remove the detector from the live scan, not just from --help output.
func TestScanFilesystemFiltersDetectors(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)

	dir := t.TempDir()
	target := dir + "/leak.txt"
	// Real-shaped AWS access-key id; verified=false but the AWS detector
	// will still emit it. Excluding the detector should silence it.
	if err := os.WriteFile(target, []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--exclude-detectors", "aws,generichighentropy", "--format", "json", "filesystem", target})

	err := Root.Execute()
	if IsFindingsError(err) {
		t.Fatalf("--exclude-detectors aws should silence the AWS finding; output:\n%s", out.String())
	}
}

// stubDet is a minimal Detector for unit tests that don't care about
// scanning behaviour — only Type() is exercised by filterDetectors.
type stubDet struct{ t detectors.DetectorType }

func (s stubDet) Type() detectors.DetectorType    { return s.t }
func (s stubDet) Keywords() []string              { return nil }
func (s stubDet) FromData(_ context.Context, _ bool, _ []byte) ([]detectors.Result, error) {
	return nil, nil
}
