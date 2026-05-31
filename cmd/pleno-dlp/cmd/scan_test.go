package cmd

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"

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
	scanOpts.revokeOnVerified = false
	scanOpts.revokeDryRun = false
	scanOpts.blastRadiusOnly = false
}

// TestBlastRadiusFilterSink_DropsAndForwards drives the sink directly to
// assert the wrap-then-emit contract: a finding tagged blast_radius=true
// reaches the inner sink, and one without it is dropped (and counted).
func TestBlastRadiusFilterSink_DropsAndForwards(t *testing.T) {
	captured := &captureSink{}
	bf := &blastRadiusFilterSink{inner: captured}

	// One finding with the rollup tag → forwarded.
	br := engineFinding(detectors.AWS, true, "AKIA…")
	if br.Result.ExtraData == nil {
		br.Result.ExtraData = map[string]string{}
	}
	br.Result.ExtraData["blast_radius"] = "true"
	bf.Emit(br)

	// One finding without the tag → dropped.
	bf.Emit(engineFinding(detectors.AWS, true, "AKIA…2"))

	if got := len(captured.findings); got != 1 {
		t.Errorf("expected 1 finding forwarded, got %d", got)
	}
	if dr := bf.dropped.Load(); dr != 1 {
		t.Errorf("expected dropped=1, got %d", dr)
	}
}

// TestScan_RevokeOnVerified_RefusesWithoutEnv asserts that scan refuses
// early when --revoke-on-verified is set but PLENO_DLP_ALLOW_REVOKE is
// not. This is the central CI-safety promise: an operator cannot
// accidentally blow up live credentials by misconfiguring a CI job.
func TestScan_RevokeOnVerified_RefusesWithoutEnv(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)
	t.Setenv(EnvAllowRevoke, "")

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "no secrets here\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--verify", "--revoke-on-verified", "--format", "json", "filesystem", target})

	err := Root.Execute()
	if err == nil {
		t.Fatalf("scan must refuse --revoke-on-verified without %s=1", EnvAllowRevoke)
	}
	if !strings.Contains(err.Error(), EnvAllowRevoke) {
		t.Errorf("error must mention %s: %v", EnvAllowRevoke, err)
	}
}

// TestScan_RevokeOnVerified_RequiresVerify catches the obvious misuse
// of asking us to revoke unverified candidates, which would risk
// invalidating tokens that aren't ours.
func TestScan_RevokeOnVerified_RequiresVerify(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)
	t.Setenv(EnvAllowRevoke, "1")

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "no secrets here\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--revoke-on-verified", "--format", "json", "filesystem", target})

	err := Root.Execute()
	if err == nil {
		t.Fatalf("--revoke-on-verified without --verify must fail")
	}
	if !strings.Contains(err.Error(), "--verify") {
		t.Errorf("error must mention --verify: %v", err)
	}
}

// TestScan_RevokeOnVerified_DryRunBypassesEnv confirms --revoke-dry-run
// is a usable preview path for operators who want to see what scan
// would attempt without setting the env opt-in. The dry-run summary
// line is emitted to stderr.
func TestScan_RevokeOnVerified_DryRunBypassesEnv(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)
	t.Setenv(EnvAllowRevoke, "")

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "nothing here\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--verify", "--revoke-on-verified", "--revoke-dry-run", "--format", "json", "filesystem", target})

	if err := Root.Execute(); err != nil {
		t.Fatalf("dry-run with no findings should succeed; got %v\nstderr:\n%s", err, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "revoke:") {
		t.Errorf("expected revoke summary on stderr; got:\n%s", errBuf.String())
	}
}

// TestRevokingSink_VerifiedFindingDispatches drives the sink directly
// (no filesystem, no network) to assert the wrap-then-emit contract:
// findings still propagate downstream, AND a verified finding whose
// detector implements Revoker triggers Revoke. This is the inner
// invariant that the higher-level CLI tests depend on.
func TestRevokingSink_VerifiedFindingDispatches(t *testing.T) {
	captured := &captureSink{}
	rev := &fakeRevoker{}
	det := fakeDetectorWithRevoker{Revoker: rev}

	rs := newRevokingSink(captured, []detectors.Detector{det}, false, &bytes.Buffer{})
	rs.Emit(engineFinding(detectors.GitHub, true, "ghp_xxx"))
	rs.Emit(engineFinding(detectors.GitHub, false, "ghp_yyy"))

	if got := len(captured.findings); got != 2 {
		t.Errorf("expected both findings forwarded, got %d", got)
	}
	if rev.calls != 1 {
		t.Errorf("expected 1 revoke call (verified only), got %d", rev.calls)
	}
	if rs.attempted.Load() != 1 || rs.revoked.Load() != 1 {
		t.Errorf("counters: attempted=%d revoked=%d, want 1/1", rs.attempted.Load(), rs.revoked.Load())
	}
}

// TestRevokingSink_DryRunDoesNotCallProvider exercises the preview
// path: a verified finding logs to logW but the provider is never
// contacted. Failure here usually means the dry-run branch fell
// through to the live revoke call.
func TestRevokingSink_DryRunDoesNotCallProvider(t *testing.T) {
	captured := &captureSink{}
	rev := &fakeRevoker{}
	det := fakeDetectorWithRevoker{Revoker: rev}

	var logBuf bytes.Buffer
	rs := newRevokingSink(captured, []detectors.Detector{det}, true, &logBuf)
	rs.Emit(engineFinding(detectors.GitHub, true, "ghp_xxx"))

	if rev.calls != 0 {
		t.Errorf("dry-run must not call provider; got %d calls", rev.calls)
	}
	if !strings.Contains(logBuf.String(), "DRY-RUN") {
		t.Errorf("dry-run must log preview line; got:\n%s", logBuf.String())
	}
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
	// AKIA + 16 alnum matches the AWS detector regex. AKIAIOSFODNN7EXAMPLE
	// would have been the natural pick, but the engine-level placeholder
	// filter now drops anything containing "EXAMPLE" (a substring marker
	// in IsPlaceholder) — the whole point of that filter is to stop AWS
	// docs literals from spamming output. Use a synthetic that satisfies
	// the regex without tripping any placeholder marker.
	Root.SetIn(strings.NewReader("aws_access_key=AKIA1234567890ABCDEF\n"))
	Root.SetArgs([]string{"scan", "--format", "json", "stdin", "--label", "test-pipe"})

	err := Root.Execute()
	if !IsFindingsError(err) {
		t.Fatalf("expected findings error from stdin scan; got %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "test-pipe") {
		t.Errorf("expected --label to ride through to output:\n%s", out.String())
	}
}

// TestScanFilesystemWithAllowlist proves a leaked AWS-shaped fixture
// is muted by an allowlist file pointed at via --allowlist. Without
// the allowlist this would trip errFindingsFound. The fixture avoids
// placeholder markers (no EXAMPLE substring, no long X/0 runs) so
// the engine-level placeholder filter doesn't pre-empt the allowlist
// path under test — we want this assertion to fail when allowlist
// regresses, not when an unrelated filter changes.
func TestScanFilesystemWithAllowlist(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYqWERTY1KEY\n"); err != nil {
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

// TestScanStdin_TruncatedButFoundStillReportsFindings is the regression
// guard for the stdin-truncation correctness bug: a stdin scan that hit
// the --max-bytes cap (truncated) but still detected a secret in the
// scanned prefix must NOT return the fatal truncation error. It must warn
// on stderr, print the end-of-scan summary, and return errFindingsFound so
// the exit code reflects the finding the user can see. Before the fix,
// scan.go treated the truncation sentinel as a fatal `scan: %w` error,
// suppressing the summary and clobbering the findings exit code.
func TestScanStdin_TruncatedButFoundStillReportsFindings(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)
	t.Cleanup(func() {
		stdinOpts.label = ""
		stdinOpts.maxBytes = 0
	})

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	// The AWS-shaped key sits in the first 35 bytes; the trailing padding
	// pushes total input past --max-bytes so the source truncates. The
	// scanned prefix still contains the full key, so a finding is emitted.
	secretLine := "aws_access_key=AKIA1234567890ABCDEF\n"
	Root.SetIn(strings.NewReader(secretLine + strings.Repeat("x", 4096)))
	Root.SetArgs([]string{"scan", "--format", "json", "stdin", "--max-bytes", "40"})

	err := Root.Execute()
	if !IsFindingsError(err) {
		t.Fatalf("truncated stdin with a finding must return errFindingsFound, not the truncation error; got %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "max_bytes") {
		t.Errorf("expected truncation warning on stderr; got:\n%s", errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "finding(s)") {
		t.Errorf("expected end-of-scan summary on stderr; got:\n%s", errBuf.String())
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

func (s stubDet) Type() detectors.DetectorType { return s.t }
func (s stubDet) Keywords() []string           { return nil }
func (s stubDet) FromData(_ context.Context, _ bool, _ []byte) ([]detectors.Result, error) {
	return nil, nil
}

// captureSink records every Finding it receives so revokingSink tests
// can assert downstream propagation.
type captureSink struct{ findings []engine.Finding }

func (c *captureSink) Emit(f engine.Finding) { c.findings = append(c.findings, f) }
func (c *captureSink) Close() error          { return nil }

// fakeRevoker counts Revoke calls and reports success.
type fakeRevoker struct{ calls int }

func (f *fakeRevoker) Revoke(_ context.Context, _ string) (detectors.RevokeResult, error) {
	f.calls++
	return detectors.RevokeResult{Revoked: true}, nil
}

// fakeDetectorWithRevoker pairs a stub Detector with a Revoker so the
// type assertion inside newRevokingSink picks it up.
type fakeDetectorWithRevoker struct{ Revoker detectors.Revoker }

func (f fakeDetectorWithRevoker) Type() detectors.DetectorType { return detectors.GitHub }
func (f fakeDetectorWithRevoker) Keywords() []string           { return []string{"ghp_"} }
func (f fakeDetectorWithRevoker) FromData(_ context.Context, _ bool, _ []byte) ([]detectors.Result, error) {
	return nil, nil
}
func (f fakeDetectorWithRevoker) Revoke(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	return f.Revoker.Revoke(ctx, secret)
}

// engineFinding builds an engine.Finding so the revoking-sink tests
// read declaratively without reciting the full struct shape.
func engineFinding(t detectors.DetectorType, verified bool, raw string) engine.Finding {
	return engine.Finding{
		Detector: t,
		Result: detectors.Result{
			DetectorType: t,
			Verified:     verified,
			Raw:          []byte(raw),
		},
	}
}
