package cmd

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"

	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
	_ "github.com/plenoai/pleno-dlp/pkg/sources/all"
)

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
	if err := scanFilesystemCmd.Args(scanFilesystemCmd, []string{}); err == nil {
		t.Errorf("expected error when no path given to scan filesystem")
	}
}

func TestScanGitHelp(t *testing.T) {
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
	if IsFindingsError(err) {
		t.Fatalf("--fail-on=critical should not trip on High; output:\n%s", out.String())
	}
}

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
	scanOpts.incremental = false
	scanOpts.incrementalState = ".pleno-dlp-incremental.json"
	scanOpts.piiEngine = "off"
	scanOpts.piiEngineCmd = "pleno-dlp pii-server --port {PORT}"
	scanOpts.piiEnginePort = 0
	scanOpts.piiEngineLanguage = "auto"
	scanOpts.piiEngineReady = 0
	scanOpts.piiEngineRequest = 10 * time.Second
	scanOpts.piiEngineDevice = "auto"
}

func TestBlastRadiusFilterSink_DropsAndForwards(t *testing.T) {
	captured := &captureSink{}
	bf := &blastRadiusFilterSink{inner: captured}

	br := engineFinding(detectors.AWS, true, "AKIA…")
	if br.Result.ExtraData == nil {
		br.Result.ExtraData = map[string]string{}
	}
	br.Result.ExtraData["blast_radius"] = "true"
	bf.Emit(br)

	bf.Emit(engineFinding(detectors.AWS, true, "AKIA…2"))

	if got := len(captured.findings); got != 1 {
		t.Errorf("expected 1 finding forwarded, got %d", got)
	}
	if dr := bf.dropped.Load(); dr != 1 {
		t.Errorf("expected dropped=1, got %d", dr)
	}
}

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

func TestScanFilesystemWithCustomRules(t *testing.T) {
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

func TestScanFilesystemWithAllowlist(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYqWERTY1KEY\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	allow := dir + "/.pleno-allow.json"
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

func TestScanFilesystemIncrementalSkipsUnchangedCleanScan(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)

	dir := t.TempDir()
	target := dir + "/clean.txt"
	state := dir + "/state/incremental.json"
	if err := writeFile(target, "ordinary docs with no credential material\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var firstOut, firstErr bytes.Buffer
	Root.SetOut(&firstOut)
	Root.SetErr(&firstErr)
	Root.SetArgs([]string{"scan", "--incremental", "--incremental-state", state, "--verify", "--revoke-on-verified", "--revoke-dry-run", "--format", "json", "filesystem", target})
	if err := Root.Execute(); err != nil {
		t.Fatalf("first incremental baseline should scan cleanly: %v\nstderr:\n%s", err, firstErr.String())
	}
	if !strings.Contains(firstErr.String(), "scanned 1 chunk") {
		t.Fatalf("first run should perform the baseline scan; stderr:\n%s", firstErr.String())
	}

	var secondOut, secondErr bytes.Buffer
	Root.SetOut(&secondOut)
	Root.SetErr(&secondErr)
	Root.SetArgs([]string{"scan", "--incremental", "--incremental-state", state, "--verify", "--revoke-on-verified", "--revoke-dry-run", "--format", "json", "filesystem", target})
	if err := Root.Execute(); err != nil {
		t.Fatalf("unchanged clean incremental run should skip and succeed: %v\nstderr:\n%s", err, secondErr.String())
	}
	if !strings.Contains(secondErr.String(), "incremental: unchanged resources; skipped scan") {
		t.Fatalf("second run should skip; stderr:\n%s", secondErr.String())
	}
}

func TestScanFilesystemIncrementalSkipPreservesFindingExit(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)

	dir := t.TempDir()
	target := dir + "/leak.txt"
	state := dir + "/incremental.json"
	rules := dir + "/rules.json"
	if err := writeFile(target, "acme_token=ACME_QWERTYUIOPASDFGHJKLZ\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := writeFile(rules, `[{
		"name":"ACME Token",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"severity":"high"
	}]`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var firstOut, firstErr bytes.Buffer
	Root.SetOut(&firstOut)
	Root.SetErr(&firstErr)
	Root.SetArgs([]string{"scan", "--incremental", "--incremental-state", state, "--rules", rules, "--format", "json", "filesystem", target})
	if err := Root.Execute(); !IsFindingsError(err) {
		t.Fatalf("first baseline should find the custom secret; got %v\nstdout:\n%s\nstderr:\n%s", err, firstOut.String(), firstErr.String())
	}

	var secondOut, secondErr bytes.Buffer
	Root.SetOut(&secondOut)
	Root.SetErr(&secondErr)
	Root.SetArgs([]string{"scan", "--incremental", "--incremental-state", state, "--rules", rules, "--format", "json", "filesystem", target})
	if err := Root.Execute(); !IsFindingsError(err) {
		t.Fatalf("unchanged finding baseline must preserve finding exit; got %v\nstdout:\n%s\nstderr:\n%s", err, secondOut.String(), secondErr.String())
	}
	if !strings.Contains(secondErr.String(), "incremental: unchanged resources; skipped scan") {
		t.Fatalf("second run should skip; stderr:\n%s", secondErr.String())
	}
	if secondOut.Len() != 0 {
		t.Fatalf("skipped scan should not replay stale findings on stdout; got:\n%s", secondOut.String())
	}
}

func TestScanFilesystemIncrementalSkipsRevokeDryRunWhenUnchanged(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)
	t.Setenv(EnvAllowRevoke, "")

	dir := t.TempDir()
	target := dir + "/clean.txt"
	state := dir + "/incremental.json"
	if err := writeFile(target, "ordinary docs with no credential material\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var firstOut, firstErr bytes.Buffer
	Root.SetOut(&firstOut)
	Root.SetErr(&firstErr)
	Root.SetArgs([]string{"scan", "--incremental", "--incremental-state", state, "--verify", "--revoke-on-verified", "--revoke-dry-run", "--format", "json", "filesystem", target})
	if err := Root.Execute(); err != nil {
		t.Fatalf("first incremental baseline should scan cleanly: %v\nstderr:\n%s", err, firstErr.String())
	}

	var secondOut, secondErr bytes.Buffer
	Root.SetOut(&secondOut)
	Root.SetErr(&secondErr)
	Root.SetArgs([]string{"scan", "--incremental", "--incremental-state", state, "--verify", "--revoke-on-verified", "--revoke-dry-run", "--format", "json", "filesystem", target})
	if err := Root.Execute(); err != nil {
		t.Fatalf("unchanged incremental revoke dry-run should skip cleanly: %v\nstderr:\n%s", err, secondErr.String())
	}
	if !strings.Contains(secondErr.String(), "incremental: unchanged resources; skipped scan") {
		t.Fatalf("state match should skip even with revoke-on-verified; stderr:\n%s", secondErr.String())
	}
	if strings.Contains(secondErr.String(), "scanned 1 chunk") {
		t.Fatalf("skipped scan should not run detectors; stderr:\n%s", secondErr.String())
	}
	if strings.Contains(secondErr.String(), "revoke:") {
		t.Fatalf("skipped scan should not emit revoke summary; stderr:\n%s", secondErr.String())
	}
}

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

func TestScanFilesystemFiltersDetectors(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)

	dir := t.TempDir()
	target := dir + "/leak.txt"
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
