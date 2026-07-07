package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

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
	for _, want := range []string{"--format", "--concurrency", "scan"} {
		if !strings.Contains(got, want) {
			t.Errorf("help missing %q in:\n%s", want, got)
		}
	}
}

func TestScanVerifyFlagRemoved(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)

	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "--verify", "--help"})

	err := Root.Execute()
	if err == nil {
		t.Fatal("--verify must be rejected; verification is default-on")
	}
	if !strings.Contains(err.Error(), "unknown flag: --verify") {
		t.Fatalf("error must reject --verify: %v", err)
	}
}

func TestScanFilesystemRequiresPath(t *testing.T) {
	if err := scanFilesystemCmd.Args(scanFilesystemCmd, []string{}); err == nil {
		t.Errorf("expected error when no path given to scan filesystem")
	}
}

func TestScanGitHelp(t *testing.T) {
	// cobra's "help" bool flag is a normal pflag value on scanGitCmd's own
	// FlagSet: Parse only touches flags present in argv, so it survives
	// across Execute() calls within one test binary. Reset it so a later
	// test that actually runs `scan git` (no --help) isn't silently
	// short-circuited into printing help again.
	t.Cleanup(func() { _ = scanGitCmd.Flags().Set("help", "false") })

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

// TestFailOnDefaultIsHigh pins the audit-first default (#250): a
// first-time adopter who never passes --fail-on must get "high", not
// the old "any". Checked against both commands that expose the flag —
// scan (persistent) and protect (its own local copy of the same flag,
// see protect.go) — since a mismatch between the two would silently
// reintroduce enforce-first behaviour for one of them.
func TestFailOnDefaultIsHigh(t *testing.T) {
	f := scanCmd.PersistentFlags().Lookup("fail-on")
	if f == nil {
		t.Fatal("scan: --fail-on flag not registered")
	}
	if f.DefValue != "high" {
		t.Errorf("scan --fail-on default = %q, want %q (audit-first rollout, #250)", f.DefValue, "high")
	}

	pf := protectCmd.Flags().Lookup("fail-on")
	if pf == nil {
		t.Fatal("protect: --fail-on flag not registered")
	}
	if pf.DefValue != "high" {
		t.Errorf("protect --fail-on default = %q, want %q (audit-first rollout, #250)", pf.DefValue, "high")
	}
}

// TestScanFailOnDefault_LowSeverityFindingExitsZero is the acceptance
// scenario from #250: a fresh `scan filesystem` run against a target
// with one low-severity finding must exit 0 by default (no --fail-on
// passed) and must explain, on stderr, why nothing failed the build
// and how to tighten the gate. Before #250 the default was "any" and
// this same finding would have exited 1.
func TestScanFailOnDefault_LowSeverityFindingExitsZero(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)

	dir := t.TempDir()
	target := dir + "/notes.txt"
	if err := writeFile(target, "acme_ref: ACME_QWERTYUIOPASDFGHJKLZ\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rules := dir + "/rules.json"
	if err := writeFile(rules, `[{
		"name":"ACME Reference",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"severity":"low"
	}]`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	// Deliberately no --fail-on: exercise the default.
	Root.SetArgs([]string{"scan", "--rules", rules, "--format", "json", "filesystem", target})

	err := Root.Execute()
	if err != nil {
		t.Fatalf("default --fail-on=high must not trip on a Low finding; err=%v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errBuf.String())
	}
	// Raw secret bytes are redacted in JSON output by design; assert on
	// the custom-rule name that rides through in extra_data instead.
	if !strings.Contains(out.String(), "ACME Reference") {
		t.Errorf("finding must still be emitted (audit, don't hide); output:\n%s", out.String())
	}
	stderr := errBuf.String()
	if !strings.Contains(stderr, "exit gate: --fail-on=high") {
		t.Errorf("expected exit-gate hint naming the active gate; stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "1 low") {
		t.Errorf("expected hint to count the below-gate finding; stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "--fail-on=any") {
		t.Errorf("expected hint to name the escape hatch to block on all; stderr:\n%s", stderr)
	}
}

func resetScanOpts() {
	scanOpts.format = "table"
	scanOpts.onlyVerified = false
	scanOpts.dropIndeterminate = false
	scanOpts.verifyRPS = 10
	scanOpts.concurrency = 8
	scanOpts.rulesPath = ""
	scanOpts.failOn = "high"
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

func TestVerifiedOnlySink_DropsUnverified(t *testing.T) {
	captured := &captureSink{}
	vo := &verifiedOnlySink{inner: captured}

	vo.Emit(engineFinding(detectors.GitHub, false, "ghp_unverified"))
	vo.Emit(engineFinding(detectors.GitHub, true, "ghp_verified"))

	if got := len(captured.findings); got != 1 {
		t.Fatalf("expected only verified finding forwarded, got %d", got)
	}
	if !captured.findings[0].Result.Verified {
		t.Fatal("forwarded finding must be verified")
	}
	if dropped := vo.dropped.Load(); dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
}

// engineFindingIndeterminate builds a Finding whose verification attempt
// failed (VerificationErr set, Verified false) — the shape a real detector
// produces on a network error / provider 5xx / rate limit rather than an
// affirmative "not live" response.
func engineFindingIndeterminate(t detectors.DetectorType, raw string) engine.Finding {
	f := engineFinding(t, false, raw)
	f.Result.VerificationErr = errors.New("dial tcp: connection refused")
	return f
}

// TestVerifiedOnlySink_KeepsIndeterminateByDefault pins the core #246 fix:
// --only-verified must not silently drop a finding whose verification
// attempt failed outright, because that's indistinguishable from "provider
// confirmed dead" once collapsed to a bool — exactly the bug this issue is
// about. The default (no --drop-indeterminate) keeps it and counts it
// separately from the confirmed-dead drops.
func TestVerifiedOnlySink_KeepsIndeterminateByDefault(t *testing.T) {
	captured := &captureSink{}
	vo := &verifiedOnlySink{inner: captured}

	vo.Emit(engineFinding(detectors.GitHub, false, "ghp_confirmed_dead"))
	vo.Emit(engineFindingIndeterminate(detectors.GitHub, "ghp_network_blip"))
	vo.Emit(engineFinding(detectors.GitHub, true, "ghp_verified"))

	if got := len(captured.findings); got != 2 {
		t.Fatalf("expected verified + indeterminate forwarded, got %d", got)
	}
	var sawIndeterminate, sawVerified bool
	for _, f := range captured.findings {
		switch f.Result.Verdict() {
		case detectors.VerdictIndeterminate:
			sawIndeterminate = true
		case detectors.VerdictVerified:
			sawVerified = true
		case detectors.VerdictUnverified:
			t.Errorf("confirmed-dead finding must not be forwarded: %v", f.Result.Raw)
		}
	}
	if !sawIndeterminate || !sawVerified {
		t.Fatalf("expected both indeterminate and verified forwarded; got %+v", captured.findings)
	}
	if got := vo.indeterminate.Load(); got != 1 {
		t.Errorf("indeterminate counter = %d, want 1", got)
	}
	if got := vo.dropped.Load(); got != 1 {
		t.Errorf("dropped counter = %d, want 1 (only the confirmed-dead finding)", got)
	}
}

// TestVerifiedOnlySink_DropIndeterminateFlag pins the --drop-indeterminate
// opt-out: when set, indeterminate findings are dropped like confirmed-dead
// ones, restoring the pre-#246 strict behaviour for callers that would
// rather under-report than see an unconfirmed finding.
func TestVerifiedOnlySink_DropIndeterminateFlag(t *testing.T) {
	captured := &captureSink{}
	vo := &verifiedOnlySink{inner: captured, dropIndeterminate: true}

	vo.Emit(engineFindingIndeterminate(detectors.GitHub, "ghp_network_blip"))
	vo.Emit(engineFinding(detectors.GitHub, true, "ghp_verified"))

	if got := len(captured.findings); got != 1 {
		t.Fatalf("expected only verified finding forwarded, got %d", got)
	}
	if captured.findings[0].Result.Verdict() != detectors.VerdictVerified {
		t.Fatalf("forwarded finding must be verified, got %v", captured.findings[0].Result.Verdict())
	}
	if got := vo.indeterminate.Load(); got != 1 {
		t.Errorf("indeterminate counter = %d, want 1 (still counted even though dropped)", got)
	}
	if got := vo.dropped.Load(); got != 1 {
		t.Errorf("dropped counter = %d, want 1", got)
	}
}

// TestRevokingSink_NeverRevokesIndeterminate pins the acceptance criterion
// from issue #246: revocation must never fire on an Indeterminate verdict.
// A failed verification attempt means liveness is unknown, not confirmed —
// dispatching Revoke on that basis could invalidate a credential that was
// never actually shown to be live.
func TestRevokingSink_NeverRevokesIndeterminate(t *testing.T) {
	captured := &captureSink{}
	rev := &fakeRevoker{}
	det := fakeDetectorWithRevoker{Revoker: rev}

	rs := newRevokingSink(captured, []detectors.Detector{det}, false, &bytes.Buffer{})
	rs.Emit(engineFindingIndeterminate(detectors.GitHub, "ghp_network_blip"))

	if rev.calls != 0 {
		t.Errorf("expected 0 revoke calls for an indeterminate verdict, got %d", rev.calls)
	}
	if rs.attempted.Load() != 0 {
		t.Errorf("attempted = %d, want 0", rs.attempted.Load())
	}
	// Same as an Unverified finding: revokingSink's "skipped" counter
	// tracks "verified but no Revoker for this detector", a distinct
	// reason from "not eligible for revoke at all". Neither Unverified
	// nor Indeterminate findings reach that branch.
	if rs.skipped.Load() != 0 {
		t.Errorf("skipped = %d, want 0", rs.skipped.Load())
	}
	if got := len(captured.findings); got != 1 {
		t.Errorf("finding must still be forwarded downstream, got %d", got)
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
	Root.SetArgs([]string{"scan", "--revoke-on-verified", "--format", "json", "filesystem", target})

	err := Root.Execute()
	if err == nil {
		t.Fatalf("scan must refuse --revoke-on-verified without %s=1", EnvAllowRevoke)
	}
	if !strings.Contains(err.Error(), EnvAllowRevoke) {
		t.Errorf("error must mention %s: %v", EnvAllowRevoke, err)
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
	Root.SetArgs([]string{"scan", "--revoke-on-verified", "--revoke-dry-run", "--format", "json", "filesystem", target})

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

// unreachableLocalPort binds an ephemeral loopback port and immediately
// closes it, so nothing listens there. Dialing it fails fast with
// "connection refused" — deterministic and independent of any external
// network reachability, unlike a real DNS-resolved unreachable host.
func unreachableLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return port
}

// TestScan_OnlyVerifiedKeepsIndeterminateFinding is the issue #246 scenario
// test: a custom rule's verify_url points at an unreachable local port, so
// every verification attempt fails with a transport error rather than an
// affirmative "not live" response. With --only-verified, the finding must
// still be emitted (marked indeterminate, not silently dropped) and a
// stderr warning must report the count — collapsing Verified=false here
// would make a live credential caught in a provider outage indistinguishable
// from "no secrets found".
func TestScan_OnlyVerifiedKeepsIndeterminateFinding(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)

	port := unreachableLocalPort(t)

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "config:\n  acme_token: ACME_QWERTYUIOPASDFGHJKLZ\n"); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}
	rules := dir + "/rules.json"
	rulesJSON := fmt.Sprintf(`[{
		"name":"ACME Token",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"severity":"high",
		"verify_url":"http://127.0.0.1:%d/verify"
	}]`, port)
	if err := writeFile(rules, rulesJSON); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--rules", rules, "--only-verified", "--format", "json", "filesystem", target})

	execErr := Root.Execute()
	if !IsFindingsError(execErr) {
		t.Fatalf("expected findings error (indeterminate finding kept); got %v\nstdout:\n%s\nstderr:\n%s", execErr, out.String(), errBuf.String())
	}

	var records []map[string]any
	if err := json.Unmarshal(out.Bytes(), &records); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
	}
	if len(records) != 1 {
		t.Fatalf("want 1 finding kept, got %d\nstdout:\n%s", len(records), out.String())
	}
	if records[0]["verdict"] != "indeterminate" {
		t.Errorf("verdict = %v, want indeterminate", records[0]["verdict"])
	}
	if records[0]["verified"] != false {
		t.Errorf("verified = %v, want false", records[0]["verified"])
	}
	if records[0]["verification_error"] == nil || records[0]["verification_error"] == "" {
		t.Errorf("verification_error must be populated, got %v", records[0]["verification_error"])
	}

	if !strings.Contains(errBuf.String(), "only-verified: kept 1 indeterminate finding") {
		t.Errorf("expected stderr warning about the kept indeterminate finding; stderr:\n%s", errBuf.String())
	}
}

// TestScan_OnlyVerifiedDropIndeterminateFlag exercises the --drop-indeterminate
// opt-out against the same unreachable-verifier scenario: the finding must
// be excluded entirely, and the scan must report success (no findings kept).
func TestScan_OnlyVerifiedDropIndeterminateFlag(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)

	port := unreachableLocalPort(t)

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "config:\n  acme_token: ACME_QWERTYUIOPASDFGHJKLZ\n"); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}
	rules := dir + "/rules.json"
	rulesJSON := fmt.Sprintf(`[{
		"name":"ACME Token",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"severity":"high",
		"verify_url":"http://127.0.0.1:%d/verify"
	}]`, port)
	if err := writeFile(rules, rulesJSON); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--rules", rules, "--only-verified", "--drop-indeterminate", "--format", "json", "filesystem", target})

	execErr := Root.Execute()
	if IsFindingsError(execErr) {
		t.Fatalf("expected no findings error (indeterminate finding dropped); got %v\nstdout:\n%s\nstderr:\n%s", execErr, out.String(), errBuf.String())
	} else if execErr != nil {
		t.Fatalf("unexpected error: %v", execErr)
	}

	var records []map[string]any
	if err := json.Unmarshal(out.Bytes(), &records); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
	}
	if len(records) != 0 {
		t.Fatalf("want 0 findings kept, got %d\nstdout:\n%s", len(records), out.String())
	}
	if !strings.Contains(errBuf.String(), "only-verified: dropped 1 indeterminate finding") {
		t.Errorf("expected stderr warning about the dropped indeterminate finding; stderr:\n%s", errBuf.String())
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// TestScanGit_DefaultReportsUnverifiedFinding is the issue #273 regression
// test: `scan git` (default flags — no --only-verified, no
// --all-occurrences) must report the same finding that `scan filesystem`
// and `scan stdin` report for identical content. Before the fix,
// engine.NewGitCrossCommitDedup buffered every finding until Close, but
// runScanCommon only ever closed the raw output sink, not the sink chain
// feeding it — so every git-mode finding was silently dropped regardless
// of its verdict.
//
// The custom rule's verify_url points at an unreachable local port so the
// verification outcome (indeterminate) is deterministic and offline,
// mirroring TestScan_OnlyVerifiedKeepsIndeterminateFinding.
func TestScanGit_DefaultReportsUnverifiedFinding(t *testing.T) {
	resetScanOpts()
	t.Cleanup(resetScanOpts)

	port := unreachableLocalPort(t)

	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	target := filepath.Join(dir, "leak.txt")
	if err := writeFile(target, "config:\n  acme_token: ACME_QWERTYUIOPASDFGHJKLZ\n"); err != nil {
		t.Fatalf("seed fixture: %v", err)
	}
	if _, err := wt.Add("leak.txt"); err != nil {
		t.Fatalf("add: %v", err)
	}
	sig := &object.Signature{Name: "Test", Email: "test@example.com", When: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}
	if _, err := wt.Commit("add-leak", &gogit.CommitOptions{Author: sig, Committer: sig}); err != nil {
		t.Fatalf("commit: %v", err)
	}

	rules := filepath.Join(dir, "rules.json")
	rulesJSON := fmt.Sprintf(`[{
		"name":"ACME Token",
		"keywords":["ACME_"],
		"regex":"ACME_[A-Z0-9]{20}",
		"severity":"high",
		"verify_url":"http://127.0.0.1:%d/verify"
	}]`, port)
	if err := writeFile(rules, rulesJSON); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"scan", "--rules", rules, "--format", "json", "git", "--repo", dir})

	execErr := Root.Execute()
	if !IsFindingsError(execErr) {
		t.Fatalf("expected findings error; got %v\nstdout:\n%s\nstderr:\n%s", execErr, out.String(), errBuf.String())
	}

	var records []map[string]any
	if err := json.Unmarshal(out.Bytes(), &records); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
	}
	if len(records) != 1 {
		t.Fatalf("want 1 finding, got %d\nstdout:\n%s", len(records), out.String())
	}
	if records[0]["verdict"] != "indeterminate" {
		t.Errorf("verdict = %v, want indeterminate", records[0]["verdict"])
	}
	if !strings.Contains(errBuf.String(), "scanned 1 chunk(s)") || strings.Contains(errBuf.String(), "0 finding(s)") {
		t.Errorf("expected non-zero finding count in summary; stderr:\n%s", errBuf.String())
	}
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
	Root.SetArgs([]string{"scan", "--incremental", "--incremental-state", state, "--revoke-on-verified", "--revoke-dry-run", "--format", "json", "filesystem", target})
	if err := Root.Execute(); err != nil {
		t.Fatalf("first incremental baseline should scan cleanly: %v\nstderr:\n%s", err, firstErr.String())
	}
	if !strings.Contains(firstErr.String(), "scanned 1 chunk") {
		t.Fatalf("first run should perform the baseline scan; stderr:\n%s", firstErr.String())
	}

	var secondOut, secondErr bytes.Buffer
	Root.SetOut(&secondOut)
	Root.SetErr(&secondErr)
	Root.SetArgs([]string{"scan", "--incremental", "--incremental-state", state, "--revoke-on-verified", "--revoke-dry-run", "--format", "json", "filesystem", target})
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
	Root.SetArgs([]string{"scan", "--incremental", "--incremental-state", state, "--revoke-on-verified", "--revoke-dry-run", "--format", "json", "filesystem", target})
	if err := Root.Execute(); err != nil {
		t.Fatalf("first incremental baseline should scan cleanly: %v\nstderr:\n%s", err, firstErr.String())
	}

	var secondOut, secondErr bytes.Buffer
	Root.SetOut(&secondOut)
	Root.SetErr(&secondErr)
	Root.SetArgs([]string{"scan", "--incremental", "--incremental-state", state, "--revoke-on-verified", "--revoke-dry-run", "--format", "json", "filesystem", target})
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
