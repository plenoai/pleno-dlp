package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/audit"
)

// TestRevoke_Single_EmitsAuditTrail exercises the real `revoke
// --detector --secret` CLI path end to end (issue #304: every revoke
// path must emit a well-formed, schema-versioned trail record).
// --dry-run keeps this network-free and deterministic while still
// running the exact same audit-trail wiring a live revoke would.
func TestRevoke_Single_EmitsAuditTrail(t *testing.T) {
	resetCommandFlags(t)

	dir := t.TempDir()
	trailPath := filepath.Join(dir, "trail.jsonl")
	const secret = "ghp_singlepathsecret1234567890abcdef"

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{
		"revoke", "--detector", "github", "--secret", secret,
		"--dry-run", "--audit-trail", trailPath,
	})

	if err := Root.Execute(); err != nil {
		t.Fatalf("revoke --dry-run failed: %v\nstderr:\n%s", err, errBuf.String())
	}

	rec := readSoleAuditRecordFile(t, trailPath)
	if rec.SchemaVersion != audit.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", rec.SchemaVersion, audit.SchemaVersion)
	}
	if rec.Path != string(audit.PathSingle) {
		t.Errorf("path = %q, want %q", rec.Path, audit.PathSingle)
	}
	if rec.Detector != "GitHub" {
		t.Errorf("detector = %q, want %q", rec.Detector, "GitHub")
	}
	if !rec.DryRun {
		t.Error("dry_run = false, want true")
	}
	if rec.Revoked {
		t.Error("revoked = true for a dry-run, want false")
	}
	if rec.SecretHash != audit.HashSecret(secret) {
		t.Errorf("secret_hash = %q, want hash of the leaked secret", rec.SecretHash)
	}
	if rec.TrailID == "" {
		t.Error("trail_id must be non-empty")
	}

	body, err := os.ReadFile(trailPath)
	if err != nil {
		t.Fatalf("read trail file: %v", err)
	}
	if strings.Contains(string(body), secret) {
		t.Fatalf("audit trail file leaked the raw secret: %s", body)
	}

	// Every other CLI surface touched by this invocation must also stay
	// clean of the raw secret: stdout (--format table writes nothing
	// there) and stderr (the human "DRY-RUN:" line uses the redacted
	// form only).
	if strings.Contains(errBuf.String(), secret) {
		t.Fatalf("stderr leaked the raw secret: %s", errBuf.String())
	}
}

// TestRevoke_Single_DefaultAuditTrailGoesToStderr pins the success
// criterion that every revoke emits a trail record even when the
// operator did not pass --audit-trail: the JSONL record must still
// appear somewhere observable (stderr), not be silently dropped.
func TestRevoke_Single_DefaultAuditTrailGoesToStderr(t *testing.T) {
	resetCommandFlags(t)

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{
		"revoke", "--detector", "slack", "--secret", "xoxb-nodurablefile",
		"--dry-run",
	})

	if err := Root.Execute(); err != nil {
		t.Fatalf("revoke --dry-run failed: %v\nstderr:\n%s", err, errBuf.String())
	}

	rec, found := findAuditRecordLine(t, errBuf.String())
	if !found {
		t.Fatalf("no audit trail JSON line found on stderr; got:\n%s", errBuf.String())
	}
	if rec.SchemaVersion != audit.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", rec.SchemaVersion, audit.SchemaVersion)
	}
	if rec.Detector != "SlackBotToken" {
		t.Errorf("detector = %q, want %q", rec.Detector, "SlackBotToken")
	}
}

// TestRevoke_FromSpool_EmitsAuditTrailPerLine covers the spool-replay
// path (`revoke --revoke-from-spool`). Each dispatched line must emit
// its own trail record carrying the spool's source_link forward as
// target_link.
func TestRevoke_FromSpool_EmitsAuditTrailPerLine(t *testing.T) {
	resetCommandFlags(t)

	dir := t.TempDir()
	spoolPath := filepath.Join(dir, "spool.jsonl")
	trailPath := filepath.Join(dir, "trail.jsonl")

	const secret = "ghp_spoolpathsecret1234567890abcdef"
	line := spoolRecord{
		Version:    spoolRecordVersion,
		Detector:   "GitHub",
		SecretB64:  base64.StdEncoding.EncodeToString([]byte(secret)),
		Redacted:   "ghp_spool...",
		SourceLink: "https://github.com/acme/repo/blob/main/leak.env",
	}
	b, err := json.Marshal(line)
	if err != nil {
		t.Fatalf("marshal spool line: %v", err)
	}
	if err := writeFile(spoolPath, string(b)+"\n"); err != nil {
		t.Fatalf("seed spool file: %v", err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{
		"revoke", "--revoke-from-spool", spoolPath,
		"--dry-run", "--audit-trail", trailPath,
	})

	if err := Root.Execute(); err != nil {
		t.Fatalf("revoke --revoke-from-spool --dry-run failed: %v\nstderr:\n%s", err, errBuf.String())
	}

	rec := readSoleAuditRecordFile(t, trailPath)
	if rec.Path != string(audit.PathSpool) {
		t.Errorf("path = %q, want %q", rec.Path, audit.PathSpool)
	}
	if rec.SchemaVersion != audit.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", rec.SchemaVersion, audit.SchemaVersion)
	}
	if rec.TargetLink != line.SourceLink {
		t.Errorf("target_link = %q, want the spool's source_link %q", rec.TargetLink, line.SourceLink)
	}
	if rec.SecretHash != audit.HashSecret(secret) {
		t.Errorf("secret_hash = %q, want hash of the spooled secret", rec.SecretHash)
	}

	body, err := os.ReadFile(trailPath)
	if err != nil {
		t.Fatalf("read trail file: %v", err)
	}
	if strings.Contains(string(body), secret) {
		t.Fatalf("audit trail file leaked the raw secret: %s", body)
	}
}

// TestScan_RevokeOnVerified_AuditTrailFile is the end-to-end
// `scan --revoke-on-verified --audit-trail <path>` check: --revoke-
// dry-run keeps it network-free while still exercising the same flag
// plumbing a live run would use.
func TestScan_RevokeOnVerified_AuditTrailFile(t *testing.T) {
	resetCommandFlags(t)
	t.Setenv(EnvAllowRevoke, "1")

	dir := t.TempDir()
	target := dir + "/leak.txt"
	if err := writeFile(target, "no secrets here\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	trailPath := filepath.Join(dir, "trail.jsonl")

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{
		"scan", "--revoke-on-verified", "--revoke-dry-run",
		"--audit-trail", trailPath, "--format", "json", "filesystem", target,
	})

	if err := Root.Execute(); err != nil {
		t.Fatalf("scan failed: %v\nstderr:\n%s", err, errBuf.String())
	}
	// No secrets in the fixture means no revoke attempt and therefore
	// no trail line — openAuditTrail must still have created/opened
	// the file cleanly (a missing-file error here would mean the flag
	// is wired but broken).
	if _, err := os.Stat(trailPath); err != nil {
		t.Errorf("--audit-trail file must exist after a scan even with 0 findings: %v", err)
	}
}

// readSoleAuditRecordFile reads path and decodes exactly one JSON
// Lines audit.Record, failing the test otherwise.
func readSoleAuditRecordFile(t *testing.T, path string) audit.Record {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit trail %q: %v", path, err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("expected exactly one audit trail line in %q, got %d: %q", path, len(lines), string(b))
	}
	var rec audit.Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("decode audit record: %v\nline: %s", err, lines[0])
	}
	return rec
}

// findAuditRecordLine scans a mixed human+JSON stderr blob line by line
// for the one that decodes as an audit.Record with a non-empty
// schema_version, returning it and whether one was found.
func findAuditRecordLine(t *testing.T, blob string) (audit.Record, bool) {
	t.Helper()
	for _, line := range strings.Split(blob, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var rec audit.Record
		if err := json.Unmarshal([]byte(line), &rec); err == nil && rec.SchemaVersion != "" {
			return rec, true
		}
	}
	return audit.Record{}, false
}
