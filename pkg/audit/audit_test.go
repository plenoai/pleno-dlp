package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)

func TestNew_RedactsSecret(t *testing.T) {
	tests := []struct {
		name   string
		secret string
	}{
		{name: "github_pat", secret: "ghp_0123456789abcdefghijklmnopqrstuvwxyz"},
		{name: "empty", secret: ""},
		{name: "short", secret: "ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := New(Attempt{
				Path:     PathSingle,
				Detector: "GitHub",
				Secret:   tt.secret,
				Redacted: "ghp_0123...",
				Now:      fixedNow,
			})

			b, err := json.Marshal(rec)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if tt.secret != "" && strings.Contains(string(b), tt.secret) {
				t.Fatalf("Record JSON leaked the raw secret: %s", b)
			}
			if tt.secret != "" && rec.SecretHash == tt.secret {
				t.Fatalf("SecretHash equals the raw secret (not hashed): %q", rec.SecretHash)
			}
			wantHash := HashSecret(tt.secret)
			if rec.SecretHash != wantHash {
				t.Errorf("SecretHash = %q, want %q", rec.SecretHash, wantHash)
			}
		})
	}
}

func TestNew_SchemaVersionEmbedded(t *testing.T) {
	rec := New(Attempt{Path: PathOnVerified, Detector: "Slack", Secret: "xoxb-x", Now: fixedNow})
	if rec.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", rec.SchemaVersion, SchemaVersion)
	}
	if rec.SchemaVersion != "1" {
		t.Errorf("SchemaVersion = %q, want literal %q (docs/audit-trail-schema.md pins v1)", rec.SchemaVersion, "1")
	}
}

func TestNew_FieldMapping(t *testing.T) {
	revokedAt := fixedNow.Add(2 * time.Second)
	rec := New(Attempt{
		Path:       PathSpool,
		Detector:   "Stripe",
		Secret:     "rk_live_abc",
		Redacted:   "rk_live_...",
		Revoked:    true,
		RevokedAt:  revokedAt,
		ProviderID: "rk_live_abc1",
		DryRun:     false,
		TargetLink: "https://github.com/acme/repo/blob/main/leak.env",
		Now:        fixedNow,
	})

	if rec.Path != string(PathSpool) {
		t.Errorf("Path = %q, want %q", rec.Path, PathSpool)
	}
	if rec.Detector != "Stripe" {
		t.Errorf("Detector = %q, want %q", rec.Detector, "Stripe")
	}
	if rec.Redacted != "rk_live_..." {
		t.Errorf("Redacted = %q", rec.Redacted)
	}
	if !rec.Revoked {
		t.Error("Revoked = false, want true")
	}
	if rec.RevokedAt != revokedAt.UTC().Format(time.RFC3339) {
		t.Errorf("RevokedAt = %q, want %q", rec.RevokedAt, revokedAt.UTC().Format(time.RFC3339))
	}
	if rec.ProviderID != "rk_live_abc1" {
		t.Errorf("ProviderID = %q", rec.ProviderID)
	}
	if rec.TargetLink != "https://github.com/acme/repo/blob/main/leak.env" {
		t.Errorf("TargetLink = %q", rec.TargetLink)
	}
	if rec.Timestamp != fixedNow.UTC().Format(time.RFC3339) {
		t.Errorf("Timestamp = %q, want %q", rec.Timestamp, fixedNow.UTC().Format(time.RFC3339))
	}
}

func TestNew_ErrorCarriesMessage(t *testing.T) {
	rec := New(Attempt{
		Path:     PathOnVerified,
		Detector: "AWS",
		Secret:   "AKIAEXAMPLE",
		Err:      errString("provider declined revocation"),
		Now:      fixedNow,
	})
	if rec.Error != "provider declined revocation" {
		t.Errorf("Error = %q, want %q", rec.Error, "provider declined revocation")
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestNewTrailID_Deterministic(t *testing.T) {
	hash := HashSecret("ghp_same_secret")
	id1 := NewTrailID("GitHub", hash, fixedNow)
	id2 := NewTrailID("GitHub", hash, fixedNow)
	if id1 != id2 {
		t.Errorf("NewTrailID not deterministic: %q != %q", id1, id2)
	}
	if id1 == "" {
		t.Error("NewTrailID returned empty string")
	}

	// Different detector, same everything else -> different id.
	id3 := NewTrailID("GitLab", hash, fixedNow)
	if id3 == id1 {
		t.Error("NewTrailID collided across different detectors")
	}

	// Different timestamp -> different id.
	id4 := NewTrailID("GitHub", hash, fixedNow.Add(time.Nanosecond))
	if id4 == id1 {
		t.Error("NewTrailID collided across different timestamps")
	}
}

func TestHashSecret_StableAndNonReversible(t *testing.T) {
	h1 := HashSecret("ghp_abc123")
	h2 := HashSecret("ghp_abc123")
	if h1 != h2 {
		t.Errorf("HashSecret not stable: %q != %q", h1, h2)
	}
	if strings.Contains(h1, "ghp_abc123") {
		t.Errorf("HashSecret output contains the raw secret: %q", h1)
	}
	if len(h1) != 64 { // sha256 hex = 32 bytes = 64 hex chars
		t.Errorf("HashSecret length = %d, want 64 (sha256 hex)", len(h1))
	}
	if HashSecret("") != "" {
		t.Errorf("HashSecret(\"\") = %q, want empty", HashSecret(""))
	}
}

func TestRecord_ToSARIFProperties_MatchesJSONLShape(t *testing.T) {
	rec := New(Attempt{
		Path:       PathOnVerified,
		Detector:   "GitHub",
		Secret:     "ghp_leaked",
		Redacted:   "ghp_leake...",
		Revoked:    true,
		ProviderID: "abc123",
		Now:        fixedNow,
	})

	jsonlLine, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	var wantMap map[string]any
	if err := json.Unmarshal(jsonlLine, &wantMap); err != nil {
		t.Fatalf("unmarshal expected map: %v", err)
	}

	got := rec.ToSARIFProperties()

	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(wantMap)
	if !bytes.Equal(normalizeJSON(t, gotJSON), normalizeJSON(t, wantJSON)) {
		t.Errorf("ToSARIFProperties() shape drifted from the JSON Lines encoding:\ngot:  %s\nwant: %s", gotJSON, wantJSON)
	}

	if got["schema_version"] != SchemaVersion {
		t.Errorf(`ToSARIFProperties()["schema_version"] = %v, want %q`, got["schema_version"], SchemaVersion)
	}
	if got["trail_id"] != rec.TrailID {
		t.Errorf(`ToSARIFProperties()["trail_id"] = %v, want %q`, got["trail_id"], rec.TrailID)
	}
}

// normalizeJSON re-marshals through a map so key ordering differences
// (Go map iteration is randomized) don't cause a false mismatch.
func normalizeJSON(t *testing.T, b []byte) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("normalizeJSON: %v", err)
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("normalizeJSON: remarshal: %v", err)
	}
	return out
}

func TestWriter_AppendsJSONLines(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	rec1 := New(Attempt{Path: PathSingle, Detector: "GitHub", Secret: "s1", Now: fixedNow})
	rec2 := New(Attempt{Path: PathSpool, Detector: "Slack", Secret: "s2", Now: fixedNow})

	if err := w.Write(rec1); err != nil {
		t.Fatalf("Write rec1: %v", err)
	}
	if err := w.Write(rec2); err != nil {
		t.Fatalf("Write rec2: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSON lines, got %d: %q", len(lines), buf.String())
	}
	var got1, got2 Record
	if err := json.Unmarshal([]byte(lines[0]), &got1); err != nil {
		t.Fatalf("decode line 1: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &got2); err != nil {
		t.Fatalf("decode line 2: %v", err)
	}
	if got1.Detector != "GitHub" || got2.Detector != "Slack" {
		t.Errorf("decoded records out of order or corrupted: %+v / %+v", got1, got2)
	}
	if got1.SchemaVersion != "1" || got2.SchemaVersion != "1" {
		t.Errorf("decoded records missing schema_version=1: %+v / %+v", got1, got2)
	}
}

// TestWriter_ConcurrentWritesDoNotInterleave asserts Writer's own mutex
// (not the caller's discipline) is what keeps concurrent Encode calls
// from interleaving mid-line onto a plain, non-thread-safe bytes.Buffer.
// scan.go's --revoke-on-verified path dispatches from engine worker
// goroutines, so this guarantee has to live in Writer itself.
func TestWriter_ConcurrentWritesDoNotInterleave(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = w.Write(New(Attempt{Path: PathOnVerified, Detector: "GitHub", Secret: "s", Now: fixedNow}))
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("expected %d lines, got %d", n, len(lines))
	}
	for i, line := range lines {
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d not valid JSON (interleaved write?): %q: %v", i, line, err)
		}
	}
}
