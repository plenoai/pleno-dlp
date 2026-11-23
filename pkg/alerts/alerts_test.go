package alerts

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// Split so the pre-commit secret scan does not flag the fixture.
var secret = "AKIA" + "IOSFODNN7SECRETX"

type nopSink struct{ n int }

func (s *nopSink) Emit(engine.Finding) { s.n++ }
func (s *nopSink) Close() error        { return nil }

func finding(sev detectors.Severity) engine.Finding {
	return engine.Finding{
		Detector: detectors.AWS,
		Result:   detectors.Result{Raw: []byte(secret), Severity: sev, Redacted: "AKIA…"},
		Chunk:    &sources.Chunk{SourceMetadata: sources.Metadata{Filesystem: &sources.FilesystemMeta{Path: "a.env", Line: 3}}},
	}
}

func TestInferFormat(t *testing.T) {
	for raw, want := range map[string]Format{
		"https://hooks.slack.com/services/T/B/X":            FormatSlack,
		"https://acme.webhook.office.com/webhookb2/x":       FormatTeams,
		"https://prod-1.westus.logic.azure.com/workflows/x": FormatTeams,
		"https://siem.example.com/ingest":                   FormatGeneric,
		"https://slack.com.evil.example/services/T":         FormatGeneric,
	} {
		w, err := ParseWebhook(raw)
		if err != nil || w.Format != want {
			t.Errorf("%s: format=%v err=%v, want %v", raw, w.Format, err, want)
		}
	}
}

func TestParseWebhookRejectsPlainHTTPAndRedacts(t *testing.T) {
	_, err := ParseWebhook("http://hooks.example.com/services/TOKEN123")
	if err == nil || strings.Contains(err.Error(), "TOKEN123") {
		t.Fatalf("err=%v, want https error without token", err)
	}
	if _, err := ParseWebhook("http://127.0.0.1:1/x"); err != nil {
		t.Fatalf("loopback http rejected: %v", err)
	}
}

func TestCollectorFiltersBySeverityAndForwardsAll(t *testing.T) {
	inner := &nopSink{}
	c := &Collector{Inner: inner, MinSeverity: detectors.SeverityHigh}
	c.Emit(finding(detectors.SeverityLow))
	c.Emit(finding(detectors.SeverityCritical))
	if inner.n != 2 {
		t.Fatalf("forwarded %d, want 2", inner.n)
	}
	fs := c.Findings()
	if len(fs) != 1 || fs[0].Severity != "critical" || fs[0].Location == "" {
		t.Fatalf("findings=%+v", fs)
	}
}

func TestPayloadsNeverContainRawSecret(t *testing.T) {
	c := &Collector{Inner: &nopSink{}}
	c.Emit(finding(detectors.SeverityHigh))
	s := BuildSummary("v1", "filesystem", 0, c.Findings())
	for _, f := range []Format{FormatSlack, FormatTeams, FormatGeneric} {
		b, err := Payload(f, s)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), secret) {
			t.Fatalf("%s payload leaks secret: %s", f, b)
		}
		if !json.Valid(b) {
			t.Fatalf("%s payload invalid JSON", f)
		}
	}
}

func TestSendRetriesOn5xxThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		got, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/hook")
	n := &Notifier{Webhooks: []Webhook{{URL: u, Format: FormatGeneric}}, Retries: 2, Backoff: time.Millisecond}
	if err := n.Send(context.Background(), BuildSummary("v", "fs", 0, []Finding{{Detector: "AWS", Severity: "high"}})); err != nil {
		t.Fatal(err)
	}
	var s Summary
	if calls.Load() != 3 || json.Unmarshal(got, &s) != nil || s.Total != 1 {
		t.Fatalf("calls=%d body=%s", calls.Load(), got)
	}
}

func TestSendNoRetryOn4xxAndRedactsURL(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/services/TOKEN123")
	n := &Notifier{Webhooks: []Webhook{{URL: u}}, Retries: 3, Backoff: time.Millisecond}
	err := n.Send(context.Background(), BuildSummary("v", "fs", 0, nil))
	if err == nil || strings.Contains(err.Error(), "TOKEN123") || calls.Load() != 1 {
		t.Fatalf("err=%v calls=%d", err, calls.Load())
	}
}

func TestSendDoesNotFollowRedirects(t *testing.T) {
	var hit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) }))
	defer target.Close()
	srv := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusTemporaryRedirect))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	n := &Notifier{Webhooks: []Webhook{{URL: u}}}
	if err := n.Send(context.Background(), BuildSummary("v", "fs", 0, nil)); err == nil || hit.Load() {
		t.Fatalf("err=%v redirected=%v", err, hit.Load())
	}
}

func TestDryRunDoesNotPost(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/services/TOKEN123")
	var log strings.Builder
	n := &Notifier{Webhooks: []Webhook{{URL: u, Format: FormatSlack}}, DryRun: true, Log: &log}
	if err := n.Send(context.Background(), BuildSummary("v", "fs", 0, []Finding{{Severity: "high"}})); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || !strings.Contains(log.String(), "alert dry-run") || strings.Contains(log.String(), "TOKEN123") {
		t.Fatalf("calls=%d log=%s", calls.Load(), log.String())
	}
}
