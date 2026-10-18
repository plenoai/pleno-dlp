package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/telemetry/report"
)

// isolateFeedback isolates telemetry state, pins the terminal check, and
// points the endpoint at srv (or an unroutable loopback when srv is nil).
func isolateFeedback(t *testing.T, srv *httptest.Server, interactive bool, stdin string) string {
	t.Helper()
	endpoint := "http://127.0.0.1:1/unused"
	if srv != nil {
		endpoint = srv.URL
	}
	dir := isolateTelemetry(t, map[string]string{report.EnvEndpoint: endpoint})
	prevTTY := feedbackInteractive
	feedbackInteractive = func(io.Reader) bool { return interactive }
	Root.SetIn(strings.NewReader(stdin))
	t.Cleanup(func() {
		feedbackInteractive = prevTTY
		Root.SetIn(nil)
	})
	return dir
}

// countingRelay records how many reports reached it and replies with body.
func countingRelay(t *testing.T, status int, body string) (*httptest.Server, *atomic.Int32, *report.Report) {
	t.Helper()
	var n atomic.Int32
	got := &report.Report{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, got)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &n, got
}

func TestFeedbackDryRunShape(t *testing.T) {
	srv, n, _ := countingRelay(t, http.StatusOK, "")
	isolateFeedback(t, srv, false, "")
	out, err := runRoot(t, "feedback", "--dry-run", "scan of /etc/app hung; ping alice@example.com")
	if err != nil {
		t.Fatalf("dry-run: %v\n%s", err, out)
	}
	if n.Load() != 0 {
		t.Fatal("dry-run reached the relay")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("dry-run output is not one JSON report: %v\n%s", err, out)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := "command commit crash_kind created_at detector fingerprint flags go_version goarch goos kind message schema stack version"
	if strings.Join(keys, " ") != want {
		t.Fatalf("keys = %v", keys)
	}
	if m["schema"] != report.Schema || m["kind"] != "feedback" || m["command"] != "feedback" ||
		m["crash_kind"] != "" || m["fingerprint"] != "" || m["stack"] != "" || m["detector"] != "" {
		t.Fatalf("report = %v", m)
	}
	if msg := m["message"].(string); msg != "scan of [PATH] hung; ping [EMAIL]" {
		t.Fatalf("message not redacted: %q", msg)
	}
	if flags, _ := json.Marshal(m["flags"]); string(flags) != `["dry-run"]` {
		t.Fatalf("flags = %s", flags)
	}
}

func TestFeedbackFalsePositiveRequiresKnownDetector(t *testing.T) {
	isolateFeedback(t, nil, false, "")
	if _, err := runRoot(t, "feedback", "--kind", "false-positive", "--dry-run", "x"); err == nil ||
		!strings.Contains(err.Error(), "requires --detector") {
		t.Fatalf("missing detector err = %v", err)
	}
	if _, err := runRoot(t, "feedback", "--kind", "false-positive", "--detector", "NoSuchDetector", "--dry-run", "x"); err == nil ||
		!strings.Contains(err.Error(), "not a registered detector type") {
		t.Fatalf("unknown detector err = %v", err)
	}
	if _, err := runRoot(t, "feedback", "--detector", "AWS", "--dry-run", "x"); err == nil {
		t.Fatal("--detector accepted for plain feedback")
	}
	out, err := runRoot(t, "feedback", "--kind", "false-positive", "--detector", "AWS", "--dry-run", "example key in docs")
	if err != nil || !strings.Contains(out, `"detector": "AWS"`) || !strings.Contains(out, `"kind": "false-positive"`) {
		t.Fatalf("known detector: %v\n%s", err, out)
	}
}

func TestFeedbackNonTTYWithoutYesRefuses(t *testing.T) {
	srv, n, _ := countingRelay(t, http.StatusOK, "")
	isolateFeedback(t, srv, false, "")
	_, err := runRoot(t, "feedback", "hello")
	if err == nil || !strings.Contains(err.Error(), "stdin is not a terminal") || n.Load() != 0 {
		t.Fatalf("err = %v, relay hits = %d", err, n.Load())
	}
	if _, err := runRoot(t, "feedback", "--stdin"); err == nil || !strings.Contains(err.Error(), "re-run with --yes") {
		t.Fatalf("--stdin without --yes err = %v", err)
	}
}

func TestFeedbackPromptDeclineAndAccept(t *testing.T) {
	srv, n, _ := countingRelay(t, http.StatusOK, "")
	isolateFeedback(t, srv, true, "n\n")
	out, err := runRoot(t, "feedback", "hello")
	if err != nil || !strings.Contains(out, "Send this anonymized report? [y/N] ") || !strings.Contains(out, "not sent") || n.Load() != 0 {
		t.Fatalf("decline: %v hits=%d\n%s", err, n.Load(), out)
	}
	Root.SetIn(strings.NewReader("y\n"))
	if out, err := runRoot(t, "feedback", "hello"); err != nil || n.Load() != 1 {
		t.Fatalf("accept: %v hits=%d\n%s", err, n.Load(), out)
	}
}

func TestFeedbackSendPrintsIssueURL(t *testing.T) {
	const issue = "https://github.com/plenoai/pleno-dlp-intake/issues/42"
	srv, _, got := countingRelay(t, http.StatusCreated, `{"issue":"`+issue+`"}`)
	isolateFeedback(t, srv, false, "the table output wraps badly\n")
	out, err := runRoot(t, "feedback", "--stdin", "--yes")
	if err != nil {
		t.Fatalf("send: %v\n%s", err, out)
	}
	if !strings.Contains(out, "feedback report recorded as "+issue+" (private intake)") {
		t.Fatalf("issue URL not printed:\n%s", out)
	}
	if !strings.Contains(out, "pleno-dlp will send this anonymized report to "+srv.URL) {
		t.Fatalf("payload preview missing:\n%s", out)
	}
	if got.Message != "the table output wraps badly" || got.Kind != report.KindFeedback {
		t.Fatalf("relay got %+v", got)
	}
}

func TestFeedbackFailureSpools(t *testing.T) {
	srv, _, _ := countingRelay(t, http.StatusBadGateway, "")
	dir := isolateFeedback(t, srv, false, "")
	msgFile := filepath.Join(t.TempDir(), "msg.txt")
	if err := os.WriteFile(msgFile, []byte("feature request: html output\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runRoot(t, "feedback", "--file", msgFile, "--yes")
	if err == nil || !strings.Contains(err.Error(), "report not sent") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(out, "retry with: pleno-dlp telemetry send "+filepath.Join(dir, "reports", "feedback-")) {
		t.Fatalf("retry hint missing:\n%s", out)
	}
	r, _, err := report.ReadReport(filepath.Join(dir, "reports", report.LastFile))
	if err != nil || r.Message != "feature request: html output" {
		t.Fatalf("spooled %+v %v", r, err)
	}
}

func TestFeedbackRejectsEmptyAndAmbiguousInput(t *testing.T) {
	isolateFeedback(t, nil, false, "")
	if _, err := runRoot(t, "feedback", "--dry-run", "   "); err == nil || !strings.Contains(err.Error(), "empty after redaction") {
		t.Fatalf("blank message err = %v", err)
	}
	if _, err := runRoot(t, "feedback", "--dry-run"); err == nil || !strings.Contains(err.Error(), "exactly one way") {
		t.Fatalf("no message err = %v", err)
	}
	if _, err := runRoot(t, "feedback", "--dry-run", "--file", "x", "words"); err == nil || !strings.Contains(err.Error(), "exactly one way") {
		t.Fatalf("two sources err = %v", err)
	}
}
