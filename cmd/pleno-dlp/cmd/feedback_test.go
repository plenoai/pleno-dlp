package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
	"github.com/plenoai/pleno-dlp/pkg/telemetry/feedback"
)

// isolateFeedback points the feedback command at a temp config dir and env.
func isolateFeedback(t *testing.T, env map[string]string) string {
	t.Helper()
	resetCommandFlags(t)
	dir := t.TempDir()
	env[crash.EnvDir] = dir
	prev := feedbackGetenv
	feedbackGetenv = func(k string) string { return env[k] }
	t.Cleanup(func() {
		feedbackGetenv = prev
		feedbackCmd.SetIn(os.Stdin)
	})
	return dir
}

// swapTTY makes the confirmation prompt read answer from f.
func swapTTY(t *testing.T, f *os.File) {
	t.Helper()
	prev := feedbackOpenTTY
	feedbackOpenTTY = func() (*os.File, error) { return f, nil }
	t.Cleanup(func() { feedbackOpenTTY = prev })
}

// ttyFile returns an open file whose contents are answer, positioned at 0.
func ttyFile(t *testing.T, answer string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "tty")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(answer); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func feedbackRelay(t *testing.T) (*httptest.Server, func() []feedback.Report) {
	srv, reports, _ := feedbackRelayWithWire(t)
	return srv, reports
}

func feedbackRelayWithWire(t *testing.T) (*httptest.Server, func() []feedback.Report, func() [][]byte) {
	t.Helper()
	var mu sync.Mutex
	var bodies []feedback.Report
	var wire [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var rep feedback.Report
		_ = json.Unmarshal(b, &rep)
		mu.Lock()
		bodies = append(bodies, rep)
		wire = append(wire, append([]byte(nil), b...))
		mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return srv, func() []feedback.Report {
			mu.Lock()
			defer mu.Unlock()
			return append([]feedback.Report(nil), bodies...)
		}, func() [][]byte {
			mu.Lock()
			defer mu.Unlock()
			out := make([][]byte, len(wire))
			for i, b := range wire {
				out[i] = append([]byte(nil), b...)
			}
			return out
		}
}

func TestFeedbackSendsAndSpools(t *testing.T) {
	srv, got := feedbackRelay(t)
	dir := isolateFeedback(t, map[string]string{feedback.EnvEndpoint: srv.URL})

	out, err := runRoot(t, "feedback", "--yes", "hello", "world")
	if err != nil || !strings.Contains(out, "sent feedback report") {
		t.Fatalf("feedback: %v\n%s", err, out)
	}
	if bodies := got(); len(bodies) != 1 || bodies[0].Message != "hello world" {
		t.Fatalf("relay got %+v", bodies)
	}
	sp, _, err := feedback.ReadReport(filepath.Join(dir, "feedback", feedback.LastFile))
	if err != nil || sp.Message != "hello world" || sp.Schema != feedback.Schema {
		t.Fatalf("spooled copy = %+v, %v", sp, err)
	}
}

func TestFeedbackStdinPromptsOnTTY(t *testing.T) {
	srv, got := feedbackRelay(t)
	isolateFeedback(t, map[string]string{feedback.EnvEndpoint: srv.URL})
	swapTTY(t, ttyFile(t, "y\n"))
	feedbackCmd.SetIn(strings.NewReader("piped feedback\n"))

	out, err := runRoot(t, "feedback", "--stdin")
	if err != nil || !strings.Contains(out, "sent feedback report") {
		t.Fatalf("feedback --stdin: %v\n%s", err, out)
	}
	if bodies := got(); len(bodies) != 1 || bodies[0].Message != "piped feedback" {
		t.Fatalf("relay got %+v", bodies)
	}
}

func TestFeedbackDeclinedKeepsSpool(t *testing.T) {
	srv, got := feedbackRelay(t)
	dir := isolateFeedback(t, map[string]string{feedback.EnvEndpoint: srv.URL})
	swapTTY(t, ttyFile(t, "n\n"))

	out, err := runRoot(t, "feedback", "do not send this")
	if err != nil || !strings.Contains(out, "not sent") {
		t.Fatalf("decline: %v\n%s", err, out)
	}
	if bodies := got(); len(bodies) != 0 {
		t.Fatalf("declined feedback was sent: %+v", bodies)
	}
	if _, _, err := feedback.ReadReport(filepath.Join(dir, "feedback", feedback.LastFile)); err != nil {
		t.Fatalf("declined report not spooled: %v", err)
	}
}

func TestFeedbackStdinWithoutTTYRequiresYes(t *testing.T) {
	isolateFeedback(t, map[string]string{})
	prev := feedbackOpenTTY
	feedbackOpenTTY = func() (*os.File, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { feedbackOpenTTY = prev })
	feedbackCmd.SetIn(strings.NewReader("piped feedback\n"))

	if _, err := runRoot(t, "feedback", "--stdin"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("expected a --yes hint, got %v", err)
	}
}

func TestFeedbackRedactsSecrets(t *testing.T) {
	srv, got := feedbackRelay(t)
	isolateFeedback(t, map[string]string{feedback.EnvEndpoint: srv.URL})

	if _, err := runRoot(t, "feedback", "--yes", "mail alice@example.com from 10.1.2.3"); err != nil {
		t.Fatal(err)
	}
	bodies := got()
	if len(bodies) != 1 {
		t.Fatalf("relay got %+v", bodies)
	}
	if strings.Contains(bodies[0].Message, "alice@") || strings.Contains(bodies[0].Message, "10.1.2.3") {
		t.Fatalf("PII left the machine: %q", bodies[0].Message)
	}
}

func TestFeedbackPIIRedactionFailureDoesNotSendOrSpool(t *testing.T) {
	srv, got := feedbackRelay(t)
	dir := isolateFeedback(t, map[string]string{feedback.EnvEndpoint: srv.URL})
	prev := feedbackPIISelector
	feedbackPIISelector = func(context.Context) (feedbackPIISelection, error) {
		return feedbackPIISelection{Detector: failingFeedbackPII{}}, nil
	}
	t.Cleanup(func() { feedbackPIISelector = prev })

	const privateText = "Mina Example"
	out, err := runRoot(t, "feedback", "--yes", "message for "+privateText)
	if err == nil || !strings.Contains(err.Error(), "PII redaction failed") {
		t.Fatalf("PII failure = %v, want closed feedback error\n%s", err, out)
	}
	if strings.Contains(err.Error(), privateText) || strings.Contains(out, privateText) {
		t.Fatalf("PII failure exposed input: err=%v output=%q", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "feedback")); !os.IsNotExist(err) {
		t.Fatalf("failed PII redaction left a spool directory: %v", err)
	}
	if reports := got(); len(reports) != 0 {
		t.Fatalf("failed PII redaction reached relay: %+v", reports)
	}
}

func TestFeedbackPIIRedactionRejectsResultAfterAcceptanceDeadline(t *testing.T) {
	const privateText = "Mina Example"
	detector := delayedFeedbackPII{match: privateText}
	got, err := redactFeedbackValueWithin(context.Background(), &crash.Redactor{}, detector, "message for "+privateText, 10*time.Millisecond)
	if got != "" || err == nil {
		t.Fatalf("late result = %q, %v; want closed rejection", got, err)
	}
	if strings.Contains(got, privateText) || strings.Contains(err.Error(), privateText) {
		t.Fatalf("late result rejection exposed input: got=%q err=%v", got, err)
	}
}

func TestFeedbackPIIStartupFailureDoesNotSendOrSpool(t *testing.T) {
	srv, got := feedbackRelay(t)
	dir := isolateFeedback(t, map[string]string{feedback.EnvEndpoint: srv.URL})
	prev := feedbackPIISelector
	feedbackPIISelector = func(context.Context) (feedbackPIISelection, error) {
		return feedbackPIISelection{}, errFeedbackPIIUnavailable
	}
	t.Cleanup(func() { feedbackPIISelector = prev })

	out, err := runRoot(t, "feedback", "--pii-engine", "anonymize", "--yes", "message with private text")
	if !errors.Is(err, errFeedbackPIIUnavailable) {
		t.Fatalf("PII startup failure = %v, want selected-engine error\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "feedback")); !os.IsNotExist(err) {
		t.Fatalf("failed PII startup left a spool directory: %v", err)
	}
	if reports := got(); len(reports) != 0 {
		t.Fatalf("failed PII startup reached relay: %+v", reports)
	}
}

func TestFeedbackPIIRedactsMessageAndSelectedMatchDisplay(t *testing.T) {
	srv, got := feedbackRelay(t)
	isolateFeedback(t, map[string]string{feedback.EnvEndpoint: srv.URL})
	path := filepath.Join(t.TempDir(), "config.env")
	const raw = fixtureAWSKey
	if err := os.WriteFile(path, []byte("AWS_ACCESS_KEY_ID="+raw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	pii := &recordingFeedbackPII{needle: "Mina"}
	prev := feedbackPIISelector
	feedbackPIISelector = func(context.Context) (feedbackPIISelection, error) {
		return feedbackPIISelection{Detector: pii, Engine: "anonymize"}, nil
	}
	t.Cleanup(func() { feedbackPIISelector = prev })

	out, err := runRoot(t, "feedback", "--yes", "--kind", "false-positive", "--scan-file", path,
		"--detector", "AWS", "--finding-hash", hash, "Mina reported a match")
	if err != nil {
		t.Fatalf("feedback with PII engine: %v\n%s", err, out)
	}
	if len(pii.seen) != 2 || !strings.Contains(pii.seen[0], "Mina") || pii.seen[1] == pii.seen[0] {
		t.Fatalf("PII engine inputs = %#v, want message and selected match display", pii.seen)
	}
	if strings.Contains(pii.seen[1], raw) {
		t.Fatalf("PII engine received raw selected secret in match display: %q", pii.seen[1])
	}
	reports := got()
	if len(reports) != 1 || reports[0].Match == nil || reports[0].Schema != feedback.SchemaV2 {
		t.Fatalf("relay got %+v", reports)
	}
	if !strings.Contains(reports[0].Message, "[PII]") {
		t.Fatalf("message did not use PII redaction: %q", reports[0].Message)
	}
	if strings.Contains(reports[0].Match.Redacted, raw) || strings.Contains(reports[0].Message, "Mina") {
		t.Fatalf("report retained sensitive text: %+v", reports[0])
	}
}

func TestFeedbackFalsePositiveSelectsAndPreviewsOnlySafeFindingFields(t *testing.T) {
	srv, got, wire := feedbackRelayWithWire(t)
	dir := isolateFeedback(t, map[string]string{feedback.EnvEndpoint: srv.URL})
	firstRaw := "AKIA1234567890ABCDEF"
	selectedRaw := "AKIA9876543210ZYXWVU"
	sum := sha256.Sum256([]byte(selectedRaw))
	selectedHash := hex.EncodeToString(sum[:])
	scanPath := filepath.Join(t.TempDir(), "config.env")
	if err := os.WriteFile(scanPath, []byte("FIRST="+firstRaw+"\nSECOND="+selectedRaw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	swapTTY(t, ttyFile(t, "yes\n"))
	preview, err := runRoot(t, "feedback", "--kind", "false-positive", "--scan-file", scanPath, "--detector", "AWS", "--finding-hash", selectedHash, "false positive in fixture")
	if err != nil {
		t.Fatalf("feedback false-positive: %v\n%s", err, preview)
	}
	if !strings.Contains(preview, selectedHash) || !strings.Contains(preview, "detector: AWS") {
		t.Fatalf("confirmation omitted the selected redacted match/hash:\n%s", preview)
	}
	if strings.Contains(preview, firstRaw) || strings.Contains(preview, selectedRaw) || strings.Contains(preview, scanPath) {
		t.Fatalf("confirmation included raw match or source path:\n%s", preview)
	}
	bodies := got()
	if len(bodies) != 1 || bodies[0].Match == nil {
		t.Fatalf("relay got %+v", bodies)
	}
	if bodies[0].Schema != feedback.SchemaV2 || bodies[0].Match.Detector != "AWS" || bodies[0].Match.RawHash != selectedHash {
		t.Fatalf("relay got %+v", bodies[0])
	}
	if strings.Contains(bodies[0].Match.Redacted, firstRaw) || strings.Contains(bodies[0].Match.Redacted, selectedRaw) {
		t.Fatalf("report match contains raw bytes: %+v", bodies[0].Match)
	}
	if gotWire := wire(); len(gotWire) != 1 || strings.Contains(string(gotWire[0]), firstRaw) || strings.Contains(string(gotWire[0]), selectedRaw) || strings.Contains(string(gotWire[0]), scanPath) {
		t.Fatalf("wire payload contains raw match or source path: %q", gotWire)
	}
	b, err := os.ReadFile(filepath.Join(dir, "feedback", feedback.LastFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), firstRaw) || strings.Contains(string(b), selectedRaw) || strings.Contains(string(b), `"raw"`) || strings.Contains(string(b), scanPath) {
		t.Fatalf("spool contains raw match material: %s", b)
	}
	spooled, _, err := feedback.ReadReport(filepath.Join(dir, "feedback", feedback.LastFile))
	if err != nil || spooled.Schema != feedback.SchemaV2 || spooled.Match == nil || spooled.Match.RawHash != selectedHash {
		t.Fatalf("v2 spool report = %+v, err=%v", spooled, err)
	}
}

func TestFeedbackFalsePositiveRequiresOneSelectedMatch(t *testing.T) {
	srv, got := feedbackRelay(t)
	isolateFeedback(t, map[string]string{feedback.EnvEndpoint: srv.URL})
	path := filepath.Join(t.TempDir(), "config.env")
	raw := "AKIA1234567890ABCDEF"
	if err := os.WriteFile(path, []byte("AWS_ACCESS_KEY_ID="+raw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runRoot(t, "feedback", "--kind", "false-positive", "--scan-file", path, "--detector", "AWS", "reason"); err == nil {
		t.Fatal("missing explicit finding hash was accepted")
	}
	sum := sha256.Sum256([]byte(raw))
	if _, err := runRoot(t, "feedback", "--kind", "false-positive", "--scan-file", path, "--detector", "Stripe", "--finding-hash", hex.EncodeToString(sum[:]), "reason"); err == nil {
		t.Fatal("an absent detector match was accepted")
	}
	if bodies := got(); len(bodies) != 0 {
		t.Fatalf("invalid selection reached relay: %+v", bodies)
	}
}

func TestFeedbackThrottledPreservesLocalCopy(t *testing.T) {
	srv, reports := feedbackRelay(t)
	dir := isolateFeedback(t, map[string]string{feedback.EnvEndpoint: srv.URL})
	for i := 0; i < crash.FeedbackSendLimit; i++ {
		if _, err := runRoot(t, "feedback", "--yes", "message"); err != nil {
			t.Fatal(err)
		}
	}
	_, err := runRoot(t, "feedback", "--yes", "over limit")
	if err == nil || !strings.Contains(err.Error(), "local copy saved") {
		t.Fatalf("expected throttled, spooled feedback, got %v", err)
	}
	if got := len(reports()); got != crash.FeedbackSendLimit {
		t.Fatalf("uploads = %d, want %d", got, crash.FeedbackSendLimit)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "feedback", "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("feedback spool missing: %v %v", paths, err)
	}
}

func TestFeedbackIgnoresCrashSettings(t *testing.T) {
	for _, setting := range []string{"0", "1", "invalid"} {
		t.Run(setting, func(t *testing.T) {
			srv, reports := feedbackRelay(t)
			isolateFeedback(t, map[string]string{
				feedback.EnvEndpoint: srv.URL,
				crash.EnvReports:     setting,
				crash.EnvEndpoint:    "invalid crash endpoint",
			})
			if _, err := runRoot(t, "feedback", "--yes", "hello"); err != nil {
				t.Fatal(err)
			}
			if len(reports()) != 1 {
				t.Fatal("explicit feedback was not uploaded")
			}
		})
	}
}

func TestFeedbackImplicitStdin(t *testing.T) {
	srv, reports := feedbackRelay(t)
	isolateFeedback(t, map[string]string{feedback.EnvEndpoint: srv.URL})
	feedbackCmd.SetIn(strings.NewReader("from stdin\n"))
	if _, err := runRoot(t, "feedback", "-y"); err != nil {
		t.Fatal(err)
	}
	if got := reports(); len(got) != 1 || got[0].Message != "from stdin" {
		t.Fatalf("reports = %+v", got)
	}
}

type failingFeedbackPII struct{}

func (failingFeedbackPII) Keywords() []string           { return nil }
func (failingFeedbackPII) Type() detectors.DetectorType { return detectors.PIIAnonymize }
func (failingFeedbackPII) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	return nil, errors.New("engine failed for " + string(data))
}

type recordingFeedbackPII struct {
	needle string
	seen   []string
}

type delayedFeedbackPII struct{ match string }

func (d delayedFeedbackPII) Keywords() []string           { return nil }
func (d delayedFeedbackPII) Type() detectors.DetectorType { return detectors.PIIAnonymize }
func (d delayedFeedbackPII) FromData(ctx context.Context, _ bool, _ []byte) ([]detectors.Result, error) {
	<-ctx.Done()
	return []detectors.Result{{DetectorType: detectors.PIIAnonymize, Raw: []byte(d.match)}}, nil
}

func (d *recordingFeedbackPII) Keywords() []string           { return nil }
func (d *recordingFeedbackPII) Type() detectors.DetectorType { return detectors.PIIAnonymize }
func (d *recordingFeedbackPII) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	text := string(data)
	d.seen = append(d.seen, text)
	if !strings.Contains(text, d.needle) {
		return nil, nil
	}
	return []detectors.Result{{DetectorType: detectors.PIIAnonymize, Raw: []byte(d.needle)}}, nil
}
