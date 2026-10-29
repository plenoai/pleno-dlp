package feedback

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
)

func envFunc(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestBuildRedactsAndFingerprints(t *testing.T) {
	red := &crash.Redactor{}
	now := time.Unix(1_700_000_000, 0)
	r := Build("contact alice@example.com about the 10.1.2.3 host", crash.Meta{
		Version: "1.0.0", Command: "feedback",
	}, red, now)
	if strings.Contains(r.Message, "alice@") || strings.Contains(r.Message, "10.1.2.3") {
		t.Fatalf("PII survived redaction: %q", r.Message)
	}
	if !strings.Contains(r.Message, "[EMAIL]") || !strings.Contains(r.Message, "[IP]") {
		t.Fatalf("redaction placeholders missing: %q", r.Message)
	}
	if r.Schema != Schema || r.Version != "1.0.0" || r.Command != "feedback" {
		t.Fatalf("report = %+v", r)
	}
	if r.CreatedAt != now.UTC().Truncate(time.Minute) {
		t.Fatalf("created_at = %v", r.CreatedAt)
	}
	if r.Fingerprint == "" || r.Fingerprint == Build("other", crash.Meta{Command: "feedback"}, red, now).Fingerprint {
		t.Fatalf("fingerprint not distinguishing: %q", r.Fingerprint)
	}
	if r.Fingerprint != Build("contact alice@example.com about the 10.1.2.3 host", crash.Meta{Command: "feedback"}, red, now.Add(time.Hour)).Fingerprint {
		t.Fatal("fingerprint changed for identical redacted message")
	}
}

func TestBuildWithMatchV2HashesRawWithoutSerializingIt(t *testing.T) {
	raw := []byte("synthetic-match-secret-001")
	rawV2 := []byte("synthetic-paired-secret-002")
	result := detectors.Result{
		DetectorType: detectors.GitHub,
		Raw:          raw,
		RawV2:        rawV2,
		Redacted:     "ghp_abc...xyz",
	}
	report, err := BuildWithMatch("false positive in a test fixture", crash.Meta{Command: "feedback"}, &crash.Redactor{}, time.Unix(1_700_000_000, 0), result)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != SchemaV2 || report.Match == nil || report.Match.Detector != detectors.GitHub.String() {
		t.Fatalf("report = %+v", report)
	}
	if got, want := report.Match.RawHash, hashForTest(raw); got != want {
		t.Errorf("raw_hash = %q, want %q", got, want)
	}
	if got, want := report.Match.RawV2Hash, hashForTest(rawV2); got != want {
		t.Errorf("raw_v2_hash = %q, want %q", got, want)
	}
	other := result
	other.Raw = []byte("different-match-secret")
	otherReport, err := BuildWithMatch("false positive in a test fixture", crash.Meta{Command: "feedback"}, &crash.Redactor{}, time.Unix(1_700_000_000, 0), other)
	if err != nil {
		t.Fatal(err)
	}
	if report.Fingerprint == otherReport.Fingerprint {
		t.Fatal("different match hashes must not collide in the local spool filename")
	}
	for _, secret := range [][]byte{raw, rawV2} {
		if strings.Contains(string(b), string(secret)) {
			t.Fatalf("serialized report contains raw match %q: %s", secret, b)
		}
	}
}

func TestBuildWithMatchUsesSafeRedactionForShortUnicodeAndPairedRaw(t *testing.T) {
	cases := []struct {
		name   string
		raw    []byte
		rawV2  []byte
		unsafe string
	}{
		{name: "short", raw: []byte("xY9"), unsafe: "xY9"},
		{name: "unicode", raw: []byte("秘密鍵"), unsafe: "秘密鍵"},
		{name: "paired raw v2", raw: []byte("account-id"), rawV2: []byte("paired-secret"), unsafe: "paired-secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := detectors.Result{DetectorType: detectors.GitHub, Raw: tc.raw, RawV2: tc.rawV2, Redacted: tc.unsafe}
			report, err := BuildWithMatch("fixture", crash.Meta{Command: "feedback"}, &crash.Redactor{}, time.Now(), result)
			if err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			for _, raw := range [][]byte{tc.raw, tc.rawV2} {
				if len(raw) > 0 && strings.Contains(string(b), string(raw)) {
					t.Fatalf("report contains raw match %q: %s", raw, b)
				}
			}
			if report.Match == nil || report.Match.Redacted == tc.unsafe {
				t.Fatalf("unsafe display was retained: %+v", report.Match)
			}
		})
	}
}

func hashForTest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestBuildBoundsMessage(t *testing.T) {
	r := Build(strings.Repeat("a", MaxReportBytes+5000), crash.Meta{Command: "feedback"}, &crash.Redactor{}, time.Now())
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxReportBytes {
		t.Fatalf("report %d bytes exceeds bound", len(b))
	}
	if !strings.Contains(r.Message, "...[truncated]") {
		t.Fatalf("message not marked truncated: %q", r.Message[len(r.Message)-40:])
	}
}

func TestSpoolPermsAndPrune(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "feedback")
	base := time.Unix(1_700_000_000, 0)
	var last string
	for i := 0; i < MaxSpoolFiles+5; i++ {
		r := Report{Schema: Schema, Fingerprint: fmt.Sprintf("%016x", i), CreatedAt: base.Add(time.Duration(i) * time.Minute)}
		p, err := Spool(dir, r)
		if err != nil {
			t.Fatal(err)
		}
		mt := base.Add(time.Duration(i) * time.Second)
		_ = os.Chtimes(p, mt, mt)
		last = p
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != MaxSpoolFiles+1 {
		t.Fatalf("spool has %d entries, want %d", len(entries), MaxSpoolFiles+1)
	}
	if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("%016x-%d.json", 0, base.Unix()))); !os.IsNotExist(err) {
		t.Fatal("oldest report not pruned")
	}
	for _, p := range []string{dir, last, filepath.Join(dir, LastFile)} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o600)
		if info.IsDir() {
			want = 0o700
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s perms %v, want %v", p, info.Mode().Perm(), want)
		}
	}
	if _, _, err := ReadReport(last); err != nil {
		t.Fatalf("ReadReport: %v", err)
	}
}

func TestReadReportRejectsForeignFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.json")
	_ = os.WriteFile(p, []byte(`{"schema":"pleno-dlp.feedback/v1","env":{"AWS_SECRET":"x"}}`), 0o600)
	if _, _, err := ReadReport(p); err == nil {
		t.Fatal("unknown field accepted")
	}
	_ = os.WriteFile(p, []byte(`{"schema":"other/v9"}`), 0o600)
	if _, _, err := ReadReport(p); err == nil {
		t.Fatal("foreign schema accepted")
	}
}

type relay struct {
	mu     sync.Mutex
	bodies []Report
	ua, ct string
	status int
}

func (r *relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var rep Report
	b, _ := io.ReadAll(req.Body)
	_ = json.Unmarshal(b, &rep)
	r.bodies = append(r.bodies, rep)
	r.ua, r.ct = req.Header.Get("User-Agent"), req.Header.Get("Content-Type")
	w.WriteHeader(r.status)
}

func TestSend(t *testing.T) {
	rl := &relay{status: http.StatusAccepted}
	srv := httptest.NewServer(rl)
	defer srv.Close()
	r := Report{Schema: Schema, Fingerprint: "abc"}
	if err := Send(context.Background(), srv.Client(), srv.URL, "1.2.3", r); err != nil {
		t.Fatal(err)
	}
	if rl.ua != "pleno-dlp/1.2.3" || rl.ct != "application/json" || rl.bodies[0].Fingerprint != "abc" {
		t.Fatalf("relay saw ua=%q ct=%q body=%+v", rl.ua, rl.ct, rl.bodies)
	}
	rl.status = http.StatusInternalServerError
	if err := Send(context.Background(), srv.Client(), srv.URL, "1.2.3", r); err == nil {
		t.Fatal("5xx treated as success")
	}
}

func TestEndpointAndSpoolDir(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{crash.EnvDir: dir}
	get := envFunc(env)
	if ep, err := Endpoint(get); err != nil || ep != DefaultEndpoint {
		t.Fatalf("default endpoint = %q, %v", ep, err)
	}
	if sd, err := SpoolDir(get); err != nil || sd != filepath.Join(dir, "feedback") {
		t.Fatalf("spool dir = %q, %v", sd, err)
	}
	env[EnvEndpoint] = "http://127.0.0.1:9/x"
	if ep, err := Endpoint(get); err != nil || ep != "http://127.0.0.1:9/x" {
		t.Fatalf("loopback endpoint = %q, %v", ep, err)
	}
	env[EnvEndpoint] = "http://relay.example.com/x"
	if _, err := Endpoint(get); err == nil {
		t.Fatal("plain http to non-loopback accepted")
	}
	delete(env, EnvEndpoint)
	_ = os.WriteFile(filepath.Join(dir, "telemetry.json"), []byte(`{"feedback_endpoint":"https://fb.example.com/v1"}`), 0o600)
	if ep, err := Endpoint(get); err != nil || ep != "https://fb.example.com/v1" {
		t.Fatalf("file endpoint = %q, %v", ep, err)
	}
}
