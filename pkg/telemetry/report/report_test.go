package report

import (
	"context"
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
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
)

func envFunc(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

const sampleStack = `goroutine 17 [running]:
github.com/plenoai/pleno-dlp/pkg/engine.(*Engine).scan(0x14000123000, {0x1029a8f40, 0x140001a2000})
	/Users/alice/ghq/github.com/plenoai/pleno-dlp/pkg/engine/engine.go:412 +0x1c4
github.com/plenoai/pleno-dlp/cmd/pleno-dlp/cmd.runScan.func1()
	/Users/alice/ghq/github.com/plenoai/pleno-dlp/cmd/pleno-dlp/cmd/scan.go:88 +0x2c
golang.org/x/sync/errgroup.(*Group).Go.func1()
	/Users/alice/go/pkg/mod/golang.org/x/sync@v0.10.0/errgroup/errgroup.go:78 +0x54
created by github.com/plenoai/pleno-dlp/pkg/engine.New in goroutine 1
	/opt/homebrew/Cellar/go/1.26.9/libexec/src/runtime/proc.go:1223 +0x9c
`

func TestRedactStack(t *testing.T) {
	red := &Redactor{Prefixes: EnvPrefixes(envFunc(map[string]string{
		"GOMODCACHE": "/Users/alice/go/pkg/mod",
		"GOPATH":     "/Users/alice/go",
		"GOROOT":     "/opt/homebrew/Cellar/go/1.26.9/libexec",
	}), "/Users/alice")}
	got := red.Redact(sampleStack)
	for _, bad := range []string{"alice", "+0x", "0x14000123000", "goroutine 17", "goroutine 1\n", "/opt/homebrew"} {
		if strings.Contains(got, bad) {
			t.Errorf("redacted stack still contains %q:\n%s", bad, got)
		}
	}
	for _, want := range []string{
		"goroutine [running]:",
		"\tgithub.com/plenoai/pleno-dlp/pkg/engine/engine.go:412\n",
		"$GOMODCACHE/golang.org/x/sync@v0.10.0/errgroup/errgroup.go:78",
		"in goroutine N",
		"\t$GOROOT/src/runtime/proc.go:1223\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("redacted stack missing %q:\n%s", want, got)
		}
	}
}

func TestRedactPatterns(t *testing.T) {
	red := &Redactor{}
	cases := []struct{ in, want string }{
		{"mail bob.smith+x@corp.example.org now", "mail [EMAIL] now"},
		{"dial tcp 192.168.10.20:443: refused", "dial tcp [IP]:443: refused"},
		{"addr fe80::1ff:fe23:4567:890a down", "addr [IP] down"},
		{"addr 2001:db8:0:0:0:0:2:1 down", "addr [IP] down"},
		{"at 12:34:56 ok", "at 12:34:56 ok"},
		{"get https://internal.corp/api?k=v failed", "get [URL] failed"},
		{"see https://github.com/plenoai/pleno-dlp/issues/1", "see https://github.com/plenoai"},
		{"see https://github.com/evil/repo", "see [URL]"},
		{"open /etc/shadow: permission denied", "open [PATH]: permission denied"},
		{`open C:\Users\bob\secret.txt failed`, "open [PATH] failed"},
		{"id deadbeefdeadbeefdeadbeef00", "id [TOKEN]"},
		{"tok dGhpcyBpcyBhIHNlY3JldCB2YWx1ZQ== x", "tok [TOKEN] x"},
		{"fn verifycoverage_sync_test_helper ok", "fn verifycoverage_sync_test_helper ok"},
		{"ptr 0xc000012345", "ptr 0x?"},
	}
	for _, c := range cases {
		if got := red.Redact(c.in); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

type fakeDetector struct{ secret string }

func (f fakeDetector) Keywords() []string           { return []string{"zzkey"} }
func (f fakeDetector) Type() detectors.DetectorType { return detectors.DetectorType(1) }
func (f fakeDetector) FromData(_ context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	if verify {
		panic("verification must never run on crash text")
	}
	if strings.Contains(string(data), f.secret) {
		return []detectors.Result{{DetectorType: f.Type(), Raw: []byte(f.secret)}}, nil
	}
	return nil, nil
}

type panicDetector struct{}

func (panicDetector) Keywords() []string           { return nil }
func (panicDetector) Type() detectors.DetectorType { return detectors.DetectorType(2) }
func (panicDetector) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	panic("detector bug")
}

func TestScrubSecretsReplacesDetectorMatches(t *testing.T) {
	red := &Redactor{Detectors: []detectors.Detector{panicDetector{}, fakeDetector{secret: "zzkey=hunter"}}}
	got := red.Redact("value zzkey=hunter end")
	want := "value [REDACTED:" + detectors.DetectorType(1).String() + "] end"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestScrubSecretsWithRegisteredDetectors(t *testing.T) {
	// A Slack webhook URL is caught by the URL rule; a Postgres DSN with a
	// short password is not a token, so it exercises the detector pass.
	red := &Redactor{Detectors: detectors.All()}
	start := time.Now()
	in := "config: password = \"Tr0ub4dor&3xyz\" postgres user\n" + strings.Repeat("filler line\n", 2000)
	_ = red.Redact(in)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("redaction with all detectors took %v", d)
	}
}

func TestFingerprintStableAcrossVersionsAndLines(t *testing.T) {
	red := &Redactor{}
	a := BuildCrash(CrashPanic, "panic: index out of range [5] with length 3", sampleStack, Meta{Version: "1.0.0"}, red, time.Now())
	moved := strings.ReplaceAll(sampleStack, "engine.go:412", "engine.go:430")
	b := BuildCrash(CrashPanic, "panic: index out of range [7] with length 2", moved, Meta{Version: "1.1.0"}, red, time.Now())
	if a.Fingerprint != b.Fingerprint || len(a.Fingerprint) != 16 {
		t.Fatalf("fingerprints differ or wrong length: %q vs %q", a.Fingerprint, b.Fingerprint)
	}
	c := BuildCrash(CrashPanic, "panic: nil map", sampleStack, Meta{}, red, time.Now())
	if c.Fingerprint == a.Fingerprint {
		t.Fatal("different messages must not share a fingerprint")
	}
}

func TestBuildFieldsAndBound(t *testing.T) {
	now := time.Date(2026, 10, 18, 9, 41, 37, 0, time.FixedZone("JST", 9*3600))
	huge := strings.Repeat("github.com/plenoai/pleno-dlp/pkg/x.f()\n\tgithub.com/plenoai/pleno-dlp/pkg/x/x.go:1\n", 2000)
	r := BuildCrash(CrashRecovered, "panic: x", huge, Meta{Command: "scan filesystem", Flags: []string{"json"}}, &Redactor{}, now)
	b, _ := Marshal(r)
	if len(b) > MaxReportBytes || len(r.Stack) > MaxStackBytes {
		t.Fatalf("report %d bytes exceeds bound", len(b))
	}
	if !strings.HasSuffix(r.Stack, truncatedMarker) {
		t.Fatal("truncated stack lacks marker")
	}
	if !r.CreatedAt.Equal(time.Date(2026, 10, 18, 0, 41, 0, 0, time.UTC)) || r.CreatedAt.Location() != time.UTC {
		t.Fatalf("created_at = %v, want minute-precision UTC", r.CreatedAt)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	want := []string{"schema", "kind", "crash_kind", "fingerprint", "version", "commit", "goos", "goarch", "go_version", "command", "flags", "message", "stack", "detector", "created_at"}
	if len(m) != len(want) {
		t.Fatalf("report has %d fields, want exactly %v: %v", len(m), want, m)
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Errorf("missing field %q", k)
		}
	}
}

func TestLoadPrecedence(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{EnvDir: dir}
	cfg, err := Load(envFunc(env))
	if err != nil || cfg.Enabled || cfg.Source != SourceDefault || cfg.Endpoint != DefaultEndpoint {
		t.Fatalf("default: %+v %v", cfg, err)
	}
	if _, err := SetEnabled(envFunc(env), true); err != nil {
		t.Fatal(err)
	}
	cfg, _ = Load(envFunc(env))
	if !cfg.Enabled || cfg.Source != SourceFile {
		t.Fatalf("file: %+v", cfg)
	}
	env[EnvReports] = "0"
	cfg, _ = Load(envFunc(env))
	if cfg.Enabled || cfg.Source != SourceEnv {
		t.Fatalf("env override: %+v", cfg)
	}
	env[EnvReports] = "maybe"
	if _, err := Load(envFunc(env)); err == nil {
		t.Fatal("invalid env value accepted")
	}
	delete(env, EnvReports)
	env[EnvEndpoint] = "http://relay.example.com/x"
	if _, err := Load(envFunc(env)); err == nil {
		t.Fatal("plain http to non-loopback accepted")
	}
	env[EnvEndpoint] = "http://127.0.0.1:9/x"
	if cfg, err := Load(envFunc(env)); err != nil || cfg.Endpoint != "http://127.0.0.1:9/x" {
		t.Fatalf("loopback endpoint: %+v %v", cfg, err)
	}
	info, err := os.Stat(filepath.Join(dir, configFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config perms: %v %v", info, err)
	}
}

func TestSpoolPermsAndPrune(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	base := time.Unix(1_700_000_000, 0)
	var last string
	for i := 0; i < MaxSpoolFiles+5; i++ {
		r := Report{Schema: Schema, Kind: KindCrash, CrashKind: CrashPanic, Fingerprint: fmt.Sprintf("%016x", i), CreatedAt: base.Add(time.Duration(i) * time.Minute)}
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
	if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("crash-%016x-%d.json", 0, base.Unix()))); !os.IsNotExist(err) {
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
	_ = os.WriteFile(p, []byte(`{"schema":"pleno-dlp.report/v1","env":{"AWS_SECRET":"x"}}`), 0o600)
	if _, _, err := ReadReport(p); err == nil {
		t.Fatal("unknown field accepted")
	}
	_ = os.WriteFile(p, []byte(`{"schema":"pleno-dlp.crash/v1"}`), 0o600)
	if _, _, err := ReadReport(p); err == nil {
		t.Fatal("retired v0.67 crash schema accepted")
	}
	// A feedback report must not carry crash-only fields.
	_ = os.WriteFile(p, []byte(`{"schema":"pleno-dlp.report/v1","kind":"feedback","message":"hi","stack":"goroutine"}`), 0o600)
	if _, _, err := ReadReport(p); err == nil {
		t.Fatal("feedback with a stack accepted")
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
	r := Report{Schema: Schema, Kind: KindCrash, CrashKind: CrashPanic, Fingerprint: "0123456789abcdef"}
	if _, err := Send(context.Background(), srv.Client(), srv.URL, "1.2.3", r); err != nil {
		t.Fatal(err)
	}
	if rl.ua != "pleno-dlp/1.2.3" || rl.ct != "application/json" || rl.bodies[0].Fingerprint != "0123456789abcdef" {
		t.Fatalf("relay saw ua=%q ct=%q body=%+v", rl.ua, rl.ct, rl.bodies)
	}
	rl.status = http.StatusInternalServerError
	if _, err := Send(context.Background(), srv.Client(), srv.URL, "1.2.3", r); err == nil {
		t.Fatal("5xx treated as success")
	}
	if len(rl.bodies) != 2 {
		t.Fatalf("send retried: %d requests", len(rl.bodies))
	}
	if _, err := Send(context.Background(), srv.Client(), srv.URL, "1.2.3", Report{Schema: Schema, Kind: KindFeedback}); err == nil {
		t.Fatal("invalid report sent")
	}
	if len(rl.bodies) != 2 {
		t.Fatal("invalid report reached the relay")
	}
}

func TestBuildUserContract(t *testing.T) {
	now := time.Now()
	red := &Redactor{}
	r, err := BuildUser(KindFalsePositive, "matched a fixture for bob@example.com", "AWS", Meta{Command: "feedback", Flags: []string{"kind"}}, red, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Fingerprint != "" || r.CrashKind != "" || r.Stack != "" || r.Detector != "AWS" || r.Message != "matched a fixture for [EMAIL]" {
		t.Fatalf("false-positive report = %+v", r)
	}
	if _, err := BuildUser(KindFalsePositive, "x", "", Meta{}, red, now); err == nil {
		t.Fatal("false-positive without detector accepted")
	}
	if _, err := BuildUser(KindFeedback, "x", "AWS", Meta{}, red, now); err == nil {
		t.Fatal("feedback with detector accepted")
	}
	if _, err := BuildUser(KindFeedback, "", "", Meta{}, red, now); err == nil {
		t.Fatal("empty feedback accepted")
	}
	if _, err := BuildUser(KindCrash, "x", "", Meta{}, red, now); err == nil {
		t.Fatal("crash built through BuildUser")
	}
	long, _ := BuildUser(KindFeedback, strings.Repeat("word ", 1000), "", Meta{}, red, now)
	if len(long.Message) > MaxMessageBytes || !strings.HasSuffix(long.Message, truncatedMarker) {
		t.Fatalf("message not capped: %d bytes", len(long.Message))
	}
}

func TestSendReturnsIssueURL(t *testing.T) {
	for reply, want := range map[string]string{
		`{"issue":"https://github.com/plenoai/pleno-dlp-intake/issues/7"}`: "https://github.com/plenoai/pleno-dlp-intake/issues/7",
		`{"issue":"http://evil.example/x"}`:                                "",
		`{"issue":"https://x.example/\u001b[2J"}`:                          "",
		`not json`: "",
		``:         "",
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, reply)
		}))
		r := Report{Schema: Schema, Kind: KindFeedback, Message: "hi"}
		got, err := Send(context.Background(), srv.Client(), srv.URL, "t", r)
		srv.Close()
		if err != nil || got.Issue != want {
			t.Errorf("reply %q: issue=%q err=%v, want %q", reply, got.Issue, err, want)
		}
	}
}

func TestSpoolNamesNonCrashByContentHash(t *testing.T) {
	dir := t.TempDir()
	r := Report{Schema: Schema, Kind: KindFeedback, Message: "hi", Flags: []string{}, CreatedAt: time.Unix(1_700_000_000, 0)}
	p, err := Spool(dir, r)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(p)
	if !strings.HasPrefix(base, "feedback-") || !strings.HasSuffix(base, "-1700000000.json") || len(base) != len("feedback-")+16+len("-1700000000.json") {
		t.Fatalf("spool name %q", base)
	}
}
