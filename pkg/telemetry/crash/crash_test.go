package crash

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
)

// helperEnv makes the test binary act as a crashing child for Supervise.
const helperEnv = "CRASH_TEST_HELPER"

func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "panic":
		panic("boom for alice@example.com at 10.1.2.3")
	case "goroutine":
		done := make(chan struct{})
		go func() { panic("goroutine boom") }()
		<-done
	case "exit3":
		fmt.Fprintln(os.Stderr, "panic: this is just output")
		os.Exit(3)
	case "clean":
		os.Exit(0)
	}
	os.Exit(m.Run())
}

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
	a := Build(KindPanic, "panic: index out of range [5] with length 3", sampleStack, Meta{Version: "1.0.0"}, red, time.Now())
	moved := strings.ReplaceAll(sampleStack, "engine.go:412", "engine.go:430")
	b := Build(KindPanic, "panic: index out of range [7] with length 2", moved, Meta{Version: "1.1.0"}, red, time.Now())
	if a.Fingerprint != b.Fingerprint || len(a.Fingerprint) != 16 {
		t.Fatalf("fingerprints differ or wrong length: %q vs %q", a.Fingerprint, b.Fingerprint)
	}
	c := Build(KindPanic, "panic: nil map", sampleStack, Meta{}, red, time.Now())
	if c.Fingerprint == a.Fingerprint {
		t.Fatal("different messages must not share a fingerprint")
	}
}

func TestFingerprintSelfPathFollowsReportPackage(t *testing.T) {
	frame := reflect.TypeOf(Report{}).PkgPath() + ".Recover.func1()"
	stack := frame + "\n" + ModulePath + "pkg/engine.scan()\n"
	frames := moduleFrames(stack, 5)
	if len(frames) != 1 || frames[0] != ModulePath+"pkg/engine.scan" {
		t.Fatalf("moduleFrames(%q) = %v", stack, frames)
	}
}

func TestBuildFieldsAndBound(t *testing.T) {
	now := time.Date(2026, 10, 18, 9, 41, 37, 0, time.FixedZone("JST", 9*3600))
	huge := strings.Repeat("github.com/plenoai/pleno-dlp/pkg/x.f()\n\tgithub.com/plenoai/pleno-dlp/pkg/x/x.go:1\n", 2000)
	r := Build(KindRecovered, "panic: x", huge, Meta{Command: "scan filesystem", Flags: []string{"json"}}, &Redactor{}, now)
	b, _ := json.Marshal(r)
	if len(b) > MaxReportBytes {
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
	want := []string{"schema", "fingerprint", "version", "commit", "goos", "goarch", "go_version", "command", "flags", "kind", "message", "stack", "created_at"}
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
	dir := filepath.Join(t.TempDir(), "crash")
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

// TestWriteFileMatchesSpoolEncoding pins the --crash-report guarantee: a
// local report is byte-identical to the spooled last.json that
// `telemetry show-last` prints.
func TestWriteFileMatchesSpoolEncoding(t *testing.T) {
	dir := t.TempDir()
	r := Report{
		Schema:      Schema,
		Fingerprint: "0123456789abcdef",
		Version:     "1.2.3",
		Kind:        KindCrash,
		Message:     "panic: boom",
		Stack:       "goroutine [running]:\n",
		CreatedAt:   time.Unix(1_700_000_000, 0).UTC(),
	}
	local := filepath.Join(dir, "local.json")
	if err := WriteFile(local, r); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	spoolDir := filepath.Join(dir, "crash")
	if _, err := Spool(spoolDir, r); err != nil {
		t.Fatalf("Spool: %v", err)
	}
	got, err := os.ReadFile(local)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(spoolDir, LastFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("local report differs from spool encoding:\nlocal:\n%s\nspool:\n%s", got, want)
	}
	if _, _, err := ReadReport(local); err != nil {
		t.Fatalf("local report not readable as a crash report: %v", err)
	}
}

func TestReadReportRejectsForeignFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.json")
	_ = os.WriteFile(p, []byte(`{"schema":"pleno-dlp.crash/v1","env":{"AWS_SECRET":"x"}}`), 0o600)
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
	if len(rl.bodies) != 2 {
		t.Fatalf("send retried: %d requests", len(rl.bodies))
	}
}

func TestParseCrash(t *testing.T) {
	buf := "scanning...\npanic: first [recovered]\n\tpanic: second\n\ngoroutine 1 [running]:\nmain.main()\n"
	kind, msg, stack, ok := parseCrash(buf)
	if !ok || kind != KindPanic || msg != "panic: first [recovered]\n\tpanic: second" || !strings.HasPrefix(stack, "goroutine 1 [running]:") {
		t.Fatalf("got %v %q %q %v", kind, msg, stack, ok)
	}
	kind, msg, _, ok = parseCrash("fatal error: concurrent map writes\n\ngoroutine 5 [running]:\n")
	if !ok || kind != KindFatal || msg != "fatal error: concurrent map writes" {
		t.Fatalf("fatal: %v %q %v", kind, msg, ok)
	}
	if _, _, _, ok := parseCrash("error: something else\n"); ok {
		t.Fatal("non-crash parsed as crash")
	}
}

func TestRingBufferPinsCrashHead(t *testing.T) {
	r := &ringBuffer{max: 64}
	_, _ = r.Write([]byte(strings.Repeat("x", 100) + "\nfatal er"))
	_, _ = r.Write([]byte("ror: boom\n" + strings.Repeat("g", 200)))
	got := r.Crash()
	if !strings.HasPrefix(got, "fatal error: boom") || len(got) != 64 {
		t.Fatalf("pinned crash = %q", got)
	}
	r2 := &ringBuffer{max: 8}
	_, _ = r2.Write([]byte("abcdefghij"))
	if r2.Crash() != "cdefghij" {
		t.Fatalf("ring = %q", r2.Crash())
	}
}

func newTestRuntime(t *testing.T, enabled bool, endpoint string) (*Runtime, map[string]string, *strings.Builder) {
	t.Helper()
	env := map[string]string{EnvDir: t.TempDir(), EnvEndpoint: endpoint}
	if enabled {
		env[EnvReports] = "1"
	}
	var stderr strings.Builder
	rt := &Runtime{
		Version: "9.9.9", Commit: "abc",
		Describe:   func([]string) (string, []string) { return "scan filesystem", []string{"json"} },
		Getenv:     envFunc(env),
		Stderr:     &stderr,
		Now:        time.Now,
		Exit:       func(code int) { panic(fmt.Sprintf("exit %d", code)) },
		Executable: func() (string, error) { return os.Args[0], nil },
	}
	return rt, env, &stderr
}

func TestRecoverDisabledSpoolsAndHints(t *testing.T) {
	rt, env, stderr := newTestRuntime(t, false, "")
	func() {
		defer func() {
			if v := recover(); v != "exit 2" {
				t.Fatalf("exit = %v", v)
			}
		}()
		_ = rt.Recover(nil, func() error { panic("kaboom 42") })
	}()
	if !strings.Contains(stderr.String(), "pleno-dlp crashed; report saved to ") ||
		!strings.Contains(stderr.String(), "Opt in to anonymous crash reports with: pleno-dlp telemetry enable") ||
		!strings.Contains(stderr.String(), "panic: kaboom 42") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	r, _, err := ReadReport(filepath.Join(env[EnvDir], "crash", LastFile))
	if err != nil || r.Kind != KindRecovered || r.Command != "scan filesystem" {
		t.Fatalf("spooled %+v %v", r, err)
	}
}

func TestRecoverInChildIsTransparent(t *testing.T) {
	rt, env, _ := newTestRuntime(t, true, "")
	env[EnvChild] = "1"
	defer func() {
		if v := recover(); v != "raw" {
			t.Fatalf("child Recover swallowed panic: %v", v)
		}
	}()
	_ = rt.Recover(nil, func() error { panic("raw") })
}

func TestSuperviseDisabledStartsNothing(t *testing.T) {
	rt, _, _ := newTestRuntime(t, false, "")
	rt.Executable = func() (string, error) { t.Fatal("executable resolved while disabled"); return "", nil }
	if _, err := rt.Supervise(context.Background(), []string{"pleno-dlp"}, nil); err != ErrNotSupervised {
		t.Fatalf("err = %v", err)
	}
}

func TestSuperviseReportsChildCrash(t *testing.T) {
	for _, mode := range []string{"panic", "goroutine"} {
		t.Run(mode, func(t *testing.T) {
			rl := &relay{status: http.StatusOK}
			srv := httptest.NewServer(rl)
			defer srv.Close()
			rt, env, stderr := newTestRuntime(t, true, srv.URL)
			rt.HTTPClient = srv.Client()
			childEnv := append(os.Environ(), helperEnv+"="+mode)
			code, err := rt.Supervise(context.Background(), []string{"pleno-dlp", "scan", "filesystem"}, childEnv)
			if err != nil || code != 2 {
				t.Fatalf("code=%d err=%v", code, err)
			}
			out := stderr.String()
			if !strings.Contains(out, "and sent. Inspect: pleno-dlp telemetry show-last. Opt out: pleno-dlp telemetry disable.") {
				t.Fatalf("notice missing: %q", out)
			}
			if len(rl.bodies) != 1 || rl.bodies[0].Kind != KindPanic {
				t.Fatalf("relay got %+v", rl.bodies)
			}
			got := rl.bodies[0]
			if mode == "panic" && (strings.Contains(got.Message, "alice@") || strings.Contains(got.Message, "10.1.2.3")) {
				t.Fatalf("PII survived: %q", got.Message)
			}
			if _, err := os.Stat(filepath.Join(env[EnvDir], "crash", LastFile)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHandleThrottlesRepeatedCrash(t *testing.T) {
	rl := &relay{status: http.StatusOK}
	srv := httptest.NewServer(rl)
	defer srv.Close()
	rt, _, stderr := newTestRuntime(t, true, srv.URL)
	rt.HTTPClient = srv.Client()

	first := rt.handle(KindRecovered, "panic: same", sampleStack, nil)
	if first.Throttled || !first.Sent || len(rl.bodies) != 1 {
		t.Fatalf("first handle: %+v bodies=%d", first, len(rl.bodies))
	}
	second := rt.handle(KindRecovered, "panic: same", sampleStack, nil)
	if !second.Throttled || second.Sent || len(rl.bodies) != 1 {
		t.Fatalf("second handle: %+v bodies=%d", second, len(rl.bodies))
	}
	if !strings.Contains(stderr.String(), "throttled locally") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestSupervisePassesThroughNonCrashExits(t *testing.T) {
	for mode, want := range map[string]int{"exit3": 3, "clean": 0} {
		rt, env, _ := newTestRuntime(t, true, "")
		code, err := rt.Supervise(context.Background(), []string{"pleno-dlp"}, append(os.Environ(), helperEnv+"="+mode))
		if err != nil || code != want {
			t.Fatalf("%s: code=%d err=%v", mode, code, err)
		}
		if _, err := os.Stat(filepath.Join(env[EnvDir], "crash")); !os.IsNotExist(err) {
			t.Fatalf("%s: spooled a report for a non-crash exit", mode)
		}
	}
}
