package crash

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

	"github.com/plenoai/pleno-dlp/pkg/telemetry/report"
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

type relay struct {
	mu     sync.Mutex
	bodies []report.Report
	ua, ct string
	status int
}

func (r *relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var rep report.Report
	b, _ := io.ReadAll(req.Body)
	_ = json.Unmarshal(b, &rep)
	r.bodies = append(r.bodies, rep)
	r.ua, r.ct = req.Header.Get("User-Agent"), req.Header.Get("Content-Type")
	w.WriteHeader(r.status)
}

func TestParseCrash(t *testing.T) {
	buf := "scanning...\npanic: first [recovered]\n\tpanic: second\n\ngoroutine 1 [running]:\nmain.main()\n"
	kind, msg, stack, ok := parseCrash(buf)
	if !ok || kind != report.CrashPanic || msg != "panic: first [recovered]\n\tpanic: second" || !strings.HasPrefix(stack, "goroutine 1 [running]:") {
		t.Fatalf("got %v %q %q %v", kind, msg, stack, ok)
	}
	kind, msg, _, ok = parseCrash("fatal error: concurrent map writes\n\ngoroutine 5 [running]:\n")
	if !ok || kind != report.CrashFatal || msg != "fatal error: concurrent map writes" {
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
	env := map[string]string{report.EnvDir: t.TempDir(), report.EnvEndpoint: endpoint}
	if enabled {
		env[report.EnvReports] = "1"
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
	r, _, err := report.ReadReport(filepath.Join(env[report.EnvDir], "reports", report.LastFile))
	if err != nil || r.Kind != report.KindCrash || r.CrashKind != report.CrashRecovered || r.Command != "scan filesystem" {
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
			if len(rl.bodies) != 1 || rl.bodies[0].Kind != report.KindCrash || rl.bodies[0].CrashKind != report.CrashPanic {
				t.Fatalf("relay got %+v", rl.bodies)
			}
			got := rl.bodies[0]
			if mode == "panic" && (strings.Contains(got.Message, "alice@") || strings.Contains(got.Message, "10.1.2.3")) {
				t.Fatalf("PII survived: %q", got.Message)
			}
			if _, err := os.Stat(filepath.Join(env[report.EnvDir], "reports", report.LastFile)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSupervisePassesThroughNonCrashExits(t *testing.T) {
	for mode, want := range map[string]int{"exit3": 3, "clean": 0} {
		rt, env, _ := newTestRuntime(t, true, "")
		code, err := rt.Supervise(context.Background(), []string{"pleno-dlp"}, append(os.Environ(), helperEnv+"="+mode))
		if err != nil || code != want {
			t.Fatalf("%s: code=%d err=%v", mode, code, err)
		}
		if _, err := os.Stat(filepath.Join(env[report.EnvDir], "reports")); !os.IsNotExist(err) {
			t.Fatalf("%s: spooled a report for a non-crash exit", mode)
		}
	}
}
