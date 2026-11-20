package crash

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	fakeToken = "ghp_" + "Zx9Qw3Er5Ty7Ui9Op1As3Df5Gh7Jk9Lz2Xc"
	fakeEmail = "bob.secret@example.com"
)

func TestMonitorSpoolsRedactedReport(t *testing.T) {
	rl := &relay{status: http.StatusOK}
	srv := httptest.NewServer(rl)
	defer srv.Close()
	rt, env, _ := newTestRuntime(t, true, srv.URL)
	rt.HTTPClient = srv.Client()
	dump := "scanning...\npanic: leaked " + fakeToken + " for " + fakeEmail + "\n\n" + sampleStack
	out, ok := rt.Monitor(strings.NewReader(dump), []string{"scan", "filesystem", "--json"})
	if !ok || out.Path == "" || !out.Sent {
		t.Fatalf("monitor outcome %+v ok=%v", out, ok)
	}
	r, _, err := ReadReport(filepath.Join(env[EnvDir], "crash", LastFile))
	if err != nil || r.Kind != KindPanic || r.Version != "9.9.9" || r.Commit != "abc" || r.Command != "scan filesystem" {
		t.Fatalf("spooled %+v %v", r, err)
	}
	entries, err := os.ReadDir(filepath.Join(env[EnvDir], "crash"))
	if err != nil || len(entries) == 0 {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(env[EnvDir], "crash", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{fakeToken, fakeEmail} {
			if strings.Contains(string(b), bad) {
				t.Fatalf("%s contains %q", e.Name(), bad)
			}
		}
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if len(rl.bodies) != 1 {
		t.Fatalf("relay got %d bodies", len(rl.bodies))
	}
	b := rl.bodies[0]
	if b.Version != "9.9.9" || b.Command != "scan filesystem" ||
		strings.Contains(b.Message+b.Stack, fakeToken) || strings.Contains(b.Message+b.Stack, fakeEmail) {
		t.Fatalf("uploaded %+v", b)
	}
}

func TestMonitorIgnoresCleanStream(t *testing.T) {
	rt, env, _ := newTestRuntime(t, true, "")
	if _, ok := rt.Monitor(strings.NewReader(""), nil); ok {
		t.Fatal("empty stream treated as crash")
	}
	if _, err := os.Stat(filepath.Join(env[EnvDir], "crash")); !os.IsNotExist(err) {
		t.Fatal("spooled without a crash")
	}
}

func TestMonitorReportsHeaderlessFatal(t *testing.T) {
	rt, env, _ := newTestRuntime(t, true, "http://127.0.0.1:9/x")
	out, ok := rt.Monitor(strings.NewReader(sampleStack), nil)
	if !ok || out.Report.Kind != KindFatal || out.Report.Message != fatalNoHeader {
		t.Fatalf("monitor outcome %+v ok=%v", out.Report, ok)
	}
	if _, err := os.Stat(filepath.Join(env[EnvDir], "crash", LastFile)); err != nil {
		t.Fatal(err)
	}
}

func TestStartMonitorNoop(t *testing.T) {
	rt, _, _ := newTestRuntime(t, false, "")
	rt.Executable = func() (string, error) { t.Fatal("executable resolved while disabled"); return "", nil }
	stop, err := rt.StartMonitor([]string{"pleno-dlp"}, nil)
	if err != ErrNotMonitored {
		t.Fatalf("disabled: err = %v", err)
	}
	stop()

	rt, env, _ := newTestRuntime(t, true, "")
	rt.Executable = func() (string, error) { t.Fatal("executable resolved in monitor"); return "", nil }
	env[EnvChild] = MonitorMarker
	if !rt.IsMonitor() {
		t.Fatal("IsMonitor = false")
	}
	stop, err = rt.StartMonitor([]string{"pleno-dlp"}, nil)
	if err != ErrNotMonitored {
		t.Fatalf("monitor: err = %v", err)
	}
	stop()
}
