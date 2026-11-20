package crash

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMonitorRedactsSyntheticDump(t *testing.T) {
	rl := &relay{status: http.StatusOK}
	srv := httptest.NewServer(rl)
	defer srv.Close()
	rt, env, _ := newTestRuntime(t, true, srv.URL)
	rt.HTTPClient = srv.Client()

	const token = "***REDACTED***3"
	const email = "carol.secret@example.com"
	dump := "fatal error: auth failed token=" + token + " user=" + email + "\n\n" +
		sampleStack + strings.Repeat("goroutine 9 [chan receive]:\nmain.wait()\n\t/x/y.go:1 +0x1\n\n", 5000)
	out, ok := rt.Monitor(strings.NewReader(dump), []string{"scan", "filesystem", "/home/carol"})
	if !ok || !out.Sent || out.Report.Kind != KindFatal {
		t.Fatalf("outcome %+v ok=%v", out, ok)
	}
	if out.Report.Version != "9.9.9" || out.Report.Command != "scan filesystem" {
		t.Fatalf("metadata %+v", out.Report)
	}
	if len(rl.bodies) != 1 {
		t.Fatalf("uploads = %d", len(rl.bodies))
	}
	for _, s := range []string{token, email, "carol"} {
		if strings.Contains(rl.bodies[0].Message+rl.bodies[0].Stack, s) {
			t.Errorf("uploaded body contains %q", s)
		}
	}
	files, _ := filepath.Glob(filepath.Join(env[EnvDir], "crash", "*"))
	if len(files) < 2 {
		t.Fatalf("spool = %v", files)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > MaxReportBytes*2 {
			t.Errorf("%s unbounded: %d bytes", f, len(b))
		}
		for _, s := range []string{token, email, "carol"} {
			if strings.Contains(string(b), s) {
				t.Errorf("%s contains %q", f, s)
			}
		}
	}
}

func TestMonitorIgnoresCleanExit(t *testing.T) {
	rt, env, _ := newTestRuntime(t, true, "")
	if _, ok := rt.Monitor(strings.NewReader(""), nil); ok {
		t.Fatal("empty stream reported as crash")
	}
	if _, err := os.Stat(filepath.Join(env[EnvDir], "crash")); !os.IsNotExist(err) {
		t.Fatal("spooled on clean exit")
	}
}

func TestStartMonitorDisabledOrChild(t *testing.T) {
	rt, env, _ := newTestRuntime(t, false, "")
	rt.Executable = func() (string, error) { t.Fatal("executable resolved while disabled"); return "", nil }
	if err := rt.StartMonitor([]string{"pleno-dlp"}, nil); err != ErrNotSupervised {
		t.Fatalf("disabled err = %v", err)
	}
	env[EnvReports] = "1"
	env[EnvChild] = MonitorMarker
	if !rt.IsMonitor() || rt.StartMonitor([]string{"pleno-dlp"}, nil) != ErrNotSupervised {
		t.Fatal("monitor re-armed itself")
	}
}
