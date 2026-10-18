package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/telemetry/report"
)

// isolateTelemetry points telemetry commands at a temp dir and a fixed env.
func isolateTelemetry(t *testing.T, env map[string]string) string {
	t.Helper()
	resetCommandFlags(t)
	dir := t.TempDir()
	env[report.EnvDir] = dir
	prev := telemetryGetenv
	telemetryGetenv = func(k string) string { return env[k] }
	t.Cleanup(func() { telemetryGetenv = prev })
	return dir
}

func runRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// Flag values persist on the package-level command tree between
	// Execute calls; reset so each invocation sees only its own flags.
	resetCommandFlagsNow()
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs(args)
	err := Root.Execute()
	return out.String(), err
}

func TestTelemetryEnableDisableStatus(t *testing.T) {
	env := map[string]string{}
	dir := isolateTelemetry(t, env)

	out, err := runRoot(t, "telemetry", "status")
	if err != nil || !strings.Contains(out, "crash reports: disabled") || !strings.Contains(out, "source:        default") ||
		!strings.Contains(out, report.DefaultEndpoint) || !strings.Contains(out, filepath.Join(dir, "reports")) {
		t.Fatalf("default status: %v\n%s", err, out)
	}
	if _, err := runRoot(t, "telemetry", "enable"); err != nil {
		t.Fatal(err)
	}
	out, _ = runRoot(t, "telemetry", "status")
	if !strings.Contains(out, "crash reports: enabled") || !strings.Contains(out, "source:        file") {
		t.Fatalf("after enable:\n%s", out)
	}
	env[report.EnvReports] = "0"
	out, _ = runRoot(t, "telemetry", "status")
	if !strings.Contains(out, "crash reports: disabled") || !strings.Contains(out, "source:        env") {
		t.Fatalf("env override:\n%s", out)
	}
	delete(env, report.EnvReports)
	if _, err := runRoot(t, "telemetry", "disable"); err != nil {
		t.Fatal(err)
	}
	out, _ = runRoot(t, "telemetry", "status")
	if !strings.Contains(out, "crash reports: disabled") || !strings.Contains(out, "source:        file") {
		t.Fatalf("after disable:\n%s", out)
	}
}

func spoolSample(t *testing.T, dir string) string {
	t.Helper()
	r := report.BuildCrash(report.CrashPanic, "panic: sample", "goroutine 1 [running]:\n", report.Meta{Version: "t"}, &report.Redactor{}, time.Now())
	p, err := report.Spool(filepath.Join(dir, "reports"), r)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTelemetryShowLast(t *testing.T) {
	dir := isolateTelemetry(t, map[string]string{})
	if _, err := runRoot(t, "telemetry", "show-last"); err == nil || !strings.Contains(err.Error(), "no report spooled") {
		t.Fatalf("empty spool err = %v", err)
	}
	spoolSample(t, dir)
	out, err := runRoot(t, "telemetry", "show-last")
	if err != nil || !strings.Contains(out, `"schema": "pleno-dlp.report/v1"`) || !strings.Contains(out, `"crash_kind": "panic"`) || !strings.Contains(out, `"message": "panic: sample"`) {
		t.Fatalf("show-last: %v\n%s", err, out)
	}
}

func TestTelemetrySend(t *testing.T) {
	var got report.Report
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
	}))
	defer srv.Close()
	dir := isolateTelemetry(t, map[string]string{report.EnvEndpoint: srv.URL})
	p := spoolSample(t, dir)
	out, err := runRoot(t, "telemetry", "send", p)
	if err != nil || got.Message != "panic: sample" || !strings.Contains(out, "crash report sent to ") {
		t.Fatalf("send: %v %+v\n%s", err, got, out)
	}
	foreign := filepath.Join(dir, "notes.json")
	_ = os.WriteFile(foreign, []byte(`{"secret":"x"}`), 0o600)
	if _, err := runRoot(t, "telemetry", "send", foreign); err == nil {
		t.Fatal("send accepted a non-report file")
	}
}

func TestTelemetryCrashTestPanics(t *testing.T) {
	isolateTelemetry(t, map[string]string{})
	defer func() {
		if v := recover(); v != "pleno-dlp telemetry crash-test" {
			t.Fatalf("recover = %v", v)
		}
	}()
	_, _ = runRoot(t, "telemetry", "crash-test")
	t.Fatal("crash-test returned without panicking")
}

func TestTelemetryCrashTestGoroutineFlag(t *testing.T) {
	// The goroutine variant kills the process, so it is exercised end to
	// end by pkg/telemetry/crash's supervisor tests; here only its wiring.
	f := telemetryCrashTestCmd.Flags().Lookup("goroutine")
	if f == nil || !telemetryCrashTestCmd.Hidden {
		t.Fatal("crash-test must be hidden and expose --goroutine")
	}
}

func TestDescribeInvocationDropsValues(t *testing.T) {
	cmd, flags := DescribeInvocation([]string{"scan", "filesystem", "/home/alice/secret", "--format=json", "--exclude", "/x", "--bogus-token=abc", "--", "--only-verified"})
	if cmd != "scan filesystem" {
		t.Fatalf("command = %q", cmd)
	}
	if !reflect.DeepEqual(flags, []string{"exclude", "format"}) {
		t.Fatalf("flags = %v", flags)
	}
	if c, f := DescribeInvocation([]string{"no-such-command", "secret"}); c != "" || len(f) != 0 {
		t.Fatalf("unknown command leaked %q %v", c, f)
	}
}
