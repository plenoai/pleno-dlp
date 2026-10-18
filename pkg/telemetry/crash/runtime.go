package crash

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Runtime carries the dependencies of the crash path. Fields are
// injectable for tests; New fills production defaults.
type Runtime struct {
	Version, Commit string
	// Describe maps argv (without argv[0]) to the subcommand path and the
	// flag names. It must never return values or positional arguments.
	Describe   func(args []string) (command string, flags []string)
	Getenv     func(string) string
	Stderr     io.Writer
	HTTPClient *http.Client
	Now        func() time.Time
	// Detectors returns the secret detectors used for redaction; it is a
	// func so the registry is read after init() self-registration.
	Detectors func() []detectors.Detector
	Exit      func(code int)
	// Executable returns the path to re-exec in Supervise.
	Executable func() (string, error)
}

// New returns a Runtime wired to the real process.
func New(version, commit string, describe func([]string) (string, []string)) *Runtime {
	return &Runtime{
		Version:    version,
		Commit:     commit,
		Describe:   describe,
		Getenv:     os.Getenv,
		Stderr:     os.Stderr,
		Now:        time.Now,
		Detectors:  detectors.All,
		Exit:       os.Exit,
		Executable: os.Executable,
	}
}

func (rt *Runtime) redactor() *Redactor {
	home, _ := os.UserHomeDir()
	red := &Redactor{Prefixes: EnvPrefixes(rt.Getenv, home)}
	if rt.Detectors != nil {
		red.Detectors = rt.Detectors()
	}
	return red
}

// Outcome is what handle did with a captured crash.
type Outcome struct {
	Report  Report
	Path    string
	Sent    bool
	SendErr error
}

// handle builds, spools, optionally sends, and announces a crash. Failures
// here are reported on stderr but never mask the original crash.
func (rt *Runtime) handle(kind Kind, message, stack string, args []string) Outcome {
	cfg, cfgErr := Load(rt.Getenv)
	meta := Meta{Version: rt.Version, Commit: rt.Commit}
	if rt.Describe != nil {
		meta.Command, meta.Flags = rt.Describe(args)
	}
	out := Outcome{Report: Build(kind, message, stack, meta, rt.redactor(), rt.Now())}
	if cfg.Dir == "" {
		fmt.Fprintf(rt.Stderr, "pleno-dlp crashed; crash report not saved: %v\n", cfgErr)
		return out
	}
	path, err := Spool(cfg.SpoolDir(), out.Report)
	if err != nil {
		fmt.Fprintf(rt.Stderr, "pleno-dlp crashed; crash report not saved: %v\n", err)
		return out
	}
	out.Path = path
	if cfgErr != nil || !cfg.Enabled {
		fmt.Fprintf(rt.Stderr, "pleno-dlp crashed; report saved to %s. Opt in to anonymous crash reports with: pleno-dlp telemetry enable\n", path)
		return out
	}
	out.SendErr = Send(context.Background(), rt.HTTPClient, cfg.Endpoint, rt.Version, out.Report)
	out.Sent = out.SendErr == nil
	sent := ""
	if out.Sent {
		sent = " and sent"
	}
	fmt.Fprintf(rt.Stderr, "pleno-dlp crashed; anonymized crash report %s saved to %s%s. Inspect: pleno-dlp telemetry show-last. Opt out: pleno-dlp telemetry disable.\n",
		out.Report.Fingerprint, path, sent)
	if out.SendErr != nil {
		fmt.Fprintf(rt.Stderr, "pleno-dlp: crash report upload failed (%v); retry with: pleno-dlp telemetry send %s\n", out.SendErr, path)
	}
	return out
}
