// Local crash reports (`--crash-report <path>`).
//
// This complements the opt-in anonymized telemetry (pkg/telemetry/crash,
// docs/telemetry.md). Telemetry always spools a report and optionally sends
// it to a relay after opt-in; --crash-report instead writes the same
// secret-free report to a path the operator names and never sends anything,
// so an offline or scripted crash can be captured without enabling telemetry.
//
// The report never records a flag *value*, only the command path and flag
// *names*, because values routinely carry credentials, repository names, or
// private filesystem paths (`--token`, `--repo`, `--rules`, ...).
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

// crashReportFlagName is the root persistent flag that opts a process into
// writing a local crash report. The empty default leaves crash behaviour
// unchanged: handleCrash re-panics, so the telemetry path still runs.
const crashReportFlagName = "crash-report"

// crashReportPath is bound to crashReportFlagName and read by handleCrash.
var crashReportPath string

func init() {
	Root.PersistentFlags().StringVar(&crashReportPath, crashReportFlagName, "",
		"write a local, secret-free crash report to this path if pleno-dlp panics "+
			"(disabled by default). The report records the command path, flag names "+
			"(never flag values), version, and stack; it is never sent anywhere.")
}

// crashReport is the on-disk schema for --crash-report. It is intentionally
// small and stable: enough to attribute and reproduce a failure without any
// secret material.
type crashReport struct {
	Schema     int    `json:"schema"`
	Timestamp  string `json:"timestamp"`
	Version    string `json:"version"`
	Commit     string `json:"commit,omitempty"`
	GoVersion  string `json:"go_version"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Invocation string `json:"invocation"`
	Panic      string `json:"panic"`
	Stack      string `json:"stack"`
}

// newCrashReport builds a report for a recovered panic value. invocation is
// supplied by the caller so tests (and future non-os.Args callers) can pin
// it; production passes invocationDescription(os.Args[1:]).
func newCrashReport(panicValue any, invocation string) crashReport {
	return crashReport{
		Schema:     1,
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Version:    toolVersion,
		Commit:     toolCommit,
		GoVersion:  runtime.Version(),
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Invocation: invocation,
		Panic:      fmt.Sprint(panicValue),
		Stack:      string(debug.Stack()),
	}
}

// invocationDescription renders a secret-free one-line description of the
// command line: the resolved command path followed by every recognised flag
// name, including a root/persistent flag given before its subcommand (see
// DescribeInvocation). Values and positional arguments never appear.
func invocationDescription(args []string) string {
	command, flags := DescribeInvocation(args)
	parts := make([]string, 0, 2+len(flags))
	parts = append(parts, Root.Name())
	if command != "" {
		parts = append(parts, command)
	}
	for _, f := range flags {
		parts = append(parts, "--"+f)
	}
	return strings.Join(parts, " ")
}

// writeCrashReport serializes r to path, creating parent directories 0700
// and the file 0600 — a report can contain local paths even though it never
// contains flag values.
func writeCrashReport(path string, r crashReport) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("crash-report: encode: %w", err)
	}
	data = append(data, '\n')
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("crash-report: create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("crash-report: write %s: %w", path, err)
	}
	return nil
}

// handleCrash is the panic path used by Execute. When the operator did not
// opt in it re-panics unchanged, preserving the telemetry crash path and
// normal Go crash behaviour; when they did, it writes the report and returns
// a plain error so main.go still exits non-zero with a readable message.
func handleCrash(panicValue any) error {
	if crashReportPath == "" {
		panic(panicValue)
	}
	report := newCrashReport(panicValue, invocationDescription(os.Args[1:]))
	if err := writeCrashReport(crashReportPath, report); err != nil {
		fmt.Fprintf(os.Stderr, "pleno-dlp: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "pleno-dlp: crash report written to %s\n", crashReportPath)
	}
	return fmt.Errorf("internal error: %v", panicValue)
}
