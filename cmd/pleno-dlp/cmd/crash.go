// Local crash reports (`--crash-report <path>`).
//
// This complements the opt-in anonymized telemetry (pkg/telemetry/crash,
// docs/telemetry.md). Telemetry always spools a report and optionally sends
// it to a relay after opt-in; --crash-report instead writes the same
// secret-free report to a path the operator names and never sends anything,
// so an offline or scripted crash can be captured without enabling telemetry.
//
// The report is a plain crash.Report built with the shared Redactor and the
// canonical Encode, so it is byte-identical to what `telemetry show-last`
// prints. The report never records a flag *value*, only the command path and
// flag *names*, because values routinely carry credentials, repository names,
// or private filesystem paths (`--token`, `--repo`, `--rules`, ...).
package cmd

import (
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
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
			"(disabled by default). The report uses the same schema and redaction "+
			"as `telemetry show-last`; it is never sent anywhere.")
}

// handleCrash is the panic path used by Execute. When the operator did not
// opt in it re-panics unchanged, preserving the telemetry crash path and
// normal Go crash behaviour; when they did, it builds a crash.Report with the
// shared redactor, writes it with the canonical encoding, and returns a plain
// error so main.go still exits non-zero with a readable message.
func handleCrash(panicValue any) error {
	if crashReportPath == "" {
		panic(panicValue)
	}
	command, flags := DescribeInvocation(os.Args[1:])
	meta := crash.Meta{Version: toolVersion, Commit: toolCommit, Command: command, Flags: flags}
	report := crash.Build(crash.KindCrash, fmt.Sprintf("panic: %v", panicValue), string(debug.Stack()),
		meta, crash.NewRedactor(os.Getenv, detectors.All), time.Now())
	if err := crash.WriteFile(crashReportPath, report); err != nil {
		fmt.Fprintf(os.Stderr, "pleno-dlp: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "pleno-dlp: crash report written to %s\n", crashReportPath)
	}
	return fmt.Errorf("internal error: %v", panicValue)
}
