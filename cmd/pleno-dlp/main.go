// Command pleno-dlp wires build metadata, registries, and exit codes.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/plenoai/pleno-dlp/cmd/pleno-dlp/cmd"
	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"

	// Activate detector and source self-registration.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
	_ "github.com/plenoai/pleno-dlp/pkg/sources/all"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	cmd.SetVersion(version, commit)

	// Capture crashes in-process with the runtime's own crash writer
	// (Go 1.23+ debug.SetCrashOutput) instead of re-executing a
	// supervisor that scraped stderr. Best-effort: if the spool cannot be
	// set up, keep scanning rather than refuse to run.
	//
	// The session is deliberately closed only on the clean-return path
	// below, never deferred: Close unlinks the (empty) spool file, and a
	// deferred Close would also run while a panic unwinds main, deleting
	// the file out from under the runtime's crash writer just before it
	// writes the dump.
	session, installErr := crash.Install(crash.Config{})
	if installErr != nil {
		fmt.Fprintln(os.Stderr, "warning: crash capture disabled:", installErr)
	} else if os.Getenv(crash.EnvReport) == "1" {
		// Surface dumps left by earlier crashes only when reporting is
		// opted into; otherwise leave them in the spool for inspection.
		if n, err := crash.ReportPending(session.Dir(), os.Stderr); err != nil {
			fmt.Fprintln(os.Stderr, "warning: read previous crash dumps:", err)
		} else if n > 0 {
			fmt.Fprintf(os.Stderr, "pleno-dlp: reported %d previous crash dump(s)\n", n)
		}
	}
	// Recover covers a main-goroutine panic that something else would
	// otherwise swallow; it spools the panic and re-raises it, after which
	// the runtime's crash writer records the fatal dump.
	defer crash.Recover()

	err := cmd.Execute(context.Background())
	if err == nil {
		if session != nil {
			session.Close()
		}
		return
	}
	if cmd.IsFindingsError(err) {
		os.Exit(1)
	}
	// Treat verify-failed like findings: the command succeeded, the answer was "no".
	if cmd.IsVerifyError(err) {
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(2)
}
