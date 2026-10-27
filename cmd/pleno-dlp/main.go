// Command pleno-dlp wires build metadata, registries, crash reporting, and
// exit codes.
package main

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"

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

// buildInfoVersion fills version and commit from the module build info when
// the binary was produced by `go install module@vX.Y.Z` (mise, pre-commit's
// golang language) instead of GoReleaser's -ldflags. Without this every such
// binary reports "dev (none)", and so would its crash reports.
func buildInfoVersion(version, commit string) (string, string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version, commit
	}
	if version == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version
	}
	if commit == "none" {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 7 {
				commit = s.Value[:7]
			}
		}
	}
	return version, commit
}

func main() {
	version, commit := buildInfoVersion(version, commit)
	cmd.SetVersion(version, commit)
	ctx := context.Background()
	rt := crash.New(version, commit, cmd.DescribeInvocation)

	// Close only after Execute returns: a deferred Close would unlink the
	// spool while a panic unwinds, before the runtime writes its fatal dump.
	session, installErr := crash.Install(crash.CaptureConfig{})
	if installErr != nil {
		fmt.Fprintln(os.Stderr, "warning: crash capture disabled:", installErr)
	} else if session.Dir() != "" && os.Getenv(crash.EnvReport) == "1" {
		if n, err := crash.ReportPending(session.Dir(), os.Stderr); err != nil {
			fmt.Fprintln(os.Stderr, "warning: read previous crash dumps:", err)
		} else if n > 0 {
			fmt.Fprintf(os.Stderr, "pleno-dlp: reported %d previous crash dump(s)\n", n)
		}
	}
	defer crash.Recover()

	err := rt.Recover(os.Args[1:], func() error { return cmd.Execute(ctx) })
	session.Close()
	if err == nil {
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
