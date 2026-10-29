// Command pleno-dlp wires build metadata, registries, crash reporting, and
// exit codes.
package main

import (
	"context"
	"errors"
	"os"
	"runtime/debug"

	"github.com/plenoai/pleno-dlp/cmd/pleno-dlp/cmd"
	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"

	// Activate detector and source self-registration.
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
	_ "github.com/plenoai/pleno-dlp/pkg/sources/all"

	"github.com/plenoai/pleno-dlp/pkg/termsafe"
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

	// With crash reports enabled the process becomes a thin supervisor and
	// exits with the child's status; otherwise it runs the CLI in-process.
	code, err := rt.Supervise(ctx, os.Args, os.Environ())
	if err == nil {
		os.Exit(code)
	}
	if !errors.Is(err, crash.ErrNotSupervised) {
		termsafe.Fprintf(os.Stderr, "pleno-dlp: crash supervisor unavailable, running unsupervised: %v\n", err)
	}

	err = rt.Recover(os.Args[1:], func() error { return cmd.Execute(ctx) })
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
	termsafe.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(2)
}
