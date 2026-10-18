// Command pleno-dlp wires build metadata, registries, crash reporting, and
// exit codes.
package main

import (
	"context"
	"errors"
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
	ctx := context.Background()
	rt := crash.New(version, commit, cmd.DescribeInvocation)

	// With crash reports enabled the process becomes a thin supervisor and
	// exits with the child's status; otherwise it runs the CLI in-process.
	code, err := rt.Supervise(ctx, os.Args, os.Environ())
	if err == nil {
		os.Exit(code)
	}
	if !errors.Is(err, crash.ErrNotSupervised) {
		fmt.Fprintln(os.Stderr, "pleno-dlp: crash supervisor unavailable, running unsupervised:", err)
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
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(2)
}
