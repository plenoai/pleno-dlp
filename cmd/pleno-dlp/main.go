// Command pleno-dlp wires build metadata, registries, and exit codes.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/plenoai/pleno-dlp/cmd/pleno-dlp/cmd"

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
	err := cmd.Execute(context.Background())
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
