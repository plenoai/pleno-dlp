// Command pleno-secret-scanner is a Go-native secret scanner with a
// trufflehog-compatible detector layer and a fresh source-connector layer.
//
// Subcommands are added under pkg-internal cmd/ files (filesystem.go,
// git.go, github.go, ...) by core-engineer. This entrypoint is intentionally
// thin so that subcommand wiring stays where it belongs.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	root := &cobra.Command{
		Use:           "pleno-secret-scanner",
		Short:         "Scan sources for leaked secrets",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       fmt.Sprintf("%s (%s)", version, commit),
	}
	// Subcommands (filesystem, git, github, ...) are registered by their own
	// init() functions in cmd/pleno-secret-scanner/cmd/*.go.
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
