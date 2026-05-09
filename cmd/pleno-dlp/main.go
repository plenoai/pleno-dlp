// Command pleno-dlp is a Go-native secret scanner with a
// trufflehog-compatible detector layer and a fresh source-connector layer.
//
// Subcommand wiring lives in cmd/pleno-dlp/cmd/*.go. This file
// is intentionally thin: build metadata injection, blank-import manifests,
// and the exit-code mapping are the only concerns here.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/plenoai/pleno-dlp/cmd/pleno-dlp/cmd"

	// Blank-imports activate detector and source self-registration. Each
	// concrete provider lives behind a manifest package so adding one is a
	// one-line edit there, not here.
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
	// Verify-failed is a "negative result" rather than an error: the
	// provider responded cleanly with 401/403, the call itself succeeded.
	// Map it to exit 1 to match `IsFindingsError` so CI scripts can dispatch
	// uniformly on "command ran but the answer is no".
	if cmd.IsVerifyError(err) {
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(2)
}
