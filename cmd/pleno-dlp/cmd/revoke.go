// `pleno-dlp revoke` — revoke a leaked credential against the issuing
// provider's revocation API. ADR-0001 D6 names the CLI as the single
// gating choke point: detectors / connectors expose Revoke through the
// detectors.Revoker contract WITHOUT local guards, and this command
// enforces uniform `--confirm` / `--dry-run` / PLENO_DLP_ALLOW_REVOKE
// policy across every provider.
//
// The first (and only, for the v1 scope of issue #73) supported
// detector is `GitHub`. Adding more is a one-line edit to
// resolveRevoker — every provider that implements detectors.Revoker
// against its leaked-credential class plugs in here without schema
// changes.
package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	githubdet "github.com/plenoai/pleno-dlp/pkg/detectors/github"
)

// revokeFlags collects everything `pleno-dlp revoke` needs. Held in a
// dedicated struct so resetRevokeOpts (test helper) can restore defaults
// between subtests without touching every cobra flag binding.
type revokeFlags struct {
	detector     string
	secret       string
	clientID     string
	clientSecret string
	confirm      bool
	dryRun       bool
	format       string
}

var revokeOpts revokeFlags

// EnvAllowRevoke gates revoke from non-TTY contexts. ADR-0001 D6 names
// it explicitly so a misconfigured CI cannot accidentally blow up live
// credentials. The variable is exported so tests can assert against the
// same constant the implementation reads.
const EnvAllowRevoke = "PLENO_DLP_ALLOW_REVOKE"

var revokeCmd = &cobra.Command{
	Use:   "revoke --detector <name> --secret <value|->",
	Short: "Revoke a leaked credential against the issuing provider",
	Long: "Revoke a leaked credential against the issuing provider. Irreversible.\n\n" +
		"Pass `--secret -` to read the leaked credential from stdin (recommended:\n" +
		"keeps the value out of shell history). For GitHub, the OAuth-app\n" +
		"credentials needed for the DELETE /applications/{client_id}/token call\n" +
		"come from --client-id / --client-secret (overrides) or the\n" +
		"PLENO_DLP_REVOKE_GITHUB_CLIENT_ID / PLENO_DLP_REVOKE_GITHUB_CLIENT_SECRET\n" +
		"env vars.\n\n" +
		"Gating (ADR-0001 D6): one of --confirm or --dry-run is mandatory.\n" +
		"Non-interactive contexts (CI, pipes) MUST also set " + EnvAllowRevoke + "=1.",
	Args: cobra.NoArgs,
	RunE: runRevoke,
}

func init() {
	revokeCmd.Flags().StringVar(&revokeOpts.detector, "detector", "", "detector type whose leaked secret should be revoked (e.g. GitHub)")
	revokeCmd.Flags().StringVar(&revokeOpts.secret, "secret", "", "the leaked credential, or `-` to read it from stdin")
	revokeCmd.Flags().StringVar(&revokeOpts.clientID, "client-id", "", "OAuth app client_id (GitHub: overrides "+githubdet.EnvClientID+")")
	revokeCmd.Flags().StringVar(&revokeOpts.clientSecret, "client-secret", "", "OAuth app client_secret (GitHub: overrides "+githubdet.EnvClientSecret+")")
	revokeCmd.Flags().BoolVar(&revokeOpts.confirm, "confirm", false, "explicit acknowledgement that revoke is irreversible (mutually required with non-interactive runs alongside "+EnvAllowRevoke+"=1)")
	revokeCmd.Flags().BoolVar(&revokeOpts.dryRun, "dry-run", false, "print the planned revoke without contacting the provider")
	revokeCmd.Flags().StringVar(&revokeOpts.format, "format", "table", "output format: table, json")
	_ = revokeCmd.MarkFlagRequired("detector")

	Root.AddCommand(revokeCmd)
}

// errRevokeRefused signals "the gating policy refused to run". main.go
// could map this to a distinct exit code (we use 2 to match invalid
// usage); separated from a transport-level failure so scripted callers
// can distinguish "you asked us not to do this" from "we tried and it
// failed".
var errRevokeRefused = errors.New("revoke: refused by gate")

// errRevokeFailed signals "we tried to revoke and the provider declined
// or unavailable". Maps to exit 1 — distinct from errRevokeRefused (gate
// refusal) and from generic flag parse errors.
var errRevokeFailed = errors.New("revoke: provider rejected or unavailable")

// IsRevokeRefused reports whether err came from the gating logic refusing
// to proceed. main.go uses this to map to exit 2 (invalid usage shape).
func IsRevokeRefused(err error) bool { return errors.Is(err, errRevokeRefused) }

// IsRevokeFailed reports whether err came from a provider rejection.
// main.go maps this to exit 1.
func IsRevokeFailed(err error) bool { return errors.Is(err, errRevokeFailed) }

func runRevoke(cmd *cobra.Command, _ []string) error {
	if revokeOpts.detector == "" {
		return errors.New("--detector is required")
	}
	if !revokeOpts.confirm && !revokeOpts.dryRun {
		fmt.Fprintln(cmd.ErrOrStderr(), "revoke: refusing to proceed without --confirm or --dry-run (irreversible operation)")
		return errRevokeRefused
	}
	if revokeOpts.confirm && !revokeOpts.dryRun {
		// Non-interactive callers (pipes, CI) MUST set the env override
		// in addition to --confirm. TTY-attached operators get the
		// shorter `--confirm` UX. The check is best-effort: if Stdin is
		// not an *os.File (test buffer), we treat it as non-interactive
		// to keep CI behaviour predictable.
		if !isInteractiveStdin(cmd.InOrStdin()) && os.Getenv(EnvAllowRevoke) != "1" {
			fmt.Fprintf(cmd.ErrOrStderr(),
				"revoke: refusing to proceed in a non-interactive context without %s=1\n", EnvAllowRevoke)
			return errRevokeRefused
		}
	}

	secret, err := resolveSecret(cmd, revokeOpts.secret)
	if err != nil {
		return err
	}
	if secret == "" {
		return errors.New("--secret is required (or pipe via --secret -)")
	}

	r, detectorType, err := resolveRevoker(revokeOpts.detector)
	if err != nil {
		return err
	}

	redacted := redactSecret(secret)

	if revokeOpts.dryRun {
		emitRevoke(cmd, revokeOpts.format, revokeRecord{
			Detector:       detectorType.String(),
			RedactedSecret: redacted,
			Revoked:        false,
			DryRun:         true,
		})
		return nil
	}

	ctx, cancel := context.WithTimeout(cmdContext(cmd), 30*time.Second)
	defer cancel()
	res, runErr := r.Revoke(ctx, secret)

	rec := revokeRecord{
		Detector:       detectorType.String(),
		RedactedSecret: redacted,
		Revoked:        res.Revoked,
		ProviderID:     res.ProviderID,
	}
	if !res.RevokedAt.IsZero() {
		rec.RevokedAt = res.RevokedAt.UTC().Format(time.RFC3339)
	}
	switch {
	case runErr != nil:
		rec.Error = runErr.Error()
	case res.Err != nil:
		rec.Error = res.Err.Error()
	}
	emitRevoke(cmd, revokeOpts.format, rec)

	if runErr != nil {
		return errRevokeFailed
	}
	if !res.Revoked {
		return errRevokeFailed
	}
	return nil
}

// resolveRevoker maps the user-facing --detector name to the concrete
// detectors.Revoker implementation plus the wire-stable DetectorType
// for the JSON output. Keep this function explicit (not registry-driven)
// for v1: the policy of *which* detectors expose a CLI revoke is a
// product decision, and routing should not silently expand whenever a
// detector grows a Revoke method without a CLI plumbing review.
func resolveRevoker(name string) (detectors.Revoker, detectors.DetectorType, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "github":
		// CLI overrides win; empty values fall back to the env vars
		// inside the github package's loadRevokeCreds helper.
		if revokeOpts.clientID != "" || revokeOpts.clientSecret != "" {
			githubdet.SetRevokeCredentials(revokeOpts.clientID, revokeOpts.clientSecret)
		}
		return githubdet.Scanner{}, detectors.GitHub, nil
	default:
		return nil, detectors.Unknown, fmt.Errorf("--detector %q: revoke not supported (supported: github)", name)
	}
}

// resolveSecret returns the secret to revoke. `--secret -` reads from
// stdin (with a 1 KiB cap so a pipe accident doesn't OOM); any other
// value passes through verbatim. Trailing whitespace is trimmed because
// `echo "ghp_..." | pleno-dlp revoke ...` always sends a trailing
// newline.
func resolveSecret(cmd *cobra.Command, raw string) (string, error) {
	if raw != "-" {
		return strings.TrimSpace(raw), nil
	}
	r := bufio.NewReader(cmd.InOrStdin())
	const maxSecretBytes = 1024
	buf, err := io.ReadAll(io.LimitReader(r, maxSecretBytes+1))
	if err != nil {
		return "", fmt.Errorf("read secret from stdin: %w", err)
	}
	if len(buf) > maxSecretBytes {
		return "", fmt.Errorf("read secret from stdin: input exceeds %d bytes", maxSecretBytes)
	}
	return strings.TrimSpace(string(buf)), nil
}

// isInteractiveStdin reports whether the command's stdin is a terminal.
// Returns false for any non-*os.File reader (cobra test buffer, piped
// fd, redirected file) so CI is treated as non-interactive by default.
func isInteractiveStdin(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// redactSecret renders a safe-to-log prefix view of the secret. Same
// shape as detectors.Result.Redacted (`prefix + ...`) so audit logs
// across scan and revoke share a single redaction style.
func redactSecret(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:8] + "..."
}

// revokeRecord is the structured shape rendered by --format json. Keep
// fields stable across releases — downstream callers (audit pipelines,
// SOAR runbooks) parse this output.
type revokeRecord struct {
	Detector       string `json:"detector"`
	RedactedSecret string `json:"redacted_secret"`
	Revoked        bool   `json:"revoked"`
	RevokedAt      string `json:"revoked_at,omitempty"`
	ProviderID     string `json:"provider_id,omitempty"`
	DryRun         bool   `json:"dry_run,omitempty"`
	Error          string `json:"error,omitempty"`
}

// emitRevoke writes the record to stdout (json) or stderr (table). The
// split mirrors `pleno-dlp scan` — structured output stays on stdout so
// pipelines can consume it cleanly; the human-readable summary goes to
// stderr so it doesn't collide with json.
func emitRevoke(cmd *cobra.Command, format string, rec revokeRecord) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		// JSON line on stdout. One record per command invocation.
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(rec)
		return
	default:
		// Table-style: human-readable line on stderr.
		switch {
		case rec.DryRun:
			fmt.Fprintf(cmd.ErrOrStderr(), "DRY-RUN: would revoke %s secret %s\n", rec.Detector, rec.RedactedSecret)
		case rec.Revoked && rec.Error == "":
			fmt.Fprintf(cmd.ErrOrStderr(), "OK: revoked %s secret %s\n", rec.Detector, rec.RedactedSecret)
		case rec.Revoked && rec.Error != "":
			fmt.Fprintf(cmd.ErrOrStderr(), "OK: revoked (idempotent) %s secret %s — %s\n", rec.Detector, rec.RedactedSecret, rec.Error)
		case !rec.Revoked && rec.Error != "":
			fmt.Fprintf(cmd.ErrOrStderr(), "FAIL: %s secret %s — %s\n", rec.Detector, rec.RedactedSecret, rec.Error)
		default:
			fmt.Fprintf(cmd.ErrOrStderr(), "FAIL: %s secret %s — provider declined revocation\n", rec.Detector, rec.RedactedSecret)
		}
	}
}

// resetRevokeOpts restores defaults — used by tests because cobra retains
// last-seen flag values across calls within a process.
func resetRevokeOpts() {
	revokeOpts = revokeFlags{format: "table"}
}
