// `pleno-dlp revoke` revokes a leaked credential through the provider API.
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
	awsdet "github.com/plenoai/pleno-dlp/pkg/detectors/aws"
	githubdet "github.com/plenoai/pleno-dlp/pkg/detectors/github"
	gitlabdet "github.com/plenoai/pleno-dlp/pkg/detectors/gitlab"
	slackdet "github.com/plenoai/pleno-dlp/pkg/detectors/slack"
	stripedet "github.com/plenoai/pleno-dlp/pkg/detectors/stripe"
	"github.com/plenoai/pleno-dlp/pkg/verify"
)

// revokeFlags collects `pleno-dlp revoke` options.
type revokeFlags struct {
	detector     string
	secret       string
	fromSpool    string
	clientID     string
	clientSecret string
	githubMode   string
	confirm      bool
	dryRun       bool
	format       string
	rateLimitRPS int

	awsAdminAccessKeyID     string
	awsAdminSecretAccessKey string
	awsAdminSessionToken    string
	awsRegion               string
	awsUserName             string
}

var revokeOpts revokeFlags

const EnvAllowRevoke = "PLENO_DLP_ALLOW_REVOKE"

var revokeCmd = &cobra.Command{
	Use:   "revoke (--detector <name> --secret <value|-> | --revoke-from-spool <path>)",
	Short: "Revoke a leaked credential against the issuing provider",
	Long: "Revoke a leaked credential against the issuing provider. Irreversible.\n\n" +
		"Pass `--secret -` to read the leaked credential from stdin (recommended:\n" +
		"keeps the value out of shell history). GitHub defaults to auto mode:\n" +
		"OAuth-app credentials use DELETE /applications/{client_id}/token;\n" +
		"otherwise PATs are revoked via POST /credentials/revoke. Override with\n" +
		"--github-revoke-mode or " + githubdet.EnvRevokeMode + ".\n\n" +
		"Batch mode: `--revoke-from-spool <path>` consumes a JSONL spool file\n" +
		"emitted by `pleno-dlp scan --revoke-spool`. Each line carries its own\n" +
		"detector and raw secret so --detector/--secret become optional in batch\n" +
		"mode. Gating still applies once for the whole batch.\n\n" +
		"Gating (ADR-0001 D6): one of --confirm or --dry-run is mandatory.\n" +
		"Non-interactive contexts (CI, pipes) MUST also set " + EnvAllowRevoke + "=1.",
	Args: cobra.NoArgs,
	RunE: runRevoke,
}

func init() {
	revokeCmd.Flags().StringVar(&revokeOpts.detector, "detector", "", "detector type whose leaked secret should be revoked (supported: github, gitlab, slack, aws, stripe)")
	revokeCmd.Flags().StringVar(&revokeOpts.secret, "secret", "", "the leaked credential, or `-` to read it from stdin")
	revokeCmd.Flags().StringVar(&revokeOpts.clientID, "client-id", "", "OAuth app client_id (GitHub: overrides "+githubdet.EnvClientID+")")
	revokeCmd.Flags().StringVar(&revokeOpts.clientSecret, "client-secret", "", "OAuth app client_secret (GitHub: overrides "+githubdet.EnvClientSecret+")")
	revokeCmd.Flags().StringVar(&revokeOpts.githubMode, "github-revoke-mode", "", "GitHub revoke mode: auto, credentials, oauth-app (overrides "+githubdet.EnvRevokeMode+")")
	revokeCmd.Flags().StringVar(&revokeOpts.awsAdminAccessKeyID, "aws-admin-access-key-id", "", "AWS admin access key id used to call iam:DeleteAccessKey (overrides "+awsdet.EnvAdminAccessKeyID+")")
	revokeCmd.Flags().StringVar(&revokeOpts.awsAdminSecretAccessKey, "aws-admin-secret-access-key", "", "AWS admin secret access key (overrides "+awsdet.EnvAdminSecretAccessKey+")")
	revokeCmd.Flags().StringVar(&revokeOpts.awsAdminSessionToken, "aws-admin-session-token", "", "AWS admin session token, optional (overrides "+awsdet.EnvAdminSessionToken+")")
	revokeCmd.Flags().StringVar(&revokeOpts.awsRegion, "aws-region", "", "AWS region for IAM endpoint (overrides "+awsdet.EnvRegion+", default us-east-1)")
	revokeCmd.Flags().StringVar(&revokeOpts.awsUserName, "aws-user-name", "", "IAM user that owns the leaked access key (required for AWS revoke; overrides "+awsdet.EnvUserName+")")
	revokeCmd.Flags().BoolVar(&revokeOpts.confirm, "confirm", false, "explicit acknowledgement that revoke is irreversible (mutually required with non-interactive runs alongside "+EnvAllowRevoke+"=1)")
	revokeCmd.Flags().BoolVar(&revokeOpts.dryRun, "dry-run", false, "print the planned revoke without contacting the provider")
	revokeCmd.Flags().StringVar(&revokeOpts.format, "format", "table", "output format: table, json")
	revokeCmd.Flags().IntVar(&revokeOpts.rateLimitRPS, "rate-limit-rps", 0, "per-host requests-per-second cap during revoke (0 = disabled). Useful when revoking many secrets in a loop to avoid provider rate limits.")
	revokeCmd.Flags().StringVar(&revokeOpts.fromSpool, "revoke-from-spool", "",
		"path to a JSONL spool file produced by `pleno-dlp scan --revoke-spool`. "+
			"Each line is dispatched to the per-detector Revoker. --detector/--secret are ignored in this mode.")

	Root.AddCommand(revokeCmd)
}

// errRevokeRefused means the CLI gate refused to run.
var errRevokeRefused = errors.New("revoke: refused by gate")

// errRevokeFailed means the provider declined or could not be reached.
var errRevokeFailed = errors.New("revoke: provider rejected or unavailable")

func IsRevokeRefused(err error) bool { return errors.Is(err, errRevokeRefused) }

func IsRevokeFailed(err error) bool { return errors.Is(err, errRevokeFailed) }

func runRevoke(cmd *cobra.Command, _ []string) error {
	if revokeOpts.fromSpool == "" && revokeOpts.detector == "" {
		return errors.New("--detector is required (or use --revoke-from-spool)")
	}
	if !revokeOpts.confirm && !revokeOpts.dryRun {
		fmt.Fprintln(cmd.ErrOrStderr(), "revoke: refusing to proceed without --confirm or --dry-run (irreversible operation)")
		return errRevokeRefused
	}
	if revokeOpts.confirm && !revokeOpts.dryRun {
		if !isInteractiveStdin(cmd.InOrStdin()) && os.Getenv(EnvAllowRevoke) != "1" {
			fmt.Fprintf(cmd.ErrOrStderr(),
				"revoke: refusing to proceed in a non-interactive context without %s=1\n", EnvAllowRevoke)
			return errRevokeRefused
		}
	}

	if revokeOpts.fromSpool != "" {
		return runRevokeFromSpool(cmd, revokeOpts.fromSpool)
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

	if revokeOpts.rateLimitRPS > 0 {
		prev := verify.Install(revokeOpts.rateLimitRPS)
		defer verify.Restore(prev)
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

// resolveRevoker maps --detector to a concrete Revoker and DetectorType.
func resolveRevoker(name string) (detectors.Revoker, detectors.DetectorType, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "github":
		if revokeOpts.clientID != "" || revokeOpts.clientSecret != "" {
			githubdet.SetRevokeCredentials(revokeOpts.clientID, revokeOpts.clientSecret)
		}
		if revokeOpts.githubMode != "" {
			githubdet.SetRevokeMode(revokeOpts.githubMode)
		}
		return githubdet.Scanner{}, detectors.GitHub, nil
	case "gitlab":
		return gitlabdet.Scanner{}, detectors.GitLab, nil
	case "slack":
		return slackdet.Scanner{}, detectors.SlackBotToken, nil
	case "stripe":
		return stripedet.Scanner{}, detectors.Stripe, nil
	case "aws":
		if revokeOpts.awsAdminAccessKeyID != "" || revokeOpts.awsAdminSecretAccessKey != "" ||
			revokeOpts.awsAdminSessionToken != "" || revokeOpts.awsRegion != "" || revokeOpts.awsUserName != "" {
			awsdet.SetRevokeCredentials(
				revokeOpts.awsAdminAccessKeyID,
				revokeOpts.awsAdminSecretAccessKey,
				revokeOpts.awsAdminSessionToken,
				revokeOpts.awsRegion,
				revokeOpts.awsUserName,
			)
		}
		return awsdet.Scanner{}, detectors.AWS, nil
	default:
		return nil, detectors.Unknown, fmt.Errorf("--detector %q: revoke not supported (supported: github, gitlab, slack, aws, stripe)", name)
	}
}

// resolveSecret returns the secret to revoke.
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
