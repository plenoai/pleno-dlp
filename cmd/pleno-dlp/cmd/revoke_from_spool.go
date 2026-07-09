// `revoke --revoke-from-spool` consumes a JSONL spool produced by
// `scan --revoke-spool` and dispatches each line to the per-detector
// Revoker. The spool format is owned by revoke_spool.go (spoolRecord
// + spoolRecordVersion) — schema changes happen there.
//
// One spool line → one revoke attempt → one emitted revokeRecord. The
// command exits non-zero if any attempt fails so a CI gate can detect
// partial failure; we don't short-circuit because revoking 99/100 is
// still useful work and the operator wants to see which one failed.
package cmd

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/audit"
	"github.com/plenoai/pleno-dlp/pkg/verify"
)

func runRevokeFromSpool(cmd *cobra.Command, path string, auditW *audit.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("revoke-from-spool: open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if revokeOpts.rateLimitRPS > 0 {
		prev := verify.Install(revokeOpts.rateLimitRPS)
		defer verify.Restore(prev)
	}

	// Buffered scan tolerates large per-line records. 1 MiB is well
	// above any plausible single secret.
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var (
		attempted int
		revoked   int
		failed    int
		skipped   int
		lineNo    int
	)
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec spoolRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			failed++
			fmt.Fprintf(cmd.ErrOrStderr(), "revoke-from-spool: line %d: parse failed: %v\n", lineNo, err)
			continue
		}
		if rec.Version != spoolRecordVersion {
			skipped++
			fmt.Fprintf(cmd.ErrOrStderr(), "revoke-from-spool: line %d: unsupported spool version %d (this binary handles %d)\n", lineNo, rec.Version, spoolRecordVersion)
			continue
		}
		secret, derr := base64.StdEncoding.DecodeString(rec.SecretB64)
		if derr != nil {
			failed++
			fmt.Fprintf(cmd.ErrOrStderr(), "revoke-from-spool: line %d: decode secret_b64: %v\n", lineNo, derr)
			continue
		}
		r, detectorType, rerr := resolveRevoker(strings.ToLower(rec.Detector))
		if rerr != nil {
			skipped++
			fmt.Fprintf(cmd.ErrOrStderr(), "revoke-from-spool: line %d: %v\n", lineNo, rerr)
			continue
		}
		attempted++
		redacted := rec.Redacted
		if redacted == "" {
			redacted = redactSecret(string(secret))
		}

		if revokeOpts.dryRun {
			emitRevoke(cmd, revokeOpts.format, revokeRecord{
				Detector:       detectorType.String(),
				RedactedSecret: redacted,
				DryRun:         true,
			})
			writeAuditRecord(cmd.ErrOrStderr(), auditW, audit.New(audit.Attempt{
				Path:       audit.PathSpool,
				Detector:   detectorType.String(),
				Secret:     string(secret),
				Redacted:   redacted,
				DryRun:     true,
				TargetLink: rec.SourceLink,
			}))
			continue
		}

		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		res, runErr := r.Revoke(ctx, string(secret))
		cancel()

		out := revokeRecord{
			Detector:       detectorType.String(),
			RedactedSecret: redacted,
			Revoked:        res.Revoked,
			ProviderID:     res.ProviderID,
		}
		if !res.RevokedAt.IsZero() {
			out.RevokedAt = res.RevokedAt.UTC().Format(time.RFC3339)
		}
		var attemptErr error
		switch {
		case runErr != nil:
			out.Error = runErr.Error()
			attemptErr = runErr
		case res.Err != nil:
			out.Error = res.Err.Error()
			attemptErr = res.Err
		}
		emitRevoke(cmd, revokeOpts.format, out)
		writeAuditRecord(cmd.ErrOrStderr(), auditW, audit.New(audit.Attempt{
			Path:       audit.PathSpool,
			Detector:   detectorType.String(),
			Secret:     string(secret),
			Redacted:   redacted,
			Revoked:    res.Revoked,
			RevokedAt:  res.RevokedAt,
			ProviderID: res.ProviderID,
			Err:        attemptErr,
			TargetLink: rec.SourceLink,
		}))
		if res.Revoked && runErr == nil {
			revoked++
		} else {
			failed++
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("revoke-from-spool: read %q: %w", path, err)
	}

	fmt.Fprintf(cmd.ErrOrStderr(),
		"revoke-from-spool: lines=%d attempted=%d revoked=%d failed=%d skipped=%d dry-run=%t\n",
		lineNo, attempted, revoked, failed, skipped, revokeOpts.dryRun,
	)
	if failed > 0 {
		return errRevokeFailed
	}
	return nil
}
