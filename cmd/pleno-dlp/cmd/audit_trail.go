// Shared audit-trail wiring for every revoke code path (issue #304):
// `revoke --detector/--secret` (single), `revoke --revoke-from-spool`
// (spool), and `scan --revoke-on-verified` (on-verified). The schema
// itself lives in pkg/audit; this file only owns where the JSONL stream
// goes for a given CLI invocation.
package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/audit"
)

// auditTrailFlagName is shared by `revoke` and `scan` so both surfaces
// document and accept the same flag.
const auditTrailFlagName = "audit-trail"

const auditTrailFlagHelp = "path to append the JSON Lines audit trail (schema v1, see docs/audit-trail-schema.md). " +
	"Every revoke attempt on this path appends one record. Omit to write the trail to stderr instead of a file " +
	"(the trail is never silently dropped)."

// openAuditTrail resolves the --audit-trail destination for one command
// invocation. An empty path is not "disabled" — it means "write to this
// command's stderr" so a trail record is emitted unconditionally,
// matching the success criterion that every revoke emits a trail record
// regardless of whether an operator opted into a durable file.
//
// The returned close func is always safe to defer and call exactly
// once; it is a no-op for the stderr fallback.
func openAuditTrail(cmd *cobra.Command, path string) (*audit.Writer, func() error, error) {
	if path == "" {
		return audit.NewWriter(cmd.ErrOrStderr()), func() error { return nil }, nil
	}
	// O_APPEND (not the revoke-spool's O_TRUNC): an audit trail is
	// meant to accumulate across invocations, not be replaced by the
	// next run — the whole point is a durable record of every attempt.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("audit-trail: open %q: %w", path, err)
	}
	// Harden permissions even if the file already existed with looser
	// ones, mirroring newSpoolSink's rationale: the trail records
	// secret hashes and provider ids, not raw credentials, but there is
	// no reason to leave it group/world readable by default.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("audit-trail: chmod 0600 %q: %w", path, err)
	}
	return audit.NewWriter(f), f.Close, nil
}

// writeAuditRecord appends rec and logs (never fails the caller) on a
// write error. A trail-write failure must never block or reverse an
// already-issued revoke — the revoke result is the thing that matters;
// losing an audit line is a degraded-observability event, not a fatal
// one.
func writeAuditRecord(logW io.Writer, w *audit.Writer, rec audit.Record) {
	if err := w.Write(rec); err != nil {
		fmt.Fprintf(logW, "audit-trail: write failed for %s: %v\n", rec.Detector, err)
	}
}
