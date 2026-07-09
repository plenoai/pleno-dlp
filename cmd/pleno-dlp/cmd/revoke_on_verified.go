// `scan --revoke-on-verified` plumbing (issue #73). Lives next to
// scan.go because the wrapping decision is a CLI concern: the engine
// itself has no opinion on revocation, only on detection. The sink
// chain inside runScanCommon is the right place to interpose because
// (a) findings have already passed dedup and allowlist by that point —
// false-positives never trigger a live revoke — and (b) every output
// format funnels through the same chain, so json / sarif / table
// callers all observe identical revoke behaviour.
package cmd

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/audit"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
)

// revokingSink wraps an inner Sink. When a finding is verified AND its
// detector implements detectors.Revoker, it dispatches the revoke
// before forwarding the finding downstream. When --revoke-dry-run is
// set, no provider call is made; only a stderr line is emitted so the
// operator can preview what would happen.
//
// Findings whose detector lacks Revoker are forwarded unchanged and
// counted in `skipped`. The end-of-scan summary surfaces all four
// counters so an operator running revoke at scale can confirm coverage
// without scraping per-finding output.
type revokingSink struct {
	inner    engine.Sink
	revokers map[detectors.DetectorType]detectors.Revoker
	dryRun   bool
	logW     io.Writer
	auditW   *audit.Writer

	attempted atomic.Int64
	revoked   atomic.Int64
	failed    atomic.Int64
	skipped   atomic.Int64
}

// newRevokingSink builds the per-DetectorType lookup once at scan
// start. Detectors that don't satisfy detectors.Revoker simply don't
// land in the map — Emit treats absent entries as "no revoker, skip".
// We dedup by type rather than by detector identity so the registered
// instance and any test double for the same Type share one entry; the
// last write wins, matching how detectors.Register handles duplicates.
// auditW receives one audit.Record per dispatched attempt (issue #304);
// it is never nil in production (openAuditTrail falls back to stderr).
func newRevokingSink(inner engine.Sink, dets []detectors.Detector, dryRun bool, logW io.Writer, auditW *audit.Writer) *revokingSink {
	revokers := make(map[detectors.DetectorType]detectors.Revoker, len(dets))
	for _, d := range dets {
		if r, ok := d.(detectors.Revoker); ok {
			revokers[d.Type()] = r
		}
	}
	return &revokingSink{inner: inner, revokers: revokers, dryRun: dryRun, logW: logW, auditW: auditW}
}

// Emit forwards the finding downstream first so the structured output
// (json / sarif / table) records the original detection. The actual
// provider call runs after the forward so a panicking provider call
// cannot silently drop findings the operator paid to scan.
//
// One exception to "forward first, decide after": for a finding that
// will be dispatched to revoke, a trail id is minted and stamped into
// f.Result.ExtraData["audit_trail_id"] BEFORE the forward. That step is
// pure local computation (hash the secret, format a timestamp) — it
// cannot panic or block the way a network call can — so it is safe to
// do ahead of the forward, and doing so is the only way the id can
// reach the scan's own json/sarif/table output at all: those sinks
// serialize the finding inside this same Emit call, before the
// eventual revoke outcome is known. `properties.audit_trail_id` in the
// SARIF (or `extra_data.audit_trail_id` in json) output is therefore
// how a finding correlates back to the full audit.Record — which
// carries the outcome — written to the audit trail below. See
// docs/audit-trail-schema.md.
func (r *revokingSink) Emit(f engine.Finding) {
	// Revoke only on a confirmed-live verdict. An Indeterminate verdict
	// (verification attempt failed — network error, provider 5xx, rate
	// limit) means liveness is unknown, not confirmed — dispatching a
	// revoke on that basis could invalidate a credential that was never
	// actually verified live. Verified==false already excludes
	// Indeterminate, but the explicit comparison
	// pins the guarantee against future refactors. See issue #246.
	verified := f.Result.Verdict() == detectors.VerdictVerified
	rev, hasRevoker := r.revokers[f.Detector]
	willAttempt := verified && hasRevoker

	secret := string(f.Result.Raw)
	redacted := f.Result.Redacted
	if redacted == "" {
		redacted = redactSecret(secret)
	}

	var now time.Time
	var trailID string
	if willAttempt {
		now = time.Now()
		hash := audit.HashSecret(secret)
		trailID = audit.NewTrailID(f.Detector.String(), hash, now)
		if f.Result.ExtraData == nil {
			f.Result.ExtraData = map[string]string{}
		}
		f.Result.ExtraData["audit_trail_id"] = trailID
	}

	r.inner.Emit(f)

	if !willAttempt {
		if verified {
			r.skipped.Add(1)
		}
		return
	}
	r.attempted.Add(1)
	targetLink := spoolSourceLink(f.Chunk)

	if r.dryRun {
		fmt.Fprintf(r.logW, "DRY-RUN revoke: %s %s\n", f.Detector.String(), redacted)
		writeAuditRecord(r.logW, r.auditW, audit.New(audit.Attempt{
			Path:       audit.PathOnVerified,
			Detector:   f.Detector.String(),
			Secret:     secret,
			Redacted:   redacted,
			DryRun:     true,
			TargetLink: targetLink,
			Now:        now,
		}))
		return
	}
	// Per-revoke timeout independent of the scan ctx so a slow
	// provider doesn't block the next finding's I/O.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := rev.Revoke(ctx, secret)
	var attemptErr error
	switch {
	case err != nil:
		r.failed.Add(1)
		attemptErr = err
		fmt.Fprintf(r.logW, "revoke FAIL: %s %s — %s\n", f.Detector.String(), redacted, err.Error())
	case res.Revoked && res.Err == nil:
		r.revoked.Add(1)
		fmt.Fprintf(r.logW, "revoke OK: %s %s\n", f.Detector.String(), redacted)
	case res.Revoked && res.Err != nil:
		r.revoked.Add(1)
		attemptErr = res.Err
		fmt.Fprintf(r.logW, "revoke OK (idempotent): %s %s — %s\n", f.Detector.String(), redacted, res.Err.Error())
	default:
		r.failed.Add(1)
		msg := "provider declined revocation"
		if res.Err != nil {
			msg = res.Err.Error()
			attemptErr = res.Err
		}
		fmt.Fprintf(r.logW, "revoke FAIL: %s %s — %s\n", f.Detector.String(), redacted, msg)
	}
	writeAuditRecord(r.logW, r.auditW, audit.New(audit.Attempt{
		Path:       audit.PathOnVerified,
		Detector:   f.Detector.String(),
		Secret:     secret,
		Redacted:   redacted,
		Revoked:    res.Revoked,
		RevokedAt:  res.RevokedAt,
		ProviderID: res.ProviderID,
		Err:        attemptErr,
		TargetLink: targetLink,
		Now:        now,
	}))
}

func (r *revokingSink) Close() error { return r.inner.Close() }
