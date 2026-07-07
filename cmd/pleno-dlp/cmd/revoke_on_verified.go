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
func newRevokingSink(inner engine.Sink, dets []detectors.Detector, dryRun bool, logW io.Writer) *revokingSink {
	revokers := make(map[detectors.DetectorType]detectors.Revoker, len(dets))
	for _, d := range dets {
		if r, ok := d.(detectors.Revoker); ok {
			revokers[d.Type()] = r
		}
	}
	return &revokingSink{inner: inner, revokers: revokers, dryRun: dryRun, logW: logW}
}

// Emit forwards the finding downstream first so the structured output
// (json / sarif / table) records the original detection. Revocation
// runs after the forward so a panicking provider call cannot silently
// drop findings the operator paid to scan.
func (r *revokingSink) Emit(f engine.Finding) {
	r.inner.Emit(f)
	// Revoke only on a confirmed-live verdict. An Indeterminate verdict
	// (verification attempt failed — network error, provider 5xx, rate
	// limit) means liveness is unknown, not confirmed — dispatching a
	// revoke on that basis could invalidate a credential that was never
	// actually verified live. Verified==false already excludes
	// Indeterminate, but the explicit comparison
	// pins the guarantee against future refactors. See issue #246.
	if f.Result.Verdict() != detectors.VerdictVerified {
		return
	}
	rev, ok := r.revokers[f.Detector]
	if !ok {
		r.skipped.Add(1)
		return
	}
	r.attempted.Add(1)
	secret := string(f.Result.Raw)
	redacted := f.Result.Redacted
	if redacted == "" {
		redacted = redactSecret(secret)
	}
	if r.dryRun {
		fmt.Fprintf(r.logW, "DRY-RUN revoke: %s %s\n", f.Detector.String(), redacted)
		return
	}
	// Per-revoke timeout independent of the scan ctx so a slow
	// provider doesn't block the next finding's I/O.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := rev.Revoke(ctx, secret)
	switch {
	case err != nil:
		r.failed.Add(1)
		fmt.Fprintf(r.logW, "revoke FAIL: %s %s — %s\n", f.Detector.String(), redacted, err.Error())
	case res.Revoked && res.Err == nil:
		r.revoked.Add(1)
		fmt.Fprintf(r.logW, "revoke OK: %s %s\n", f.Detector.String(), redacted)
	case res.Revoked && res.Err != nil:
		r.revoked.Add(1)
		fmt.Fprintf(r.logW, "revoke OK (idempotent): %s %s — %s\n", f.Detector.String(), redacted, res.Err.Error())
	default:
		r.failed.Add(1)
		msg := "provider declined revocation"
		if res.Err != nil {
			msg = res.Err.Error()
		}
		fmt.Fprintf(r.logW, "revoke FAIL: %s %s — %s\n", f.Detector.String(), redacted, msg)
	}
}

func (r *revokingSink) Close() error { return r.inner.Close() }
