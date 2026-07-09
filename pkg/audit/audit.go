// Package audit defines the versioned audit-trail schema for verify/revoke
// runs (issue #304 — moat roadmap item 9, loop provenance).
//
// Every revoke code path — `revoke --detector/--secret` (single),
// `revoke --revoke-from-spool` (spool replay), and
// `scan --revoke-on-verified` (on-verified) — emits exactly one Record per
// attempt through a shared Writer, so the trail is uniform regardless of
// entry point. Records are JSON Lines: one self-contained JSON object per
// line, append-friendly, and trivially greppable/jq-able.
//
// Redaction is structural, not a convention callers have to remember: the
// only constructor (New) takes the raw secret and immediately reduces it
// to a SHA-256 hash plus the CLI's existing prefix+ellipsis redaction —
// the raw bytes never enter the Record and are not retained by anything
// in this package.
//
// docs/audit-trail-schema.md is the published, human-readable mirror of
// this file. The two must move together: any field added, renamed, or
// removed here is a schema change and requires a doc update in the same
// commit; a breaking change to meaning or shape (not just an additive
// omitempty field) requires bumping SchemaVersion.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// SchemaVersion is embedded in every Record as schema_version. Bump this
// string on any breaking change to Record's shape or field semantics
// (renaming a field, changing its type, changing what a value means).
// Purely additive fields (new omitempty field, new enum value that old
// readers can ignore) do not require a bump.
const SchemaVersion = "1"

// Path names the revoke code path that produced a Record. Every revoke
// entry point in cmd/pleno-dlp/cmd maps to exactly one of these.
type Path string

const (
	// PathSingle is `pleno-dlp revoke --detector <d> --secret <s>`.
	PathSingle Path = "single"
	// PathSpool is `pleno-dlp revoke --revoke-from-spool <file>`, one
	// record per dispatched spool line.
	PathSpool Path = "spool"
	// PathOnVerified is `pleno-dlp scan --revoke-on-verified`, one record
	// per verified finding whose detector implements Revoker.
	PathOnVerified Path = "on-verified"
)

// Record is one JSON Lines entry in the audit trail. Field order mirrors
// the table in docs/audit-trail-schema.md.
type Record struct {
	// SchemaVersion pins this record to a documented shape. Consumers
	// MUST check this before assuming field semantics, the same
	// contract spoolRecord.Version already establishes for the revoke
	// spool file.
	SchemaVersion string `json:"schema_version"`
	// TrailID correlates this record with other artifacts produced for
	// the same revoke attempt — in particular the `audit_trail_id`
	// ExtraData/SARIF-properties key stamped onto the originating
	// engine.Finding by the on-verified path (see revoke_on_verified.go).
	TrailID string `json:"trail_id"`
	// Timestamp is when this revoke attempt was initiated (RFC3339, UTC)
	// — the same instant TrailID was derived from, so the two stay
	// correlated even though the attempt's outcome (Revoked/RevokedAt/
	// ProviderID/Error) is only known once the provider round trip
	// completes, potentially seconds later. RevokedAt, not this field,
	// is the provider-confirmed completion time.
	Timestamp string `json:"ts"`
	// Path is one of the Path constants above.
	Path string `json:"path"`
	// Detector is DetectorType.String() — the same identifier used
	// throughout pkg/output and pkg/detectors.
	Detector string `json:"detector"`
	// SecretHash is sha256(raw secret) hex-encoded. This is the only
	// secret-derived field: it lets an operator confirm "was this exact
	// leaked value ever revoked" without the trail ever holding
	// anything the secret could be reconstructed from.
	SecretHash string `json:"secret_hash"`
	// Redacted is the same prefix+ellipsis rendering used by
	// `revoke --format json`'s redacted_secret field and
	// detectors.Result.Redacted — safe to display, never the full value.
	Redacted string `json:"redacted,omitempty"`
	// Revoked is the provider's confirmation that the credential is now
	// dead. False for a --dry-run preview or a failed/declined attempt.
	Revoked bool `json:"revoked"`
	// RevokedAt is when the provider confirmed revocation (RFC3339,
	// UTC). Empty when Revoked is false or the provider did not report
	// a completion time.
	RevokedAt string `json:"revoked_at,omitempty"`
	// ProviderID is a provider-specific non-secret identifier for the
	// revoked credential (e.g. Stripe's key-prefix diagnostic). Empty
	// when the provider does not return one.
	ProviderID string `json:"provider_id,omitempty"`
	// DryRun marks a preview record: no provider call was made.
	DryRun bool `json:"dry_run,omitempty"`
	// TargetLink is a best-effort non-secret locator for where the
	// credential was found — a GitHub file URL, a SIEM link, a spool
	// record's source_link. Empty when the path has no such context
	// (e.g. `revoke --secret` supplied directly with no source chunk).
	TargetLink string `json:"target_link,omitempty"`
	// Error carries the provider diagnostic on a failed attempt, or the
	// idempotent-success diagnostic ("already revoked") when Revoked is
	// still true. Mirrors revokeRecord.Error's dual use.
	Error string `json:"error,omitempty"`
}

// HashSecret returns sha256(secret) hex-encoded. Used instead of storing
// the secret itself so a Record can be compared for "was this exact
// credential revoked" without being a second place raw credentials leak
// from. Mirrors pkg/output's jsonRecord.SecretHash so the two hashes are
// comparable across a scan's JSON output and the audit trail for the
// same leaked value.
func HashSecret(secret string) string {
	if secret == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// NewTrailID derives a stable, non-secret-bearing identifier for one
// revoke attempt from the detector name, the secret's hash, and a
// timestamp. Deterministic (no randomness) so tests can assert exact
// values and so re-running the exact same (detector, secret, instant)
// tuple yields the same id rather than a fresh one each time.
func NewTrailID(detector, secretHash string, ts time.Time) string {
	h := sha256.Sum256([]byte(detector + "|" + secretHash + "|" + ts.UTC().Format(time.RFC3339Nano)))
	// 16 hex chars (64 bits) is ample for a correlation id that only
	// needs to be unique within one operator's trail, not globally
	// collision-resistant like a cryptographic identifier.
	return hex.EncodeToString(h[:8])
}

// Attempt is the input to New. Secret is the raw credential; New reduces
// it to a hash immediately and does not retain it.
type Attempt struct {
	Path       Path
	Detector   string
	Secret     string
	Redacted   string
	Revoked    bool
	RevokedAt  time.Time
	ProviderID string
	DryRun     bool
	TargetLink string
	Err        error
	// Now overrides the record's timestamp source; zero value means
	// time.Now(). Tests set this for deterministic output.
	Now time.Time
}

// New builds a schema-versioned Record for one revoke attempt. This is
// the only place a Record is constructed so every call site — single,
// spool, on-verified — produces an identically-shaped record.
func New(a Attempt) Record {
	now := a.Now
	if now.IsZero() {
		now = time.Now()
	}
	hash := HashSecret(a.Secret)
	rec := Record{
		SchemaVersion: SchemaVersion,
		TrailID:       NewTrailID(a.Detector, hash, now),
		Timestamp:     now.UTC().Format(time.RFC3339),
		Path:          string(a.Path),
		Detector:      a.Detector,
		SecretHash:    hash,
		Redacted:      a.Redacted,
		Revoked:       a.Revoked,
		ProviderID:    a.ProviderID,
		DryRun:        a.DryRun,
		TargetLink:    a.TargetLink,
	}
	if !a.RevokedAt.IsZero() {
		rec.RevokedAt = a.RevokedAt.UTC().Format(time.RFC3339)
	}
	if a.Err != nil {
		rec.Error = a.Err.Error()
	}
	return rec
}

// ToSARIFProperties renders the record into the shape suitable for a
// SARIF result's `properties` bag (pkg/output/sarif.go's
// map[string]any). Round-tripping through JSON guarantees this
// representation can never silently drift from the JSON Lines shape —
// one schema, two encodings, exactly as required by issue #304.
//
// Callers should nest the result under a single properties key (e.g.
// `properties["audit_trail"] = rec.ToSARIFProperties()`) so it reads
// as one structured value rather than flattening into the top-level
// properties bag and risking a key collision with a detector's own
// ExtraData. See docs/audit-trail-schema.md for the wiring notes on
// why a scan's SARIF output can only carry the pre-attempt fields of a
// Record (schema_version/trail_id/ts/path/detector/secret_hash/
// redacted/dry_run/target_link) and not the outcome fields
// (revoked/revoked_at/provider_id/error), which are decided by a
// network round trip that completes after the SARIF result is already
// serialized.
func (r Record) ToSARIFProperties() map[string]any {
	b, err := json.Marshal(r)
	if err != nil {
		// Record's fields are all strings/bools; Marshal cannot
		// realistically fail. Fall back to the two fields that matter
		// most for correlation rather than losing the property
		// entirely.
		return map[string]any{"schema_version": r.SchemaVersion, "trail_id": r.TrailID}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{"schema_version": r.SchemaVersion, "trail_id": r.TrailID}
	}
	return m
}

// Writer appends Records as JSON Lines to an underlying io.Writer. Safe
// for concurrent use: scan.go's --revoke-on-verified path dispatches
// from engine worker goroutines, so a Writer shared across a whole scan
// invocation needs its own locking rather than relying on callers to
// serialize.
type Writer struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewWriter wraps w for JSON Lines append. w is never closed by Writer —
// callers that opened a file own its lifecycle (see
// cmd/pleno-dlp/cmd/audit_trail.go).
func NewWriter(w io.Writer) *Writer {
	return &Writer{enc: json.NewEncoder(w)}
}

// Write appends one record as a single JSON line. A write failure is the
// underlying writer's (e.g. a full disk) — callers decide whether to
// surface it, but a trail-write failure must never block or reverse an
// already-issued revoke; the revoke result itself always wins.
func (w *Writer) Write(r Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(r)
}
