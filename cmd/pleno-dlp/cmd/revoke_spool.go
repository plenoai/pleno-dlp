// `scan --revoke-spool` defers revocation to a separate `pleno-dlp
// revoke --revoke-from-spool` step. The spool is the only place raw
// secret bytes leave the engine — stdout/stderr remain redaction-only.
//
// Rationale: a single-pass --revoke-on-verified is ergonomic but
// couples scan and revoke into one trust boundary. Spool decouples
// them, so an org can run scan with a low-privilege scanner identity
// and revoke later with a separate admin identity, replay revokes
// after rotating provider credentials, and dry-run the revoke step
// against the spool before committing. The trade-off is that the
// spool file contains raw credentials on disk — gate with
// PLENO_DLP_ALLOW_RAW_EXPORT=1 and a 0600 file mode.
package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// spoolSourceLink extracts a stable URL for the finding's source when
// the underlying source kind carries one (GitHub blob link, SIEM event
// link). Empty otherwise — the spool doesn't fabricate URLs.
func spoolSourceLink(c *sources.Chunk) string {
	if c == nil {
		return ""
	}
	switch {
	case c.SourceMetadata.GitHub != nil:
		return c.SourceMetadata.GitHub.Link
	case c.SourceMetadata.SIEM != nil:
		return c.SourceMetadata.SIEM.Link
	}
	return ""
}

// EnvAllowRawExport gates --revoke-spool. Required because the spool
// file persists raw secrets to disk — operators must opt in so a
// misconfigured CI cannot accidentally serialize live credentials.
const EnvAllowRawExport = "PLENO_DLP_ALLOW_RAW_EXPORT"

// spoolRecordVersion lets future revoke consumers handle older spool
// files. Bump on any breaking schema change.
const spoolRecordVersion = 1

// spoolRecord is one JSONL line in the revoke spool. Fields are
// deliberately minimal: only what `pleno-dlp revoke --revoke-from-spool`
// needs to dispatch to the per-detector Revoker. `secret_b64` keeps
// the raw payload binary-safe across any pipe that may touch the file
// (cp, tar, etc.) without depending on UTF-8 validity.
type spoolRecord struct {
	Version    int    `json:"version"`
	Detector   string `json:"detector"`
	SecretB64  string `json:"secret_b64"`
	Redacted   string `json:"redacted,omitempty"`
	SourceLink string `json:"source_link,omitempty"`
	Timestamp  string `json:"ts,omitempty"`
}

// spoolSink wraps an inner Sink. For every verified finding whose
// detector implements detectors.Revoker, it appends one spoolRecord to
// the spool file. Non-verified and non-revokable findings flow through
// unchanged.
//
// Concurrency: scan workers call Emit from many goroutines. The mutex
// guards the JSON encoder's buffered write so each line is atomic on
// disk (no interleaved bytes between two findings).
type spoolSink struct {
	inner       engine.Sink
	revokerSet  map[detectors.DetectorType]struct{}
	f           *os.File
	mu          sync.Mutex
	enc         *json.Encoder
	logW        io.Writer
	now         func() time.Time
	queued      atomic.Int64
	skippedNoRv atomic.Int64
	writeErrs   atomic.Int64
}

// newSpoolSink opens the spool file with O_TRUNC and mode 0600. We
// truncate so re-running a scan replaces the spool deterministically;
// appending would risk stale findings from a previous (now-revoked)
// scan being re-dispatched to revoke.
func newSpoolSink(inner engine.Sink, dets []detectors.Detector, path string, logW io.Writer) (*spoolSink, error) {
	if path == "" {
		return nil, fmt.Errorf("revoke-spool: path is empty")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("revoke-spool: open %q: %w", path, err)
	}
	// If the file already existed with looser perms, harden it. The
	// OpenFile mode is the upper bound at creation, not a chmod on an
	// existing file, so we explicitly tighten.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("revoke-spool: chmod 0600 %q: %w", path, err)
	}
	revokerSet := make(map[detectors.DetectorType]struct{}, len(dets))
	for _, d := range dets {
		if _, ok := d.(detectors.Revoker); ok {
			revokerSet[d.Type()] = struct{}{}
		}
	}
	return &spoolSink{
		inner:      inner,
		revokerSet: revokerSet,
		f:          f,
		enc:        json.NewEncoder(f),
		logW:       logW,
		now:        time.Now,
	}, nil
}

// Emit forwards downstream first so the structured output sees every
// finding, then queues the verified+revokable ones into the spool.
// Ordering matches revokingSink so the two paths behave identically
// from the report's perspective.
func (s *spoolSink) Emit(f engine.Finding) {
	s.inner.Emit(f)
	if !f.Result.Verified {
		return
	}
	if _, ok := s.revokerSet[f.Detector]; !ok {
		s.skippedNoRv.Add(1)
		return
	}
	rec := spoolRecord{
		Version:    spoolRecordVersion,
		Detector:   f.Detector.String(),
		SecretB64:  base64.StdEncoding.EncodeToString(f.Result.Raw),
		Redacted:   f.Result.Redacted,
		SourceLink: spoolSourceLink(f.Chunk),
		Timestamp:  s.now().UTC().Format(time.RFC3339),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enc.Encode(rec); err != nil {
		s.writeErrs.Add(1)
		fmt.Fprintf(s.logW, "revoke-spool: write failed for %s: %v\n", f.Detector.String(), err)
		return
	}
	s.queued.Add(1)
}

// Close flushes the underlying file and forwards Close downstream.
// Returns the first error so the caller surfaces both spool and inner
// sink failures.
func (s *spoolSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	if s.f != nil {
		if err := s.f.Sync(); err != nil {
			firstErr = fmt.Errorf("revoke-spool: sync: %w", err)
		}
		if err := s.f.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("revoke-spool: close: %w", err)
		}
		s.f = nil
	}
	if err := s.inner.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
