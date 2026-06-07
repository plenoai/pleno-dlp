package engine

import (
	"strconv"
	"sync"
)

// _ = sources.SourceUnknown // reserved for future use; the field accesses on
// f.Chunk.SourceMetadata travel through the type already declared in engine.go.

// dedupSink wraps a downstream Sink and suppresses duplicate findings.
//
// Two distinct keys are tracked:
//
//   - perDetectorKey = (DetectorType, Raw, path, line). Two identical
//     secrets hit by the same detector at the same location collapse to
//     one Emit. This is the long-standing baseline behaviour.
//   - collisionKey = (Raw, path, line). When two DIFFERENT detectors
//     fire on identical raw bytes at the same location, we keep only
//     the higher-confidence finding: Verifier-backed beats non-Verifier.
//     This is the rule that makes the generic high-entropy detector
//     stop spamming the user with shadow hits for every AWS / Slack /
//     OpenAI key the provider-specific detector already caught.
//
// Engine.NewWithDetectors orders detectors so Verifier-backed ones run
// first, which means the Verifier-backed finding for a given raw bytes
// is normally emitted first and the generic finding then arrives as the
// loser. Order is enforced in two layers — engine order + dedup
// suppression — so neither layer alone is load-bearing: even if a future
// caller bypasses the engine and emits findings in arbitrary order, the
// "first to arrive wins" rule still does the right thing when only
// generic appeared (it gets emitted alone), and "Verifier first +
// generic suppressed" still holds when both appear because engine order
// guarantees Verifier-backed arrives first.
type dedupSink struct {
	inner Sink
	mu    sync.Mutex
	seen  map[string]struct{}
	// emittedByCollision records, per (raw, path, line), whether a
	// Verifier-backed finding has already been emitted. Once true, every
	// incoming non-Verifier finding for the same key is suppressed.
	emittedByCollision map[string]bool
}

// NewDedup wraps inner so repeated identical findings are forwarded only
// once, and so generic high-entropy findings that collide with a
// Verifier-backed provider detector at the same raw bytes / location
// are suppressed. Concurrency-safe: scan workers may Emit from many
// goroutines.
func NewDedup(inner Sink) Sink {
	return &dedupSink{
		inner:              inner,
		seen:               make(map[string]struct{}),
		emittedByCollision: make(map[string]bool),
	}
}

func (d *dedupSink) Emit(f Finding) {
	key := dedupKey(f)
	collision := collisionKey(f)
	d.mu.Lock()
	if _, dup := d.seen[key]; dup {
		d.mu.Unlock()
		return
	}
	// Cross-detector collision suppression. If a Verifier-backed
	// finding has already been emitted for this raw+location, drop the
	// arriving non-Verifier finding. The reverse direction (generic
	// arrived first, then Verifier) is uncommon because engine.NewWith-
	// Detectors orders Verifier-backed detectors ahead of non-Verifier
	// ones; when it does happen, we accept the streaming-cost of
	// emitting both rather than buffering all output until scan end.
	if d.emittedByCollision[collision] && !f.VerifierBacked {
		d.mu.Unlock()
		return
	}
	d.seen[key] = struct{}{}
	if f.VerifierBacked {
		d.emittedByCollision[collision] = true
	}
	d.mu.Unlock()
	d.inner.Emit(f)
}

func (d *dedupSink) Close() error {
	return d.inner.Close()
}

// dedupKey collapses the (detector, secret, location) triple into a string
// suitable for map lookup. Raw bytes are used as-is — they're the canonical
// form of the secret and any whitespace differences are meaningful.
func dedupKey(f Finding) string {
	path, line := locationOf(f)
	// Detector type is encoded as int to keep the key compact and to avoid
	// the (admittedly unlikely) risk of a future detector name colliding
	// with an embedded separator.
	return strconv.Itoa(int(f.Detector)) + "\x00" + string(f.Result.Raw) + "\x00" + path + "\x00" + strconv.Itoa(line)
}

// collisionKey is dedupKey minus the detector identifier — same raw at
// the same location collapses regardless of which detector emitted it.
// Used by the Verifier-priority suppression in Emit.
func collisionKey(f Finding) string {
	path, line := locationOf(f)
	return string(f.Result.Raw) + "\x00" + path + "\x00" + strconv.Itoa(line)
}

// locationOf renders a stable (path, line) pair from any SourceMetadata
// variant. Extracted from dedupKey so the per-detector and cross-
// detector keys share one source of truth — a future SourceMetadata
// addition only needs one edit, and a mismatched switch can't make the
// two keys silently disagree on what "same location" means.
func locationOf(f Finding) (string, int) {
	if f.Chunk == nil {
		return "", 0
	}
	md := f.Chunk.SourceMetadata
	switch {
	case md.Filesystem != nil:
		return md.Filesystem.Path, md.Filesystem.Line
	case md.Git != nil:
		return md.Git.Repository + "@" + md.Git.Commit + ":" + md.Git.File, md.Git.Line
	case md.GitHub != nil:
		return md.GitHub.Repository + "@" + md.GitHub.Commit + ":" + md.GitHub.File, md.GitHub.Line
	case md.S3 != nil:
		return "s3://" + md.S3.Bucket + "/" + md.S3.Key, 0
	case md.GCS != nil:
		return "gs://" + md.GCS.Bucket + "/" + md.GCS.Object, 0
	case md.Slack != nil:
		return md.Slack.Channel + "@" + md.Slack.Timestamp, 0
	case md.GitLab != nil:
		return md.GitLab.Group + "/" + md.GitLab.Project + "@" + md.GitLab.Sha + ":" + md.GitLab.Path, 0
	case md.Confluence != nil:
		return md.Confluence.SpaceKey + "/" + md.Confluence.PageID + ":" + md.Confluence.Type, 0
	case md.Jira != nil:
		return md.Jira.Project + "/" + md.Jira.IssueKey + ":" + md.Jira.Part, 0
	case md.Notion != nil:
		return md.Notion.PageID + ":" + md.Notion.Part, 0
	case md.Bitbucket != nil:
		return md.Bitbucket.Workspace + "/" + md.Bitbucket.Repo + "@" + md.Bitbucket.Commit + ":" + md.Bitbucket.Path, 0
	case md.Stdin != nil:
		// Stdin produces one chunk per scan, so the key needs to
		// include the stdin label to avoid collapsing distinct scans
		// of differently-labelled stdin streams. Over-suppression
		// inside one run is the failure mode if we omit it.
		return "stdin:" + md.Stdin.Label, 0
	default:
		return f.Chunk.SourceType.String(), 0
	}
}
