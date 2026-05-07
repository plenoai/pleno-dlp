package engine

import (
	"strconv"
	"sync"
)

// _ = sources.SourceUnknown // reserved for future use; the field accesses on
// f.Chunk.SourceMetadata travel through the type already declared in engine.go.

// dedupSink wraps a downstream Sink and suppresses duplicate findings. A
// duplicate is keyed by (DetectorType, Raw secret bytes, source path/line).
// Two identical access keys found at the same file:line by the same detector
// collapse to one Emit; the same key found in two different files is two
// distinct findings — that distinction is exactly what users need to triage.
type dedupSink struct {
	inner Sink
	mu    sync.Mutex
	seen  map[string]struct{}
}

// NewDedup wraps inner so repeated identical findings are forwarded only
// once. Concurrency-safe: scan workers may Emit from many goroutines.
func NewDedup(inner Sink) Sink {
	return &dedupSink{
		inner: inner,
		seen:  make(map[string]struct{}),
	}
}

func (d *dedupSink) Emit(f Finding) {
	key := dedupKey(f)
	d.mu.Lock()
	if _, dup := d.seen[key]; dup {
		d.mu.Unlock()
		return
	}
	d.seen[key] = struct{}{}
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
	var path string
	var line int
	if f.Chunk != nil {
		md := f.Chunk.SourceMetadata
		switch {
		case md.Filesystem != nil:
			path = md.Filesystem.Path
			line = md.Filesystem.Line
		case md.Git != nil:
			path = md.Git.Repository + "@" + md.Git.Commit + ":" + md.Git.File
			line = md.Git.Line
		case md.GitHub != nil:
			path = md.GitHub.Repository + "@" + md.GitHub.Commit + ":" + md.GitHub.File
			line = md.GitHub.Line
		case md.S3 != nil:
			path = "s3://" + md.S3.Bucket + "/" + md.S3.Key
		case md.GCS != nil:
			path = "gs://" + md.GCS.Bucket + "/" + md.GCS.Object
		case md.Slack != nil:
			path = md.Slack.Channel + "@" + md.Slack.Timestamp
		case md.Stdin != nil:
			// Stdin produces one chunk per scan, so the key needs to
			// include the stdin label to avoid collapsing distinct
			// scans of differently-labelled stdin streams. The
			// dedup map is per-process anyway, so the worst case is
			// over-suppression within a single run — but explicit is
			// better than relying on default-branch behaviour.
			path = "stdin:" + md.Stdin.Label
		default:
			path = f.Chunk.SourceType.String()
		}
	}
	// Detector type is encoded as int to keep the key compact and to avoid
	// the (admittedly unlikely) risk of a future detector name colliding
	// with an embedded separator.
	return strconv.Itoa(int(f.Detector)) + "\x00" + string(f.Result.Raw) + "\x00" + path + "\x00" + strconv.Itoa(line)
}
