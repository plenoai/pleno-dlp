package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

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
// generic appeared, and "Verifier first +
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
	// arriving non-Verifier finding. The reverse direction is uncommon
	// because engine.NewWith-
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
	// the risk of a future detector name colliding with an embedded
	// separator.
	return strconv.Itoa(int(f.Detector)) + "\x00" + string(f.Result.Raw) + "\x00" + path + "\x00" + strconv.Itoa(line)
}

// collisionKey is dedupKey minus the detector identifier — same raw at
// the same location collapses regardless of which detector emitted it.
// Used by the Verifier-priority suppression in Emit.
func collisionKey(f Finding) string {
	path, line := locationOf(f)
	return string(f.Result.Raw) + "\x00" + path + "\x00" + strconv.Itoa(line)
}

// gitCrossCommitSink collapses findings that appear for the same secret+file
// pair across multiple commits, keeping only the first (oldest, introducing)
// occurrence and annotating it with extra_data.occurrence_count.
//
// Non-git findings are forwarded to the inner sink immediately. Git findings
// are buffered during the scan and emitted on Close once occurrence counts are
// final — this is the only sink in the chain that buffers, so Close must be
// called for git findings to appear.
//
// The git source delivers commits in oldest-first order (collectCommits sorts
// by committer date ascending), so the first buffered finding for a key is
// the introducing commit. Parallel native history shards break arrival
// order; they stamp GitMeta.Ordinal and the lowest ordinal wins instead.
type replicatedFinding struct {
	f   Finding
	seq uint64
}

type gitCrossCommitSink struct {
	inner       Sink
	mu          sync.Mutex
	counts      map[string]int     // gitHashFileKey → occurrence count
	first       map[string]Finding // gitHashFileKey → introducing-commit finding
	insertOrder []string           // preserves emission order of first occurrences
	// firstSeq is the arrival sequence of first[key]. Arrival order
	// decides between commits whose ordinal is unknown (merge
	// resolutions), so expanded replicas compete at their scanned copy's
	// arrival position.
	firstSeq map[string]uint64
	seq      uint64
	// replicated holds findings from chunks that stand for several
	// identical diffs (GitMeta.Replicas). The replica set is final only
	// once the walk ends, so the replicas are expanded in Flush.
	replicated []replicatedFinding
}

// NewGitCrossCommitDedup wraps inner with cross-commit deduplication for git
// findings. When the same secret appears in the same file across multiple
// commits, only the introducing (earliest) commit is forwarded, annotated with
// extra_data.occurrence_count. Non-git findings pass through immediately.
func NewGitCrossCommitDedup(inner Sink) Sink {
	return &gitCrossCommitSink{
		inner:    inner,
		counts:   make(map[string]int),
		first:    make(map[string]Finding),
		firstSeq: make(map[string]uint64),
	}
}

func (g *gitCrossCommitSink) Emit(f Finding) {
	if f.Chunk == nil || f.Chunk.SourceMetadata.Git == nil {
		g.inner.Emit(f)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seq++
	if f.Chunk.SourceMetadata.Git.Replicas != nil {
		g.replicated = append(g.replicated, replicatedFinding{f: f, seq: g.seq})
		meta := *f.Chunk.SourceMetadata.Git
		meta.Replicas = nil
		f = withGitMeta(f, meta)
	}
	g.emitLocked(f, g.seq)
}

func (g *gitCrossCommitSink) emitLocked(f Finding, seq uint64) {
	key := gitHashFileKey(f)
	g.counts[key]++
	if prev, exists := g.first[key]; !exists {
		g.first[key] = f
		g.firstSeq[key] = seq
		g.insertOrder = append(g.insertOrder, key)
	} else if olderAt(f, seq, prev, g.firstSeq[key]) {
		// Parallel history shards deliver commits out of order; keep the
		// introducing (lowest-ordinal) commit rather than the first arrival.
		g.first[key] = f
		g.firstSeq[key] = seq
	}
}

// olderAt is older with explicit arrival sequences: across commits whose
// ordinal is unknown the earlier arrival wins. For findings emitted in
// arrival order (seq increasing) it is exactly older.
func olderAt(f Finding, fseq uint64, prev Finding, pseq uint64) bool {
	fg, pg := f.Chunk.SourceMetadata.Git, prev.Chunk.SourceMetadata.Git
	if (fg.Commit != pg.Commit || fg.Repository != pg.Repository) && (fg.Ordinal <= 0 || pg.Ordinal <= 0) {
		return fseq < pseq
	}
	return older(f, prev)
}

// expandReplicas re-emits every replicated finding once per identical-diff
// replica (the scanned copy was emitted on arrival), exactly as if each copy had
// been scanned. Callers hold g.mu.
func (g *gitCrossCommitSink) expandReplicas() {
	pending := g.replicated
	g.replicated = nil
	for _, p := range pending {
		meta := *p.f.Chunk.SourceMetadata.Git
		for _, r := range meta.Replicas.List() {
			g.emitLocked(withGitMeta(p.f, r.Apply(meta)), p.seq)
		}
	}
}

func withGitMeta(f Finding, m sources.GitMeta) Finding {
	cp := *f.Chunk
	cp.SourceMetadata.Git = &m
	f.Chunk = &cp
	return f
}

// Flush forwards every buffered introducing-commit finding to inner and
// resets the buffers. Exported so callers that need the buffered findings
// to reach inner before end-of-scan counting (e.g. the CLI's summary line
// and --fail-on gate) can do so without also closing inner — mirrors
// piidb.Sink's Flush/Close split for the same reason.
func (g *gitCrossCommitSink) Flush() error {
	g.mu.Lock()
	g.expandReplicas()
	order := g.insertOrder
	counts := g.counts
	first := g.first
	g.insertOrder = nil
	g.counts = make(map[string]int)
	g.first = make(map[string]Finding)
	g.firstSeq = make(map[string]uint64)
	g.mu.Unlock()

	for _, key := range order {
		f := first[key]
		count := counts[key]
		if count > 1 {
			extra := make(map[string]string, len(f.Result.ExtraData)+1)
			for k, v := range f.Result.ExtraData {
				extra[k] = v
			}
			extra["occurrence_count"] = strconv.Itoa(count)
			f.Result.ExtraData = extra
		}
		g.inner.Emit(f)
	}
	return nil
}

func (g *gitCrossCommitSink) Close() error {
	if err := g.Flush(); err != nil {
		return err
	}
	return g.inner.Close()
}

// older reports whether f should replace prev as the reported occurrence
// of a secret in a file. Across commits the lower GitMeta.Ordinal (the
// introducing commit) wins when both are known; otherwise the earlier
// arrival is kept. Within one commit the choice is made deterministic
// regardless of which worker finished first: lower line, then earlier offset, then a
// Verifier-backed detector, then the lower detector type.
func older(f, prev Finding) bool {
	fg, pg := f.Chunk.SourceMetadata.Git, prev.Chunk.SourceMetadata.Git
	if fg.Commit != pg.Commit || fg.Repository != pg.Repository {
		return fg.Ordinal > 0 && pg.Ordinal > 0 && fg.Ordinal < pg.Ordinal
	}
	_, fl := locationOf(f)
	_, pl := locationOf(prev)
	if fl != pl {
		return fl < pl
	}
	if f.RawSpan != nil && prev.RawSpan != nil && f.RawSpan[0] != prev.RawSpan[0] {
		return f.RawSpan[0] < prev.RawSpan[0]
	}
	if f.VerifierBacked != prev.VerifierBacked {
		return f.VerifierBacked
	}
	return f.Detector < prev.Detector
}

// gitHashFileKey produces a dedup key from the SHA-256 of the secret bytes
// and the file path, ignoring which commit the finding came from.
func gitHashFileKey(f Finding) string {
	h := sha256.Sum256(f.Result.Raw)
	return hex.EncodeToString(h[:]) + "\x00" + f.Chunk.SourceMetadata.Git.File
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
	case md.AzureBlob != nil:
		return md.AzureBlob.Locator(), 0
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
