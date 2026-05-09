// Package sources defines the Source interface and the Chunk shape that
// detectors consume. Concrete sources live under pkg/sources/<name>/ and
// self-register in registry.go via init().
package sources

import "context"

type SourceType int32

const (
	SourceUnknown SourceType = iota
	SourceFilesystem
	SourceGit
	SourceGitHub
	SourceGitLab
	SourceS3
	SourceGCS
	SourceSlack
	SourceJira
	SourceConfluence
	SourceAzureBlob
	SourceBitbucket
	SourceNotion
	SourceStdin
)

// Metadata is a discriminated union of source-specific location info. Each
// source populates exactly one field. Output formatters dispatch on the
// non-nil field to render "where the secret was found".
type Metadata struct {
	Filesystem *FilesystemMeta
	Git        *GitMeta
	GitHub     *GitHubMeta
	S3         *S3Meta
	GCS        *GCSMeta
	Slack      *SlackMeta
	Stdin      *StdinMeta
}

type FilesystemMeta struct {
	Path string
	Line int
}

type GitMeta struct {
	Repository string
	Commit     string
	File       string
	Line       int
	Email      string
}

// GitHubMeta is populated by the GitHub source / SaaS connector. The legacy
// fields (Repository, Link, Commit, File, Line, Visibility) are preserved so
// existing output formatters keep rendering. The connector port (#74) added
// the typed fields below — Owner, Repo, Path, Sha, Branch — so downstream
// code can address blob coordinates without re-parsing "owner/name" strings
// or guessing whether Commit holds a commit-sha or a blob-sha.
type GitHubMeta struct {
	Repository string
	Link       string
	Commit     string
	File       string
	Line       int
	Visibility string
	Owner      string
	Repo       string
	Path       string
	Sha        string
	Branch     string
}

type S3Meta struct {
	Bucket    string
	Key       string
	VersionID string
	ETag      string
}

type GCSMeta struct {
	Bucket    string
	Object    string
	Generation int64
}

type SlackMeta struct {
	Channel   string
	Timestamp string
	Permalink string
}

// StdinMeta describes a chunk read from standard input. Label defaults to
// "<stdin>" but callers can override it (e.g. `--label "git diff"`) so the
// output formatters render something more useful than a generic placeholder.
type StdinMeta struct {
	Label string
}

// Chunk is a unit of data emitted by a Source for detectors to scan. Sources
// MUST select on ctx.Done() when sending so cancellation propagates promptly.
type Chunk struct {
	SourceID       int64
	SourceType     SourceType
	SourceName     string
	Data           []byte
	SourceMetadata Metadata
	Verify         bool
}

// Source is the trufflehog-compatible source contract. Init parses config and
// validates auth; Chunks streams data into ch and closes when done. Returning
// an error from Chunks means the source itself failed (auth, fatal config).
// Per-item errors should be logged and skipped so partial results survive.
type Source interface {
	Init(ctx context.Context, name string, jobID, sourceID int64, verify bool, config []byte, concurrency int) error
	Chunks(ctx context.Context, ch chan<- *Chunk) error
	Type() SourceType
}
