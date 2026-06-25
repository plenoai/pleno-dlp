// Package sources defines the Source interface and the Chunk shape that
// detectors consume. Concrete sources live under pkg/sources/<name>/ and
// self-register in registry.go via init().
package sources

import (
	"context"
	"encoding/json"
)

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
	SourceForgejo
	SourceGitea
	SourceGogs
	SourceGitbucket
	SourceCodeberg
	SourceOneDev
	SourceCodebase
	SourcePagure
	SourceDatadog
	SourceSplunk
	SourceBigQuery
	SourceRedash
	SourceSQLDump
	SourceDockerImage
	SourceElasticsearch
	SourceJenkins
	SourcePostman
	SourceHuggingFace
	SourceCircleCI
)

// Metadata is a discriminated union of source-specific location info. Each
// source populates exactly one field. Output formatters dispatch on the
// non-nil field to render "where the secret was found".
type Metadata struct {
	Filesystem  *FilesystemMeta
	Git         *GitMeta
	GitHub      *GitHubMeta
	GitLab      *GitLabMeta
	S3          *S3Meta
	GCS         *GCSMeta
	Slack       *SlackMeta
	Confluence  *ConfluenceMeta
	Jira        *JiraMeta
	Notion      *NotionMeta
	Bitbucket   *BitbucketMeta
	Stdin       *StdinMeta
	Forge       *ForgeMeta
	SIEM        *SIEMMeta
	SQLDump     *SQLDumpMeta
	DockerImage *DockerImageMeta
	HuggingFace *HuggingFaceMeta
}

type FilesystemMeta struct {
	Path string
	Line int
}

type GitMeta struct {
	Repository   string
	Commit       string
	File         string
	Line         int
	Email        string
	Author       string
	AuthoredDate string // RFC3339
	Message      string // first line of commit message
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

// GitLabMeta is populated by the GitLab source / SaaS connector. Mirrors
// the GitHubMeta structure so downstream formatters can render provenance
// without provider-specific branching on coordinate shape.
type GitLabMeta struct {
	ProjectID int64
	Path      string
	Sha       string
	Branch    string
	Group     string
	Project   string
}

type S3Meta struct {
	Bucket    string
	Key       string
	VersionID string
	ETag      string
}

type GCSMeta struct {
	Bucket     string
	Object     string
	Generation int64
}

type SlackMeta struct {
	Channel   string
	Timestamp string
	Permalink string
}

// ConfluenceMeta is populated by the Confluence SaaS connector. It captures
// the space, page, and content coordinates so output formatters can render
// provenance without re-fetching the API.
type ConfluenceMeta struct {
	SpaceKey  string
	SpaceName string
	PageID    string
	Title     string
	URL       string
	Type      string // "page" or "footer-comment" or "inline-comment"
}

type JiraMeta struct {
	Project  string
	IssueKey string
	Part     string // "description" or "comment:<id>"
}

type NotionMeta struct {
	PageID   string
	Database string
	Title    string
	URL      string
	Part     string // "page" or "database_row:<id>" or "block:<id>"
}

type BitbucketMeta struct {
	Workspace string
	Repo      string
	Path      string
	Commit    string
	Branch    string
}

// StdinMeta describes a chunk read from standard input. Label defaults to
// "<stdin>" but callers can override it (e.g. `--label "git diff"`) so the
// output formatters render something more useful than a generic placeholder.
type StdinMeta struct {
	Label string
}

type ForgeMeta struct {
	Provider   string
	Repository string
	Branch     string
	Commit     string
	File       string
	Line       int
}

// SIEMMeta is populated by SIEM connectors (Datadog, Splunk, BigQuery,
// Redash). Provider distinguishes the SIEM system; the remaining fields
// map to the event/log/query provenance so output formatters can render
// a clickable location without provider-specific branching.
type SIEMMeta struct {
	Provider  string // "datadog", "splunk", "bigquery", "redash"
	Host      string // SIEM host or project
	Index     string // index, dataset, or query name
	EventID   string // unique event/log/row identifier
	Timestamp string // event timestamp (RFC 3339 or provider-native)
	Link      string // deep link to the event in the SIEM UI
}

// SQLDumpMeta is populated by the sqldump source. It tracks provenance down
// to the table and line within the dump file so operators can locate the
// original record.
type SQLDumpMeta struct {
	File     string // path to the dump file
	Database string // database name (from USE or CREATE DATABASE)
	Table    string // current table context (from INSERT INTO or CREATE TABLE)
	Line     int    // 1-based line number in the dump file
	Format   string // "mysql", "postgres", or "sqlite"
}

// Chunk is a unit of data emitted by a Source for detectors to scan. Sources
// MUST select on ctx.Done() when sending so cancellation propagates promptly.
type Chunk struct {
	SourceID       int64
	SourceType     SourceType
	SourceName     string
	Data           []byte
	SourceMetadata Metadata
}

// DockerImageMeta is populated by the docker-image source. It captures
// the image reference, layer digest, and file path within the layer so
// output formatters can render where the secret was found without
// re-fetching the image.
type DockerImageMeta struct {
	Image  string // full image reference (e.g., "docker.io/library/alpine:3.20")
	Digest string // image manifest digest (sha256:...)
	Layer  string // layer digest (sha256:...) or "config" for the image config blob
	File   string // path within the layer (empty for the config blob)
	Line   int    // 1-based line number within the file (0 if unknown)
}

// HuggingFaceMeta is populated by the HuggingFace connector. It tracks
// provenance to the organization, repository, and file path within the repo
// so output formatters can render where the secret was found.
type HuggingFaceMeta struct {
	Organization string `json:"organization"`
	Repository   string `json:"repository"`
	RepoType     string `json:"repo_type"`
	Path         string `json:"path"`
	Commit       string `json:"commit"`
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

// ResourceFingerprinter is an optional Source extension used by the CLI's
// incremental mode. Implementations return a stable digest for the resources
// this initialized source would scan. It must be computed after Init, because
// source config such as include/exclude/max-size changes the resource set.
type ResourceFingerprinter interface {
	ResourceFingerprint(ctx context.Context) (string, error)
}

// IncrementalStateSource is an optional Source extension for sources that can
// narrow a changed scan to only resources newer than the previous baseline.
type IncrementalStateSource interface {
	SetIncrementalState(previous json.RawMessage) error
	IncrementalState() json.RawMessage
}

// IncrementalFlushFunc は partial に処理が進んだ時点の source state を
// 呼び出し元 (cmd 層) に流すための callback。 cmd 層は受け取った
// sourceState を incremental state file に wrap して atomic に persist
// する想定。 callback 自体は nil 安全。
type IncrementalFlushFunc func(sourceState json.RawMessage) error

// IncrementalFlushSource は IncrementalStateSource の opt-in 拡張。
// 大量 resource を順番に処理する source が、 unit (例: per-repo) 完了の
// たびに最新 state を flush できるようにする。 中断後の resume と、
// scan が exit 非 0 で死んだ場合の partial state 永続化のための仕組み。
type IncrementalFlushSource interface {
	IncrementalStateSource
	SetIncrementalFlush(IncrementalFlushFunc)
}
