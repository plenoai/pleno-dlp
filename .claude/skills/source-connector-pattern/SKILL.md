---
name: source-connector-pattern
description: Author or revise Go source connectors (filesystem, git, github, gitlab, s3, gcs, slack, jira, and others) that emit Chunks for the secret scanner engine. Use when adding a source, changing authentication models, revising pagination, or revising concurrency. connector-engineer only.
---

# source-connector-pattern

## Purpose

Implement source connectors that follow trufflehog's `Source` interface semantics, with code written fresh. Detectors only consume `Chunk`s, so source–detector coupling stays at zero.

## Interface

```go
// pkg/sources/sources.go
package sources

import "context"

type SourceType int32

type Chunk struct {
    SourceID       int64
    SourceType     SourceType
    SourceName     string
    Data           []byte
    SourceMetadata Metadata // discriminated union, source-specific
    Verify         bool
}

type Source interface {
    Init(ctx context.Context, name string, jobID, sourceID int64, verify bool, config []byte, concurrency int) error
    Chunks(ctx context.Context, ch chan<- *Chunk) error
    Type() SourceType
}
```

`Metadata` is a discriminated union — exactly one of `Filesystem`, `Git`, `GitHub`, `S3`, `GCS`, `Slack`, etc. is non-nil. Output formatters dispatch on the non-nil field to render "where the secret was found".

## Adding a new source

`pkg/sources/<name>/<name>.go`. Filesystem example:

```go
package filesystem

import (
    "context"
    "encoding/json"
    "io/fs"
    "path/filepath"

    "github.com/plenoai/pleno-secret-scanner/pkg/sources"
)

type Source struct {
    name     string
    sourceID int64
    verify   bool
    paths    []string
    maxBytes int64
}

var _ sources.Source = (*Source)(nil)

func (s *Source) Init(ctx context.Context, name string, jobID, sourceID int64, verify bool, config []byte, concurrency int) error {
    s.name, s.sourceID, s.verify = name, sourceID, verify
    var c struct {
        Paths    []string `json:"paths"`
        MaxBytes int64    `json:"max_bytes"`
    }
    if err := json.Unmarshal(config, &c); err != nil {
        return err
    }
    s.paths, s.maxBytes = c.Paths, c.MaxBytes
    if s.maxBytes == 0 {
        s.maxBytes = 10 << 20
    }
    return nil
}

func (s *Source) Type() sources.SourceType { return sources.SourceFilesystem }

func (s *Source) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
    for _, root := range s.paths {
        err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
            if err != nil {
                return nil // partial failure: log and continue
            }
            if d.IsDir() || isBinary(path) {
                return nil
            }
            data, err := readCapped(path, s.maxBytes)
            if err != nil {
                return nil
            }
            select {
            case <-ctx.Done():
                return ctx.Err()
            case ch <- &sources.Chunk{
                SourceID:       s.sourceID,
                SourceType:     s.Type(),
                SourceName:     s.name,
                Data:           data,
                SourceMetadata: sources.Metadata{Filesystem: &sources.FilesystemMeta{Path: path}},
                Verify:         s.verify,
            }:
            }
            return nil
        })
        if err != nil {
            return err
        }
    }
    return nil
}
```

## Core rules

1. **Always `select` when sending to `ch`.** A bare `ch <- chunk` will block forever on cancellation.
2. **Pick the right concurrency model per source.** Filesystem: a single walker (OS readdir is fast). GitHub: per-repo worker pool. S3: parallel per-prefix on top of `ListObjectsV2` pagination.
3. **Partial failures must not block the chunk stream.** A 404 on one repository: log and continue. `Chunks` returns an error only for whole-source failure (auth, fatal config).
4. **Cap chunk size** (default 10 MB). Loading a giant binary or lock file whole risks OOM; skip and log.
5. **Auth precedence:**
   - explicit CLI flag (`--github-token`)
   - well-known env var (`GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID`, `GOOGLE_APPLICATION_CREDENTIALS`)
   - friendly Init error
   No silent disk auto-discovery.
6. **Rate limits.** Read `X-RateLimit-Remaining` / `Retry-After`; back off exponentially. 429 must never panic.
7. **Pagination.** Prefer cursor / `since` over offset (offset misses items under concurrent writes).

## Priority source matrix

| Source | Auth | Pagination | Concurrency |
|---|---|---|---|
| filesystem | none | n/a | single walker |
| git | none / SSH key / HTTPS PAT | commit graph walk | single (go-git iter) |
| github | PAT / GitHub App | per_page=100, since (REST) / cursor (GraphQL) | per-repo worker pool (default 8) |
| gitlab | PAT / OAuth | per_page=100 + Link header | per-project worker pool |
| s3 | IAM (env / IRSA / SSO) | ContinuationToken | per-prefix parallel |
| gcs | ADC (env / Workload Identity) | NextPageToken | per-prefix parallel |
| slack | Bot token (xoxb-) | cursor (`next_cursor`) | per-channel worker pool |
| jira | Basic / OAuth | startAt + maxResults | per-project worker pool |
| confluence | API token | start + limit | per-space worker pool |
| azure-blob | ConnString / SAS / DefaultAzureCredential | NextMarker | per-container worker pool |

## Registration

`pkg/sources/registry.go`:

```go
package sources

import "github.com/plenoai/pleno-secret-scanner/pkg/sources/filesystem"

func init() {
    Register(SourceFilesystem, func() Source { return &filesystem.Source{} })
}
```

## Tests

Place fixtures under `testdata/<source>/<scenario>/`. `<source>_test.go` should cover:
- Normal chunk emission with metadata
- Immediate exit on `ctx` cancellation (race-detector clean)
- Partial failure (one item 404) does not stop the rest
- Missing auth produces a friendly Init error

## Metadata design

`SourceMetadata` is what users see in output (especially SARIF) when asking "where did this come from?".
- `filesystem`: `path`, `line` (if known)
- `git`: `repository`, `commit`, `file`, `line`, `email` (blame)
- `github`: `repository`, `link`, `commit`, `file`, `line`, `visibility`
- `s3`: `bucket`, `key`, `version_id`, `etag`
- `slack`: `channel`, `timestamp`, `permalink`

When adding a source, update SARIF mappings in `pkg/output/` together with core-engineer.
