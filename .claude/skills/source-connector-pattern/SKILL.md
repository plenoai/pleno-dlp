---
name: source-connector-pattern
description: 데이터 소스(filesystem, git, github, gitlab, s3, gcs, slack, jira 등)에서 시크릿 스캐너로 chunk 를 emit하는 Source 커넥터를 Go 로 작성한다. 새 source 추가, 인증·페이지네이션·concurrency 모델 변경 시 사용한다. connector-engineer 전용.
---

# source-connector-pattern

## 목적

trufflehog 의 `Source` 인터페이스 시맨틱을 그대로 따르되 코드는 새로 작성한다. detector 가 chunk 만 받으면 작동하므로, source 와 detector 의 결합도를 영(0) 으로 유지한다.

## 인터페이스

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
    SourceMetadata MetadataOneof // 각 source 가 자기 metadata 채움
    Verify         bool
}

type Source interface {
    Init(ctx context.Context, name string, jobID, sourceID int64, verify bool, config []byte, concurrency int) error
    Chunks(ctx context.Context, ch chan<- *Chunk) error
    Type() SourceType
}
```

`MetadataOneof` 는 source 별 (`FilesystemMeta`, `GitMeta`, `GithubMeta` 등) discriminated union. 출력 단계에서 source 를 알아내기 위해 필요.

## 새 source 만드는 절차

`pkg/sources/<name>/<name>.go` 에 작성. 예시 (filesystem):

```go
package filesystem

import (
    "context"
    "io/fs"
    "os"
    "path/filepath"

    "github.com/plenoai/pleno-secret-scanner/pkg/sources"
)

type Source struct {
    name      string
    sourceID  int64
    verify    bool
    paths     []string
    maxBytes  int64
}

var _ sources.Source = (*Source)(nil)

func (s *Source) Init(ctx context.Context, name string, jobID, sourceID int64, verify bool, config []byte, concurrency int) error {
    s.name, s.sourceID, s.verify = name, sourceID, verify
    var c struct {
        Paths    []string `json:"paths"`
        MaxBytes int64    `json:"max_bytes"`
    }
    if err := json.Unmarshal(config, &c); err != nil { return err }
    s.paths, s.maxBytes = c.Paths, c.MaxBytes
    if s.maxBytes == 0 { s.maxBytes = 10 << 20 } // 10MB
    return nil
}

func (s *Source) Type() sources.SourceType { return sources.SourceType_Filesystem }

func (s *Source) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
    for _, root := range s.paths {
        err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
            if err != nil { return nil } // 부분 실패는 누적해도 walk 자체는 계속
            if d.IsDir() || isBinary(path) { return nil }
            data, err := readCapped(path, s.maxBytes)
            if err != nil { return nil }
            select {
            case <-ctx.Done(): return ctx.Err()
            case ch <- &sources.Chunk{
                SourceID:   s.sourceID,
                SourceType: s.Type(),
                SourceName: s.name,
                Data:       data,
                SourceMetadata: sources.FilesystemMeta{Path: path},
                Verify:     s.verify,
            }:
            }
            return nil
        })
        if err != nil { return err }
    }
    return nil
}
```

## 핵심 규칙

1. **chunk emit 은 항상 `select`.** `ch <- chunk` 만 쓰면 cancel 시 영원히 블록.
2. **concurrency 는 source 가 자기 도메인에 맞게.** filesystem 은 단일 walker 면 충분 (OS readdir 가 빠름). github 는 repo 단위 worker pool. s3 는 `ListObjectsV2` pagination + per-prefix 병렬.
3. **부분 실패는 chunk 흐름을 막지 않는다.** repo 1개 404 → log 누적, 나머지 repo 계속 처리. `Chunks` return error 는 **전체 source 가 실패** 한 경우만 (인증 실패 등).
4. **최대 청크 크기.** 거대 바이너리/lock 파일을 통째 메모리 적재하면 OOM. 기본 10MB cap, 초과 시 skip + 로그.
5. **인증 정책:**
   - CLI flag 명시 (`--github-token`)
   - 없으면 표준 환경변수 (`GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID`, `GOOGLE_APPLICATION_CREDENTIALS`)
   - 없으면 Init 단계 즉시 친절한 에러
   - 디스크상 임의 위치 자동 탐색 금지
6. **Rate limit:** GitHub/GitLab/Jira 응답에서 `X-RateLimit-Remaining` / `Retry-After` 헤더 확인, exponential backoff. 429 만나도 panic 금지.
7. **페이지네이션:** cursor / since 기반 우선. offset 기반은 결과 누락 위험 (object 추가/삭제 중일 때).

## 우선순위 source 매트릭스

| Source | Auth | 페이지네이션 | Concurrency 모델 |
|---|---|---|---|
| filesystem | (none) | - | 단일 walker |
| git | (none) / SSH key / HTTPS PAT | commit 그래프 walk | 단일 (go-git의 iter) |
| github | PAT / GitHub App | per_page=100, since (REST) / cursor (GraphQL) | repo 단위 worker pool (default 8) |
| gitlab | PAT / OAuth | per_page=100 + Link header | project 단위 worker pool |
| s3 | IAM (env / IRSA / SSO) | ListObjectsV2 ContinuationToken | prefix 단위 병렬 |
| gcs | ADC (env / Workload Identity) | NextPageToken | prefix 단위 병렬 |
| slack | Bot token (xoxb-) | cursor (`next_cursor`) | channel 단위 worker pool |
| jira | Basic / OAuth | startAt + maxResults | project 단위 |
| confluence | API token | start + limit | space 단위 |
| azure-blob | Connection string / SAS / DefaultAzureCredential | NextMarker | container 단위 |

## 등록

`pkg/sources/registry.go`:

```go
package sources

import "github.com/plenoai/pleno-secret-scanner/pkg/sources/filesystem"

func init() { Register(SourceType_Filesystem, func() Source { return &filesystem.Source{} }) }
```

## 테스트

`testdata/<source>/<scenario>/` 에 fixture, `<source>_test.go` 에 다음 케이스:
- 정상 chunk emit + metadata 정확성
- ctx cancel 시 즉시 종료 (race detector 통과)
- 부분 실패 (1개 객체 404) 시 나머지 계속 처리
- 인증 부재 시 Init 단계 친절한 에러

## metadata 설계 가이드

`SourceMetadata` 는 출력 (특히 SARIF) 에서 사용자가 "어디서 발견했는가" 를 보는 핵심.
- `filesystem`: `path`, `line` (가능하면)
- `git`: `repository`, `commit`, `file`, `line`, `email` (블레임)
- `github`: `repository`, `link`, `commit`, `file`, `line`, `visibility`
- `s3`: `bucket`, `key`, `version_id`, `etag`
- `slack`: `channel`, `timestamp`, `permalink`

새 source 추가 시 SARIF mapping 도 함께 업데이트 (core-engineer 와 합의).
