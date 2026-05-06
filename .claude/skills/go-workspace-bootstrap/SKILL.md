---
name: go-workspace-bootstrap
description: Go workspace(go.work / go.mod) 구조와 GoReleaser 기반 tag-push trusted publishing 파이프라인을 구성·갱신한다. 초기 부트스트랩, 새 sub-module 추가, Go 버전 업, GitHub Actions 워크플로우 작성·핀닝, 의존성 정책 변경 시 사용한다. architect 전용.
---

# go-workspace-bootstrap

## 목적

repo 루트의 빌드/배포 시스템을 일관되게 유지한다. 단일 모듈 + GoReleaser + tag push 기반 trusted publishing.

## 모듈 정책

**현 단계: 단일 모듈.**

- 루트에 `go.mod` 1개. `module github.com/plenoai/pleno-secret-scanner`.
- `go.work` 는 일단 만들지 않는다 (단일 모듈에서는 불필요).
- detector·source 가 늘어나 빌드 시간이 30초를 넘기 시작하면 sub-module 분할 검토. ADR 작성 후 진행.

**Go 버전:** `go 1.23` (toolchain 라인은 명시하지 않음, 사용자 환경 따름).

## 디렉토리 스켈레톤

```
pleno-secret-scanner/
  cmd/pleno-secret-scanner/
    main.go
    cmd/                     # cobra subcommands
      root.go
      filesystem.go
      git.go
      github.go
  pkg/
    detectors/
      detectors.go           # interface + Result + DetectorType
      registry.go            # init() 등록
      <provider>/<provider>.go
    sources/
      sources.go             # interface + Chunk + SourceType
      registry.go
      <source>/<source>.go
    engine/
      engine.go              # 스캔 루프
      dedup.go
      filter.go
    output/
      json.go
      sarif.go
      table.go
    common/
      httpclient/             # Verify 용 공통 client (timeout, retry)
      entropy/
  testdata/
  .github/workflows/
    test.yml
    release.yml
  .goreleaser.yaml
  CHANGELOG.md
  go.mod
```

## go.mod 초기

```
module github.com/plenoai/pleno-secret-scanner

go 1.23

require (
    github.com/spf13/cobra v1.8.1
    github.com/google/uuid v1.6.0
)
```

cobra 외 의존성은 detector/source 추가 시 PR 단위로 추가. **slog (표준 lib) 사용**, 외부 로깅 lib 도입 금지.

## CI workflow (test.yml)

```yaml
name: test
on:
  push: { branches: [main] }
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-sha>
      - uses: actions/setup-go@<full-sha>
        with: { go-version: "1.23" }
      - run: go test ./... -race -count=1
      - run: go vet ./...
      - uses: golangci/golangci-lint-action@<full-sha>
```

**규칙:**
- 모든 action은 commit SHA 핀 (Dependabot 으로 정기 갱신).
- `permissions: contents: read` 최소권한, job 별 필요 시 확장.
- `pull_request_target` 금지.

## release workflow (release.yml)

```yaml
name: release
on:
  push:
    tags: ['v*']
permissions:
  contents: write       # release 작성
  id-token: write       # OIDC trusted publishing
jobs:
  goreleaser:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-sha>
        with: { fetch-depth: 0 }
      - uses: actions/setup-go@<full-sha>
        with: { go-version: "1.23" }
      - uses: goreleaser/goreleaser-action@<full-sha>
        with: { args: release --clean }
        env: { GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }} }
```

**기본 정책:** GitHub Release 만 발행. Homebrew tap, scoop 등은 사용자 요구가 명확해진 뒤에 추가.

## .goreleaser.yaml 초기

```yaml
version: 2
project_name: pleno-secret-scanner
builds:
  - id: pleno-secret-scanner
    main: ./cmd/pleno-secret-scanner
    binary: pleno-secret-scanner
    env: [CGO_ENABLED=0]
    goos: [linux, darwin, windows]
    goarch: [amd64, arm64]
    ldflags:
      - -s -w -X main.version={{.Version}} -X main.commit={{.Commit}}
archives:
  - name_template: "{{.ProjectName}}_{{.Os}}_{{.Arch}}"
    formats: [tar.gz]
    format_overrides:
      - goos: windows
        formats: [zip]
checksum:
  name_template: 'checksums.txt'
release:
  prerelease: auto
changelog:
  use: github
```

## 의존성 정책

- **표준 lib 우선.** slog, errors, encoding/json. 라이트한 라이브러리 (cobra, uuid) 만 직접 의존.
- **provider SDK** (aws-sdk-go-v2, google-cloud-go, github.com/google/go-github 등) 은 source/detector 단위로 도입, **detector/source 단위 import 만**. 다른 패키지에서 transitive 노출 금지.
- 신규 의존성 추가 PR 은 ADR 짧게: 왜 표준 lib 로 안 되는가, 라이선스, 활성도.

## 태그 릴리스 절차

1. `CHANGELOG.md` 갱신 (Keep-a-Changelog 형식).
2. main 에 머지 + 푸시.
3. `git tag vX.Y.Z && git push --tags` (no-gpg-sign 금지, GPG 서명 유지).
4. GitHub Actions release.yml 가 자동으로 GoReleaser 실행.
5. GitHub Release 페이지에서 결과물 확인.

(SemVer: detector/source 추가 = minor, output schema 깨는 변경 = major, 버그 픽스 = patch.)

## 이전 산출물이 있을 때

`_workspace/architecture-decisions.md` 의 이전 ADR을 모두 읽고, 결정 뒤집기 전에 새 ADR 추가.
