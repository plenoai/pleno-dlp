---
name: go-workspace-bootstrap
description: Set up or revise the Go workspace (go.work / go.mod) and the GoReleaser-driven tag-push trusted-publishing pipeline. Use for the initial bootstrap, adding a sub-module, bumping the Go toolchain version, authoring or pinning GitHub Actions workflows, or revising dependency policy. architect only.
---

# go-workspace-bootstrap

## Purpose

Keep the build and release system at the repository root coherent. Single Go module, GoReleaser, tag-push trusted publishing.

## Module policy

**Current stage: single module.**

- One `go.mod` at the root: `module github.com/plenoai/pleno-secret-scanner`.
- `go.work` is not introduced yet (unnecessary with one module).
- Once detector and source counts push build time past ~30 seconds, evaluate a sub-module split — and only with an ADR.

**Go toolchain:** `go 1.23` (no explicit `toolchain` line; respect the developer's environment).

## Directory skeleton

```
pleno-secret-scanner/
  cmd/pleno-secret-scanner/
    main.go
    cmd/                      # cobra subcommands
      root.go
      filesystem.go
      git.go
      github.go
  pkg/
    detectors/
      detectors.go            # interface + Result + DetectorType
      registry.go             # init() registration
      <provider>/<provider>.go
    sources/
      sources.go              # interface + Chunk + SourceType + Metadata
      registry.go
      <source>/<source>.go
    engine/
      engine.go               # scan loop
      dedup.go
      filter.go
    output/
      json.go
      sarif.go
      table.go
    common/
      httpclient/             # shared client for Verify (timeouts, retries)
      entropy/
  testdata/
  .github/workflows/
    test.yml
    release.yml
  .goreleaser.yaml
  CHANGELOG.md
  go.mod
```

## Initial go.mod

```
module github.com/plenoai/pleno-secret-scanner

go 1.23

require (
    github.com/spf13/cobra v1.8.1
    github.com/google/uuid v1.6.0
)
```

Other dependencies are introduced per-PR alongside the detector or source that needs them. **Use `slog` from the standard library**; no third-party logging.

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

**Rules:**
- Pin every action to a full commit SHA (Dependabot keeps them current).
- Keep `permissions: contents: read` minimal; widen per job only when required.
- `pull_request_target` is forbidden.

## Release workflow (release.yml)

```yaml
name: release
on:
  push:
    tags: ['v*']
permissions:
  contents: write       # for the release
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

**Default policy:** publish only to GitHub Releases. Add Homebrew taps, scoop, etc. only when there is concrete user demand.

## .goreleaser.yaml starter

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

## Dependency policy

- **Standard library first.** slog, errors, encoding/json. Lightweight libraries (cobra, uuid) are direct dependencies only when justified.
- **Provider SDKs** (aws-sdk-go-v2, google-cloud-go, github.com/google/go-github) are imported only by the detector or source that needs them. Do not leak them transitively into other packages.
- New dependency PRs include a short ADR: why the standard library is insufficient, license, and project health.

## Tag release procedure

1. Update `CHANGELOG.md` (Keep a Changelog format).
2. Merge to main and push.
3. `git tag vX.Y.Z && git push --tags` (always GPG-signed; `--no-gpg-sign` is forbidden).
4. release.yml runs GoReleaser automatically.
5. Confirm artefacts on the GitHub Release page.

(SemVer: detector or source addition → minor; breaking output schema → major; fixes → patch.)

## When prior artifacts exist

Read every prior ADR in `_workspace/architecture-decisions.md` and append a new ADR before reversing a previous decision.
