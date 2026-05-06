# pleno-secret-scanner

Go-native secret scanner. Detector interface is trufflehog-compatible; source connectors are reimplemented under `pkg/sources/`.

## Harness: secret-scanner

**Goal:** build and evolve a Go CLI that scans, verifies, and reports secrets, using trufflehog-compatible detectors plus our own source connectors.

**Trigger:** invoke the `secret-scanner-orchestrator` skill when a request involves any of:
- adding or modifying detectors or sources
- engine, CLI, output-format, or CI changes
- detector or source interface changes (high blast radius)

Single-file greps and trivial questions should be answered directly without invoking the orchestrator.

## Workflow rules

- All packages live in a single Go module rooted at this repo. New packages go under `pkg/<area>/<name>/` without their own `go.mod` (single-module configuration).
- Tests must pass `go test ./... -race`. Race-detector failures block PRs.
- Releases are triggered exclusively by `vX.Y.Z` tag pushes that fan out to GoReleaser via GitHub Actions trusted publishing. `main` push does **not** publish (this is a CLI binary, not a service).
- Because this tool itself handles secret material, every new detector must either implement `Verify()` or be explicitly marked as unverified-only.

## Change history

| Date | Change | Target | Reason |
|------|--------|--------|--------|
| 2026-05-06 | Initial harness (5 agents, 5 skills) + Go scaffold | repo-wide | Spun up from pleno-anonymize as a reference |
| 2026-05-06 | Translated harness to English | `.claude/`, `CLAUDE.md` | Operator language preference |
