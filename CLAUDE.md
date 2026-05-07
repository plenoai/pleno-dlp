# pleno-dlp

Unified DLP scanner — secrets and PII over filesystem and SaaS content.
Detector interface is trufflehog-compatible (Go); SaaS sources flow
through [saas-retriever](https://github.com/plenoai/saas-retriever) on
the Python side.

## Harness: pleno-dlp

**Goal:** maintain and evolve the unified DLP scanner — Go binary
(filesystem-only) + Python package (SaaS via saas-retriever, secret +
PII backends).

**Trigger:** invoke the `secret-scanner-orchestrator` skill when a
request involves any of:
- adding or modifying detectors or sources
- engine, CLI, output-format, or CI changes
- detector / source / backend interface changes (high blast radius)
- PII backend integration with pleno-anonymize

Single-file greps and trivial questions should be answered directly
without invoking the orchestrator.

## Workflow rules

- All Go packages live in a single Go module rooted at this repo. New
  packages go under `pkg/<area>/<name>/` without their own `go.mod`
  (single-module configuration).
- Go tests must pass `go test ./... -race`. Race-detector failures block
  PRs.
- Python tests must pass `uv run --frozen pytest` and stay ruff + mypy
  strict-clean.
- Releases trigger exclusively by tag push:
  - `vX.Y.Z` → Go binary release via GoReleaser trusted publishing.
  - `py-vX.Y.Z` → Python package release to PyPI via trusted publishing.
- `main` push runs build + tests only — it does not publish (this is a
  CLI binary, not a service).
- Because this tool handles secret material, every new secret detector
  must either implement `Verify()` or be explicitly marked
  unverified-only. PII backends must mark findings with
  `finding_class="pii"` so downstream callers can route by class.

## Change history

| Date | Change | Target | Reason |
|------|--------|--------|--------|
| 2026-05-06 | Initial harness (5 agents, 5 skills) + Go scaffold | repo-wide | Spun up from pleno-anonymize as a reference |
| 2026-05-06 | Translated harness to English | `.claude/`, `CLAUDE.md` | Operator language preference |
| 2026-05-06 | MVP end-to-end (filesystem source + AWS/GitHub/Slack/OpenAI/Anthropic detectors + scan CLI + json/sarif/table output) | `pkg/`, `cmd/` | Make the scanner usable from the command line; 51 race-clean tests, 11/11 e2e checks |
| 2026-05-06 | Python package 0.2.0 consuming saas-scraper (native/trufflehog/gitleaks backends, json/sarif/table sinks, CLI) | `python/`, `.github/workflows/{test,release}-py.yml` | SaaS-source path; Go binary keeps filesystem scope. Tag pattern `py-vX.Y.Z` |
| 2026-05-06 | Python 0.4.0 — switch to saas-retriever (API-only, no Playwright) | `python/` | Org-wide GitHub support, no Chromium |
| 2026-05-07 | Rebrand `pleno-secret-scanner` → `pleno-dlp`; Python 0.5.0 with PII backend slot | repo-wide | Unified DLP scanner consolidating secret + PII scans; pleno-anonymize trims to PII model + API only |
| 2026-05-07 | saas-retriever 1.0.0 with all 7 connectors (github, gitlab, bitbucket, notion, confluence, jira, slack); pleno-dlp 0.6.0 bridge surfaces every kind via `--option k=v` | `python/`, saas-retriever | Org-wide SaaS coverage; CLI now addresses all v1 connector kinds |
| 2026-05-07 | Strip pleno-anonymize to PII filter API + Model only (28 `pii-scanner*` packages, `deploy/`, scanner ADR/solution notes deleted) | pleno-anonymize | Single-responsibility per repo: pleno-anonymize hosts the PII model + API; pleno-dlp owns scanning |
| 2026-05-07 | Detector batches 1–3 (37 trufflehog-compatible detectors), decoder pipeline (base64/percent/hex), archive walker (zip/tar/gzip), severity classification + custom-rule loader, SARIF Code Scanning compliance, --fail-on, git history source, filesystem --include/--exclude globs | `pkg/detectors/`, `pkg/decoder/`, `pkg/archive/`, `pkg/output/sarif.go`, `pkg/sources/git/`, `cmd/scan.go` | Production-ready depth: 42 detectors, severity gating, decoded variants, archive expansion |
| 2026-05-08 | Stdin source + allowlist mechanism + detector batch 4 (15 more → 57 total: jira, confluence, bitbucketcloud, square, paypal, plaid, discord, cohere, replicate, mistral, groq, intercom, openrouter, together, dropbox); CHANGELOG.md; v0.2.0 tag-push trusted publishing | `pkg/sources/stdin/`, `pkg/engine/allowlist.go`, `pkg/detectors/`, `CHANGELOG.md` | Production-ready breadth: 57 detectors, FP allowlist, pipe-to-scan UX, 429 race-clean tests across 71 packages |
