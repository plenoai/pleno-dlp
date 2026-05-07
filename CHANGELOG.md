# Changelog

All notable changes to **pleno-dlp** (Go binary). Tracks tag-push
trusted publishing — `vX.Y.Z` tags trigger GoReleaser, archives, SLSA
build provenance, and syft SBOMs. The Python package on PyPI is
versioned independently (`py-vX.Y.Z`).

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Anything merged to `main` since v0.6.0.

### Added

- **15 more secret detectors** — batch 10 (constants 140..154): OneLogin,
  JumpCloud, Twitch, Lacework, DroneCI, Harness, Sysdig, Lokalise, Pulumi,
  Coda, LoopsSo, AppCenter, Bitwarden, Resend, Helcim. Total now
  **148 secret + 4 PII = 152 detectors**. Bitwarden machine-account tokens
  and Helcim payment tokens surface as Critical even unverified (rotation
  is the only safe remediation). DroneCI is unverified-by-design (server
  URL tenant-specific). Bitwarden, the original list candidates Auth0
  Management and Klaviyo Private were swapped because both already exist
  in earlier batches under the same shapes.

## [0.6.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 9 (constants 125..139): ClickUp,
  Monday, Trello, Gitter, LaunchNotes, Paperspace, RunPod, Modal,
  Linode, Vultr, Scaleway, UpstashRedis, PlanetScale, Clerk, Supabase.
  Total now **133 secret + 4 PII = 137 detectors**. PlanetScale service
  tokens, Clerk `sk_live_`, and Supabase `service_role` JWTs surface as
  Critical (admin-equivalent unverified). Trello / Modal / PlanetScale
  emit pair detectors (RawV2 carries the second half of the credential).
- **`--include-detectors` / `--exclude-detectors`** scoping flags for the
  `scan` subcommand. Comma-separated, case-insensitive, validated against
  the live registry — typos error out instead of silently producing zero
  findings. Custom rules (`--rules`) pass through unfiltered.
- **End-of-scan summary** on stderr: `scanned N chunk(s), B byte(s),
  F finding(s) in T`. Suppress with `--quiet`. Powered by a new
  `engine.Stats{Chunks,Bytes,Findings,Duration}` struct returned from
  the new `Engine.RunWithStats()` API; `Engine.Run()` is unchanged for
  back-compat. Counters are atomic so the snapshot is safe to read
  during a scan.

### Fixed

- Dedup key now incorporates the stdin label, so two distinct stdin scans
  with different `--label` values no longer collapse a shared secret into
  a single finding.

## [0.5.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 8 (constants 110..124):
  Redis URL, Postgres URL, MySQL URL, MongoDB URI, RabbitMQ AMQP,
  Kafka SASL, basic-auth URL, SMTP URL, Adobe.io,
  Docker Hub PAT, GitHub Container Registry, AWS S3 presigned URL,
  GCS signed URL, Azure SQL connection string, kubeconfig.
  Total now **118 secret + 4 PII = 122 detectors**.
- **Engine concurrency benchmarks** (`pkg/engine/bench_test.go`):
  - `BenchmarkScan_ColdPath` (concurrency 1/4/8/16) for sizing
    `--concurrency` against real hardware.
  - `BenchmarkKeywordMatch` to isolate the prefilter cost — every
    chunk pays this regardless of detector hit rate.

### Changed

- URI-shaped detectors (redis, postgres, mysql, mongodb, rabbitmq,
  smtp, basicauth) populate `Raw` with the password span and `RawV2`
  with the full URI so operators can rotate without exposing the
  rest of the connection string.

## [0.4.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 7 (constants 95..109): AlibabaCloud,
  AzureApp, Databricks, DatadogAppKey, DopplerCLI, Freshdesk,
  GCPIDToken, HashiCorpCloud, LaunchDarklyRelay, Ngrok, Opsgenie,
  Snowflake, TencentCloud, TerraformCloudTeam, Zendesk. Total now
  **103 secret + 4 PII = 107 detectors**.
- **Per-host verify rate limiter** (`pkg/verify`) — `--verify-rps`
  (default 10) installs a `RateLimitedTransport` as
  `http.DefaultTransport`. Every detector that uses the default
  client is rate-limited automatically without per-detector
  refactoring. `--verify-rps 0` disables limiting.
- **`.pre-commit-hooks.yaml`** so consumers can adopt pleno-dlp via
  pre-commit with one block in `.pre-commit-config.yaml`.
- **`docs/recipes/`** — GitHub Actions, GitLab CI, pre-commit, and
  allowlist-pattern recipes.

## [0.3.0] — 2026-05-08

### Added

- **31 more secret detectors** — batches 5 (15) + 6 (15) + the
  built-in generic high-entropy detector. Total now **88 secret
  detectors**:
  - Batch 5 (61..75): AzureAD, Telegram, Shodan, VirusTotal,
    Doppler, Vault, Algolia, Airtable, Grafana, LaunchDarkly,
    Auth0, Buildkite, CircleCI, Snyk, Spotify
  - Batch 6 (80..94): AWSSession, AzureSAS, GCPOAuth, GCPAPIKey,
    BitbucketServer, GitLabDeploy, Codecov, Rollbar, Bugsnag,
    SumoLogic, Honeycomb, Tailscale, Figma, Zoom, Klaviyo
  - Constant 13 (`GenericHighEntropy`): catch-all that fires on
    20–128 char runs scoring ≥ 4.0 bits/byte Shannon entropy when
    a credential keyword sits within 256 bytes
- **4 PII detectors** with `finding_class="pii"`:
  - PIIEmail (RFC5322 conservative shape with TLD requirement)
  - PIIUSSSN (xxx-xx-xxxx, rejects reserved blocks)
  - PIICreditCard (Luhn-validated with network labelling)
  - PIIIBAN (mod-97 validated with per-country length table)
- **Allowlist** (`pkg/engine/allowlist.go`) — `--allowlist <path>`
  plus auto-discovery of `.pleno-allow.json`. Match by detector
  type, raw literal, raw regex, and path glob (AND).
- **Stdin source** — `pleno-dlp scan stdin` reads `os.Stdin`,
  `--label` overrides the pseudo-path. TTY guard prevents silent
  blocking on keyboard input.
- **`detectors list` introspection** — `--format table|json|names`,
  output deterministic across runs (sorted by type), powered by the
  same registry the scanner uses.
- **Shell completions** — `pleno-dlp completion <bash|zsh|fish|powershell>`.
- **CHANGELOG.md**, refreshed README with full coverage matrix and
  recipes.

### Changed

- README detector matrix replaced with class-grouped table (77+
  detectors don't fit a per-row spec table).
- Default severity for the four PII types is Medium — information
  leak severity vs the High default for unverified credentials.

## [0.2.0] — 2026-05-08

### Added

- **57 secret detectors** ported from trufflehog's surface, each with
  `Keywords` / `FromData` / `Type` / `Verify`:
  - **Cloud / infra** — AWS, GCP service-account, Azure storage key,
    DigitalOcean, Cloudflare, Heroku, Render, Fly.io, Vercel, Netlify,
    Terraform Cloud, Dropbox
  - **VCS / dev tooling** — GitHub PAT, GitLab PAT, Bitbucket Cloud,
    npm, PyPI, Hugging Face, Postman, Atlassian, Jira, Confluence
  - **AI** — OpenAI, Anthropic, Cohere, Replicate, Mistral, Groq,
    OpenRouter, Together
  - **Comms / SaaS** — Slack bot tokens, Slack webhooks, Discord,
    Twilio, SendGrid, Mailgun, Mailchimp, Brevo, Postmark, Notion,
    Linear, Asana, Mixpanel, Segment, Okta, HubSpot, Intercom,
    Salesforce refresh
  - **Observability** — Datadog, Sentry, New Relic, PagerDuty
  - **Payments / data** — Stripe, Square, PayPal, Plaid,
    MongoDB Atlas
  - **Format-shaped** — JWT, PEM private keys
- **Decoder pipeline** (`pkg/decoder`) — base64 (std + url-safe + raw),
  percent-encoding, hex. Decoded variants are scanned alongside the
  raw chunk; ExtraData["decoded_from"] marks which decode produced
  the hit.
- **Archive walker** (`pkg/archive`) — zip, tar, tar.gz, gzip.
  Recursive expansion with depth cap (4) and per-entry size cap
  (50 MiB) to defuse zip bombs. ExtraData["archive_path"] travels
  with the finding.
- **Custom rule loader** (`pkg/detectors/custom`) — JSON rules with
  `keywords`, `regex`, optional `entropy_min`, `severity`, and
  `verify_url` + `verify_header` (with `{{ .Secret }}` substitution).
- **Severity classification** — `info` / `low` / `medium` / `high` /
  `critical`. Default model: verified ⇒ critical, generic / JWT /
  PEM unverified ⇒ medium, explicit detectors unverified ⇒ high.
  `--fail-on <severity>` gates CI exit code.
- **Allowlist** (`pkg/engine/allowlist.go`) — `--allowlist <path>` and
  auto-discovery of `.pleno-allow.json` from cwd. Match by detector
  type, raw literal, raw regex, and path glob (AND).
- **Git source** (`pkg/sources/git`) — walks a local repository's
  commit history. Flags: `--repo`, `--branch`, `--since`,
  `--max-depth`, `--include`, `--exclude`.
- **Stdin source** (`pkg/sources/stdin`) — `pleno-dlp scan stdin`
  reads a single chunk from `os.Stdin`. `--label` overrides the
  pseudo-path. `--max-bytes` caps buffered input (default 64 MiB).
  TTY guard prevents silent waiting on keyboard input.
- **Filesystem source globs** — `--include`, `--exclude`,
  `--max-size`, `--no-default-excludes`. Default excludes: `.git`,
  `.hg`, `.svn`, `node_modules`, `vendor`, `target`, `dist`,
  `build`, `__pycache__`, `.venv`, `.tox`.
- **SARIF 2.1.0** output now satisfies GitHub Code Scanning ingest
  (rules array, partialFingerprints, semanticVersion, level
  per-severity).
- **JSON / table** outputs render the new severity field plus
  source-specific metadata (file path, repo+commit, stdin label).
- **GoReleaser pipeline** — `-trimpath`, LICENSE + README in
  archives, syft SBOMs, conventional-commit changelog grouping,
  SLSA build provenance via `actions/attest-build-provenance`,
  release attestations via `gh attestation verify`.

### Changed

- `pleno-secret-scanner` rebranded to `pleno-dlp` (unified
  DLP scanner consolidating secrets + PII).

## [0.1.0] — 2026-05-06

### Added

- Initial MVP: filesystem source + 5 detectors (AWS, GitHub PAT,
  Slack bot, OpenAI, Anthropic) + JSON / SARIF / table output +
  cobra `scan` CLI. 51 race-clean tests.

[Unreleased]: https://github.com/plenoai/pleno-dlp/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.6.0
[0.5.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.5.0
[0.4.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.4.0
[0.3.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.3.0
[0.2.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.2.0
[0.1.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.1.0
