# Changelog

All notable changes to **pleno-dlp** (Go binary). Tracks tag-push
trusted publishing — `vX.Y.Z` tags trigger GoReleaser, archives, SLSA
build provenance, and syft SBOMs. The Python package on PyPI is
versioned independently (`py-vX.Y.Z`).

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Anything merged to `main` since v0.14.0.

### Added

- **15 more secret detectors** — batch 18 (constants 260..274):
  MercuryBank, LemonSqueezy, Schematic, Hyperline, Fattureincloud,
  VercelAIGateway, Gandi, Codefresh, Earthly, Spacelift,
  CouchbaseCapella, SlackUserToken, PusherChannels, Hetzner, Pumble.
  Total now **268 secret + 4 PII = 272 detectors**. MercuryBank
  surfaces SeverityCritical when verified (live banking access via
  api.mercury.com). SlackUserToken (xoxp-) is distinct from
  SlackBotToken (xoxb-) because xoxp- grants user-scope (act-as-user)
  which is broader than bot-scope. VercelAIGateway uses the `vck_`
  prefix and is distinct from the existing Vercel deploy-token
  detector (24-char alphanumeric, no prefix). Spacelift (per-account
  host <account>.app.spacelift.io required) and PusherChannels (HMAC
  scheme requires app_id + cluster) are unverified-by-default. The
  GoogleAIStudio candidate was dropped because Gemini API keys share
  the `AIza` prefix already covered by GCPAPIKey — substituted Gandi
  (registrar). The OpenAIProject candidate was dropped because
  `sk-proj-` is already covered by the existing OpenAI detector.

## [0.14.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 17 (constants 245..259):
  WorkOS, FrontEgg, Kinde, Hanko, GitHubFineGrained,
  AzureContainerRegistry, Quay, Replit, PostmarkAccount, Beehiiv, NS1,
  Perplexity, DeepInfra, XAI, GoCardless. Total now **253 secret + 4 PII
  = 257 detectors**. GitHubFineGrained is a separate type from GitHub
  because `github_pat_<82>` is structurally distinct from
  `ghp_/gho_/ghu_/ghs_/ghr_`. PostmarkAccount is distinct from Postmark
  (server token) because it grants account-wide scope. FrontEgg emits a
  paired client_id + client_secret detector via RawV2. GoCardless `live_`
  verified surfaces SeverityCritical (and verifies against the live host;
  `sandbox_` verifies against api-sandbox.gocardless.com). Kinde, Hanko,
  and AzureContainerRegistry are unverified-by-default — they require a
  per-tenant or per-registry host the chunk doesn't carry. Perplexity
  verifies via POST /chat/completions splitting token-good (400/422) from
  token-bad (401) without issuing a billable completion.

## [0.13.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 16 (constants 230..244):
  Webex, Tenable, Rapid7, CrowdStrike, Wiz, SonarQube, MailerLite,
  ActiveCampaign, Drip, BunnyCDN, Vimeo, Cloudinary, PingIdentity,
  Mux, Hookdeck. Total now **238 secret + 4 PII = 242 detectors**.
  Tenable, CrowdStrike, Mux, Cloudinary emit pair detectors (RawV2 carries
  the second half of the credential triple). Hookdeck `hookdeck_live_`
  surfaces SeverityCritical when verified. Wiz, ActiveCampaign, and
  PingIdentity are unverified-by-design — tenant / per-region host not
  predictable from the chunk. Verified detectors (Webex /v1/people/me,
  Rapid7 /idr/v1/users/me, SonarQube /api/authentication/validate,
  MailerLite /api/subscribers/me, Drip /v2/accounts, BunnyCDN /apikey,
  Vimeo /me, Hookdeck /sources, Mux /video/v1/assets,
  Cloudinary /v1_1/&lt;cloud&gt;/usage, Tenable /session, CrowdStrike
  /oauth2/token) all use read-only or auth-only endpoints.

## [0.12.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 15 (constants 215..229):
  AzureDevOps, Jenkins, GoCD, Bamboo, Smartsheet, Wrike, Productboard,
  Miro, Lucidchart, SonatypeNexus, AppStoreConnect, Bitrise,
  Browserstack, StabilityAI, CiscoMeraki. Total now
  **223 secret + 4 PII = 227 detectors**. Browserstack is a paired
  (username + access key) detector emitted via RawV2 — verified with
  HTTP Basic against /automate/plan.json. AzureDevOps verifies via
  /_apis/connectionData with HTTP Basic (empty user, PAT as password).
  Self-hosted shapes (Jenkins, GoCD, Bamboo, SonatypeNexus) and
  AppStoreConnect (.p8 PEM, needs issuer_id + key_id for JWT signing)
  are unverified-by-design — host or signing inputs not in the chunk.
  StabilityAI uses the `sk-` prefix that overlaps with OpenAI's shape;
  the `stability` keyword window plus base62-only suffix gating
  bound the false-positive rate. CiscoMeraki uses the
  `X-Cisco-Meraki-API-Key` header (idiomatic for the platform);
  Smartsheet, Wrike, Productboard, Miro, Lucidchart, and Bitrise all
  verify via Bearer-auth read-only endpoints.

  Swaps from the candidate list, with rationale:
  - **Asana** already covered (batch 4) → **Wrike** (alt workflow API).
  - **Auth0 M2M** would collide with existing Auth0 detector (batch 5)
    → **AzureDevOps** (identity / DevOps slot).
  - **TravisCI / CodeShip** ambiguous against existing CI coverage →
    **Bamboo** (Atlassian self-hosted CI, distinct from Confluence /
    Jira API tokens we already detect).
  - **Sumo Logic Source** would collide with existing SumoLogic →
    **CiscoMeraki** (network / security platform with no existing
    detector).
  - **Honeycomb Beeline** same shape window as existing Honeycomb →
    skipped, replaced by **AppStoreConnect**.
  - **HuggingFace Inference** already covered as HuggingFace →
    **StabilityAI** (frontier image-gen platform).
  - **JFrog Pipelines** would collide with existing JFrog →
    **SonatypeNexus** (distinct artifact-platform shape).
  - **Webex / Workspace ONE / Ping Identity / Beyond Identity** all
    deferred — identity slot taken by AzureDevOps; revisit in batch 16.

## [0.11.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 14 (constants 200..214):
  Akamai EdgeGrid, Fastly, Quip, Box, Zoho, Adyen, Wise, Razorpay,
  Mollie, MessageBird, Sinch, BackblazeB2, Wasabi, Stytch, Cloud66.
  Total now **208 secret + 4 PII = 212 detectors**. Razorpay (key id +
  secret) and BackblazeB2 (key id + app key) emit pair detectors via
  RawV2. Razorpay live, Mollie live, and Stytch live surface
  SeverityCritical (production payment / production identity scope).
  Akamai (HMAC signing scheme), Zoho (region-specific OAuth host),
  Adyen (env-bound endpoint), Sinch (project_id required), BackblazeB2
  / Wasabi (multi-region S3-compat clones), and Stytch (project_id
  required) are unverified-by-design — verification would either need
  state we can't infer from the chunk or trigger destructive write
  paths. Verified detectors (Fastly /tokens/self, Quip
  /1/users/current, Box /2.0/users/me, Wise /v2/profiles, Razorpay
  /v1/items, Mollie /v2/methods, MessageBird /contacts, Cloud66
  /3/account.json) all use read-only endpoints with provider-idiomatic
  auth headers (Fastly-Key, AccessKey, Bearer, Basic).

### Fixed

- `engine.engineRecordingSink` (test fixture) is now concurrent-safe;
  closes an intermittent `-race` flake in
  `TestRunWithStats_CountsChunksBytesFindings` introduced in v0.6.0.

## [0.10.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 13 (constants 185..199):
  Aiven, YugabyteCloud, CockroachCloud, Fauna, Tinybird,
  ClickHouseCloud, Neon, GitLabPipeline, ArgoCD, TektonHub, Spinnaker,
  ConstantContact, Vonage, Workato, AikidoSecurity. Total now
  **193 secret + 4 PII = 197 detectors**. Vonage and ClickHouseCloud
  emit pair detectors (RawV2 carries the second half). Self-hosted CI
  surfaces (ArgoCD, TektonHub, Spinnaker) are unverified-by-design —
  per-tenant Gate-API host not predictable. GitLabPipeline trigger
  tokens are unverified by design too: probing would actually start
  a pipeline (destructive side effect). Swaps from the original list:
  Buildkite Agent → Spinnaker (Buildkite already covered),
  GitLabRunner → AikidoSecurity (`glrt-` already in GitLabDeploy
  regex), Snyk Org → Workato (Snyk already covered). Sentry
  legacy DSN-with-secret and Pardot JWT skipped — both need careful
  disambiguation against existing detectors and were left for a
  follow-up batch.

## [0.9.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 12 (constants 170..184):
  SplunkHEC, ElasticCloud, LogzIO, Coralogix, Loggly, UptimeRobot,
  Pingdom, Honeybadger, Raygun, Statuspage, VictorOps, PagerTree,
  AWX, ConcourseCI, TeamCity. Total now **178 secret + 4 PII =
  182 detectors**. Self-hosted observability and CI surfaces
  (Splunk HEC, Elastic Cloud, AWX, ConcourseCI, TeamCity) are
  unverified-by-design — per-tenant host not predictable from the
  chunk. Swaps from the original list: DatadogAppKey → Pingdom
  (already covered by batch 7), Bugsnag → Raygun (already in batch
  6), NewRelic Insights → UptimeRobot (covered by existing newrelic
  detector via `NRII-` regex).

## [0.8.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 11 (constants 155..169):
  AnthropicAdmin, Pinecone, Weaviate, VoyageAI, Fireworks, Cerebras,
  GitHubApp, JFrog, Pendo, PostHog, SentryUser, CloudflareR2, Mapbox,
  Railway, Telnyx. Total now **163 secret + 4 PII = 167 detectors**.
  Anthropic Console admin keys, Cloudflare R2 access-key + secret pair,
  and Mapbox secret tokens surface as Critical even unverified (admin/
  destructive scope). Anthropic detector now skips `sk-ant-admin-` so
  the new AnthropicAdmin detector is the sole owner. PostHog is scoped
  to `phx_` personal API keys — `phc_` project keys are publishable by
  design. JFrog covers reference tokens (`cmVmdGtuO…` prefix); the
  identifier-aware JWT shape stays with the JWT detector. Mapbox
  deliberately ignores `pk.` public tokens. Swaps from the original
  list, with rationale: Together → Fireworks (Together exists), Modal
  /Replicate → Cerebras (both already in batch 9), GitHub fine-grained
  PAT → JFrog Artifactory (covered by existing github detector), NPM
  granular → Pendo (NPM exists), Heroku → Railway (Heroku exists).

## [0.7.0] — 2026-05-08

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

[Unreleased]: https://github.com/plenoai/pleno-dlp/compare/v0.14.0...HEAD
[0.14.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.14.0
[0.13.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.13.0
[0.12.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.12.0
[0.11.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.11.0
[0.10.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.10.0
[0.9.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.9.0
[0.8.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.8.0
[0.7.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.7.0
[0.6.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.6.0
[0.5.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.5.0
[0.4.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.4.0
[0.3.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.3.0
[0.2.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.2.0
[0.1.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.1.0
