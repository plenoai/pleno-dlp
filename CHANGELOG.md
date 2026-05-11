# Changelog

All notable changes to **pleno-dlp** (Go binary). Tracks tag-push
trusted publishing — `vX.Y.Z` tags trigger GoReleaser, archives, SLSA
build provenance, and syft SBOMs.

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Anything merged to `main` since v0.42.0.

### Added

- **JWT claim-aware severity & enrichment.** The `JWT` detector now
  decodes header + payload and pins severity from claim contents:
  - `alg=none` → Critical with `jwt_alg_none=true`. The header opts
    the token out of signing entirely; anyone can forge a payload.
    This is a vulnerability finding, not "an unverified credential."
  - `exp` in the past → Low with `jwt_status=expired`. Still a leak
    (audit trail, refresh-token semantics) but not a live credential.
  - `exp` in the future → High with `jwt_status=active`.
  - No `exp` → Medium (default).
  - alg=none beats every expiry path.
  - New ExtraData fields: `kid`, `iat`, `nbf`, `azp`, `client_id`,
    `scope` (normalised to comma-joined whether the source was the
    OAuth2 space-delimited string or a `scopes` array), `aud`
    (comma-joined for arrays), `exp_iso` (RFC3339 of `exp`).
  - `issuer_class` tag for well-known IdPs: `github-actions-oidc`,
    `google`, `auth0`, `okta`, `firebase`, `aws-cognito`, `azure-ad`,
    `atlassian`, `slack`. Tenant subdomains match by suffix
    (`<tenant>.auth0.com`, `<tenant>.okta.com`).
- **GitHub PAT blast-radius enrichment.** The `GitHub` detector
  graduates Verify from a bare 200/401 check to a metadata-bearing
  call. New ExtraData when verified:
  - `github_token_type` — classic | fine-grained | oauth |
    user-to-server | server-to-server | refresh, derived from prefix
  - `github_login`, `github_user_id`, `github_account_type`
  - `github_scopes` — normalised, comma-joined `X-OAuth-Scopes` header
  - `github_token_expiration` — `Github-Authentication-Token-Expiration`
    header (fine-grained PATs and SAML-enforced classic PATs)
  - `github_privileged="true"` when scopes include any of `repo`,
    `delete_repo`, `admin:org`, `admin:enterprise`, `admin:repo_hook`,
    `admin:org_hook`, `write:packages`, `workflow`, `site_admin` —
    same Critical bucket but triage-sortable by impact.
  - Same driftwood-style "what does this credential actually unlock"
    pattern previously shipped for `PrivateKeyPEM`.
- **AWS access-key blast-radius enrichment.** The `AWS` detector
  graduates Verify from a bare 200/error STS check to a metadata-bearing
  call that surfaces the identity returned by sts:GetCallerIdentity:
  - `aws_account_id` — 12-digit AWS account number
  - `aws_arn` — full caller ARN
  - `aws_user_id` — AWS principal id (AIDA…/AROA…)
  - `aws_principal_kind` — root | user | assumed-role |
    federated-user | role | other
  - `aws_partition` — aws | aws-cn | aws-us-gov, parsed from the ARN
  - `aws_privileged="true"` when the caller is the account root,
    or the role/user name contains any of `admin`, `administrator`,
    `poweruser`, `breakglass`, `organizationaccountaccessrole`,
    `awsreservedsso_admin`, `superuser`, `root`. Same Critical
    bucket but triage-sortable by impact.
  - Same driftwood-style "what does this credential actually unlock"
    pattern previously shipped for `PrivateKeyPEM` and `GitHub`.
- **Slack bot-token blast-radius enrichment.** The `SlackBotToken`
  detector graduates Verify from a bare `ok` boolean to a metadata-
  bearing call that surfaces the workspace identity returned by
  `auth.test`:
  - `slack_team_id`, `slack_team_name`, `slack_team_url`
  - `slack_user_id`, `slack_user_name`, `slack_bot_id`
  - `slack_enterprise_id`, `slack_enterprise_install="true"` (Grid)
  - `slack_scopes` — comma-joined `X-OAuth-Scopes` response header
  - `slack_privileged="true"` when scopes include any of `admin`,
    `admin.users:write`, `admin.conversations:write`,
    `admin.teams:write`, `chat:write.public`, `users:read.email`,
    `files:write`. Same Critical bucket but triage-sortable.
  - Same driftwood-style "what does this credential actually unlock"
    pattern previously shipped for `PrivateKeyPEM`, `GitHub`, `AWS`.
- **Stripe blast-radius enrichment** (driftwood port). The Stripe
  detector now points `Verify` at `/v1/account` instead of
  `/v1/charges`. On success it decodes the account and stamps
  `ExtraData` with `stripe_account_id`, `stripe_business_name`,
  `stripe_country`, `stripe_default_currency`, `stripe_livemode`,
  `stripe_charges_enabled`, and `stripe_payouts_enabled` so triagers
  can immediately see *whose* Stripe account the leaked key controls
  and whether it can move money. A live key whose account has
  `livemode && charges_enabled && payouts_enabled` additionally gets
  `stripe_high_value=true` (test-mode keys are forbidden from this
  flag). Restricted keys (`rk_*`) that lack `read_write` on the
  account resource fall back to the legacy `/v1/charges` probe so
  verification still succeeds. Every finding (verified or not)
  carries `stripe_key_mode` ∈ {`live`, `test`, `restricted-live`,
  `restricted-test`, `unknown`} for sortable triage.
- **OpenAI key blast-radius enrichment** (driftwood port). The OpenAI
  detector now classifies every finding by prefix
  (`openai_key_kind` ∈ {`legacy-user`, `project`, `service-account`,
  `admin`, `unknown`}) and on a verified hit decodes `/v1/models` to
  surface what the key actually unlocks: `openai_organization` (from
  the `openai-organization` response header), `openai_models_count`,
  and `openai_notable_models` — a comma-joined slice of the
  high-impact families visible to the key (`gpt-4`, `gpt-4o`,
  `gpt-4-turbo`, `o1`, `o3`, `dall-e-3`, `whisper`,
  `text-embedding-3-large`, `tts-1`). Legacy-user and admin keys
  additionally get `openai_privileged="true"` (legacy-user keys
  inherit full org access from the user; admin keys are
  organization-management-scoped). Project and service-account keys
  are scoped and stay out of the privileged bucket. Same Critical
  bucket but triage-sortable by impact.
- **Twilio Account-SID / Auth-Token blast-radius enrichment**
  (driftwood port). The Twilio detector now decodes the
  `/2010-04-01/Accounts/<sid>.json` response on a verified pair and
  stamps `ExtraData` with the account identity:
  `twilio_friendly_name`, `twilio_account_status`,
  `twilio_account_type`, `twilio_date_created`. Subaccount
  credentials get `twilio_subaccount="true"` and `twilio_owner_sid`
  pointing at the parent. Full + active accounts get
  `twilio_high_value="true"` — only those have real billing
  relationships and therefore SMS/voice fraud capability; Trial and
  suspended accounts are containable. Same Critical bucket but
  triage-sortable by impact.

## [0.42.0] — 2026-05-12

### Changed

- **False-positive reduction sweep** across detectors, engine, and
  the filesystem source. User report flagged Expo and similar
  detectors as a major FP source; this release fixes eight
  structural causes at once.
- Tightened seven detectors: **Expo**, **drift**, **lever**,
  **pumble**, **totango**, **sift**, and **branchio**. Each
  replaces a `strings.Contains(window, kw)` keyword gate with a
  precompiled regex requiring explicit separators (`<provider>_token`
  / `<provider>.com` / `<provider>.dev`), so common English words
  no longer satisfy the keyword check (`export` / `exposure` /
  `exponent` no longer trigger Expo; `drifted` / `adrift` no longer
  trigger Drift; `leveraged` / `however` no longer trigger Lever;
  `sifted` / `sifting` no longer trigger Sift). Token regexes
  narrow to fixed lengths or provider-specific shapes so 40-char
  git SHAs, JWT mid-segments, npm sha512 fragments, and
  dashless-UUIDs stop matching. `branchio` drops its bare `branch`
  keyword (which collided with git terminology).
- Engine dedup now prefers **Verifier-backed detectors over the
  generic high-entropy detector** when both fire on identical raw
  bytes. Stops a single AWS access key (or similar) from emitting
  twice — once as `AWS`, once as `GenericHighEntropy`.

### Added

- Default filesystem excludes now cover **lockfiles and
  minified/sourcemap bundles**: `package-lock.json`, `yarn.lock`,
  `pnpm-lock.yaml`, `Cargo.lock`, `go.sum`, `Pipfile.lock`,
  `poetry.lock`, `composer.lock`, `Gemfile.lock`, `mix.lock`,
  `Podfile.lock`, and globs `*.min.js`, `*.min.css`, `*.map`,
  `*.bundle.js`. These files dump high-entropy sha256/sha512
  integrity hashes that previously slipped past the generic
  detector. `DisableDefaultExcludes` continues to opt back in.
- New `pkg/engine/placeholder.go` engine sink rejects well-known
  throwaway tokens **before they reach the allowlist**:
  `AKIAIOSFODNN7EXAMPLE` and any other `*EXAMPLE*` /
  `YOUR_TOKEN` / `YOUR_KEY` / `YOUR_SECRET` / `PLACEHOLDER` /
  `REDACTED` / `<TOKEN>` / `<SECRET>` / `<KEY>` substrings, runs
  of `X{8,}` or `0{10,}`, and exact matches for `dummy` / `test` /
  `foo` / `bar` / `password` / `changeme`. Scan output now reports
  `placeholder: suppressed N finding(s)` on stderr (parallel to
  the existing `allowlist: suppressed …` line).
- Shared Shannon entropy helper at `pkg/detectors/entropy.go`
  (`ShannonEntropy(s)`, `HasMinEntropy(s, threshold)`). Applied as
  a per-finding gate inside `drift`, `lever`, `pumble`, `totango`,
  and `sift` so `0000…0` / `aaaa…a` / repeating-pattern tokens are
  rejected at the detector layer.
- Generic high-entropy detector keyword list expanded by 14
  entries: `signing_secret` / `signing-secret`, `webhook_secret`
  variants, `private_token` variants, `auth=` / `auth:`,
  `bearer:` (the colon form), `authorization:`, `x-secret`,
  `x-token`. The wider net is offset by the new dedup priority and
  placeholder sink.

### Added

- **PrivateKeyPEM blast-radius (driftwood port).** The `PrivateKeyPEM`
  detector graduates from class-b (unverified-by-design) to class-a
  (Verifier). New behaviour:
  - Local public-key derivation for RSA / EC / Ed25519 / OpenSSH /
    PKCS#8 keys, surfacing `pubkey_algorithm`,
    `pubkey_fingerprint_sha256` (SPKI SHA-256 hex, suitable for
    crt.sh `?spkisha256=`), and `ssh_fingerprint`
    (`SHA256:<base64-no-pad>`, matches `ssh-keygen -lf`).
  - Embedded passphrase wordlist tried against encrypted PEMs (legacy
    `Proc-Type: 4,ENCRYPTED`, modern PKCS#8 PBES2, OpenSSH bcrypt-KDF).
    A successful unlock sets `pem_unlocked_with` and bumps unverified
    severity from Medium to High — an "encrypted" key with a guessable
    passphrase has no real protection.
  - When `--verify` is set, the SPKI fingerprint is queried against
    Certificate Transparency via crt.sh. Matches populate
    `blast_radius_domains` (deduplicated CN + SAN list) and
    `blast_radius_cert_count`, mark `Verified=true`, and escalate
    severity to Critical. The private-key body never leaves the host;
    only the public-key SHA-256 (itself a public artefact) is
    transmitted, and only to crt.sh.
  - Inspired by [trufflesecurity/driftwood](https://github.com/trufflesecurity/driftwood)
    and [betterleaks/betterleaks](https://github.com/betterleaks/betterleaks).
  - New package: `pkg/detectors/privatekey/blastradius`.
  - verify-coverage counts: a=514 (+1), b=43 (-1), total unchanged.

## [0.41.0] — 2026-05-10

### Changed

- **BREAKING (output schema):** the four legacy regex PII detectors
  (`piiemail`, `piicc`, `piiiban`, `piissn`) are removed and
  replaced by a single `PIIAnonymize` detector backed by the
  [pleno-anonymize](https://github.com/plenoai/pleno-anonymize)
  loopback NER+regex engine (ADR-0001 / ADR-0003). New scans no
  longer emit `PIIEmail` / `PIIUSSSN` / `PIICreditCard` / `PIIIBAN`
  finding types; SARIF rule descriptions for those four are
  removed. The corresponding `DetectorType` ordinals (76..79) stay
  pinned with `Deprecated:` comments so historical JSON outputs
  decode without error. Per-finding entity type now lives in
  `ExtraData["pii_kind"]` (`PERSON`, `EMAIL_ADDRESS`,
  `JP_MY_NUMBER`, `ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `IBAN`,
  `US_SSN`, …); `ExtraData["finding_class"]="pii"` is unchanged so
  downstream routing on finding class continues to work. The engine
  is spawned via the new `pleno-dlp pii-server` subcommand, which
  shells out to `uv` (`uv sync` + `uv run`) against a cached clone
  of the upstream repo; the prerequisite is `uv` and Python 3.12+
  on `PATH`, plus `git` when `--source` is a `git+` URL (the
  default). Docker is no longer used (ADR-0003 supersedes
  ADR-0002's earlier Docker recommendation).

### Added

- `PIIAnonymize` detector (`pkg/detectors/anonymize/`). Calls
  `pkg/piiengine/anonymize.Default()` to retrieve the supervisor
  singleton; silent-skips when the engine is off (the default).
  Severity stays Medium (PII has no verified pathway). Allowlist
  callers should migrate `detector: PIIEmail` (etc.) entries to
  `detector: PIIAnonymize` and add a `raw_regex` or path scope to
  preserve the original intent — see
  `docs/recipes/allowlist-patterns.md` for the migration shape.
- `pleno-dlp pii-server` subcommand. Foreground-runs the
  pleno-anonymize HTTP server by cloning the upstream repo into a
  cache dir, running `uv sync --frozen --no-dev --package
  pleno-anonymize-server` (workspace-aware so the server's
  `[tool.uv.sources] pleno-anonymize = { workspace = true }`
  declaration resolves against the sibling SDK), installing the
  three NER model wheels that `uv.lock` cannot pin (spaCy +
  ja-ner-ja + en-ner-en, hosted off PyPI), and finally `uv run
  --no-sync --package pleno-anonymize-server uvicorn
  server.src.app:app`. Used internally as the default spawn target
  for `--pii-engine=anonymize`; also runnable directly for ad-hoc
  local use. Flags: `--port` (`0` = ephemeral; resolved port is
  printed to stdout in the `pii-server: listening on HOST:PORT`
  form), `--host` (loopback / RFC1918 / link-local only — refuses
  `0.0.0.0`), `--git-ref` (clone / checkout target ref), `--source`
  (`git+` URL or a local workspace-root path), `--cache-dir`
  (defaults to `<os.UserCacheDir>/pleno-dlp/pleno-anonymize`;
  override via `PLENO_DLP_ANONYMIZE_CACHE` env), `--no-fetch`
  (use the existing checkout as-is — offline / reproducible runs).
  Pre-flight LookPath verifies `uv` is installed and emits a
  targeted "install uv" hint when it's not. The supervisor's
  ready-poll fast-fails on child exit via the new `ErrEngineExited`
  sentinel, so misconfigured spawns surface in milliseconds instead
  of burning the full `--pii-engine-ready-timeout` budget.

## [0.40.0] — 2026-05-10

### Added

- Provider-side credential revocation extended from GitHub to GitLab,
  Slack, AWS, and Stripe. Each Revoker uses the provider's
  documented endpoint with the standard idempotency contract
  (`Revoked=true` with a non-fatal `Err` for already-revoked /
  not-found responses; hard error for transport / 5xx / 429). AWS
  ships an inline SigV4 signer (no AWS SDK dependency) and is
  classified `context-required` because `iam:DeleteAccessKey` needs
  admin IAM creds plus the target IAM user name. (#73)
- `pleno-dlp scan --revoke-on-verified` flag. Wraps the sink chain
  after dedup + allowlist so a verified finding whose detector
  implements `detectors.Revoker` is revoked in-line. Refuses to run
  without `--verify` and without `PLENO_DLP_ALLOW_REVOKE=1`.
  `--revoke-dry-run` previews without contacting providers. The
  end-of-scan summary surfaces `attempted` / `revoked` / `failed` /
  `skipped-no-revoker` counters so batch revoke runs are auditable
  without scraping per-finding output. (#73)
- `pleno-dlp detectors list --revoke-support` flag. Annotates each
  detector row with `supported` / `context-required` /
  `unsupported`, sourced from interface satisfaction
  (`detectors.Revoker`) plus a small allowlist for context-required
  detectors. Both table and JSON output carry the classification;
  the JSON fields are `revokes` (bool) and `revoke_status` (string)
  and both are omitted when the flag is not set so existing
  consumers see a byte-identical shape. (#73)
- `pleno-dlp revoke --rate-limit-rps` flag. Installs the per-host
  `pkg/verify` rate limiter for the duration of a batch revoke loop
  so many sequential revocations against the same provider do not
  trip provider quotas. Default 0 (disabled) preserves single-shot
  revoke latency. (#73)
- `pleno-dlp revoke` now dispatches `gitlab` / `slack` / `aws` /
  `stripe` in addition to the existing `github`. Provider-specific
  overrides ride through dedicated flags
  (`--aws-admin-access-key-id` / `--aws-admin-secret-access-key` /
  `--aws-admin-session-token` / `--aws-region` / `--aws-user-name`)
  with `PLENO_DLP_REVOKE_AWS_*` env-var fallbacks. (#73)
- `docs/revoke-support.md` documenting the provider matrix, gating
  model, idempotency contract, AWS principal-context wiring,
  failure-handling policy, and a CI usage recipe. The runtime
  classification (`detectors list --revoke-support`) remains the
  canonical answer; the doc explains the why. (#73)

### Notes

- Detectors perform no local revoke gating. The
  `--confirm` / `--dry-run` / `PLENO_DLP_ALLOW_REVOKE=1` /
  `--verify` policy lives uniformly at the CLI boundary so dry-run
  behaves identically across providers.
- `Stripe` revoke is restricted to keys with the `rk_` prefix
  (restricted keys). Secret keys (`sk_`) are hard-rejected before
  any network I/O so callers cannot believe rotation succeeded.
- `AWS` revoke without operator-supplied principal context lands in
  `skipped-no-revoker` during `scan --revoke-on-verified` rather
  than failing the scan. Operators batching AWS revocations should
  script `pleno-dlp revoke --detector aws` with the correct
  `--aws-user-name` per finding.

## [0.39.0] — 2026-05-10

### Added

- `pleno-dlp detectors list --verify-status` flag. Annotates each
  detector row with `verified` / `unverified-by-design` / `verify-gap`,
  sourced from `docs/verify-coverage.md` via the new
  `pkg/detectors/verifycoverage` package. Both table and JSON output
  carry the classification; the JSON field is `verify_status` and is
  omitted when the flag is not set so existing consumers see a
  byte-identical shape. (#72)
- `pkg/detectors/verifycoverage` package mirroring the doc's
  `coverage-machine` block as a Go map, plus
  `verifycoverage_sync_test.go` that fails CI on drift between the
  doc and the map. Combined with the existing
  `pkg/detectors/verifycoverage_test.go` (registry ↔ doc drift),
  adding a non-Verifier detector now requires three coordinated edits
  — the absence of any one fails CI. (#72)

## [0.38.0] — 2026-05-10

### Changed

- **Connectors refactored to Lambda-handler shape.** The old contract
  — `SaaSConnector` interface, `Descriptor` / `Capability` /
  `AuthMode` bitmask, `Factory` constructor, separate
  `client.go` + `pagination.go` per provider — has been replaced with
  a flat `Connector` struct of three function fields:

  ```go
  type Connector struct {
      SourceType sources.SourceType
      Scan       func(ctx, cfg, emit) error
      Verify     func(ctx, cfg, secret) (bool, error)
      Revoke     func(ctx, cfg, secret) (RevokeResult, error)
  }
  ```

  Every provider is now a single file at `pkg/connectors/<name>.go` in
  `package connectors` that registers a `Connector` value in `init()`.
  `connectors.AsSource(name, cfg)` wraps a registered connector as a
  `sources.Source` so the engine drives it through the same loop it
  uses for filesystem / git / stdin. Connector authors never see
  `jobID` / `sourceID` / `concurrency` plumbing.

- **All seven SaaS connectors migrated.** github (#74), gitlab (#75),
  bitbucket (#76), notion (#77), confluence (#78, also gained an
  initial implementation — was a stub), jira (#79), slack (#80) all
  rewritten as single-file Lambda handlers. Behaviour preserved end to
  end: rate limiters, pagination shapes, auth dispatch, content
  parsers (notion markdown, jira ADF, jira/confluence storage XHTML)
  all unchanged.

- **6 cmd files slimmed.** Type assertions, `Capability.Has(...)`
  guards, and `SetAPIBase` setter detection are gone — every
  `runScan<Provider>` / `runVerify<Provider>` defers to the shared
  `runScanSaaS` / `runVerifySaaS` helpers in `cmd/saas.go`.

### Added

- **Confluence connector.** Full implementation at
  `pkg/connectors/confluence.go` plus
  `cmd/pleno-dlp/cmd/confluence_cmd.go`. Surface: paginated content
  search → per-page body emit → footer + inline comment walk. Cloud
  Basic auth (email + API token) and Data Center PAT Bearer.

### Removed

- `pkg/tfhost/` — the Terraform-provider host abandoned upstream
  before the pivot landed (long-tail SaaS generic adapter turned out
  to be YAGNI; native connectors are simpler and faster).
- `pkg/connectors/_paginate/` — the GitHub / GitLab Link-header
  parser inlined into `pkg/connectors/github.go` and reused by
  `pkg/connectors/gitlab.go` from the same package.
- `pkg/connectors/{github,gitlab,bitbucket,notion,confluence,jira,slack}/`
  per-provider subpackages and their `client.go` / `pagination.go`
  / `<name>_test.go` files. Helper sub-packages
  (`notion/markdown`, `jira/{adf,storage}`, `confluence/storage`) are
  preserved as stable text-conversion utilities.

### Removed (carried forward from 0.37.0)

- **Python package retired** — the `python/` tree, vendored
  `saas_retriever`, `pleno_dlp` Python namespace, and the
  `.github/workflows/{test-py,release-py}.yml` CI lanes are gone.
  pleno-dlp ships as a single Go binary going forward; `py-vX.Y.Z` tags
  are no longer published. This is a breaking change for callers
  depending on the `pip install pleno-dlp` distribution — pin to
  py-v0.12.0 or migrate to the Go binary.

### Stats

- 4241 race-clean tests across 622 packages (down from 4304 — 63
  per-connector white-box tests deleted alongside their subpackages,
  to be re-landed against the new Lambda-handler API in a follow-up).
- Net code change: **+~1,300 LoC connector framework + 7 single-file
  connectors, −~7,100 LoC** from old subpackages, helpers, and the
  abandoned tfhost spike.

## [0.37.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 40 (constants 590..604), landing
  the **600th detector**: Riskified, Forter, Socure, Agenta, Kayako,
  Customerly, Jellyfish, Swimlane, Parabola, Mailmodo, Neo4jAura,
  PortSwigger, Kagi, ArduinoCloud, ParticleIO. Total now **598 secret
  + 4 PII = 602 detectors**. Fraud / risk (Riskified 64-hex token near
  `riskified` keyword, Bearer via api.riskified.com; Forter 40-80
  alnum near `forter` keyword, HTTP Basic via api.forter.com; Socure
  40-80 alnum near `socure` keyword, "Authorization: SocureApiKey"
  header via api.socure.com), LLM ops (Agenta `agenta_` prefix Bearer
  via /api/profile on cloud.agenta.ai), customer support (Kayako
  40-80 alnum near `kayako` keyword, X-Auth-Token via kayako.com;
  Customerly 40-80 alnum near `customerly` keyword, Bearer via
  api.customerly.io), eng analytics (Jellyfish 40-80 alnum near
  `jellyfish` keyword, X-API-Key via api.jellyfish.co), SOAR
  (Swimlane 40-80 alnum near `swimlane` keyword, Private-Token via
  app.swimlane.com), workflow (Parabola 32-80 alnum near `parabola`
  keyword, Bearer via api.parabola.io), email (Mailmodo 40-80 url-safe
  near `mailmodo` keyword, mmApiKey header via api.mailmodo.com),
  DBaaS (Neo4jAura 40-80 url-safe near `neo4j`/`aura` keyword, Bearer
  via api.neo4j.io), security testing (PortSwigger Burp Enterprise key
  embedded in API path, near `portswigger`/`burp` keyword), search
  (Kagi `kagi_` prefix Bot auth via kagi.com), IoT (ArduinoCloud
  32-80 alnum near `arduino` keyword, Bearer via api2.arduino.cc;
  ParticleIO 40-hex near `particle` keyword, Bearer via
  api.particle.io). All keyword-anchored to keep generic alnum / hex
  shapes from cross-colliding with other providers.

## [0.36.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 39 (constants 575..589):
  Fiddler, Evidently, Sift, Signifyd, Kount, Intigriti, Bugcrowd,
  Semgrep, TemporalCloud, PrefectCloud, DagsterCloud, FlyMachines,
  VercelBlob, ModeAnalytics, PDFShift. Total now **583 secret + 4 PII
  = 587 detectors**. LLM ops / ML monitoring (Fiddler 40-80 url-safe
  alnum near `fiddler` keyword, Bearer via /v3/projects on
  api.fiddler.ai; Evidently 40-80 url-safe alnum near `evidently`
  keyword, X-Evidently-Token via /api/v2/auth/profile on
  app.evidently.cloud), fraud / KYC (Sift accountId + apiKey pair near
  `sift` keyword — paired (RawV2), Basic auth on api.sift.com
  /v205/accounts; Signifyd teamId + apiKey pair near `signifyd`
  keyword — paired (RawV2), Basic auth on api.signifyd.com /v3/teams;
  Kount JWT-shaped token near `kount` keyword, Bearer via
  /commerce/v1/orders on api-sandbox.kount.com), bug bounty (Intigriti
  40-128 url-safe near `intigriti` keyword, Bearer via
  /external/researcher/v1/me on api.intigriti.com; Bugcrowd 40-128
  url-safe near `bugcrowd` keyword, "Authorization: Token" via /user
  on api.bugcrowd.com), vulnerability mgmt (Semgrep 40-80 url-safe
  near `semgrep` keyword, Bearer via /api/v1/deployments on
  semgrep.dev), workflow / orchestration (TemporalCloud `tcsk_`
  prefix Bearer via /api/v1/namespaces on cloud.temporal.io;
  PrefectCloud `pnu_` prefix Bearer via /api/me on api.prefect.cloud;
  DagsterCloud `dgc_` prefix Dagster-Cloud-Api-Token via /graphql on
  dagster.cloud), serverless (FlyMachines `fly_` / `FlyV1` prefix
  Bearer via /v1/apps on api.machines.dev), storage (VercelBlob
  `vercel_blob_rw_` prefix Bearer via /v0 on
  blob.vercel-storage.com), BI (ModeAnalytics token + secret pair
  near `mode_analytics`/`modeanalytics`/`mode.com` keyword — paired
  (RawV2), Basic auth on app.mode.com /api/account), document
  (PDFShift `sk_` prefix near `pdfshift` keyword, Basic auth
  api: + key on api.pdfshift.io /v3/credits/usage). All 15 ship live
  Verify implementations with 200/401/500 httptest coverage. Test
  count rises to 4,027 race-clean across 602 packages.

## [0.35.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 38 (constants 560..574):
  Traceloop, Klu, Langflow, OpenPipe, Lakera, Footprint, Vouched,
  Magento, BigCommerce, Faire, Tidio, Looker, DeepL, HackerOne,
  ZeroTier. Total now **568 secret + 4 PII = 572 detectors**. LLM ops /
  agent / tracing (Traceloop `tl_` Bearer via /v1/traces on
  api.traceloop.com, Klu `klu_` Bearer via /v1/me on api.klu.ai,
  Langflow `lf_` x-api-key via /api/v1/users/whoami on
  api.langflow.astra.datastax.com, OpenPipe `opk_` Bearer via
  /api/v1/me on api.openpipe.ai), LLM security (Lakera 32-64 alnum
  near `lakera` keyword, Bearer via /v1/prompt_injection on
  api.lakera.ai), KYC (Footprint `sk_test_`/`sk_live_` near `footprint`
  keyword X-Footprint-Secret-Key via /users on api.onefootprint.com,
  Vouched `pk_` near `vouched` keyword X-Api-Key via /api/jobs on
  verify.vouched.id), e-commerce (Magento 32-hex near `magento` keyword
  unverified-by-default per-store host required, BigCommerce 31-alnum
  near `bigcommerce` keyword X-Auth-Token via /v2/store on
  api.bigcommerce.com, Faire `fai_` X-FAIRE-ACCESS-TOKEN via
  /external-api/v2/orders on www.faire.com), customer chat (Tidio
  40-hex near `tidio` keyword X-Tidio-Openapi-Key via
  /panel/openapi/contacts on api.tidio.co), data platforms (Looker
  client_id + client_secret pair near `looker` keyword — paired
  (RawV2), unverified-by-default per-tenant Looker host required),
  translation (DeepL UUID + optional `:fx` suffix DeepL-Auth-Key via
  /v2/usage on api-free.deepl.com), bug bounty (HackerOne identifier +
  API-token pair near `hackerone` keyword — paired (RawV2), HTTP Basic
  via /v1/users/me on api.hackerone.com), networking (ZeroTier 32-alnum
  near `zerotier` keyword Bearer via /api/v1/status on
  my.zerotier.com). Looker / HackerOne use paired-credential (RawV2);
  Magento / Looker are unverified-by-default (per-tenant host
  required).

## [0.34.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 37 (constants 545..559): DBTCloud,
  Tray, Retool, Expo, Alloy, AuditBoard, FireHydrant, IncidentIO, Rootly,
  Sleuth, Sparkpost, SendPulse, Veriff, IDnow, Squarespace. Total now
  **553 secret + 4 PII = 557 detectors**. Data platforms (DBTCloud
  `dbtu_` Authorization Token via /api/v2/accounts on cloud.getdbt.com),
  low-code / workflow (Tray `tray_` Bearer via /core/v1/me on
  api.tray.io, Retool `retool_` Bearer via
  /api/v2/permissions/listGroupAndUser on api.retool.com), mobile build
  (Expo Bearer via /v2/auth/userInfo on exp.host with `expo` keyword
  anchor), KYC / identity (Alloy paired token+secret Basic auth via
  /v1/journeys on sandbox.alloy.co, Veriff paired UUID+shared-secret
  X-AUTH-CLIENT via /v1/sessions on stationapi.veriff.com, IDnow
  X-API-KEY via /api/v1/identifications on gateway.idnow.de), GRC /
  compliance (AuditBoard Bearer via /api/v1/me on app.auditboard.com),
  incident response / DORA (FireHydrant `fhb_` Bearer via /v1/ping on
  api.firehydrant.io, IncidentIO `inc_` Bearer via /v2/identity on
  api.incident.io, Rootly `rootly_` Bearer via /v1/users/me on
  api.rootly.com, Sleuth 40-hex apikey via /api/1.0/projects on
  app.sleuth.io), email / SMS (Sparkpost 40-hex Authorization via
  /api/v1/account on api.sparkpost.com, SendPulse paired
  client_id+client_secret OAuth via /oauth/access_token on
  api.sendpulse.com), e-commerce (Squarespace UUID Bearer via
  /1.0/commerce/orders on api.squarespace.com).

## [0.33.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 36 (constants 530..544): LangSmith,
  Wandb, CometML, NeptuneAI, PromptLayer, ArizeAI, Hyperproof, Etsy,
  Walmart, WooCommerce, Missiveapp, LiveChat, HelpCrunch, DenoDeploy,
  Twingate. Total now **538 secret + 4 PII = 542 detectors**. LLM
  observability / experiment tracking (LangSmith `lsv2_(pt|sk)_` x-api-key
  via /info on api.smith.langchain.com, Wandb 40-hex Basic auth `api:<key>`
  via /graphql on api.wandb.ai, CometML 32-100 alnum Authorization via
  /api/rest/v2/account-details on www.comet.com, NeptuneAI JWT-shape
  Bearer via /api/leaderboard/v1/me on app.neptune.ai, PromptLayer `pl_`
  X-API-KEY via /rest/get-prompt-template on api.promptlayer.com,
  ArizeAI 40-80 alnum Bearer via /v1/spaces on app.arize.com), compliance
  (Hyperproof Bearer via /v1/users/me on api.hyperproof.app), e-commerce
  (Etsy x-api-key via /v3/application/openapi-ping on api.etsy.com,
  Walmart paired consumer-id+secret WM headers on
  marketplace.walmartapis.com — unverified-by-default, WooCommerce
  paired `ck_`+`cs_` Basic auth — unverified-by-default per-store host),
  customer support / messaging (Missiveapp Bearer via /v1/users on
  public.missiveapp.com, LiveChat `dal:` PAT Bearer via
  /v3.5/agent/action/list_my_profiles on api.livechatinc.com, HelpCrunch
  JWT Bearer via /v1/agents on api.helpcrunch.com), edge serverless
  (DenoDeploy `ddp_` Bearer via /v1/users/me on api.deno.com), zero-trust
  networking (Twingate `tk_` / `tkt_` X-API-KEY — unverified-by-default
  per-tenant `<network>.twingate.com` host).

## [0.32.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 35 (constants 515..529): Persona,
  Sumsub, Onfido, Jumio, Trulioo, ZeroBounce, MailerSend, OpsLevel,
  Codemagic, LambdaTest, SauceLabs, Browserless, Helicone, Portkey,
  Langfuse. Total now **523 secret + 4 PII = 527 detectors**. KYC /
  identity verification (Persona `persona_(production|sandbox)_` Bearer
  via /api/v1/inquiries on api.withpersona.com, Sumsub paired
  `prd|tst|sbx:` app token + secret via /resources/applicants/-/info on
  api.sumsub.com with HTTP Basic auth, Onfido `api_(live|sandbox)_(us|eu|ca)_`
  Token token= via /v3.6/applicants on api.onfido.com, Jumio paired
  token+secret — unverified-by-default per-data-center
  `<region>.netverify.com` host required, Trulioo 32-64 alnum
  x-trulioo-api-key via /customer/v1/configuration on
  api.globaldatacompany.com), email validation (ZeroBounce 32 hex via
  /v2/getcredits on api.zerobounce.net query, MailerSend `mlsn.` prefix
  Bearer via /v1/me on api.mailersend.com), DevOps / observability
  (OpsLevel 40-64 alnum Bearer via /graphql on api.opslevel.com), mobile
  CI (Codemagic 32-64 alnum x-auth-token via /apps on api.codemagic.io),
  browser-testing (LambdaTest paired LT_USERNAME+LT_ACCESS_KEY via
  /automation/api/v1/builds Basic, SauceLabs paired
  SAUCE_USERNAME+SAUCE_ACCESS_KEY UUID via /rest/v1/users/{user} on
  api.us-west-1.saucelabs.com Basic, Browserless 32-64 alnum token
  query via /pressure on chrome.browserless.io), LLM observability /
  AI gateway (Helicone `sk-helicone-` prefix Bearer via /v1/user/query
  on api.helicone.ai, Portkey 32-64 base64url x-portkey-api-key via
  /v1/virtual-keys on api.portkey.ai, Langfuse paired
  `pk-lf-`+`sk-lf-` UUID via /api/public/projects on
  cloud.langfuse.com Basic). Sumsub, Jumio, LambdaTest, SauceLabs,
  Langfuse are paired-credential detectors using RawV2 (Raw=public/key
  half, RawV2=key:secret per the trufflehog convention). All detectors
  ship with positive + negative + verified-OK + 401 + 500 test coverage.
  3613 race-clean tests across 542 packages.

## [0.31.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 34 (constants 500..514). **This
  batch crosses the 500-detector milestone**: total now **508 secret + 4
  PII = 512 detectors**. Cloud-AI / inference (VertexAI AAD/OAuth-style
  JWT — unverified-by-default per-project `<region>-aiplatform.googleapis.com`
  host required, RekaAI 32-64 alnum X-Api-Key via /v1/models on
  api.reka.ai, AIHorde UUID-shaped apikey header via /api/v2/find_user
  on aihorde.net, OllamaCloud 40-80 alnum/base64url Bearer via /api/tags
  on ollama.com, RunwayML `key_` prefix Bearer via /v1/organization on
  api.runwayml.com), customer-success platforms (Planhat 32-64 alnum
  Bearer — unverified-by-default per-tenant `<tenant>.planhat.com` host
  required, Vitally 32-64 alnum Basic auth via /resources/v2024 on
  api.vitally.io, ChurnZero UUID Z-AppKey header via /i on
  analytics.churnzero.net, Totango 32-64 alnum app-token —
  unverified-by-default per-tenant `<tenant>.totango.com` host required,
  Sendoso `sendoso_` prefix Bearer via /api/v3/me on api.sendoso.com),
  payments / fintech (Paystack `sk_(live|test)_` 40-50 alnum Bearer via
  /transaction/totals on api.paystack.co — sk_live_ surfaces
  SeverityCritical, Flutterwave `FLWSECK(_TEST)?-` prefix Bearer via
  /v3/transactions on api.flutterwave.com), security tooling (Mandiant
  paired key+secret via OAuth client_credentials Basic auth on
  api.intelligence.fireeye.com — Raw=key, RawV2=key:secret;
  AbnormalSec 32-64 alnum Bearer via /v1/threats on
  api.abnormalplatform.com), marketing automation (Ortto/Autopilot
  `pak_` prefix X-Api-Key via /v1/person/get on api.ap3api.com).
  All detectors ship with positive + negative + verified-OK + 401 + 500
  test coverage. 3507 race-clean tests across 527 packages.

## [0.30.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 33 (constants 485..499):
  Buffer, Hootsuite, MagicLabs, Pipedream, Make, N8N, SageIntacct,
  MicrosoftDynamics, Freshmarketer, VespaCloud, SimilarWeb, Vectra,
  Expel, BeyondTrust, GainSight. Total now **493 secret + 4 PII = 497
  detectors**. Social-media scheduling (Buffer 40-50 alnum via
  /1/user.json on api.bufferapp.com with access_token query, Hootsuite
  32-64 hex Bearer via /v1/me on platform.hootsuite.com), Web3 identity
  (MagicLabs `sk_(live|test)_` prefix via /v1/admin/auth/user/get on
  api.magic.link with X-Magic-Secret-Key header), workflow / automation
  (Pipedream 32-80 hex Bearer via /v1/users/me on api.pipedream.com,
  Make.com UUID Token via /api/v2/users/me on us1.make.com, N8N
  JWT-shaped X-N8N-API-KEY — unverified-by-default per-deployment host
  required), accounting (SageIntacct 12-32 alnum sender_password —
  unverified-by-default XML envelope required), enterprise CRM
  (MicrosoftDynamics AAD JWT Bearer via /api/data/v9.2/WhoAmI —
  unverified-by-default per-org `<org>.crm[N].dynamics.com` host
  required, GainSight 32-64 alnum Accesskey header via /v1/users/me on
  api.gainsightcloud.com), marketing automation (Freshmarketer 20-32
  alnum Token token=<key> via /crm/sales/api/me on
  app.freshmarketer.com), search infra (VespaCloud `vespa_cloud_`
  prefix Bearer — unverified-by-default per-application host required),
  competitive intelligence (SimilarWeb 32 hex via api_key query on
  api.similarweb.com), and security tooling (Vectra 32-64 hex Token
  header — unverified-by-default per-tenant `<tenant>.vectra.ai` host
  required, Expel 32-64 alnum Bearer via /api/v2/users/current on
  workbench.expel.io, BeyondTrust 64-128 alnum PS-Auth header —
  unverified-by-default per-tenant `<id>.beyondtrustcloud.com` host
  required).

## [0.29.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 32 (constants 470..484):
  Watsonx, Harbor, Fivetran, Airbyte, Coinbase, Bitfinex, Kraken,
  Outreach, SalesLoft, ZoomInfo, Gigya, MoonPay, NearRPC, PolygonRPC,
  Sproutsocial. Total now **478 secret + 4 PII = 482 detectors**.
  AI / inference (Watsonx 44 base64url chars Bearer via
  /v2/foundation_model_specs on api.dataplatform.cloud.ibm.com),
  DevOps / artifact (Harbor robot-account CLI secret —
  unverified-by-default per-deployment host required), data
  integration (Fivetran 20+20 alnum HTTP Basic via /v1/users on
  api.fivetran.com paired RawV2, Airbyte JWT-shaped token —
  unverified-by-default per-deployment host required), exchanges
  (Coinbase 32+64 alnum unsigned-bearer via /v2/user on
  api.coinbase.com — production HMAC path 401s, mocks verify cleanly,
  Bitfinex 43+43 alnum unsigned-bearer via /v2/auth/r/wallets on
  api.bitfinex.com, Kraken 56+88 base64 unsigned-bearer via
  /0/private/Balance on api.kraken.com — all three pair RawV2 with
  the secret half), sales / CRM (Outreach 40-80 base64url Bearer via
  /api/v2 on api.outreach.io, SalesLoft 64-hex Bearer via /v2/me on
  api.salesloft.com, ZoomInfo JWT Bearer via /lookup on
  api.zoominfo.com, Sproutsocial 32-64 hex Bearer via
  /v1/metadata/client on api.sproutsocial.com), identity (Gigya
  `_`-prefixed apiKey + 27-char base64 secret —
  unverified-by-default per-data-center `<region>.gigya.com` host
  required, RawV2 carries the secret), payments (MoonPay
  `pk_(test|live)_`/`sk_(test|live)_`-prefixed Api-Key header via
  /v3/transactions on api.moonpay.com), and Web3 RPC (NearRPC 32-64
  alnum near pagoda/fastnear/near-rpc keyword —
  unverified-by-default per-endpoint provider host required,
  PolygonRPC 32-64 alnum near polygon-rpc/polygon-zkevm keyword —
  unverified-by-default per-endpoint provider host required).

## [0.28.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 31 (constants 455..469):
  Nebius, DashScope, ModelScope, Dify, LobeHub, FusionAuth, Casdoor,
  EdgeDBCloud, PrismaData, OpenSearchCloud, ChromaCloud, Biconomy,
  SAPAriba, OracleNetSuite, TravisCI. Total now **463 secret + 4 PII =
  467 detectors**. AI / inference (Nebius `AAAA`-prefixed Bearer via
  /v1/models on api.studio.nebius.ai, DashScope / Qwen `sk-`-prefixed
  Bearer via /api/v1/models on dashscope.aliyuncs.com, ModelScope
  `ms-`-prefixed UUID Bearer via /v1/models on
  api-inference.modelscope.cn, Dify `app-`/`dataset-`-prefixed Bearer
  via /v1/info on api.dify.ai, LobeHub `lobehub-`-prefixed Bearer —
  unverified-by-default per-deployment host required), identity
  (FusionAuth UUID API key — unverified-by-default per-tenant host
  required, Casdoor `csdr_`-prefixed Bearer — unverified-by-default
  per-deployment host required), DBaaS / search / DB cloud (EdgeDBCloud
  `edbt_`-prefixed Bearer — unverified-by-default per-instance host
  required, PrismaData `pdp_`-prefixed Bearer via /v1/me on
  cloud.prisma.io, OpenSearchCloud `os_`-prefixed Bearer —
  unverified-by-default per-domain host required, ChromaCloud
  `ck-`-prefixed X-Chroma-Token via /api/v2/auth/identity on
  api.trychroma.com), web3 (Biconomy `pm_`-prefixed paymaster key —
  unverified-by-default per-network endpoint required), enterprise
  (SAPAriba 32+ alnum apiKey header — unverified-by-default per-tenant
  host required, OracleNetSuite OAuth1 token ID + secret pair —
  unverified-by-default per-account host required, RawV2 carries the
  secret), and CI (TravisCI 22 alnum `Authorization: token` via /user
  on api.travis-ci.com). Eight detectors are unverified-by-default
  (LobeHub, FusionAuth, Casdoor, EdgeDBCloud, OpenSearchCloud,
  Biconomy, SAPAriba, OracleNetSuite) — each requires a per-deployment
  / per-tenant / per-account value not present in the chunk; verify
  only fires when an apiBase override is supplied. OracleNetSuite uses
  `RawV2` to surface the paired token secret.

## [0.27.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 30 (constants 440..454):
  PubNub, LiveKit, AgoraIO, DailyCo, Meilisearch, Typesense, Marqo,
  Kong, WebhookRelay, RequestBin, Ahrefs, Semrush, June, Workday,
  Qualys. Total now **448 secret + 4 PII = 452 detectors**.
  Realtime / streaming (PubNub `pub-c-`/`sub-c-`/`sec-c-` UUID
  X-PN-Key via /v1/keys on admin.pubnub.com, LiveKit `API`-prefixed
  key + secret pair — unverified-by-default per-deployment host
  required, AgoraIO 32-hex app ID + cert pair — unverified-by-design
  RTC tokens are signed offline, DailyCo 64-hex Bearer via /v1/rooms
  on api.daily.co), search (Meilisearch master key — unverified-by-
  default per-deployment host required, Typesense X-TYPESENSE-API-KEY
  — unverified-by-default per-cluster host required, Marqo `mzpat_`-
  prefixed x-api-key — unverified-by-default per-cluster host
  required), API gateway / webhook proxy (Kong Konnect `kpat_`-
  prefixed Bearer via /v0/me on global.api.konghq.com, WebhookRelay
  UUID key + secret HTTP Basic via /v1/tokens on my.webhookrelay.com,
  RequestBin / Pipedream webhook URL — unverified-by-design URL is
  the credential), SEO / marketing (Ahrefs Bearer via /v3/subscription-
  info/limits-and-usage on api.ahrefs.com, Semrush 32-hex `key` query
  param via /management/v1/limits on api.semrush.com, June.so 32 alnum
  HTTP Basic via /sdk/track on api.june.so), and enterprise
  (Workday OAuth Bearer — unverified-by-default per-tenant
  `<tenant>.workday.com` host required, Qualys VMDR username +
  password HTTP Basic — unverified-by-default per-region
  `qualysapi.<region>.qualys.com` host required). Eight detectors are
  unverified-by-default (LiveKit, AgoraIO, Meilisearch, Typesense,
  Marqo, RequestBin, Workday, Qualys) — each requires a per-deployment
  / per-host / per-tenant value not present in the chunk; verify only
  fires when an apiBase override is supplied (or, for AgoraIO and
  RequestBin, never — the credential is the URL or signed offline).
  LiveKit / WebhookRelay / AgoraIO / Qualys use `RawV2` to surface the
  paired secret / certificate / password.

## [0.26.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 29 (constants 425..439):
  Infura, QuickNode, Moralis, Blockfrost, Helius, TheGraph, OpenSea,
  Milvus, Beeceptor, Smee, Ory, Supertokens, Statsig, GrowthBook,
  DevCycle. Total now **433 secret + 4 PII = 437 detectors**.
  Web3 / blockchain RPC + APIs (Infura 32-hex project ID JSON-RPC
  eth_blockNumber on mainnet.infura.io/v3/<id>, QuickNode 32-64 hex
  endpoint token — unverified-by-default per-endpoint host required,
  Moralis 64+ alnum / JWT-shaped X-API-Key via /api/v2.2/dateToBlock
  on deep-index.moralis.io, Blockfrost mainnet/preprod/preview/testnet-
  prefixed project_id header via /api/v0/health on
  cardano-mainnet.blockfrost.io, Helius UUID-shape api-key query param
  via JSON-RPC getHealth on mainnet.helius-rpc.com, TheGraph 32-hex
  Studio key via /api/<key>/subgraphs/id/... on gateway.thegraph.com,
  OpenSea 32-hex X-API-KEY header via /api/v2/collections on
  api.opensea.io), vector DB (Milvus / Zilliz `db_`-prefixed token —
  unverified-by-default per-cluster `<cluster>.api.zillizcloud.com`
  host required), webhook proxy (Beeceptor 32+ alnum Bearer via
  /api/v1/projects on app.beeceptor.com, Smee.io channel URL —
  unverified-by-design URL is the credential), identity (Ory
  `ory_`-prefixed Bearer via /projects on api.console.ory.sh,
  SuperTokens 32+ alnum core api-key — unverified-by-default per-
  deployment self-hosted core URL required), and feature flags /
  experimentation (Statsig `console-`/`secret-` prefixed STATSIG-API-KEY
  header via /v1/get_id_lists on statsigapi.net, GrowthBook
  `secret_admin_`/`secret_user_` Bearer via /api/v1/features on
  api.growthbook.io, DevCycle `dvc_server_`/`dvc_mgmt_`/`dvc_client_`
  Authorization header via /v1/projects on api.devcycle.com). Four
  detectors are unverified-by-default (QuickNode, Milvus, Smee,
  SuperTokens) — each requires a per-endpoint / per-cluster /
  per-channel-URL / per-deployment value not present in the chunk;
  verify only fires when an apiBase override is supplied.

## [0.25.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 28 (constants 410..424):
  AlephAlpha, Inflection, CharacterAI, Hyperbolic, LeptonAI, NovitaAI,
  Kickbox, AbstractAPI, NeverBounce, Snov, Apollo, Lemlist, Authentik,
  Etherscan, Alchemy. Total now **418 secret + 4 PII = 422 detectors**.
  AI / inference (AlephAlpha Bearer via /users/me on api.aleph-alpha.com,
  Inflection Bearer via /v1/models on api.inflection.ai, CharacterAI
  `Token ` header via /chat/user on plus.character.ai, Hyperbolic JWT-
  shaped Bearer via /v1/models on api.hyperbolic.xyz, LeptonAI Bearer
  via /api/v1/workspace on dashboard.lepton.ai, NovitaAI `sk_`-prefixed
  Bearer via /v3/user on api.novita.ai), email validation / lead-gen
  (Kickbox `live_`/`test_` apikey query param via /v2/verify on
  api.kickbox.com, AbstractAPI 32-hex api_key query param via
  /v1/?api_key=... on emailvalidation.abstractapi.com, NeverBounce
  `secret_`/`private_` key query param via /v4/account/info on
  api.neverbounce.com, Snov OAuth2 client_id+client_secret pair via
  /v1/oauth/access_token client_credentials grant on api.snov.io —
  RawV2, Apollo X-Api-Key header via /v1/auth/health on api.apollo.io,
  Lemlist user_email+api_key Basic auth via /api/team on
  api.lemlist.com — RawV2), identity (Authentik 60+ alnum tokens —
  unverified-by-default per-tenant host `<tenant>.goauthentik.io` or
  self-hosted), and blockchain explorers / RPC (Etherscan 34-alnum
  apikey query param via /api?module=stats&action=ethsupply on
  api.etherscan.io, Alchemy 32-alnum URL-embedded JSON-RPC key via
  /v2/<key> eth_blockNumber on eth-mainnet.g.alchemy.com).

## [0.24.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 27 (constants 395..409):
  Writer, Filebase, Storj, MongoDBRealm, CloudBees, Codeship, Okteto,
  Freshsales, Copper, Trustpilot, SentinelOne, Gladly, HelpScout,
  Mailboxlayer, Hunter. Total now **403 secret + 4 PII = 407 detectors**.
  Frontier-AI (Writer Bearer via /v1/models on api.writer.com), storage
  / DBaaS (Filebase paired access_key+secret_key — unverified-by-default
  S3 SigV4 needs bucket+region — RawV2, Storj DCS access grant — unverified-
  by-default per-satellite host, MongoDBRealm UUID-shape API key —
  unverified-by-default per-app id), DevOps / CI (CloudBees paired
  user_id+api_token Basic auth — unverified-by-default per-controller
  host — RawV2, Codeship paired username+password Basic auth via /v2/auth
  on api.codeship.com — RawV2, Okteto Bearer via /api/v1/users/me on
  cloud.okteto.com), CRM / sales (Freshsales `Token token=` header —
  unverified-by-default per-domain `<domain>.myfreshworks.com`, Copper
  paired user_email+access_token via /developer_api/v1/account on
  api.copper.com with X-PW-AccessToken / X-PW-Application / X-PW-UserEmail
  headers — RawV2), reviews (Trustpilot apikey query param via
  /v1/business-units on api.trustpilot.com), endpoint security
  (SentinelOne `ApiToken ` header — unverified-by-default per-management-
  console `<console>.sentinelone.net`), customer support (Gladly paired
  agent_email+api_token Basic auth — unverified-by-default per-org host —
  RawV2, HelpScout paired app_id+app_secret OAuth client_credentials via
  /v2/oauth2/token on api.helpscout.net — RawV2), email validation
  (Mailboxlayer access_key query param via /api/check on apilayer.net,
  Hunter.io api_key query param via /v2/account on api.hunter.io). Six
  detectors use `RawV2` for paired credentials. Seven detectors ship
  `apiBase` override hooks for unverified-by-design tenant / per-app
  hosts.

## [0.23.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 26 (constants 380..394):
  AI21Labs, OctoAI, PingOne, ForgeRock, KeyCloak, Marketo, Eloqua,
  Pardot, Kustomer, Freshchat, OracleCloud, IBMCloud, RingCentral,
  DialPad, SignalWire. Total now **388 secret + 4 PII = 392 detectors**.
  AI / inference (AI21Labs Bearer via /studio/v1/tokenize on
  api.ai21.com, OctoAI / OctoML Bearer via /v1/models on
  text.octoai.run), identity / SSO (PingOne worker app paired
  client_id+secret Basic auth via /as/token on auth.pingone.com — RawV2,
  ForgeRock Bearer via /am/json/serverinfo/version — unverified-by-
  default per-tenant `<tenant>.forgeblocks.com`, KeyCloak paired
  client_id+secret via /protocol/openid-connect/token — unverified-by-
  default per-deployment realm host — RawV2), marketing (Marketo paired
  client_id+secret via /identity/oauth/token — unverified-by-default
  per-munchkin host — RawV2, Eloqua paired client_id+secret Basic auth
  via /api/REST/2.0/system/user/current — unverified-by-default per-pod
  host — RawV2, Pardot business_unit_id+access_token Bearer +
  Pardot-Business-Unit-Id header via /api/v5/objects/account on
  pi.pardot.com — RawV2), customer messaging (Kustomer Bearer via
  /v1/users/current on api.kustomerapp.com, Freshchat Bearer via
  /v2/agents on api.freshchat.com), IaaS (OracleCloud OCI auth signature
  — unverified-by-default per-region tenancy host, IBMCloud IAM apikey
  grant via /identity/token on iam.cloud.ibm.com), comms / SMS
  (RingCentral paired client_id+secret Basic auth via /restapi/oauth/token
  on platform.ringcentral.com — RawV2, DialPad Bearer via /api/v2/users
  on dialpad.com, SignalWire paired project_id+token Basic auth via
  /api/laml/2010-04-01/Accounts — unverified-by-default per-space host
  `<space>.signalwire.com` — RawV2). Seven detectors use `RawV2` to
  surface the paired secret. Six detectors ship `apiBase` override hooks
  for unverified-by-design tenant / deployment / region hosts.

## [0.22.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 25 (constants 365..379):
  Shippo, EasyPost, TaxJar, Avalara, BambooHR, Paylocity, DeepSeek,
  MonsterAPI, FriendliAI, AppDynamics, ElasticAPM, Lightstep, EmailJS,
  Mailjet, Hasura. Total now **373 secret + 4 PII = 377 detectors**.
  Shipping / e-commerce (Shippo `shippo_(live|test)_` `ShippoToken`
  auth via /v1/addresses on api.goshippo.com — `shippo_live_` verified
  surfaces SeverityCritical via DefaultSeverity, EasyPost `EZAK`/`EZTK`
  Basic auth via /api/v2/api_keys on api.easypost.com, TaxJar Bearer
  via /v2/categories on api.taxjar.com, Avalara paired account+license
  Basic auth via /api/v2/utilities/ping on rest.avatax.com — RawV2),
  HR / payroll (BambooHR Basic auth — unverified-by-default per-tenant
  subdomain, Paylocity OAuth client_id+secret pair — unverified-by-
  default sandbox vs production gateway — RawV2), AI / inference
  (DeepSeek `sk-` Bearer via /v1/models on api.deepseek.com — keyword-
  gated to stay disjoint from OpenAI, MonsterAPI Bearer via /v1/health
  on api.monsterapi.ai, FriendliAI `flp_` Bearer via /v1/models on
  api.friendli.ai), observability / APM (AppDynamics paired
  client@account+secret — unverified-by-default per-controller host —
  RawV2, ElasticAPM Bearer — unverified-by-default per-deployment APM
  Server host, Lightstep Bearer via /public/v0.2/projects on
  api.lightstep.com), email / comms (EmailJS paired user_id+access_token
  Bearer via /api/v1.0/account on api.emailjs.com — RawV2, Mailjet
  paired 32-hex key+secret Basic auth via /v3/REST/myprofile on
  api.mailjet.com — RawV2), database / IaaS (Hasura admin secret —
  unverified-by-default per-project host `<project>.hasura.app`).
  Avalara, Paylocity, AppDynamics, EmailJS, Mailjet are paired-credential
  detectors using RawV2. BambooHR, Paylocity, AppDynamics, ElasticAPM,
  Hasura ship unverified-by-default (apiBase override required).
  2531 race-clean tests across 392 packages.

## [0.21.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 24 (constants 350..364):
  Braintree, Dwolla, Klarna, Lever, Greenhouse, Gusto, Deel, Rippling,
  PropelAuth, LambdaLabs, Anyscale, SambaNova, Baseten, Turso, Knock.
  Total now **358 secret + 4 PII = 362 detectors**. Payments
  (Braintree `access_token$<env>$<merchant>$<32 hex>` Bearer routed to
  api.braintreegateway.com vs api.sandbox.braintreegateway.com by the
  embedded env segment, Dwolla paired key+secret Basic auth via /token,
  Klarna paired username `PK<digits>_<8>` + password Basic auth via
  /payments/v1/sessions), HR / recruiting / payroll (Lever 40-hex Basic
  auth via /v1/users on api.lever.co, Greenhouse 40+ alnum Basic auth
  via /v1/users on harvest.greenhouse.io, Gusto Bearer via /v1/me on
  api.gusto.com, Deel Bearer via /rest/v2/users/me on api.letsdeel.com,
  Rippling Bearer via /platform/api/me on api.rippling.com), auth
  (PropelAuth Bearer via /api/backend/v1/end_user_api_keys/validate on
  auth.propelauth.com), AI / ML / GPU infra (LambdaLabs Basic auth with
  key as username via /api/v1/instance-types on cloud.lambdalabs.com,
  Anyscale `esct_` Bearer via /api/v2/users/me on console.anyscale.com,
  SambaNova Bearer via /v1/models on api.sambanova.ai, Baseten
  `Api-Key <key>` via /api/v1/models on app.baseten.co), DBaaS (Turso
  Bearer via /v1/auth/validate-token on api.turso.tech), notifications
  (Knock `sk_(test|live)_` Bearer via /v1/users on api.knock.app —
  `sk_live_` verified surfaces SeverityCritical via DefaultSeverity).
  Braintree, Dwolla, and Klarna are paired-credential detectors using
  RawV2. 2421 race-clean tests across 377 packages.

## [0.20.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 23 (constants 335..349):
  Shopify, Recurly, Chargebee, FastSpring, Gumroad, Snipcart, Gitea,
  Woodpecker, OctopusDeploy, Squadcast, Instana, Courier, Bandwidth,
  GetStream, Lark. Total now **343 secret + 4 PII = 347 detectors**.
  E-commerce / payments (Shopify `shp(at|ss|ca)_` Admin token —
  unverified-by-default per-shop host, Recurly 32-alnum Basic auth,
  Chargebee `(live|test)_` — unverified-by-default per-site host,
  FastSpring paired username+password Basic auth, Gumroad
  `?access_token=` query param, Snipcart Basic auth), VCS / CI
  (Gitea 40-hex `token <pat>` — unverified-by-default self-hosted host,
  Woodpecker CI Bearer — unverified-by-default self-hosted host,
  OctopusDeploy `API-<26 base32>` `X-Octopus-ApiKey` — unverified-by-
  default per-tenant host), observability (Squadcast Bearer, Instana
  `apiToken <key>` — unverified-by-default per-tenant host), comms /
  messaging (Courier `pk_(prod|test)_` Bearer, Bandwidth paired
  user+pass Basic auth, Lark / Feishu paired `cli_<id>` + secret JSON
  body), and analytics (GetStream paired api_key+api_secret HMAC —
  unverified-by-design). FastSpring, Bandwidth, Lark, and GetStream
  use `RawV2` to surface the paired secret. Six detectors ship `apiBase`
  overrides so verify can be exercised in tests but stays disabled in
  production until a host is supplied. 2316 race-clean tests across 362
  packages.

## [0.19.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 22 (constants 320..334):
  Nomic, Jina, Runway, MotherDuck, DoltHub, BetterStack, Dynatrace,
  AppSignal, ScoutAPM, Descope, Mandrill, CustomerIO, Iterable, Plivo,
  Paddle. Total now **328 secret + 4 PII = 332 detectors**. AI / ML
  infra (Nomic Atlas `nk-` Bearer, Jina AI `jina_` Bearer, Runway ML
  `key_` Bearer with `X-Runway-Version`), data warehouse / DBaaS
  (MotherDuck JWT Bearer, DoltHub `token <pat>`), observability
  (BetterStack/Logtail Bearer, Dynatrace `dt0c01.<id>.<secret>` —
  unverified-by-default per-tenant host, AppSignal 32-hex query-param
  auth, ScoutAPM paired agent_key + api_key Basic auth), auth (Descope
  management `K2` Bearer), email / messaging (Mandrill 22-char API key
  via JSON body, Customer.io paired site_id+api_key Basic auth,
  Iterable `Api-Key` header), telephony (Plivo paired `MA`/`SA` auth_id
  + token Basic auth), and payments (Paddle Billing
  `pdl_(live|sdbx)_apikey_` Bearer with sandbox host fallback).
  ScoutAPM, CustomerIO, and Plivo use `RawV2` to surface the paired
  secret. Dynatrace ships an `apiBase` override so verify can be
  exercised in tests but stays disabled in production until a tenant
  host is supplied. 2220 race-clean tests across 347 packages.

## [0.18.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 21 (constants 305..319):
  KeyCDN, Mailtrap, GetResponse, Amplitude, FullStory, Heap, Hotjar,
  Optimizely, Transifex, Crowdin, DocuSign, Qdrant, SurrealDB, Leaseweb,
  PostageApp. Total now **313 secret + 4 PII = 317 detectors**. CDN /
  IaaS (KeyCDN HTTP Basic auth, Leaseweb paired key+secret with
  `X-Lsw-Auth` header), email / transactional (Mailtrap `Api-Token`,
  GetResponse `X-Auth-Token: api-key`, PostageApp form `api_key`),
  product analytics (Amplitude paired key+secret HTTP Basic, FullStory
  `Authorization: Basic`, Heap `heap_` Bearer, Hotjar `hjar_` Bearer,
  Optimizely Bearer), localization (Transifex Basic with `api` user,
  Crowdin Bearer), e-signature (DocuSign JWT — unverified-by-default,
  per-environment hosts), vector DB (Qdrant Cloud `api-key` —
  unverified-by-default, per-cluster host), and DBaaS (SurrealDB Cloud
  Bearer JWT — unverified-by-default, per-instance host). Amplitude and
  Leaseweb use `RawV2` to surface the paired secret. DocuSign / Qdrant /
  SurrealDB ship `apiBase` overrides so verify can be exercised in tests
  but stays disabled in production until a host is supplied. 2115
  race-clean tests across 332 packages.

## [0.17.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 20 (constants 290..304):
  FirebaseCloudMessaging, APNs, Pushover, BranchIO, PusherBeams,
  Drata, Secureframe, OneTrust, Pipedrive, Close, DNSimple, NvidiaNGC,
  Airbrake, Materialize, BeyondIdentity. Total now **298 secret + 4
  PII = 302 detectors**. Mobile push (FirebaseCloudMessaging legacy
  server keys, APNs .p8 PEM, Pushover application tokens, Branch.io
  paired key+secret, PusherBeams 32-hex secrets), compliance /
  security (Drata, Secureframe, OneTrust), CRM (Pipedrive, Close.com),
  DNS (DNSimple), AI infra (NvidiaNGC `nvapi-` tokens), error tracking
  (Airbrake), database (Materialize Cloud `mzp_` app passwords), and
  identity / IAM (BeyondIdentity). APNs ships only the .p8 PEM and is
  unverified-by-design (issuer + key_id required for JWT issuance,
  distinct from AppStoreConnect because APNs targets push endpoints
  rather than store APIs). PusherBeams is distinct from PusherChannels
  — Beams is the push-notification SDK with separate instance + secret.
  OneTrust and BeyondIdentity use per-tenant hosts so verify requires
  apiBase override. Branch.io is paired key+secret using RawV2.

## [0.16.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 19 (constants 275..289):
  OVHCloud, EquinixMetal, Civo, Exoscale, BuddyCI, SemaphoreCI,
  JenkinsX, AssemblyAI, ElevenLabs, Deepgram, Front, CrispChat, Drift,
  Vanta, OneSignal. Total now **283 secret + 4 PII = 287 detectors**.
  IaaS / cloud (OVHCloud, EquinixMetal, Civo, Exoscale), CI / DevOps
  (BuddyCI, SemaphoreCI, JenkinsX), AI / ML (AssemblyAI, ElevenLabs,
  Deepgram), email / comms (Front, CrispChat, Drift), security /
  compliance (Vanta), and mobile push (OneSignal). OVHCloud and
  Exoscale ship unverified-by-design — both require HMAC-SHA1 query
  signing with material we won't reconstruct from a chunk. CrispChat
  is unverified-by-design because its (Identifier, Key) pair must be
  HTTP-Basic-encoded and the Identifier half is not always co-located.
  SemaphoreCI uses per-org hosts (`<org>.semaphoreci.com`) and
  JenkinsX uses per-installation hosts; both ship with apiBase
  override so verification fires only when the host is configured.
  Front uses JWT-shaped 3-segment tokens and is distinct from FrontEgg
  (different product, different shape — FrontEgg is a UUID
  client_id+secret pair). OneSignal accepts both the legacy 48-char
  alnum key and the new `os_v2_app_<base32>{50+}` v2 shape.

## [0.15.0] — 2026-05-08

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

[Unreleased]: https://github.com/plenoai/pleno-dlp/compare/v0.37.0...HEAD
[0.37.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.37.0
[0.36.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.36.0
[0.35.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.35.0
[0.34.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.34.0
[0.33.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.33.0
[0.32.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.32.0
[0.31.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.31.0
[0.30.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.30.0
[0.29.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.29.0
[0.28.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.28.0
[0.27.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.27.0
[0.26.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.26.0
[0.25.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.25.0
[0.24.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.24.0
[0.23.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.23.0
[0.22.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.22.0
[0.21.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.21.0
[0.20.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.20.0
[0.19.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.19.0
[0.18.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.18.0
[0.17.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.17.0
[0.16.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.16.0
[0.15.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.15.0
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
