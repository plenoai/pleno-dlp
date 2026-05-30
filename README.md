# pleno-dlp

Trufflehog-compatible DLP scanner — secrets **and** PII — over the local
filesystem, git history, and stdin. AGPL-3.0.

```sh
go install github.com/plenoai/pleno-dlp/cmd/pleno-dlp@latest

pleno-dlp scan filesystem ./repo
pleno-dlp scan git --repo ./repo --max-depth 200
git diff | pleno-dlp scan stdin --label git-diff
pleno-dlp scan filesystem ./repo --format sarif --verify > findings.sarif
pleno-dlp detectors list                        # audit registered coverage
```

Single Go binary. Trufflehog-compatible detector interface,
archive-aware (zip / tar / tar.gz / gzip), base64 / percent / hex
decoder pipeline, per-host verify rate limiter. **600 detectors**
built-in (598 secrets + 2 opt-in PII engines). Tag pattern
`vX.Y.Z`.

SaaS sources (GitHub / GitLab / Bitbucket / Slack / Notion / Confluence /
Jira) are tracked in issues #74–#80 for native Go ports — the previous
Python package was retired in v1.0.0.

## Detector coverage

600 built-in detectors. Every secret detector that can confirm against
an upstream provider implements `Verify` (run with `--verify`); the rest
emit `Verified=false` with rotation guidance in the output.

| Class | Providers |
|---|---|
| **Cloud / infra** | AWS, AWS session token, AWS S3 presigned URL, GCP service-account, GCP API key, GCP OAuth, GCP ID token, GCS signed URL, Azure storage key, Azure SAS, AzureAD, AzureApp, Azure SQL conn-string, AlibabaCloud, TencentCloud, DigitalOcean, Cloudflare, Heroku, Render, Fly.io, Vercel, Netlify, Terraform Cloud, Terraform Cloud Team, Dropbox, kubeconfig |
| **VCS / dev tooling** | GitHub PAT, GitHub Container Registry, GitLab PAT, GitLab Deploy, Bitbucket Cloud, Bitbucket Server, npm, PyPI, Hugging Face, Postman, Atlassian, Jira, Confluence, Buildkite, CircleCI, Codecov, Adobe.io, Docker Hub PAT |
| **AI** | OpenAI, Anthropic, Cohere, Replicate, Mistral, Groq, OpenRouter, Together |
| **Comms / SaaS** | Slack bot, Slack webhook, Discord, Twilio, SendGrid, Mailgun, Mailchimp, Brevo, Postmark, Notion, Linear, Asana, Mixpanel, Segment, Telegram, Okta, HubSpot, Intercom, Salesforce refresh, Spotify, Zoom, Klaviyo, Zendesk, Freshdesk, ClickUp, Monday, Trello, Gitter, LaunchNotes, Clerk |
| **GPU / IaaS** | Paperspace, RunPod, Modal, Linode, Vultr, Scaleway |
| **DBaaS / edge** | UpstashRedis, PlanetScale, Supabase |
| **Observability** | Datadog, Datadog AppKey, Sentry, New Relic, PagerDuty, Opsgenie, Shodan, VirusTotal, Honeycomb, Sumo Logic, Rollbar, Bugsnag |
| **Payments / data** | Stripe, Square, PayPal, Plaid, MongoDB Atlas, Snowflake, Databricks |
| **Connection strings** | Redis, Postgres, MySQL, MongoDB URI, RabbitMQ, Kafka SASL, basic-auth URL, SMTP |
| **Format-shaped** | JWT, PEM private keys, **Generic high-entropy** (catch-all near credential keywords) |
| **Secrets management / IAM** | Doppler, DopplerCLI, Vault, HashiCorpCloud, Algolia, Airtable, Grafana, LaunchDarkly, LaunchDarkly Relay, Auth0, Snyk, Tailscale, Figma, Ngrok |
| **PII (`finding_class=pii`)** | Two opt-in engines; mutually exclusive in v1. `PIIAnonymize` (`--pii-engine=anonymize`) — backed by the [pleno-anonymize](https://github.com/plenoai/pleno-anonymize) NER+regex engine (PERSON, EMAIL_ADDRESS, ADDRESS, PHONE_NUMBER, JP_MY_NUMBER, CREDIT_CARD, IBAN, US_SSN, …); ja-first, fast cold start. `PIIOpenAIPF` (`--pii-engine=openai-pf`) — backed by [openai/privacy-filter](https://github.com/openai/privacy-filter), a 1.5B-param MoE classifier covering `account_numbers`, `private_addresses`, `private_emails`, `private_persons`, `private_phone_numbers`, `private_urls`, `private_dates`, `secrets`; English-strong, GPU-recommended, multi-minute cold-path (HuggingFace checkpoint download). Both engines run via a loopback supervisor — the scan command auto-spawns `pleno-dlp pii-server` or `pleno-dlp openai-pf-server`, each of which shells out to `uvx`. Prerequisites: `uv` on `PATH` and Python 3.12+. Override the spawn recipe via `--pii-engine-cmd`; pick the device hint with `--pii-engine-device={auto,cpu,cuda,mps}` (openai-pf only). The per-finding entity type lives in `properties.pii_kind`; the engine identifier in `properties.engine`. |

Run `pleno-dlp detectors list` for the live registry, or
`pleno-dlp detectors list --format json` for machine-readable output.
Add `--verify-status` to annotate each row with its
`docs/verify-coverage.md` class — `verified`, `unverified-by-design`,
or `verify-gap` — when you want to know what a given build will
actually verify against upstream.

Add org-specific patterns without forking the binary — see
[Custom rules](#custom-rules) below.

## Private-key blast radius

The `PrivateKeyPEM` detector does more than match a `-----BEGIN … PRIVATE
KEY-----` block. For every match it derives the public-key half locally
(RSA / EC / Ed25519 / OpenSSH / PKCS#8) and surfaces:

- `pubkey_algorithm` — RSA, EC, ED25519, OPENSSH, …
- `pubkey_fingerprint_sha256` — hex SPKI digest, the same value crt.sh
  exposes at `?spkisha256=`
- `ssh_fingerprint` — `SHA256:<base64-no-pad>`, matches `ssh-keygen -lf`

Encrypted PEMs (legacy `Proc-Type: 4,ENCRYPTED`, modern PKCS#8 PBES2,
OpenSSH bcrypt-KDF) are tried against an embedded passphrase wordlist.
A successful unlock writes `pem_unlocked_with` and bumps the finding
from Medium to High — an "encrypted" key behind `password` has no real
protection.

When `--verify` is set, the SPKI fingerprint is queried against
Certificate Transparency via crt.sh. Any match marks the finding
`Verified=true` (severity → Critical) and writes the discovered
domains:

```json
{
  "DetectorType": "PrivateKeyPEM",
  "Verified": true,
  "Severity": "critical",
  "ExtraData": {
    "pubkey_algorithm": "RSA",
    "pubkey_fingerprint_sha256": "ab12…",
    "ct_status": "match",
    "blast_radius_cert_count": "7",
    "blast_radius_domains": "*.example.com,api.example.com,example.com"
  }
}
```

The private key body never leaves the host. Only the public-key
SHA-256 (a public artefact — it appears in every certificate the key
has signed) is transmitted, and only to crt.sh. Inspired by
[trufflesecurity/driftwood](https://github.com/trufflesecurity/driftwood).

## Severity and CI gating

Every finding carries a Severity:

| When | Severity |
|---|---|
| Verified=true | Critical |
| Unverified explicit secret detector | High |
| Generic high-entropy / JWT / PEM unverified | Medium |
| PII (any kind) | Medium |

`--fail-on` chooses what blocks the build:

```sh
pleno-dlp scan filesystem ./repo --fail-on critical    # only Critical = exit 1
pleno-dlp scan filesystem ./repo --fail-on high        # High and Critical
pleno-dlp scan filesystem ./repo                       # default: any finding
```

SARIF output maps Severity to GitHub Code Scanning levels (Critical/High
→ error, Medium → warning, Low/Info → note). `partialFingerprints`
carries `secret/v1` (sha256(detector|raw)) so GitHub dedups the same
leak across PRs.

Scope by detector when one provider is too noisy for a particular repo:

```sh
pleno-dlp scan filesystem ./repo --exclude-detectors GenericHighEntropy
pleno-dlp scan filesystem ./repo --include-detectors AWS,GitHub,Stripe
```

Names match `pleno-dlp detectors list --format names` (case-insensitive).
Unknown names error so a typo can't silently downgrade the scan.

## Allowlist (mute known false positives)

`--allowlist <path>` plus auto-discovery of `.pleno-allow.json` from
the process cwd. Entries match by detector type, raw secret literal,
raw secret regex, and path glob (AND across non-empty fields):

```json
{
  "entries": [
    {"detector": "AWS", "raw": "AKIAIOSFODNN7EXAMPLE",
     "reason": "trufflehog dummy"},
    {"path": "fixtures/**/*.env",
     "reason": "local test fixtures"},
    {"raw_regex": "^sk-test_",
     "reason": "Stripe test-mode keys"},
    {"detector": "PIIAnonymize", "raw_regex": "@example\\.com$",
     "reason": "documented contact emails (matches PIIAnonymize EMAIL_ADDRESS findings)"}
  ]
}
```

Suppression count surfaces on stderr (`allowlist: suppressed N`),
flagging stale rules.

## Custom rules

JSON file passed via `--rules`:

```json
[
  {
    "name": "ACME Internal API Key",
    "keywords": ["ACME_API_KEY", "x-acme-token"],
    "regex": "ACME_[A-Z0-9]{20}",
    "entropy_min": 3.5,
    "severity": "high",
    "verify_url": "https://api.acme.example/verify",
    "verify_header": "Authorization: Bearer {{ .Secret }}"
  }
]
```

`keywords` are required — they gate the regex from running on every
chunk. `verify_url` is optional; 200 = verified, 401/403 = unverified,
transport errors surface as `VerificationErr`.

```sh
pleno-dlp scan filesystem ./repo --rules ./acme-rules.json
```

## Decoding and archives

The engine expands every chunk through:

1. **Archive walker** — zip, tar, tar.gz, plain gzip, recursively up to
   depth 4 (configurable). Inner entries carry
   `ExtraData["archive_path"] = "outer.zip!inner.tar.gz!leak.env"` so
   the trail is visible in output.
2. **Decoder pipeline** — base64 (std + url-safe), percent-encoded, hex
   (≥40 chars). Decoded variants are scanned alongside the original;
   hits stamp `ExtraData["decoded_from"]`.

A printable-byte gate keeps binary noise from reaching detectors. Hard
limits (50 MiB per entry, 200 MiB total expanded, depth cap) defuse
zip-bomb DoS.

## Sources

```sh
# Filesystem (recursive walk)
pleno-dlp scan filesystem ./repo \
  --include 'src/**' --exclude '**/*_test.go' \
  --no-default-excludes  # opt-in: re-scan .git, node_modules, vendor, ...

# Local git history
pleno-dlp scan git --repo ./repo --branch main --max-depth 500
pleno-dlp scan git --repo ./repo --since 2024-01-01T00:00:00Z

# Stdin (one chunk read from os.Stdin)
git diff | pleno-dlp scan stdin --label git-diff
kubectl get secret app-config -o yaml | pleno-dlp scan stdin
```

Default filesystem excludes (`.git`, `.hg`, `.svn`, `node_modules`,
`vendor`, `target`, `dist`, `build`, `__pycache__`, `.venv`, `.tox`)
keep most scans tractable; pass `--no-default-excludes` to opt out.

## PII detection (opt-in)

PII coverage is opt-in and ships two mutually-exclusive engines.
Default is `off` to preserve the single-binary UX.

| engine | flag | detector | source | strengths |
|---|---|---|---|---|
| pleno-anonymize | `--pii-engine=anonymize` | `PIIAnonymize` | [pleno-anonymize](https://github.com/plenoai/pleno-anonymize) (spaCy + Presidio + `ja_ner_ja`) | ja-first NER + regex + checksums (PERSON, EMAIL_ADDRESS, ADDRESS, PHONE_NUMBER, JP_MY_NUMBER, CREDIT_CARD, IBAN, US_SSN, …); fast cold start |
| openai/privacy-filter | `--pii-engine=openai-pf` | `PIIOpenAIPF` | [openai/privacy-filter](https://github.com/openai/privacy-filter) (1.5B-param MoE token classifier) | English-strong; 8 categories (`account_numbers`, `private_addresses`, `private_emails`, `private_persons`, `private_phone_numbers`, `private_urls`, `private_dates`, `secrets`); GPU-recommended |

```sh
pleno-dlp scan filesystem ./src --pii-engine=anonymize
pleno-dlp scan filesystem ./src --pii-engine=openai-pf
```

Both engines run via a loopback HTTP supervisor: the scan command
spawns the engine on an ephemeral 127.0.0.1 port at scan start,
calls `POST /api/analyze` per chunk, and shuts down at scan end.
The default spawn recipe self-invokes this binary's matching
subcommand, which in turn drives `uv`.

```
pleno-dlp scan --pii-engine=anonymize ./src
  └─ pleno-dlp pii-server --port <ephemeral>
      ├─ git clone --depth 1 https://github.com/plenoai/pleno-anonymize.git <cache>
      ├─ uv sync --frozen --no-dev --package pleno-anonymize-server
      └─ uv run uvicorn server.src.app:app --host 127.0.0.1 --port <ephemeral>

pleno-dlp scan --pii-engine=openai-pf ./src
  └─ pleno-dlp openai-pf-server --port <ephemeral> --device auto
      └─ uv tool run --from git+https://github.com/plenoai/pleno-dlp.git#subdirectory=python/openaipf-server \
             python -m openaipf_server --host 127.0.0.1 --port <ephemeral> --device auto
```

The anonymize path uses a cached-clone (not `uvx --from "git+...#subdirectory=server"`)
because pleno-anonymize's server depends on the workspace SDK.
The openai-pf path uses `uv tool run --from` directly against this
repo's `python/openaipf-server/` subdirectory; first run pulls a
~3GB HuggingFace checkpoint, so `--pii-engine-ready-timeout`
defaults to `300s` when `--pii-engine=openai-pf`.

Prerequisites: [`uv`](https://docs.astral.sh/uv/) and Python 3.12+
on `PATH`; `git` for the default `git+` sources. **No Docker
required.** Caches live under `<os.UserCacheDir>/pleno-dlp/` and
`~/.cache/huggingface/` respectively.

Useful flags (all on the `scan` command, persistent across source kinds):

| flag | default | meaning |
|---|---|---|
| `--pii-engine` | `off` | `off`, `anonymize`, or `openai-pf` (mutually exclusive) |
| `--pii-engine-cmd` | engine-specific | argv to spawn; `{PORT}` is substituted with the chosen ephemeral port. Default is `pleno-dlp pii-server --port {PORT}` for anonymize and `pleno-dlp openai-pf-server --port {PORT}` for openai-pf |
| `--pii-engine-port` | `0` | `0` = auto-allocate a loopback port |
| `--pii-engine-language` | `auto` | `ja`, `en`, or `auto` (anonymize only) |
| `--pii-engine-device` | `auto` | `auto`, `cpu`, `cuda`, `mps` (openai-pf only) |
| `--pii-engine-ready-timeout` | `60s` (anonymize) / `300s` (openai-pf) | how long to wait for the engine's `/ready` endpoint before giving up and continuing without PII |
| `--pii-engine-request-timeout` | `10s` | per-chunk HTTP timeout |

Direct invocation of either subcommand is supported for ad-hoc local use:

```sh
pleno-dlp pii-server --port 8080                  # anonymize, fixed port
pleno-dlp pii-server --git-ref v0.5.0             # pin pleno-anonymize to a tag
pleno-dlp openai-pf-server --port 8081            # openai-pf, fixed port
pleno-dlp openai-pf-server --device cuda          # force a GPU device
pleno-dlp openai-pf-server --source /path/to/wrapper  # local Python wrapper checkout
```

`--host` on both subcommands is hard-restricted to loopback /
RFC1918 / link-local addresses; binding `0.0.0.0` (or any public
IP) is refused so a DLP tool cannot accidentally relay scanned
text to a non-trusted listener. Both engines also enforce this at
the Python layer in their `__main__`.

If an engine fails to start (no `uv` on PATH, network blocked,
checkpoint download timeout, ready-timeout exceeded), the scan
logs a single warning to stderr and continues without PII
detection — `--pii-engine` never turns a working secret scan into
a failure.

Per-finding output: the engine identifier is in `properties.engine`
(`anonymize` or `openai-pf`); the entity type is in
`properties.pii_kind` (e.g. `PERSON`, `EMAIL_ADDRESS`, `OPF_SECRET`).

## Output formats

```sh
--format table       # human-readable, default
--format json        # array of findings, machine-parseable
--format sarif       # SARIF 2.1.0, GitHub Code Scanning compliant
```

Pipe SARIF to GitHub Code Scanning:

```yaml
# .github/workflows/secret-scan.yml
- run: pleno-dlp scan filesystem . --format sarif > findings.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: findings.sarif
```

For full workflows (PR-only diff scan, `--fail-on critical`, SARIF
upload, verify rate limiting, pre-commit hook, GitLab CI),
see [`docs/recipes/`](docs/recipes/).

## Shell completions

```sh
source <(pleno-dlp completion bash)
pleno-dlp completion zsh > "${fpath[1]}/_pleno-dlp"
pleno-dlp completion fish | source
pleno-dlp completion powershell | Out-String | Invoke-Expression
```

## Install

```sh
# Latest release
go install github.com/plenoai/pleno-dlp/cmd/pleno-dlp@latest

# Pre-built archive (linux / darwin / windows × amd64 / arm64)
# https://github.com/plenoai/pleno-dlp/releases — every release
# ships a syft SBOM alongside each archive.

# From source
git clone https://github.com/plenoai/pleno-dlp
cd pleno-dlp
go build ./cmd/pleno-dlp
```

## Development

```sh
go test ./... -race    # full test suite, race-clean
go build ./...
```

Engine throughput numbers — microbenchmarks plus a wall-clock
comparison against trufflehog and gitleaks on the same corpora — are
recorded in [`docs/benchmarks.md`](docs/benchmarks.md).

Releases trigger exclusively on tag push:
- `vX.Y.Z` → Go binary release via GoReleaser trusted publishing.

`main` push runs build + tests only.

## License

[AGPL-3.0](LICENSE) — matching pleno-anonymize.
