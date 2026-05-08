# pleno-dlp

Trufflehog-compatible DLP scanner — secrets **and** PII — over the local
filesystem, git history, stdin, and SaaS content. AGPL-3.0.

```sh
go install github.com/plenoai/pleno-dlp/cmd/pleno-dlp@latest

pleno-dlp scan filesystem ./repo
pleno-dlp scan git --repo ./repo --max-depth 200
git diff | pleno-dlp scan stdin --label git-diff
pleno-dlp scan filesystem ./repo --format sarif --verify > findings.sarif
pleno-dlp detectors list                        # audit registered coverage
```

Two surfaces in one repo. Pick the one that matches your scan target:

- **Go binary** (`cmd/pleno-dlp/`, this README) — filesystem, local git
  history, and stdin. Trufflehog-compatible detector interface,
  archive-aware (zip / tar / tar.gz / gzip), base64 / percent / hex
  decoder pipeline, per-host verify rate limiter. **572 detectors**
  built-in (568 secrets + 4 PII). Tag pattern `vX.Y.Z`.
- **Python package** (`python/`) — SaaS sources via
  [saas-retriever](https://pypi.org/project/saas-retriever/) (GitHub,
  GitLab, Bitbucket, Slack, Notion, Confluence, Jira). Backends:
  trufflehog / gitleaks / native (regex) for secrets; `pii` for
  delegated PII inference. Tag pattern `py-vX.Y.Z`. See
  [`python/README.md`](python/README.md).

## Detector coverage

572 built-in detectors. Every secret detector that can confirm against
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
| **PII (`finding_class=pii`)** | Email, US SSN, Credit card (Luhn-validated), IBAN (mod-97 validated) |

Run `pleno-dlp detectors list` for the live registry, or
`pleno-dlp detectors list --format json` for machine-readable output.

Add org-specific patterns without forking the binary — see
[Custom rules](#custom-rules) below.

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
    {"detector": "PIIEmail", "path": "docs/**",
     "reason": "documented contact emails"}
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

Releases trigger exclusively on tag push:
- `vX.Y.Z` → Go binary release via GoReleaser trusted publishing.
- `py-vX.Y.Z` → Python package release to PyPI via trusted publishing.

`main` push runs build + tests only.

## License

[AGPL-3.0](LICENSE) — matching pleno-anonymize.
