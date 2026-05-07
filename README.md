# pleno-dlp

Trufflehog-compatible DLP scanner — secrets **and** PII — over the local
filesystem, git history, and SaaS content. AGPL-3.0.

```sh
go install github.com/plenoai/pleno-dlp/cmd/pleno-dlp@latest

pleno-dlp scan filesystem ./repo
pleno-dlp scan git --repo ./repo --max-depth 200
pleno-dlp scan filesystem ./repo --format sarif --verify > findings.sarif
```

Two surfaces in one repo. Pick the one that matches your scan target:

- **Go binary** (`cmd/pleno-dlp/`) — filesystem and local git history.
  Trufflehog-compatible detector interface, archive-aware (zip / tar /
  tar.gz / gzip), base64 / percent / hex decoder pipeline. Tag pattern
  `vX.Y.Z`. This README.
- **Python package** (`python/`) — SaaS sources via
  [saas-retriever](https://pypi.org/project/saas-retriever/) (GitHub,
  GitLab, Bitbucket, Slack, Notion, Confluence, Jira). Backends:
  trufflehog / gitleaks / native (regex) for secrets; `pii` for
  delegated PII inference. Tag pattern `py-vX.Y.Z`. See
  [`python/README.md`](python/README.md).

## Detector matrix

27 detectors today. Verify column lists detectors that can confirm a
candidate against the upstream provider (`--verify` flag); detectors
without an upstream verification path emit findings as
`Verified=false`.

| Detector | Match | Verify |
|---|---|---|
| AWS | `AKIA…` access-key + nearest 40-char secret | `sts:GetCallerIdentity` |
| GCP service account | JSON key blob | OAuth token exchange |
| Azure storage key | base64 88-char | regex only |
| GitHub | classic + fine-grained PAT | `GET /user` |
| GitLab | `glpat-…` | `GET /personal_access_tokens/self` |
| Stripe | `sk_live_` / `sk_test_` / `rk_live_` | `GET /v1/charges` |
| Slack bot | `xoxb-…` | `auth.test` |
| Slack webhook | `hooks.slack.com/services/…` | regex only |
| OpenAI | `sk-…` | `GET /v1/models` |
| Anthropic | `sk-ant-…` | `GET /v1/models` |
| Datadog | API key + App key pair | `GET /api/v1/validate` |
| NPM | `npm_…` | `GET /-/whoami` |
| PyPI | `pypi-AgEIc…` | `GET upload.pypi.org/legacy/` |
| HuggingFace | `hf_…` | `GET /api/whoami-v2` |
| Cloudflare | API token (keyword-gated) | `GET /user/tokens/verify` |
| SendGrid | `SG.…` | `GET /v3/scopes` |
| Twilio | `AC…` SID + 32-hex auth token pair | `GET /Accounts/<sid>.json` |
| JWT | three-segment base64url | regex only (decodes claims to ExtraData) |
| Private key (PEM) | `-----BEGIN … PRIVATE KEY-----` | regex only |
| DigitalOcean | `dop_v1_…` | `GET /v2/account` |
| Sentry DSN | `https://<32hex>@…/<id>` | regex only |
| MongoDB Atlas | public+private key pair | `GET /api/atlas/v2/orgs` (Basic) |
| HubSpot | `pat-…` | `GET /integrations/v1/me` |
| Salesforce refresh | `5Aep861…` OAuth refresh | regex only (Severity=Medium) |
| New Relic | NRRA / NRAK / NRII keys | `GET /v2/applications.json` (NRRA only) |
| PagerDuty | 20-char alnum (keyword-gated) | `GET /users` |
| Postman | `PMAK-…` | `GET /me` |
| Mailgun | `key-…` (legacy) / `…-…-…` (new) | `GET /v3/domains` |
| Terraform Cloud | `…atlasv1.…` | `GET /api/v2/account/details` |

Add org-specific patterns without forking the binary — see
[Custom rules](#custom-rules) below.

## Severity and CI gating

Every finding carries a Severity:

| When | Severity |
|---|---|
| Verified=true | Critical |
| Unverified explicit detector | High |
| Generic high-entropy / JWT / PEM unverified | Medium |

Use `--fail-on` to choose what blocks the build:

```sh
pleno-dlp scan filesystem ./repo --fail-on critical    # only Critical = exit 1
pleno-dlp scan filesystem ./repo --fail-on high        # High and Critical
pleno-dlp scan filesystem ./repo                       # default: any finding
```

SARIF output maps Severity to GitHub Code Scanning levels (Critical/High
→ error, Medium → warning, Low/Info → note). `partialFingerprints`
carries `secret/v1` (sha256(detector|raw)) so GitHub dedups the same
leak across PRs.

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

`keywords` are required (they gate the regex from running on every
chunk). `verify_url` is optional; when set, a 200 response counts as
verified, 401/403 as unverified, transport errors surface as
`VerificationErr`.

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
   (>=40 chars). Decoded variants are scanned alongside the original;
   hits stamp `ExtraData["decoded_from"]`.

A printable-byte gate keeps binary noise from reaching detectors and
hard limits (50 MiB per entry, 200 MiB total expanded, depth cap)
defeat zip-bomb DoS.

## Git history scan

```sh
pleno-dlp scan git --repo ./repo
pleno-dlp scan git --repo ./repo --branch main --max-depth 500
pleno-dlp scan git --repo ./repo --since 2024-01-01T00:00:00Z
pleno-dlp scan git --repo ./repo --include 'src/**' --exclude '**/*_test.go'
```

Walks every commit reachable from HEAD (or `--branch`) oldest-first,
diffs each commit against its first parent, emits one Chunk per
added/modified blob with full GitMeta (repo path, commit SHA, file,
first-changed line, committer email).

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

## Install

```sh
# Latest release
go install github.com/plenoai/pleno-dlp/cmd/pleno-dlp@latest

# Pre-built archive (linux / darwin / windows × amd64 / arm64)
# https://github.com/plenoai/pleno-dlp/releases

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
