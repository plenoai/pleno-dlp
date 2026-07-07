# Comparison: pleno-dlp vs trufflehog vs gitleaks

Measured functional-gap comparison. Every number in this document was
produced by running the three tools side by side on 2026-06-10 — none
is quoted from vendor documentation. Coverage spans a controlled
synthetic recall corpus (§2), real-world labeled corpora and
popular-OSS noise sweeps (§3–§6), and capability probes (§7–§8).
Performance (wall-clock) numbers live separately in
[`benchmarks.md`](benchmarks.md); this document covers what each tool
*finds* and what each tool *can do*.

## Versions and environment

| Component | Value |
|-----------|-------|
| pleno-dlp  | v0.53.0 (released binary; every number in this document reproduced against it) |
| trufflehog | 3.95.5 (Homebrew; upstream latest as of 2026-06-10) |
| gitleaks   | 8.30.1 (upstream latest as of 2026-06-10) |
| Hardware/OS | Apple M3, 24 GiB, macOS 26.3 — same host as `benchmarks.md` |

Canonical invocations (verification disabled where the tool supports
it; all corpora are `.git`-free unless the probe says otherwise):

```sh
pleno-dlp scan filesystem <dir> --quiet --format json
trufflehog filesystem <dir> --no-verification --no-update --json --log-level=-1
gitleaks dir <dir> --no-banner --report-format json --report-path out.json --exit-code 0
```

## 1. Coverage counts

All counts observed from the installed binaries or the upstream source
tree at the exact released tag.

| Metric | pleno-dlp | trufflehog 3.95.5 | gitleaks 8.30.1 |
|--------|----------:|------------------:|----------------:|
| Detectors / rules | 608 | 870 | 222 |
| Live-verification capable | 552 (+56 unverified-by-design, see [`verify-coverage.md`](verify-coverage.md)) | most detectors (core design) | 0 — no verification subsystem |
| Revocation support | 4 providers + 1 context-required (AWS) | 0 | 0 |
| Scan sources | 28 | 18 (16 excluding `multi-scan` / `json-enumerator` meta-inputs) | 3 (`git`, `dir`, `stdin`) |
| Output formats | json, sarif, table | json, json-legacy, github-actions | json, csv, junit, sarif, template |
| PII detection | yes (`--pii-engine`) | no | no |

Evidence: pleno-dlp counts from `pleno-dlp detectors list
[--verify-status|--revoke-support]` and `pleno-dlp sources list` — the
latter enumerates `pkg/sources/catalog.All()` (the union of the core-source
and SaaS-connector registries) with a `CLI-WIRED` column; the "28" here is
the wired count, matching `pleno-dlp scan --help`'s subcommand list, and is
CI-pinned against `pkg/connectors`/`cmd/pleno-dlp/cmd` drift by
`cmd/pleno-dlp/cmd/sources_sync_test.go` so it cannot go stale like this
row previously did (#259);
trufflehog detector count = detector package directories in
`pkg/detectors` at tag `v3.95.5` (GitHub API), sources/formats from
`trufflehog --help`; gitleaks rule count = `[[rules]]` entries in
`config/gitleaks.toml` at tag `v8.30.1`, sources/formats from the
binary's help.

Detector count alone says little — trufflehog has the largest set yet
the lowest recall on the corpus below. Breadth, recall, and noise have
to be read together.

## 2. Detection recall — 50-type synthetic corpus

Corpus: 50 files, one per credential type, each containing exactly one
synthetic but **format-valid** credential (correct prefix, length,
charset, and checksum where the format defines one; real throwaway
keys for the PEM/PGP types) embedded in 3–6 lines of realistic config
context. A type counts as detected iff the tool emitted at least one
secret finding in that type's file. Detection only — verification was
off; all three tools saw byte-identical input.

| | pleno-dlp | gitleaks | trufflehog |
|---|---:|---:|---:|
| **Detected (of 50)** | **46 (92%)** | **45 (90%)** | **34 (68%)** |

These are best-case numbers: well-formed tokens with cooperative
keyword context. Section 3 measures the same tools on real-world
placements, where every tool's recall drops sharply — read the two
together.

Misses per tool:

- **pleno-dlp (4):** `asana-pat`, `azure-storage-account-key`,
  `pgp-private-key-block`, `slack-webhook-url`. Each is caught by at
  least one competitor, so all four are confirmed detector-gap
  candidates (audited: fixture validity re-verified, single-file
  re-scan reproduced each miss).
- **gitleaks (5):** `asana-pat`, `mongodb-srv-uri`,
  `mysql-conn-string`, `postgres-uri-with-password`,
  `redis-uri-with-password` — no connection-string rules in the
  default config.
- **trufflehog (16):** `atlassian-api-token`, `datadog-api-key`,
  `discord-bot-token`, `grafana`, `jwt-hs256`, `mysql-conn-string`,
  `newrelic`, `pagerduty`, `pgp-private-key-block`, `pypi`,
  `redis-uri-with-password`, `sentry`, `shopify`, `square`,
  `terraform-cloud`, `vault-token`.

Specificity caveat: 9 of gitleaks' 45 hits fire only its
`generic-api-key` entropy rule (azure, datadog, dockerhub, …) — the
leak is caught but not identified, so downstream routing (severity,
revocation, ownership) gets no provider signal. pleno-dlp has 2 such
generic-only hits (`rubygems`, `sentry`); trufflehog has none (every
hit is provider-specific).

### Audit trail

The first corpus build contained 7 malformed fixtures (wrong length /
missing checksum / wrong marker) that biased the as-measured totals to
46/41/31 in pleno-dlp's favor — pleno-dlp's looser regexes matched
several malformed keys that trufflehog/gitleaks correctly require
exact formats for. An adversarial audit format-validated every miss
against the official credential format, rebuilt the invalid fixtures,
and the full corpus was re-scanned with all three tools to produce the
numbers above. pleno-dlp's 4 misses survived the audit; 3 trufflehog
and 4 gitleaks "misses" did not (fixture artifacts, corrected).

<details>
<summary>Full 50-type matrix (detector/rule names that fired)</summary>

| Type | pleno-dlp | trufflehog | gitleaks |
|------|-----------|------------|----------|
| airtable | `Airtable` | `AirtablePersonalAccessToken` | `airtable-personnal-access-token` |
| algolia | `Algolia` | `AlgoliaAdminKey` | `algolia-api-key` |
| anthropic | `Anthropic` | `Anthropic` | `anthropic-api-key` |
| asana-pat | — miss | `AsanaOauth`, `AsanaPersonalAccessToken` | — miss |
| atlassian-api-token | `Atlassian`, `GenericHighEntropy` | — miss | `atlassian-api-token` |
| aws-access-key-pair | `AWS`, `GenericHighEntropy` | `AWS` | `generic-api-key` |
| azure-storage-account-key | — miss | `AzureStorage` | `generic-api-key` |
| cloudflare-api-token | `Cloudflare` | `CloudflareApiToken` | `cloudflare-api-key` |
| datadog-api-key | `Datadog` | — miss | `generic-api-key` |
| digitalocean | `DigitalOcean`, `GenericHighEntropy` | `DigitalOceanV2` | `digitalocean-pat` |
| discord-bot-token | `Discord`, `GenericHighEntropy` | — miss | `generic-api-key` |
| dockerhub | `DockerHub`, `GenericHighEntropy` | `Dockerhub` | `generic-api-key` |
| ec-private-key | `PrivateKeyPEM` | `PrivateKey` | `private-key` |
| gcp-service-account-json | `GenericHighEntropy`, `PrivateKeyPEM` | `PrivateKey` | `private-key` |
| github-pat-classic | `GenericHighEntropy`, `GitHub` | `Github` | `github-pat` |
| github-pat-fine-grained | `GenericHighEntropy`, `GitHub`, `GitHubFineGrained` | `Github` | `github-fine-grained-pat` |
| gitlab-pat | `GenericHighEntropy`, `GitLab` | `Gitlab` | `gitlab-pat` |
| google-api-key | `GCPAPIKey`, `GenericHighEntropy` | `GoogleGeminiAPIKey` | `gcp-api-key` |
| grafana | `GenericHighEntropy`, `Grafana` | — miss | `grafana-service-account-token` |
| huggingface | `GenericHighEntropy`, `HuggingFace` | `HuggingFace` | `generic-api-key` |
| jwt-hs256 | `JWT` | — miss | `jwt` |
| linear | `GenericHighEntropy`, `Linear` | `LinearAPI` | `linear-api-key` |
| mailchimp | `Mailchimp` | `Mailchimp` | `generic-api-key` |
| mailgun | `GenericHighEntropy`, `Mailgun` | `Mailgun` | `mailgun-private-api-token` |
| mongodb-srv-uri | `MongoDB` | `MongoDB` | — miss |
| mysql-conn-string | `MySQL` | — miss | — miss |
| netlify | `GenericHighEntropy`, `Netlify` | `Netlify` | `netlify-access-token` |
| newrelic | `GenericHighEntropy`, `NewRelic` | — miss | `new-relic-user-api-key` |
| notion | `GenericHighEntropy`, `Notion` | `Notion` | `generic-api-key` |
| npm | `GenericHighEntropy`, `NPM` | `NpmToken` | `npm-access-token` |
| openai | `GenericHighEntropy`, `OpenAI` | `OpenAI` | `openai-api-key` |
| openssh-private-key | `PrivateKeyPEM` | `PrivateKey` | `private-key` |
| pagerduty | `PagerDuty` | — miss | `generic-api-key` |
| pgp-private-key-block | — miss | — miss | `private-key` |
| postgres-uri-with-password | `Postgres` | `Postgres` | — miss |
| pypi | `GenericHighEntropy`, `PyPI` | — miss | `pypi-upload-token` |
| redis-uri-with-password | `Redis` | — miss | — miss |
| rsa-private-key-pem | `PrivateKeyPEM` | `PrivateKey` | `private-key` |
| rubygems | `GenericHighEntropy` | `RubyGems` | `rubygems-api-token` |
| sendgrid | `GenericHighEntropy`, `SendGrid` | `SendGrid` | `sendgrid-api-token` |
| sentry | `GenericHighEntropy` | — miss | `sentry-org-token` |
| shopify | `GenericHighEntropy`, `Shopify` | — miss | `shopify-access-token` |
| slack-bot-token | `GenericHighEntropy`, `SlackBotToken` | `Slack` | `slack-bot-token` |
| slack-webhook-url | — miss | `SlackWebhook` | `slack-webhook-url` |
| square | `GenericHighEntropy`, `Square` | — miss | `square-access-token` |
| stripe-secret-key | `Stripe` | `Stripe` | `stripe-access-token` |
| telegram-bot-token | `GenericHighEntropy`, `Telegram` | `TelegramBotToken` | `telegram-bot-api-token` |
| terraform-cloud | `TerraformCloud` | — miss | `hashicorp-tf-api-token` |
| twilio-api-key | `GenericHighEntropy`, `Twilio` | `Twilio` | `generic-api-key`, `twilio-api-key` |
| vault-token | `GenericHighEntropy`, `Vault` | — miss | `vault-service-token` |

</details>

## 3. Real-world recall — labeled corpora

Three public corpora with realistically-placed (not synthetic)
credentials, scanned in dir mode (`.git` removed for trufflehog
fairness).

### leaky-repo (Plazmaz/leaky-repo @ `2e95135`)

The community-standard scanner benchmark: 44 ground-truth files
(README secrets table, cross-checked against `.leaky-meta/secrets.csv`
and the tree) holding credentials in their natural homes — dotfiles,
`wp-config.php`, `.pgpass`, FTP-client XML, IDE configs.

| | pleno-dlp | gitleaks | trufflehog | union of all 3 |
|---|---:|---:|---:|---:|
| Ground-truth files hit (of 44) | **13 (30%)** | **13 (30%)** | 8 (18%) | 19 (43%) |

The headline is the last column: **25 of 44 real-world secret files are
missed by every tool tested** — `.pgpass`, `.netrc`, `.git-credentials`,
`wp-config.php`, Django `SECRET_KEY`, Rails `master.key`, FileZilla/
SFTP-client configs, `/etc/shadow`. Structured config-file passwords
and low-entropy secrets are an industry-wide blind spot, not a
two-tool race. The three tools are also complementary: pleno-dlp hits
3 files nobody else does (Laravel `.env`, `db/dump.sql`, Firefox
`logins.json`), gitleaks 4 (`.tugboat`, `heroku.json`, `hub`,
`secrets.yml`), trufflehog 1 (PuTTY `.ppk`).

Every miss was double-checked by single-file re-scan with a working
positive control, so these are detection misses, not directory-walker
skips.

<details>
<summary>Per-file matrix (44 ground-truth files)</summary>

| File | Secret kind | pleno | TH | GL |
|------|-------------|:--:|:--:|:--:|
| `.npmrc` | NPM registry auth token | — | ✓ | ✓ |
| `.docker/.dockercfg` | Docker registry auth (base64) | ✓ | — | ✓ |
| `misc-keys/cert-key.pem` | PEM private key | ✓ | ✓ | ✓ |
| `misc-keys/putty-example.ppk` | PuTTY private key | — | ✓ | — |
| `.ssh/id_rsa` | SSH private key | ✓ | ✓ | ✓ |
| `.ssh/id_rsa.pub` | SSH public key (informative-only, 0 risk) | — | — | — |
| `db/dump.sql` | MySQL dump with bcrypt hashes | ✓ | — | — |
| `cloud/.credentials` | AWS/S3 credentials file | ✓ | — | ✓ |
| `cloud/.s3cfg` | s3cmd S3 credentials | ✓ | — | ✓ |
| `cloud/.tugboat` | DigitalOcean tugboat API key | — | — | ✓ |
| `cloud/heroku.json` | Heroku API key | — | — | ✓ |
| `web/var/www/public_html/wp-config.php` | WordPress DB password + auth keys/salts | — | — | — |
| `web/var/www/public_html/.htpasswd` | htpasswd password hash | — | — | — |
| `web/var/www/public_html/config.php` | PHP app config DB password | — | — | — |
| `web/var/www/.env` | Laravel .env APP_KEY + passwords | ✓ | — | — |
| `.git-credentials` | git credential store (URL-embedded password) | — | — | — |
| `.bashrc` | env-var secrets (Mailchimp key etc.) | ✓ | ✓ | ✓ |
| `.bash_profile` | env-var secrets (GitHub token, Slack token etc.) | ✓ | ✓ | ✓ |
| `db/robomongo.json` | Mongolab/robomongo MongoDB + SSH creds | — | — | — |
| `db/mongoid.yml` | MongoDB connection URI credentials | ✓ | ✓ | — |
| `web/js/salesforce.js` | Salesforce credentials in Node.js code | — | — | — |
| `.netrc` | netrc SMTP credentials | — | — | — |
| `hub` | GitHub OAuth token (hub config) | — | — | ✓ |
| `filezilla/filezilla.xml` | FileZilla FTP password (base64) | — | — | — |
| `filezilla/recentservers.xml` | FileZilla recent-server FTP passwords | — | — | — |
| `.docker/config.json` | Docker registry auth (base64) | ✓ | — | ✓ |
| `config` | IRC NickServ password | — | — | — |
| `db/.pgpass` | PostgreSQL .pgpass password | — | — | — |
| `proftpdpasswd` | proftpd/cpanel crypt password hash | — | — | — |
| `ventrilo_srv.ini` | Ventrilo server passwords | — | — | — |
| `etc/shadow` | /etc/shadow password hash | — | — | — |
| `db/dbeaver-data-sources.xml` | DBeaver MySQL JDBC credentials | ✓ | ✓ | — |
| `.esmtprc` | esmtp SMTP password | — | — | — |
| `.mozilla/firefox/logins.json` | Firefox saved-login encrypted blobs | ✓ | — | — |
| `web/django/settings.py` | Django SECRET_KEY | — | — | — |
| `web/ruby/secrets.yml` | Rails secrets.yml secret_key_base | — | — | ✓ |
| `web/ruby/config/master.key` | Rails master key | — | — | — |
| `deployment-config.json` | sftp-deployment (Atom) server creds | — | — | — |
| `.ftpconfig` | remote-ssh (Atom) SFTP/SSH creds + passphrase | — | — | — |
| `.remote-sync.json` | remote-sync (Atom) FTP/SFTP creds | — | — | — |
| `.vscode/sftp.json` | vscode-sftp SFTP creds | — | — | — |
| `sftp-config.json` | Sublime SFTP FTP/SFTP creds | — | — | — |
| `.idea/WebServers.xml` | JetBrains webserver password (encoded, not encrypted) | — | — | — |
| `high-entropy-misc.txt` | misc high-entropy strings (informative-only, 0 risk) | — | — | — |

</details>

### terragoat (bridgecrewio/terragoat @ `729f8da`)

Intentionally vulnerable Terraform; ground truth built by manual sweep
(6 files with hardcoded credentials). On the classic IaC leak shape —
low-entropy hardcoded DB passwords (`Aa1234321Bb` style) — pleno-dlp
and trufflehog catch **0 of 3** password files; gitleaks catches 1 via
its dedicated `hashicorp-tf-password` rule. All three tools skip the
AWS keypair because terragoat uses AWS's documented example key
(`AKIAIOSFODNN7EXAMPLE`), which all three correctly allowlist
(confirmed by controlled probe with a non-example key).

### OWASP Juice Shop (juice-shop/juice-shop @ `160f306`)

A real Node.js application tree (~25 MB) with 9 ground-truth files /
33 planted credential instances (JWT RSA signing key, HMAC secret,
TOTP secret, 23 seeded user passwords, key files, an Ethereum
mnemonic).

| | pleno-dlp | gitleaks | trufflehog |
|---|---:|---:|---:|
| Ground-truth files hit (of 9) | **6** | 5 | 1 |
| Instances detected (of 33) | **10** | 6 | 1 |
| Total findings emitted | 103 | 59 | 5 |

pleno-dlp leads recall but at the highest noise (103 findings for 10
true instances); trufflehog detects essentially only the RSA private
key. Universally missed: standalone key files without PEM armor
(`ctf.key`, `premium.key`), the BIP39 mnemonic, and most low-entropy
seeded passwords.

## 4. Real-world noise — popular OSS and clean corpora

### Popular-OSS sweep (8 repos, default branches @ 2026-06-10)

express, flask, gin, sinatra, laravel/framework, spring-petclinic,
axios, serilog — maintained repos with no known live leaks. Every
finding was read in context and adjudicated (live-risk / test-fixture
/ doc-placeholder / non-credential); adjudication capped at 30
findings per tool per repo.

| | pleno-dlp | trufflehog | gitleaks |
|---|---:|---:|---:|
| Total findings (8 repos) | 70 | 44 | 31 |
| → live-risk credentials | 0 | 0 | 0 |
| → test fixtures (real-format keys in tests) | 6 | 8 | 21 |
| → doc placeholders | 3 | 17 | 7 |
| → non-credential (hashes, IDs) | 50 | 10 | 3 |

Zero live credentials anywhere (expected for maintained OSS) — so all
volume is triage noise, and the composition matters: gitleaks' noise
is mostly genuine test keys (defensible alerts); pleno-dlp's is
dominated by `GenericHighEntropy` firing on hashes and random IDs in
hash-dense ecosystems (41 findings in laravel/framework alone, 23 in
axios). The Go-module corpus below shows the opposite ranking —
noise profiles are ecosystem-dependent, and pleno-dlp's FP hardening
(tuned on Go corpora) has not yet caught up on PHP/JS trees.

> **2026-07-07 update (#249):** added hash-dense PHP/JS context gating
> to `GenericHighEntropy` — crypt(3)-family hash-fragment detection
> (bcrypt `$2y$`/`$2a$`/`$2b$`/`$2x$`, Argon2 `$argon2i$/$argon2d$/
> $argon2id$`, classic crypt `$1$/$5$/$6$`, pbkdf2, and the generic
> `$xxxx$` salt/hash-segment shape), a targeted fix for algorithm-name
> test identifiers that defeated the existing CamelCase-identifier
> filter (`testBasicArgon2iHashing`-style method names), bundler
> content-hash filename recognition (`<Name>-<hash>.js` in Vite/webpack
> manifests), MIME-type string recognition (`application/x-www-form-
> urlencoded`), and a base64-decodes-to-printable-text check (catches
> RFC 7617's canonical Basic-Auth doc example). Re-running the exact
> two repos named above (fresh shallow clones, same
> `pleno-dlp scan filesystem --quiet --format json` invocation, current
> `main`) measured:
>
> | Repo | GenericHighEntropy before | GenericHighEntropy after |
> |---|---:|---:|
> | laravel/framework | 23 | 1 (the one retained is a real Laravel `APP_KEY`-shaped `base64:<32 random bytes>` value — correctly still flagged) |
> | axios/axios | 7 | 1 (one non-ASCII Basic-Auth doc-example variant the printable-text check doesn't cover — known residual) |
>
> The 23/7 "before" counts are lower than the 41/23 quoted above because
> they're measured against current `main` (which already includes the
> SRI-hash and hex-digest hardening from PR #207, landed after the
> 2026-06-10 sweep) rather than the original snapshot — this update
> layers on top of that fix, it does not re-derive it. No other
> detector's finding count changed on either repo (verified via
> per-detector diff). All existing `pkg/detectors/generic` unit tests
> plus new fixture-based regression tests for each new check pass, and
> the project's synthetic recall fixtures for `GenericHighEntropy`
> (`Hf83KdjL9qZ8...`-shaped tokens) and a Laravel `APP_KEY`-shaped
> control both still fire. **Pending:** a full 8-repo re-adjudication
> against this change is maintainer work and has not been done here —
> the Total/bucket numbers in the table above are not yet updated.

### Clean Go-module corpus (Workload D)

Workload D from [`benchmarks.md`](benchmarks.md): go-git v5.19.0 +
cobra v1.8.1 + aws-sdk-go-v2 v1.41.7 (754 files, 7.9 MiB, zero live
secrets — only docs literals, test fixtures, and hashes). Every
finding is a false positive by construction.

| | pleno-dlp | trufflehog | gitleaks |
|---|---:|---:|---:|
| False positives | 6 | 6 | 5 |

trufflehog (6) and gitleaks (5) exactly reproduce the 2026-05-12
snapshot in `benchmarks.md`. pleno-dlp dropped from 484 to 6 — the
snapshot predates the FP-hardening campaign completed 2026-06-01. The
overlap is one genuine-looking test TLS key
(`plumbing/transport/http/testdata/certs/server.key`) flagged by all
three; the rest are entropy hits on changelogs and test fixtures.

## 5. Git-history scans on real repos

Full clones, git-mode invocations, single timed run (informational):

| Repo (commits) | pleno-dlp | trufflehog | gitleaks |
|---|---|---|---|
| flask (5,539) | 0 findings, 14.0 s | 0 findings, 2.1 s | 12 findings / 2 unique, 0.7 s |
| express (6,146) | 93 findings / 2 unique, 16.5 s | 1 finding, 2.1 s | 0 findings, 0.9 s |
| gin (1,996) | 37 findings / 6 unique, 11.5 s | 3 findings / 2 unique, 2.0 s | 6 findings / 5 unique, 0.5 s |

The findings/unique ratio exposes duplicate handling: by default
pleno-dlp now applies cross-commit dedup (`NewGitCrossCommitDedup`,
`cmd/scan.go`) so the same secret+file pair across many commits collapses
to a single introducing-commit finding annotated with
`extra_data.occurrence_count`. The numbers above were measured against
v0.53.0 before this was added; opt-out via `--all-occurrences`.
trufflehog reports a secret once at its introducing diff; gitleaks
reports per commit-touch but its volumes stay small. gitleaks is also
15–25× faster than pleno-dlp on history scans of this size.

## 6. Verification as a triage filter

Live verification (pleno-dlp and trufflehog only; gitleaks has none)
re-checks each candidate against the issuing provider. On leaky-repo +
terragoat + express + flask:

| Operator view | Alerts to read (4 repos) |
|---|---:|
| gitleaks, all findings | 32 |
| pleno-dlp, default (all findings, verified flag annotated) | 31 |
| trufflehog `--results=verified` | **0** |
| pleno-dlp `--only-verified` | **0** |

Every detected credential in these public corpora is dead (leaky-repo
secrets are published-and-revoked by design), so verification-gated CI
reduces 30+ must-read alerts to zero with no live credential missed.
This is the strongest real-world argument for verification-capable
scanners — and it is exactly the gate gitleaks cannot offer. The
flip side: a verification-gated pipeline reports nothing for dead-but-
sensitive material (the leaky-repo corpus would sail through), so
`--only-verified` is a triage policy, not a hygiene policy.

## 7. Capability probes

Each row was exercised with a purpose-built fixture; "yes/no" reflects
observed behavior, not documentation.

| Capability | pleno-dlp | trufflehog | gitleaks |
|------------|-----------|------------|----------|
| Git history (secret only in a deleted past commit) | ✓ detected | ✓ detected | ✓ detected |
| Commit attribution on history findings | commit + file + author + email + date + message + computed line (fullest) | email + timestamp | author + email + date + message (fullest) |
| stdin source | ✓ | ✓ (`stdin` subcommand) | ✓ |
| Secrets inside `.zip` | ✗ (archive walker exists but blocked by `isBinary` gate — see #208) | ✓ | ✗ |
| Secrets inside `.tar.gz` | ✗ (archive walker exists but blocked by `isBinary` gate — see #208) | ✓ | ✗ |
| Base64-encoded secret (decode-then-detect) | ✓ (`extra_data.decoded_from=base64`) | ✗ (decoder exists; generic AWS-secret line not re-detected) | ✓ (`decoded:base64` tag) |
| UTF-16 encoded secret | ✗ | ✓ (UTF16 decoder) | ✗ |
| SARIF output | ✓ valid 2.1.0 | ✗ (no SARIF format) | ✓ valid 2.1.0 |
| Exit-code gating | exit 1 on findings; `--fail-on` severity threshold | exit 0 by default; opt-in `--fail` → 183 | exit 1 on findings; `--exit-code N`; no severity concept |
| Custom rules | ✓ (`--rules` JSON) | ✓ (`--config` YAML CustomRegex) | ✓ (`--config` TOML `[[rules]]`) |
| Machine-clean stdout | ✓ JSON array; `--quiet` empties stderr | ✓ NDJSON; logs on stderr | ✓ report file; logs on stderr |

Two behaviors worth flagging:

- **trufflehog filesystem mode reads `.git` internals.** On a worktree
  whose HEAD is clean but whose history contains a secret, `trufflehog
  filesystem` still surfaced the secret by decompressing loose objects
  under `.git/`. pleno-dlp and gitleaks treat directory scans as
  worktree-only (0 findings). Neither behavior is wrong, but
  cross-tool finding counts on repos that include `.git` are not
  comparable.
- **pleno-dlp git-mode attribution** — commit, file, author, email, date, message, and computed line numbers are all now emitted (landed in PR #199). This behavior is now on par with gitleaks.

## 8. PII detection — capability only pleno-dlp has

Fixtures: a Japanese customer-support record with 8 labeled PII items
(name, furigana, phone, email, postal address, birth date, My Number,
credit-card number) and an English record with 5 (name, email, phone,
SSN, address). All values fictional.

| Items detected | pleno-dlp (`--pii-engine anonymize`) | trufflehog | gitleaks |
|---|---|---|---|
| Japanese (8 items) | 6/8 — missed: postal address, birth date | 0/8 | 0/8 |
| English (5 items) | 4/5 — missed: street address | 0/5 | 0/5 |

trufflehog and gitleaks produced zero findings on both files (neither
has a PII subsystem; not even the Luhn-valid card number fired a
rule). pleno-dlp numbers are engine-level recall via the anonymize
engine's `/api/analyze` (entity types: `PERSON`, `PHONE_NUMBER`,
`EMAIL_ADDRESS`, `MY_NUMBER`, `CREDIT_CARD`, `US_SSN`); all PII
findings carry `extra_data.finding_class=pii` for downstream routing.
Engine cost on this host: ~6.4 s end-to-end warm scan (engine spawn
included), ~25 s after an upstream ref change (wheel reinstall); the
very first bootstrap clones ~550 MiB of model data.

## 9. Known gaps (pleno-dlp roadmap candidates)

Where the competition — or the whole industry — is measurably ahead:

1. **Real-world config-file recall** (§3) — 25/44 leaky-repo files
   missed by every tool. The biggest wins available to any scanner:
   structured-config password extraction (`wp-config.php`, `.pgpass`,
   `.netrc`, `.git-credentials`, framework secret keys, SFTP/IDE
   client configs) and low-entropy hardcoded passwords in IaC (§3
   terragoat: 0/3 for pleno-dlp; gitleaks has a dedicated rule).
2. **GenericHighEntropy noise on hash-dense ecosystems** (§4) — 50 of
   70 sweep findings were non-credentials (laravel 41, axios 23). FP
   hardening was tuned on Go corpora and doesn't transfer to PHP/JS
   trees yet. *(partially addressed in #249: crypt-hash-fragment,
   algorithm-name-identifier, bundler-asset-filename, MIME-type, and
   base64-printable-text context gating added to
   `pkg/detectors/generic`, measured 23→1 on laravel/framework and 7→1
   on axios/axios — see the dated note in §4. A full 8-repo
   re-adjudication against the new baseline is still pending.)*
3. **Git-mode duplicate findings** (§5) — *(closed: cross-commit dedup
   landed in `pkg/engine/dedup.go:NewGitCrossCommitDedup`, wired in
   `cmd/scan.go`. git attribution also closed in PR #199.)*
4. **Archive scanning** — trufflehog finds secrets inside `.zip` /
   `.tar.gz`; pleno-dlp and gitleaks scan only raw bytes. The
   pleno-dlp archive walker exists and is wired at the engine layer
   (`pkg/engine/engine.go:173`) but is unreachable from the filesystem
   source because the `isBinary` gate drops archives before they reach
   the engine (tracked in #208).
5. **UTF-16 decoding** — trufflehog only.
6. **Synthetic-corpus recall misses** (§2) — `slack-webhook-url`,
   `azure-storage-account-key` (AccountKey= connection strings),
   `asana-pat`, PGP `PRIVATE KEY BLOCK` armor headers.
7. **Detector breadth** — trufflehog ships 870 detector packages vs
   608 (long tail of niche SaaS providers).
8. **Source breadth vs trufflehog** — several trufflehog sources have no
   pleno-dlp equivalent. They fall into two categories:

   *Planned (tracked in #188)*: Elasticsearch (#217), Jenkins (#218),
   Postman (#219) — connectors exist under `pkg/connectors/` but have no
   CLI subcommand yet, so they are not reachable via `pleno-dlp scan`.
   Docker image layers (#215), GCS (#216), HuggingFace (#220), and
   CircleCI (#221) were previously listed here but are implemented and
   CLI-reachable (`pleno-dlp scan docker-image|gcs|huggingface|circleci`);
   counted in the 28 below (recounted in #259). Run `pleno-dlp sources
   list` to see the live split — every row it prints comes from
   `pkg/sources/catalog.All()` (`pkg/sources.Registered()` plus
   `pkg/connectors.Names()`), and its `CLI-WIRED` column is exactly this
   planned/implemented boundary, computed rather than hand-tracked (#259).

   *Not supported — accepted gap by design* (#222): `syslog` (long-running
   listener daemon; architectural mismatch with pleno-dlp's batch model),
   `travisci` (platform in decline; low and shrinking demand),
   `github-experimental` (explicitly experimental upstream; not a stable
   parity target). These will not be implemented unless concrete user demand
   is reported.

   pleno-dlp's 28 sources lead on SaaS-document surfaces: confluence, jira,
   notion, slack, splunk, datadog, redash, bigquery, sqldump, forge-API
   comments.

## Limitations

- §2's corpus is synthetic with cooperative context (env-var style
  keyword lines); §3 shows real-world recall is far lower for every
  tool. Neither number alone characterizes a scanner.
- File-level hit matching throughout: a finding anywhere in the
  ground-truth file counts, which credits generic entropy rules
  equally with provider-specific ones (see the specificity caveats).
- Ground truth for terragoat and juice-shop was built by manual review
  (method recorded in each section); leaky-repo ground truth comes
  from the benchmark's own documented inventory.
- Sweep adjudications were capped at 30 findings per tool per repo
  (laravel pleno-dlp and axios trufflehog hit the cap); the audit
  spot-checked classifications but not all of them.
- All claimed misses were re-verified by single-file re-scan with a
  positive control; an independent adversarial audit re-ran sampled
  scans and reproduced every headline number
  (verdict: holds-with-corrections — two derived union counts fixed).
- Single host, single run for the capability probes and history
  timings; recall and FP dir-scans are deterministic so run-to-run
  variance is nil for those tables.
- pleno-dlp numbers are from the released v0.53.0 binary;
  trufflehog/gitleaks were stock Homebrew/nix builds at the upstream
  latest releases as of 2026-06-10.

## Reproducing

Synthetic corpus (§2): generators and raw outputs are not committed
(the fixtures are format-valid fake credentials — committing them
would trip push protection and every scanner in CI, by design). To
rebuild: generate one file per type listed in the matrix above with a
fresh random format-valid token embedded in 3–6 lines of env-style
context, then run the three canonical invocations at the top of this
document and count per-file hits.

Real-world corpora (§3–§6) are all public and pinned by commit:
`Plazmaz/leaky-repo@2e95135`, `bridgecrewio/terragoat@729f8da`,
`juice-shop/juice-shop@160f306`, plus the 8 sweep repos and 3
history repos at their 2026-06-10 default branches. Clone, strip
`.git` for dir-mode runs, and apply the canonical invocations. The
Workload D FP corpus is reproducible exactly via the `benchmarks.md`
recipe.
