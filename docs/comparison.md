# Comparison: pleno-dlp vs trufflehog vs gitleaks

Measured functional-gap comparison. Every number in this document was
produced by running the three tools side by side on 2026-06-10 — none
is quoted from vendor documentation. Performance (wall-clock) numbers
live separately in [`benchmarks.md`](benchmarks.md); this document
covers what each tool *finds* and what each tool *can do*.

## Versions and environment

| Component | Value |
|-----------|-------|
| pleno-dlp  | `dev` build of `main` (post-`00c339b`, including the PII-engine wheel fix shipped with this document) |
| trufflehog | 3.95.5 (Homebrew; binary self-reported version) |
| gitleaks   | 8.30.1 |
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
| Detectors / rules | 600 | 870 | 222 |
| Live-verification capable | 550 (+50 unverified-by-design, see [`verify-coverage.md`](verify-coverage.md)) | most detectors (core design) | 0 — no verification subsystem |
| Revocation support | 4 providers + 1 context-required (AWS) | 0 | 0 |
| Scan sources | 24 | 18 (16 excluding `multi-scan` / `json-enumerator` meta-inputs) | 3 (`git`, `dir`, `stdin`) |
| Output formats | json, sarif, table | json, json-legacy, github-actions | json, csv, junit, sarif, template |
| PII detection | yes (`--pii-engine`) | no | no |

Evidence: pleno-dlp counts from `pleno-dlp detectors list
[--verify-status|--revoke-support]` and `pleno-dlp scan --help`;
trufflehog detector count = detector package directories in
`pkg/detectors` at tag `v3.95.5` (GitHub API), sources/formats from
`trufflehog --help`; gitleaks rule count = `[[rules]]` entries in
`config/gitleaks.toml` at tag `v8.30.1`, sources/formats from the
binary's help.

Detector count alone says little — trufflehog has the largest set yet
the lowest recall on the corpus below. Breadth, recall, and noise have
to be read together.

## 2. Detection recall — 50-type labeled corpus

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

## 3. False positives — clean real-world corpus

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

## 4. Capability probes

Each row was exercised with a purpose-built fixture; "yes/no" reflects
observed behavior, not documentation.

| Capability | pleno-dlp | trufflehog | gitleaks |
|------------|-----------|------------|----------|
| Git history (secret only in a deleted past commit) | ✓ detected | ✓ detected | ✓ detected |
| Commit attribution on history findings | commit + file only | email + timestamp | author + email + date + message (fullest) |
| stdin source | ✓ | ✓ (`stdin` subcommand) | ✓ |
| Secrets inside `.zip` | ✗ | ✓ | ✗ |
| Secrets inside `.tar.gz` | ✗ | ✓ | ✗ |
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
- **pleno-dlp git-mode line numbers are unreliable** (always `1` in
  this probe) and findings carry no author/date — tracked as a known
  gap below.

## 5. PII detection — capability only pleno-dlp has

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

Benchmarking found the anonymize engine entirely broken at HEAD (two
bugs: stale model-wheel URLs after the upstream `ja_ner_ja` →
`pleno_anonymize_ja` rename, and `uv sync` pruning the model wheels on
warm starts). Both were fixed in the same change that added this
document; the numbers above are from the fixed binary.

## 6. Known gaps (pleno-dlp roadmap candidates)

Where the competition is measurably ahead:

1. **Archive scanning** — trufflehog finds secrets inside `.zip` /
   `.tar.gz`; pleno-dlp and gitleaks scan only raw bytes.
2. **UTF-16 decoding** — trufflehog only.
3. **Recall misses** — `slack-webhook-url`, `azure-storage-account-key`
   (AccountKey= connection strings), `asana-pat`, PGP `PRIVATE KEY
   BLOCK` armor headers.
4. **Detector breadth** — trufflehog ships 870 detector packages vs
   600 (long tail of niche SaaS providers).
5. **Source breadth vs trufflehog** — docker images, postman, jenkins,
   elasticsearch, GCS, syslog, CircleCI/TravisCI have no pleno-dlp
   equivalent (pleno-dlp's 24 sources lead on SaaS-document surfaces:
   confluence, jira, notion, slack, splunk, datadog, redash, bigquery,
   sqldump, forge-API comments).
6. **Git-mode attribution** — gitleaks reports author/email/date/
   message per finding; pleno-dlp reports commit + file only and
   currently mis-reports line numbers in git mode.

## Limitations

- Recall corpus is synthetic with cooperative context (env-var style
  keyword lines); real-world recall is lower for every tool.
- File-level hit matching: a finding anywhere in the type's file
  counts. One credential per file makes this exact, but it credits
  generic entropy rules equally with provider-specific ones (see the
  specificity caveat).
- Fixture validity was format-audited for every miss; hits were
  spot-checked (8 random) but not exhaustively re-validated.
- Single host, single run for the capability probes; recall and FP
  scans are deterministic (verification off) so run-to-run variance is
  nil for those tables.
- pleno-dlp was a `dev` build of `main`; the released binaries may
  differ. trufflehog/gitleaks were stock Homebrew/nix builds.

## Reproducing

Corpus generators and raw outputs are not committed (the fixtures are
format-valid fake credentials — committing them would trip push
protection and every scanner in CI, by design). To rebuild: generate
one file per type listed in the matrix above with a fresh random
format-valid token embedded in 3–6 lines of env-style context, then
run the three canonical invocations at the top of this document and
count per-file hits. The FP corpus is reproducible exactly via the
`benchmarks.md` Workload D recipe.
