# kingfisher CLI parity

This document maps every subcommand and flag of
[mongodb/kingfisher](https://github.com/mongodb/kingfisher) (reference
commit `98b67a0`; sources `src/cli/**`, `docs/USAGE.md`, `ADVANCED.md`,
`CONFIG.md`, `ALERTS.md`, `AUDIT_LOG.md`, `INTEGRATIONS.md`) to its
pleno-dlp equivalent. It tracks epic #817: pleno-dlp aims to be a strict
superset of kingfisher.

Status values:

- **done** — an equivalent exists (the pleno-dlp spelling is given).
- **gap** — not yet implemented; tracked in #870.
- **won't** — intentionally not implemented; the rationale is given.

## Subcommands

| kingfisher | pleno-dlp | Status |
|---|---|---|
| `scan <path>` / `scan filesystem` | `scan filesystem` | done |
| `scan --git-url` | `scan git --git-url` | done |
| `scan github` / `gitlab` / `gitea` / `bitbucket` / `azure` | `scan github` / `gitlab` / `gitea` (+ forgejo, codeberg, gogs, ...) / `bitbucket` / `azure-devops` | done |
| `scan huggingface` | `scan huggingface` | done (models, datasets, spaces, buckets, users, orgs) |
| `scan slack` / `teams` / `jira` / `confluence` / `postman` | same names | done |
| `scan gcs` / `s3` / `azure-blob` / `docker-image` | same names | done |
| `scan <provider> --list-only` (`ListRepositories`) | `sources` introspection only | gap |
| `rules list` | `detectors list` (`--verify-status`) | done |
| `rules check` (positive/negative examples) | detector fixture tests (`go test ./pkg/detectors/...`); custom rules validated at load | partial |
| `rules compile-cache` / `prune-cache`, `--rule-cache*`, `--no-rule-cache`, `--prune-rule-cache` | — | won't: Go RE2 + Aho-Corasick prefilter compile at start-up in milliseconds; there is no Vectorscan database to cache |
| `validate --rule R --secret S` | `validate --detector D --secret -` (stdin; table/json; exit 0 only when verified) | done |
| `revoke` | `revoke` | done |
| `blast-radius` / `access-map` | `blast-radius`, `scan --blast-radius` | done |
| `view` | `view` | done |
| `config` (emit `kingfisher.yaml` from flags) | — | gap |
| `self-update`, `--self-update`, `--no-update-check` | — | won't: binaries ship through Homebrew and GoReleaser trusted publishing with signed provenance; an in-place updater would bypass the package manager and the attestation check. `brew upgrade pleno-dlp` is the update path |

## Scan flags

| kingfisher | pleno-dlp | Status |
|---|---|---|
| `--format pretty/json/jsonl/sarif/html` | `--format table/json/jsonl/sarif/html` | done |
| `--format bson` / `toon` | same | done |
| `--output/-o` | shell redirection; `view -o` | partial |
| `--confidence` / `--min-confidence` | `--fail-on` severity tiers | partial (severity, not confidence) |
| `--only-valid` | `--only-verified`, `--only-provider-confirmed` | done |
| `--no-validate` | `--no-verify` | done |
| `--validation-rps` | `--verify-rps` (per host) | done |
| `--validation-rps-rule`, `--validation-retries`, `--validation-timeout` | `--verify-rps-detector DETECTOR=RPS`, `--verify-retries`, `--verify-timeout` | done |
| `--max-validation-response-length`, `--full-validation-response` | — | won't: pleno-dlp never stores provider response bodies (redaction policy, `docs/redaction.md`) |
| `--skip-aws-account`, `--skip-aws-account-file` | same; built-in Thinkst canary list; account decoded offline into `aws_account_id` | done |
| `--allow-internal-ips`, `--enable-rule-internal-ips` | verifiers refuse non-public IPs; custom-rule `validation` has SSRF guards | done (stricter, not overridable) |
| `--skip-regex`, `--skip-word` | same | done |
| `--no-inline-ignore`, `--extra-ignore-comments` | `--no-inline-allow`; pragma `pleno-dlp:allow` | done (custom comment tokens: gap) |
| `--baseline-file`, `--manage-baseline` | `--baseline`, `baseline create/update` | done |
| `--exclude`, `--skip-path-prefixes`, `--file-extensions` | `--exclude`, `--include` globs | done |
| `--no-ignore`, `--no-ignore-if-contains` | `--no-default-excludes` | done |
| `--max-file-size(-mb)` | `--max-size` (bytes) | done |
| `--no-binary` | binary detection is automatic | done |
| `--no-extract-archives`, `--extraction-depth` | `pkg/archive` budgets; `--extraction-depth`; git `--git-archive-max-depth` | partial (`--no-extract-archives`: gap) |
| `--no-dedup` | `scan git --all-occurrences` | partial |
| `--redact` | redaction is always on | done (stricter) |
| `--min-entropy` | per-detector entropy thresholds | won't: global override would weaken calibrated detectors |
| `--rule`, `--exclude-rule`, `--load-builtins/--no-builtins`, `--rules-path` | `--include-detectors`, `--exclude-detectors`, `--rules` | done |
| `--jobs/-j`, `--num-jobs` | `--concurrency` | done |
| `--rule-stats` | `--cpu-profile`, `docs/counts.md` | partial |
| `--since-commit`, `--branch`, `--branch-root(-commit)`, `--staged` | `scan git --since-commit/--branch/--branch-root-commit`, `protect` | done |
| `--git-history`, `--git-clone`, `--git-clone-dir`, `--keep-clones`, `--repo-clone-limit`, `--git-repo-timeout` | `--history`, `--repo-clone-timeout`, `--repo-walk-timeout` | done (clone dir retention: won't, clones are ephemeral by design) |
| `--repo-artifacts`, `--include-contributors` | `--include-issues/--include-pull-requests/--include-wikis/--include-comments` | done |
| `--scan-nested-repos` | — | gap |
| `--turbo`, `--no-limits`, `--no-timeouts` | — | won't: disabling budgets reopens the archive-bomb and hung-remote classes fixed in #810 |
| `--blast-radius`, `--access-map` | `--blast-radius` | done |
| `--audit-log` | `--audit-trail` | done |
| `--view-report*` | `view` | done |
| `--tls-mode`, `--ignore-certs` | — | won't: verification always uses system trust |
| `--user-agent-suffix` | — | gap |
| `--config` (`kingfisher.yaml`) | `.pleno-dlp-allowlist` discovery only | gap |
| `--quiet`, `--verbose`, `--color`, `--progress` | `--quiet` | done |
| `--warnings-as-errors` | `--fail-on-coverage=any` | done |

## Source-specific flags

| kingfisher | pleno-dlp | Status |
|---|---|---|
| GitHub `--user`, `--organization`, `--all-organizations`, `--exclude`, `--repo-type`, `--include-gists` | `--org`, `--user`, `--repo`, `--exclude-repo`, `--include-forks/--include-archived`, `--gist` | done |
| GitHub `--public-events`, `--event-lookback-hours` | `--include-user-events`, `--event-lookback-hours` | done |
| GitLab `--group`, `--user`, `--include-subgroups`, `--include-snippets` | `--group`, `--user`, `--project`, `--include-snippets` | done |
| Bitbucket `--workspace`, `--project`, `--user`, `--include-snippets` | `--workspace`, `--repo`, snippets | done |
| Azure `--organization`, `--project`, `--all-projects` | `scan azure-devops` | done |
| Hugging Face `--model`, `--dataset`, `--space`, `--bucket`, `--user`, `--organization` | `--org`, `--user`, `--bucket`, `--repo`, `--repo-types` | done |
| Slack query, files | `--channel` messages + attached files, `--query` (search.messages + search.files), `--max-results` | done |
| Teams `--teams-query` | `scan teams` | done |
| Jira `--jql`, `--max-results`, `--include-comments`, `--include-changelog` | `--jql`, `--project`, `--max-results`, comments (always, fully paged), `--include-changelog` | done |
| Confluence `--cql` | `scan confluence` | done |
| Postman workspaces/collections/environments/mocks | `scan postman` | done |
| S3 `--role-arn`, `--profile`, `--prefix`; GCS `--service-account`; Azure Blob container | `scan s3/gcs/azure-blob` | done |
| Docker `--docker-image`, `--docker-archive` | `scan docker-image` | done |

## Alerts

| kingfisher | pleno-dlp | Status |
|---|---|---|
| `--alert-webhook`, `--alert-dry-run` | same | done |
| `--alert-min-confidence` | `--alert-min-severity` | done |
| `--alert-format slack/teams/discord/mattermost/googlechat/generic` | `--alert-format` (default `auto`, inferred from host) | done |
| `--alert-on`, `--alert-finding-filter`, `--alert-detail`, `--alert-prevent-empty`, `--alert-report-url` | same (`--alert-prevent-empty` defaults to true) | done |
| `--alert-include-secret` | — | won't: alerts carry redacted findings only |

pleno-dlp-only capabilities (PII detection, stdin/diff scanning, SaaS
connectors such as Notion, Datadog, Splunk, BigQuery, Redash, CircleCI,
incremental state, the C ABI and bindings, crash telemetry) are listed in
`README.md` and are not repeated here.
