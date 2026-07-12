# GitHub full-history scanning

The GitHub connector scans the **full commit history** of every enumerated
repository. There is a single scan mode.

## How it works

For each enumerated repository the connector performs a
single mirror clone over git smart-HTTP and then walks **every commit reachable
from every branch** locally, diffing each commit against its first parent and
emitting added text per changed file and commit. Text added to files over
1 MiB is split into bounded 1 MiB chunks with overlap; modifications use a
native streaming diff.

```sh
pleno-dlp scan github --repo acme/widget
pleno-dlp scan github --org acme
```

REST is
used only for repository enumeration and, optionally, the comments surface.

Coverage: HEAD plus all `refs/heads/` and `refs/remotes/` refs.

## Comments

`--include-comments` scans issue comments and pull-request review comments.
Comments are always fetched over REST. `--comments-timeframe-days N` adds a
GitHub `since` bound to both comment surfaces; `0` (the default) scans all
comments. A timeframe reduces REST and scan cost but excludes
older comments, including on the first run.

## Issues and pull requests

Issue and pull-request descriptions are explicit, independent surfaces:

- `--include-issues` scans each issue title and body.
- `--include-pull-requests` scans each pull-request title and body.
- `--include-comments` continues to mean comments only; it enables neither
  title/body surface.
- `--collaboration-timeframe-days N` limits issue/PR entities by `updated_at`;
  `0` (default) performs the full backfill.

Title and body are emitted as separate chunks with metadata fields `entity`
(`issue` or `pull_request`), `number`, and `part` (`title` or `body`). Their
incremental cursors retain each entity's `updated_at`, so an unchanged body is
not re-emitted. Issue pagination uses GitHub's server-side `since` filter; the
pull-request REST API has no equivalent, so its timeframe is enforced against
each returned `updated_at`. All requests use the connector's shared
rate-limit/retry client.

## Wikis

`--include-wikis` is opt-in. For each enumerated repository it schedules a
separate `repository-wiki:<owner>/<repo>` source unit and clones
`<repo>.wiki.git` with the same PAT or concurrency-safe GitHub App token used
for the main repository. Public and Enterprise clone hosts follow the same
`--api-base` derivation rules.

Wiki ref heads and policy are stored under the independent `repository-wiki`
incremental-state namespace. Findings retain the parent `owner/repo`, carry
`entity=wiki` and `part=page`, and link to the repository's clickable `/wiki/`
page. Repositories reporting `has_wiki=false`, and enabled wikis whose Git
repository is still absent, are nonfatal `wiki-disabled` / `wiki-missing`
skips. Authentication, network, and walk failures remain structured degraded
coverage. Wiki and main-history units share the bounded `--repo-concurrency`
window.

## Gists

Gists are off by default and never inherit organisation membership. The initial
privacy boundary has only two explicit scopes:

- repeatable `--gist <URL-or-ID>` for selected gists;
- `--include-authenticated-gists` for gists visible from `GET /gists` to the
  authenticated identity.

`--include-gist-comments` is a separate opt-in because comments add API cost
and PII-heavy user content. A classic PAT needs the `gist` scope for secret gists; fine-grained
tokens and GitHub App installations can only return resources granted to that
identity, and insufficient access is degraded coverage rather than “missing.”

Gist Git content and comments use independent `gist-history:<id>` and
`gist-comments:<id>` units/state namespaces under the same bounded
`--repo-concurrency` lifecycle. Public GitHub clones derive as
`https://gist.github.com/<id>.git`; Enterprise scans prefer the API-provided
`git_pull_url`, with `<enterprise>/gist/<id>.git` as the deterministic fallback.
Explicitly missing gists, authentication failures, and network failures remain
distinguishable through structured source degradation.

## Repository scope

Organisation scans preserve the historical full scope by default: forks and
archived repositories are included, member-owned repositories are not. Scope
can be made explicit with repeatable owner/name globs:

```sh
pleno-dlp scan github --org acme \
  --include-repo 'acme/*' --exclude-repo '*/legacy-*' \
  --include-forks=false --include-archived=false \
  --expand-members --repo-concurrency 4
```

Include globs form an allowlist (no include glob means all); exclude globs win.
Member expansion enumerates each visible organisation member's owned
repositories and deduplicates repositories already returned by the org. Fork,
archived, glob, and duplicate exclusions are reported separately in completion
statistics. Filtering happens before source units are scheduled, so excluded
repositories consume no clone worker and do not disturb retained incremental
state for repositories that remain in scope.

## Commit metadata and notes

`--include-commit-metadata` adds one `commit:metadata` unit per commit with
the full commit message, author and committer identities, and git notes. It is
off by default because identity email addresses are expected PII and would be
noisy when `--pii-engine` is enabled. The same explicit flag and default apply
to `scan git` and `scan github`. GitHub clones mirror `refs/notes/*`, and
metadata findings link to the commit (there is no synthetic blob path).
Native git is required to enumerate notes; on git-less hosts commit messages
and identities still scan, while notes are unavailable. Large modification
streaming also requires native git and fails visibly if it is unavailable.

## Binary and archive history

Binary history remains excluded by default. `--include-git-archives` expands
ZIP, TAR, gzip, and bzip2 blobs; `--include-git-binaries` scans other binary
bytes. Both are opt-in. Defaults are 10 MiB compressed/raw and per entry,
50 MiB total expanded, 1,000 files, depth 3, and 5 seconds per archive.
Override them with the `--git-artifact-max-bytes`,
`--git-archive-max-expanded-bytes`, `--git-archive-max-files`,
`--git-archive-max-depth`, and `--git-archive-timeout` flags. Budget breaches
are reported as incomplete scans. See ADR 0004.

## Authentication

`--token` (or `GITHUB_TOKEN`), or GitHub App credentials. The same token is
reused for REST (`Authorization: Bearer <token>`) and for clones (HTTP Basic
`x-access-token:<token>`, which works for both PATs and App installation
tokens).

## GitHub Enterprise / clone-URL derivation

The clone host is derived from `--api-base`:

| `api_base`                        | clone URL                                |
| --------------------------------- | ---------------------------------------- |
| `https://api.github.com` (default)| `https://github.com/<owner>/<repo>.git`  |
| `https://ghe.example/api/v3`      | `https://ghe.example/<owner>/<repo>.git` |
| `https://git.example`             | `https://git.example/<owner>/<repo>.git` |

The `/api/v3` REST suffix is stripped; the remaining prefix is used as the web
host for both clones and blob deep-links
(`https://<host>/<owner>/<repo>/blob/<commit>/<path>#L<line>`).

An advanced/test-only `clone_url_template` config key overrides the derivation
entirely (placeholders `{owner}`/`{repo}`; a value without a scheme is treated
as a local filesystem path, which the clone supports directly).

## API-call accounting

| Surface | Default | Cost |
| --- | --- | --- |
| Repository enumeration | on | 1 repo request or paginated org requests |
| Main Git history | on | 1 clone/repo, 0 REST calls |
| Forks / archived repos | included | clone cost when selected |
| Member expansion | off | member pages plus each member's repo pages |
| Comments | off | issue-comment and review-comment REST pagination |
| Issue title/body | off | issue REST pagination |
| Pull-request title/body | off | pull REST pagination; ordered timeframe early-stop |
| Wiki history | off | at most 1 additional clone/repo, 0 REST content calls |
| Explicit/authenticated gists | off | gist REST lookup/list plus 1 clone/gist |
| Gist comments | off | REST pagination per selected gist |
| Commit metadata / notes | off | no REST; notes travel in the mirror clone |
| Git archives / binaries | off | no REST; bounded local expansion/scanning |

## Incremental rescans

With `--incremental` (state file set via `--incremental-state`, default
`.pleno-dlp-incremental.json`), the connector persists per-repo incremental
state recording each ref's head
sha. A rerun seeds the walk's stop-set from those heads so only commits added
since the last scan are emitted (a commit reachable from a previously recorded
head is never re-emitted, even across branches). Legacy tree-mode state written
by pre-removal builds is ignored once (one full rescan), then replaced with
history state.

The state also records the repo's `pushed_at` as observed at enumeration time.
When an `--incremental` rerun reports the same `pushed_at` **and the persisted history-policy
fingerprint still matches**, the main clone and walk are skipped and prior
state is carried forward. Enabling metadata/artifact surfaces or changing their
budgets changes that fingerprint and forces the required rescan. On a large org
where most repos see no pushes between daily runs, this removes most of the
clone traffic. The `--include-comments` pass still runs for skipped repos,
since issue/PR comments move without touching `pushed_at`. A push racing the
scan lands after the recorded timestamp, so the next run picks it up with a
forced re-walk; it is never missed.

State is namespaced by surface: `repository-history`, `repository-wiki`,
`gist-history`, and `gist-comments`. Main repositories, wikis, and gists keep
independent ref heads and policy fingerprints.

The reproducible selected-defaults large-org measurement, including wall time,
peak RSS, actual clone bytes, API calls, and findings, is recorded in
[`docs/github-large-org-benchmark.md`](../github-large-org-benchmark.md).

## Partial coverage and exit policy

A clone, history walk, or comment failure for one repository does not discard
findings from repositories that completed. The connector commits successful
unit state in stable owner/name order; a failed code unit retains its previous
valid checkpoint (or has no checkpoint on its first failure), while a failed
comment pass retains the new code heads and the previous comment cursors. The
mixed state is atomically flushed before exit and is safe to resume.

Partial coverage exits non-zero with a structured `engine.DegradedError`
(`FailureSource`, source identity `repository-history:<owner>/<repo>`). The CLI
still flushes JSON/SARIF/table findings, then writes a machine-readable stderr
line such as:

```text
coverage: status=degraded failures=1 source=1 archive=0 detector=0
```

Coverage failure takes precedence over the finding-severity exit gate.
