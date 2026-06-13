# GitHub full-history scanning

The GitHub connector scans the **full commit history** of every enumerated
repository. There is a single scan mode — there is no flag or config key to
select it.

## How it works

Trufflehog parity. For each enumerated repository the connector performs a
single bare clone over git smart-HTTP and then walks **every commit reachable
from every branch** locally, diffing each commit against its first parent and
emitting one chunk per changed text file per commit.

```sh
pleno-dlp scan github --repo acme/widget
pleno-dlp scan github --org acme
```

Why clone-based: git smart-HTTP does **not** consume the GitHub REST rate
limit, so the per-repo REST cost of a full-history scan is **zero**. REST is
used only for repository enumeration and, optionally, the comments surface.

Coverage: HEAD plus all `refs/heads/` and `refs/remotes/` refs. A secret that
was committed to a side branch — or rewritten away on the default branch but
still reachable from another ref — is found.

## Comments

`--include-comments` scans issue comments and pull-request review comments.
Comments are always fetched over REST.

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

| Surface                         | cost                    |
| ------------------------------- | ----------------------- |
| Repo enumeration                | 1 (repo) / N (org page) |
| Per-repo code scan              | 0 REST (1 clone)        |
| Per-repo fingerprint            | 0 REST (1 ref advert.)  |
| `--include-comments`            | REST pagination         |

## Incremental rescans

The connector persists per-repo incremental state recording each ref's head
sha. A rerun seeds the walk's stop-set from those heads so only commits added
since the last scan are emitted (a commit reachable from a previously recorded
head is never re-emitted, even across branches). Legacy tree-mode state written
by pre-removal builds is ignored once (one full rescan), then replaced with
history state.
