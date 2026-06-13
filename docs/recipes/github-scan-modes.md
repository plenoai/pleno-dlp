# GitHub scan modes

The GitHub connector supports two scan modes, selected with `--scan-mode`
(connector config key `scan_mode`).

## `history` (default) — full commit history

Trufflehog parity. For each enumerated repository the connector performs a
single bare clone over git smart-HTTP and then walks **every commit reachable
from every branch** locally, diffing each commit against its first parent and
emitting one chunk per changed text file per commit.

```sh
pleno-dlp scan github --repo acme/widget            # history is the default
pleno-dlp scan github --org acme --scan-mode history
```

Why clone-based: git smart-HTTP does **not** consume the GitHub REST rate
limit, so the per-repo REST cost of a full-history scan is **zero**. REST is
used only for repository enumeration and, optionally, the comments surface.

Coverage: HEAD plus all `refs/heads/` and `refs/remotes/` refs. A secret that
was committed to a side branch (or rewritten away on the default branch but
still reachable from another ref) is found here but **not** in `tree` mode.

## `tree` — default-branch snapshot via REST

The original behaviour: list the default-branch tree and fetch each blob via
the REST git-trees / git-blobs API. Cheaper when you only care about the
current state of the default branch and want to avoid clones.

```sh
pleno-dlp scan github --org acme --scan-mode tree
```

## Comments

`--include-comments` scans issue comments and pull-request review comments in
**both** modes. Comments are always fetched over REST.

## Authentication

`--token` (or `GITHUB_TOKEN`), or GitHub App credentials. The same token is
reused for REST (`Authorization: Bearer <token>`) and for clones in history
mode (HTTP Basic `x-access-token:<token>`, which works for both PATs and App
installation tokens).

## GitHub Enterprise / clone-URL derivation

History mode derives the clone host from `--api-base`:

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

| Surface                         | history mode            | tree mode                         |
| ------------------------------- | ----------------------- | --------------------------------- |
| Repo enumeration                | 1 (repo) / N (org page) | 1 (repo) / N (org page)           |
| Per-repo code scan              | 0 REST (1 clone)        | 1 tree + 1 blob per changed blob  |
| Per-repo fingerprint            | 0 REST (1 ref advert.)  | 1 tree call                       |
| `--include-comments`            | REST pagination         | REST pagination                   |

## Incremental rescans

Both modes persist per-repo incremental state. In history mode the state
records each ref's head sha; a rerun seeds the walk's stop-set from those heads
so only commits added since the last scan are emitted (a commit reachable from
a previously recorded head is never re-emitted, even across branches). Legacy
tree-mode state encountered by a history-mode run is ignored once (one full
scan), then replaced with history state.
