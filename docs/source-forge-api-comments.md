# Forge API comment sources

Forge API comment sources scan review and discussion text that is not
present in normal Git history. They do not clone repository contents.
Use `pleno-dlp scan git` or `pleno-dlp scan filesystem` for source
blobs.

All commands inherit the regular scan flags, including `--format`,
`--verify`, `--include-detectors`, `--exclude-detectors`, and
`--fail-on`.

## Implemented providers

| Provider | Implemented scope | Required auth/config | Reference |
|---|---|---|---|
| `forgejo` | repository issue comments through the Gitea-compatible API | `--repo owner/name`, `--api-base`, `--token` or `FORGEJO_TOKEN` | [Forgejo API compatibility](https://forgejo.org/docs/latest/user/api-usage/), [Gitea issue comments API](https://docs.gitea.com/api/1.20/#tag/issue/operation/issueListIssueComments) |
| `gitea` | repository issue comments | `--repo owner/name`, `--api-base`, `--token` or `GITEA_TOKEN` | [Gitea issue comments API](https://docs.gitea.com/api/1.20/#tag/issue/operation/issueListIssueComments) |
| `gogs` | repository issue comments through the Gitea/Gogs v1 shape | `--repo owner/name`, `--api-base`, `--token` or `GOGS_TOKEN` | [Gogs API reference](https://gogs.io/api-reference) |
| `gitbucket` | repository issue comments through the GitHub-like repository comments shape | `--repo owner/name`, `--api-base`, `--token` or `GITBUCKET_TOKEN` | TBD: public endpoint reference is incomplete; implementation uses the GitHub-compatible `/api/v3/repos/{owner}/{repo}/issues/comments` shape |
| `codeberg` | repository issue comments through the Gitea-compatible API | `--repo owner/name`, optional `--api-base`, `--token` or `CODEBERG_TOKEN` | [Codeberg API base](https://codeberg.org/api/swagger), [Gitea issue comments API](https://docs.gitea.com/api/1.20/#tag/issue/operation/issueListIssueComments) |
| `onedev` | issue descriptions/comments and pull request descriptions/comments | `--api-base`, `--token` or `ONEDEV_TOKEN`, `--project-id` or `--repo` | [OneDev IssueResource](https://github.com/theonedev/onedev/blob/main/server-core/src/main/java/io/onedev/server/rest/resource/IssueResource.java), [OneDev PullRequestResource](https://github.com/theonedev/onedev/blob/main/server-core/src/main/java/io/onedev/server/rest/resource/PullRequestResource.java) |
| `codebase` | ticket notes and merge request comments | `--repo project/repository`, `--account`, `--username`, `--token` or `CODEBASE_API_KEY` | [Codebase auth](https://support.codebasehq.com/kb), [ticket notes](https://support.codebasehq.com/kb/tickets-and-milestones/updating-tickets), [merge requests](https://support.codebasehq.com/kb/repositories/merge-requests) |
| `pagure` | issue descriptions/comments and pull request descriptions/comments | `--repo`, optional `--api-base`, optional `--token` or `PAGURE_TOKEN` | [Pagure API entrypoint](https://docs.pagure.org/pagure/usage/#pagure-api), [`/api/0` on pagure.io](https://pagure.io/api/0/) |

## Examples

```sh
pleno-dlp scan codeberg --repo acme/widget

pleno-dlp scan forgejo \
  --api-base https://forgejo.example.com/api/v1 \
  --repo acme/widget

pleno-dlp scan onedev \
  --api-base https://onedev.example.com/~api \
  --project-id 123 \
  --repo 123

pleno-dlp scan codebase \
  --repo widgets/app \
  --account acme \
  --username alice \
  --token "$CODEBASE_API_KEY"

pleno-dlp scan pagure --repo pagure
```

## API contracts

Gitea-compatible connectors read repository issue comments from the
provider REST API: `/repos/{owner}/{repo}/issues/comments`. Forgejo
and Codeberg expose the Gitea API shape; Gogs follows the same broad
v1 shape; GitBucket is handled through its GitHub-like repository
comments endpoint.

OneDev uses the REST resources exposed under the configured API base:
`/issues`, `/issues/{id}/comments`, `/pulls`, and
`/pulls/{id}/comments`. The command filters returned issues and pull
requests to the configured project id/path/name.

Codebase uses the XML API at `https://api3.codebasehq.com` by default.
It reads ticket notes via `/project/tickets/{ticket_id}/notes` and
merge request comments by listing merge requests and fetching each
`/project/repository/merge_requests/{id}` record.

Pagure uses the `/api/0` API. It reads issue and pull request pages
from `/api/0/<repo>/issues` and `/api/0/<repo>/pull-requests`; both
responses include the discussion fields scanned by this source.

## TBD / out of scope

The surfaces below are intentionally not part of the current connector
scope. Add them as separate connector changes once their provider API
contracts are confirmed and the emitted metadata shape is clear.

| Provider | TBD surface | Reason |
|---|---|---|
| `forgejo`, `gitea`, `gogs`, `gitbucket`, `codeberg` | pull request review comments / inline diff comments | Current implementation scans repository issue comments only. Inline review comments have provider-specific shapes and line metadata. |
| `onedev` | standalone code comments from `/code-comments/{id}` | The public resource exposes ID-based retrieval, but this connector does not yet have a bounded list/query source for code comment IDs. |
| `codebase` | discussion posts and repository commit comments | Current implementation covers ticket notes and merge request comments only. Add once the relevant API endpoints and pagination are pinned. |
| `pagure` | metadata git repositories for issues and pull requests | This connector is API-only. Pagure also exposes metadata through git repositories, but that is a separate source mode and should not be mixed with API scanning. |
