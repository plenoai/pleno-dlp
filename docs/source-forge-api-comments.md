# Forge API comment sources

Forge API comment sources scan issue/ticket and pull-request
discussion text, without cloning repository contents.

## Implemented providers

| Provider | Implemented scope | Required auth/config | Reference |
|---|---|---|---|
| `forgejo` | repository issue comments | `--repo owner/name`, `--api-base`, `--token` or `FORGEJO_TOKEN` | [Forgejo API compatibility](https://forgejo.org/docs/latest/user/api-usage/), [Gitea issue comments API](https://docs.gitea.com/api/1.20/#tag/issue/operation/issueListIssueComments) |
| `gitea` | repository issue comments | `--repo owner/name`, `--api-base`, `--token` or `GITEA_TOKEN` | [Gitea issue comments API](https://docs.gitea.com/api/1.20/#tag/issue/operation/issueListIssueComments) |
| `gogs` | repository issue comments | `--repo owner/name`, `--api-base`, `--token` or `GOGS_TOKEN` | [Gogs API reference](https://gogs.io/api-reference) |
| `gitbucket` | repository issue comments | `--repo owner/name`, `--api-base`, `--token` or `GITBUCKET_TOKEN` | No complete public endpoint reference. The connector requests the GitHub-compatible `/repos/{owner}/{repo}/issues/comments` path, so point `--api-base` at GitBucket's API root (e.g. `https://gitbucket.example.com/api/v3`) |
| `codeberg` | repository issue comments | `--repo owner/name`, optional `--api-base`, `--token` or `CODEBERG_TOKEN` | [Codeberg API base](https://codeberg.org/api/swagger), [Gitea issue comments API](https://docs.gitea.com/api/1.20/#tag/issue/operation/issueListIssueComments) |
| `onedev` | issue descriptions/comments and pull request descriptions/comments | `--api-base`, `--token` or `ONEDEV_TOKEN`, `--repo` (project id, path, or name; `--project-id` optionally overrides it) | [OneDev IssueResource](https://github.com/theonedev/onedev/blob/main/server-core/src/main/java/io/onedev/server/rest/resource/IssueResource.java), [OneDev PullRequestResource](https://github.com/theonedev/onedev/blob/main/server-core/src/main/java/io/onedev/server/rest/resource/PullRequestResource.java) |
| `codebase` | ticket notes and merge request comments | `--repo project/repository`, `--account`, `--username`, `--token` or `CODEBASE_API_KEY` | [Codebase auth](https://support.codebasehq.com/kb), [ticket notes](https://support.codebasehq.com/kb/tickets-and-milestones/updating-tickets), [merge requests](https://support.codebasehq.com/kb/repositories/merge-requests) |
| `pagure` | issue descriptions/comments and pull request descriptions/comments | `--repo`, optional `--api-base`, optional `--token` or `PAGURE_TOKEN` | [Pagure API entrypoint](https://docs.pagure.org/pagure/usage/#pagure-api), [`/api/0` on pagure.io](https://pagure.io/api/0/) |

## Examples

```sh
CODEBERG_TOKEN=... pleno-dlp scan codeberg --repo acme/widget

FORGEJO_TOKEN=... pleno-dlp scan forgejo \
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
provider REST API: `/repos/{owner}/{repo}/issues/comments`.

For OneDev, the REST resources under the configured API base are
`/issues`, `/issues/{id}/comments`, `/pulls`, and
`/pulls/{id}/comments`. The command filters returned issues and pull
requests to the configured project id/path/name.

Codebase defaults to the XML API at `https://api3.codebasehq.com`,
reading ticket notes via `/project/tickets/{ticket_id}/notes` and
merge request comments by listing merge requests and fetching each
`/project/repository/merge_requests/{id}` record.

Pagure serves issue and pull request pages at `/api/0/<repo>/issues`
and `/api/0/<repo>/pull-requests`; both responses include the
discussion fields scanned by this source.

## TBD / out of scope

| Provider | TBD surface | Reason |
|---|---|---|
| `forgejo`, `gitea`, `gogs`, `gitbucket`, `codeberg` | pull request review comments / inline diff comments | Inline review comments have provider-specific shapes and line metadata. |
| `onedev` | standalone code comments from `/code-comments/{id}` | The public resource is retrievable only by ID, and no bounded list or query supplies the code comment IDs. |
| `codebase` | discussion posts and repository commit comments | The relevant API endpoints and their pagination are unconfirmed. |
| `pagure` | metadata git repositories for issues and pull requests | This connector is API-only; Pagure's metadata git repositories are a separate source mode. |
