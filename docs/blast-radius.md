# Blast-radius mapping

Blast-radius mapping resolves a confirmed credential into the identity it
authenticates as, the permissions it holds, and the resources it can reach.
It answers three triage questions: who is this credential, what can it reach,
and which permissions make it urgent.

Mapping performs additional authenticated requests against the provider. Run
it only against accounts you are authorized to inspect.

## Usage

During a scan, `--blast-radius` maps every verified finding from a supported
detector. The result is attached to the finding:

| `extra_data` key | Meaning |
|---|---|
| `blast_radius_map` | JSON `AccessMap` (schema below) |
| `blast_radius_privileged` | `true` / `false` |
| `blast_radius` | set to `true` when the map is privileged, so `--blast-radius-only` keeps the finding |
| `blast_radius_error` | provider error when mapping failed (no response body is included) |

`--blast-radius` is ignored with `--no-verify`, because only verified findings
are mapped.

The standalone command maps one credential and prints JSON:

```sh
pleno-dlp blast-radius github token.txt
echo "$GITLAB_TOKEN" | pleno-dlp blast-radius gitlab
pleno-dlp blast-radius gcp service-account.json
pleno-dlp blast-radius aws creds.json   # {"access_key_id","secret_access_key","session_token"?}
```

`access-map` is an alias of `blast-radius`.

## Providers

| Provider | Detector | Identity | Permissions | Resources |
|---|---|---|---|---|
| aws | `aws` | STS GetCallerIdentity | attached, inline, and group policy names (IAM users) | IAM policies and groups |
| gcp | `gcp_service_account` | key `client_email` | sampled `testIamPermissions` | visible projects |
| github | `github` | `GET /user` | `X-OAuth-Scopes` | organizations, repositories (role per repository) |
| gitlab | `gitlab` | `GET /api/v4/user` | `personal_access_tokens/self` scopes | member projects (access level) |
| slack | `slack_bot_token` | `auth.test` | `X-OAuth-Scopes` | workspace |
| openai | `OpenAI` | `GET /v1/me` | — | organizations (role), projects (admin keys) |
| anthropic | `Anthropic` | — (admin keys flagged privileged) | — | models, workspaces (admin keys) |
| huggingface | `HuggingFace` | `GET /api/whoami-v2` | token role | organizations (role) |
| buildkite | `Buildkite` | `GET /v2/user` | `/v2/access-token` scopes | organizations |
| harness | `Harness` | `currentUser` | — (admin flag) | accounts |
| gitea | `Gitea` | `GET /api/v1/user` | — (`is_admin`) | organizations, repositories (role) |
| bitbucket | `BitbucketCloud` | `GET /2.0/user` | `X-OAuth-Scopes` | workspaces, repositories (permission) |
| digitalocean | `DigitalOcean` | `GET /v2/account` | — | projects, droplets |
| sendgrid | `SendGrid` | `/v3/user/username` | `/v3/scopes` | — |
| stripe | `Stripe` | `GET /v1/account` | — (`sk_live_` privileged) | — |
| circleci | `CircleCI` | `GET /api/v2/me` | — | collaborations |
| terraformcloud | `TerraformCloud` | `account/details` | — | organizations (can-update/destroy) |
| jira | `Jira`, `Atlassian` | `myself` | `mypermissions` | projects |
| confluence | `Confluence` | `user/current` | — | spaces |
| pinecone | `Pinecone` | — | — | indexes |
| asana | `Asana` | `users/me` | — | workspaces |
| fastly | `Fastly` | `current_user` | `/tokens/self` scopes | — |

The providers from openai onward are table-driven `spec.Spec` values in
`pkg/blastradius/spec`. GitHub, GitLab and Gitea accept
`{"token","api_endpoint"}` for self-hosted instances; Gitea, Jira and
Confluence require `api_endpoint` (an `https` URL). Jira/Confluence take
`email` for basic auth, and Bitbucket app passwords take `username`.

Every listing follows provider pagination (Link header, `next` URL field,
page or offset parameters) up to 1000 items per resource type; reaching the
cap is recorded in `limitations`. Pagination links that leave the API origin
are never followed, so credentials are not sent cross-origin.

A registry memoizes mappings per credential for one scan run (keyed by a
SHA-256 of the credential, never the raw value) and runs at most
`blastradius.DefaultConcurrency` (4) mappings at once.

## Schema `pleno-dlp.access-map/v1`

```json
{
  "schema": "pleno-dlp.access-map/v1",
  "provider": "github",
  "identity": {"id": "1", "name": "octo", "type": "user", "account": ""},
  "permissions": ["repo"],
  "resources": [{"type": "repository", "name": "acme/app", "permissions": ["push", "pull"]}],
  "privileged": true,
  "limitations": ["repository listing capped at 1000"]
}
```

`permissions`, `resources`, and `limitations` are always arrays. A non-empty
`limitations` list proves the view is incomplete; an empty list does not prove
it is complete.

## Extending

A provider implements `detectors.AccessMapper` (beside `detectors.Verifier`)
under `pkg/blastradius/<provider>/` and is registered in
`blastradius.Default()`. Providers that fit "identity endpoint plus
paginated listings" should be a `spec.Spec` entry in
`pkg/blastradius/spec/providers.go` instead of a new package. Tests must use `httptest` servers; no test may reach a
live provider.
