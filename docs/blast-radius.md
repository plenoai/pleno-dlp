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
| aws | `aws` | STS GetCallerIdentity; key last-used (`activity`) | policy names plus `allow:`/`deny:` actions evaluated from attached, inline, and group policy documents (IAM users and assumed roles) | IAM policies/groups, `aws_resource` (actions per resource ARN), `assumable_role` (trust path) |
| gcp | `gcp_service_account` | key `client_email` | sampled `testIamPermissions` on projects, folders, organizations | projects, folder/organization ancestors, `impersonable_service_account` |
| github | `github` | `GET /user` | `X-OAuth-Scopes` | organizations, repositories (role per repository) |
| gitlab | `gitlab` | `GET /api/v4/user` | `personal_access_tokens/self` scopes | member projects (access level) |
| slack | `slack_bot_token` | `auth.test` | `X-OAuth-Scopes` | workspace |
| azure | `AzureAD`, `AzureApp` | Entra client-credentials token; `servicePrincipals(appId=)` | Graph app roles (`graph:`), ARM role assignments (`rbac:`) | directory roles/groups, subscriptions (roles) |
| azure-storage | `AzureStorageKey` | account name | `storage:*` (shared key = full access) | blob containers |
| alibaba | — (standalone) | STS `GetCallerIdentity` | RAM user policy names | RAM policies |
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
| airtable | `Airtable` | `meta/whoami` | token scopes | bases (permission level) |
| hubspot | `HubSpot` | `account-info/v3/details` | — | — |
| square | `Square` | `merchants/me` | — | locations |
| brevo | `Brevo` | `/v3/account` | — (full account) | — |
| zendesk | `Zendesk` | `users/me.json` (api_endpoint + email) | user role | — |
| azure-devops | `AzureDevOps` | `profiles/me` | — | — |
| shopify | `Shopify` | — (api_endpoint shop URL) | `access_scopes` | — |
| algolia | `Algolia` (`application_id`) | `/1/keys/{key}` | key ACLs | indexes, index restrictions |
| artifactory | `JFrog` | `api/security/current` (api_endpoint); `access/api/v1/tokens/me` activity | groups (admin flag) | repositories |
| xray | — (standalone) | ping (api_endpoint); token activity | — | Xray repositories, policies |
| auth0 | `Auth0` (`client_id`, `domain`) | client-credentials grant | granted Management API scopes | clients, resource servers |
| ibmcloud | `IBMCloud` | IAM API-key grant; `apikeys/details`; `last_authn` activity | — | resource instances |
| monday | `Monday` | GraphQL `me` | — (`is_admin`) | teams, workspaces, boards |
| wandb | `Wandb` | GraphQL `viewer` | — (`admin`) | teams |
| paypal | `PayPal` (client id + secret) | client-credentials grant | granted OAuth scopes | merchant (userinfo) |
| plaid | `Plaid` (client id + secret) | `/institutions/get` | — (production privileged) | institutions |
| salesforce | — (standalone, api_endpoint instance URL) | `oauth2/userinfo` | — | permission sets (ModifyAllData, ManageUsers, AuthorApex, ...), sObjects |
| microsoft-teams | — (standalone webhook URL) | parsed from the URL, no request | `channel:post_message` | channel webhook |
| postgres | `Postgres` (URI) | `current_user` role attributes | superuser/createrole/createdb/replication/bypassrls | role memberships, databases (owner/create/connect/temp) |
| mysql | `MySQL` (URI) | `CURRENT_USER()` | global grants | `SHOW GRANTS` entries, databases |
| mongodb | `MongoDB` (URI) | `connectionStatus` | roles | roles, authorized databases |

AWS evaluation is an over-approximation: statement conditions, permission
boundaries, SCPs and resource policies are not applied, and `NotAction` is
recorded rather than expanded (each listed in `limitations`). A map is
privileged when the effective allow covers `*`, `iam:*`, or an escalation
action (`iam:PassRole`, `iam:CreateAccessKey`, `iam:Put*Policy`,
`sts:AssumeRole`, ...) on `*`. `assumable_role` entries are roles whose trust
policy names the caller directly (`trust:direct`), or its account or `*`
while the identity policy allows `sts:AssumeRole` on that role
(`trust:account`/`trust:any`), plus identity-policy targets whose trust policy
could not be read (`identity-policy (trust unverified)`).

GCP follows `getAncestry` from each visible project and probes the folder and
organization ancestors, whose bindings inherit to every descendant; it then
probes up to 200 visible service accounts for `getAccessToken`, `signJwt`,
`signBlob`, `implicitDelegation`, `actAs`, and key creation.

`activity` (`{"last_used","service","region"}`) is present when the provider
reports credential last use: AWS `GetAccessKeyLastUsed` (`service: "N/A"`
means never used), GitLab `personal_access_tokens/self`, Fastly
`/tokens/self`, HCP Terraform `authentication-tokens/{id}`, Zendesk OAuth
`tokens/current`, JFrog `access/api/v1/tokens/me` (artifactory, xray), and
IBM Cloud `apikeys/{id}?include_activity=true`. It is additive within v1.

The database mappers (postgres, mysql, mongodb) connect with the connection
URI found by the detector. Sessions are read-only (Postgres
`default_transaction_read_only=on`, MySQL `SET SESSION TRANSACTION READ
ONLY`, MongoDB `connectionStatus`/`listDatabases` only), bounded by a
10-second connect and 30-second session timeout, and refuse loopback and
documentation hosts. Driver errors are redacted of the password.

Credentials without a scan-time detector pairing (salesforce, xray,
microsoft-teams) and unverified detectors (auth0) are mapped through the
standalone command. Two-part credentials accept JSON
with `token` and `secondary` fields or `id:secret` for paypal and plaid; algolia takes
`application_id`, auth0 `client_id` and `domain`, paypal and plaid an
optional `environment` (`sandbox`, `development`).

Every provider in kingfisher's `src/access_map` has a pleno-dlp mapper;
`TestKingfisherProviderParity` fails if one is removed.

The providers from openai onward are table-driven `spec.Spec` values in
`pkg/blastradius/spec`. A spec can exchange the credential for a bearer
token first (`Exchange`), issue GraphQL (`IdentityQuery`, `Listing.Query`)
or JSON POST requests, and expand the placeholders `secret`, `secondary`,
`extra.<k>` and `id` (each written in braces) into paths and bodies (each value encoded for its position; `{id}` is
restricted to identifier characters), and read `Activity`. GitHub, GitLab and Gitea accept
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
