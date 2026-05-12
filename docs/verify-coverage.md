# Verify coverage audit

This file is the source of truth for which detectors under
`pkg/detectors/<provider>/` implement live verification (call the
provider API to confirm a candidate secret), which are deliberately
shipped without verification, and which are currently regex-only with a
verifiable upstream that we just have not wired yet.

The fenced ` ```coverage-machine ` block at the end of this document is
machine-readable. `pkg/detectors/verifycoverage_test.go` walks the
registry, asserts every registered `DetectorType` appears here exactly
once, and fails CI on drift (count change, classification change, or
a registered detector missing from the doc).

Counts are pinned at the top of the machine block. Total = 600
(598 secret + 1 NER-backed PIIAnonymize detector + 1 transformer-backed
PIIOpenAIPF detector). The four legacy regex PII detectors (piiemail /
piicc / piiiban / piissn) were retired in favour of PIIAnonymize; their
DetectorType constants (PIIEmail / PIIUSSSN / PIICreditCard / PIIIBAN,
ordinals 76..79) stay pinned for wire compatibility per ADR-0002 but no
live scan emits them, so the registry / doc drift test does not list
them. PIIOpenAIPF (ADR-0004) is a sibling PII engine — opt-in via
`--pii-engine=openai-pf`, mutually exclusive with `anonymize` in v1.

## Severity model recap

`detectors.DefaultSeverity` is the contract:

| Detector class                                          | Verified  | Unverified |
|---------------------------------------------------------|-----------|------------|
| Default (every named provider unless overridden)        | Critical  | High       |
| `JWT`, `PrivateKeyPEM`, `GenericHighEntropy`            | Critical  | Medium     |
| `PIIAnonymize`, `PIIOpenAIPF`                           | (n/a)     | Medium     |

A handful of providers (`Stripe`, `MercuryBank`, `Bitwarden`, `Helcim`,
…) override their unverified severity to Critical at the detector level
because the leak surface is destructive even before verification. Those
are not enumerated here — `DefaultSeverity` is the floor; per-detector
overrides only raise it.

## (a) Verify implemented — 514 detectors

Detector type satisfies `detectors.Verifier`. The detector calls the
upstream provider and returns `(true, nil)` on success, `(false, nil)`
when the credential is rejected, and `(false, err)` only for transport
errors. Verified findings surface at `Severity = Critical`
(via `DefaultSeverity`).

Some entries in this column implement `Verify` but return
`(false, nil)` until an `apiBase` override is supplied (per-tenant or
per-region host). They satisfy the interface — the detector's `Verify`
function exists and is reachable from the engine — and are counted in
class (a). Where the host shape is structurally absent from the chunk
and no apiBase fallback is wired, the detector lives in (b) instead.

The full enumeration is in the machine block. There are 514 entries;
listing every name in prose would not add information beyond the
machine block. Spot-check examples: `AWS`, `GitHub`, `GitHubFineGrained`,
`SlackBotToken`, `OpenAI`, `Anthropic`, `Stripe`, `Datadog`, `OpenAI`,
`Coinbase` (unsigned-bearer fallback — verifies via HTTP 401 → false),
plus most batch 1–40 detectors that hit a public API host.

## (b) Unverified-by-design — 44 detectors

These detectors deliberately do not implement `Verify`. The rationale
is one of:

- **Connection-string / URL-embedded credential.** The credential is
  meaningful only against a host that lives elsewhere. Reachability is
  the user's environment, not ours, and a generic verify call would
  either be wrong or destructive.
- **Presigned URL / signed bearer.** Verification depends on
  unguessable signed-time-bound headers we cannot recreate.
- **Self-hosted, host not in chunk.** Provider runs on
  customer-controlled infrastructure (Jenkins, GoCD, Vault, etc.) so
  there is no fixed verify endpoint.
- **HMAC signing required.** Provider rejects bearer probes; verify
  needs request signing (Akamai EdgeGrid, OVH, Exoscale, …).
- **Paired credential half missing.** Provider needs a second component
  (key id, issuer id, project id) that is not co-located with the
  matched secret in the chunk.
- **Generic shape detector.** No fixed upstream provider (`JWT`,
  `GenericHighEntropy`). `PrivateKeyPEM` was previously in this list
  but is now class (a) — see the Verifier note below.
- **PII finding class.** No "is this real?" call exists — PII is
  identity, not credential, and the appropriate response is access
  control / redaction, not verification.

Severity-on-finding is High by default, Medium for `JWT`,
`PrivateKeyPEM`, `GenericHighEntropy`, `PIIAnonymize`, and `PIIOpenAIPF`.

> **PrivateKeyPEM Verifier (class a).** PEM private keys do not have a
> single upstream provider, but the public-key half can be correlated
> against Certificate Transparency logs. The detector derives the SPKI
> SHA-256 locally (the private key never leaves the host) and queries
> crt.sh `?spkisha256=<hex>` when `--verify` is set. A non-empty CT
> match marks the finding `Verified=true` and surfaces the discovered
> domains via `ExtraData["blast_radius_domains"]` — the leak's literal
> blast radius. Encrypted PEMs are also tried against an embedded
> ~250-entry passphrase wordlist; a successful unlock escalates the
> unverified severity from Medium to High. Inspired by
> trufflesecurity/driftwood.

| DetectorType            | Class    | Rationale                                                                 |
|-------------------------|----------|---------------------------------------------------------------------------|
| ActiveCampaign          | secret   | per-account host (`<account>.api-us1.com`) not in chunk                   |
| Adyen                   | secret   | environment-bound endpoints (live vs test) not in chunk                   |
| AgoraIO                 | secret   | per-app HMAC token signing required                                       |
| Akamai                  | secret   | EdgeGrid HMAC signing required, no bearer endpoint                        |
| APNs                    | secret   | only the .p8 PEM is in chunk; JWT issuance requires issuer + key_id       |
| AppStoreConnect         | secret   | only the .p8 PEM is in chunk; JWT requires issuer_id + key_id             |
| AWSS3PresignedURL       | secret   | presigned URL, signed-time-bound, no verify endpoint                      |
| AWX                     | secret   | self-hosted CI, host not in chunk                                         |
| AzureSQLConnString      | secret   | connection string, host not derivable from chunk                          |
| BackblazeB2             | secret   | explicit region+endpoint pairing required                                 |
| Bamboo                  | secret   | self-hosted CI, host not in chunk                                         |
| BasicAuth               | secret   | HTTP basic credential, host not in chunk                                  |
| ConcourseCI             | secret   | self-hosted CI, host not in chunk                                         |
| CrispChat               | secret   | paired credential — Identifier half not co-located                        |
| ElasticCloud            | secret   | per-customer host not in chunk                                            |
| Exoscale                | secret   | HMAC signing required                                                     |
| GCSSignedURL            | secret   | signed URL, signed-time-bound, no verify endpoint                         |
| GenericHighEntropy      | secret   | entropy-only shape, no fixed upstream provider                            |
| Jenkins                 | secret   | self-hosted CI, host not in chunk                                         |
| JWT                     | secret   | generic shape, issuer-dependent verification not centralizable            |
| Kafka                   | secret   | connection string, broker host not in chunk                               |
| Kubeconfig              | secret   | static config, no remote endpoint to call                                 |
| GoCD                    | secret   | self-hosted CI, host not in chunk                                         |
| MongoDB                 | secret   | connection string, host not in chunk                                      |
| MySQL                   | secret   | connection string, host not in chunk                                      |
| OVHCloud                | secret   | HMAC signing required                                                     |
| PIIAnonymize            | pii      | PII finding class — NER + regex via pleno-anonymize, no provider API to verify |
| PIIOpenAIPF             | pii      | PII finding class — MoE classifier (openai/privacy-filter), no provider-side verify path |
| PingIdentity            | secret   | per-region host (`api.pingone.{com,eu,asia,ca}`) not in chunk             |
| Postgres                | secret   | connection string, host not in chunk                                      |
| RabbitMQ                | secret   | connection string, host not in chunk                                      |
| Redis                   | secret   | connection string, host not in chunk                                      |
| RequestBin              | secret   | per-bin endpoint not in chunk                                             |
| Sinch                   | secret   | project_id half of (project_id, key) not in chunk                         |
| Smee                    | secret   | per-channel proxy URL not in chunk                                        |
| SMTP                    | secret   | connection string, SMTP host not in chunk                                 |
| SonatypeNexus           | secret   | self-hosted artifact repo, host not in chunk                              |
| SplunkHEC               | secret   | per-customer host not in chunk                                            |
| Stytch                  | secret   | environment-bound endpoints (test vs live) not in chunk                   |
| TeamCity                | secret   | self-hosted CI, host not in chunk                                         |
| UpstashRedis            | secret   | connection string with URL-embedded credential                            |
| Wasabi                  | secret   | explicit region+endpoint pairing required                                 |
| Wiz                     | secret   | tenant-specific host (`api.<tenant>.app.wiz.io`) not in chunk             |
| Zoho                    | secret   | region-specific accounts host (`accounts.zoho.<tld>`) not in chunk        |

## (c) Verifiable but not implemented — 42 detectors

These detectors regex-match but do not call upstream. The provider
*does* expose a verify-able endpoint; we have just not wired it. Each
row is a candidate for a follow-up PR that adds `Verify(ctx, secret)`.

Severity-on-finding is High (default unverified). Once `Verify` lands,
verified hits surface at Critical.

| DetectorType            | Class    | Verify path on the upstream                                               |
|-------------------------|----------|---------------------------------------------------------------------------|
| AlibabaCloud            | secret   | `GET /` STS / RAM with HMAC-SHA1 signing (sig logic; gap: signing impl)   |
| ArgoCD                  | secret   | `GET /api/v1/account` against per-deploy host (gap: apiBase override)     |
| Atlassian               | secret   | `GET /rest/api/3/myself` against `<workspace>.atlassian.net`              |
| Auth0                   | secret   | `GET /api/v2/users` against `https://<tenant>.auth0.com`                  |
| AWSSession              | secret   | `GetCallerIdentity` STS call (paired access key + secret + token)         |
| AzureAD                 | secret   | `POST /oauth2/v2.0/token` against `login.microsoftonline.com`             |
| AzureApp                | secret   | management.azure.com bearer probe; needs subscription scope               |
| AzureContainerRegistry  | secret   | `GET /v2/` registry probe — host parsed from refresh token claim          |
| BitbucketServer         | secret   | `GET /rest/api/1.0/users` against per-deploy host (gap: apiBase override) |
| Bitwarden               | secret   | `POST /identity/connect/token` for machine accounts                       |
| Bugsnag                 | secret   | `GET /user` on api.bugsnag.com                                            |
| ClickHouseCloud         | secret   | `GET /v1/services` on api.clickhouse.cloud                                |
| CloudflareR2            | secret   | `GET /` S3-compatible probe with signed-V4 against accountid.r2.cloudflarestorage.com |
| Confluence              | secret   | `GET /wiki/rest/api/user/current` against `<workspace>.atlassian.net`     |
| Databricks              | secret   | `GET /api/2.0/clusters/list` against `<workspace>.cloud.databricks.com`   |
| DatadogAppKey           | secret   | `GET /api/v1/validate` against `api.<region>.datadoghq.com`               |
| DockerHub               | secret   | `GET /v2/users/<username>/` on hub.docker.com                             |
| DroneCI                 | secret   | `GET /api/user` against per-deploy drone host                             |
| Freshdesk               | secret   | `GET /api/v2/agents/me` against `<domain>.freshdesk.com`                  |
| GCPIDToken              | secret   | `GET /tokeninfo?id_token=...` on oauth2.googleapis.com                    |
| GetStream               | secret   | `GET /api/v2/app` against api.stream-io-api.com                           |
| GitLabPipeline          | secret   | trigger token validation via `POST /trigger/pipeline` (low-impact probe)  |
| Grafana                 | secret   | `GET /api/user` against per-instance host (gap: apiBase override)         |
| Jira                    | secret   | `GET /rest/api/3/myself` against `<workspace>.atlassian.net`              |
| LaunchNotes             | secret   | `POST /public/graphql` introspection on api.launchnotes.io                |
| Looker                  | secret   | `POST /api/4.0/login` against per-instance host                           |
| Magento                 | secret   | `GET /rest/V1/customers/me` against per-store host                        |
| Modal                   | secret   | `GET /v0.1/apps` on api.modal.com (paired token id + secret)              |
| Okta                    | secret   | `GET /api/v1/users/me` against `<tenant>.okta.com`                        |
| PusherBeams             | secret   | `GET /publish_api/v1/instances/<id>/users` (paired instance + secret)     |
| SalesforceRefresh       | secret   | `POST /services/oauth2/token` with refresh_token grant                    |
| Segment                 | secret   | per-source HTTP basic against api.segment.io/v1/identify                  |
| Sentry                  | secret   | `GET /api/0/organizations/<slug>/` on sentry.io                           |
| Snowflake               | secret   | JWT keypair auth — signed assertion to `<account>.snowflakecomputing.com` |
| Spinnaker               | secret   | `GET /auth/user` against per-deploy host                                  |
| Supabase                | secret   | `GET /rest/v1/` with service-role key against `<project>.supabase.co`     |
| Tailscale               | secret   | `GET /api/v2/tailnet/<tailnet>/devices` (gap: tailnet name)               |
| TektonHub               | secret   | `GET /v1/auth/me` against per-deploy host                                 |
| TencentCloud            | secret   | TC3-HMAC-SHA256 signed call to cvm.tencentcloudapi.com (gap: signing impl) |
| Vault                   | secret   | `GET /v1/auth/token/lookup-self` against per-deploy Vault host            |
| Vonage                  | secret   | `GET /account/get-balance` (paired key+secret)                            |
| Zendesk                 | secret   | `GET /api/v2/users/me.json` against `<subdomain>.zendesk.com`             |

Several (c) entries are blocked on auth-side work that is not strictly
verification: SDK-grade HMAC signing for AlibabaCloud / TencentCloud,
mandatory `apiBase` plumbing for self-hosted-shaped providers
(BitbucketServer, ArgoCD, DroneCI, Grafana, Looker, Magento, Spinnaker,
TektonHub, Vault), and paired-credential reassembly for Vonage /
PusherBeams. Those are scoped under task #2 follow-ups, not within this
audit.

## Machine-readable block

The `coverage-machine` block below pins counts and per-detector class.
`pkg/detectors/verifycoverage_test.go` parses it and compares against
the live `detectors.All()` registry.

- `class=a` → Verify implemented (detector satisfies `detectors.Verifier`)
- `class=b` → Unverified-by-design (no Verify, deliberate)
- `class=c` → Verifiable but not implemented (gap item)

```coverage-machine
total=600
a=514
b=44
c=42
type=APNs class=b
type=AWSS3PresignedURL class=b
type=AWX class=b
type=ActiveCampaign class=b
type=Adyen class=b
type=AgoraIO class=b
type=Akamai class=b
type=AppStoreConnect class=b
type=AzureSQLConnString class=b
type=BackblazeB2 class=b
type=Bamboo class=b
type=BasicAuth class=b
type=ConcourseCI class=b
type=CrispChat class=b
type=ElasticCloud class=b
type=Exoscale class=b
type=GCSSignedURL class=b
type=GenericHighEntropy class=b
type=GoCD class=b
type=JWT class=b
type=Jenkins class=b
type=Kafka class=b
type=Kubeconfig class=b
type=MongoDB class=b
type=MySQL class=b
type=OVHCloud class=b
type=PIIAnonymize class=b
type=PIIOpenAIPF class=b
type=PingIdentity class=b
type=Postgres class=b
type=RabbitMQ class=b
type=Redis class=b
type=RequestBin class=b
type=SMTP class=b
type=Sinch class=b
type=Smee class=b
type=SonatypeNexus class=b
type=SplunkHEC class=b
type=Stytch class=b
type=TeamCity class=b
type=UpstashRedis class=b
type=Wasabi class=b
type=Wiz class=b
type=Zoho class=b
type=AWSSession class=c
type=AlibabaCloud class=c
type=ArgoCD class=c
type=Atlassian class=c
type=Auth0 class=c
type=AzureAD class=c
type=AzureApp class=c
type=AzureContainerRegistry class=c
type=BitbucketServer class=c
type=Bitwarden class=c
type=Bugsnag class=c
type=ClickHouseCloud class=c
type=CloudflareR2 class=c
type=Confluence class=c
type=Databricks class=c
type=DatadogAppKey class=c
type=DockerHub class=c
type=DroneCI class=c
type=Freshdesk class=c
type=GCPIDToken class=c
type=GetStream class=c
type=GitLabPipeline class=c
type=Grafana class=c
type=Jira class=c
type=LaunchNotes class=c
type=Looker class=c
type=Magento class=c
type=Modal class=c
type=Okta class=c
type=PusherBeams class=c
type=SalesforceRefresh class=c
type=Segment class=c
type=Sentry class=c
type=Snowflake class=c
type=Spinnaker class=c
type=Supabase class=c
type=Tailscale class=c
type=TektonHub class=c
type=TencentCloud class=c
type=Vault class=c
type=Vonage class=c
type=Zendesk class=c
```

The `class=a` membership is the open-set complement: every registered
DetectorType not listed above is in (a). The CI test enforces this —
adding a new detector without listing it as `b` or `c` here, AND
without implementing `Verify`, will fail.
