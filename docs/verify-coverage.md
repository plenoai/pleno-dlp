# Verify coverage audit

This page classifies each registered detector as verifier-backed or
unverified-by-design. The machine block is parsed by
`pkg/detectors/verifycoverage_test.go`.

Counts are pinned in the machine block. Total = 601: 599 secret
detectors, `PIIAnonymize`, and `PIIOpenAIPF`. The retired regex PII
detector constants remain reserved for wire compatibility but are not
listed because they are no longer registered.

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

## (a) Verify implemented — 551 detectors

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

The full enumeration lives in the machine block.

### Context-extraction Verify

Azure AD and Azure App detectors extract `tenant_id` from surrounding
chunk data (assignment anchors, URLs, and known Azure directory
patterns). The extracted tenant is combined with the matched
`client_id` / `client_secret` pair to attempt an OAuth2
`client_credentials` grant against
`https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`.
A `200` with a valid `access_token` marks the finding verified; a
`401` / `invalid_client` marks it unverified; transport errors are
returned as `(false, err)` per the standard Verifier contract. This
"context-extraction" pattern lets the detector verify credentials whose
host endpoint is not self-contained in the secret itself but is
recoverable from neighbouring text.

## (b) Unverified-by-design — 50 detectors

These detectors deliberately do not implement `Verify`. The rationale
is one of:

- **Connection-string / URL-embedded credential.** The credential is
  meaningful only against a host that lives elsewhere. Reachability is
  the user's environment, not ours, and a generic verify call would
  either be wrong or destructive.
- **Presigned URL / signed bearer.** Verification depends on
  unguessable signed-time-bound headers we cannot recreate.
- **Self-hosted, host not in chunk.** Provider runs on
  customer-controlled infrastructure (Jenkins, GoCD, ConcourseCI, etc.) so
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
`PrivateKeyPEM`, `GenericHighEntropy`, `PIIAnonymize`, `PIIOpenAIPF`, and
`SalesforceRefresh` (explicit override — instance URL and client credentials
absent, so the finding acknowledges the token shape without implying live access).

> **PrivateKeyPEM Verifier (class a).** PEM private keys do not have a
> single upstream provider, but the public-key half can be correlated
> against Certificate Transparency logs. The detector derives the SPKI
> SHA-256 locally (the private key never leaves the host) and queries
> crt.sh `?spkisha256=<hex>` during verification. A non-empty CT
> match marks the finding `Verified=true` and surfaces the discovered
> domains via `ExtraData["blast_radius_domains"]` — the leak's literal
> blast radius. Encrypted PEMs are also tried against an embedded
> ~250-entry passphrase wordlist; a successful unlock escalates the
> unverified severity from Medium to High. Inspired by
> trufflesecurity/driftwood.

| DetectorType            | Class    | Rationale (verify infeasible; hardening applied where noted)                  |
|-------------------------|----------|---------------------------------------------------------------------------|
| AgoraIO                 | secret   | per-app HMAC token signing required |
| Akamai                  | secret   | EdgeGrid HMAC signing required, no bearer endpoint |
| APNs                    | secret   | only the .p8 PEM is in chunk; JWT issuance requires issuer + key_id |
| AppStoreConnect         | secret   | only the .p8 PEM is in chunk; JWT requires issuer_id + key_id |
| Atlassian               | secret   | token is half of a Basic-auth credential, `<workspace>.atlassian.net` not in chunk; hardened: ATATT3 prefix anchor + entropy gate |
| Auth0                   | secret   | matched token not self-authenticating, tenant host not derivable; hardened: auth0.com context regex + signature entropy, RFC-7519/alg:none exclusion |
| AWSS3PresignedURL       | secret   | presigned URL, signed-time-bound, no verify endpoint |
| BasicAuth               | secret   | HTTP basic credential, host not in chunk |
| Bugsnag                 | secret   | matched value is project ingest key, not a /user-authorizing token; hardened: assignment anchor + hash exclusion + entropy |
| CloudflareR2            | secret   | SigV4 signing unfakeable, no signing host in chunk; hardened: entropy floor + digest-lookalike exclusion |
| ConcourseCI             | secret   | self-hosted CI, host not in chunk |
| Confluence              | secret   | token is half of Basic-auth, workspace host not in chunk; hardened: ATATT3 prefix anchor + entropy |
| CrispChat               | secret   | paired credential — Identifier half not co-located |
| DatadogAppKey           | secret   | a lone App key cannot be authenticated (needs API-key pair); hardened: assignment/header anchor + SHA exclusion + entropy |
| DroneCI                 | secret   | self-hosted, host not in chunk; hardened: drone-prefixed assignment anchor + entropy + SHA exclusion |
| Exoscale                | secret   | HMAC signing required |
| GCSSignedURL            | secret   | signed URL, signed-time-bound, no verify endpoint |
| GenericHighEntropy      | secret   | entropy-only shape, no fixed upstream provider |
| GetStream               | secret   | HMAC/JWT signing, no mirrorable reference impl; hardened: credential-context anchor + entropy + char-class gate |
| GitLabPipeline          | secret   | trigger-token verify is destructive, no read-only endpoint; hardened: assignment anchor + entropy + commit-SHA exclusion |
| GoCD                    | secret   | self-hosted CI, host not in chunk |
| Jenkins                 | secret   | self-hosted CI, host not in chunk |
| Jira                    | secret   | token-only probe always 401 (needs email pair), host not in chunk; hardened: entropy + assignment vicinity + hex exclusion |
| JWT                     | secret   | generic shape, issuer-dependent verification not centralizable |
| Kafka                   | secret   | connection string, broker host not in chunk |
| LaunchNotes             | secret   | ln_ shape isn't an authentic credential; hardened: delimiter+public_ regex + context + entropy |
| Looker                  | secret   | no per-instance host channel; hardened: client_id/secret/api3 anchor + entropy + lookalike exclusion |
| Magento                 | secret   | per-store host not in chunk; hardened: hex-digest exclusion + entropy + two-tier proximity |
| Modal                   | secret   | no documented REST endpoint for the (id,secret) pair; hardened: entropy/char-class looksRandom gate on the pair |
| OVHCloud                | secret   | HMAC signing required |
| PIIAnonymize            | pii      | PII finding class — NER + regex via pleno-anonymize, no provider API to verify |
| PIIOpenAIPF             | pii      | PII finding class — MoE classifier (openai/privacy-filter), no provider-side verify path |
| PingIdentity            | secret   | per-region host (`api.pingone.{com,eu,asia,ca}`) not in chunk |
| PusherBeams             | secret   | instance_id host/path uncapturable; hardened: narrowed vicinity + digest exclusion + entropy |
| RabbitMQ                | secret   | connection string, host not in chunk |
| RequestBin              | secret   | per-bin endpoint not in chunk |
| SalesforceRefresh       | secret   | paired credential — instance URL + client_id + client_secret not co-located; Severity=Medium (explicit override, see severity recap above) |
| Segment                 | secret   | ingest returns 200 for invalid keys and a probe mints billed events; hardened: entropy floor + pure-hex exclusion |
| Sentry                  | secret   | matched value is a DSN ingest *write* key; the only verify is submitting an event (destructive / billed), no non-destructive validate — reclassified from (c) |
| Sinch                   | secret   | project_id half of (project_id, key) not in chunk |
| Smee                    | secret   | per-channel proxy URL not in chunk |
| SMTP                    | secret   | connection string, SMTP host not in chunk |
| Snowflake               | secret   | keypair JWT auth needs the *private key* to sign the assertion, never present in the matched chunk — reclassified from (c) |
| SonatypeNexus           | secret   | self-hosted artifact repo, host not in chunk |
| Spinnaker               | secret   | per-deploy Gate host, /auth/user returns anonymous 200; hardened: JWT structure validation + entropy + assignment anchor |
| Stytch                  | secret   | environment-bound endpoints (test vs live) not in chunk |
| TektonHub               | secret   | matched value is unverifiable base62, not a Tekton Hub JWT; hardened: token-specific assignment anchor + entropy + hex exclusion |
| UpstashRedis            | secret   | connection string with URL-embedded credential |
| Wiz                     | secret   | tenant-specific host (`api.<tenant>.app.wiz.io`) not in chunk |
| Zoho                    | secret   | region-specific accounts host (`accounts.zoho.<tld>`) not in chunk |

## Machine-readable block

The `coverage-machine` block pins counts and per-detector class.

- `class=a` → Verify implemented (detector satisfies `detectors.Verifier`)
- `class=b` → Unverified-by-design (no Verify, deliberate)

```coverage-machine
total=602
a=552
b=50
type=APNs class=b
type=AWSS3PresignedURL class=b
type=AgoraIO class=b
type=Akamai class=b
type=AppStoreConnect class=b
type=Atlassian class=b
type=Auth0 class=b
type=BasicAuth class=b
type=Bugsnag class=b
type=CloudflareR2 class=b
type=ConcourseCI class=b
type=Confluence class=b
type=CrispChat class=b
type=DatadogAppKey class=b
type=DroneCI class=b
type=Exoscale class=b
type=GCSSignedURL class=b
type=GenericHighEntropy class=b
type=GetStream class=b
type=GitLabPipeline class=b
type=GoCD class=b
type=JWT class=b
type=Jenkins class=b
type=Jira class=b
type=Kafka class=b
type=LaunchNotes class=b
type=Looker class=b
type=Magento class=b
type=Modal class=b
type=OVHCloud class=b
type=PIIAnonymize class=b
type=PIIOpenAIPF class=b
type=PingIdentity class=b
type=PusherBeams class=b
type=RabbitMQ class=b
type=RequestBin class=b
type=SMTP class=b
type=SalesforceRefresh class=b
type=Segment class=b
type=Sentry class=b
type=Sinch class=b
type=Smee class=b
type=Snowflake class=b
type=SonatypeNexus class=b
type=Spinnaker class=b
type=Stytch class=b
type=TektonHub class=b
type=UpstashRedis class=b
type=Wiz class=b
type=Zoho class=b
```

`class=a` is the open-set complement of the list above. Adding a new
detector without `Verify` and without listing it as `b` will fail CI.
