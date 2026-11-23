# Verify coverage audit

This page classifies each registered detector as verifier-backed or
unverified-by-design. The machine block is parsed by
`pkg/detectors/verifycoverage_test.go`.

Counts are pinned in the machine block. Total = 723: 721 secret
detectors, `PIIAnonymize`, and `PIIOpenAIPF`. The retired regex PII
detector constants (and the retired China-hosted providers
`TencentCloud` / `DashScope` / `ModelScope`) remain reserved for wire
compatibility, but are not listed because they are no longer
registered. `AlibabaCloud` lost its China-hosted verifier and returns
as a kingfisher catalog host verified through STS GetCallerIdentity
(HMAC-SHA1 RPC signing, class a). See
[`docs/counts.md`](counts.md) for the repo-wide definition this total
feeds (README and website) and the drift test that enforces it.

## Severity model recap

`detectors.DefaultSeverity`:

| Detector class                                          | Verified  | Unverified |
|---------------------------------------------------------|-----------|------------|
| Default (every named provider unless overridden)        | Critical  | High       |
| `JWT`, `PrivateKeyPEM`, `GenericHighEntropy`            | Critical  | Medium     |
| `PIIAnonymize`, `PIIOpenAIPF`                           | (n/a)     | Medium     |

A handful of providers (`Bitwarden`, `Helcim`, `AzureAD`, `CloudflareR2`,
…) override their unverified severity to Critical at the detector level.
Those are not enumerated here, since `DefaultSeverity` applies only
when a detector leaves severity unset. Per-detector overrides usually
raise it; the one lowering exception is `SalesforceRefresh` (see the
class (b) table).

## (a) Verify implemented — 638 detectors

Detector type satisfies `detectors.Verifier`. The detector calls the
upstream provider and returns `(true, nil)` on success, `(false, nil)`
when the credential is rejected, and `(false, err)` only for transport
errors.

Some entries in this column implement `Verify` but return
`(false, nil)` until an `apiBase` override is supplied (per-tenant or
per-region host). They satisfy the interface and are counted in
class (a). Where the host shape is structurally absent from the chunk
and no apiBase fallback is wired, the detector lives in (b) instead.

### Context-extraction Verify

Azure AD and Azure App detectors extract `tenant_id` from surrounding
chunk data (assignment anchors, URLs, and known Azure directory
patterns). The extracted tenant is combined with the matched
`client_id` / `client_secret` pair to attempt an OAuth2
`client_credentials` grant. Transport errors currently return
`(false, nil)`, deviating from the standard Verifier contract: the
AzureAD/AzureApp verifiers cannot yet distinguish a rejected credential
from an unreachable token endpoint.

## (b) Unverified-by-design — 76 detectors

These detectors deliberately do not implement `Verify`. The rationale
is one of:

- **Connection-string / URL-embedded credential.** The credential is
  meaningful only against a host that lives elsewhere.
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
  `GenericHighEntropy`). `PrivateKeyPEM` is class (a) — see the
  Verifier note below.
- **PII finding class.** No "is this real?" call exists.

> **PrivateKeyPEM Verifier (class a).** PEM private keys do not have a
> single upstream provider, but the public-key half can be correlated
> against Certificate Transparency logs. The detector derives the SPKI
> SHA-256 locally (the private key never leaves the host) and queries
> crt.sh during verification. A non-empty CT
> match marks the finding `Verified=true` and surfaces the discovered
> domains via `ExtraData["blast_radius_domains"]`. Encrypted PEMs are
> also tried against an embedded
> 325-entry passphrase wordlist; a successful unlock pins severity at
> High — including for findings the CT lookup subsequently verifies,
> which therefore surface at High rather than the table's Critical.
> Inspired by trufflesecurity/driftwood.

| DetectorType            | Class    | Rationale (verify infeasible; hardening applied where noted)                  |
|-------------------------|----------|---------------------------------------------------------------------------|
| AgoraIO                 | secret   | per-app HMAC token signing required |
| Akamai                  | secret   | EdgeGrid HMAC signing required, no bearer endpoint |
| APIKeyAssignment        | secret   | offline config `api_key:`/`api_key=` assignment, host not in chunk; no provider endpoint to verify against |
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
| DjangoConfigSecret      | secret   | offline Django settings.py credential (SECRET_KEY constant / DATABASES quoted-key password), no provider endpoint to verify against |
| DroneCI                 | secret   | self-hosted, host not in chunk; hardened: drone-prefixed assignment anchor + entropy + SHA exclusion |
| Esmtprc                 | secret   | credential authenticates against the `hostname` directive elsewhere in the same file, an arbitrary user-configured SMTP relay |
| Exoscale                | secret   | HMAC signing required |
| FileZillaXML            | secret   | credential authenticates against the arbitrary FTP/SFTP host stored elsewhere in the same `<Server>` block |
| GCSSignedURL            | secret   | signed URL, signed-time-bound, no verify endpoint |
| GenericHighEntropy      | secret   | entropy-only shape, no fixed upstream provider |
| GetStream               | secret   | HMAC/JWT signing, no mirrorable reference impl; hardened: credential-context anchor + entropy + char-class gate |
| GitCredentialsURL       | secret   | host is data-controlled and arbitrary (any `scheme://user:pass@host` a user configured); no fixed provider to probe |
| GitLabPipeline          | secret   | trigger-token verify is destructive, no read-only endpoint; hardened: assignment anchor + entropy + commit-SHA exclusion |
| GoCD                    | secret   | self-hosted CI, host not in chunk |
| HardcodedPassword       | secret   | offline config password, host not in chunk; no provider endpoint to verify against |
| Jenkins                 | secret   | self-hosted CI, host not in chunk |
| JetBrainsWebServers     | secret   | host is data-controlled and arbitrary (any SFTP/FTP/deploy target a developer configured); no fixed provider to probe |
| Jira                    | secret   | token-only probe always 401 (needs email pair), host not in chunk; hardened: entropy + assignment vicinity + hex exclusion |
| JSLoginCallSecret       | secret   | credential authenticates against whatever host the SDK client object was configured against elsewhere in the codebase, not present in this chunk |
| JSONConfigSecret        | secret   | offline SFTP/deploy JSON config credential, host — when present at all — is data-controlled and arbitrary, not a fixed provider endpoint |
| JWT                     | secret   | generic shape, issuer-dependent verification not centralizable |
| Kafka                   | secret   | connection string, broker host not in chunk |
| LaunchNotes             | secret   | ln_ shape isn't an authentic credential; hardened: delimiter+public_ regex + context + entropy |
| Looker                  | secret   | no per-instance host channel; hardened: client_id/secret/api3 anchor + entropy + lookalike exclusion |
| Magento                 | secret   | per-store host not in chunk; hardened: hex-digest exclusion + entropy + two-tier proximity |
| Modal                   | secret   | no documented REST endpoint for the (id,secret) pair; hardened: entropy/char-class looksRandom gate on the pair |
| Netrc                   | secret   | host is data-controlled and arbitrary (mail/FTP/HTTP endpoint a user configured); no fixed provider to probe |
| NpmrcAuth               | secret   | registry host (npmjs.org, a private mirror, ...) is data-controlled and arbitrary |
| OVHCloud                | secret   | HMAC signing required |
| PHPConfigSecret         | secret   | offline config secret (PHP `define()`/variable-assignment), host not in chunk; no provider endpoint to verify against |
| PIIAnonymize            | pii      | PII finding class — NER + regex via pleno-anonymize, no provider API to verify |
| PIIOpenAIPF             | pii      | PII finding class — MoE classifier (openai/privacy-filter), no provider-side verify path |
| Pgpass                  | secret   | host is data-controlled and arbitrary (any Postgres instance a user configured); a live connection attempt would be a blind probe |
| PingIdentity            | secret   | per-region host (`api.pingone.{com,eu,asia,ca}`) not in chunk |
| PuTTYPrivateKey         | secret   | PPK-format private key; no PPK-to-DER conversion implemented yet to correlate against Certificate Transparency the way PrivateKeyPEM does |
| PusherBeams             | secret   | instance_id host/path uncapturable; hardened: narrowed vicinity + digest exclusion + entropy |
| RabbitMQ                | secret   | connection string, host not in chunk |
| RailsMasterKey          | secret   | local AES key for config/credentials.yml.enc; the paired ciphertext is not present in this chunk, so there is no way to confirm it decrypts anything real |
| RailsSecretKeyBase      | secret   | signs/encrypts this specific Rails app's session cookies; no provider endpoint, only meaningful against that one running instance |
| RequestBin              | secret   | per-bin endpoint not in chunk |
| SalesforceRefresh       | secret   | paired credential — instance URL + client_id + client_secret not co-located; Severity=Medium (explicit override, see severity recap above) |
| Segment                 | secret   | ingest returns 200 for invalid keys and a probe mints billed events; hardened: entropy floor + pure-hex exclusion |
| Sentry                  | secret   | matched value is a DSN ingest *write* key; the only verify is submitting an event (destructive / billed), no non-destructive validate |
| Sinch                   | secret   | project_id half of (project_id, key) not in chunk |
| Smee                    | secret   | per-channel proxy URL not in chunk |
| SMTP                    | secret   | connection string, SMTP host not in chunk |
| Snowflake               | secret   | keypair JWT auth needs the *private key* to sign the assertion, never present in the matched chunk |
| SonatypeNexus           | secret   | self-hosted artifact repo, host not in chunk |
| Spinnaker               | secret   | per-deploy Gate host, /auth/user returns anonymous 200; hardened: JWT structure validation + entropy + assignment anchor |
| Stytch                  | secret   | environment-bound endpoints (test vs live) not in chunk |
| TektonHub               | secret   | matched value is unverifiable base62, not a Tekton Hub JWT; hardened: token-specific assignment anchor + entropy + hex exclusion |
| UnixCryptHash           | secret   | matched value is an offline password hash (crypt/apr1/bcrypt/Apache legacy tag), not a bearer credential against any endpoint |
| UpstashRedis            | secret   | connection string with URL-embedded credential |
| Wiz                     | secret   | tenant-specific host (`api.<tenant>.app.wiz.io`) not in chunk |
| Zoho                    | secret   | region-specific accounts host (`accounts.zoho.<tld>`) not in chunk |

## (c) Verify gap and kingfisher catalog hosts

`pkg/detectors/catalog` registers host types for kingfisher rules no
native provider detector covers (`scripts/kingfisher-catalog.py`, #900).
Every rule kingfisher validates carries a catalog check
(`pkg/detectors/catalog/checks.go`, #934): routed to the provider's own
verifier with paired credentials packed into its secret shape, a
declarative request modelled on kingfisher's validator, or a signed
scheme (Alibaba RPC HMAC-SHA1, Exoscale EXO2-HMAC-SHA256, Polymarket and
Packagist HMAC-SHA256, OVH `$1$`, Azure App Configuration HMAC and
Service Bus SAS, OIDC JWKS signature checks). Hosts with a check are
Verifiers (class a) and are not listed. The hosts below have no
kingfisher validator: class (c) hosts have a provider API that is not
wired yet; class (b) hosts cannot be verified by design.

Supplementary formats attached to existing provider types
(`detectors.RegisterFormats`) are verified when they carry a check
(`ExtraData["verification"]="format"`, with the check's own assurance)
and are otherwise detection-only (`"not-attempted"`). Check assurance is
honest per scheme: provider-confirmed only when the provider returns an
identity, an account-scoped resource, or an issued token;
response-confirmed for OAuth `invalid_grant` probes after client
authentication, token introspection, SDK/ingest keys, and JWT issuer
signatures; heuristic for the offline secp256k1 key check.
`docs/kingfisher-parity.md` records the verification kind per rule.

<!-- BEGIN kingfisher catalog hosts -->
| DetectorType | Class | Rationale |
|---|---|---|
| AgeSecretKey | b | offline age X25519 identity; no provider endpoint exists (kingfisher catalog host, detection-only) |
| Bittrex | b | exchange shut down in 2023; no live API remains (kingfisher catalog host, detection-only) |
| Clojars | c | kingfisher catalog host, detection-only in kingfisher too; deploy tokens authenticate only with the account username in Basic auth; no reliable username context pattern yet (#950 follow-up) |
| Coveralls | c | kingfisher catalog host, detection-only in kingfisher too; no documented identity endpoint for personal API tokens; repo-scoped endpoints need an owner/repo partner (#950 follow-up) |
| CurlAuth | b | credential belongs to the arbitrary host on the same curl command line (kingfisher catalog host, detection-only) |
| DockerSwarm | b | self-hosted swarm manager, host not in chunk (kingfisher catalog host, detection-only) |
| Finicity | c | kingfisher catalog host, detection-only in kingfisher too; needs App-Key plus partner ID alongside the secret; three-part pairing not yet modelled (#950 follow-up) |
| Freemius | c | kingfisher catalog host, detection-only in kingfisher too; requests are HMAC-signed with developer ID and public key partners (#950 follow-up) |
| Greptile | c | kingfisher catalog host, detection-only in kingfisher too; no account endpoint; API calls need a GitHub token and repository partner (#950 follow-up) |
| KuCoin | c | kingfisher catalog host, detection-only in kingfisher too; HMAC-signed requests need the API passphrase as a third partner (#950 follow-up) |
| KubernetesSecret | b | self-hosted cluster, API server not in chunk (kingfisher catalog host, detection-only) |
| LinkedIn | c | kingfisher catalog host, detection-only in kingfisher too; client_credentials is disabled for most apps, so a probe cannot separate a bad secret from an unauthorized app (#950 follow-up) |
| Mattermost | b | self-hosted server URL; a host derived from scanned text cannot be allowlisted (kingfisher catalog host, detection-only) |
| MicrosoftTeamsWebhook | b | the only probe posts a message (destructive); no read-only endpoint (kingfisher catalog host, detection-only) |
| OpenShift | b | self-hosted cluster, API server not in chunk (kingfisher catalog host, detection-only) |
| PrivateAI | c | kingfisher catalog host, detection-only in kingfisher too; no documented account or metrics endpoint for API keys (#950 follow-up) |
| RapidAPI | b | key is only accepted by each subscribed API's own host; no account endpoint to probe (kingfisher catalog host, detection-only) |
| SettleMint | c | kingfisher catalog host, detection-only in kingfisher too; tokens authenticate against a per-deployment platform URL not present in the token (#950 follow-up) |
<!-- END kingfisher catalog hosts -->

## Machine-readable block

The `coverage-machine` block pins counts and per-detector class.

- `class=a` → Verify implemented (detector satisfies `detectors.Verifier`)
- `class=b` → Unverified-by-design (no Verify, deliberate)
- `class=c` → verifiable but not yet implemented (verify-gap)

```coverage-machine
total=723
a=638
b=76
c=9
type=APIKeyAssignment class=b
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
type=DjangoConfigSecret class=b
type=DroneCI class=b
type=Esmtprc class=b
type=Exoscale class=b
type=FileZillaXML class=b
type=GCSSignedURL class=b
type=GenericHighEntropy class=b
type=GetStream class=b
type=GitCredentialsURL class=b
type=GitLabPipeline class=b
type=GoCD class=b
type=HardcodedPassword class=b
type=JSLoginCallSecret class=b
type=JSONConfigSecret class=b
type=JWT class=b
type=Jenkins class=b
type=JetBrainsWebServers class=b
type=Jira class=b
type=Kafka class=b
type=LaunchNotes class=b
type=Looker class=b
type=Magento class=b
type=Modal class=b
type=Netrc class=b
type=NpmrcAuth class=b
type=OVHCloud class=b
type=PHPConfigSecret class=b
type=PIIAnonymize class=b
type=PIIOpenAIPF class=b
type=Pgpass class=b
type=PingIdentity class=b
type=PuTTYPrivateKey class=b
type=PusherBeams class=b
type=RabbitMQ class=b
type=RailsMasterKey class=b
type=RailsSecretKeyBase class=b
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
type=UnixCryptHash class=b
type=UpstashRedis class=b
type=Wiz class=b
type=Zoho class=b
# BEGIN kingfisher catalog hosts
type=AgeSecretKey class=b
type=Bittrex class=b
type=Clojars class=c
type=Coveralls class=c
type=CurlAuth class=b
type=DockerSwarm class=b
type=Finicity class=c
type=Freemius class=c
type=Greptile class=c
type=KuCoin class=c
type=KubernetesSecret class=b
type=LinkedIn class=c
type=Mattermost class=b
type=MicrosoftTeamsWebhook class=b
type=OpenShift class=b
type=PrivateAI class=c
type=RapidAPI class=b
type=SettleMint class=c
# END kingfisher catalog hosts
```

`class=a` is the open-set complement of the list above. Adding a new
detector without `Verify` and without listing it as `b` or `c` will
fail CI.
