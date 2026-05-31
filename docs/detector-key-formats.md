<!--
  GENERATED + CURATED. The "Detectors" table below is seeded from a mechanical
  scan (bare [A-Za-z0-9]{N} token regex + nearKeyword + no entropy gate) and is
  filled in per-detector by the FP-hardening campaign. Edit rows as each
  detector is researched and hardened; do not regenerate blindly (it would drop
  the curated Key-format / Source / Hardening columns).
-->

# Detector key formats & false-positive hardening campaign

## Why this document exists

The scanner grew ~121 secret detectors from one copy-pasted template: a bare
`\b([A-Za-z0-9]{N})\b` token regex + a `nearKeyword` proximity gate with
`radius = 256` + **no entropy floor**. In aggregate this is a Medium
false-positive surface — any generic high-entropy-looking string (a UUID, a git
SHA, a build ID, a base64 blob) that happens to sit within 256 bytes of a
provider keyword gets reported as that provider's secret.

These detectors **cannot be hardened mechanically**. A blanket
`HasMinEntropy(token, 3.5)` would silently destroy **recall** on providers whose
real credentials are short or low-variety (a missed secret is worse than a false
positive for a scanner), and the correct length / charset / entropy threshold is
**provider-specific**. So each detector needs its real credential format
researched from an authoritative source before it is tightened.

This document is the **durable record of that research** — captured so the
knowledge outlives the campaign and future detector authors can reuse a cited
key format instead of re-deriving it. Every length or format claim must cite a
source.

## Methodology (per detector)

1. **Research** the provider's real credential format from an authoritative
   source — official API/auth docs, the dashboard "create token" screen, or the
   upstream trufflehog detector. Capture: prefix (if any), length, charset,
   structural markers.
2. **Harden** per the rubric below, matched to the real format.
3. **Preserve recall** — every pre-existing positive fixture must still detect.
   Add a regression fixture for the FP shape now rejected.
4. **Record** the row below with the cited source, then ship.

## Hardening rubric

- **Distinguishing prefix exists** (`sk-`, `ghp_`, `glpat-`, `rzp_live_`, …):
  anchor the regex on the prefix. Highest-precision fix; entropy usually
  unnecessary.
- **No prefix · fixed length · high-variety charset**: pin the documented length
  and add `HasMinEntropy(token, 3.5)`; tighten `radius` 256 → 64.
- **No prefix · hex / low-variety**: `HasMinEntropy(token, 3.0)` (hex entropy
  caps ~3.6, so 3.5 over-culls). Do **not** pin a length unless a source
  documents it.
- **Two-part credential** (id + secret): require an assignment anchor near one
  half; entropy on both halves.
- **Keyword gate**: replace a bare `strings.Contains(window, "vendor")` over
  radius 256 with an assignment-style arm regex
  `(?i)vendor[_-]?(api[_-]?)?(token|key|secret)` within radius 64; keep the bare
  keyword only in `Keywords()` as the cheap Aho-Corasick prefilter.

> **The cardinal rule:** cite the source for every length/format claim. An
> over-tight length or entropy floor silently destroys recall, which a scanner's
> users never see until a real leak is missed.

## Reference: already hardened (the pattern to follow)

These were hardened before the campaign and are the worked examples:

| Detector | Hardening | Shipped |
|----------|-----------|---------|
| jumio | window+anchor+entropy 3.5, radius→64 | #121 |
| vercel | entropy 3.5, radius→64, `vercel_token` proximity | #121 |
| fivetran | assignment anchor, radius→64, entropy 3.0 | #121 |
| freshdesk | host/anchor, length pinned 20, entropy 3.5 secondary | #121 |
| cohere | `\bcohere\b`/`_api_key` arm regex + entropy 3.5 | #121 |
| equinixmetal | entropy 3.0, radius→96, anchored proximity | #121 |
| bitfinex | entropy 3.5 on key+secret | #121 |
| gladly | entropy 3.5, radius→64, `gladly[_-]?...` arm regex | #127 |

## Status legend

`pending` → not yet researched · `researched` → format captured, not yet
hardened · `hardened (#PR)` → shipped.

## Detectors

| Detector | Status | Current token regex | radius | Key format (cited) | Source | Hardening applied | Shipped |
|----------|--------|---------------------|--------|--------------------|--------|-------------------|---------|
| abnormalsec | hardened | `[A-Za-z0-9]{32,64}` | 256 | unknown — not documented (vendor + integration guides say only "API access token") | conservative fallback (trufflehog has no detector; KB/Swagger no format) | radius→64, arm regex, entropy 3.0, length kept | #130 |
| activecampaign | hardened | `[A-Za-z0-9]{60,80}` | 256 | unknown — docs show Api-Token header only, example is a hyphenated placeholder | conservative fallback ([developers.activecampaign.com/reference/authentication](https://developers.activecampaign.com/reference/authentication); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #130 |
| ai21labs | hardened | `[A-Za-z0-9]{32,64}` | 256 | unknown — Bearer auth only, no format published | conservative fallback ([docs.ai21.com/reference/authentication](https://docs.ai21.com/reference/authentication); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #130 |
| aikidosecurity | hardened | `[A-Za-z0-9]{40,80}` | 256 | 2-part client_id/secret (OAuth client-credentials → JWT); credential length/charset undocumented | [apidocs.aikido.dev/reference/getaccesstoken](https://apidocs.aikido.dev/reference/getaccesstoken) (auth flow; no format) | radius→64, arm regex, entropy 3.0, length kept | #130 |
| airbrake | hardened | `[A-Za-z0-9]{40,80}` | 256 | **40** alphanumeric, no prefix | authoritative: [trufflehog airbrakeuserkey](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/airbrakeuserkey/airbrakeuserkey.go) (`{40}`, verify `/api/v4/projects?key=`) | length pinned `{40,80}`→`{40}`, radius→64, arm regex, entropy 3.5 | #130 |
| aiven | hardened | `[A-Za-z0-9]{32,80}` | 256 | base64 `[A-Za-z0-9/+=]`, length **372**, no prefix, header `aivenv1 <TOKEN>` | authoritative: [trufflehog aiven](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/aiven/aiven.go) (`{372}`) + GitGuardian | charset→base64, len→`{32,400}`, radius→64, arm regex, entropy 3.5 | #130 |
| appdynamics | hardened | `[A-Za-z0-9]{20,64}` | 256 | API Client **secret = UUID** (8-4-4-4-12 hex); client id = `<api_client>@<account>` | authoritative: [Splunk AppDynamics API-clients](https://help.splunk.com/en/appdynamics-on-premises/extend-appdynamics/25.10.0/extend-splunk-appdynamics/splunk-appdynamics-apis/api-clients) ("generate a UUID as the secret") | secret regex→UUID layout, radius→64, arm regex, entropy 3.0 | #130 |
| arduinocloud | hardened | `[A-Za-z0-9]{32,80}` | 256 | client_id = 32-hex (public id); client_secret undocumented | conservative fallback ([docs.arduino.cc/cloud-api](https://docs.arduino.cc/cloud-api); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #130 |
| arizeai | hardened | `[A-Za-z0-9]{40,80}` | 256 | unknown — docs publish no prefix/length/charset (key shown once) | conservative fallback ([arize.com/docs/ax/security-and-settings/api-keys](https://arize.com/docs/ax/security-and-settings/api-keys); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #130 |
| auditboard | hardened | `[A-Za-z0-9]{32,64}` | 128 | unknown — Bearer token; developer docs behind auth wall | conservative fallback (no trufflehog detector; docs auth-walled) | radius 128→64, arm regex, entropy 3.0, length kept | #130 |
| authentik | hardened | `[A-Za-z0-9]{60,}` | 256 | `[A-Za-z0-9]`, default length **60** (tenant-configurable, no upper bound), no prefix | authoritative: authentik source [generators.py](https://github.com/goauthentik/authentik/blob/main/authentik/lib/generators.py) + [tenants/models.py](https://github.com/goauthentik/authentik/blob/main/authentik/tenants/models.py) (`DEFAULT_TOKEN_LENGTH=60`) | radius→64, arm regex, entropy 3.5, length kept `{60,}` | #130 |
| avalara | hardened | `[A-Za-z0-9]{24,32}` | 256 | 2-part account (numeric) + license key (~30 hex-ish); not formally pinned | [developer.avalara.com/avatax/authentication-in-rest](https://developer.avalara.com/avatax/authentication-in-rest/) (examples only, no spec); no trufflehog detector | radius→64, arm regex, entropy 3.0, length kept | #130 |
| awx | hardened | `[A-Za-z0-9]{40}` | 256 | **30**-char base62, no prefix (Django OAuth Toolkit / oauthlib `generate_token(length=30)`) | authoritative: [oauthlib common.py](https://github.com/oauthlib/oauthlib/blob/master/oauthlib/common.py) + AWX docs example tokens (30) | **recall bug fixed** `{40}`→`{30}` (40 never matched), radius→64, arm regex, entropy 3.5 | #131 |
| bamboohr | hardened | `[A-Za-z0-9]{40,64}` | 256 | **40 hex** `[a-fA-F0-9]`, no prefix (160-bit secret in hex) | authoritative: [BambooHR getting-started](https://documentation.bamboohr.com/docs/getting-started) ("160-bit number in hexadecimal form") | charset→hex, length→`{40}`, radius→64, arm regex, entropy 3.0 | #131 |
| bandwidth | hardened | `[A-Za-z0-9]{10,32}` | 96 | unknown — Basic auth id:secret, no length/charset documented | conservative fallback ([dev.bandwidth.com credentials](https://dev.bandwidth.com/docs/account/credentials/management/); no trufflehog detector) | radius 96→64, entropy 3.0 on both halves, length kept | #131 |
| beeceptor | hardened | `[A-Za-z0-9]{32,}` | 256 | hex `[a-fA-F0-9]`, no prefix, example length 40 | authoritative: [beeceptor.com/docs/api-overview](https://beeceptor.com/docs/api-overview/) | charset→hex, radius→64, arm regex, entropy 3.0, length kept | #131 |
| betterstack | hardened | `[A-Za-z0-9]{24,40}` | 256 | 24-char base62, no prefix, Bearer (upstream pins `{24}`) | authoritative: [trufflehog betterstack](https://github.com/trufflesecurity/trufflehog) + [Better Stack API docs](https://betterstack.com/docs/uptime/api/getting-started-with-uptime-api/) | radius→64, arm regex, entropy 3.5, length kept (lower bound 24 sourced) | #131 |
| beyondtrust | hardened | `[A-Za-z0-9]{64,128}` | 256 | **128**-char key (length documented; charset undocumented, example hex) | authoritative: [BeyondInsight/Password Safe API usage](https://docs.beyondtrust.com/bips/reference/beyondinsight-and-password-safe-api-usage) | length→`{128}`, radius→64, arm regex, entropy 3.0 (hex-conservative) | #131 |
| bitbucketcloud | hardened | `[A-Za-z0-9]{32}` | 256 | **prefix-anchored**: Atlassian API token `ATCTT3xFfG…=`+8-char checksum | authoritative: [trufflehog atlassian v2](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/atlassian/v2/atlassian.go) | regex→upstream prefix-anchored (`ATCTT3xFfG`); prefix carries precision, no entropy | #131 |
| bitbucketserver | hardened | `[A-Za-z0-9]{40}` | 256 | **prefix-anchored**: HTTP token `BBDC-`+`[A-Za-z0-9+/@_-]{40,50}`; + prefix-less 40-char PAT | authoritative: [trufflehog bitbucketdatacenter](https://github.com/trufflesecurity/trufflehog) | `BBDC-` shape prefix-anchored; prefix-less PAT radius→64 + arm regex + entropy 3.5 | #131 |
| box | hardened | `[A-Za-z0-9]{32,64}` | 256 | 32-char alnum, no prefix | authoritative: [trufflehog box](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/box/box.go) (`{32}`) | length→`{32}`, radius→64, arm regex, entropy 3.5 | #131 |
| buddyci | hardened | `[A-Za-z0-9]{40,80}` | 256 | **UUID v4** (8-4-4-4-12 hex), no prefix, Bearer | authoritative: [buddy.works API docs](https://buddy.works/docs/api/getting-started/hello-world) (literal example token) | regex→UUID layout, radius→64, arm regex, entropy 3.0 | #131 |
| buffer | hardened | `[A-Za-z0-9]{40,50}` | 96 | unknown — OAuth2 "long-lived access token", no literal format published | conservative fallback ([legacy Buffer OAuth doc](https://web.archive.org/web/20130514055415/https://bufferapp.com/developers/api/oauth)) | radius 96→64, entropy 3.0, length kept | #131 |
| civo | hardened | `[A-Za-z0-9]{50}` | 256 | no prefix; conflicting non-authoritative samples (50-char base62 vs 70-char) | conservative fallback (civo/cli README + civogo tests; not authoritative) | radius→64, arm regex, entropy 3.0, length kept | #131 |
| clickhousecloud | hardened | `[A-Za-z0-9]{32}` | 256 | unknown — Key ID + Key Secret pair (Basic auth); format undocumented | conservative fallback (no trufflehog detector; docs pin no format) | radius→64, arm regex (`clickhouse.(cloud\|api)` / `chc_`), entropy 3.0, length kept | #131 |
| coinbase | hardened | `[A-Za-z0-9]{32}` | 256 | CDP credential = key name `organizations/{uuid}/apiKeys/{uuid}` + EC PEM secret | authoritative: [Coinbase CDP auth docs](https://docs.cdp.coinbase.com/coinbase-app/authentication-authorization/api-key-authentication) + trufflehog | radius→64, arm regex, entropy 3.5 | #131 |
| cometml | hardened | `[A-Za-z0-9]{32,100}` | 256 | unknown — docs describe key only as a header string, no format | conservative fallback ([Comet REST API docs](https://www.comet.com/docs/v2/api-and-sdk/rest-api/overview/)) | radius→64, arm regex, entropy 3.0, length kept | #131 |
| copper | hardened | `[A-Za-z0-9]{32,128}` | 256 | 32-char lowercase hex `[a-z0-9]`, no prefix | authoritative: [trufflehog copper](https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/pkg/detectors/copper/copper.go) (`{32}`) | charset→`[a-z0-9]`, length→`{32}`, radius→64, arm regex, entropy 3.0 | #131 |
| customerio | hardened | `[A-Za-z0-9]{20}` | 256 | Track API `site_id:api_key`, each 20-char base62, no prefix | authoritative: [trufflehog customerio](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/customerio/customerio.go) (`{20}`) | radius→64, arm regex, entropy 3.5 on both halves, length kept | #131 |
| customerly | hardened | `[A-Za-z0-9]{40,80}` | 256 | unknown — help-centre describes only how to obtain the token, no format | conservative fallback ([Customerly help](https://docs.customerly.io/en/articles/15223-how-to-obtain-your-api-access-token-in-customerly)) | radius→64, arm regex, entropy 3.0, length kept | #131 |
| deel | hardened | `[A-Za-z0-9]{40,}` | 256 | unknown — docs show only `Bearer YOUR-TOKEN-HERE` placeholder, no prefix/length/charset | conservative fallback ([developer.deel.com/api/authentication](https://developer.deel.com/api/authentication); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #132 |
| dialpad | hardened | `[A-Za-z0-9]{40,128}` | 256 | unknown — docs publish no prefix/length/charset (share last 4 chars only) | conservative fallback ([developers.dialpad.com api-key-generation](https://developers.dialpad.com/docs/api-key-generation); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #132 |
| drip | hardened | `[A-Za-z0-9]{32}` | 256 | unknown — docs say only "alphanumeric" token (Basic-auth username); no length/charset | conservative fallback ([DripEmail/api-docs authentication](https://github.com/DripEmail/api-docs/blob/main/source/includes/rest/_authentication.md); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length + hex-guard kept | #132 |
| dwolla | hardened | `[A-Za-z0-9]{50,}` | 256 | key+secret pair, each **50**-char `[A-Za-z0-9]`, no prefix | authoritative: [trufflehog dwolla](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/dwolla/dwolla.go) (`{50}`) | length `{50,}`→`{50}`, radius→64, arm regex, entropy 3.5 on both halves | #132 |
| earthly | hardened | `[A-Za-z0-9]{40,120}` | 256 | unknown — token minted server-side, docs use opaque placeholders | conservative fallback ([docs.earthly.dev earthly-command](https://docs.earthly.dev/docs/earthly-command); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #132 |
| elasticapm | hardened | `[A-Za-z0-9]{40,80}` | 256 | unknown — secret token is operator-defined freeform, no enforced prefix/length/charset | conservative fallback ([elastic.co APM secret-token](https://www.elastic.co/docs/solutions/observability/apm/secret-token); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #132 |
| eloqua | hardened | `[A-Za-z0-9]{24,128}` | 256 | unknown — HTTP-Basic base64(client_id:client_secret), no length/charset/prefix | conservative fallback ([Oracle Eloqua auth docs](https://docs.oracle.com/en/cloud/saas/marketing/eloqua-rest-api/Authentication_Auth.html); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #132 |
| expel | hardened | `[A-Za-z0-9]{32,64}` | 256 | unknown — opaque non-expiring Bearer token, no prefix/length/charset | conservative fallback ([Expel API Key Self-Service](https://support.expel.io/hc/en-us/articles/17165510512659-API-Key-Self-Service); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #132 |
| fastspring | hardened | `[A-Za-z0-9]{16,32}` | 256 | unknown — dashboard-generated user+password, case-sensitive; no length/prefix/charset | conservative fallback ([developer.fastspring.com getting-started](https://developer.fastspring.com/reference/getting-started-with-your-api); no trufflehog detector) | radius→64, arm regex, entropy 3.0 on both halves, length kept | #132 |
| forter | hardened | `[A-Za-z0-9]{40,80}` | 256 | unknown — Basic auth (key as username), Site ID/Secret pair; no length/charset/prefix | conservative fallback ([docs.forter.com/reference/overview](https://docs.forter.com/reference/overview); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #132 |
| freshmarketer | hardened | `[A-Za-z0-9]{20,32}` | 256 | unknown — `Token token=` scheme, alnum no prefix; length/charset undocumented (sibling Freshworks detectors conflict) | conservative fallback ([Freshworks CRM API](https://developers.freshworks.com/crm/api/); no freshmarketer trufflehog detector) | radius→64, arm regex, entropy 3.0, **widened** `{20,32}`→`{16,40}` (recall-safe) | #132 |
| gainsight | hardened | `[A-Za-z0-9]{32,64}` | 256 | unknown — opaque Accesskey-header credential; UUID-v4-shaped example but no pinned length/charset | conservative fallback ([Gainsight Generate REST API Access Key](https://support.gainsight.com/gainsight_nxt/Connectors/API_Integrations/Generate_REST_API_Access_Key); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #132 |
| gandi | hardened | `[A-Za-z0-9]{24,80}` | 256 | unknown — docs show only placeholder PAT examples, no prefix/length/charset | conservative fallback ([api.gandi.net/docs/authentication](https://api.gandi.net/docs/authentication/); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #132 |
| greenhouse | hardened | `[A-Za-z0-9]{40,}` | 256 | **32-char lowercase hex** `[a-f0-9]`, no prefix (Harvest API token) | authoritative: [developers.greenhouse.io/harvest](https://developers.greenhouse.io/harvest.html) (32-hex example token) | charset→hex `[a-f0-9]{32,}`, radius→64, arm regex (incl. bare `GREENHOUSE_API`), entropy 3.0 | #132 |
| harbor | hardened | `[A-Za-z0-9]{16,64}` | 96 | robot-secret **32**-char base62, no prefix (server requires mixed-case + digit) | authoritative: [goharbor/harbor utils.go](https://github.com/goharbor/harbor/blob/main/src/common/utils/utils.go) (`GenerateRandomStringWithLen(32)`) | length→`{32}`, radius 96→64, arm regex (pre-existing), entropy 3.5 | #132 |
| hasura | hardened | `[A-Za-z0-9]{40,80}` | 256 | admin secret **64**-char `[a-zA-Z0-9]`, no prefix | authoritative: [trufflehog hasura](https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/pkg/detectors/hasura/hasura.go) (`{64}`) | length→`{64}`, radius→64, arm regex, entropy 3.5 | #132 |
| helpscout | hardened | `[A-Za-z0-9]{32,128}` | 256 | App ID + App Secret (OAuth2 client_credentials) pair; length/charset undocumented | conservative fallback ([Help Scout Mailbox auth](https://developer.helpscout.com/mailbox-api/overview/authentication/); upstream single-token detector is a different credential) | radius→64, arm regex, entropy 3.0 on both halves, length kept | #132 |
| hetzner | hardened | `[A-Za-z0-9]{64}` | 256 | **64**-char (length authoritative), no prefix; charset undocumented | authoritative: [terraform-provider-hcloud](https://github.com/hetznercloud/terraform-provider-hcloud) (`len(token) != 64` validation) | length pin `{64}` now sourced, radius→64, arm regex, entropy 3.5 | #132 |
| hyperline | pending | `[A-Za-z0-9]{32,80}` | 256 | — | — | — | — |
| hyperproof | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| idnow | pending | `[A-Za-z0-9]{32,64}` | 128 | — | — | — | — |
| inflection | pending | `[A-Za-z0-9]{40,}` | 256 | — | — | — | — |
| jellyfish | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| jenkinsx | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| june | pending | `[A-Za-z0-9]{32}` | 256 | — | — | — | — |
| kayako | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| keycdn | pending | `[A-Za-z0-9]{20,64}` | 256 | — | — | — | — |
| keycloak | pending | `[A-Za-z0-9]{24,128}` | 256 | — | — | — | — |
| klarna | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| lakera | pending | `[A-Za-z0-9]{32,64}` | 128 | — | — | — | — |
| lambdalabs | pending | `[A-Za-z0-9]{40,}` | 256 | — | — | — | — |
| lark | pending | `[A-Za-z0-9]{32}` | 256 | — | — | — | — |
| lemlist | pending | `[A-Za-z0-9]{32,128}` | 256 | — | — | — | — |
| leptonai | pending | `[A-Za-z0-9]{32,}` | 256 | — | — | — | — |
| lightstep | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| livekit | pending | `[A-Za-z0-9]{10,16}` | 256 | — | — | — | — |
| mailtrap | pending | `[A-Za-z0-9]{32,80}` | 256 | — | — | — | — |
| mandiant | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| marketo | pending | `[A-Za-z0-9]{24,64}` | 256 | — | — | — | — |
| mercurybank | pending | `[A-Za-z0-9]{32,120}` | 256 | — | — | — | — |
| messagebird | pending | `[A-Za-z0-9]{25,32}` | 256 | — | — | — | — |
| mistral | pending | `[A-Za-z0-9]{32}` | 256 | — | — | — | — |
| modeanalytics | pending | `[A-Za-z0-9]{16,80}` | 256 | — | — | — | — |
| monsterapi | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| nearrpc | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| onesignal | pending | `[A-Za-z0-9]{48}` | 256 | — | — | — | — |
| opslevel | pending | `[A-Za-z0-9]{40,64}` | 256 | — | — | — | — |
| oraclecloud | pending | `[A-Za-z0-9]{32,128}` | 256 | — | — | — | — |
| parabola | pending | `[A-Za-z0-9]{32,80}` | 256 | — | — | — | — |
| pardot | pending | `[A-Za-z0-9]{18,256}` | 256 | — | — | — | — |
| paylocity | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| planetscale | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| planhat | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| portswigger | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| propelauth | pending | `[A-Za-z0-9]{40,}` | 256 | — | — | — | — |
| pusherchannels | pending | `[A-Za-z0-9]{20}` | 256 | — | — | — | — |
| pushover | pending | `[A-Za-z0-9]{30}` | 256 | — | — | — | — |
| razorpay | pending | `[A-Za-z0-9]{14,}` | 256 | — | — | — | — |
| recurly | pending | `[A-Za-z0-9]{32}` | 256 | — | — | — | — |
| rekaai | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| ringcentral | pending | `[A-Za-z0-9]{24,128}` | 256 | — | — | — | — |
| rippling | pending | `[A-Za-z0-9]{40,}` | 256 | — | — | — | — |
| sageintacct | pending | `[A-Za-z0-9]{12,32}` | 256 | — | — | — | — |
| sapariba | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| scoutapm | pending | `[A-Za-z0-9]{16}` | 256 | — | — | — | — |
| semaphoreci | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| sentinelone | pending | `[A-Za-z0-9]{80,256}` | 256 | — | — | — | — |
| shodan | pending | `[A-Za-z0-9]{32}` | 256 | — | — | — | — |
| signalwire | pending | `[A-Za-z0-9]{24,128}` | 256 | — | — | — | — |
| signifyd | pending | `[A-Za-z0-9]{20,80}` | 256 | — | — | — | — |
| smartsheet | pending | `[A-Za-z0-9]{24,64}` | 256 | — | — | — | — |
| snipcart | pending | `[A-Za-z0-9]{50,75}` | 256 | — | — | — | — |
| socure | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| sumologic | pending | `[A-Za-z0-9]{12}` | 256 | — | — | — | — |
| sumsub | pending | `[A-Za-z0-9]{20,40}` | ? | — | — | — | — |
| supertokens | pending | `[A-Za-z0-9]{32,}` | 256 | — | — | — | — |
| swimlane | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| taxjar | pending | `[A-Za-z0-9]{40,64}` | 256 | — | — | — | — |
| trulioo | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| trustpilot | pending | `[A-Za-z0-9]{32,128}` | 256 | — | — | — | — |
| twitch | pending | `[A-Za-z0-9]{30}` | 256 | — | — | — | — |
| typesense | pending | `[A-Za-z0-9]{32,}` | 256 | — | — | — | — |
| vimeo | pending | `[A-Za-z0-9]{32,128}` | 256 | — | — | — | — |
| vitally | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| vonage | pending | `[A-Za-z0-9]{8}` | 256 | — | — | — | — |
| webex | pending | `[A-Za-z0-9]{60,160}` | 256 | — | — | — | — |
| woodpecker | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| workato | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| writer | pending | `[A-Za-z0-9]{40,128}` | 96 | — | — | — | — |
| zendesk | pending | `[A-Za-z0-9]{40}` | 256 | — | — | — | — |
| zerotier | pending | `[A-Za-z0-9]{32}` | 128 | — | — | — | — |
