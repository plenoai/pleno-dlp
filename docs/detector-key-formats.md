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
| hyperline | hardened | `[A-Za-z0-9]{32,80}` | 256 | **prefix-anchored**: `prod_`/`test_` + base62 tail (tail length undocumented) | authoritative: [docs.hyperline.co/llms-full.txt](https://docs.hyperline.co/llms-full.txt) (prefix documented) | regex→`(?:prod\|test)_` prefix-anchored, tail `{16,}` (no length pin), radius→64, arm regex, entropy 3.0 | #133 |
| hyperproof | hardened | `[A-Za-z0-9]{32,64}` | 256 | unknown — OAuth2 client_id+client_secret, literal format unpublished | conservative fallback ([developer.hyperproof.app oauth-client-credentials](https://developer.hyperproof.app/guides/oauth-client-credentials); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #133 |
| idnow | hardened | `[A-Za-z0-9]{32,64}` | 128 | unknown — apiKey POSTed as JSON, no prefix/length/charset documented | conservative fallback (IDnow docs are JS SPAs; no trufflehog detector) | radius 128→64, arm regex, entropy 3.0, length kept | #133 |
| inflection | hardened | `[A-Za-z0-9]{40,}` | 256 | unknown — docs show only `YOUR_API_KEY` placeholder | conservative fallback ([developers.inflection.ai authentication](https://developers.inflection.ai/docs/authentication); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #133 |
| jellyfish | hardened | `[A-Za-z0-9]{40,80}` | 256 | unknown — docs specify only `Authorization: Token`, no shape published | conservative fallback (Jellyfish docs; no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #133 |
| jenkinsx | hardened | `[A-Za-z0-9]{40,80}` | 256 | unknown — JX has no native token; consumes SCM token (≥40-char min validator) | conservative fallback ([jenkins-x/jx#7358](https://github.com/jenkins-x/jx/issues/7358); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #133 |
| june | hardened | `[A-Za-z0-9]{32}` | 256 | unknown — Segment Analytics.js fork; docs show only `YOUR_WRITE_KEY` | conservative fallback ([june.so/docs/quickstart](https://www.june.so/docs/quickstart/install); no trufflehog detector) | radius→64, arm regex, entropy 3.0, **removed** unsourced `{32}` pin → `{16,}` | #133 |
| kayako | hardened | `[A-Za-z0-9]{40,80}` | 256 | unknown — docs show OAuth UUID + variable-length session tokens; email+API-token pair unpinned | conservative fallback ([developer.kayako.com authentication](https://developer.kayako.com/api/v1/reference/authentication/); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #133 |
| keycdn | hardened | `[A-Za-z0-9]{20,64}` | 256 | **prefix-anchored**: `sk_prod_` + base62 suffix (example suffix 24 chars) | authoritative: [keycdn.com/api](https://www.keycdn.com/api) (Basic-auth example `sk_prod_…`) | regex→`sk_prod_` prefix-anchored `{16,64}`, **keyword gate removed** (prefix carries precision) | #133 |
| keycloak | hardened | `[A-Za-z0-9]{24,128}` | 256 | client_secret **32/48/64**-char `[A-Za-z0-9]` (HS256/384/512), no prefix; client_id free-form | authoritative: [keycloak SecretGenerator.java](https://github.com/keycloak/keycloak/blob/main/common/src/main/java/org/keycloak/common/util/SecretGenerator.java) (256/384/512-bit lengths) | length→`{32}\|{48}\|{64}` (all three documented; **not** {32}-only — would drop HS384/HS512), radius→64, arm regex, entropy 3.5 | #133 |
| klarna | hardened | `[A-Za-z0-9]{32,64}` | 256 | **prefix-anchored**: `klarna_(live\|test)_api_` + base64-ish tail; UUID username (Basic auth) | authoritative: [docs.klarna.com authentication](https://docs.klarna.com/api-reference/authentication/) (key format documented) | regex→`klarna_(live\|test)_api_` prefix-anchored, radius→64, arm regex, no entropy (prefix) | #133 |
| lakera | hardened | `[A-Za-z0-9]{32,64}` | 128 | unknown — docs show only `$LAKERA_GUARD_API_KEY` placeholder behind Bearer | conservative fallback ([docs.lakera.ai/docs/api](https://docs.lakera.ai/docs/api); no trufflehog detector) | radius 128→64, arm regex, entropy 3.0, length kept | #133 |
| lambdalabs | hardened | `[A-Za-z0-9]{40,}` | 256 | unknown — Basic auth (key as username); OpenAPI uses placeholders only | conservative fallback ([docs.lambda.ai cloud-api](https://docs.lambda.ai/public-cloud/cloud-api/); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #133 |
| lark | hardened | `[A-Za-z0-9]{32}` | 256 | two-part: app_id `cli_`+16 base62, app_secret **32**-char base62 | authoritative: [trufflehog larksuiteapikey](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/larksuiteapikey/larksuiteapikey.go) (`cli_[a-z0-9A-Z]{16}` / `{32}`) | secret length 32 kept, entropy 3.5, radius→64, arm regex (incl. `cli_` self-arm); app_id `cli_` already anchored | #133 |
| lemlist | hardened | `[A-Za-z0-9]{32,128}` | 256 | **32-char lowercase hex** `[a-f0-9]`, no prefix (Basic-auth password) | authoritative: [trufflehog lemlist](https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/pkg/detectors/lemlist/lemlist.go) (`[a-f0-9]{32}`) | charset→hex `[a-f0-9]{32}`, radius→64, arm regex, entropy 3.0 | #133 |
| leptonai | hardened | `[A-Za-z0-9]{32,}` | 256 | unknown — docs show combined `workspace-id:secret` Bearer, no length/charset | conservative fallback ([docs.nvidia.com dgx-cloud/lepton](https://docs.nvidia.com/dgx-cloud/lepton/reference/api/); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #133 |
| lightstep | hardened | `[A-Za-z0-9]{40,80}` | 256 | unknown — docs specify only Bearer usage + 1-year expiry, no shape | conservative fallback ([docs.lightstep.com tokens-and-keys](https://docs.lightstep.com/docs/tokens-and-keys); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #133 |
| livekit | hardened | `[A-Za-z0-9]{10,16}` | 256 | key `API`+12 base57; secret = base62(32 bytes) = **43–45** chars `[0-9A-Za-z]` | authoritative: [livekit/protocol secret.go](https://github.com/livekit/protocol/blob/main/utils/secret.go) + guid/id.go (`APIKeyPrefix="API"`, Size=12; RandomSecret base62 of 32 bytes) | key→`API[A-Za-z0-9]{12}`, secret→`{43,45}` (**not** {43}-only — base62 yields 43/44/45), radius→64, arm regex, entropy 3.5 | #133 |
| mailtrap | hardened | `[A-Za-z0-9]{32,80}` | 256 | unknown — docs show only `Api-Token`/`Bearer` headers with placeholders | conservative fallback ([docs.mailtrap.io authentication](https://docs.mailtrap.io/developers/authentication); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #134 |
| mandiant | hardened | `[A-Za-z0-9]{32,64}` | 256 | unknown — OAuth client_credentials (Key ID + Secret), partner-only docs, no shape | conservative fallback ([google/mandiant-ti-client](https://github.com/google/mandiant-ti-client); no trufflehog detector) | radius→64, arm regex (`mandiant\|fireeye`), entropy 3.0 on both halves, length kept | #134 |
| marketo | hardened | `[A-Za-z0-9]{24,64}` | 256 | two-part: client_id **UUID v4** (hex), client_secret **32**-char base62 | authoritative: [Marketo REST-Sample-Code](https://github.com/Marketo/REST-Sample-Code/blob/master/java/Authentication/Identity/Identity.java) (secret 32-char); client_id is a standard hex UUID | id→UUID-v4 structural anchor, secret length 32 + entropy 3.5, radius→64, arm regex | #134 |
| mercurybank | hardened | `[A-Za-z0-9]{32,120}` | 256 | **prefix-anchored**: `mercury_(production\|sandbox)_…_yrucrem` self-describing token | authoritative: Mercury token shape (self-describing `secret-token:mercury_…_yrucrem`) | regex→prefix/suffix-anchored, **keyword gate removed** (prefix is the gate), no entropy | #134 |
| messagebird | hardened | `[A-Za-z0-9]{25,32}` | 256 | **25**-char `[A-Za-z0-9_-]` body, test keys carry `test_` prefix | authoritative: [trufflehog messagebird](https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/pkg/detectors/messagebird/messagebird.go) (`{25}`) | length→`{25}`, charset→`[A-Za-z0-9_-]`, radius→64, arm regex, entropy 3.5 | #134 |
| mistral | hardened | `[A-Za-z0-9]{32}` | 256 | unknown — no prefix/length/charset published (the `sk-` claim was an OpenAI conflation) | conservative fallback ([docs.mistral.ai api-keys](https://docs.mistral.ai/admin/security-access/api-keys); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept (not pinned on a guess) | #134 |
| modeanalytics | hardened | `[A-Za-z0-9]{16,80}` | 256 | two-part token+secret, **24-char hex** documented example (`[a-fA-F0-9]`) | authoritative: [mode.com discovery-api/signature-tokens](https://mode.com/developer/discovery-api/signature-tokens/) (24-hex example) | charset→hex `[a-fA-F0-9]{16,64}`, radius→64, arm regex, entropy 3.0 | #134 |
| monsterapi | hardened | `[A-Za-z0-9]{40,80}` | 256 | unknown — Bearer token, docs show only `YOUR_BEARER_TOKEN` | conservative fallback ([docs.monsterapi.ai authentication](https://docs.monsterapi.ai/authentication-using-api-keys); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #134 |
| nearrpc | hardened | `[A-Za-z0-9]{32,64}` | 256 | unknown — docs specify only transmission (Bearer/`?apiKey=`/`x-api-key`), no shape | conservative fallback ([docs.fastnear.com rpc-api](https://docs.fastnear.com/docs/rpc-api); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #134 |
| onesignal | hardened | `[A-Za-z0-9]{48}` | 256 | legacy REST key = **lowercase-hex UUID**; v2 token = `os_v2_app_` + base32 | authoritative: [trufflehog onesignal](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/onesignal/onesignal.go) (UUIDPattern) | legacy regex→hex-UUID layout (fixes wrong 48-alnum shape), v2 prefix-anchored, radius→64, arm regex, entropy 3.0 | #134 |
| opslevel | hardened | `[A-Za-z0-9]{40,64}` | 256 | no prefix, mixed-case alnum; only a **36**-char example documented | authoritative: [docs.opslevel.com package-versions](https://docs.opslevel.com/docs/package-versions) (36-char example); no trufflehog detector | radius→64, arm regex, entropy 3.0, **lowered** floor `{40,64}`→`{36,64}` (recall fix) | #134 |
| oraclecloud | hardened | `[A-Za-z0-9]{32,128}` | 256 | unknown — OCI Auth Token shown only obfuscated, no length/charset/prefix | conservative fallback ([Oracle OCI auth-token docs](https://docs.oracle.com/en-us/iaas/Content/Registry/Tasks/registrygettingauthtoken.htm); no trufflehog detector) | radius→64, arm regex (`oci\|oraclecloud`/`ocid1.`), entropy 3.0, length kept | #134 |
| parabola | hardened | `[A-Za-z0-9]{32,80}` | 256 | unknown — docs cover only third-party connection auth, not the issued-key shape | conservative fallback ([parabola.io api docs](https://parabola.io/docs/product/integration/api); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #134 |
| pardot | hardened | `[A-Za-z0-9]{18,256}` | 256 | two-part: BU ID **`0Uv`+18 chars**; access token `00D<orgid>!<tail>` (incl. `._-`) | authoritative: [Pardot auth docs](https://developer.salesforce.com/docs/marketing/pardot/guide/authentication.html) (BU ID `0Uv`, 18 chars) | BU→`0Uv` prefix-anchored, token→`00D`-anchored real Salesforce charset (fixes recall bug: old regex excluded `!._`), radius→64, arm regex, entropy 3.5 | #134 |
| paylocity | hardened | `[A-Za-z0-9]{32,64}` | 256 | client_id **32-char lowercase hex** (documented); client_secret undocumented | authoritative: [developer.paylocity.com authentication](https://developer.paylocity.com/integrations/reference/authentication) (id 32-hex example) | radius→64, arm regex, entropy 3.0 on both halves, length kept (secret undocumented) | #134 |
| planetscale | hardened | `[A-Za-z0-9]{32,64}` | 256 | two-part: token ID `[a-z0-9]{12}`, secret `pscale_tkn_`+`[A-Za-z0-9_]{43}` | authoritative: [trufflehog planetscale](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/planetscale/planetscale.go) | ID prefix-anchored (`pscale_(oauth\|tkn)_`), bare-secret half gets entropy 3.5, radius→64, arm regex | #134 |
| planhat | hardened | `[A-Za-z0-9]{32,64}` | 256 | unknown — docs cover token generation only, no length/charset/prefix (the "340-char" figure is unsubstantiated) | conservative fallback ([planhat.com authentication-limits](https://www.planhat.com/developers/api/authentication-limits); no trufflehog detector) | radius→64, arm regex, entropy 3.0, length kept | #134 |
| portswigger | hardened | `[A-Za-z0-9]{40,80}` | 256 | unknown — Burp Enterprise key shown only as a URL path segment, no shape | conservative fallback ([portswigger.net enterprise api docs](https://portswigger.net/burp/documentation/enterprise/api-documentation/create-api-user); no trufflehog detector) | radius→64, arm regex (`portswigger\|burp`), entropy 3.0, length kept | #134 |
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
