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
| abnormalsec | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| activecampaign | pending | `[A-Za-z0-9]{60,80}` | 256 | — | — | — | — |
| ai21labs | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| aikidosecurity | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| airbrake | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| aiven | pending | `[A-Za-z0-9]{32,80}` | 256 | — | — | — | — |
| appdynamics | pending | `[A-Za-z0-9]{20,64}` | 256 | — | — | — | — |
| arduinocloud | pending | `[A-Za-z0-9]{32,80}` | 256 | — | — | — | — |
| arizeai | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| auditboard | pending | `[A-Za-z0-9]{32,64}` | 128 | — | — | — | — |
| authentik | pending | `[A-Za-z0-9]{60,}` | 256 | — | — | — | — |
| avalara | pending | `[A-Za-z0-9]{24,32}` | 256 | — | — | — | — |
| awx | pending | `[A-Za-z0-9]{40}` | 256 | — | — | — | — |
| bamboohr | pending | `[A-Za-z0-9]{40,64}` | 256 | — | — | — | — |
| bandwidth | pending | `[A-Za-z0-9]{10,32}` | 96 | — | — | — | — |
| beeceptor | pending | `[A-Za-z0-9]{32,}` | 256 | — | — | — | — |
| betterstack | pending | `[A-Za-z0-9]{24,40}` | 256 | — | — | — | — |
| beyondtrust | pending | `[A-Za-z0-9]{64,128}` | 256 | — | — | — | — |
| bitbucketcloud | pending | `[A-Za-z0-9]{32}` | 256 | — | — | — | — |
| bitbucketserver | pending | `[A-Za-z0-9]{40}` | 256 | — | — | — | — |
| box | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| buddyci | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| buffer | pending | `[A-Za-z0-9]{40,50}` | 96 | — | — | — | — |
| civo | pending | `[A-Za-z0-9]{50}` | 256 | — | — | — | — |
| clickhousecloud | pending | `[A-Za-z0-9]{32}` | 256 | — | — | — | — |
| coinbase | pending | `[A-Za-z0-9]{32}` | 256 | — | — | — | — |
| cometml | pending | `[A-Za-z0-9]{32,100}` | 256 | — | — | — | — |
| copper | pending | `[A-Za-z0-9]{32,128}` | 256 | — | — | — | — |
| customerio | pending | `[A-Za-z0-9]{20}` | 256 | — | — | — | — |
| customerly | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| deel | pending | `[A-Za-z0-9]{40,}` | 256 | — | — | — | — |
| dialpad | pending | `[A-Za-z0-9]{40,128}` | 256 | — | — | — | — |
| drip | pending | `[A-Za-z0-9]{32}` | 256 | — | — | — | — |
| dwolla | pending | `[A-Za-z0-9]{50,}` | 256 | — | — | — | — |
| earthly | pending | `[A-Za-z0-9]{40,120}` | 256 | — | — | — | — |
| elasticapm | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| eloqua | pending | `[A-Za-z0-9]{24,128}` | 256 | — | — | — | — |
| expel | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| fastspring | pending | `[A-Za-z0-9]{16,32}` | 256 | — | — | — | — |
| forter | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| freshmarketer | pending | `[A-Za-z0-9]{20,32}` | 256 | — | — | — | — |
| gainsight | pending | `[A-Za-z0-9]{32,64}` | 256 | — | — | — | — |
| gandi | pending | `[A-Za-z0-9]{24,80}` | 256 | — | — | — | — |
| greenhouse | pending | `[A-Za-z0-9]{40,}` | 256 | — | — | — | — |
| harbor | pending | `[A-Za-z0-9]{16,64}` | 96 | — | — | — | — |
| hasura | pending | `[A-Za-z0-9]{40,80}` | 256 | — | — | — | — |
| helpscout | pending | `[A-Za-z0-9]{32,128}` | 256 | — | — | — | — |
| hetzner | pending | `[A-Za-z0-9]{64}` | 256 | — | — | — | — |
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
