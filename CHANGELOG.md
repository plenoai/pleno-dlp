# Changelog

All notable changes to **pleno-dlp** (Go binary). Tracks tag-push
trusted publishing — `vX.Y.Z` tags trigger GoReleaser, archives, SLSA
build provenance, and syft SBOMs. The Python package on PyPI is
versioned independently (`py-vX.Y.Z`).

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Anything merged to `main` since v0.26.0.

## [0.26.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 29 (constants 425..439):
  Infura, QuickNode, Moralis, Blockfrost, Helius, TheGraph, OpenSea,
  Milvus, Beeceptor, Smee, Ory, Supertokens, Statsig, GrowthBook,
  DevCycle. Total now **433 secret + 4 PII = 437 detectors**.
  Web3 / blockchain RPC + APIs (Infura 32-hex project ID JSON-RPC
  eth_blockNumber on mainnet.infura.io/v3/<id>, QuickNode 32-64 hex
  endpoint token — unverified-by-default per-endpoint host required,
  Moralis 64+ alnum / JWT-shaped X-API-Key via /api/v2.2/dateToBlock
  on deep-index.moralis.io, Blockfrost mainnet/preprod/preview/testnet-
  prefixed project_id header via /api/v0/health on
  cardano-mainnet.blockfrost.io, Helius UUID-shape api-key query param
  via JSON-RPC getHealth on mainnet.helius-rpc.com, TheGraph 32-hex
  Studio key via /api/<key>/subgraphs/id/... on gateway.thegraph.com,
  OpenSea 32-hex X-API-KEY header via /api/v2/collections on
  api.opensea.io), vector DB (Milvus / Zilliz `db_`-prefixed token —
  unverified-by-default per-cluster `<cluster>.api.zillizcloud.com`
  host required), webhook proxy (Beeceptor 32+ alnum Bearer via
  /api/v1/projects on app.beeceptor.com, Smee.io channel URL —
  unverified-by-design URL is the credential), identity (Ory
  `ory_`-prefixed Bearer via /projects on api.console.ory.sh,
  SuperTokens 32+ alnum core api-key — unverified-by-default per-
  deployment self-hosted core URL required), and feature flags /
  experimentation (Statsig `console-`/`secret-` prefixed STATSIG-API-KEY
  header via /v1/get_id_lists on statsigapi.net, GrowthBook
  `secret_admin_`/`secret_user_` Bearer via /api/v1/features on
  api.growthbook.io, DevCycle `dvc_server_`/`dvc_mgmt_`/`dvc_client_`
  Authorization header via /v1/projects on api.devcycle.com). Four
  detectors are unverified-by-default (QuickNode, Milvus, Smee,
  SuperTokens) — each requires a per-endpoint / per-cluster /
  per-channel-URL / per-deployment value not present in the chunk;
  verify only fires when an apiBase override is supplied.

## [0.25.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 28 (constants 410..424):
  AlephAlpha, Inflection, CharacterAI, Hyperbolic, LeptonAI, NovitaAI,
  Kickbox, AbstractAPI, NeverBounce, Snov, Apollo, Lemlist, Authentik,
  Etherscan, Alchemy. Total now **418 secret + 4 PII = 422 detectors**.
  AI / inference (AlephAlpha Bearer via /users/me on api.aleph-alpha.com,
  Inflection Bearer via /v1/models on api.inflection.ai, CharacterAI
  `Token ` header via /chat/user on plus.character.ai, Hyperbolic JWT-
  shaped Bearer via /v1/models on api.hyperbolic.xyz, LeptonAI Bearer
  via /api/v1/workspace on dashboard.lepton.ai, NovitaAI `sk_`-prefixed
  Bearer via /v3/user on api.novita.ai), email validation / lead-gen
  (Kickbox `live_`/`test_` apikey query param via /v2/verify on
  api.kickbox.com, AbstractAPI 32-hex api_key query param via
  /v1/?api_key=... on emailvalidation.abstractapi.com, NeverBounce
  `secret_`/`private_` key query param via /v4/account/info on
  api.neverbounce.com, Snov OAuth2 client_id+client_secret pair via
  /v1/oauth/access_token client_credentials grant on api.snov.io —
  RawV2, Apollo X-Api-Key header via /v1/auth/health on api.apollo.io,
  Lemlist user_email+api_key Basic auth via /api/team on
  api.lemlist.com — RawV2), identity (Authentik 60+ alnum tokens —
  unverified-by-default per-tenant host `<tenant>.goauthentik.io` or
  self-hosted), and blockchain explorers / RPC (Etherscan 34-alnum
  apikey query param via /api?module=stats&action=ethsupply on
  api.etherscan.io, Alchemy 32-alnum URL-embedded JSON-RPC key via
  /v2/<key> eth_blockNumber on eth-mainnet.g.alchemy.com).

## [0.24.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 27 (constants 395..409):
  Writer, Filebase, Storj, MongoDBRealm, CloudBees, Codeship, Okteto,
  Freshsales, Copper, Trustpilot, SentinelOne, Gladly, HelpScout,
  Mailboxlayer, Hunter. Total now **403 secret + 4 PII = 407 detectors**.
  Frontier-AI (Writer Bearer via /v1/models on api.writer.com), storage
  / DBaaS (Filebase paired access_key+secret_key — unverified-by-default
  S3 SigV4 needs bucket+region — RawV2, Storj DCS access grant — unverified-
  by-default per-satellite host, MongoDBRealm UUID-shape API key —
  unverified-by-default per-app id), DevOps / CI (CloudBees paired
  user_id+api_token Basic auth — unverified-by-default per-controller
  host — RawV2, Codeship paired username+password Basic auth via /v2/auth
  on api.codeship.com — RawV2, Okteto Bearer via /api/v1/users/me on
  cloud.okteto.com), CRM / sales (Freshsales `Token token=` header —
  unverified-by-default per-domain `<domain>.myfreshworks.com`, Copper
  paired user_email+access_token via /developer_api/v1/account on
  api.copper.com with X-PW-AccessToken / X-PW-Application / X-PW-UserEmail
  headers — RawV2), reviews (Trustpilot apikey query param via
  /v1/business-units on api.trustpilot.com), endpoint security
  (SentinelOne `ApiToken ` header — unverified-by-default per-management-
  console `<console>.sentinelone.net`), customer support (Gladly paired
  agent_email+api_token Basic auth — unverified-by-default per-org host —
  RawV2, HelpScout paired app_id+app_secret OAuth client_credentials via
  /v2/oauth2/token on api.helpscout.net — RawV2), email validation
  (Mailboxlayer access_key query param via /api/check on apilayer.net,
  Hunter.io api_key query param via /v2/account on api.hunter.io). Six
  detectors use `RawV2` for paired credentials. Seven detectors ship
  `apiBase` override hooks for unverified-by-design tenant / per-app
  hosts.

## [0.23.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 26 (constants 380..394):
  AI21Labs, OctoAI, PingOne, ForgeRock, KeyCloak, Marketo, Eloqua,
  Pardot, Kustomer, Freshchat, OracleCloud, IBMCloud, RingCentral,
  DialPad, SignalWire. Total now **388 secret + 4 PII = 392 detectors**.
  AI / inference (AI21Labs Bearer via /studio/v1/tokenize on
  api.ai21.com, OctoAI / OctoML Bearer via /v1/models on
  text.octoai.run), identity / SSO (PingOne worker app paired
  client_id+secret Basic auth via /as/token on auth.pingone.com — RawV2,
  ForgeRock Bearer via /am/json/serverinfo/version — unverified-by-
  default per-tenant `<tenant>.forgeblocks.com`, KeyCloak paired
  client_id+secret via /protocol/openid-connect/token — unverified-by-
  default per-deployment realm host — RawV2), marketing (Marketo paired
  client_id+secret via /identity/oauth/token — unverified-by-default
  per-munchkin host — RawV2, Eloqua paired client_id+secret Basic auth
  via /api/REST/2.0/system/user/current — unverified-by-default per-pod
  host — RawV2, Pardot business_unit_id+access_token Bearer +
  Pardot-Business-Unit-Id header via /api/v5/objects/account on
  pi.pardot.com — RawV2), customer messaging (Kustomer Bearer via
  /v1/users/current on api.kustomerapp.com, Freshchat Bearer via
  /v2/agents on api.freshchat.com), IaaS (OracleCloud OCI auth signature
  — unverified-by-default per-region tenancy host, IBMCloud IAM apikey
  grant via /identity/token on iam.cloud.ibm.com), comms / SMS
  (RingCentral paired client_id+secret Basic auth via /restapi/oauth/token
  on platform.ringcentral.com — RawV2, DialPad Bearer via /api/v2/users
  on dialpad.com, SignalWire paired project_id+token Basic auth via
  /api/laml/2010-04-01/Accounts — unverified-by-default per-space host
  `<space>.signalwire.com` — RawV2). Seven detectors use `RawV2` to
  surface the paired secret. Six detectors ship `apiBase` override hooks
  for unverified-by-design tenant / deployment / region hosts.

## [0.22.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 25 (constants 365..379):
  Shippo, EasyPost, TaxJar, Avalara, BambooHR, Paylocity, DeepSeek,
  MonsterAPI, FriendliAI, AppDynamics, ElasticAPM, Lightstep, EmailJS,
  Mailjet, Hasura. Total now **373 secret + 4 PII = 377 detectors**.
  Shipping / e-commerce (Shippo `shippo_(live|test)_` `ShippoToken`
  auth via /v1/addresses on api.goshippo.com — `shippo_live_` verified
  surfaces SeverityCritical via DefaultSeverity, EasyPost `EZAK`/`EZTK`
  Basic auth via /api/v2/api_keys on api.easypost.com, TaxJar Bearer
  via /v2/categories on api.taxjar.com, Avalara paired account+license
  Basic auth via /api/v2/utilities/ping on rest.avatax.com — RawV2),
  HR / payroll (BambooHR Basic auth — unverified-by-default per-tenant
  subdomain, Paylocity OAuth client_id+secret pair — unverified-by-
  default sandbox vs production gateway — RawV2), AI / inference
  (DeepSeek `sk-` Bearer via /v1/models on api.deepseek.com — keyword-
  gated to stay disjoint from OpenAI, MonsterAPI Bearer via /v1/health
  on api.monsterapi.ai, FriendliAI `flp_` Bearer via /v1/models on
  api.friendli.ai), observability / APM (AppDynamics paired
  client@account+secret — unverified-by-default per-controller host —
  RawV2, ElasticAPM Bearer — unverified-by-default per-deployment APM
  Server host, Lightstep Bearer via /public/v0.2/projects on
  api.lightstep.com), email / comms (EmailJS paired user_id+access_token
  Bearer via /api/v1.0/account on api.emailjs.com — RawV2, Mailjet
  paired 32-hex key+secret Basic auth via /v3/REST/myprofile on
  api.mailjet.com — RawV2), database / IaaS (Hasura admin secret —
  unverified-by-default per-project host `<project>.hasura.app`).
  Avalara, Paylocity, AppDynamics, EmailJS, Mailjet are paired-credential
  detectors using RawV2. BambooHR, Paylocity, AppDynamics, ElasticAPM,
  Hasura ship unverified-by-default (apiBase override required).
  2531 race-clean tests across 392 packages.

## [0.21.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 24 (constants 350..364):
  Braintree, Dwolla, Klarna, Lever, Greenhouse, Gusto, Deel, Rippling,
  PropelAuth, LambdaLabs, Anyscale, SambaNova, Baseten, Turso, Knock.
  Total now **358 secret + 4 PII = 362 detectors**. Payments
  (Braintree `access_token$<env>$<merchant>$<32 hex>` Bearer routed to
  api.braintreegateway.com vs api.sandbox.braintreegateway.com by the
  embedded env segment, Dwolla paired key+secret Basic auth via /token,
  Klarna paired username `PK<digits>_<8>` + password Basic auth via
  /payments/v1/sessions), HR / recruiting / payroll (Lever 40-hex Basic
  auth via /v1/users on api.lever.co, Greenhouse 40+ alnum Basic auth
  via /v1/users on harvest.greenhouse.io, Gusto Bearer via /v1/me on
  api.gusto.com, Deel Bearer via /rest/v2/users/me on api.letsdeel.com,
  Rippling Bearer via /platform/api/me on api.rippling.com), auth
  (PropelAuth Bearer via /api/backend/v1/end_user_api_keys/validate on
  auth.propelauth.com), AI / ML / GPU infra (LambdaLabs Basic auth with
  key as username via /api/v1/instance-types on cloud.lambdalabs.com,
  Anyscale `esct_` Bearer via /api/v2/users/me on console.anyscale.com,
  SambaNova Bearer via /v1/models on api.sambanova.ai, Baseten
  `Api-Key <key>` via /api/v1/models on app.baseten.co), DBaaS (Turso
  Bearer via /v1/auth/validate-token on api.turso.tech), notifications
  (Knock `sk_(test|live)_` Bearer via /v1/users on api.knock.app —
  `sk_live_` verified surfaces SeverityCritical via DefaultSeverity).
  Braintree, Dwolla, and Klarna are paired-credential detectors using
  RawV2. 2421 race-clean tests across 377 packages.

## [0.20.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 23 (constants 335..349):
  Shopify, Recurly, Chargebee, FastSpring, Gumroad, Snipcart, Gitea,
  Woodpecker, OctopusDeploy, Squadcast, Instana, Courier, Bandwidth,
  GetStream, Lark. Total now **343 secret + 4 PII = 347 detectors**.
  E-commerce / payments (Shopify `shp(at|ss|ca)_` Admin token —
  unverified-by-default per-shop host, Recurly 32-alnum Basic auth,
  Chargebee `(live|test)_` — unverified-by-default per-site host,
  FastSpring paired username+password Basic auth, Gumroad
  `?access_token=` query param, Snipcart Basic auth), VCS / CI
  (Gitea 40-hex `token <pat>` — unverified-by-default self-hosted host,
  Woodpecker CI Bearer — unverified-by-default self-hosted host,
  OctopusDeploy `API-<26 base32>` `X-Octopus-ApiKey` — unverified-by-
  default per-tenant host), observability (Squadcast Bearer, Instana
  `apiToken <key>` — unverified-by-default per-tenant host), comms /
  messaging (Courier `pk_(prod|test)_` Bearer, Bandwidth paired
  user+pass Basic auth, Lark / Feishu paired `cli_<id>` + secret JSON
  body), and analytics (GetStream paired api_key+api_secret HMAC —
  unverified-by-design). FastSpring, Bandwidth, Lark, and GetStream
  use `RawV2` to surface the paired secret. Six detectors ship `apiBase`
  overrides so verify can be exercised in tests but stays disabled in
  production until a host is supplied. 2316 race-clean tests across 362
  packages.

## [0.19.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 22 (constants 320..334):
  Nomic, Jina, Runway, MotherDuck, DoltHub, BetterStack, Dynatrace,
  AppSignal, ScoutAPM, Descope, Mandrill, CustomerIO, Iterable, Plivo,
  Paddle. Total now **328 secret + 4 PII = 332 detectors**. AI / ML
  infra (Nomic Atlas `nk-` Bearer, Jina AI `jina_` Bearer, Runway ML
  `key_` Bearer with `X-Runway-Version`), data warehouse / DBaaS
  (MotherDuck JWT Bearer, DoltHub `token <pat>`), observability
  (BetterStack/Logtail Bearer, Dynatrace `dt0c01.<id>.<secret>` —
  unverified-by-default per-tenant host, AppSignal 32-hex query-param
  auth, ScoutAPM paired agent_key + api_key Basic auth), auth (Descope
  management `K2` Bearer), email / messaging (Mandrill 22-char API key
  via JSON body, Customer.io paired site_id+api_key Basic auth,
  Iterable `Api-Key` header), telephony (Plivo paired `MA`/`SA` auth_id
  + token Basic auth), and payments (Paddle Billing
  `pdl_(live|sdbx)_apikey_` Bearer with sandbox host fallback).
  ScoutAPM, CustomerIO, and Plivo use `RawV2` to surface the paired
  secret. Dynatrace ships an `apiBase` override so verify can be
  exercised in tests but stays disabled in production until a tenant
  host is supplied. 2220 race-clean tests across 347 packages.

## [0.18.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 21 (constants 305..319):
  KeyCDN, Mailtrap, GetResponse, Amplitude, FullStory, Heap, Hotjar,
  Optimizely, Transifex, Crowdin, DocuSign, Qdrant, SurrealDB, Leaseweb,
  PostageApp. Total now **313 secret + 4 PII = 317 detectors**. CDN /
  IaaS (KeyCDN HTTP Basic auth, Leaseweb paired key+secret with
  `X-Lsw-Auth` header), email / transactional (Mailtrap `Api-Token`,
  GetResponse `X-Auth-Token: api-key`, PostageApp form `api_key`),
  product analytics (Amplitude paired key+secret HTTP Basic, FullStory
  `Authorization: Basic`, Heap `heap_` Bearer, Hotjar `hjar_` Bearer,
  Optimizely Bearer), localization (Transifex Basic with `api` user,
  Crowdin Bearer), e-signature (DocuSign JWT — unverified-by-default,
  per-environment hosts), vector DB (Qdrant Cloud `api-key` —
  unverified-by-default, per-cluster host), and DBaaS (SurrealDB Cloud
  Bearer JWT — unverified-by-default, per-instance host). Amplitude and
  Leaseweb use `RawV2` to surface the paired secret. DocuSign / Qdrant /
  SurrealDB ship `apiBase` overrides so verify can be exercised in tests
  but stays disabled in production until a host is supplied. 2115
  race-clean tests across 332 packages.

## [0.17.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 20 (constants 290..304):
  FirebaseCloudMessaging, APNs, Pushover, BranchIO, PusherBeams,
  Drata, Secureframe, OneTrust, Pipedrive, Close, DNSimple, NvidiaNGC,
  Airbrake, Materialize, BeyondIdentity. Total now **298 secret + 4
  PII = 302 detectors**. Mobile push (FirebaseCloudMessaging legacy
  server keys, APNs .p8 PEM, Pushover application tokens, Branch.io
  paired key+secret, PusherBeams 32-hex secrets), compliance /
  security (Drata, Secureframe, OneTrust), CRM (Pipedrive, Close.com),
  DNS (DNSimple), AI infra (NvidiaNGC `nvapi-` tokens), error tracking
  (Airbrake), database (Materialize Cloud `mzp_` app passwords), and
  identity / IAM (BeyondIdentity). APNs ships only the .p8 PEM and is
  unverified-by-design (issuer + key_id required for JWT issuance,
  distinct from AppStoreConnect because APNs targets push endpoints
  rather than store APIs). PusherBeams is distinct from PusherChannels
  — Beams is the push-notification SDK with separate instance + secret.
  OneTrust and BeyondIdentity use per-tenant hosts so verify requires
  apiBase override. Branch.io is paired key+secret using RawV2.

## [0.16.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 19 (constants 275..289):
  OVHCloud, EquinixMetal, Civo, Exoscale, BuddyCI, SemaphoreCI,
  JenkinsX, AssemblyAI, ElevenLabs, Deepgram, Front, CrispChat, Drift,
  Vanta, OneSignal. Total now **283 secret + 4 PII = 287 detectors**.
  IaaS / cloud (OVHCloud, EquinixMetal, Civo, Exoscale), CI / DevOps
  (BuddyCI, SemaphoreCI, JenkinsX), AI / ML (AssemblyAI, ElevenLabs,
  Deepgram), email / comms (Front, CrispChat, Drift), security /
  compliance (Vanta), and mobile push (OneSignal). OVHCloud and
  Exoscale ship unverified-by-design — both require HMAC-SHA1 query
  signing with material we won't reconstruct from a chunk. CrispChat
  is unverified-by-design because its (Identifier, Key) pair must be
  HTTP-Basic-encoded and the Identifier half is not always co-located.
  SemaphoreCI uses per-org hosts (`<org>.semaphoreci.com`) and
  JenkinsX uses per-installation hosts; both ship with apiBase
  override so verification fires only when the host is configured.
  Front uses JWT-shaped 3-segment tokens and is distinct from FrontEgg
  (different product, different shape — FrontEgg is a UUID
  client_id+secret pair). OneSignal accepts both the legacy 48-char
  alnum key and the new `os_v2_app_<base32>{50+}` v2 shape.

## [0.15.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 18 (constants 260..274):
  MercuryBank, LemonSqueezy, Schematic, Hyperline, Fattureincloud,
  VercelAIGateway, Gandi, Codefresh, Earthly, Spacelift,
  CouchbaseCapella, SlackUserToken, PusherChannels, Hetzner, Pumble.
  Total now **268 secret + 4 PII = 272 detectors**. MercuryBank
  surfaces SeverityCritical when verified (live banking access via
  api.mercury.com). SlackUserToken (xoxp-) is distinct from
  SlackBotToken (xoxb-) because xoxp- grants user-scope (act-as-user)
  which is broader than bot-scope. VercelAIGateway uses the `vck_`
  prefix and is distinct from the existing Vercel deploy-token
  detector (24-char alphanumeric, no prefix). Spacelift (per-account
  host <account>.app.spacelift.io required) and PusherChannels (HMAC
  scheme requires app_id + cluster) are unverified-by-default. The
  GoogleAIStudio candidate was dropped because Gemini API keys share
  the `AIza` prefix already covered by GCPAPIKey — substituted Gandi
  (registrar). The OpenAIProject candidate was dropped because
  `sk-proj-` is already covered by the existing OpenAI detector.

## [0.14.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 17 (constants 245..259):
  WorkOS, FrontEgg, Kinde, Hanko, GitHubFineGrained,
  AzureContainerRegistry, Quay, Replit, PostmarkAccount, Beehiiv, NS1,
  Perplexity, DeepInfra, XAI, GoCardless. Total now **253 secret + 4 PII
  = 257 detectors**. GitHubFineGrained is a separate type from GitHub
  because `github_pat_<82>` is structurally distinct from
  `ghp_/gho_/ghu_/ghs_/ghr_`. PostmarkAccount is distinct from Postmark
  (server token) because it grants account-wide scope. FrontEgg emits a
  paired client_id + client_secret detector via RawV2. GoCardless `live_`
  verified surfaces SeverityCritical (and verifies against the live host;
  `sandbox_` verifies against api-sandbox.gocardless.com). Kinde, Hanko,
  and AzureContainerRegistry are unverified-by-default — they require a
  per-tenant or per-registry host the chunk doesn't carry. Perplexity
  verifies via POST /chat/completions splitting token-good (400/422) from
  token-bad (401) without issuing a billable completion.

## [0.13.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 16 (constants 230..244):
  Webex, Tenable, Rapid7, CrowdStrike, Wiz, SonarQube, MailerLite,
  ActiveCampaign, Drip, BunnyCDN, Vimeo, Cloudinary, PingIdentity,
  Mux, Hookdeck. Total now **238 secret + 4 PII = 242 detectors**.
  Tenable, CrowdStrike, Mux, Cloudinary emit pair detectors (RawV2 carries
  the second half of the credential triple). Hookdeck `hookdeck_live_`
  surfaces SeverityCritical when verified. Wiz, ActiveCampaign, and
  PingIdentity are unverified-by-design — tenant / per-region host not
  predictable from the chunk. Verified detectors (Webex /v1/people/me,
  Rapid7 /idr/v1/users/me, SonarQube /api/authentication/validate,
  MailerLite /api/subscribers/me, Drip /v2/accounts, BunnyCDN /apikey,
  Vimeo /me, Hookdeck /sources, Mux /video/v1/assets,
  Cloudinary /v1_1/&lt;cloud&gt;/usage, Tenable /session, CrowdStrike
  /oauth2/token) all use read-only or auth-only endpoints.

## [0.12.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 15 (constants 215..229):
  AzureDevOps, Jenkins, GoCD, Bamboo, Smartsheet, Wrike, Productboard,
  Miro, Lucidchart, SonatypeNexus, AppStoreConnect, Bitrise,
  Browserstack, StabilityAI, CiscoMeraki. Total now
  **223 secret + 4 PII = 227 detectors**. Browserstack is a paired
  (username + access key) detector emitted via RawV2 — verified with
  HTTP Basic against /automate/plan.json. AzureDevOps verifies via
  /_apis/connectionData with HTTP Basic (empty user, PAT as password).
  Self-hosted shapes (Jenkins, GoCD, Bamboo, SonatypeNexus) and
  AppStoreConnect (.p8 PEM, needs issuer_id + key_id for JWT signing)
  are unverified-by-design — host or signing inputs not in the chunk.
  StabilityAI uses the `sk-` prefix that overlaps with OpenAI's shape;
  the `stability` keyword window plus base62-only suffix gating
  bound the false-positive rate. CiscoMeraki uses the
  `X-Cisco-Meraki-API-Key` header (idiomatic for the platform);
  Smartsheet, Wrike, Productboard, Miro, Lucidchart, and Bitrise all
  verify via Bearer-auth read-only endpoints.

  Swaps from the candidate list, with rationale:
  - **Asana** already covered (batch 4) → **Wrike** (alt workflow API).
  - **Auth0 M2M** would collide with existing Auth0 detector (batch 5)
    → **AzureDevOps** (identity / DevOps slot).
  - **TravisCI / CodeShip** ambiguous against existing CI coverage →
    **Bamboo** (Atlassian self-hosted CI, distinct from Confluence /
    Jira API tokens we already detect).
  - **Sumo Logic Source** would collide with existing SumoLogic →
    **CiscoMeraki** (network / security platform with no existing
    detector).
  - **Honeycomb Beeline** same shape window as existing Honeycomb →
    skipped, replaced by **AppStoreConnect**.
  - **HuggingFace Inference** already covered as HuggingFace →
    **StabilityAI** (frontier image-gen platform).
  - **JFrog Pipelines** would collide with existing JFrog →
    **SonatypeNexus** (distinct artifact-platform shape).
  - **Webex / Workspace ONE / Ping Identity / Beyond Identity** all
    deferred — identity slot taken by AzureDevOps; revisit in batch 16.

## [0.11.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 14 (constants 200..214):
  Akamai EdgeGrid, Fastly, Quip, Box, Zoho, Adyen, Wise, Razorpay,
  Mollie, MessageBird, Sinch, BackblazeB2, Wasabi, Stytch, Cloud66.
  Total now **208 secret + 4 PII = 212 detectors**. Razorpay (key id +
  secret) and BackblazeB2 (key id + app key) emit pair detectors via
  RawV2. Razorpay live, Mollie live, and Stytch live surface
  SeverityCritical (production payment / production identity scope).
  Akamai (HMAC signing scheme), Zoho (region-specific OAuth host),
  Adyen (env-bound endpoint), Sinch (project_id required), BackblazeB2
  / Wasabi (multi-region S3-compat clones), and Stytch (project_id
  required) are unverified-by-design — verification would either need
  state we can't infer from the chunk or trigger destructive write
  paths. Verified detectors (Fastly /tokens/self, Quip
  /1/users/current, Box /2.0/users/me, Wise /v2/profiles, Razorpay
  /v1/items, Mollie /v2/methods, MessageBird /contacts, Cloud66
  /3/account.json) all use read-only endpoints with provider-idiomatic
  auth headers (Fastly-Key, AccessKey, Bearer, Basic).

### Fixed

- `engine.engineRecordingSink` (test fixture) is now concurrent-safe;
  closes an intermittent `-race` flake in
  `TestRunWithStats_CountsChunksBytesFindings` introduced in v0.6.0.

## [0.10.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 13 (constants 185..199):
  Aiven, YugabyteCloud, CockroachCloud, Fauna, Tinybird,
  ClickHouseCloud, Neon, GitLabPipeline, ArgoCD, TektonHub, Spinnaker,
  ConstantContact, Vonage, Workato, AikidoSecurity. Total now
  **193 secret + 4 PII = 197 detectors**. Vonage and ClickHouseCloud
  emit pair detectors (RawV2 carries the second half). Self-hosted CI
  surfaces (ArgoCD, TektonHub, Spinnaker) are unverified-by-design —
  per-tenant Gate-API host not predictable. GitLabPipeline trigger
  tokens are unverified by design too: probing would actually start
  a pipeline (destructive side effect). Swaps from the original list:
  Buildkite Agent → Spinnaker (Buildkite already covered),
  GitLabRunner → AikidoSecurity (`glrt-` already in GitLabDeploy
  regex), Snyk Org → Workato (Snyk already covered). Sentry
  legacy DSN-with-secret and Pardot JWT skipped — both need careful
  disambiguation against existing detectors and were left for a
  follow-up batch.

## [0.9.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 12 (constants 170..184):
  SplunkHEC, ElasticCloud, LogzIO, Coralogix, Loggly, UptimeRobot,
  Pingdom, Honeybadger, Raygun, Statuspage, VictorOps, PagerTree,
  AWX, ConcourseCI, TeamCity. Total now **178 secret + 4 PII =
  182 detectors**. Self-hosted observability and CI surfaces
  (Splunk HEC, Elastic Cloud, AWX, ConcourseCI, TeamCity) are
  unverified-by-design — per-tenant host not predictable from the
  chunk. Swaps from the original list: DatadogAppKey → Pingdom
  (already covered by batch 7), Bugsnag → Raygun (already in batch
  6), NewRelic Insights → UptimeRobot (covered by existing newrelic
  detector via `NRII-` regex).

## [0.8.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 11 (constants 155..169):
  AnthropicAdmin, Pinecone, Weaviate, VoyageAI, Fireworks, Cerebras,
  GitHubApp, JFrog, Pendo, PostHog, SentryUser, CloudflareR2, Mapbox,
  Railway, Telnyx. Total now **163 secret + 4 PII = 167 detectors**.
  Anthropic Console admin keys, Cloudflare R2 access-key + secret pair,
  and Mapbox secret tokens surface as Critical even unverified (admin/
  destructive scope). Anthropic detector now skips `sk-ant-admin-` so
  the new AnthropicAdmin detector is the sole owner. PostHog is scoped
  to `phx_` personal API keys — `phc_` project keys are publishable by
  design. JFrog covers reference tokens (`cmVmdGtuO…` prefix); the
  identifier-aware JWT shape stays with the JWT detector. Mapbox
  deliberately ignores `pk.` public tokens. Swaps from the original
  list, with rationale: Together → Fireworks (Together exists), Modal
  /Replicate → Cerebras (both already in batch 9), GitHub fine-grained
  PAT → JFrog Artifactory (covered by existing github detector), NPM
  granular → Pendo (NPM exists), Heroku → Railway (Heroku exists).

## [0.7.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 10 (constants 140..154): OneLogin,
  JumpCloud, Twitch, Lacework, DroneCI, Harness, Sysdig, Lokalise, Pulumi,
  Coda, LoopsSo, AppCenter, Bitwarden, Resend, Helcim. Total now
  **148 secret + 4 PII = 152 detectors**. Bitwarden machine-account tokens
  and Helcim payment tokens surface as Critical even unverified (rotation
  is the only safe remediation). DroneCI is unverified-by-design (server
  URL tenant-specific). Bitwarden, the original list candidates Auth0
  Management and Klaviyo Private were swapped because both already exist
  in earlier batches under the same shapes.

## [0.6.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 9 (constants 125..139): ClickUp,
  Monday, Trello, Gitter, LaunchNotes, Paperspace, RunPod, Modal,
  Linode, Vultr, Scaleway, UpstashRedis, PlanetScale, Clerk, Supabase.
  Total now **133 secret + 4 PII = 137 detectors**. PlanetScale service
  tokens, Clerk `sk_live_`, and Supabase `service_role` JWTs surface as
  Critical (admin-equivalent unverified). Trello / Modal / PlanetScale
  emit pair detectors (RawV2 carries the second half of the credential).
- **`--include-detectors` / `--exclude-detectors`** scoping flags for the
  `scan` subcommand. Comma-separated, case-insensitive, validated against
  the live registry — typos error out instead of silently producing zero
  findings. Custom rules (`--rules`) pass through unfiltered.
- **End-of-scan summary** on stderr: `scanned N chunk(s), B byte(s),
  F finding(s) in T`. Suppress with `--quiet`. Powered by a new
  `engine.Stats{Chunks,Bytes,Findings,Duration}` struct returned from
  the new `Engine.RunWithStats()` API; `Engine.Run()` is unchanged for
  back-compat. Counters are atomic so the snapshot is safe to read
  during a scan.

### Fixed

- Dedup key now incorporates the stdin label, so two distinct stdin scans
  with different `--label` values no longer collapse a shared secret into
  a single finding.

## [0.5.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 8 (constants 110..124):
  Redis URL, Postgres URL, MySQL URL, MongoDB URI, RabbitMQ AMQP,
  Kafka SASL, basic-auth URL, SMTP URL, Adobe.io,
  Docker Hub PAT, GitHub Container Registry, AWS S3 presigned URL,
  GCS signed URL, Azure SQL connection string, kubeconfig.
  Total now **118 secret + 4 PII = 122 detectors**.
- **Engine concurrency benchmarks** (`pkg/engine/bench_test.go`):
  - `BenchmarkScan_ColdPath` (concurrency 1/4/8/16) for sizing
    `--concurrency` against real hardware.
  - `BenchmarkKeywordMatch` to isolate the prefilter cost — every
    chunk pays this regardless of detector hit rate.

### Changed

- URI-shaped detectors (redis, postgres, mysql, mongodb, rabbitmq,
  smtp, basicauth) populate `Raw` with the password span and `RawV2`
  with the full URI so operators can rotate without exposing the
  rest of the connection string.

## [0.4.0] — 2026-05-08

### Added

- **15 more secret detectors** — batch 7 (constants 95..109): AlibabaCloud,
  AzureApp, Databricks, DatadogAppKey, DopplerCLI, Freshdesk,
  GCPIDToken, HashiCorpCloud, LaunchDarklyRelay, Ngrok, Opsgenie,
  Snowflake, TencentCloud, TerraformCloudTeam, Zendesk. Total now
  **103 secret + 4 PII = 107 detectors**.
- **Per-host verify rate limiter** (`pkg/verify`) — `--verify-rps`
  (default 10) installs a `RateLimitedTransport` as
  `http.DefaultTransport`. Every detector that uses the default
  client is rate-limited automatically without per-detector
  refactoring. `--verify-rps 0` disables limiting.
- **`.pre-commit-hooks.yaml`** so consumers can adopt pleno-dlp via
  pre-commit with one block in `.pre-commit-config.yaml`.
- **`docs/recipes/`** — GitHub Actions, GitLab CI, pre-commit, and
  allowlist-pattern recipes.

## [0.3.0] — 2026-05-08

### Added

- **31 more secret detectors** — batches 5 (15) + 6 (15) + the
  built-in generic high-entropy detector. Total now **88 secret
  detectors**:
  - Batch 5 (61..75): AzureAD, Telegram, Shodan, VirusTotal,
    Doppler, Vault, Algolia, Airtable, Grafana, LaunchDarkly,
    Auth0, Buildkite, CircleCI, Snyk, Spotify
  - Batch 6 (80..94): AWSSession, AzureSAS, GCPOAuth, GCPAPIKey,
    BitbucketServer, GitLabDeploy, Codecov, Rollbar, Bugsnag,
    SumoLogic, Honeycomb, Tailscale, Figma, Zoom, Klaviyo
  - Constant 13 (`GenericHighEntropy`): catch-all that fires on
    20–128 char runs scoring ≥ 4.0 bits/byte Shannon entropy when
    a credential keyword sits within 256 bytes
- **4 PII detectors** with `finding_class="pii"`:
  - PIIEmail (RFC5322 conservative shape with TLD requirement)
  - PIIUSSSN (xxx-xx-xxxx, rejects reserved blocks)
  - PIICreditCard (Luhn-validated with network labelling)
  - PIIIBAN (mod-97 validated with per-country length table)
- **Allowlist** (`pkg/engine/allowlist.go`) — `--allowlist <path>`
  plus auto-discovery of `.pleno-allow.json`. Match by detector
  type, raw literal, raw regex, and path glob (AND).
- **Stdin source** — `pleno-dlp scan stdin` reads `os.Stdin`,
  `--label` overrides the pseudo-path. TTY guard prevents silent
  blocking on keyboard input.
- **`detectors list` introspection** — `--format table|json|names`,
  output deterministic across runs (sorted by type), powered by the
  same registry the scanner uses.
- **Shell completions** — `pleno-dlp completion <bash|zsh|fish|powershell>`.
- **CHANGELOG.md**, refreshed README with full coverage matrix and
  recipes.

### Changed

- README detector matrix replaced with class-grouped table (77+
  detectors don't fit a per-row spec table).
- Default severity for the four PII types is Medium — information
  leak severity vs the High default for unverified credentials.

## [0.2.0] — 2026-05-08

### Added

- **57 secret detectors** ported from trufflehog's surface, each with
  `Keywords` / `FromData` / `Type` / `Verify`:
  - **Cloud / infra** — AWS, GCP service-account, Azure storage key,
    DigitalOcean, Cloudflare, Heroku, Render, Fly.io, Vercel, Netlify,
    Terraform Cloud, Dropbox
  - **VCS / dev tooling** — GitHub PAT, GitLab PAT, Bitbucket Cloud,
    npm, PyPI, Hugging Face, Postman, Atlassian, Jira, Confluence
  - **AI** — OpenAI, Anthropic, Cohere, Replicate, Mistral, Groq,
    OpenRouter, Together
  - **Comms / SaaS** — Slack bot tokens, Slack webhooks, Discord,
    Twilio, SendGrid, Mailgun, Mailchimp, Brevo, Postmark, Notion,
    Linear, Asana, Mixpanel, Segment, Okta, HubSpot, Intercom,
    Salesforce refresh
  - **Observability** — Datadog, Sentry, New Relic, PagerDuty
  - **Payments / data** — Stripe, Square, PayPal, Plaid,
    MongoDB Atlas
  - **Format-shaped** — JWT, PEM private keys
- **Decoder pipeline** (`pkg/decoder`) — base64 (std + url-safe + raw),
  percent-encoding, hex. Decoded variants are scanned alongside the
  raw chunk; ExtraData["decoded_from"] marks which decode produced
  the hit.
- **Archive walker** (`pkg/archive`) — zip, tar, tar.gz, gzip.
  Recursive expansion with depth cap (4) and per-entry size cap
  (50 MiB) to defuse zip bombs. ExtraData["archive_path"] travels
  with the finding.
- **Custom rule loader** (`pkg/detectors/custom`) — JSON rules with
  `keywords`, `regex`, optional `entropy_min`, `severity`, and
  `verify_url` + `verify_header` (with `{{ .Secret }}` substitution).
- **Severity classification** — `info` / `low` / `medium` / `high` /
  `critical`. Default model: verified ⇒ critical, generic / JWT /
  PEM unverified ⇒ medium, explicit detectors unverified ⇒ high.
  `--fail-on <severity>` gates CI exit code.
- **Allowlist** (`pkg/engine/allowlist.go`) — `--allowlist <path>` and
  auto-discovery of `.pleno-allow.json` from cwd. Match by detector
  type, raw literal, raw regex, and path glob (AND).
- **Git source** (`pkg/sources/git`) — walks a local repository's
  commit history. Flags: `--repo`, `--branch`, `--since`,
  `--max-depth`, `--include`, `--exclude`.
- **Stdin source** (`pkg/sources/stdin`) — `pleno-dlp scan stdin`
  reads a single chunk from `os.Stdin`. `--label` overrides the
  pseudo-path. `--max-bytes` caps buffered input (default 64 MiB).
  TTY guard prevents silent waiting on keyboard input.
- **Filesystem source globs** — `--include`, `--exclude`,
  `--max-size`, `--no-default-excludes`. Default excludes: `.git`,
  `.hg`, `.svn`, `node_modules`, `vendor`, `target`, `dist`,
  `build`, `__pycache__`, `.venv`, `.tox`.
- **SARIF 2.1.0** output now satisfies GitHub Code Scanning ingest
  (rules array, partialFingerprints, semanticVersion, level
  per-severity).
- **JSON / table** outputs render the new severity field plus
  source-specific metadata (file path, repo+commit, stdin label).
- **GoReleaser pipeline** — `-trimpath`, LICENSE + README in
  archives, syft SBOMs, conventional-commit changelog grouping,
  SLSA build provenance via `actions/attest-build-provenance`,
  release attestations via `gh attestation verify`.

### Changed

- `pleno-secret-scanner` rebranded to `pleno-dlp` (unified
  DLP scanner consolidating secrets + PII).

## [0.1.0] — 2026-05-06

### Added

- Initial MVP: filesystem source + 5 detectors (AWS, GitHub PAT,
  Slack bot, OpenAI, Anthropic) + JSON / SARIF / table output +
  cobra `scan` CLI. 51 race-clean tests.

[Unreleased]: https://github.com/plenoai/pleno-dlp/compare/v0.26.0...HEAD
[0.26.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.26.0
[0.25.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.25.0
[0.24.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.24.0
[0.23.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.23.0
[0.22.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.22.0
[0.21.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.21.0
[0.20.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.20.0
[0.19.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.19.0
[0.18.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.18.0
[0.17.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.17.0
[0.16.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.16.0
[0.15.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.15.0
[0.14.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.14.0
[0.13.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.13.0
[0.12.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.12.0
[0.11.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.11.0
[0.10.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.10.0
[0.9.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.9.0
[0.8.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.8.0
[0.7.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.7.0
[0.6.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.6.0
[0.5.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.5.0
[0.4.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.4.0
[0.3.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.3.0
[0.2.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.2.0
[0.1.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.1.0
