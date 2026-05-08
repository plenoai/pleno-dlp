// Package detectors defines the trufflehog-compatible Detector interface and
// the Result shape returned to the engine. Concrete detectors live under
// pkg/detectors/<provider>/ and self-register in registry.go via init().
package detectors

import "context"

// DetectorType is a stable identifier for each detector. Values are stable
// across releases; new detectors get a new value, never reuse retired ones.
type DetectorType int32

const (
	Unknown DetectorType = iota
	AWS
	GCPServiceAccount
	AzureStorageKey
	GitHub
	GitLab
	SlackBotToken
	SlackWebhook
	OpenAI
	Anthropic
	Stripe
	JWT
	PrivateKeyPEM
	GenericHighEntropy
	// New constants are appended below — values are wire-stable, never reorder.
	Datadog
	NPM
	PyPI
	HuggingFace
	Cloudflare
	SendGrid
	Twilio
	DigitalOcean
	Sentry
	MongoDBAtlas
	HubSpot
	SalesforceRefresh
	NewRelic
	PagerDuty
	Postman
	Mailgun
	TerraformCloud
	Vercel
	Netlify
	Heroku
	Render
	FlyIO
	Atlassian
	Notion
	Linear
	Asana
	Mixpanel
	Segment
	Brevo
	Mailchimp
	Postmark
	Okta
	// batch 4 — appended in wire-stable order; never reorder.
	Jira
	Confluence
	BitbucketCloud
	Square
	PayPal
	Plaid
	Discord
	Cohere
	Replicate
	Mistral
	Groq
	Intercom
	OpenRouter
	Together
	Dropbox
	// batch 5 — appended in wire-stable order; never reorder.
	AzureAD
	Telegram
	Shodan
	VirusTotal
	Doppler
	Vault
	Algolia
	Airtable
	Grafana
	LaunchDarkly
	Auth0
	Buildkite
	CircleCI
	Snyk
	Spotify
	// PII class — appended in wire-stable order; never reorder. PII
	// detectors set ExtraData["finding_class"]="pii" so downstream
	// callers can route by class (rotate-the-token logic for secrets vs
	// access-control logic for PII).
	PIIEmail
	PIIUSSSN
	PIICreditCard
	PIIIBAN
	// batch 6 — appended in wire-stable order; never reorder. Secret
	// detectors land after the PII block because the wire format is
	// append-only — even though PII is a different finding class,
	// reusing values 80+ for non-PII detectors keeps existing PII
	// constants pinned at 76..79.
	AWSSession
	AzureSAS
	GCPOAuth
	GCPAPIKey
	BitbucketServer
	GitLabDeploy
	Codecov
	Rollbar
	Bugsnag
	SumoLogic
	Honeycomb
	Tailscale
	Figma
	Zoom
	Klaviyo
	// batch 7 — appended in wire-stable order, never reorder. Enterprise-
	// parity coverage: Alibaba/Tencent (regional clouds), Azure App Service
	// secrets distinct from AzureAD client secrets, Databricks PATs,
	// Datadog application keys (single-key surface), Doppler CLI tokens
	// (different scope+endpoint than service tokens), Freshdesk / Zendesk
	// support-platform tokens, GCP ID tokens, HashiCorp Cloud Platform,
	// LaunchDarkly relay-proxy tokens, ngrok / Opsgenie SRE tooling,
	// Snowflake JWT keypair auth, Terraform Cloud team tokens.
	AlibabaCloud
	AzureApp
	Databricks
	DatadogAppKey
	DopplerCLI
	Freshdesk
	GCPIDToken
	HashiCorpCloud
	LaunchDarklyRelay
	Ngrok
	Opsgenie
	Snowflake
	TencentCloud
	TerraformCloudTeam
	Zendesk
	// batch 8 — appended in wire-stable order, never reorder. Connection-
	// string and URL-embedded credentials (Redis/Postgres/MySQL/MongoDB/
	// RabbitMQ/Kafka/SMTP/HTTP-basic-auth) plus container-registry tokens
	// (Docker Hub PAT, GHCR), AWS S3 / GCS presigned URLs, Azure SQL
	// connection strings, kubeconfig files, and Adobe.io key+secret pairs.
	Redis
	Postgres
	MySQL
	MongoDB
	RabbitMQ
	Kafka
	BasicAuth
	SMTP
	AdobeIO
	DockerHub
	GHCR
	AWSS3PresignedURL
	GCSSignedURL
	AzureSQLConnString
	Kubeconfig
	// batch 9 — appended in wire-stable order, never reorder. Enterprise
	// SaaS leverage tokens not yet covered: project-management (ClickUp,
	// Monday, Trello), realtime chat (Gitter), release-notes (LaunchNotes),
	// alt-cloud GPU/IaaS (Paperspace, RunPod, Modal, Linode, Vultr,
	// Scaleway), edge-Redis (Upstash), DB platform (PlanetScale), auth
	// platform (Clerk), and BaaS service-role (Supabase). Pair detectors
	// here use RawV2: trello (key+token), modal (id+secret), planetscale
	// (token-id+secret).
	ClickUp
	Monday
	Trello
	Gitter
	LaunchNotes
	Paperspace
	RunPod
	Modal
	Linode
	Vultr
	Scaleway
	UpstashRedis
	PlanetScale
	Clerk
	Supabase
	// batch 10 — appended in wire-stable order, never reorder. Identity
	// + IT-management (OneLogin, JumpCloud), CI/CD (DroneCI, Harness),
	// observability + cloud-security (Lacework, Sysdig), localization
	// (Lokalise), IaC platform (Pulumi), docs/notes (Coda), email/comms
	// (LoopsSo, Resend), mobile-app platform (AppCenter), creator-platform
	// OAuth (Twitch), secrets-manager machine accounts (Bitwarden), and
	// payments (Helcim). Bitwarden + Helcim ship as SeverityCritical
	// because their leak surface is destructive money/secret access.
	OneLogin
	JumpCloud
	Twitch
	Lacework
	DroneCI
	Harness
	Sysdig
	Lokalise
	Pulumi
	Coda
	LoopsSo
	AppCenter
	Bitwarden
	Resend
	Helcim
	// batch 11 — appended in wire-stable order, never reorder. Frontier-model
	// admin keys (Anthropic Console), AI infra (Pinecone, Weaviate, VoyageAI,
	// Fireworks, Cerebras), GitHub Apps installation tokens (distinct from
	// PATs), JFrog Artifactory access tokens, Pendo integration JWTs,
	// PostHog project keys, Sentry user tokens, Cloudflare R2 access-key +
	// secret pair (S3-compatible), Mapbox secret tokens, Railway API tokens,
	// and Telnyx messaging API keys. AnthropicAdmin / CloudflareR2 / Mapbox
	// secret keys all surface SeverityCritical because they grant full
	// account-level scope on the issuing platform.
	AnthropicAdmin
	Pinecone
	Weaviate
	VoyageAI
	Fireworks
	Cerebras
	GitHubApp
	JFrog
	Pendo
	PostHog
	SentryUser
	CloudflareR2
	Mapbox
	Railway
	Telnyx
	// batch 12 — appended in wire-stable order, never reorder. Observability
	// + log-aggregator tokens (Splunk HEC, Elastic Cloud, Logz.io, Coralogix,
	// Loggly), uptime monitoring (UptimeRobot, Pingdom), error-tracking
	// (Honeybadger, Raygun), incident/status (Statuspage, VictorOps,
	// PagerTree), and CI/CD bearer tokens (AWX/Ansible Tower, Concourse CI,
	// TeamCity). Self-hosted CI/CD detectors (AWX, Concourse, TeamCity) and
	// per-customer-host SaaS (SplunkHEC, ElasticCloud) ship without Verify
	// because the host isn't in the chunk; keyword + shape gating bound
	// the false-positive rate.
	SplunkHEC
	ElasticCloud
	LogzIO
	Coralogix
	Loggly
	UptimeRobot
	Pingdom
	Honeybadger
	Raygun
	Statuspage
	VictorOps
	PagerTree
	AWX
	ConcourseCI
	TeamCity
	// batch 13 — appended in wire-stable order, never reorder. Modern
	// DBaaS platforms (Aiven, YugabyteCloud, CockroachCloud, Fauna,
	// Tinybird, ClickHouseCloud, Neon), CI/CD bearer tokens distinct from
	// shapes already handled (GitLabPipeline trigger UUID, ArgoCD JWT,
	// TektonHub, Spinnaker), email/marketing (ConstantContact), telephony
	// (Vonage), enterprise integration platforms (Workato, AikidoSecurity).
	// ClickHouseCloud is a key+secret pair (Raw + RawV2 like AWS/R2).
	// GitLabPipeline trigger tokens grant pipeline-execute scope on the
	// project, not full GitLab API access — distinct from existing GitLab
	// PAT/Deploy tokens.
	Aiven
	YugabyteCloud
	CockroachCloud
	Fauna
	Tinybird
	ClickHouseCloud
	Neon
	GitLabPipeline
	ArgoCD
	TektonHub
	Spinnaker
	ConstantContact
	Vonage
	Workato
	AikidoSecurity
	// batch 14 — appended in wire-stable order, never reorder. CDN/edge
	// (Akamai EdgeGrid, Fastly), productivity / docs (Quip, Box, Zoho),
	// payments / fintech (Adyen, Wise, Razorpay, Mollie), telephony / SMS
	// (MessageBird, Sinch), object storage clones of S3 (Backblaze B2,
	// Wasabi), identity (Stytch), and PaaS (Cloud66). Razorpay and
	// Backblaze ship as paired (key+secret) detectors using RawV2; all
	// others are single-token. Akamai, Zoho, Adyen, Sinch, Backblaze,
	// Wasabi, and Stytch are unverified-by-design — Akamai uses HMAC
	// signing rather than a token-bearing read endpoint, Zoho needs the
	// region-specific accounts.zoho.<tld>, Adyen / Stytch need
	// environment-bound endpoints, Backblaze / Wasabi require explicit
	// region+endpoint pairing, and Sinch needs a project_id we won't
	// guess from the chunk.
	Akamai
	Fastly
	Quip
	Box
	Zoho
	Adyen
	Wise
	Razorpay
	Mollie
	MessageBird
	Sinch
	BackblazeB2
	Wasabi
	Stytch
	Cloud66
	// batch 15 — appended in wire-stable order, never reorder. Identity /
	// DevOps (AzureDevOps), self-hosted CI / build (Jenkins, GoCD, Bamboo),
	// productivity / workflow (Smartsheet, Wrike, Productboard, Miro,
	// Lucidchart), build artifacts (SonatypeNexus), mobile / app distribution
	// (AppStoreConnect, Bitrise, Browserstack), generative AI (StabilityAI),
	// and network / security (CiscoMeraki). Self-hosted shapes (Jenkins,
	// GoCD, Bamboo, SonatypeNexus) are unverified-by-design — the host is not
	// in the chunk. AppStoreConnect ships only the .p8 PEM and is unverified
	// (issuer_id + key_id required for JWT issuance). Browserstack is a paired
	// username+access-key detector (RawV2). Live keys with explicit `live`
	// prefixes (Stripe, Mollie, Stytch) follow the existing Critical-on-
	// verify convention.
	AzureDevOps
	Jenkins
	GoCD
	Bamboo
	Smartsheet
	Wrike
	Productboard
	Miro
	Lucidchart
	SonatypeNexus
	AppStoreConnect
	Bitrise
	Browserstack
	StabilityAI
	CiscoMeraki
	// batch 16 — appended in wire-stable order, never reorder. Identity / SSO
	// (Webex, PingIdentity), security tooling (Tenable, Rapid7, CrowdStrike,
	// Wiz, SonarQube), email/marketing (MailerLite, ActiveCampaign, Drip),
	// CDN/storage/media (BunnyCDN, Vimeo, Cloudinary), video infra (Mux),
	// webhooks (Hookdeck). Wiz / ActiveCampaign / PingIdentity are
	// unverified-by-design — Wiz uses tenant-specific hosts
	// (api.<tenant>.app.wiz.io), ActiveCampaign needs <account>.api-us1.com,
	// and PingIdentity has per-region hosts (api.pingone.com / .eu / .asia /
	// .ca). Tenable / CrowdStrike / Mux / Cloudinary are paired (id+secret)
	// detectors using RawV2. Hookdeck `hookdeck_live_` matches surface
	// SeverityCritical when verified (handled by DefaultSeverity).
	Webex
	Tenable
	Rapid7
	CrowdStrike
	Wiz
	SonarQube
	MailerLite
	ActiveCampaign
	Drip
	BunnyCDN
	Vimeo
	Cloudinary
	PingIdentity
	Mux
	Hookdeck
	// batch 17 — appended in wire-stable order, never reorder. Identity / SSO
	// (WorkOS, FrontEgg, Kinde, Hanko), CI / DevOps / artifacts (GitHubFineGrained,
	// AzureContainerRegistry, Quay, Replit), email / comms (PostmarkAccount,
	// Beehiiv), DNS / edge (NS1), generative AI (Perplexity, DeepInfra, XAI),
	// payments (GoCardless). GitHubFineGrained is a separate type from GitHub
	// because the `github_pat_` prefix is structurally distinct from
	// `ghp_/gho_/ghu_/ghs_/ghr_` and warrants its own identity. PostmarkAccount
	// is distinct from Postmark (server token) because it grants account-wide
	// scope. AzureContainerRegistry is distinct from AzureApp/AzureAD because
	// it's a registry refresh token — different surface area. GoCardless live
	// vs sandbox prefixes follow the Stripe / Mollie / Stytch convention:
	// `live_` verified -> SeverityCritical (DefaultSeverity).
	WorkOS
	FrontEgg
	Kinde
	Hanko
	GitHubFineGrained
	AzureContainerRegistry
	Quay
	Replit
	PostmarkAccount
	Beehiiv
	NS1
	Perplexity
	DeepInfra
	XAI
	GoCardless
	// batch 18 — appended in wire-stable order, never reorder. Payments / banking
	// (MercuryBank, LemonSqueezy, Schematic, Hyperline, Fattureincloud), AI infra
	// (VercelAIGateway), CI / DevOps (Codefresh, Earthly, Spacelift), database
	// (CouchbaseCapella), comms / SaaS (SlackUserToken, PusherChannels, Pumble),
	// IaaS (Hetzner), and registrar (Gandi). MercuryBank surfaces SeverityCritical
	// when verified (live banking access). Spacelift / PusherChannels are
	// unverified-by-default — Spacelift uses per-account hosts and Pusher
	// requires HMAC signing with app_id + cluster not in the chunk.
	// SlackUserToken is distinct from SlackBotToken (xoxp- vs xoxb-) because
	// xoxp- grants user-scope (act-as-user) which is broader than bot-scope.
	// VercelAIGateway uses the `vck_` prefix and is distinct from the existing
	// Vercel deploy-token detector (24-char alphanumeric, no prefix).
	MercuryBank
	LemonSqueezy
	Schematic
	Hyperline
	Fattureincloud
	VercelAIGateway
	Gandi
	Codefresh
	Earthly
	Spacelift
	CouchbaseCapella
	SlackUserToken
	PusherChannels
	Hetzner
	Pumble
	// batch 19 — appended in wire-stable order, never reorder. IaaS / cloud
	// (OVHCloud, EquinixMetal, Civo, Exoscale), CI / DevOps (BuddyCI,
	// SemaphoreCI, JenkinsX), AI / ML (AssemblyAI, ElevenLabs, Deepgram),
	// email / comms (Front, CrispChat, Drift), security / compliance (Vanta),
	// and mobile push (OneSignal). OVHCloud / Exoscale / CrispChat are
	// unverified-by-design — OVH and Exoscale require HMAC signing, Crisp
	// needs the Identifier half of the (Identifier, Key) pair which is not
	// always co-located with the key. SemaphoreCI / JenkinsX use per-org /
	// per-installation hosts not in the chunk; verify only fires when an
	// apiBase override is supplied. Front uses JWT-shaped tokens distinct
	// from the existing FrontEgg client_id+client_secret pair (unrelated
	// products). OneSignal accepts both the 48-char legacy key and the
	// `os_v2_app_<base32>` v2 shape.
	OVHCloud
	EquinixMetal
	Civo
	Exoscale
	BuddyCI
	SemaphoreCI
	JenkinsX
	AssemblyAI
	ElevenLabs
	Deepgram
	Front
	CrispChat
	Drift
	Vanta
	OneSignal
	// batch 20 — appended in wire-stable order, never reorder. Mobile push
	// (FirebaseCloudMessaging, APNs, Pushover, BranchIO, PusherBeams),
	// compliance / security (Drata, Secureframe, OneTrust), CRM
	// (Pipedrive, Close), DNS (DNSimple), AI infra (NvidiaNGC), error
	// tracking (Airbrake), database (Materialize), and identity / IAM
	// (BeyondIdentity). APNs ships only the .p8 PEM and is unverified
	// (issuer + key_id required for JWT issuance, distinct from
	// AppStoreConnect because APNs JWTs target push endpoints rather
	// than App Store APIs). BranchIO is a paired key+secret detector
	// using RawV2. PusherBeams is distinct from PusherChannels — Beams
	// is the push-notification SDK with separate instance + secret.
	// OneTrust uses per-tenant hosts (`<tenant>.onetrust.com`) so verify
	// requires apiBase override. Drata / Secureframe verify against
	// public api hosts. NvidiaNGC tokens use the `nvapi-` prefix.
	FirebaseCloudMessaging
	APNs
	Pushover
	BranchIO
	PusherBeams
	Drata
	Secureframe
	OneTrust
	Pipedrive
	Close
	DNSimple
	NvidiaNGC
	Airbrake
	Materialize
	BeyondIdentity
	// batch 21 — appended in wire-stable order, never reorder. CDN / IaaS
	// (KeyCDN, Leaseweb), email (Mailtrap, GetResponse, PostageApp),
	// analytics (Amplitude, FullStory, Heap, Hotjar, Optimizely),
	// localization (Transifex, Crowdin), e-sign (DocuSign), vector DB
	// (Qdrant), DBaaS (SurrealDB). Amplitude and Leaseweb are paired
	// key+secret detectors using RawV2. DocuSign / Qdrant / SurrealDB are
	// unverified-by-default (per-tenant or per-cluster host requires
	// apiBase override). Heap server-side keys use the `heap_` prefix;
	// Hotjar uses `hjar_` prefix. Mailtrap tokens use a long alphanumeric
	// shape near the `mailtrap` keyword (verified via /api/accounts).
	KeyCDN
	Mailtrap
	GetResponse
	Amplitude
	FullStory
	Heap
	Hotjar
	Optimizely
	Transifex
	Crowdin
	DocuSign
	Qdrant
	SurrealDB
	Leaseweb
	PostageApp
	// batch 22 — appended in wire-stable order, never reorder. AI/ML infra
	// (Nomic, Jina, Runway), data warehouse / DBaaS (MotherDuck, DoltHub),
	// observability (BetterStack, Dynatrace, AppSignal, ScoutAPM), auth
	// (Descope), email / messaging (Mandrill, CustomerIO, Iterable),
	// telephony (Plivo), and payments (Paddle). CustomerIO and Plivo are
	// paired credentials (site_id+api_key, auth_id+auth_token) using
	// RawV2; ScoutAPM is also a paired (org_id, key) detector. Dynatrace
	// is unverified-by-default — tokens carry the public id segment but
	// the per-tenant host (`<env>.live.dynatrace.com`) isn't in the chunk,
	// so verify requires apiBase override.
	Nomic
	Jina
	Runway
	MotherDuck
	DoltHub
	BetterStack
	Dynatrace
	AppSignal
	ScoutAPM
	Descope
	Mandrill
	CustomerIO
	Iterable
	Plivo
	Paddle
	// batch 23 — appended in wire-stable order, never reorder. E-commerce /
	// payments (Shopify, Recurly, Chargebee, FastSpring, Gumroad, Snipcart),
	// VCS / CI (Gitea, Woodpecker, OctopusDeploy), observability (Squadcast,
	// Instana), comms / messaging (Courier, Bandwidth, Lark), and analytics /
	// activity (GetStream). Shopify carries its API token shape (`shpat_`,
	// `shpss_`, `shpca_`) but verify needs the per-shop `<shop>.myshopify.com`
	// host so it ships unverified-by-default with apiBase override. Chargebee,
	// Gitea, Woodpecker, OctopusDeploy, Instana, GetStream, FastSpring share
	// the same per-tenant / per-host constraint and follow the same pattern.
	// Bandwidth (account_id+token+secret), FastSpring (username+password), and
	// Lark (app_id+app_secret) are paired-credential detectors using RawV2.
	Shopify
	Recurly
	Chargebee
	FastSpring
	Gumroad
	Snipcart
	Gitea
	Woodpecker
	OctopusDeploy
	Squadcast
	Instana
	Courier
	Bandwidth
	GetStream
	Lark
	// batch 24 — appended in wire-stable order, never reorder. Payments
	// (Braintree paired access_token shape, Dwolla key+secret pair, Klarna
	// paired username+password Basic auth), HR / recruiting (Lever, Greenhouse,
	// Gusto, Deel, Rippling), auth (PropelAuth Bearer), AI / ML / GPU infra
	// (LambdaLabs, Anyscale, SambaNova, Baseten), DBaaS (Turso), and
	// notifications (Knock `sk_(test|live)_`). Braintree, Dwolla, and Klarna are
	// paired (RawV2 carries the secret half). LambdaLabs uses HTTP Basic auth
	// with the key as the username (no separate password). Knock follows the
	// Stripe / Mollie / Stytch live-prefix convention: `sk_live_` verified
	// surfaces SeverityCritical via DefaultSeverity. PropelAuth and Rippling
	// share the per-tenant-host concern but have public api hosts they can fall
	// back on (auth.propelauth.com, api.rippling.com), so verify ships enabled.
	Braintree
	Dwolla
	Klarna
	Lever
	Greenhouse
	Gusto
	Deel
	Rippling
	PropelAuth
	LambdaLabs
	Anyscale
	SambaNova
	Baseten
	Turso
	Knock
	// batch 25 — appended in wire-stable order, never reorder. Shipping /
	// e-commerce (Shippo, EasyPost, TaxJar, Avalara), HR / payroll (BambooHR,
	// Paylocity), AI / inference (DeepSeek, MonsterAPI, FriendliAI),
	// observability / APM (AppDynamics, ElasticAPM, Lightstep), email / comms
	// (EmailJS, Mailjet), and database / IaaS (Hasura). Avalara, Mailjet, and
	// EmailJS are paired-credential detectors using RawV2 (account+license,
	// api_key+api_secret, user_id+access_token). BambooHR / AppDynamics /
	// ElasticAPM / Hasura are unverified-by-default — each requires a
	// per-tenant / per-deployment / per-controller host that isn't in the
	// chunk; verify only fires when an apiBase override is supplied.
	// Paylocity is unverified-by-default for the same reason (sandbox vs
	// prod gateway). FriendliAI tokens use the `flp_` prefix; DeepSeek
	// reuses the OpenAI `sk-` shape so the deepseek keyword window keeps
	// the detector disjoint from OpenAI.
	Shippo
	EasyPost
	TaxJar
	Avalara
	BambooHR
	Paylocity
	DeepSeek
	MonsterAPI
	FriendliAI
	AppDynamics
	ElasticAPM
	Lightstep
	EmailJS
	Mailjet
	Hasura
	// batch 26 — appended in wire-stable order, never reorder. AI / inference
	// (AI21Labs, OctoAI), identity / SSO (PingOne, ForgeRock, KeyCloak),
	// marketing (Marketo, Eloqua, Pardot), customer messaging (Kustomer,
	// Freshchat), IaaS (OracleCloud, IBMCloud), and comms / SMS (RingCentral,
	// DialPad, SignalWire). RingCentral / SignalWire / Marketo / Eloqua /
	// Pardot use RawV2 for paired credentials. ForgeRock / KeyCloak / OracleCloud
	// are unverified-by-default — each requires a per-tenant / per-realm /
	// per-region host that isn't in the chunk; verify only fires when an
	// apiBase override is supplied.
	AI21Labs
	OctoAI
	PingOne
	ForgeRock
	KeyCloak
	Marketo
	Eloqua
	Pardot
	Kustomer
	Freshchat
	OracleCloud
	IBMCloud
	RingCentral
	DialPad
	SignalWire
	// batch 27 — appended in wire-stable order, never reorder. Frontier-AI
	// (Writer), storage / DBaaS (Filebase, Storj, MongoDBRealm), DevOps / CI
	// (CloudBees, Codeship, Okteto), CRM / sales (Freshsales, Copper),
	// reviews (Trustpilot), endpoint security (SentinelOne), customer support
	// (Gladly, HelpScout), and email validation (Mailboxlayer, Hunter).
	// CloudBees / Filebase / Storj / MongoDBRealm / Freshsales / SentinelOne /
	// Gladly are unverified-by-default — each requires a per-tenant /
	// per-bucket / per-app / per-realm host that isn't in the chunk; verify
	// only fires when an apiBase override is supplied. HelpScout / Copper
	// use RawV2 for paired credentials (app_id+app_secret, user_email+api_key).
	Writer
	Filebase
	Storj
	MongoDBRealm
	CloudBees
	Codeship
	Okteto
	Freshsales
	Copper
	Trustpilot
	SentinelOne
	Gladly
	HelpScout
	Mailboxlayer
	Hunter
	// batch 28 — appended in wire-stable order, never reorder. AI / inference
	// (AlephAlpha, Inflection, CharacterAI, Hyperbolic, LeptonAI, NovitaAI),
	// email validation / lead-gen (Kickbox, AbstractAPI, NeverBounce, Snov,
	// Apollo, Lemlist), identity (Authentik), and blockchain explorers /
	// RPC (Etherscan, Alchemy). Snov / Lemlist use RawV2 for the paired
	// secret. Authentik is unverified-by-default (per-tenant host
	// `<tenant>.goauthentik.io` not in the chunk); verify only fires when
	// an apiBase override is supplied.
	AlephAlpha
	Inflection
	CharacterAI
	Hyperbolic
	LeptonAI
	NovitaAI
	Kickbox
	AbstractAPI
	NeverBounce
	Snov
	Apollo
	Lemlist
	Authentik
	Etherscan
	Alchemy
	// batch 29 — appended in wire-stable order, never reorder. Web3 / blockchain
	// RPC + APIs (Infura, QuickNode, Moralis, Blockfrost, Helius, TheGraph,
	// OpenSea), vector DB (Milvus), webhook proxy (Beeceptor, Smee), identity
	// (Ory, Supertokens), feature flags / experimentation (Statsig, GrowthBook,
	// DevCycle). Smee / Supertokens / Milvus / QuickNode are unverified-by-
	// default — each requires a per-channel / per-deployment / per-cluster /
	// per-endpoint host that isn't in the chunk; verify only fires when an
	// apiBase override is supplied.
	Infura
	QuickNode
	Moralis
	Blockfrost
	Helius
	TheGraph
	OpenSea
	Milvus
	Beeceptor
	Smee
	Ory
	Supertokens
	Statsig
	GrowthBook
	DevCycle
	// batch 30 — appended in wire-stable order, never reorder. Realtime /
	// streaming (PubNub, LiveKit, AgoraIO, DailyCo), search (Meilisearch,
	// Typesense, Marqo), API gateway / webhook proxy (Kong, WebhookRelay,
	// RequestBin), SEO / marketing (Ahrefs, Semrush, June), enterprise
	// (Workday, Qualys). LiveKit / AgoraIO / Meilisearch / Typesense /
	// Marqo / RequestBin / Workday / Qualys are unverified-by-default —
	// each requires a per-deployment / per-host / per-tenant value
	// not present in the chunk; verify only fires when an apiBase
	// override is supplied.
	PubNub
	LiveKit
	AgoraIO
	DailyCo
	Meilisearch
	Typesense
	Marqo
	Kong
	WebhookRelay
	RequestBin
	Ahrefs
	Semrush
	June
	Workday
	Qualys
	// batch 31 — appended in wire-stable order, never reorder. AI / inference
	// (Nebius, DashScope, ModelScope, Dify, LobeHub), identity (FusionAuth,
	// Casdoor), DBaaS / search / DB cloud (EdgeDBCloud, PrismaData,
	// OpenSearchCloud, ChromaCloud), web3 (Biconomy), enterprise (SAPAriba,
	// OracleNetSuite), CI (TravisCI). LobeHub / FusionAuth / Casdoor /
	// EdgeDBCloud / OpenSearchCloud / Biconomy / SAPAriba / OracleNetSuite
	// are unverified-by-default — each requires a per-deployment /
	// per-tenant / per-account value not present in the chunk; verify
	// only fires when an apiBase override is supplied.
	Nebius
	DashScope
	ModelScope
	Dify
	LobeHub
	FusionAuth
	Casdoor
	EdgeDBCloud
	PrismaData
	OpenSearchCloud
	ChromaCloud
	Biconomy
	SAPAriba
	OracleNetSuite
	TravisCI
	// batch 32 — appended in wire-stable order, never reorder. AI / inference
	// (Watsonx), DevOps / artifact (Harbor), data integration (Fivetran,
	// Airbyte), exchanges (Coinbase, Bitfinex, Kraken), sales / CRM (Outreach,
	// SalesLoft, ZoomInfo, Sproutsocial), identity (Gigya), payments (MoonPay),
	// and Web3 RPC (NearRPC, PolygonRPC). Kraken / Gigya are paired-credential
	// detectors using RawV2 (api_key+api_secret). Harbor / Airbyte / NearRPC /
	// PolygonRPC / Gigya are unverified-by-default — each requires a per-
	// deployment / per-tenant / per-data-center / per-endpoint host that
	// isn't in the chunk; verify only fires when an apiBase override is
	// supplied. Watsonx tokens use the IAM `Bearer` shape; Outreach uses
	// OAuth bearer; SalesLoft uses Bearer; ZoomInfo verifies via
	// /authenticate. Coinbase API keys ship as paired (api_key+api_secret)
	// but the verify path is the v2 /user endpoint with HMAC-SHA256 signing
	// — we ship the unsigned-bearer fallback (HTTP 401 → unverified) for
	// safety since signing is timestamp-bound and risks key drift.
	Watsonx
	Harbor
	Fivetran
	Airbyte
	Coinbase
	Bitfinex
	Kraken
	Outreach
	SalesLoft
	ZoomInfo
	Gigya
	MoonPay
	NearRPC
	PolygonRPC
	Sproutsocial
	// batch 33 — appended in wire-stable order, never reorder. Social-media
	// scheduling (Buffer, Hootsuite), Web3 identity (MagicLabs), workflow /
	// automation (Pipedream, Make, N8N), accounting (SageIntacct), enterprise
	// CRM (MicrosoftDynamics, GainSight), marketing automation (Freshmarketer),
	// search infra (VespaCloud), competitive intelligence (SimilarWeb), and
	// security tooling (Vectra, Expel, BeyondTrust). MicrosoftDynamics /
	// VespaCloud / Vectra / BeyondTrust are unverified-by-design — each
	// requires a per-tenant / per-deployment / per-org host
	// (`<org>.crm.dynamics.com`, `<tenant>.vectra.ai`,
	// `<id>-services.beyondtrustcloud.com`, `<app>.vespa-cloud.com`) not in
	// the chunk; verify only fires when an apiBase override is supplied.
	// SageIntacct ships unverified because the auth surface is XML over a
	// shared session_id — bearer probes 4xx without a multi-credential
	// envelope.
	Buffer
	Hootsuite
	MagicLabs
	Pipedream
	Make
	N8N
	SageIntacct
	MicrosoftDynamics
	Freshmarketer
	VespaCloud
	SimilarWeb
	Vectra
	Expel
	BeyondTrust
	GainSight
	// batch 34 — appended in wire-stable order, never reorder. Cloud-AI
	// (VertexAI, RekaAI, AIHorde, OllamaCloud, RunwayML), customer-success
	// (Planhat, Vitally, ChurnZero, Totango, Sendoso), payments / fintech
	// (Paystack, Flutterwave), security tooling (Mandiant, AbnormalSec),
	// marketing automation (Ortto). VertexAI / Planhat / Totango are
	// unverified-by-default — each requires a per-project / per-tenant host
	// (`<region>-aiplatform.googleapis.com`, `<tenant>.planhat.com`,
	// `<tenant>.totango.com`) not in the chunk. Mandiant carries paired
	// key + secret-id (Raw/RawV2) and verifies via OAuth client_credentials.
	VertexAI
	RekaAI
	AIHorde
	OllamaCloud
	RunwayML
	Planhat
	Vitally
	ChurnZero
	Totango
	Sendoso
	Paystack
	Flutterwave
	Mandiant
	AbnormalSec
	Ortto
	// batch 35 — appended in wire-stable order, never reorder. KYC / identity
	// verification (Persona, Sumsub, Onfido, Jumio, Trulioo), email validation
	// (ZeroBounce, MailerSend), DevOps / observability (OpsLevel), mobile CI
	// (Codemagic), browser-testing (LambdaTest, SauceLabs, Browserless), LLM
	// observability / AI gateway (Helicone, Portkey, Langfuse). Sumsub /
	// Jumio / SauceLabs / Langfuse are paired-credential detectors using
	// RawV2 (key+secret, accountId+secret, username+access-key, public+secret).
	// LambdaTest is also paired (username+access-key). Onfido uses
	// `api_(live|sandbox)_us_` prefixes; Persona uses `persona_` prefix.
	// MailerSend tokens use the `mlsn.` prefix and JWT-shaped suffix.
	// Helicone uses `sk-helicone-` prefix; Portkey uses the `pk-` prefix
	// near a portkey keyword to disambiguate from other `pk-` issuers.
	Persona
	Sumsub
	Onfido
	Jumio
	Trulioo
	ZeroBounce
	MailerSend
	OpsLevel
	Codemagic
	LambdaTest
	SauceLabs
	Browserless
	Helicone
	Portkey
	Langfuse
	// batch 36 — appended in wire-stable order, never reorder. LLM
	// observability / experiment tracking (LangSmith, Wandb, CometML,
	// NeptuneAI, PromptLayer, ArizeAI), compliance (Hyperproof),
	// e-commerce (Etsy, Walmart, WooCommerce), customer support /
	// messaging (Missiveapp, LiveChat, HelpCrunch), edge serverless
	// (DenoDeploy), and zero-trust networking (Twingate). WooCommerce
	// is paired-credential (consumer_key + consumer_secret via RawV2).
	// Walmart / Twingate / LiveChat / HelpCrunch / Missiveapp / Etsy
	// keyword-anchor disambiguates broad token shapes.
	LangSmith
	Wandb
	CometML
	NeptuneAI
	PromptLayer
	ArizeAI
	Hyperproof
	Etsy
	Walmart
	WooCommerce
	Missiveapp
	LiveChat
	HelpCrunch
	DenoDeploy
	Twingate
	// batch 37 — appended in wire-stable order, never reorder. Data
	// platforms (DBTCloud), low-code / workflow (Tray, Retool), mobile
	// build (Expo), KYC / identity (Alloy, Veriff, IDnow), GRC /
	// compliance (AuditBoard), incident response / DORA (FireHydrant,
	// IncidentIO, Rootly, Sleuth), email / SMS (Sparkpost, SendPulse),
	// e-commerce (Squarespace). Tray / Retool / Squarespace / Alloy
	// keyword-anchor disambiguates broad token shapes; Sleuth /
	// FireHydrant / IncidentIO / Rootly use distinctive prefixes.
	DBTCloud
	Tray
	Retool
	Expo
	Alloy
	AuditBoard
	FireHydrant
	IncidentIO
	Rootly
	Sleuth
	Sparkpost
	SendPulse
	Veriff
	IDnow
	Squarespace
)

// Severity classifies a finding for triage. Output formatters map this to
// SARIF level / table glyph / JSON field. Values are stable across releases.
type Severity int8

const (
	SeverityUnknown  Severity = 0
	SeverityInfo     Severity = 1
	SeverityLow      Severity = 2
	SeverityMedium   Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

// String returns the lowercase wire form of a Severity. Unknown is rendered
// as "info" so legacy results without a Severity field don't surface as the
// literal "unknown" — that would falsely look like a triage failure.
func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "info"
	}
}

// Result is what a detector emits per match. Mirrors trufflehog's Result so
// detectors can be ported in either direction.
type Result struct {
	DetectorType    DetectorType
	Verified        bool
	VerificationErr error
	// Severity classifies the finding for triage. When zero (the default),
	// the engine derives one from Verified and DetectorType via DefaultSeverity.
	Severity Severity
	// Raw is the matched secret bytes. Never logged in plaintext.
	Raw []byte
	// RawV2 is a paired secret (e.g. AWS secret access key when Raw is the
	// access key id). Empty when single-secret.
	RawV2 []byte
	// Redacted is a safe-to-display rendering (prefix + ellipsis).
	Redacted  string
	ExtraData map[string]string
}

// DefaultSeverity assigns a severity when a detector hasn't picked one.
// Verified findings are Critical (a real, working credential is the highest-
// risk leak class). Unverified hits from explicit detectors are High.
// Generic high-entropy hits are Medium because false-positive rates are
// non-trivial. JWT / private key pem hits unverified are Medium for the
// same reason — finding the token doesn't confirm it's still active.
func DefaultSeverity(t DetectorType, verified bool) Severity {
	if verified {
		return SeverityCritical
	}
	switch t {
	case GenericHighEntropy:
		return SeverityMedium
	case JWT, PrivateKeyPEM:
		return SeverityMedium
	case PIIEmail, PIIUSSSN, PIICreditCard, PIIIBAN:
		// PII has no "verified" pathway — these are pattern matches with
		// no upstream API to confirm. Medium reflects information-leak
		// severity vs the High default for unverified credentials. PII
		// rotation isn't a thing; the appropriate response is access
		// control, redaction, or removal.
		return SeverityMedium
	default:
		return SeverityHigh
	}
}

// Detector is the trufflehog-compatible detector contract. Keywords gates the
// expensive FromData step: the engine skips chunks containing none of the
// returned strings (case-insensitive substring match).
type Detector interface {
	Keywords() []string
	FromData(ctx context.Context, verify bool, data []byte) ([]Result, error)
	Type() DetectorType
}

// Verifier is optionally implemented by detectors that can confirm a candidate
// secret with the upstream provider. Engine will call Verify only when the
// caller requested verification.
type Verifier interface {
	Verify(ctx context.Context, secret string) (bool, error)
}
