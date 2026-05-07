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
