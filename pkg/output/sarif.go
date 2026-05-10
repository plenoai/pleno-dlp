package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
)

// SARIF 2.1.0 envelope. Field set chosen to satisfy the GitHub Code
// Scanning ingest, which is stricter than the spec — it requires
// `tool.driver.rules`, `partialFingerprints`, and `version` at the run
// level even though the spec marks them optional. Anything beyond that
// is here because it improves triage UX in the GitHub UI.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	InformationURI  string      `json:"informationUri,omitempty"`
	Version         string      `json:"version,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	Rules           []sarifRule `json:"rules"`
}

// sarifRule describes one detector. ruleId values in sarifResult must
// match an id in this list — GitHub Code Scanning rejects results whose
// rule is undeclared.
type sarifRule struct {
	ID                   string                  `json:"id"`
	Name                 string                  `json:"name"`
	ShortDescription     sarifMessage            `json:"shortDescription"`
	FullDescription      sarifMessage            `json:"fullDescription,omitempty"`
	HelpURI              string                  `json:"helpUri,omitempty"`
	DefaultConfiguration *sarifRuleConfiguration `json:"defaultConfiguration,omitempty"`
	Properties           *sarifRuleProperties    `json:"properties,omitempty"`
}

type sarifRuleConfiguration struct {
	Level string `json:"level,omitempty"`
}

type sarifRuleProperties struct {
	Tags     []string `json:"tags,omitempty"`
	Security string   `json:"security-severity,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

// sarifSink buffers results and writes the full SARIF document on Close.
// Buffering is required because SARIF is a single JSON object, not a
// stream. The mutex protects both the result slice and the per-rule
// activity map (which detectors actually fired this run).
type sarifSink struct {
	w           io.Writer
	mu          sync.Mutex
	results     []sarifResult
	seenRuleIDs map[string]struct{}
}

func newSARIFSink(w io.Writer) *sarifSink {
	return &sarifSink{
		w:           w,
		results:     make([]sarifResult, 0, 64),
		seenRuleIDs: make(map[string]struct{}),
	}
}

func (s *sarifSink) Emit(f engine.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := toSARIFResult(f)
	s.seenRuleIDs[r.RuleID] = struct{}{}
	s.results = append(s.results, r)
}

func (s *sarifSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc := sarifLog{
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:            "pleno-dlp",
				InformationURI:  "https://github.com/plenoai/pleno-dlp",
				SemanticVersion: "0.1.0",
				Rules:           rulesFor(s.seenRuleIDs),
			}},
			Results: s.results,
		}},
	}
	enc := json.NewEncoder(s.w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// rulesFor builds the rule descriptor list for every detector that fired
// at least one result this run. The list is sorted by id so consecutive
// runs over the same input produce byte-identical SARIF — important for
// downstream caches that key on document hash.
func rulesFor(seen map[string]struct{}) []sarifRule {
	out := make([]sarifRule, 0, len(seen))
	for id := range seen {
		out = append(out, ruleDescriptor(id))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ruleDescriptor returns metadata for one detector id. The map is
// intentionally hand-curated; auto-generating from DetectorType.String()
// loses the human-readable description GitHub renders in the UI.
func ruleDescriptor(id string) sarifRule {
	r := sarifRule{
		ID:                   id,
		Name:                 id,
		ShortDescription:     sarifMessage{Text: id + " secret leak"},
		HelpURI:              "https://github.com/plenoai/pleno-dlp",
		DefaultConfiguration: &sarifRuleConfiguration{Level: "error"},
		Properties: &sarifRuleProperties{
			Tags:     []string{"security", "secret"},
			Security: "9.0", // CVSSv3-shaped score; secrets are by definition critical.
		},
	}
	if d, ok := ruleDescriptions[id]; ok {
		r.ShortDescription = sarifMessage{Text: d}
	}
	return r
}

// ruleDescriptions maps DetectorType.String() values to a human-readable
// description GitHub Code Scanning surfaces in the rule pane. Falls back
// to a generic "<id> secret leak" when an entry is missing — adding new
// detectors does NOT require editing this map, but doing so improves UX.
var ruleDescriptions = map[string]string{
	detectors.AWS.String():                "AWS access key id with paired secret access key",
	detectors.GCPServiceAccount.String():  "GCP service account JSON key",
	detectors.AzureStorageKey.String():    "Azure storage account key",
	detectors.GitHub.String():             "GitHub personal access token or fine-grained PAT",
	detectors.GitLab.String():             "GitLab personal access token",
	detectors.SlackBotToken.String():      "Slack bot token (xoxb-)",
	detectors.SlackWebhook.String():       "Slack incoming webhook URL",
	detectors.OpenAI.String():             "OpenAI API key",
	detectors.Anthropic.String():          "Anthropic API key",
	detectors.Stripe.String():             "Stripe secret API key",
	detectors.JWT.String():                "JSON Web Token",
	detectors.PrivateKeyPEM.String():      "Private key (PEM-encoded RSA/EC/OPENSSH/...)",
	detectors.GenericHighEntropy.String(): "Generic high-entropy string near a credential keyword",
	detectors.DigitalOcean.String():       "DigitalOcean personal access token (dop_v1_)",
	detectors.Sentry.String():             "Sentry DSN (project ingest credential)",
	detectors.MongoDBAtlas.String():       "MongoDB Atlas programmatic API key pair (public + private)",
	detectors.HubSpot.String():            "HubSpot Private App access token (pat-)",
	detectors.SalesforceRefresh.String():  "Salesforce OAuth refresh token (5Aep861)",
	detectors.NewRelic.String():           "New Relic license / ingest / insert key",
	detectors.PagerDuty.String():          "PagerDuty REST API token",
	detectors.Postman.String():            "Postman API key (PMAK-)",
	detectors.Mailgun.String():            "Mailgun API key (legacy or new format)",
	detectors.TerraformCloud.String():     "Terraform Cloud / Enterprise user API token (atlasv1)",
	detectors.Vercel.String():             "Vercel API access token (24-char) near vercel keyword",
	detectors.Netlify.String():            "Netlify personal access token (nfp_)",
	detectors.Heroku.String():             "Heroku API token (UUID) near heroku keyword",
	detectors.Render.String():             "Render API key (rnd_)",
	detectors.FlyIO.String():              "Fly.io macaroon token (fm1_/fm2_)",
	detectors.Atlassian.String():          "Atlassian Cloud API token (24-char) near atlassian keyword",
	detectors.Notion.String():             "Notion integration token (secret_)",
	detectors.Linear.String():             "Linear personal API key (lin_api_)",
	detectors.Asana.String():              "Asana personal access token (1/<gid>/<hex>)",
	detectors.Mixpanel.String():           "Mixpanel service account credential pair (account.id + secret)",
	detectors.Segment.String():            "Segment write key (32-char) near segment keyword",
	detectors.Brevo.String():              "Brevo / Sendinblue API key (xkeysib-)",
	detectors.Mailchimp.String():          "Mailchimp API key (32-hex-us<dc>)",
	detectors.Postmark.String():           "Postmark server API token (UUID) near postmark keyword",
	detectors.Okta.String():               "Okta API token (00...) — tenant URL required to verify",
	detectors.Jira.String():               "Atlassian Jira API token (24-char) near jira keyword — unverified by design",
	detectors.Confluence.String():         "Atlassian Confluence API token (24-char) near confluence keyword — unverified by design",
	detectors.BitbucketCloud.String():     "Bitbucket Cloud access token (ATCTT3xFfGF0…) or app password near bitbucket keyword",
	detectors.Square.String():             "Square access token (EAAA…) or sandbox token (sq0atp-)",
	detectors.PayPal.String():             "PayPal REST client_id + client_secret pair (full account access)",
	detectors.Plaid.String():              "Plaid client_id + secret pair (linked-bank-account access)",
	detectors.Discord.String():            "Discord bot token (id.timestamp.hmac base64url segments)",
	detectors.Cohere.String():             "Cohere API key (40-char) near cohere keyword",
	detectors.Replicate.String():          "Replicate API token (r8_)",
	detectors.Mistral.String():            "Mistral AI API key (32-char) near mistral keyword",
	detectors.Groq.String():               "Groq Cloud API key (gsk_)",
	detectors.Intercom.String():           "Intercom access token (dG9rOg…)",
	detectors.OpenRouter.String():         "OpenRouter API key (sk-or-v1-)",
	detectors.Together.String():           "Together.ai API key (64-char hex) near together keyword",
	detectors.Dropbox.String():            "Dropbox short-lived (sl.) or app token near dropbox keyword",
	detectors.AzureAD.String():            "Azure AD (Entra ID) client secret + app id pair — unverified by design (tenant unknown)",
	detectors.Telegram.String():           "Telegram Bot API token (<bot_id>:<base64>)",
	detectors.Shodan.String():             "Shodan API key (32-char alphanumeric) near shodan keyword",
	detectors.VirusTotal.String():         "VirusTotal API key (64-char hex) near virustotal keyword",
	detectors.Doppler.String():            "Doppler service / personal token (dp.<scope>.…)",
	detectors.Vault.String():              "HashiCorp Vault token (hvs./hvb./s.) — unverified by design (server URL unknown)",
	detectors.Algolia.String():            "Algolia admin API key + application id pair near algolia keyword",
	detectors.Airtable.String():           "Airtable PAT (pat…) or legacy API key (key…) near airtable keyword",
	detectors.Grafana.String():            "Grafana service-account token (glsa_) — unverified by design (host unknown)",
	detectors.LaunchDarkly.String():       "LaunchDarkly access (api-) or SDK (sdk-) key",
	detectors.Auth0.String():              "Auth0 management API token (JWT-shaped) near auth0 keyword — unverified by design (audience unknown)",
	detectors.Buildkite.String():          "Buildkite agent (bkua_) or API access (bka_) token",
	detectors.CircleCI.String():           "CircleCI project (CCIPRJ_) or personal API token near circleci keyword",
	detectors.Snyk.String():               "Snyk API token (UUID) near snyk keyword",
	detectors.Spotify.String():            "Spotify client_id + client_secret pair (full app scope)",
	detectors.PIIEmail.String():           "Email address (PII) — finding_class=pii (deprecated: superseded by PIIAnonymize, retained for wire compatibility)",
	detectors.PIIUSSSN.String():           "US Social Security Number xxx-xx-xxxx (PII) — finding_class=pii (deprecated: superseded by PIIAnonymize, retained for wire compatibility)",
	detectors.PIICreditCard.String():      "Credit card number with valid Luhn checksum (PII) — finding_class=pii (deprecated: superseded by PIIAnonymize, retained for wire compatibility)",
	detectors.PIIIBAN.String():            "International Bank Account Number with valid mod-97 checksum (PII) — finding_class=pii (deprecated: superseded by PIIAnonymize, retained for wire compatibility)",
	detectors.PIIAnonymize.String():       "PII detected by the pleno-anonymize NER+regex engine (PERSON, EMAIL_ADDRESS, ADDRESS, PHONE_NUMBER, JP_MY_NUMBER, CREDIT_CARD, IBAN, US_SSN, …) — finding_class=pii, see properties.pii_kind for entity type",
	detectors.AWSSession.String():         "AWS temporary session credential triple (ASIA…) — unverified by design (region/audit unknown)",
	detectors.AzureSAS.String():           "Azure Storage SAS URL with embedded sig= signature",
	detectors.GCPOAuth.String():           "Google OAuth refresh token (1//0…)",
	detectors.GCPAPIKey.String():          "Google Cloud / Firebase API key (AIza…)",
	detectors.BitbucketServer.String():    "Bitbucket Server / Data Center HTTP access (BBDC-) or PAT — unverified by design (host unknown)",
	detectors.GitLabDeploy.String():       "GitLab project / deploy / agent / runner token (gldt-/glptt-/glagent-/glsoat-/glcbt-/glrt-)",
	detectors.Codecov.String():            "Codecov upload token (UUID) near codecov keyword",
	detectors.Rollbar.String():            "Rollbar access token (32 hex) near rollbar keyword",
	detectors.Bugsnag.String():            "Bugsnag API key (32 hex) near bugsnag keyword — unverified by design (no read endpoint, /notify is destructive)",
	detectors.SumoLogic.String():          "Sumo Logic access ID + access key pair (full log archive access)",
	detectors.Honeycomb.String():          "Honeycomb API key (hcaik_) or legacy 32-hex near honeycomb keyword",
	detectors.Tailscale.String():          "Tailscale auth / API key (tskey-…) — unverified by design (provisioning use, no read endpoint)",
	detectors.Figma.String():              "Figma personal access token (figd_/figpat_)",
	detectors.Zoom.String():               "Zoom OAuth client_id + client_secret pair (full account scope)",
	detectors.Klaviyo.String():            "Klaviyo private (pk_) or site (sk_) API key",
	detectors.AlibabaCloud.String():       "Alibaba Cloud AccessKey id (LTAI) + secret pair — unverified by design (region unknown, audit-log-bound)",
	detectors.AzureApp.String():           "Azure AD legacy v1 application secret (no tilde) + client_id pair — unverified by design (tenant unknown)",
	detectors.Databricks.String():         "Databricks personal access token (dapi…) — unverified by design (workspace host unknown)",
	detectors.DatadogAppKey.String():      "Datadog Application key standalone (40 hex) — paired path delegated to datadog detector",
	detectors.DopplerCLI.String():         "Doppler CLI token (dp.cli.…)",
	detectors.Freshdesk.String():          "Freshdesk API key near freshdesk keyword — unverified by design (subdomain unknown)",
	detectors.GCPIDToken.String():         "Google-issued OIDC ID token (audience-bound JWT) — unverified by design (audience unknown)",
	detectors.HashiCorpCloud.String():     "HashiCorp Cloud Platform access token (hcp.…)",
	detectors.LaunchDarklyRelay.String():  "LaunchDarkly relay-proxy service token (relay-proxy-<uuid>)",
	detectors.Ngrok.String():              "ngrok personal auth or API token near ngrok keyword",
	detectors.Opsgenie.String():           "Opsgenie API integration key (UUID) near opsgenie keyword",
	detectors.Snowflake.String():          "Snowflake JWT keypair-auth token — unverified by design (account host + public key unknown)",
	detectors.TencentCloud.String():       "Tencent Cloud SecretId (AKID) + SecretKey pair — unverified by design (region unknown, audit-log-bound)",
	detectors.TerraformCloudTeam.String(): "Terraform Cloud / Enterprise team API token (atlasv1) near team keyword",
	detectors.Zendesk.String():            "Zendesk API token + operator email pair — unverified by design (subdomain unknown)",
	detectors.Redis.String():              "Redis connection URI with embedded password (redis://:password@host) — unverified by design (host tenant-specific)",
	detectors.Postgres.String():           "PostgreSQL connection URI with embedded password (postgres://user:password@host) — unverified by design (host tenant-specific)",
	detectors.MySQL.String():              "MySQL connection URI with embedded password (mysql://user:password@host) — unverified by design (host tenant-specific)",
	detectors.MongoDB.String():            "MongoDB connection URI with embedded password (mongodb://, mongodb+srv://) — unverified by design (cluster tenant-specific)",
	detectors.RabbitMQ.String():           "RabbitMQ AMQP URI with embedded password (amqp(s)://user:password@host) — unverified by design (broker tenant-specific)",
	detectors.Kafka.String():              "Kafka SASL/PLAIN credentials (sasl.password / JAAS PlainLoginModule) — unverified by design (broker tenant-specific)",
	detectors.BasicAuth.String():          "HTTP/HTTPS/FTP URL with embedded Basic-auth userinfo (https://user:password@host) — unverified by design (host unbounded)",
	detectors.SMTP.String():               "SMTP submission URI with embedded password (smtp(s)://user:password@host) — unverified by design (host tenant-specific)",
	detectors.AdobeIO.String():            "Adobe.io api_key + client_secret pair, verified against IMS /ims/token/v3 client_credentials POST",
	detectors.DockerHub.String():          "Docker Hub personal access token (dckr_pat_…) — unverified by design (username required, not always in chunk)",
	detectors.GHCR.String():               "GitHub Container Registry token (gh[posru]_… co-occurring with ghcr.io), verified against ghcr.io/v2/",
	detectors.AWSS3PresignedURL.String():  "AWS S3 presigned URL (X-Amz-Algorithm=AWS4-HMAC-SHA256) — unverified by design (issuing the URL would fetch the underlying object)",
	detectors.GCSSignedURL.String():       "GCS V4 signed URL (X-Goog-Algorithm=GOOG4-RSA-SHA256) — unverified by design (issuing the URL would fetch the underlying object)",
	detectors.AzureSQLConnString.String(): "Azure SQL Database connection string (Server=…database.windows.net;…;Password=…) — unverified by design (host tenant-specific)",
	detectors.Kubeconfig.String():         "kubeconfig YAML credential field (client-certificate-data / client-key-data / token under kind: Config) — unverified by design (cluster API host tenant-specific)",
	detectors.ClickUp.String():            "ClickUp personal API token (pk_<digits>_<32 uppercase alnum>) near clickup keyword",
	detectors.Monday.String():             "Monday.com API token (JWT) near monday keyword, verified via /v2 GraphQL { me { id } }",
	detectors.Trello.String():             "Trello API key (32-hex) + token (64-hex) pair, verified via /1/members/me",
	detectors.Gitter.String():             "Gitter personal access token (40-hex) near gitter keyword, verified via /v1/user/me",
	detectors.LaunchNotes.String():        "LaunchNotes API key (ln_) — unverified by design (no read endpoint, write API is destructive)",
	detectors.Paperspace.String():         "Paperspace API key (40-char base64url) near paperspace keyword, verified via /users/getPublicProfile",
	detectors.RunPod.String():             "RunPod API key near runpod keyword, verified via GraphQL { myself { id } }",
	detectors.Modal.String():              "Modal token id (ak-) + token secret (as-) pair — unverified by design (workspace short-name not in chunk)",
	detectors.Linode.String():             "Linode personal access token (64-hex) near linode keyword, verified via /v4/account",
	detectors.Vultr.String():              "Vultr API key (36-char uppercase alnum) near vultr keyword, verified via /v2/account",
	detectors.Scaleway.String():           "Scaleway secret key (UUID) near scaleway keyword, verified via /account/v3/users with X-Auth-Token",
	detectors.UpstashRedis.String():       "Upstash Redis REST token near upstash keyword — unverified by design (per-database host not predictable)",
	detectors.PlanetScale.String():        "PlanetScale service token id (pscale_oauth_/pscale_tkn_) + secret pair — admin-equivalent, surfaces SeverityCritical",
	detectors.Clerk.String():              "Clerk secret key (sk_test_/sk_live_) near clerk keyword — sk_live_ surfaces SeverityCritical",
	detectors.Supabase.String():           "Supabase service-role key (JWT with role=service_role) near supabase keyword — unverified by design (project URL tenant-specific); service_role surfaces SeverityCritical",
	detectors.OneLogin.String():           "OneLogin API client_secret (64-hex) near onelogin keyword, verified via /api/2/users with `Authorization: bearer:<token>`",
	detectors.JumpCloud.String():          "JumpCloud admin API key (40-hex) near jumpcloud keyword, verified via /api/systemusers with `x-api-key`",
	detectors.Twitch.String():             "Twitch OAuth client_secret / app-access token (30-char alnum) near twitch keyword, verified via /oauth2/validate",
	detectors.Lacework.String():           "Lacework API access token (`<base64>_<hex>` shape) near lacework keyword, verified via /api/v2/AccessTokens",
	detectors.DroneCI.String():            "Drone CI personal access token (24+ alnum) near drone keyword — unverified by design (server URL tenant-specific)",
	detectors.Harness.String():            "Harness CI/CD personal access token (`pat.<account>.<id>.<secret>` 4-segment dotted) verified via /ng/api/user/currentUser",
	detectors.Sysdig.String():             "Sysdig API token (UUID or 40-hex) near sysdig keyword, verified via /api/v1/user/me",
	detectors.Lokalise.String():           "Lokalise API token (40-hex) near lokalise keyword, verified via /api2/projects with `x-api-token`",
	detectors.Pulumi.String():             "Pulumi Cloud access token (`pul-<40-hex>`) verified via /api/user with `Authorization: token <pat>`",
	detectors.Coda.String():               "Coda API token (UUID or 40+ alnum) near coda keyword, verified via /apis/v1/whoami",
	detectors.LoopsSo.String():            "Loops.so API key (32-hex) near loops keyword, verified via /api/v1/api-key",
	detectors.AppCenter.String():          "Microsoft App Center API token (40-hex) near appcenter keyword, verified via /v0.1/user with `X-API-Token`",
	detectors.Bitwarden.String():          "Bitwarden Secrets Manager (BWS) machine-account access token (`0.<uuid>.<base64>:<base64>`) — unverified by design; surfaces SeverityCritical",
	detectors.Resend.String():             "Resend API key (`re_<base62>`) verified via /domains with Bearer auth",
	detectors.Helcim.String():             "Helcim payment API token (32-hex) near helcim keyword, verified via /v2/connect-test; surfaces SeverityCritical",
	detectors.AnthropicAdmin.String():     "Anthropic Console admin API key (sk-ant-admin-) — distinct from runtime keys, verified via /v1/organizations/me; surfaces SeverityCritical",
	detectors.Pinecone.String():           "Pinecone API key (pcsk_<base62>) verified via /databases with Api-Key header",
	detectors.Weaviate.String():           "Weaviate Cloud admin API key (64-char base62) near weaviate keyword, verified via /v1/meta with Bearer when cluster URL co-occurs",
	detectors.VoyageAI.String():           "Voyage AI API key (pa-<base64url>) near voyage keyword, verified via /v1/embeddings with Bearer auth",
	detectors.Fireworks.String():          "Fireworks AI API key (fw_<base62>) verified via /v1/models with Bearer auth",
	detectors.Cerebras.String():           "Cerebras Cloud inference API key (csk-<base62>) verified via /v1/models with Bearer auth",
	detectors.GitHubApp.String():          "GitHub Apps installation access token (ghs_<base62>{36}) verified via /installation/repositories — distinct from PATs",
	detectors.JFrog.String():              "JFrog Artifactory reference token (cmVmdGtuO… prefix) verified via /artifactory/api/system/ping when host co-occurs",
	detectors.Pendo.String():              "Pendo integration token (32-hex) near pendo keyword, verified via /api/v1/feature with x-pendo-integration-key header",
	detectors.PostHog.String():            "PostHog personal API key (phx_<base62>) verified via /api/projects/@current; phc_ project keys are publishable and intentionally not surfaced",
	detectors.SentryUser.String():         "Sentry user auth token (sntryu_<64-hex>) verified via /api/0/ — distinct from project DSNs handled by sentry detector",
	detectors.CloudflareR2.String():       "Cloudflare R2 access-key-id (32-hex) + secret-access-key (64-hex) pair near r2_access_key keyword — unverified by design (per-account host); surfaces SeverityCritical",
	detectors.Mapbox.String():             "Mapbox secret token (sk.<jwt>) — public pk. tokens deliberately not surfaced; verified via /tokens/v2/<username>; surfaces SeverityCritical",
	detectors.Railway.String():            "Railway API token (UUID) near railway keyword, verified via /graphql/v2 { me { id } } with Bearer auth",
	detectors.Telnyx.String():             "Telnyx V2 API key (KEY<32+ alnum>) near telnyx keyword, verified via /v2/messaging_profiles with Bearer auth",
	detectors.SplunkHEC.String():          "Splunk HEC token (UUID) near splunk_hec / services/collector keyword — unverified by design (per-customer hostnames)",
	detectors.ElasticCloud.String():       "Elastic Cloud / Elasticsearch API key (id:secret base64-url pair) near elastic / elasticsearch — unverified by design (per-deployment hostnames)",
	detectors.LogzIO.String():             "Logz.io account API token (32-hex) near logz keyword, verified via /v1/whoami with X-API-TOKEN header",
	detectors.Coralogix.String():          "Coralogix API token (32-hex) near coralogix keyword, verified via /api/v1/users with Bearer auth",
	detectors.Loggly.String():             "Loggly customer token (UUID) near loggly keyword, verified via /inputs/<token> on logs-01.loggly.com",
	detectors.UptimeRobot.String():        "UptimeRobot API key (u<digits>-<32 alnum> main, m<digits>-<32 alnum> monitor) near uptimerobot, verified via POST /v2/getAccountDetails",
	detectors.Pingdom.String():            "Pingdom API token (40-80 char base62) near pingdom keyword, verified via /api/3.1/checks with Bearer auth",
	detectors.Honeybadger.String():        "Honeybadger personal API token (hbp_<base62>) near honeybadger, verified via /v2/projects with Basic auth (token as user)",
	detectors.Raygun.String():             "Raygun personal access token (UUID) near raygun keyword, verified via /v3/applications with X-ApiKey header",
	detectors.Statuspage.String():         "Atlassian Statuspage API key (UUID) near statuspage keyword, verified via /v1/pages with `OAuth <token>` authorization",
	detectors.VictorOps.String():          "VictorOps / Splunk On-Call API key (UUID) near victorops, verified via /api-public/v1/team with X-VO-Api-Key header",
	detectors.PagerTree.String():          "PagerTree integration token (32-hex) near pagertree keyword, verified via /api/v4/integrations with Bearer auth",
	detectors.AWX.String():                "AWX / Ansible Tower OAuth2 Bearer token (40-char base62) near awx_token / ansible_tower — unverified by design (self-hosted)",
	detectors.ConcourseCI.String():        "Concourse CI fly local-user bearer token (28+ char base64) near concourse keyword — unverified by design (self-hosted)",
	detectors.TeamCity.String():           "JetBrains TeamCity server access token (40+ char base62 / eyJ JWT) near teamcity keyword — unverified by design (self-hosted / per-customer subdomain)",
	detectors.Aiven.String():              "Aiven personal access token (32+ char base62) near aiven keyword, verified via /v1/me with `Authorization: aivenv1 <token>`",
	detectors.YugabyteCloud.String():      "YugabyteDB Managed (Yugabyte Cloud) API key (64+ char base64url) near yugabyte keyword, verified via /api/public/v1/accounts with Bearer auth",
	detectors.CockroachCloud.String():     "Cockroach Cloud API key (`ccdb_<base62>`) verified via /api/v1/clusters with Bearer auth",
	detectors.Fauna.String():              "FaunaDB admin/server secret (`fnAd…` / `fnAk…`) verified via /version with Bearer auth",
	detectors.Tinybird.String():           "Tinybird auth token (UUID) near tinybird keyword, verified via /v0/datasources with Bearer auth",
	detectors.ClickHouseCloud.String():    "ClickHouse Cloud key id (32-char) + secret (40+ char base64url) pair — unverified by design (per-org host)",
	detectors.Neon.String():               "Neon serverless Postgres API key (`neon_<base62>`) verified via /api/v2/users/me with Bearer auth",
	detectors.GitLabPipeline.String():     "GitLab pipeline trigger token (40-hex or UUID) near pipeline_trigger keyword — unverified by design (verify would actually run the pipeline)",
	detectors.ArgoCD.String():             "Argo CD API token (JWT-shaped) near argocd_token keyword — unverified by design (self-hosted Gate API host)",
	detectors.TektonHub.String():          "Tekton Hub API token (40+ char base62) near tekton keyword — unverified by design (community / self-hosted)",
	detectors.Spinnaker.String():          "Spinnaker (Netflix) API token (40+ char base62 / eyJ JWT) near spinnaker keyword — unverified by design (self-hosted Gate API)",
	detectors.ConstantContact.String():    "Constant Contact API access token (Bearer JWT or 32+ base62) near constant_contact keyword, verified via /v3/account/summary with Bearer auth",
	detectors.Vonage.String():             "Vonage (Nexmo) API key (8-char) + secret (16-char) pair, verified via /v0.1/users with HTTP Basic; surfaces SeverityCritical when verified (paid SMS/voice scope)",
	detectors.Workato.String():            "Workato API token (40+ base62) near workato keyword, verified via /api/users/me with Bearer auth",
	detectors.AikidoSecurity.String():     "Aikido Security API token (40+ base62) near aikido keyword, verified via /api/public/v1/me with Bearer auth",
	detectors.Akamai.String():             "Akamai EdgeGrid client_secret (32+ base64) near akamai keyword — unverified by design (HMAC signing scheme requires client_token + access_token + client_secret triple)",
	detectors.Fastly.String():             "Fastly API token (32-char base62) near fastly keyword, verified via /tokens/self with Fastly-Key header",
	detectors.Quip.String():               "Quip developer token (40+ base64) near quip keyword, verified via /1/users/current with Bearer auth",
	detectors.Box.String():                "Box developer token (32+ alnum) near box_ keyword, verified via /2.0/users/me with Bearer auth",
	detectors.Zoho.String():               "Zoho OAuth refresh token (1000.<base62>.<base62>) near zoho keyword — unverified by design (region-specific accounts.zoho.<tld>)",
	detectors.Adyen.String():              "Adyen API key (AQE/AQF prefix, 40+ base64) near adyen keyword — unverified by design (merchant account name not in chunk)",
	detectors.Wise.String():               "Wise (TransferWise) API token (UUID) near wise keyword, verified via /v2/profiles with Bearer auth",
	detectors.Razorpay.String():           "Razorpay key id (rzp_test_/rzp_live_) + secret pair, verified via /v1/items with HTTP Basic; rzp_live_ surfaces SeverityCritical when verified",
	detectors.Mollie.String():             "Mollie API key (live_/test_<base62>{30+}) near mollie keyword, verified via /v2/methods with Bearer auth; live_ surfaces SeverityCritical when verified",
	detectors.MessageBird.String():        "MessageBird API access key (25+ alnum) near messagebird keyword, verified via /contacts with `Authorization: AccessKey <token>`",
	detectors.Sinch.String():              "Sinch API key (UUID) near sinch keyword — unverified by design (project_id + region required)",
	detectors.BackblazeB2.String():        "Backblaze B2 application key id (K00...) + key pair near b2_/backblaze keyword — unverified by design (b2_authorize_account would be a write to session-token API)",
	detectors.Wasabi.String():             "Wasabi access key + secret pair (S3-compatible) near wasabi keyword — unverified by design (multi-region SigV4 signing)",
	detectors.Stytch.String():             "Stytch project secret (secret-test-/secret-live-) near stytch keyword — unverified by design (project_id required for Basic auth); secret-live- surfaces SeverityCritical",
	detectors.Cloud66.String():            "Cloud66 personal access token (64-hex) near cloud66 keyword, verified via /3/account.json with Bearer auth",
	detectors.AzureDevOps.String():        "Azure DevOps personal access token (52-char base32) near azure_devops / dev.azure.com keyword, verified via /_apis/connectionData with HTTP Basic auth",
	detectors.Jenkins.String():            "Jenkins API token (11<32-hex>) near jenkins keyword — unverified by design (self-hosted host not in chunk)",
	detectors.GoCD.String():               "GoCD server token (40+ alnum) near gocd keyword — unverified by design (self-hosted host not in chunk)",
	detectors.Bamboo.String():             "Atlassian Bamboo personal access token (>=24 base64) near bamboo keyword — unverified by design (self-hosted host not in chunk)",
	detectors.Smartsheet.String():         "Smartsheet API access token (>=24 base32-style) near smartsheet keyword, verified via /2.0/users/me with Bearer auth",
	detectors.Wrike.String():              "Wrike permanent access token (>=40 base64url) near wrike keyword, verified via /api/v4/contacts?me=true with Bearer auth",
	detectors.Productboard.String():       "Productboard API key (>=32 base64url) near productboard keyword, verified via /companies with Bearer auth and X-Version: 1",
	detectors.Miro.String():               "Miro OAuth access token (>=40 base64url) near miro keyword, verified via /v2/users/me with Bearer auth",
	detectors.Lucidchart.String():         "Lucidchart API token (>=40 base64url) near lucidchart keyword, verified via /users/me with Bearer auth",
	detectors.SonatypeNexus.String():      "Sonatype Nexus user token (NXRT-<base64url>) near nexus keyword — unverified by design (self-hosted host not in chunk)",
	detectors.AppStoreConnect.String():    "App Store Connect .p8 PEM private key near app_store_connect keyword — unverified by design (issuer_id + key_id required for JWT signing)",
	detectors.Bitrise.String():            "Bitrise personal access token (>=40 base64url) near bitrise keyword, verified via /v0.1/me with Bearer auth",
	detectors.Browserstack.String():       "Browserstack username + access key pair near browserstack keyword, verified via /automate/plan.json with HTTP Basic auth",
	detectors.StabilityAI.String():        "Stability AI API key (sk-<base62>{>=40}) near stability keyword (distinct shape gating from OpenAI), verified via /v1/user/account with Bearer auth",
	detectors.CiscoMeraki.String():        "Cisco Meraki API key (40-char hex) near meraki keyword, verified via /api/v1/organizations with X-Cisco-Meraki-API-Key header",
	detectors.Webex.String():              "Cisco Webex personal access token (>=60-char base64) near webex keyword, verified via /v1/people/me with Bearer auth",
	detectors.Tenable.String():            "Tenable.io accessKey + secretKey pair (64-hex each) near tenable keyword, verified via /session with X-ApiKeys header",
	detectors.Rapid7.String():             "Rapid7 InsightVM/IDR API key (UUID) near rapid7 keyword, verified via /idr/v1/users/me with X-Api-Key header",
	detectors.CrowdStrike.String():        "CrowdStrike Falcon OAuth2 client_id (32-hex) + client_secret (40 alnum) pair near crowdstrike keyword, verified via /oauth2/token with client_credentials grant",
	detectors.Wiz.String():                "Wiz.io service-account JWT-shaped token near wiz_io keyword — unverified by design (tenant-specific host required)",
	detectors.SonarQube.String():          "SonarQube/SonarCloud user token (sqp_/squ_/sqa_ prefix or 40-hex near sonar keyword), verified via /api/authentication/validate with HTTP Basic auth",
	detectors.MailerLite.String():         "MailerLite v2 JWT-shaped API token near mailerlite keyword, verified via /api/subscribers/me with Bearer auth",
	detectors.ActiveCampaign.String():     "ActiveCampaign API key (>=60 alnum) near activecampaign keyword — unverified by design (per-account host <account>.api-us1.com required)",
	detectors.Drip.String():               "Drip (getdrip) API token (32 alnum) near getdrip keyword, verified via /v2/accounts with HTTP Basic auth (token as username)",
	detectors.BunnyCDN.String():           "Bunny.net account API key (UUID) near bunny keyword, verified via /apikey with AccessKey header",
	detectors.Vimeo.String():              "Vimeo OAuth access token (>=32 alnum) near vimeo keyword, verified via /me with Bearer auth",
	detectors.Cloudinary.String():         "Cloudinary URL credential (cloudinary://<key>:<secret>@<cloud>) — verified via /v1_1/<cloud>/usage with HTTP Basic auth",
	detectors.PingIdentity.String():       "PingOne worker app secret (UUID) near ping_identity keyword — unverified by design (per-region host required)",
	detectors.Mux.String():                "Mux access token id (UUID) + secret pair near mux keyword, verified via /video/v1/assets with HTTP Basic auth",
	detectors.Hookdeck.String():           "Hookdeck API key (hookdeck_test_/hookdeck_live_ prefix) — verified via /sources with Bearer auth; hookdeck_live_ surfaces SeverityCritical when verified",
	detectors.WorkOS.String():                 "WorkOS API key (sk_test_/sk_live_ prefix, base62) near workos keyword, verified via /users on api.workos.com with Bearer auth",
	detectors.FrontEgg.String():               "FrontEgg vendor client_id + client_secret pair (UUID each) near frontegg keyword, verified via POST /auth/vendor with JSON body",
	detectors.Kinde.String():                  "Kinde Auth M2M secret / API key near kinde keyword (>=40 base64url) — verified via /api/v1/users with Bearer auth on a per-tenant host (apiBase override required)",
	detectors.Hanko.String():                  "Hanko Cloud admin API key near hanko keyword (>=32 base64url-ish) — verified via /webhooks with Bearer auth on a per-tenant host (apiBase override required)",
	detectors.GitHubFineGrained.String():      "GitHub fine-grained personal access token (github_pat_<82>) — verified via /user on api.github.com with Bearer auth; distinct from classic ghp_/gho_/ghu_/ghs_/ghr_ shapes",
	detectors.AzureContainerRegistry.String(): "Azure Container Registry refresh/access token (JWT-shaped) near azurecr/acr_ keywords — unverified by design (per-registry host <name>.azurecr.io required)",
	detectors.Quay.String():                   "Quay.io OAuth access token (>=40 alnum) near quay keyword, verified via /api/v1/user on quay.io with Bearer auth",
	detectors.Replit.String():                 "Replit deploy / API token (>=40 base62) near replit keyword, verified via /data/me on replit.com with Bearer auth",
	detectors.PostmarkAccount.String():        "Postmark Account API token (UUID) near postmark_account keyword — distinct from server-scope Postmark; verified via /servers using X-Postmark-Account-Token header",
	detectors.Beehiiv.String():                "Beehiiv API key (>=40 alnum) near beehiiv keyword, verified via /v2/publications on api.beehiiv.com with Bearer auth",
	detectors.NS1.String():                    "NS1 (IBM NS1 Connect) API key (>=16 alnum) near ns1/nsone keyword, verified via /v1/account/usage on api.nsone.net using X-NSONE-Key header",
	detectors.Perplexity.String():             "Perplexity AI API key (pplx-<base62>) — verified via POST /chat/completions on api.perplexity.ai with Bearer auth (token-good vs token-bad split via 400 vs 401)",
	detectors.DeepInfra.String():              "DeepInfra API token (>=40 alnum) near deepinfra keyword, verified via /v1/openai/models on api.deepinfra.com with Bearer auth",
	detectors.XAI.String():                    "xAI Grok API key (xai-<base62>{40+}) — verified via /v1/api-key on api.x.ai with Bearer auth",
	detectors.GoCardless.String():             "GoCardless live_<base64url>{40+} or sandbox_<base64url>{40+} near gocardless keyword, verified via /creditors on api.gocardless.com (live) or api-sandbox.gocardless.com (sandbox); live_ verified surfaces SeverityCritical",
	detectors.MercuryBank.String():            "Mercury Bank API token (>=32 base62) near mercury keyword, verified via /api/v1/accounts on api.mercury.com with Bearer auth; surfaces SeverityCritical when verified (live banking access)",
	detectors.LemonSqueezy.String():           "Lemon Squeezy API key (JWT-shaped 3-segment base64url) near lemonsqueezy keyword, verified via /v1/users/me on api.lemonsqueezy.com with Bearer + Accept: application/vnd.api+json",
	detectors.Schematic.String():              "Schematic (schematichq) pricing/billing API key (`api_<base62>`) near schematic keyword, verified via /v1/companies on api.schematichq.com using X-Schematic-Api-Key header",
	detectors.Hyperline.String():              "Hyperline billing API key (>=32 base62) near hyperline keyword, verified via /v1/customers on api.hyperline.co with Bearer auth",
	detectors.Fattureincloud.String():         "Fatture in Cloud (fattureincloud.it) API access token (>=40 base64url) near fattureincloud keyword, verified via /user/info on api-v2.fattureincloud.it with Bearer auth",
	detectors.VercelAIGateway.String():        "Vercel AI Gateway API key (`vck_<base62>{32+}`) — distinct from Vercel deploy tokens; verified via /v1/models on ai-gateway.vercel.sh with Bearer auth",
	detectors.Gandi.String():                  "Gandi (registrar) personal API key (>=24 base62) near gandi keyword, verified via /v5/organization/organizations on api.gandi.net using `Authorization: Apikey <key>`",
	detectors.Codefresh.String():              "Codefresh CI/CD API key (>=40 base64url) near codefresh keyword, verified via /api/user on g.codefresh.io using `Authorization: <token>` (no Bearer prefix)",
	detectors.Earthly.String():                "Earthly Cloud token (>=40 base62) near earthly keyword, verified via /api/v0/account/me on api.earthly.dev with Bearer auth",
	detectors.Spacelift.String():              "Spacelift IaC API key (`s_<base62>{32+}`) near spacelift keyword — unverified by default (per-account host <account>.app.spacelift.io required); apiBase override enables verify",
	detectors.CouchbaseCapella.String():       "Couchbase Capella API token (>=40 base64url) near couchbase/capella keyword, verified via /v4/organizations on cloudapi.cloud.couchbase.com with Bearer auth",
	detectors.SlackUserToken.String():         "Slack user OAuth token (xoxp-) — distinct from xoxb- bot tokens; user-scope grants act-as-user; verified via /api/auth.test on slack.com with Bearer auth",
	detectors.PusherChannels.String():         "Pusher Channels app secret (20-char alnum) near pusher keyword — unverified by design (HMAC signing requires app_id + cluster not in chunk)",
	detectors.Hetzner.String():                "Hetzner Cloud API token (64-char base62) near hcloud/hetzner keyword, verified via /v1/servers on api.hetzner.cloud with Bearer auth",
	detectors.Pumble.String():                 "Pumble team-chat API token (>=40 alnum) near pumble keyword, verified via /listUsers on Pumble API addons host using `Api-Key` header",
	detectors.OVHCloud.String():               "OVH Cloud (application_key / application_secret / consumer_key) 32-char triple near ovh / consumer_key keyword — unverified by design (HMAC-SHA1 signing required)",
	detectors.EquinixMetal.String():           "Equinix Metal (formerly Packet) API token (32-char alnum) near equinix / packet / metal_api keyword, verified via /metal/v1/user on api.equinix.com using `X-Auth-Token` header",
	detectors.Civo.String():                   "Civo Cloud API key (50-char alnum) near civo keyword, verified via /v2/account on api.civo.com with Bearer auth",
	detectors.Exoscale.String():               "Exoscale IaaS API key (`EXO<base62>{56}`) + secret (paired RawV2) near exoscale keyword — unverified by design (HMAC-SHA1 query signing required)",
	detectors.BuddyCI.String():                "Buddy CI personal access token (>=40 base64url) near buddy / buddy.works keyword, verified via /user on api.buddy.works with Bearer auth",
	detectors.SemaphoreCI.String():            "Semaphore CI 2.0 API token (>=40 alnum) near semaphore keyword — verified via /api/v1alpha/projects on the per-org host (`<org>.semaphoreci.com`); apiBase override required",
	detectors.JenkinsX.String():               "Jenkins X (jx) API token (>=40 alnum) near jenkinsx / jx_ keyword — unverified by default (per-installation host required); apiBase override enables verify",
	detectors.AssemblyAI.String():             "AssemblyAI API key (32-char hex) near assemblyai keyword, verified via /v2/transcript on api.assemblyai.com using `Authorization: <key>` (no Bearer prefix)",
	detectors.ElevenLabs.String():             "ElevenLabs API key (32-char hex) near elevenlabs / xi-api-key keyword, verified via /v1/user on api.elevenlabs.io using `xi-api-key` header",
	detectors.Deepgram.String():               "Deepgram API key (40-char hex) near deepgram keyword, verified via /v1/projects on api.deepgram.com using `Authorization: Token <key>`",
	detectors.Front.String():                  "Front (frontapp.com) API token (JWT-shaped 3-segment base64url) near frontapp / fronthq / front_api keyword, verified via /me on api2.frontapp.com with Bearer auth",
	detectors.CrispChat.String():              "Crisp Chat plugin key (>=40 base64url) near crisp keyword — unverified by design (Identifier+Key paired auth required)",
	detectors.Drift.String():                  "Drift API token (>=32 base64url) near drift keyword, verified via /core/v1/users/list on driftapi.com with Bearer auth",
	detectors.Vanta.String():                  "Vanta API token ((vat_|usr_)?<base62>{40+}) near vanta keyword, verified via /v1/integrations on api.vanta.com with Bearer auth",
	detectors.OneSignal.String():              "OneSignal REST API key (legacy 48-char alnum or `os_v2_app_<base32>{50+}`) near onesignal keyword, verified via /api/v1/apps on api.onesignal.com using `Authorization: Basic <key>`",
	detectors.FirebaseCloudMessaging.String(): "Firebase Cloud Messaging legacy server key (`AAAA<base64url>:APA91b<base64url>{134+}`) near fcm / firebase keyword, verified via /fcm/send on fcm.googleapis.com using `Authorization: key=<token>`",
	detectors.APNs.String():                   "Apple Push Notification service .p8 PEM private key near apns / apple_push keyword — unverified by design (issuer + key_id required for JWT issuance)",
	detectors.Pushover.String():               "Pushover application token (30-char alnum) near pushover keyword, verified via /1/sounds.json on api.pushover.net using POST form `token=<token>`",
	detectors.BranchIO.String():               "Branch.io key (`key_(live|test)_<base62>{32+}`) + matching secret (`secret_(live|test)_<base62>{32+}`) paired RawV2 near branch / branch_io keyword, verified via /v1/app on api2.branch.io with branch_secret query param",
	detectors.PusherBeams.String():            "Pusher Beams secret key (32-hex) near pusher_beams / beams keyword — unverified by design (instance_id required for /publish_api endpoint)",
	detectors.Drata.String():                  "Drata API token (>=40 base64url) near drata keyword, verified via /v1/users on public-api.drata.com with Bearer auth",
	detectors.Secureframe.String():            "Secureframe API token (>=40 base64url) near secureframe keyword, verified via /v1/users on api.secureframe.com with Bearer auth",
	detectors.OneTrust.String():               "OneTrust integration token (>=40 base64url) near onetrust keyword — verified via /api/v1/tenants on the per-tenant host (`<tenant>.onetrust.com`); apiBase override required",
	detectors.Pipedrive.String():              "Pipedrive personal API token (40-hex) near pipedrive keyword, verified via /v1/users/me on api.pipedrive.com with `?api_token=` query param",
	detectors.Close.String():                  "Close.com API key (`api_<base62>{40+}`) near close.com / closecrm keyword, verified via /api/v1/me/ on api.close.com with HTTP basic auth (key as user, empty password)",
	detectors.DNSimple.String():               "DNSimple API token (>=40 alnum) near dnsimple keyword, verified via /v2/whoami on api.dnsimple.com with Bearer auth",
	detectors.NvidiaNGC.String():              "NVIDIA NGC API key (`nvapi-<base64url>{40+}`) near nvidia / ngc / nvapi keyword, verified via /v2/org on api.ngc.nvidia.com with Bearer auth",
	detectors.Airbrake.String():               "Airbrake user API token (>=40 alnum) near airbrake keyword, verified via /api/v4/projects on api.airbrake.io with `?key=` query param",
	detectors.Materialize.String():            "Materialize Cloud app password (`mzp_<base64url>{40+}`) near materialize keyword, verified via /api/users/me on api.materialize.com with Bearer auth",
	detectors.BeyondIdentity.String():         "Beyond Identity API token (>=40 base64url) near beyondidentity / byndid keyword — verified via /v1/tenants/me on the per-tenant host (`api-<region>.byndid.com`); apiBase override required",
	detectors.KeyCDN.String():                 "KeyCDN API key (>=20 alnum) near keycdn keyword, verified via /zones.json on api.keycdn.com using HTTP Basic auth (key as user, empty password)",
	detectors.Mailtrap.String():               "Mailtrap API token (>=32 alnum) near mailtrap keyword, verified via /api/accounts on mailtrap.io with `Api-Token: <token>` header",
	detectors.GetResponse.String():            "GetResponse API key (32-hex) near getresponse keyword, verified via /v3/accounts on api.getresponse.com using `X-Auth-Token: api-key <key>` header",
	detectors.Amplitude.String():              "Amplitude analytics API key + secret pair (32-hex each) near amplitude keyword, verified via /api/2/usersearch on amplitude.com with HTTP Basic auth (RawV2 carries the secret)",
	detectors.FullStory.String():              "FullStory API key (>=40 base64url) near fullstory keyword, verified via /operations/v1 on api.fullstory.com with `Authorization: Basic <key>` header",
	detectors.Heap.String():                   "Heap analytics server-side key (`heap_<base62>{32+}`) near heap keyword, verified via /api/public/v0/auth_token on heapanalytics.com with Bearer auth",
	detectors.Hotjar.String():                 "Hotjar API token (`hjar_<base64url>{40+}`) near hotjar keyword, verified via /v1/sites on api.hotjar.com with Bearer auth",
	detectors.Optimizely.String():             "Optimizely personal access token (>=40 base64url) near optimizely keyword, verified via /v2/projects on api.optimizely.com with Bearer auth",
	detectors.Transifex.String():              "Transifex API token (`1/[a-f0-9]{40}` or >=40 alnum) near transifex keyword, verified via /api/2/user on rest.api.transifex.com using HTTP Basic auth (user `api`, token as password)",
	detectors.Crowdin.String():                "Crowdin personal access token (>=40 base64url) near crowdin keyword, verified via /api/v2/user on api.crowdin.com with Bearer auth",
	detectors.DocuSign.String():               "DocuSign integration key / access token (>=40 base64url JWT) near docusign keyword — verified via /restapi/v2.1/accounts on the per-environment host (demo / na2 / eu); apiBase override required",
	detectors.Qdrant.String():                 "Qdrant Cloud API key (>=40 base64url) near qdrant keyword — verified via /collections on the per-cluster host; apiBase override required",
	detectors.SurrealDB.String():              "SurrealDB Cloud token (>=40 base64url) near surrealdb / surreal keyword — verified via /sql on the per-instance host; apiBase override required",
	detectors.Leaseweb.String():               "Leaseweb API key + secret pair (32-hex each) near leaseweb keyword, verified via /v1/account on api.leaseweb.com with `X-Lsw-Auth: <key>` and HMAC `X-Lsw-Sign` (RawV2 carries the secret)",
	detectors.PostageApp.String():             "PostageApp API key (32-hex) near postageapp keyword, verified via /v.1.0/get_account_info.json on api.postageapp.com with form `api_key=<key>`",
	detectors.Nomic.String():                  "Nomic Atlas API key (`nk-<base64url>{40+}`) near nomic keyword, verified via /v1/user on api-atlas.nomic.ai with Bearer auth",
	detectors.Jina.String():                   "Jina AI API key (`jina_<base64url>{40+}`) near jina keyword, verified via /v1/embeddings on api.jina.ai with Bearer auth",
	detectors.Runway.String():                 "Runway ML API key (`key_<hex>{48+}`) near runway / runwayml keyword, verified via /v1/organization on api.dev.runwayml.com with Bearer auth",
	detectors.MotherDuck.String():             "MotherDuck access token (>=80 base64url JWT) near motherduck keyword, verified via /v1/databases on api.motherduck.com with Bearer auth",
	detectors.DoltHub.String():                "DoltHub personal access token (>=40 base64url) near dolthub keyword, verified via /api/v1alpha1/{owner}/profile on dolthub.com with `authorization: token <pat>`",
	detectors.BetterStack.String():            "Better Stack (Logtail) team API token (>=24 alnum) near betterstack / better_stack / logtail keyword, verified via /api/v2/teams on uptime.betterstack.com with Bearer auth",
	detectors.Dynatrace.String():              "Dynatrace API token (`dt0c01.<id>.<secret>`) near dynatrace keyword — verified via /api/v1/config/clusterversion on the per-tenant host (`<env>.live.dynatrace.com`); apiBase override required",
	detectors.AppSignal.String():              "AppSignal push API key (32-hex) near appsignal keyword, verified via /1/auth on push.appsignal.com with `?api_key=<key>` query parameter",
	detectors.ScoutAPM.String():               "Scout APM agent key + secret pair (account ID and 64-char key) near scout / scoutapm / scout_apm keyword, verified via /api/v0/check on scoutapm.com with HTTP Basic auth (RawV2 carries the secret)",
	detectors.Descope.String():                "Descope management key (`K2<base64url>{40+}`) near descope keyword, verified via /v1/mgmt/project/list on api.descope.com with Bearer auth",
	detectors.Mandrill.String():               "Mandrill API key (22-char URL-safe alnum) near mandrill keyword, verified via /api/1.0/users/ping on mandrillapp.com with form `key=<api_key>`",
	detectors.CustomerIO.String():             "Customer.io tracking site_id + api_key pair (each 20 alnum) near customerio / customer_io keyword, verified via /api/v1/customers on track.customer.io with HTTP Basic auth (RawV2 carries the api_key)",
	detectors.Iterable.String():               "Iterable API key (>=40 alnum) near iterable keyword, verified via /api/users/byEmail on api.iterable.com with `Api-Key: <key>` header",
	detectors.Plivo.String():                  "Plivo Auth ID + Auth Token pair (auth_id starts `MA` / `SA` then 18 alnum, token >=40 base64url) near plivo keyword, verified via /v1/Account/{auth_id}/ on api.plivo.com with HTTP Basic auth (RawV2 carries the auth token)",
	detectors.Paddle.String():                 "Paddle Billing API key (`pdl_(live|sdbx)_apikey_<base64url>{40+}`) near paddle keyword, verified via /event-types on api.paddle.com with Bearer auth (sandbox host `sandbox-api.paddle.com`)",
	detectors.Shopify.String():                "Shopify Admin API access token (`shp(at|ss|ca)_<32 hex>`) — verified via /admin/api/2023-10/shop.json on the per-shop `<shop>.myshopify.com` host; apiBase override required",
	detectors.Recurly.String():                "Recurly subscription billing API key (32 alnum) near recurly keyword, verified via /sites on v3.recurly.com with HTTP Basic auth (key as username)",
	detectors.Chargebee.String():              "Chargebee subscription billing API key (`(live|test)_<base64url>{20+}`) near chargebee keyword — verified via /api/v2/customers on the per-site `<site>.chargebee.com` host; apiBase override required",
	detectors.FastSpring.String():             "FastSpring API username + password pair (each 16+ alnum) near fastspring keyword, verified via /accounts on api.fastspring.com with HTTP Basic auth (RawV2 carries the password)",
	detectors.Gumroad.String():                "Gumroad personal access token (32+ alnum) near gumroad keyword, verified via /v2/user on api.gumroad.com with `?access_token=` query parameter",
	detectors.Snipcart.String():               "Snipcart secret API key (50+ alnum) near snipcart keyword, verified via /api/orders on app.snipcart.com with HTTP Basic auth (key as username)",
	detectors.Gitea.String():                  "Gitea personal access token (40-hex) near gitea keyword — verified via /api/v1/user on the self-hosted Gitea host; apiBase override required",
	detectors.Woodpecker.String():             "Woodpecker CI access token (32+ alnum) near woodpecker keyword — verified via /api/user on the self-hosted Woodpecker host; apiBase override required",
	detectors.OctopusDeploy.String():          "Octopus Deploy API key (`API-<26 base32>`) — verified via /api/users/me on the per-tenant `<tenant>.octopus.app` host; apiBase override required",
	detectors.Squadcast.String():              "Squadcast API token (40+ alnum) near squadcast keyword, verified via /v3/users on api.squadcast.com with Bearer auth",
	detectors.Instana.String():                "IBM Instana API token (40+ alnum) near instana keyword — verified via /api/instana/version on the per-tenant `<unit>-<tenant>.instana.io` host with `apiToken <key>`; apiBase override required",
	detectors.Courier.String():                "Courier auth token (`pk_(prod|test)_<base32>{40+}`) verified via /profiles on api.courier.com with Bearer auth",
	detectors.Bandwidth.String():              "Bandwidth.com API username + password pair (each 10+ alnum) near bandwidth keyword, verified via /api/accounts on dashboard.bandwidth.com with HTTP Basic auth (RawV2 carries the password)",
	detectors.GetStream.String():              "Stream / getstream.io chat / activity feed api_key + api_secret pair near getstream / stream_io keyword — unverified by design (HMAC-signed JWTs, no cleartext-secret read endpoint)",
	detectors.Lark.String():                   "Lark / Feishu Open Platform app_id (`cli_<16 hex>`) + app_secret (32 alnum) pair, verified via /open-apis/auth/v3/tenant_access_token/internal on open.larksuite.com with JSON body (RawV2 carries the app_secret)",
	detectors.Braintree.String():              "Braintree access token (`access_token$(production|sandbox)$<merchant>$<32 hex>`) verified via /merchants/<id> on api.braintreegateway.com / api.sandbox.braintreegateway.com with Bearer auth (RawV2 carries the merchant id)",
	detectors.Dwolla.String():                 "Dwolla app key + secret pair (each 50+ base64-ish) near dwolla keyword, verified via /token on api.dwolla.com (sandbox: api-sandbox.dwolla.com) with HTTP Basic auth (RawV2 carries the secret)",
	detectors.Klarna.String():                 "Klarna paired username (`PK<digits>_<8>`) + password Basic-auth credential near klarna keyword, verified via /payments/v1/sessions on api.klarna.com (RawV2 carries the password)",
	detectors.Lever.String():                  "Lever recruiting API key (40-hex) near lever keyword, verified via /v1/users on api.lever.co with HTTP Basic auth (key as username)",
	detectors.Greenhouse.String():             "Greenhouse Harvest API key (40+ alnum) near greenhouse keyword, verified via /v1/users on harvest.greenhouse.io with HTTP Basic auth (key as username)",
	detectors.Gusto.String():                  "Gusto OAuth bearer token (40+ hex) near gusto keyword, verified via /v1/me on api.gusto.com with Bearer auth",
	detectors.Deel.String():                   "Deel API token (40+ alnum) near deel keyword, verified via /rest/v2/users/me on api.letsdeel.com with Bearer auth",
	detectors.Rippling.String():               "Rippling API token (40+ alnum) near rippling keyword, verified via /platform/api/me on api.rippling.com with Bearer auth",
	detectors.PropelAuth.String():             "PropelAuth backend API key (40+ alnum) near propelauth keyword, verified via /api/backend/v1/end_user_api_keys/validate on auth.propelauth.com with Bearer auth",
	detectors.LambdaLabs.String():             "Lambda Labs Cloud API key (40+ alnum) near lambdalabs / lambda_labs keyword, verified via /api/v1/instance-types on cloud.lambdalabs.com with HTTP Basic auth (key as username)",
	detectors.Anyscale.String():               "Anyscale API key (`esct_<base64ish>` or 40+ alnum) near anyscale keyword, verified via /api/v2/users/me on console.anyscale.com with Bearer auth",
	detectors.SambaNova.String():              "SambaNova Cloud API key (40+ alnum) near sambanova keyword, verified via /v1/models on api.sambanova.ai with Bearer auth",
	detectors.Baseten.String():                "Baseten API key (40+ alnum) near baseten keyword, verified via /api/v1/models on app.baseten.co with `Api-Key <key>` auth",
	detectors.Turso.String():                  "Turso platform API token (40+ alnum) near turso keyword, verified via /v1/auth/validate-token on api.turso.tech with Bearer auth",
	detectors.Knock.String():                  "Knock notifications service API key (`sk_(test|live)_<32+ alnum>`), verified via /v1/users on api.knock.app with Bearer auth — `sk_live_` verified surfaces SeverityCritical via DefaultSeverity",
	detectors.Shippo.String():                 "Shippo shipping API key (`shippo_(live|test)_<40+ alnum>`), verified via /v1/addresses on api.goshippo.com with `ShippoToken <key>` auth",
	detectors.EasyPost.String():               "EasyPost API key (`EZAK<alnum>` or `EZTK<alnum>`), verified via /api/v2/api_keys on api.easypost.com with HTTP Basic auth (key as username)",
	detectors.TaxJar.String():                 "TaxJar API token (40+ alnum) near taxjar keyword, verified via /v2/categories on api.taxjar.com with Bearer auth",
	detectors.Avalara.String():                "Avalara AvaTax account_id + license_key pair near avalara / avatax keyword, verified via /api/v2/utilities/ping on rest.avatax.com (sandbox: sandbox-rest.avatax.com) with HTTP Basic auth (RawV2 carries the license)",
	detectors.BambooHR.String():               "BambooHR API key (40+ alnum) near bamboohr keyword — unverified by design (per-subdomain host `<co>.bamboohr.com`), apiBase override required",
	detectors.Paylocity.String():              "Paylocity OAuth client_id + client_secret pair near paylocity keyword — unverified by design (sandbox vs production gateway), apiBase override required (RawV2 carries the secret)",
	detectors.DeepSeek.String():               "DeepSeek API key (`sk-<48+ alnum>`) near deepseek keyword, verified via /v1/models on api.deepseek.com with Bearer auth",
	detectors.MonsterAPI.String():             "MonsterAPI inference API key (40+ alnum) near monsterapi keyword, verified via /v1/health on api.monsterapi.ai with Bearer auth",
	detectors.FriendliAI.String():             "FriendliAI API token (`flp_<32+ alnum>`), verified via /v1/models on api.friendli.ai with Bearer auth",
	detectors.AppDynamics.String():            "AppDynamics API client + secret pair near appdynamics keyword — unverified by design (per-controller host `<acct>.saas.appdynamics.com`), apiBase override required (RawV2 carries the secret)",
	detectors.ElasticAPM.String():             "Elastic APM secret token (40+ alnum) near elastic-apm / elasticapm keyword — unverified by design (per-deployment APM Server host), apiBase override required",
	detectors.Lightstep.String():              "Lightstep / ServiceNow Cloud Observability API key (40+ alnum) near lightstep keyword, verified via /public/v0.2/projects on api.lightstep.com with Bearer auth",
	detectors.EmailJS.String():                "EmailJS user_id + private access_token pair near emailjs keyword, verified via /api/v1.0/account on api.emailjs.com with Bearer auth (RawV2 carries the access_token)",
	detectors.Mailjet.String():                "Mailjet API key + API secret pair (each 32-hex) near mailjet keyword, verified via /v3/REST/myprofile on api.mailjet.com with HTTP Basic auth (RawV2 carries the secret)",
	detectors.Hasura.String():                 "Hasura Cloud admin secret (40+ alnum) near hasura keyword — unverified by design (per-project host `<project>.hasura.app`), apiBase override required",
	detectors.AI21Labs.String():               "AI21 Labs API key (32+ alnum) near ai21 keyword, verified via /studio/v1/tokenize on api.ai21.com with Bearer auth",
	detectors.OctoAI.String():                 "OctoAI / OctoML inference token (40+ alnum / JWT-shape) near octoai / octoml keyword, verified via /v1/models on text.octoai.run with Bearer auth",
	detectors.PingOne.String():                "PingOne worker app client_id + client_secret pair near pingone keyword, verified via /as/token on auth.pingone.com with HTTP Basic auth (RawV2 carries the secret)",
	detectors.ForgeRock.String():              "ForgeRock / Ping Identity Cloud SSO token (40+ alnum) near forgerock keyword — unverified by design (per-tenant host `<tenant>.forgeblocks.com`), apiBase override required",
	detectors.KeyCloak.String():               "Keycloak client_id + client_secret pair near keycloak keyword — unverified by design (per-deployment host + realm required), apiBase override required (RawV2 carries the secret)",
	detectors.Marketo.String():                "Marketo REST API client_id + client_secret pair near marketo / mktorest keyword — unverified by design (per-munchkin host `<munchkin>.mktorest.com`), apiBase override required (RawV2 carries the secret)",
	detectors.Eloqua.String():                 "Oracle Eloqua REST API client_id + client_secret pair near eloqua keyword — unverified by design (per-pod host `secure.p<NN>.eloqua.com`), apiBase override required (RawV2 carries the secret)",
	detectors.Pardot.String():                 "Salesforce Pardot / Account Engagement business_unit_id + access_token pair near pardot keyword, verified via /api/v5/objects/account on pi.pardot.com with Bearer + Pardot-Business-Unit-Id header (RawV2 carries the token)",
	detectors.Kustomer.String():               "Kustomer API token (40+ alnum / JWT-shape) near kustomer keyword, verified via /v1/users/current on api.kustomerapp.com with Bearer auth",
	detectors.Freshchat.String():              "Freshchat API token (40+ alnum / JWT-shape) near freshchat keyword, verified via /v2/agents on api.freshchat.com with Bearer auth",
	detectors.OracleCloud.String():            "Oracle Cloud Infrastructure (OCI) auth token (32+ alnum) near oraclecloud / ocid1. / oci_ keyword — unverified by design (per-region tenancy host required), apiBase override required",
	detectors.IBMCloud.String():               "IBM Cloud IAM API key (40+ alnum) near ibmcloud / ibm_cloud keyword, verified via /identity/token on iam.cloud.ibm.com with the IAM apikey grant_type",
	detectors.RingCentral.String():            "RingCentral OAuth client_id + client_secret pair near ringcentral keyword, verified via /restapi/oauth/token on platform.ringcentral.com with HTTP Basic auth (RawV2 carries the secret)",
	detectors.DialPad.String():                "Dialpad API token (40+ alnum) near dialpad keyword, verified via /api/v2/users on dialpad.com with Bearer auth",
	detectors.SignalWire.String():             "SignalWire project_id + API token pair near signalwire keyword — unverified by design (per-space host `<space>.signalwire.com`), apiBase override required (RawV2 carries the token)",
	detectors.Writer.String():                 "Writer.com Writer-Key API token (40+ alnum) near writer keyword, verified via /v1/models on api.writer.com with Bearer auth",
	detectors.Filebase.String():               "Filebase S3-compatible access_key + secret_key pair near filebase keyword — unverified by design (S3 SigV4 requires bucket + region not in chunk), apiBase override required (RawV2 carries the secret)",
	detectors.Storj.String():                  "Storj DCS access grant / API key (40+ alnum near storj or grant prefix) — unverified by design (per-satellite host required), apiBase override required",
	detectors.MongoDBRealm.String():           "MongoDB Realm / Atlas App Services API key (UUID-shape, 36 chars) near realm or app_services keyword — unverified by design (per-app `<app-id>` required for /api/client/v2.0/app/<app-id>/auth/providers/api-key/login), apiBase override required",
	detectors.CloudBees.String():              "CloudBees CI / Jenkins X user_id + api_token pair near cloudbees keyword — unverified by design (per-controller host required), apiBase override required (RawV2 carries the token)",
	detectors.Codeship.String():               "Codeship Pro API username + password pair near codeship keyword, verified via /v2/auth on api.codeship.com with HTTP Basic auth (RawV2 carries the password)",
	detectors.Okteto.String():                 "Okteto Cloud API token (40+ alnum / `okteto_`-prefixed) near okteto keyword, verified via /api/v1/users/me on cloud.okteto.com with Bearer auth",
	detectors.Freshsales.String():             "Freshsales / Freshworks CRM API token (40+ alnum) near freshsales / freshworks keyword — unverified by design (per-domain host `<domain>.myfreshworks.com`), apiBase override required",
	detectors.Copper.String():                 "Copper CRM user_email + access_token pair near copper keyword, verified via /developer_api/v1/account on api.copper.com with X-PW-AccessToken / X-PW-Application / X-PW-UserEmail headers (RawV2 carries the token)",
	detectors.Trustpilot.String():             "Trustpilot Business API key (32+ alnum) near trustpilot keyword, verified via /v1/business-units on api.trustpilot.com with apikey query param",
	detectors.SentinelOne.String():            "SentinelOne Singularity API token (80+ alnum) near sentinelone / s1 keyword — unverified by design (per-management-console host `<console>.sentinelone.net`), apiBase override required",
	detectors.Gladly.String():                 "Gladly customer support agent_email + api_token pair near gladly keyword — unverified by design (per-org host `<org>.gladly.com`), apiBase override required (RawV2 carries the token)",
	detectors.HelpScout.String():              "Help Scout app_id + app_secret pair near helpscout keyword, verified via /v2/oauth2/token on api.helpscout.net with client_credentials grant (RawV2 carries the secret)",
	detectors.Mailboxlayer.String():           "Mailboxlayer email verification access_key (32 hex) near mailboxlayer keyword, verified via /api/check on apilayer.net with access_key query param",
	detectors.Hunter.String():                 "Hunter.io email-finder API key (40 hex) near hunter keyword, verified via /v2/account on api.hunter.io with api_key query param",
	detectors.AlephAlpha.String():             "Aleph Alpha API token (40+ alnum) near aleph keyword, verified via /users/me on api.aleph-alpha.com with Bearer auth",
	detectors.Inflection.String():             "Inflection AI API token (40+ alnum) near inflection keyword, verified via /v1/models on api.inflection.ai with Bearer auth",
	detectors.CharacterAI.String():            "Character.AI session token (40-80 hex) near character keyword, verified via /chat/user on plus.character.ai with Token auth header",
	detectors.Hyperbolic.String():             "Hyperbolic AI inference token (JWT-shaped eyJ...eyJ...sig) near hyperbolic keyword, verified via /v1/models on api.hyperbolic.xyz with Bearer auth",
	detectors.LeptonAI.String():               "Lepton AI workspace token (32+ alnum) near lepton keyword, verified via /api/v1/workspace on dashboard.lepton.ai with Bearer auth",
	detectors.NovitaAI.String():               "Novita AI API key (`sk_`-prefixed alnum) near novita keyword, verified via /v3/user on api.novita.ai with Bearer auth",
	detectors.Kickbox.String():                "Kickbox email-verification key (`live_`/`test_` alnum) near kickbox keyword, verified via /v2/verify on api.kickbox.com with apikey query param",
	detectors.AbstractAPI.String():            "AbstractAPI key (32 hex) near abstract keyword, verified via /v1/?api_key=... on emailvalidation.abstractapi.com with api_key query param",
	detectors.NeverBounce.String():            "NeverBounce API key (`secret_`/`private_` alnum) near neverbounce keyword, verified via /v4/account/info on api.neverbounce.com with key query param",
	detectors.Snov.String():                   "Snov.io OAuth2 client_id + client_secret pair near snov keyword, verified via /v1/oauth/access_token (client_credentials) on api.snov.io (RawV2 carries the secret)",
	detectors.Apollo.String():                 "Apollo.io sales-engagement API key (22 alnum) near apollo keyword, verified via /v1/auth/health on api.apollo.io with X-Api-Key header",
	detectors.Lemlist.String():                "Lemlist user_email + api_key pair near lemlist keyword, verified via /api/team on api.lemlist.com with HTTP Basic auth (RawV2 carries the api_key)",
	detectors.Authentik.String():              "Authentik identity-provider token (60+ alnum) near authentik keyword — unverified by design (per-tenant host `<tenant>.goauthentik.io` or self-hosted), apiBase override required",
	detectors.Etherscan.String():              "Etherscan blockchain explorer API key (34 alnum) near etherscan keyword, verified via /api?module=stats&action=ethsupply on api.etherscan.io with apikey query param",
	detectors.Alchemy.String():                "Alchemy blockchain RPC API key (32 alnum) near alchemy keyword, verified via JSON-RPC eth_blockNumber on eth-mainnet.g.alchemy.com/v2/<key>",
	detectors.Infura.String():                 "Infura project ID (32 hex) near infura keyword, verified via JSON-RPC eth_blockNumber on mainnet.infura.io/v3/<id>",
	detectors.QuickNode.String():              "QuickNode endpoint URL or token (32+ alnum) near quicknode keyword — unverified by design (per-endpoint host required), apiBase override required",
	detectors.Moralis.String():                "Moralis Web3 API key (64+ alnum/JWT-shaped) near moralis keyword, verified via /api/v2.2/dateToBlock on deep-index.moralis.io with X-API-Key header",
	detectors.Blockfrost.String():             "Blockfrost Cardano API key (`mainnet`/`preprod`/`preview`/`testnet` prefix + 32 alnum) near blockfrost keyword, verified via /api/v0/health on cardano-mainnet.blockfrost.io with project_id header",
	detectors.Helius.String():                 "Helius Solana RPC API key (UUID shape) near helius keyword, verified via JSON-RPC getHealth on mainnet.helius-rpc.com/?api-key=<key>",
	detectors.TheGraph.String():               "The Graph Studio API key (32 hex) near thegraph keyword, verified via /api/<key>/subgraphs/id/... on gateway.thegraph.com",
	detectors.OpenSea.String():                "OpenSea API key (32 hex) near opensea keyword, verified via /api/v2/collections on api.opensea.io with X-API-KEY header",
	detectors.Milvus.String():                 "Milvus / Zilliz Cloud API token (`db_`-prefixed alnum) near milvus keyword — unverified by design (per-cluster `<cluster>.api.zillizcloud.com` host required), apiBase override required",
	detectors.Beeceptor.String():              "Beeceptor HTTP mock API key (32+ alnum) near beeceptor keyword, verified via /api/v1/projects on app.beeceptor.com with Authorization Bearer header",
	detectors.Smee.String():                   "smee.io webhook proxy channel URL (https://smee.io/<id>) near smee keyword — unverified by design (channel URL is the credential, no auth probe)",
	detectors.Ory.String():                    "Ory Network workspace API key (`ory_`-prefixed alnum) near ory keyword, verified via /projects on api.console.ory.sh with Authorization Bearer header",
	detectors.Supertokens.String():            "SuperTokens core API key (32+ alnum) near supertokens keyword — unverified by design (per-deployment self-hosted core URL required), apiBase override required",
	detectors.Statsig.String():                "Statsig Console / server-secret API key (`console-`/`secret-` prefix + alnum) near statsig keyword, verified via /v1/get_id_lists on statsigapi.net with STATSIG-API-KEY header",
	detectors.GrowthBook.String():             "GrowthBook secret API key (`secret_admin_`/`secret_user_` prefix + alnum) near growthbook keyword, verified via /api/v1/features on api.growthbook.io with Authorization Bearer header",
	detectors.DevCycle.String():               "DevCycle server / management API key (`dvc_server_`/`dvc_mgmt_` prefix + alnum) near devcycle keyword, verified via /v1/projects on api.devcycle.com with Authorization Bearer header",
	detectors.PubNub.String():                 "PubNub realtime publish / subscribe / secret key (`pub-c-`/`sub-c-`/`sec-c-` UUID) near pubnub keyword, verified via /v1/keys on admin.pubnub.com with X-PN-Key header",
	detectors.LiveKit.String():                "LiveKit realtime audio/video API key (`API` + 12 alnum) + secret pair near livekit keyword — unverified by design (per-deployment self-hosted host or LiveKit Cloud project URL required), apiBase override required (RawV2 carries the secret)",
	detectors.AgoraIO.String():                "Agora.io realtime app ID + app certificate pair (32 hex each) near agora keyword — unverified by design (signed RTC token issuance is offline, no auth probe), RawV2 carries the certificate",
	detectors.DailyCo.String():                "Daily.co realtime video API key (64 hex) near daily keyword, verified via /v1/rooms on api.daily.co with Authorization Bearer header",
	detectors.Meilisearch.String():            "Meilisearch master / admin API key (32+ alnum) near meilisearch keyword — unverified by design (per-deployment host required), apiBase override required",
	detectors.Typesense.String():              "Typesense API key (32+ alnum) near typesense keyword — unverified by design (per-deployment host required), apiBase override required",
	detectors.Marqo.String():                  "Marqo Cloud API key (`mzpat_` prefix + alnum) near marqo keyword — unverified by design (per-cluster host required), apiBase override required",
	detectors.Kong.String():                   "Kong Konnect personal access token (`kpat_` prefix + alnum) near kong keyword, verified via /v0/me on global.api.konghq.com with Authorization Bearer header",
	detectors.WebhookRelay.String():           "WebhookRelay token (key + secret pair, `whrelay-` prefix + alnum) near webhookrelay keyword, verified via /v1/tokens on my.webhookrelay.com with HTTP Basic auth (RawV2 carries the secret)",
	detectors.RequestBin.String():             "RequestBin / Pipedream webhook URL (https://*.m.pipedream.net/<id>) near pipedream/requestbin keyword — unverified by design (URL is the credential, posting probes triggers events)",
	detectors.Ahrefs.String():                 "Ahrefs SEO API token (32+ alnum) near ahrefs keyword, verified via /v3/subscription-info on api.ahrefs.com with Authorization Bearer header",
	detectors.Semrush.String():                "Semrush SEO API key (32 hex) near semrush keyword, verified via /management/v1/limits on api.semrush.com with `key` query param",
	detectors.June.String():                   "June.so analytics write key (32 alnum) near june keyword, verified via /sdk/track on api.june.so with HTTP Basic auth",
	detectors.Workday.String():                "Workday OAuth bearer token (alnum) near workday keyword — unverified by design (per-tenant `<tenant>.workday.com` host required), apiBase override required",
	detectors.Qualys.String():                 "Qualys VMDR API username + password pair near qualys keyword — unverified by design (per-region `qualysapi.<region>.qualys.com` host required), apiBase override required (RawV2 carries the password)",
	detectors.Nebius.String():                 "Nebius AI Studio API key (`AAAA` JWT-like prefix + alnum) near nebius keyword, verified via /v1/models on api.studio.nebius.ai with Authorization Bearer header",
	detectors.DashScope.String():              "Alibaba DashScope / Qwen API key (`sk-` prefix + 32 alnum) near dashscope keyword, verified via /api/v1/models on dashscope.aliyuncs.com with Authorization Bearer header",
	detectors.ModelScope.String():             "ModelScope API token (`ms-` prefix + UUID) near modelscope keyword, verified via /v1/models on api-inference.modelscope.cn with Authorization Bearer header",
	detectors.Dify.String():                   "Dify LLM ops API key (`app-` or `dataset-` prefix + 32 alnum) near dify keyword, verified via /v1/info on api.dify.ai with Authorization Bearer header",
	detectors.LobeHub.String():                "LobeHub / LobeChat API key (`lobehub-` prefix + alnum) near lobehub keyword — unverified by design (self-hosted per-deployment host required), apiBase override required",
	detectors.FusionAuth.String():             "FusionAuth API key (32 hex with optional dashes) near fusionauth keyword — unverified by design (per-tenant host required), apiBase override required",
	detectors.Casdoor.String():                "Casdoor client secret (`csdr_` prefix + alnum) near casdoor keyword — unverified by design (per-deployment host required), apiBase override required",
	detectors.EdgeDBCloud.String():            "EdgeDB Cloud secret key (`edbt_` prefix + alnum) near edgedb keyword — unverified by design (per-instance host required), apiBase override required",
	detectors.PrismaData.String():             "Prisma Data Platform service token (`pdp_` prefix + alnum) near prisma keyword, verified via /v1/me on cloud.prisma.io with Authorization Bearer header",
	detectors.OpenSearchCloud.String():        "OpenSearch Service / Aiven OpenSearch credentials (`os_` prefix + alnum) near opensearch keyword — unverified by design (per-domain host required), apiBase override required",
	detectors.ChromaCloud.String():            "Chroma Cloud API key (`ck-` prefix + alnum) near chroma keyword, verified via /api/v2/auth/identity on api.trychroma.com with X-Chroma-Token header",
	detectors.Biconomy.String():               "Biconomy paymaster API key (`pm_` prefix + alnum) near biconomy keyword — unverified by design (per-network endpoint, posting probes consumes gas), apiBase override required",
	detectors.SAPAriba.String():               "SAP Ariba API key (32+ alnum) near ariba keyword — unverified by design (per-tenant `<region>.api.ariba.com` host required), apiBase override required",
	detectors.OracleNetSuite.String():         "Oracle NetSuite OAuth token ID + secret pair (32 hex each) near netsuite keyword — unverified by design (per-account host `<account>.suitetalk.api.netsuite.com` required), apiBase override required (RawV2 carries the secret)",
	detectors.TravisCI.String():               "Travis CI personal access token (22 alnum) near travis keyword, verified via /user on api.travis-ci.com with Authorization token header",
	detectors.Watsonx.String():                "IBM watsonx.ai API key (44 base64url chars) near watsonx keyword, verified via /v2/foundation_model_specs on api.dataplatform.cloud.ibm.com with Authorization Bearer header",
	detectors.Harbor.String():                 "Harbor container registry CLI secret / robot account password (16+ alnum) near harbor keyword — unverified by design (self-hosted per-deployment host required), apiBase override required",
	detectors.Fivetran.String():               "Fivetran API key+secret pair (20 alnum each) near fivetran keyword, verified via /v1/users on api.fivetran.com with HTTP Basic auth (RawV2 carries the secret)",
	detectors.Airbyte.String():                "Airbyte access token (JWT-shaped) near airbyte keyword — unverified by design (self-hosted vs cloud per-deployment host required), apiBase override required",
	detectors.Coinbase.String():               "Coinbase API key+secret pair (32 alnum + 64 alnum) near coinbase keyword, unsigned-bearer verify against /v2/user on api.coinbase.com (production HMAC path 401s — mocks verify cleanly; RawV2 carries the secret)",
	detectors.Bitfinex.String():               "Bitfinex API key+secret pair (43 alnum each) near bitfinex keyword, unsigned-bearer verify against /v2/auth/r/wallets on api.bitfinex.com (production HMAC path 401s — mocks verify cleanly; RawV2 carries the secret)",
	detectors.Kraken.String():                 "Kraken exchange API key+secret pair (56 base64 + 88 base64) near kraken keyword, unsigned-bearer verify against /0/private/Balance on api.kraken.com (production HMAC path 401s — mocks verify cleanly; RawV2 carries the secret)",
	detectors.Outreach.String():               "Outreach.io OAuth access token (40-80 base64url) near outreach keyword, verified via /api/v2 on api.outreach.io with Authorization Bearer header",
	detectors.SalesLoft.String():              "Salesloft API key (64 hex chars) near salesloft keyword, verified via /v2/me on api.salesloft.com with Authorization Bearer header",
	detectors.ZoomInfo.String():               "ZoomInfo OAuth access token (JWT-shaped) near zoominfo keyword, verified via /lookup on api.zoominfo.com with Authorization Bearer header",
	detectors.Gigya.String():                  "SAP Customer Data Cloud (Gigya) API key+secret pair near gigya keyword — unverified by design (per-data-center `<region>.gigya.com` host required), apiBase override required (RawV2 carries the secret)",
	detectors.MoonPay.String():                "MoonPay API key (`pk_(test|live)_` / `sk_(test|live)_` prefix + alnum) near moonpay keyword, verified via /v3/transactions on api.moonpay.com with Api-Key header",
	detectors.NearRPC.String():                "NEAR Protocol RPC API key (32-64 alnum) near pagoda / fastnear / near-rpc keyword — unverified by design (per-endpoint provider host required), apiBase override required",
	detectors.PolygonRPC.String():             "Polygon (PoS / zkEVM) RPC API key (32-64 alnum) near polygon-rpc / polygon-zkevm keyword — unverified by design (per-endpoint provider host required), apiBase override required",
	detectors.Sproutsocial.String():           "Sprout Social API access token (32-64 hex) near sproutsocial keyword, verified via /v1/metadata/client on api.sproutsocial.com with Authorization Bearer header",
	detectors.Buffer.String():                 "Buffer (social-media scheduling) access token (40-50 alnum) near buffer keyword, verified via /1/user.json on api.bufferapp.com with access_token query parameter",
	detectors.Hootsuite.String():              "Hootsuite OAuth access token (32-64 hex) near hootsuite keyword, verified via /v1/me on platform.hootsuite.com with Authorization Bearer header",
	detectors.MagicLabs.String():              "Magic (magic.link) secret API key (`sk_(live|test)_` prefix + alnum) near magic keyword, verified via /v1/admin/auth/user/get on api.magic.link with X-Magic-Secret-Key header",
	detectors.Pipedream.String():              "Pipedream API token (32-80 hex) near pipedream keyword, verified via /v1/users/me on api.pipedream.com with Authorization Bearer header",
	detectors.Make.String():                   "Make.com (Integromat) API token (UUID) near make.com / integromat keyword, verified via /api/v2/users/me on us1.make.com with Authorization Token header",
	detectors.N8N.String():                    "n8n workflow-automation API key (JWT-shaped) near n8n keyword — unverified by design (self-hosted per-deployment host required), apiBase override required to verify via /api/v1/me with X-N8N-API-KEY header",
	detectors.SageIntacct.String():            "Sage Intacct sender / user password (12-32 alnum) near intacct keyword — unverified by design (XML-over-HTTPS with multi-credential <login> envelope required), apiBase override required",
	detectors.MicrosoftDynamics.String():      "Microsoft Dynamics 365 access token (AAD JWT) near dynamics / dataverse keyword — unverified by design (per-org `<org>.crm[N].dynamics.com` host required), apiBase override required to verify via /api/data/v9.2/WhoAmI with Authorization Bearer header",
	detectors.Freshmarketer.String():          "Freshmarketer (Freshworks marketing) API key (20-32 alnum) near freshmarketer keyword, verified via /crm/sales/api/me on app.freshmarketer.com with Token token=<key> Authorization header",
	detectors.VespaCloud.String():             "Vespa Cloud (search-engine PaaS) API token (`vespa_cloud_` prefix + alnum/_) near vespa keyword — unverified by design (per-application `<tenant>.<app>.<env>.z.vespa-cloud.com` host required), apiBase override required",
	detectors.SimilarWeb.String():             "SimilarWeb API key (32 hex) near similarweb keyword, verified via /v1/website/{domain}/total-traffic-and-engagement/visits on api.similarweb.com with api_key query parameter",
	detectors.Vectra.String():                 "Vectra AI (NDR) API token (32-64 hex) near vectra keyword — unverified by design (per-tenant `<tenant>.vectra.ai` host required), apiBase override required to verify via /api/v3.3/users with Authorization Token header",
	detectors.Expel.String():                  "Expel (MDR) API token (32-64 alnum) near expel keyword, verified via /api/v2/users/current on workbench.expel.io with Authorization Bearer header",
	detectors.BeyondTrust.String():            "BeyondTrust (privileged access management) API key (64-128 alnum) near beyondtrust / ps-auth keyword — unverified by design (per-tenant `<id>.beyondtrustcloud.com` host required), apiBase override required to verify via /api/public/v3/Auth/SignAppin with Authorization PS-Auth header",
	detectors.GainSight.String():              "Gainsight customer-success API access key (32-64 alnum) near gainsight keyword, verified via /v1/users/me on api.gainsightcloud.com with Accesskey header",
	detectors.VertexAI.String():               "Google Vertex AI access token (AAD/OAuth-style JWT) near vertex / aiplatform keyword — unverified by design (per-project `<region>-aiplatform.googleapis.com` host required), apiBase override required to verify via /v1/projects/{project} with Authorization Bearer header",
	detectors.RekaAI.String():                 "Reka AI API key (32-64 alnum) near reka keyword, verified via /v1/models on api.reka.ai with X-Api-Key header",
	detectors.AIHorde.String():                "AI Horde (Stable Horde) API key (UUID-shaped) near aihorde / stablehorde keyword, verified via /api/v2/find_user on aihorde.net with apikey header",
	detectors.OllamaCloud.String():            "Ollama Cloud API key (40-80 alnum / base64url) near ollama keyword, verified via /api/tags on ollama.com with Authorization Bearer header",
	detectors.RunwayML.String():               "RunwayML SDK secret key (`key_` prefix + 48-64 alnum) near runwayml / runway keyword, verified via /v1/organization on api.runwayml.com with Authorization Bearer header",
	detectors.Planhat.String():                "Planhat customer-success tenant token (32-64 alnum) near planhat keyword — unverified by design (per-tenant `<tenant>.planhat.com` host required), apiBase override required to verify via /api/users/me with Authorization Bearer header",
	detectors.Vitally.String():                "Vitally customer-success API token (32-64 alnum) near vitally keyword, verified via /resources/v2024 on api.vitally.io with Authorization Basic header (key as username, empty password)",
	detectors.ChurnZero.String():              "ChurnZero appKey (UUID-shaped) near churnzero keyword, verified via /i on analytics.churnzero.net with Z-AppKey header",
	detectors.Totango.String():                "Totango service token (32-64 alnum) near totango keyword — unverified by design (per-tenant `<tenant>.totango.com` host required), apiBase override required to verify via /api/v3/accounts/search with app-token header",
	detectors.Sendoso.String():                "Sendoso direct-mail API key (`sendoso_` prefix + 32-64 alnum) near sendoso keyword, verified via /api/v3/me on api.sendoso.com with Authorization Bearer header",
	detectors.Paystack.String():               "Paystack secret key (`sk_(live|test)_` prefix + 40-50 alnum) near paystack keyword, verified via /transaction/totals on api.paystack.co with Authorization Bearer header (sk_live_ surfaces SeverityCritical)",
	detectors.Flutterwave.String():            "Flutterwave secret key (`FLWSECK(_TEST|-)` prefix + 32-64 alnum) near flutterwave keyword, verified via /v3/transactions on api.flutterwave.com with Authorization Bearer header",
	detectors.Mandiant.String():               "Mandiant Advantage API key + secret pair (32-64 alnum each) near mandiant / fireeye keyword, verified via /token (OAuth client_credentials) on api.intelligence.fireeye.com with HTTP Basic auth (Raw=key, RawV2=key:secret)",
	detectors.AbnormalSec.String():            "Abnormal Security API token (32-64 alnum) near abnormal / abnormalsecurity keyword, verified via /v1/threats on api.abnormalplatform.com with Authorization Bearer header",
	detectors.Ortto.String():                  "Ortto (Autopilot) marketing-automation API key (`pak_` prefix + 32-64 alnum) near ortto / autopilothq keyword, verified via /v1/person/get on api.ap3api.com with X-Api-Key header",
	detectors.Persona.String():                "Persona (withpersona.com) KYC API key (`persona_(production|sandbox)_` prefix + alnum) verified via /api/v1/inquiries on api.withpersona.com with Authorization Bearer header",
	detectors.Sumsub.String():                 "Sumsub KYC app token (`prd|tst|sbx:` prefix) + secret pair near sumsub keyword, verified via /resources/applicants/-/info on api.sumsub.com with HTTP Basic auth (RawV2 carries the secret)",
	detectors.Onfido.String():                 "Onfido KYC API token (`api_(live|sandbox)_(us|eu|ca)_` prefix + alnum) verified via /v3.6/applicants on api.onfido.com with Authorization Token header",
	detectors.Jumio.String():                  "Jumio KYC API token + secret pair near jumio / netverify keyword — unverified by design (per-data-center `<region>.netverify.com` host required), apiBase override required (RawV2 carries the secret)",
	detectors.Trulioo.String():                "Trulioo GlobalGateway API key (32-64 alnum) near trulioo keyword, verified via /customer/v1/configuration on api.globaldatacompany.com with x-trulioo-api-key header",
	detectors.ZeroBounce.String():             "ZeroBounce email-validation API key (32 hex) near zerobounce keyword, verified via /v2/getcredits on api.zerobounce.net with api_key query parameter",
	detectors.MailerSend.String():             "MailerSend API token (`mlsn.` prefix + JWT-shaped suffix) verified via /v1/me on api.mailersend.com with Authorization Bearer header",
	detectors.OpsLevel.String():               "OpsLevel API token (40-64 alnum) near opslevel keyword, verified via /graphql on api.opslevel.com with Authorization Bearer header",
	detectors.Codemagic.String():              "Codemagic mobile-CI API token (32-64 alnum) near codemagic keyword, verified via /apps on api.codemagic.io with x-auth-token header",
	detectors.LambdaTest.String():             "LambdaTest username + access_key pair near LT_ACCESS_KEY keyword, verified via /automation/api/v1/builds on api.lambdatest.com with HTTP Basic auth (RawV2 carries the access_key)",
	detectors.SauceLabs.String():              "Sauce Labs username + access_key (UUID) pair near SAUCE_ACCESS_KEY keyword, verified via /rest/v1/users/{user} on api.us-west-1.saucelabs.com with HTTP Basic auth (RawV2 carries the access_key)",
	detectors.Browserless.String():            "Browserless API token (32-64 alnum) near browserless keyword, verified via /pressure on chrome.browserless.io with token query parameter",
	detectors.Helicone.String():               "Helicone LLM-observability API key (`sk-helicone-` prefix + alnum) verified via /v1/user/query on api.helicone.ai with Authorization Bearer header",
	detectors.Portkey.String():                "Portkey AI-gateway API key (32-64 base64url) near portkey keyword, verified via /v1/virtual-keys on api.portkey.ai with x-portkey-api-key header",
	detectors.Langfuse.String():               "Langfuse public + secret key pair (`pk-lf-` + `sk-lf-` UUID-shaped) verified via /api/public/projects on cloud.langfuse.com with HTTP Basic auth (RawV2 carries the secret_key)",
	detectors.LangSmith.String():              "LangSmith API key (`lsv2_(pt|sk)_` prefix + hex segments) verified via /info on api.smith.langchain.com with x-api-key header",
	detectors.Wandb.String():                  "Weights & Biases API key (40 hex) near wandb keyword, verified via /graphql on api.wandb.ai with HTTP Basic auth (username `api`)",
	detectors.CometML.String():                "Comet ML API key (32-100 alnum) near comet keyword, verified via /api/rest/v2/account-details on www.comet.com with Authorization header",
	detectors.NeptuneAI.String():              "Neptune.ai API token (JWT shape carrying api_address) near neptune keyword, verified via /api/leaderboard/v1/me on app.neptune.ai with Authorization Bearer header",
	detectors.PromptLayer.String():            "PromptLayer API key (`pl_` prefix + hex) verified via /rest/get-prompt-template on api.promptlayer.com with X-API-KEY header",
	detectors.ArizeAI.String():                "Arize AI ML-observability API key (40-80 alnum) near arize keyword, verified via /v1/spaces on app.arize.com with Authorization Bearer header",
	detectors.Hyperproof.String():             "Hyperproof compliance API token (32-64 alnum) near hyperproof keyword, verified via /v1/users/me on api.hyperproof.app with Authorization Bearer header",
	detectors.Etsy.String():                   "Etsy Open API v3 keystring (24-32 alnum) near etsy keyword, verified via /v3/application/openapi-ping on api.etsy.com with x-api-key header",
	detectors.Walmart.String():                "Walmart Marketplace consumer-id (UUID) + secret pair near walmart keyword — paired (RawV2 carries the secret), verified via WM headers on marketplace.walmartapis.com",
	detectors.WooCommerce.String():            "WooCommerce REST consumer key + secret (`ck_` / `cs_` + 40 hex) — unverified by design (per-store `<store>.com/wp-json/wc/v3` host required), apiBase override required (RawV2 carries the cs)",
	detectors.Missiveapp.String():             "Missive API token (32-64 alnum) near missive keyword, verified via /v1/users on public.missiveapp.com with Authorization Bearer header",
	detectors.LiveChat.String():               "LiveChat personal access token (`dal:` prefix + colon-separated id/secret) verified via /v3.5/agent/action/list_my_profiles on api.livechatinc.com with Authorization Bearer header",
	detectors.HelpCrunch.String():             "HelpCrunch API token (JWT shape) near helpcrunch keyword, verified via /v1/agents on api.helpcrunch.com with Authorization Bearer header",
	detectors.DenoDeploy.String():             "Deno Deploy personal access token (`ddp_` prefix + alnum) verified via /v1/users/me on api.deno.com with Authorization Bearer header",
	detectors.Twingate.String():               "Twingate API token (`tk_` / `tkt_` prefix + base64url) — unverified by design (per-tenant `<network>.twingate.com` host required), apiBase override required",
	detectors.DBTCloud.String():               "dbt Cloud personal access token (`dbtu_` prefix + base64url) verified via /api/v2/accounts on cloud.getdbt.com with Authorization Token header",
	detectors.Tray.String():                   "Tray.io master token (`tray_` prefix + alnum) near tray keyword, verified via /core/v1/me on api.tray.io with Authorization Bearer header",
	detectors.Retool.String():                 "Retool API key (`retool_` prefix + alnum) verified via /api/v2/permissions/listGroupAndUser on api.retool.com with Authorization Bearer header",
	detectors.Expo.String():                   "Expo personal access token (24-32 alnum) near expo keyword, verified via /v2/auth/userInfo on exp.host with Authorization Bearer header",
	detectors.Alloy.String():                  "Alloy KYC API token + secret pair near alloy keyword — paired (RawV2 carries the secret), verified via HTTP Basic auth on sandbox.alloy.co",
	detectors.AuditBoard.String():             "AuditBoard GRC API token (32-64 alnum) near auditboard keyword, verified via /api/v1/me on app.auditboard.com with Authorization Bearer header",
	detectors.FireHydrant.String():            "FireHydrant incident-response API token (`fhb_` prefix + base64url) verified via /v1/ping on api.firehydrant.io with Authorization Bearer header",
	detectors.IncidentIO.String():             "incident.io API key (`inc_` prefix + base64url) verified via /v2/identity on api.incident.io with Authorization Bearer header",
	detectors.Rootly.String():                 "Rootly incident-response API key (`rootly_` prefix + alnum) verified via /v1/users/me on api.rootly.com with Authorization Bearer header",
	detectors.Sleuth.String():                 "Sleuth DORA-metrics API key (40 hex) near sleuth keyword, verified via /api/1.0/projects on app.sleuth.io with Authorization apikey header",
	detectors.Sparkpost.String():              "SparkPost transactional email API key (40 hex) near sparkpost keyword, verified via /api/v1/account on api.sparkpost.com with Authorization header",
	detectors.SendPulse.String():              "SendPulse client_id + secret pair near sendpulse keyword — paired (RawV2 carries the secret), verified via /oauth/access_token on api.sendpulse.com",
	detectors.Veriff.String():                 "Veriff KYC API key (UUID) + shared-secret pair near veriff keyword — paired (RawV2 carries the secret), verified via /v1/sessions on stationapi.veriff.com with X-AUTH-CLIENT header",
	detectors.IDnow.String():                  "IDnow KYC API token (32-64 alnum) near idnow keyword, verified via /api/v1/identifications on gateway.idnow.de with X-API-KEY header",
	detectors.Squarespace.String():            "Squarespace Commerce API key (UUID) near squarespace keyword, verified via /1.0/commerce/orders on api.squarespace.com with Authorization Bearer header",
	detectors.Traceloop.String():              "Traceloop LLM tracing API key (`tl_` prefix + alnum) verified via /v1/traces on api.traceloop.com with Authorization Bearer header",
	detectors.Klu.String():                    "Klu LLM ops API key (`klu_` prefix + alnum) verified via /v1/me on api.klu.ai with Authorization Bearer header",
	detectors.Langflow.String():               "Langflow API key (`lf_` prefix + alnum) verified via /api/v1/users/whoami on api.langflow.astra.datastax.com with x-api-key header",
	detectors.OpenPipe.String():               "OpenPipe LLM gateway API key (`opk_` prefix + alnum) verified via /api/v1/me on api.openpipe.ai with Authorization Bearer header",
	detectors.Lakera.String():                 "Lakera Guard LLM-security API key (32-64 alnum) near lakera keyword, verified via /v1/prompt_injection on api.lakera.ai with Authorization Bearer header",
	detectors.Footprint.String():              "Footprint KYC API key (`sk_test_` or `sk_live_` prefix + alnum) verified via /users on api.onefootprint.com with X-Footprint-Secret-Key header",
	detectors.Vouched.String():                "Vouched KYC API key (`pk_` prefix + alnum) verified via /api/jobs on verify.vouched.id with X-Api-Key header",
	detectors.Magento.String():                "Magento (Adobe Commerce) admin access token (32 alnum) near magento keyword, unverified-by-default (per-store host required)",
	detectors.BigCommerce.String():            "BigCommerce store API access token (`bc_` prefix + alnum) verified via /v2/store on api.bigcommerce.com with X-Auth-Token header",
	detectors.Faire.String():                  "Faire wholesale marketplace API key (`fai_` prefix + alnum) verified via /external-api/v2/orders on www.faire.com with X-FAIRE-ACCESS-TOKEN header",
	detectors.Tidio.String():                  "Tidio customer-chat API key (40 hex) near tidio keyword, verified via /panel/openapi/contacts on api.tidio.co with X-Tidio-Openapi-Key header",
	detectors.Looker.String():                 "Looker API3 client_id + client_secret pair (alnum) near looker keyword — paired (RawV2 carries the secret), verified via /api/4.0/login on lookerhost",
	detectors.DeepL.String():                  "DeepL API key (32 hex + `:fx` suffix or 36 hex Pro) verified via /v2/usage on api-free.deepl.com with Authorization DeepL-Auth-Key header",
	detectors.HackerOne.String():              "HackerOne identifier + API token pair near hackerone keyword — paired (RawV2 carries the token), verified via HTTP Basic auth on api.hackerone.com /v1/me",
	detectors.ZeroTier.String():               "ZeroTier Central API token (32 alnum) near zerotier keyword, verified via /api/v1/status on my.zerotier.com with Authorization Bearer header",
	detectors.Fiddler.String():                "Fiddler AI bearer token near fiddler keyword, verified via /v3/projects on api.fiddler.ai with Authorization Bearer header",
	detectors.Evidently.String():              "Evidently AI API token near evidently keyword, verified via /api/v2/auth/profile on app.evidently.cloud with X-Evidently-Token header",
	detectors.Sift.String():                   "Sift Science API key + account id pair near sift keyword — paired (RawV2 carries id:key), verified via HTTP Basic auth on api.sift.com /v205/users",
	detectors.Signifyd.String():               "Signifyd API key + team id pair near signifyd keyword — paired (RawV2 carries team:key), verified via HTTP Basic auth on api.signifyd.com /v3/teams",
	detectors.Kount.String():                  "Kount API key (JWT-shaped) near kount keyword, verified via /commerce/v1/orders on api-sandbox.kount.com with Authorization Bearer header",
	detectors.Intigriti.String():              "Intigriti researcher / company API token near intigriti keyword, verified via /external/researcher/v1/me on api.intigriti.com with Authorization Bearer header",
	detectors.Bugcrowd.String():               "Bugcrowd API token near bugcrowd keyword, verified via /user on api.bugcrowd.com with Authorization Token header",
	detectors.Semgrep.String():                "Semgrep API token near semgrep keyword, verified via /api/v1/deployments on semgrep.dev with Authorization Bearer header",
	detectors.TemporalCloud.String():          "Temporal Cloud API key (`tcsk_` prefix) verified via /api/v1/namespaces on cloud.temporal.io with Authorization Bearer header",
	detectors.PrefectCloud.String():           "Prefect Cloud API key (`pnu_` prefix) verified via /api/me on api.prefect.cloud with Authorization Bearer header",
	detectors.DagsterCloud.String():           "Dagster Cloud user token (`dgc_` prefix) verified via /graphql on dagster.cloud with Dagster-Cloud-Api-Token header",
	detectors.FlyMachines.String():            "Fly.io Machines API token (`fly_`/`FlyV1` prefix) verified via /v1/apps on api.machines.dev with Authorization Bearer header",
	detectors.VercelBlob.String():             "Vercel Blob read-write token (`vercel_blob_rw_` prefix) verified via /v0 on blob.vercel-storage.com with Authorization Bearer header",
	detectors.ModeAnalytics.String():          "Mode Analytics API token + secret pair near mode keyword — paired (RawV2 carries token:secret), verified via HTTP Basic auth on app.mode.com /api/account",
	detectors.PDFShift.String():               "PDFShift API key near pdfshift keyword, verified via /v3/credits/usage on api.pdfshift.io with HTTP Basic auth",
	detectors.Riskified.String():              "Riskified merchant API token near riskified keyword, verified via api.riskified.com with Authorization Bearer header",
	detectors.Forter.String():                 "Forter fraud-prevention API key near forter keyword, verified via api.forter.com with HTTP Basic auth",
	detectors.Socure.String():                 "Socure identity-verification API key near socure keyword, verified via api.socure.com with SocureApiKey header",
	detectors.Agenta.String():                 "Agenta LLM-ops API key (`agenta_` prefix) verified via /api/profile on cloud.agenta.ai with Authorization Bearer header",
	detectors.Kayako.String():                 "Kayako support API token near kayako keyword, verified via /api/v1/me on kayako.com with X-Auth-Token header",
	detectors.Customerly.String():             "Customerly customer-service API token near customerly keyword, verified via /v1/account on api.customerly.io with Authorization Bearer header",
	detectors.Jellyfish.String():              "Jellyfish engineering-analytics API token near jellyfish keyword, verified via /endpoints/users/me on api.jellyfish.co with X-API-Key header",
	detectors.Swimlane.String():               "Swimlane SOAR PAT token near swimlane keyword, verified via /api/user/me on app.swimlane.com with Private-Token header",
	detectors.Parabola.String():               "Parabola workflow API token near parabola keyword, verified via /v2/user on api.parabola.io with Authorization Bearer header",
	detectors.Mailmodo.String():               "Mailmodo email-marketing API key near mailmodo keyword, verified via /api/v1/lists on api.mailmodo.com with mmApiKey header",
	detectors.Neo4jAura.String():              "Neo4j Aura DBaaS API client credential near neo4j/aura keyword, verified via /v1/instances on api.neo4j.io with Authorization Bearer header",
	detectors.PortSwigger.String():            "PortSwigger Burp Suite Enterprise API key near portswigger/burp keyword, verified by embedding the key in the API path",
	detectors.Kagi.String():                   "Kagi search API token (`kagi_` prefix) verified via /api/v0/search on kagi.com with Authorization Bot header",
	detectors.ArduinoCloud.String():           "Arduino IoT Cloud client credential near arduino keyword, verified via /iot/v1/users/byme on api2.arduino.cc with Authorization Bearer header",
	detectors.ParticleIO.String():             "Particle.io IoT access token near particle keyword, verified via /v1/user on api.particle.io with Authorization Bearer header",
}

func toSARIFResult(f engine.Finding) sarifResult {
	r := sarifResult{
		RuleID:              f.Detector.String(),
		Level:               levelFor(f),
		Message:             sarifMessage{Text: f.Result.Redacted},
		PartialFingerprints: fingerprints(f),
	}
	uri, line := sarifLocationOf(f)
	if uri != "" {
		loc := sarifLocation{PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: uri},
		}}
		if line > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{StartLine: line}
		}
		r.Locations = []sarifLocation{loc}
	}
	props := make(map[string]any, len(f.Result.ExtraData)+2)
	for k, v := range f.Result.ExtraData {
		props[k] = v
	}
	props["verified"] = f.Result.Verified
	props["severity"] = f.Result.Severity.String()
	r.Properties = props
	return r
}

// levelFor maps a finding to a SARIF level. Critical and High findings
// surface as "error" so CI gates can fail on them; Medium is "warning"
// (noisy regex hits surface but don't block); Low/Info is "note".
// The mapping uses Severity rather than Verified directly so detectors
// that override severity (e.g. a custom rule marking a hit Critical
// even when unverified) propagate cleanly.
func levelFor(f engine.Finding) string {
	switch f.Result.Severity {
	case detectors.SeverityCritical, detectors.SeverityHigh:
		return "error"
	case detectors.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// fingerprints produces stable cross-run identifiers GitHub uses to
// dedup the same finding across PRs. We hash (detector, raw secret)
// because the secret-content hash survives file moves and renames; the
// (detector, raw, location) variant is added separately so location
// changes don't lose the dedup link.
func fingerprints(f engine.Finding) map[string]string {
	uri, line := sarifLocationOf(f)

	contentH := sha256.Sum256(append([]byte(f.Detector.String()+":"), f.Result.Raw...))
	out := map[string]string{
		"secret/v1": hex.EncodeToString(contentH[:]),
	}
	if uri != "" {
		locH := sha256.Sum256([]byte(uri))
		out["location/v1"] = hex.EncodeToString(locH[:]) + ":" + itoa(line)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	// Tiny int→string without strconv; keeps the dependency surface flat
	// and avoids the formatter for hot-path output.
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// sarifLocationOf extracts a (uri, line) pair from chunk metadata. Sources
// that don't have a file-shaped origin (S3, Slack) return their best-effort
// URI and zero line.
func sarifLocationOf(f engine.Finding) (string, int) {
	if f.Chunk == nil {
		return "", 0
	}
	md := f.Chunk.SourceMetadata
	switch {
	case md.Filesystem != nil:
		return md.Filesystem.Path, md.Filesystem.Line
	case md.Git != nil:
		return md.Git.File, md.Git.Line
	case md.GitHub != nil:
		return md.GitHub.File, md.GitHub.Line
	case md.S3 != nil:
		return "s3://" + md.S3.Bucket + "/" + md.S3.Key, 0
	case md.GCS != nil:
		return "gs://" + md.GCS.Bucket + "/" + md.GCS.Object, 0
	case md.Slack != nil:
		return md.Slack.Permalink, 0
	case md.Stdin != nil:
		return md.Stdin.Label, 0
	}
	return "", 0
}
