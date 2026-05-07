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
	detectors.PIIEmail.String():           "Email address (PII) — finding_class=pii",
	detectors.PIIUSSSN.String():           "US Social Security Number xxx-xx-xxxx (PII) — finding_class=pii",
	detectors.PIICreditCard.String():      "Credit card number with valid Luhn checksum (PII) — finding_class=pii",
	detectors.PIIIBAN.String():            "International Bank Account Number with valid mod-97 checksum (PII) — finding_class=pii",
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
