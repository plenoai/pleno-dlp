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
