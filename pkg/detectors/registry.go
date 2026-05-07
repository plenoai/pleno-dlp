package detectors

import "sync"

var (
	mu        sync.RWMutex
	registry  = map[DetectorType]Detector{}
)

// Register adds a detector to the global registry. Concrete detector packages
// call this from init(). Duplicate types panic to surface the conflict early.
func Register(d Detector) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[d.Type()]; exists {
		panic("detectors: duplicate registration for type " + d.Type().String())
	}
	registry[d.Type()] = d
}

// All returns a snapshot of registered detectors. Safe for concurrent reads.
func All() []Detector {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Detector, 0, len(registry))
	for _, d := range registry {
		out = append(out, d)
	}
	return out
}

func (t DetectorType) String() string {
	switch t {
	case AWS:
		return "AWS"
	case GCPServiceAccount:
		return "GCPServiceAccount"
	case AzureStorageKey:
		return "AzureStorageKey"
	case GitHub:
		return "GitHub"
	case GitLab:
		return "GitLab"
	case SlackBotToken:
		return "SlackBotToken"
	case SlackWebhook:
		return "SlackWebhook"
	case OpenAI:
		return "OpenAI"
	case Anthropic:
		return "Anthropic"
	case Stripe:
		return "Stripe"
	case JWT:
		return "JWT"
	case PrivateKeyPEM:
		return "PrivateKeyPEM"
	case GenericHighEntropy:
		return "GenericHighEntropy"
	case Datadog:
		return "Datadog"
	case NPM:
		return "NPM"
	case PyPI:
		return "PyPI"
	case HuggingFace:
		return "HuggingFace"
	case Cloudflare:
		return "Cloudflare"
	case SendGrid:
		return "SendGrid"
	case Twilio:
		return "Twilio"
	case DigitalOcean:
		return "DigitalOcean"
	case Sentry:
		return "Sentry"
	case MongoDBAtlas:
		return "MongoDBAtlas"
	case HubSpot:
		return "HubSpot"
	case SalesforceRefresh:
		return "SalesforceRefresh"
	case NewRelic:
		return "NewRelic"
	case PagerDuty:
		return "PagerDuty"
	case Postman:
		return "Postman"
	case Mailgun:
		return "Mailgun"
	case TerraformCloud:
		return "TerraformCloud"
	case Vercel:
		return "Vercel"
	case Netlify:
		return "Netlify"
	case Heroku:
		return "Heroku"
	case Render:
		return "Render"
	case FlyIO:
		return "FlyIO"
	case Atlassian:
		return "Atlassian"
	case Notion:
		return "Notion"
	case Linear:
		return "Linear"
	case Asana:
		return "Asana"
	case Mixpanel:
		return "Mixpanel"
	case Segment:
		return "Segment"
	case Brevo:
		return "Brevo"
	case Mailchimp:
		return "Mailchimp"
	case Postmark:
		return "Postmark"
	case Okta:
		return "Okta"
	case Jira:
		return "Jira"
	case Confluence:
		return "Confluence"
	case BitbucketCloud:
		return "BitbucketCloud"
	case Square:
		return "Square"
	case PayPal:
		return "PayPal"
	case Plaid:
		return "Plaid"
	case Discord:
		return "Discord"
	case Cohere:
		return "Cohere"
	case Replicate:
		return "Replicate"
	case Mistral:
		return "Mistral"
	case Groq:
		return "Groq"
	case Intercom:
		return "Intercom"
	case OpenRouter:
		return "OpenRouter"
	case Together:
		return "Together"
	case Dropbox:
		return "Dropbox"
	case AzureAD:
		return "AzureAD"
	case Telegram:
		return "Telegram"
	case Shodan:
		return "Shodan"
	case VirusTotal:
		return "VirusTotal"
	case Doppler:
		return "Doppler"
	case Vault:
		return "Vault"
	case Algolia:
		return "Algolia"
	case Airtable:
		return "Airtable"
	case Grafana:
		return "Grafana"
	case LaunchDarkly:
		return "LaunchDarkly"
	case Auth0:
		return "Auth0"
	case Buildkite:
		return "Buildkite"
	case CircleCI:
		return "CircleCI"
	case Snyk:
		return "Snyk"
	case Spotify:
		return "Spotify"
	case PIIEmail:
		return "PIIEmail"
	case PIIUSSSN:
		return "PIIUSSSN"
	case PIICreditCard:
		return "PIICreditCard"
	case PIIIBAN:
		return "PIIIBAN"
	default:
		return "Unknown"
	}
}
