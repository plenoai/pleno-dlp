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
	default:
		return "Unknown"
	}
}
