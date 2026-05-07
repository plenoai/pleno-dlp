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
	default:
		return "Unknown"
	}
}
