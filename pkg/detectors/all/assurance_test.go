package all

import (
	"slices"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func TestProviderConfirmedDetectorSetIsExplicitlyAudited(t *testing.T) {
	var got []string
	for _, detector := range detectors.All() {
		policy, ok := detector.(detectors.VerificationPolicy)
		if !ok || policy.MaxVerificationAssurance() != detectors.AssuranceProviderConfirmed {
			continue
		}
		got = append(got, detector.Type().String())
	}
	slices.Sort(got)

	want := []string{
		"AWS", "Apollo", "Datadog", "DocuSign", "GCPServiceAccount", "HubSpot", "IPStack", "OpenAI", "OpenWeather",
		"SendGrid", "SlackBotToken", "SlackWebhook", "Square", "Twilio", "TwilioAPIKey",
		// kingfisher parity batch 1 (tokenverify; Valid rules require an authenticated response)
		"OnePasswordServiceAccount", "AbuseIPDB", "Apify", "Bitly", "BraveSearch", "Cartesia", "CheckoutCom", "Cloudsmith", "ConfigCat", "CratesIO", "Cursor", "Databento", "DataGov", "DataStaxAstra", "Disqus", "FalAI", "FrameIO", "Infomaniak", "InfluxDB", "Instantly", "Ionic", "Labelbox", "Lichess", "LightOn", "LlamaCloud", "Mem0", "Mergify", "Midtrans", "NuGet", "Nylas", "Pinterest", "Polar", "Proof", "RedirectPizza", "Retell", "RubyGems", "Samsara", "Sourcegraph", "SSLMate", "Thunderstore", "Unkey", "UpCloud", "Upstage", "ValTown", "WakaTime", "Weatherstack", "Xendit", "Zuplo", "GCNotify",
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("provider-confirmed detectors = %v, want explicitly audited set %v", got, want)
	}
}

func TestVerifiersDeclareVerificationAssurance(t *testing.T) {
	seen := map[string]bool{}
	for _, detector := range detectors.All() {
		if _, ok := detector.(detectors.Verifier); !ok {
			continue
		}
		name := detector.Type().String()
		_, hasPolicy := detector.(detectors.VerificationPolicy)
		_, frozen := unauditedVerifiers[name]
		switch {
		case !hasPolicy && !frozen:
			t.Errorf("%s implements Verify without MaxVerificationAssurance; --verify-min-assurance would silently skip it", name)
		case hasPolicy && frozen:
			t.Errorf("%s now declares MaxVerificationAssurance; remove it from unauditedVerifiers", name)
		}
		seen[name] = true
	}
	for name := range unauditedVerifiers {
		if !seen[name] {
			t.Errorf("unauditedVerifiers lists %s, which is not a registered Verifier", name)
		}
	}
}
