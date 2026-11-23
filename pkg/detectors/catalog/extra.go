package catalog

import "github.com/plenoai/pleno-dlp/pkg/detectors"

// extraRules are kingfisher-validated rules whose detection a native
// detector already credits (docs/kingfisher-parity.md) but under a type
// that cannot verify them — a generic JWT, a JSON config, or a provider
// without a verifier. They are re-attached to the provider type so the
// catalog check can verify them with the paired context kingfisher uses.
// Patterns: mongodb/kingfisher pin 98b67a0 (Betterleaks import, MIT).
var extraRules = []rule{
	{ID: "betterleaks.auth0-client-secret.1", Type: detectors.Auth0, Validation: "Betterleaks", MinEntropy: 3.5, Keywords: []string{`auth0`}, Pattern: `(?i:(?:auth0[_.-]?(?:client[_.-]?)?(?:secret|private|key|token))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_-]{64,128})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{ID: "betterleaks.gcp-application-default-credentials", Type: detectors.GCPOAuth, Validation: "Betterleaks", Keywords: []string{`.apps.googleusercontent.com`}, Pattern: `\{[^{]+(?:(?:"client_secret"\s*:\s*"[^"]+"[^}]+"refresh_token"\s*:\s*"[^"]+")|(?:"refresh_token"\s*:\s*"[^"]+"[^}]+"client_secret"\s*:\s*"[^"]+"))[^}]+\}`},
	{ID: "betterleaks.monday-api-token.1", Type: detectors.Monday, Validation: "Betterleaks", MinEntropy: 3.5, Keywords: []string{`monday`}, Pattern: `(?i:(?:monday)(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(eyJ[A-Za-z0-9_-]{10,200}\.eyJ[A-Za-z0-9_-]{50,1000}\.[A-Za-z0-9_-]{20,500})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{ID: "betterleaks.ovh-application-secret", Type: detectors.OVHCloud, Validation: "Betterleaks", MinEntropy: 3.5, Keywords: []string{`ovh`}, Pattern: `(?i)(?:app(?:lication)?[_.-]{0,1}secret)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9-]{32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{ID: "betterleaks.paypal-client-secret.1", Type: detectors.PayPal, Validation: "Betterleaks", MinEntropy: 3.5, Keywords: []string{`paypal`}, Pattern: `(?i:(?:paypal[_.-]?(?:client[_.-]?)?(?:secret|private|access|key|token))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_.-]{78,120})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{ID: "betterleaks.scalr-api-access-token.1", Type: detectors.JWT, Validation: "Betterleaks", Keywords: []string{`scalr`}, Pattern: `(?i:(?:scalr(?:[_. -]*(?:api|access))?[_. -]*(?:secret|key|token))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJpc3MiOiJ1c2VyIiwianRpIjoiYXQt[A-Za-z0-9_-]{20,40}\.[A-Za-z0-9_-]{43})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{ID: "betterleaks.upstash-redis-rest-token.1", Type: detectors.UpstashRedis, Validation: "Betterleaks", MinEntropy: 3.5, Keywords: []string{`upstash`}, Pattern: `(?i:(?:upstash)(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}((?:[A-Za-z0-9]{32,48}|AYNgAS[A-Za-z0-9+/_-]{26,90}={0,2}))(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{ID: "veles.secrets/hcpclientcredentials", Type: detectors.HashiCorpCloud, Validation: "Http", Keywords: []string{`hcp_client_secret`}, Pattern: `["']?\b(?:HCP_CLIENT_SECRET|hcp_client_secret)\b["']?\s*[:=]\s*["']?([A-Za-z0-9._~\-]{64})["']?`},
}
