package catalog

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Assurance levels, as declared per check (docs/verify-coverage.md):
//
//   - pc (provider-confirmed): the provider authenticated the credential
//     and returned an identity, an account-scoped resource, or an issued
//     access token.
//   - rc (response-confirmed): a provider-specific response showed the
//     credential was accepted, without an identity or capability (OAuth
//     "invalid_grant" after client authentication, token introspection,
//     SDK or ingest keys, offline-plus-issuer signature checks).
//   - hx (heuristic): an offline shape or curve check only.
const (
	pc = detectors.AssuranceProviderConfirmed
	rc = detectors.AssuranceResponseConfirmed
	hx = detectors.AssuranceHeuristic
)

func st(code int, contains ...string) tokenverify.Rule {
	r := tokenverify.Rule{Status: code}
	if len(contains) > 0 {
		r.BodyContains = contains[0]
	}
	return r
}

func orOK(valid []tokenverify.Rule) []tokenverify.Rule {
	if len(valid) == 0 {
		return []tokenverify.Rule{st(http.StatusOK)}
	}
	return valid
}

func get(url string, headers map[string]string, valid ...tokenverify.Rule) *httpCheck {
	valid = orOK(valid)
	return &httpCheck{Method: http.MethodGet, URL: url, Headers: headers, Valid: valid}
}

func bearer(url string, valid ...tokenverify.Rule) *httpCheck {
	return get(url, map[string]string{"Authorization": "Bearer {secret}", "Accept": "application/json"}, valid...)
}

func post(url, contentType, body string, headers map[string]string, valid ...tokenverify.Rule) *httpCheck {
	valid = orOK(valid)
	return &httpCheck{Method: http.MethodPost, URL: url, ContentType: contentType, Body: body, Headers: headers, Valid: valid}
}

func (h *httpCheck) invalid(r ...tokenverify.Rule) *httpCheck { h.Invalid = r; return h }

func (h *httpCheck) hosts(s ...string) *httpCheck { h.Hosts = s; return h }

const form = "application/x-www-form-urlencoded"

// Partner patterns: kingfisher's hidden context rules (pin 98b67a0).
const (
	pAlgoliaApp        = `(?i)(?:algolia)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{10})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pAlibabaID         = `\b(LTAI[A-Za-z0-9]{17,21})\b`
	pAlibabaSTSID      = `\b(STS\.[A-Za-z0-9]{16,64})\b`
	pAlibabaSTSTok     = `\b(CAIS[A-Za-z0-9+/_=-]{20,1000})`
	pJFrogHost         = `(?i)(?:^|[^a-z0-9-])([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.jfrog\.io)(?:$|[^a-z0-9-])`
	pAuth0ClientID     = `(?i:(?:auth0[_.-]?(?:client[_.-]?)?(?:id|identifier))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_-]{32,60})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pAuth0Domain       = `(?i)\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+auth0\.com)\b`
	pAWSSecret         = `(?i:(?:secret|access|key|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9/+=]{40})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pAWSKeyID          = `\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`
	pAzureClientID     = `(?i)\b(?:client[_\s.-]*id|AZURE_CLIENT_ID)\b(?s:.{0,24}?)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`
	pAzureTenantID     = `(?i)\b(?:tenant[_\s.-]*(?:id)?|AZURE_TENANT_ID)\b(?s:.{0,24}?)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`
	pAzureStorage      = `(?i)(?:\bAccountName\s*=\s*([a-z0-9]{3,24})\b|https://([a-z0-9]{3,24})\.blob\.core\.windows\.net\b|\b(?:azure[_\s.-]*storage[_\s.-]*(?:account[_\s.-]*)?name|storage[_\s.-]*account[_\s.-]*name)\b(?s:.{0,24}?)([a-z0-9]{3,24})\b)`
	pBrowserstackU     = `(?i:(?:browserstack[_.-]?(?:username|user))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9][A-Za-z0-9._-]{2,39})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pCanvaClientID     = `(?i)\b(OC-[A-Za-z0-9_-]{8,16})\b`
	pClickHouseID      = `(?i)\bclickhouse(?:.|[\n\r]){0,16}?(?:ID|USER)(?:.|[\n\r]){0,16}?([a-z0-9]{20})`
	pCFAccountID       = `(?i:(?:account[_. -]*id)(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pCloudinaryKey     = `(?i)\bcloudinary(?:.|[\n\r]){0,32}?(?:API[_\s]?KEY|KEY)(?:.|[\n\r]){0,16}?\b([0-9]{15})\b`
	pCloudinaryName    = `(?i)\bcloudinary(?:.|[\n\r]){0,32}?(?:CLOUD[_\s]?NAME|CLOUD)(?:.|[\n\r]){0,16}?\b([a-z0-9_-]{3,32})\b`
	pEbayClientID      = `\b([a-zA-Z0-9_-]+-[a-zA-Z0-9_-]+-PRD-[a-f0-9]{8,12}-[a-f0-9]{8,12})`
	pExoscaleSecret    = `(?i)(?:exoscale)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_\-]{40,60})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pLarkAppID         = `\b(cli_[A-Za-z0-9]{16})`
	pMiroClientID      = `(?i)(?:miro[_. -]*client[_. -]*id)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]{15,21})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pAtlasSAID         = `\b(mdb_sa_id_[a-f0-9]{24})\b`
	pMuxTokenID        = `(?i)(?:mux[_.-]?(?:access[_.-]?)?token[_.-]?(?:id|identifier))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pOVHAppKey         = `(?i)(?:app(?:lication)?[_.-]{0,1}key)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9-]{16})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pOVHConsumerKey    = `(?i)(?:consumer[_.-]{0,1}key)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9-]{32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pPaypalClientID    = `(?i:(?:paypal[_.-]?(?:client[_.-]?)?(?:id|user))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(A[A-Za-z0-9_-]{78,99})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pPlanetscaleID     = `(?i)(?:pscale|planetscale)(?:.|[\n\r]){0,16}?(?:USER|ID|NAME)(?:.|[\n\r]){0,16}?([a-z0-9]{12})`
	pPlivoAuthID       = `\b(MA[A-Z0-9]{18})\b`
	pPolySecret        = `(?i:(?:poly.{0,20}secret)(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9+/_-]{40,}={0,2})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pPolyPassphrase    = `(?i:(?:poly.{0,20}passphrase)(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9_]{8,128})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pRampClientID      = `\b(ramp_id_[A-Za-z0-9]{40})\b`
	pRazorpayKeyID     = `\b(rzp_(?:live|test)_[A-Za-z0-9]{14})\b`
	pSalesforceHost    = `(?i)(?:^|[^a-z0-9.-])(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){0,4}\.my\.salesforce\.com|[a-z]{2,8}[0-9]{1,4}\.salesforce\.com))(?:[^a-z0-9.-]|$)`
	pSnowflakeHost     = `(?i)\b([a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.snowflakecomputing\.com)\b`
	pSupabaseURL       = `\b(https://[a-z0-9]{16,32}\.supabase\.co)\b`
	pTableauName       = `(?i:(?:tableau(?:[_. -]*(?:personal[_. -]*access|pat))?[_. -]*(?:token[_. -]*)?name)(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z][A-Za-z0-9_-]{2,50})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pTableauHost       = `(?i)\b([a-z0-9-]+\.online\.tableau\.com)\b`
	pUpstashURL        = `(?i)\b(https://[a-z0-9][a-z0-9-]{2,63}\.upstash\.io)\b`
	pWizClientID       = `(?i:(?:wiz)(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{53,56})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`
	pZohoClientID      = `\b(1000\.[A-Za-z0-9]{30})\b`
	pHCPClientID       = `["']?\b(?:HCP_CLIENT_ID|hcp_client_id)\b["']?\s*[:=]\s*["']?([A-Za-z0-9]{32})["']?`
	pPackagistRepo     = `(https://repo\.packagist\.com[/\w\-\.]*)`
	pPackagistKey      = `(packagist_ack_[0-9a-f]{28,32})`
	pAppConfigEndpoint = `(?i)Endpoint=(https://[a-z0-9-]+\.azconfig\.io);Id=`
	pAppConfigID       = `(?i)\.azconfig\.io;Id=([^;\s'"]{4,80});Secret=`
	pContentfulSpace   = `(?i)(?:space[_. -]*id|spaces/)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,|)[\x60'"\s=]{0,5}([a-z0-9]{12})\b`
	pEndorKey          = `(?i)(?:endor(?:labs)?[_. -]*(?:api[_. -]*)?key)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(endr\+[A-Za-z0-9-]{16})`
	pIntra42UID        = `\b(u-s4t2(?:ud|af)-[a-f0-9]{64})\b`
	pMaxMindAccount    = `(?i)(?:maxmind[_. -]*)?(?:account[_. -]*id|user[_. -]*id)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]{4,10})\b`
	pSendbirdApp       = `(?i)(?:sendbird[_. -]*app(?:lication)?[_. -]*id)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})`
	pBitwardenID       = `"user_([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})_token_apiKeyClientSecret"`
)

func p(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func base(tmpl string, partners map[string]string) *check {
	return &check{base: tmpl, partners: partners}
}

func hc(a detectors.VerificationAssurance, h *httpCheck) *check { return &check{http: h, assurance: a} }

// checks maps each kingfisher-validated rule that pleno-dlp's native
// detectors do not already verify to its verification (issue #934).
// kingfisher's validator for the rule is the reference for endpoint and
// response rules.
var checks = map[string]*check{
	// Routed to the provider's verifier: same credential kind, single token.
	"betterleaks.airtable-oauth-token":               base("{secret}", nil),
	"betterleaks.box-api-access-token":               base("{secret}", nil),
	"betterleaks.buildkite-user-access-token":        base("{secret}", nil),
	"betterleaks.circleci-personal-token":            base("{secret}", nil),
	"betterleaks.civo-api-key":                       base("{secret}", nil),
	"betterleaks.clickup-personal-api-token":         base("{secret}", nil),
	"betterleaks.cockroachlabs-cloud-api-key":        base("{secret}", nil),
	"betterleaks.codecov-access-token":               base("{secret}", nil),
	"betterleaks.figma-personal-access-header-token": base("{secret}", nil),
	"betterleaks.gcp-gemini-api":                     base("{secret}", nil),
	"betterleaks.gcp-service-account":                base("{secret}", nil),
	"betterleaks.github-oauth":                       base("{secret}", nil),
	"betterleaks.github-refresh-token":               base("{secret}", nil),
	"betterleaks.gitlab-pat-routable":                base("{secret}", nil),
	"betterleaks.gitlab-pat-routable-versioned":      base("{secret}", nil),
	"betterleaks.huggingface-organization-api-token": base("{secret}", nil),
	"betterleaks.ibm-cloud-user-api-key":             base("{secret}", nil),
	"betterleaks.jumpcloud-api-key":                  base("{secret}", nil),
	"betterleaks.kagi-api-key":                       base("{secret}", nil),
	"betterleaks.mapbox-api-token":                   base("{secret}", nil),
	"betterleaks.mapbox-secret-token":                base("{secret}", nil),
	"betterleaks.mistral-api-key":                    base("{secret}", nil),
	"betterleaks.neon-api-key":                       base("{secret}", nil),
	"betterleaks.openweather-api-key":                base("{secret}", nil),
	"betterleaks.pagerduty-authorization-token.1":    base("{secret}", nil),
	"betterleaks.private-key":                        base("{secret}", nil),
	"betterleaks.render-api-key":                     base("{secret}", nil),
	"betterleaks.runpod-api-key.1":                   base("{secret}", nil),
	"betterleaks.sendgrid-api-token":                 base("{secret}", nil),
	"betterleaks.slack-bot-token":                    base("{secret}", nil),
	"betterleaks.slack-legacy-bot-token":             base("{secret}", nil),
	"betterleaks.tailscale-key":                      base("{secret}", nil),
	"betterleaks.togetherai-api-key":                 base("{secret}", nil),
	"betterleaks.twitch-api-token":                   base("{secret}", nil),
	"betterleaks.vercel-api-token":                   base("{secret}", nil),
	"betterleaks.vercel-integration-token":           base("{secret}", nil),
	"betterleaks.vercel-personal-access-token":       base("{secret}", nil),
	"betterleaks.voyageai-api-key":                   base("{secret}", nil),
	"betterleaks.vultr-api-key.1":                    base("{secret}", nil),
	"betterleaks.weights-and-biases-api-key-v1":      base("{secret}", nil),
	"veles.secrets/herokuplatformkey":                base("{secret}", nil),
	"veles.secrets/slackappconfigaccesstoken":        base("{secret}", nil),
	"veles.secrets/slackappconfigrefreshtoken":       base("{secret}", nil),
	"veles.secrets/slackappleveltoken":               base("{secret}", nil),
	"betterleaks.monday-api-token.1":                 base("{secret}", nil),

	// Routed to the provider's verifier with a paired credential
	// (kingfisher depends_on) packed into the provider's secret shape.
	"betterleaks.algolia-api-key":                 base("{app}:{secret}", p("app", pAlgoliaApp)),
	"betterleaks.artifactory-api-key":             base("{host}|{secret}", p("host", pJFrogHost)),
	"betterleaks.artifactory-reference-token":     base("{host}|{secret}", p("host", pJFrogHost)),
	"betterleaks.aws-access-token":                base("{secret}:{sk}", p("sk", pAWSSecret)),
	"betterleaks.aws-session-token":               base("{id}:{sk}:{secret}", p("id", pAWSKeyID, "sk", pAWSSecret)),
	"betterleaks.azure-ad-client-secret":          base("{tenant}:{client}:{secret}", p("tenant", pAzureTenantID, "client", pAzureClientID)),
	"betterleaks.azure-storage-account-key":       base("{account}\n{secret}", p("account", pAzureStorage)),
	"betterleaks.browserstack-access-key.1":       base("{user}:{secret}", p("user", pBrowserstackU)),
	"betterleaks.clickhouse-cloud-api-secret-key": base("{id}:{secret}", p("id", pClickHouseID)),
	"betterleaks.cloudinary-api-secret":           base("{key}:{secret}@{cloud}", p("key", pCloudinaryKey, "cloud", pCloudinaryName)),
	"betterleaks.lark-app-secret":                 base("{app}:{secret}", p("app", pLarkAppID)),
	"betterleaks.mux-access-token-secret.1":       base("{id}:{secret}", p("id", pMuxTokenID)),
	"betterleaks.planetscale-api-token":           base("{id}:{secret}", p("id", pPlanetscaleID)),
	"betterleaks.plivo-auth-token":                base("{id}:{secret}", p("id", pPlivoAuthID)),
	"betterleaks.razorpay-key-secret.1":           base("{id}:{secret}", p("id", pRazorpayKeyID)),
	"betterleaks.paypal-client-secret.1":          base("{id}:{secret}", p("id", pPaypalClientID)),

	// Declarative single round trips.
	"betterleaks.amplitude-secret-key": hc(rc, post("https://api2.amplitude.com/2/httpapi", "application/json",
		`{"api_key":{secret|json},"events":[{"user_id":"203201202","device_id":"C8F9E604-F01A-4BD9-95C6-8E5357DF265D","event_type":"watch_tutorial"}]}`,
		nil, st(200, `"code":200`)).invalid(st(400), st(401), st(403))),
	"betterleaks.anthropic-admin-api-key": hc(pc, get("https://api.anthropic.com/v1/organizations/me",
		map[string]string{"x-api-key": "{secret}", "anthropic-version": "2023-06-01"}, st(200, `"organization"`))),
	"betterleaks.asaas-api-token": hc(pc, get("https://api.asaas.com/v3/myAccount/commercialInfo/",
		map[string]string{"access_token": "{secret}", "Accept": "application/json"}, st(200, `"commercialInfo"`))),
	"betterleaks.authress-service-client-access-key": hc(pc, bearer("https://api.authress.io/v1/users/me").
		invalid(st(401), st(403), st(0, `"Unauthorized"`))),
	"betterleaks.canva-client-secret": {partners: p("client", pCanvaClientID), assurance: rc, http: post(
		"https://api.canva.com/rest/v1/oauth/token", form,
		"grant_type=authorization_code&client_id={client|url}&client_secret={secret|url}&code_verifier=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abcdefgh&code=invalid",
		nil, tokenverify.Rule{Status: 400, BodyContains: `"invalid_grant"`, BodyNotContains: `"invalid_client"`}).
		invalid(st(400, `"invalid_client"`), st(401, `"invalid_client"`), st(403, `"invalid_client"`))},
	"betterleaks.datadog-api-key": hc(pc, get("https://api.datadoghq.com/api/v1/validate",
		map[string]string{"DD-API-KEY": "{secret}", "Accept": "application/json"},
		tokenverify.Rule{Status: 200, BodyNotContains: `"Forbidden"`}).invalid(st(401), st(403), st(0, `"Forbidden"`))),
	"betterleaks.devcycle-client-sdk-key": hc(rc, devcycle()),
	"betterleaks.devcycle-mobile-sdk-key": hc(rc, devcycle()),
	"betterleaks.devcycle-server-sdk-key": hc(rc, devcycle()),
	"betterleaks.devin-personal-api-key":  {assurance: pc, prefix: "apk_user_", http: bearer("https://api.devin.ai/v1/sessions?limit=1", st(200, `"sessions"`))},
	"betterleaks.devin-service-api-key":   {assurance: pc, prefix: "apk_", http: bearer("https://api.devin.ai/v1/sessions?limit=1", st(200, `"sessions"`))},
	"betterleaks.devin-service-user-token": {assurance: pc, prefix: "cog_", http: bearer("https://api.devin.ai/v3/self",
		st(200, `"principal_type"`), st(200, `"service_user_id"`))},
	"betterleaks.ebay-client-secret": {partners: p("client", pEbayClientID), assurance: rc, http: post(
		"https://api.ebay.com/identity/v1/oauth2/token/introspect", form,
		"token=pleno-dlp-validation-token&token_type_hint=access_token",
		map[string]string{"Authorization": "Basic {basic:client:secret}", "Accept": "application/json"},
		st(200, `"active":false`)).invalid(st(401, "invalid_client"))},
	"betterleaks.elastic-cloud-api-key": hc(pc, get("https://api.elastic-cloud.com/api/v1/deployments",
		map[string]string{"Authorization": "ApiKey {secret}"}, st(200, `"deployments"`))),
	"betterleaks.freshbooks-access-token": hc(pc, bearer("https://api.freshbooks.com/auth/api/v1/users/me")),
	"betterleaks.fullstory-api-key": hc(pc, get("https://api.fullstory.com/me",
		map[string]string{"Authorization": "Basic {secret}", "Accept": "application/json"}, st(200, `"role"`)).invalid(st(401))),
	"betterleaks.gitlab-rrt": hc(pc, post("https://gitlab.com/api/v4/runners/verify", form, "token={secret|url}", nil,
		tokenverify.Rule{Status: 200, BodyNotContains: "token is missing"})),
	"betterleaks.grafana-cloud-api-token": hc(rc, bearer("https://grafana.com/api/stack-regions")),
	"betterleaks.labelbox-recursion-api-key": hc(pc, bearer("https://api.recursion.labelbox.com/managed-agents/v1/models",
		st(200), st(400, "x-organization-id")).invalid(st(401))),
	"betterleaks.mercury-production-api-token": hc(pc, get("https://api.mercury.com/api/v1/accounts",
		map[string]string{"Authorization": "Bearer secret-token:{secret}", "Accept": "application/json"}, st(200))),
	"betterleaks.miro-client-secret": {partners: p("client", pMiroClientID), assurance: rc, http: post(
		"https://api.miro.com/v1/oauth/token", form,
		"grant_type=refresh_token&client_id={client|url}&client_secret={secret|url}&refresh_token=invalid", nil,
		st(401, "Invalid refresh token")).invalid(st(401), st(400))},
	"betterleaks.mongodb-atlas-service-account-secret": {partners: p("id", pAtlasSAID), assurance: pc, http: post(
		"https://cloud.mongodb.com/api/oauth/token", form, "grant_type=client_credentials",
		map[string]string{"Authorization": "Basic {basic:id:secret}", "Accept": "application/json"},
		st(200, `"access_token"`)).invalid(st(401))},
	"betterleaks.onesignal-rich-authentication-token": hc(pc, get("https://api.onesignal.com/apps",
		map[string]string{"Authorization": "Key {secret}", "Accept": "application/json"},
		st(200), st(403, `"errors"`)).invalid(st(401))),
	"betterleaks.onfido-live-api-token-ca": hc(pc, onfido("ca")),
	"betterleaks.onfido-live-api-token-eu": hc(pc, onfido("eu")),
	"betterleaks.onfido-live-api-token-us": hc(pc, onfido("us")),
	"betterleaks.pinecone-api-key.1": hc(pc, get("https://api.pinecone.io/indexes",
		map[string]string{"Api-Key": "{secret}", "X-Pinecone-Api-Version": "2025-10", "Accept": "application/json"},
		st(200, `"indexes"`), st(403)).invalid(st(401))),
	"betterleaks.rainforest-pay-production-api-key": hc(pc, get("https://api.rainforestpay.com/v1/merchants?limit=1",
		map[string]string{"Authorization": "Bearer {secret}", "Rainforest-Api-Version": "2024-10-16", "Accept": "application/json"},
		st(200, `"SUCCESS"`), st(403, `"ERROR"`)).invalid(st(401))),
	"betterleaks.ramp-client-secret": {partners: p("client", pRampClientID), assurance: rc, http: post(
		"https://api.ramp.com/developer/v1/token", form, "grant_type=client_credentials&scope=pleno-dlp%3Avalidate",
		map[string]string{"Authorization": "Basic {basic:client:secret}", "Accept": "application/json"},
		st(200, `"access_token"`), st(400, "invalid_scope"), st(400, "unauthorized_client")).invalid(st(401), st(400, "invalid_client"))},
	"betterleaks.salesforce-access-token.1": {partners: p("host", pSalesforceHost), assurance: pc, http: bearer(
		"https://{host}/services/data/v67.0/limits", st(200, `"DailyApiRequests"`), st(403, `"REQUEST_LIMIT_EXCEEDED"`)).
		invalid(st(401)).hosts("salesforce.com")},
	"betterleaks.scalr-api-access-token.1": hc(pc, get("https://scalr.io/api/iacp/v3/accounts",
		map[string]string{"Authorization": "Bearer {secret}", "Accept": "application/vnd.api+json"},
		st(200, `"data"`), st(403)).invalid(st(401))),
	"betterleaks.segment-public-api-token.1": hc(pc, bearer("https://api.segmentapis.com/").invalid(st(401), st(403))),
	"betterleaks.snowflake-programmatic-access-token.1": {partners: p("host", pSnowflakeHost), assurance: pc, http: post(
		"https://{host}/api/v2/statements", "application/json", `{"statement":"select 1","timeout":5}`,
		map[string]string{"Authorization": "Bearer {secret}", "X-Snowflake-Authorization-Token-Type": "PROGRAMMATIC_ACCESS_TOKEN", "Accept": "application/json"},
		st(200, `"statementHandle"`), st(200, `"resultSetMetaData"`), st(202, `"statementHandle"`)).hosts("snowflakecomputing.com")},
	"betterleaks.supabase-management-token": hc(pc, bearer("https://api.supabase.com/v1/organizations")),
	"betterleaks.supabase-project-api-key": {partners: p("url", pSupabaseURL), assurance: rc, http: get(
		"{url}/rest/v1/?select=*", map[string]string{"Apikey": "{secret}"}, st(200, `"host":`)).hosts("supabase.co")},
	"betterleaks.tableau-personal-access-token.1": {partners: p("name", pTableauName, "host", pTableauHost), assurance: pc, http: post(
		"https://{host}/api/3.26/auth/signin", "application/json",
		`{"credentials":{"personalAccessTokenName":{name|json},"personalAccessTokenSecret":{secret|json},"site":{}}}`,
		map[string]string{"Accept": "application/json"}, st(200, `"token"`)).invalid(st(400), st(401), st(403)).hosts("online.tableau.com")},
	"betterleaks.temporal-cloud-api-key.1": hc(pc, bearer("https://saas-api.tmprl.cloud/cloud/current-identity",
		st(200, `"user"`), st(200, `"serviceAccount"`)).invalid(st(401))),
	"betterleaks.vercel-app-access-token": hc(pc, post("https://api.vercel.com/login/oauth/userinfo", "", "",
		map[string]string{"Authorization": "Bearer {secret}"}, st(200, `"sub"`))),
	"betterleaks.vercel-app-refresh-token": hc(rc, post("https://api.vercel.com/login/oauth/token/introspect", form,
		"token={secret|url}", nil, st(200, `"active":true`)).invalid(st(200, `"active":false`), st(401), st(403))),
	"betterleaks.wiz-client-secret.1": {partners: p("client", pWizClientID), assurance: pc, http: post(
		"https://auth.app.wiz.io/oauth/token", form,
		"grant_type=client_credentials&audience=wiz-api&client_id={client|url}&client_secret={secret|url}",
		map[string]string{"Accept": "application/json"}, st(200, `"access_token"`)).invalid(st(400), st(401), st(403))},
	"betterleaks.workato-developer-api-token.1": {assurance: pc, fn: workato},
	"betterleaks.zai-api-key": hc(pc, post("https://api.z.ai/api/paas/v4/tokenizer", "application/json",
		`{"model":"glm-4.6","messages":[{"role":"user","content":"hello"}]}`,
		map[string]string{"Authorization": "Bearer {secret}", "Accept": "application/json"}, st(200, `"usage"`))),
	"betterleaks.zoho-client-secret.1": {partners: p("client", pZohoClientID), assurance: rc, prefix: "", http: post(
		"https://accounts.zoho.com/oauth/v2/token", form,
		"client_id={client|url}&client_secret={secret|url}&grant_type=authorization_code&code=pleno_dlp_invalid_code&redirect_uri=https%3A%2F%2Fexample.com%2Fpleno-dlp",
		map[string]string{"Accept": "application/json"}, st(200, `"invalid_code"`)).invalid(st(200, `"invalid_client"`), st(400), st(401))},
	"betterleaks.zoho-oauth-token.1": {assurance: pc, prefix: "1000.", http: get("https://www.zohoapis.com/crm/v8/users?type=CurrentUser",
		map[string]string{"Authorization": "Zoho-oauthtoken {secret}", "Accept": "application/json"}, st(200, `"users"`)).invalid(st(401))},
	"betterleaks.auth0-client-secret.1": {partners: p("client", pAuth0ClientID, "domain", pAuth0Domain), assurance: rc, http: post(
		"https://{domain}/oauth/token", form,
		"grant_type=authorization_code&client_id={client|url}&client_secret={secret|url}&code=pleno_dlp_invalid_code&redirect_uri=https%3A%2F%2Fexample.com%2Fpleno-dlp",
		map[string]string{"Accept": "application/json"}, st(0, `"invalid_grant"`)).invalid(st(0, `"invalid_client"`)).hosts("auth0.com")},
	"betterleaks.upstash-redis-rest-token.1": {partners: p("url", pUpstashURL), assurance: pc, http: bearer(
		"{url}/ping", st(200, "PONG")).invalid(st(401)).hosts("upstash.io")},
	"veles.secrets/bitbucketcredentials":    {assurance: pc, fn: gitURL("bitbucket.org", 200)},
	"veles.secrets/codecatalystcredentials": {assurance: pc, prefix: "", fn: gitURL("codecatalyst.aws", 200)},
	"veles.secrets/codecommitcredentials":   {assurance: pc, fn: gitURL("amazonaws.com", 200, 404)},
	"veles.secrets/bitwardenoauth2access": {partners: p("id", pBitwardenID), assurance: pc, http: post(
		"https://identity.bitwarden.com/connect/token", form,
		"grant_type=client_credentials&scope=api&client_id=user.{id|url}&client_secret={secret|url}&deviceName=firefox&twoFactorToken=0&deviceIdentifier=0&deviceType=0",
		nil, st(200, `"access_token"`)).invalid(st(400), st(401))},
	"veles.secrets/circleciproject": hc(rc, get("https://circleci.com/api/v1.1/project/pleno-dlp-validation-nonexistent-a8f3c2d9",
		map[string]string{"Circle-Token": "{secret}"}, st(200), st(404))),
	"veles.secrets/denopatorg": hc(pc, bearer("https://api.deno.com/organization")),
	"veles.secrets/postmancollectiontoken": hc(rc, get("https://api.postman.com/collections/aaaaaaaa-aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa?access_key={secret|url}",
		nil, st(403, `"name":"forbiddenError"`)).invalid(st(401), st(403))),
	"veles.secrets/hcpclientcredentials": {partners: p("client", pHCPClientID), assurance: pc, http: post(
		"https://auth.idp.hashicorp.com/oauth2/token", form,
		"client_id={client|url}&client_secret={secret|url}&grant_type=client_credentials", nil,
		st(200, `"access_token"`)).invalid(st(400), st(401))},
	"veles.secrets/packagistorgreadtoken": {partners: p("repo", pPackagistRepo), assurance: pc, prefix: "packagist_ort_", http: get(
		"{repo}/packages.json", map[string]string{"Accept": "application/json", "Authorization": "Basic {basic:'token':secret}"},
		st(200, "{")).hosts("repo.packagist.com")},
	"veles.secrets/packagistorgupdatetoken": {partners: p("repo", pPackagistRepo), assurance: pc, prefix: "packagist_out_", http: get(
		"{repo}/packages.json", map[string]string{"Accept": "application/json", "Authorization": "Basic {basic:'token':secret}"},
		st(200, "{")).hosts("repo.packagist.com")},

	// pleno-only: catalog hosts kingfisher detects but does not validate
	// (issue #950). Endpoints are fixed provider hosts or partner-derived
	// hosts pinned by an allowlist.
	"betterleaks.adafruit-api-key": hc(pc, get("https://io.adafruit.com/api/v2/user",
		map[string]string{"X-AIO-Key": "{secret}", "Accept": "application/json"}, st(200, `"username"`))),
	"betterleaks.beamer-api-token": hc(rc, post("https://api.getbeamer.com/v0/ping", "", "",
		map[string]string{"Beamer-Api-Key": "{secret}"}, st(200))),
	"betterleaks.contentful-delivery-api-token": {partners: p("space", pContentfulSpace), assurance: pc, http: get(
		"https://cdn.contentful.com/spaces/{space|url}", map[string]string{"Authorization": "Bearer {secret}"},
		st(200, `"sys"`)).invalid(st(401), st(404))},
	"betterleaks.defined-networking-api-token": hc(pc, bearer("https://api.defined.net/v1/hosts?pageSize=1", st(200, `"data"`))),
	"betterleaks.duffel-api-token": hc(rc, get("https://api.duffel.com/air/airlines?limit=1",
		map[string]string{"Authorization": "Bearer {secret}", "Duffel-Version": "v2", "Accept": "application/json"}, st(200, `"data"`))),
	"betterleaks.endorlabs-api-secret": {partners: p("key", pEndorKey), assurance: pc, http: post(
		"https://api.endorlabs.com/v1/auth/api-key", "application/json", `{"key":{key|json},"secret":{secret|json}}`,
		map[string]string{"Accept": "application/json"}, st(200, `"token"`)).invalid(st(400), st(401), st(403))},
	"betterleaks.facebook-access-token": hc(pc, get("https://graph.facebook.com/v19.0/app?access_token={secret|url}", nil,
		st(200, `"id"`)).invalid(st(400), st(401), st(403))),
	"betterleaks.facebook-page-access-token": {assurance: pc, prefix: "EAA", http: get("https://graph.facebook.com/v19.0/me?access_token={secret|url}", nil,
		st(200, `"id"`)).invalid(st(400), st(401), st(403))},
	"betterleaks.finnhub-access-token": hc(rc, get("https://finnhub.io/api/v1/quote?symbol=AAPL",
		map[string]string{"X-Finnhub-Token": "{secret}"}, st(200))),
	"betterleaks.flickr-access-token": hc(rc, get("https://api.flickr.com/services/rest/?method=flickr.test.echo&format=json&nojsoncallback=1&api_key={secret|url}", nil,
		st(200, `"stat":"ok"`)).invalid(st(0, `"stat":"fail"`), st(401), st(403))),
	"betterleaks.infracost-api-token": hc(rc, post("https://pricing.api.infracost.io/graphql", "application/json", `{"query":"{__typename}"}`,
		map[string]string{"X-Api-Key": "{secret}"}, st(200, `"data"`))),
	"betterleaks.intra42-client-secret": {partners: p("client", pIntra42UID), assurance: pc, http: post(
		"https://api.intra.42.fr/oauth/token", form, "grant_type=client_credentials&client_id={client|url}&client_secret={secret|url}",
		map[string]string{"Accept": "application/json"}, st(200, `"access_token"`)).invalid(st(400), st(401))},
	"betterleaks.lob-api-key": hc(pc, get("https://api.lob.com/v1/addresses?limit=1",
		map[string]string{"Authorization": "Basic {basic:secret:''}"}, st(200, `"data"`))),
	"betterleaks.maxmind-license-key": {partners: p("account", pMaxMindAccount), assurance: pc, http: get(
		"https://geoip.maxmind.com/geoip/v2.1/country/me", map[string]string{"Authorization": "Basic {basic:account:secret}"},
		st(200), st(402)).invalid(st(401))},
	"betterleaks.nytimes-access-token": hc(rc, get("https://api.nytimes.com/svc/topstories/v2/home.json?api-key={secret|url}", nil, st(200))),
	"betterleaks.readme-api-token": hc(pc, get("https://dash.readme.com/api/v1",
		map[string]string{"Authorization": "Basic {basic:secret:''}", "Accept": "application/json"}, st(200, `"name"`))),
	"betterleaks.scalingo-api-token": hc(pc, post("https://auth.scalingo.com/v1/tokens/exchange", "", "",
		map[string]string{"Authorization": "Basic {basic:'':secret}", "Accept": "application/json"}, st(200, `"token"`))),
	"betterleaks.sendbird-access-token": {partners: p("app", pSendbirdApp), assurance: pc, http: get(
		"https://api-{app}.sendbird.com/v3/users?limit=1", map[string]string{"Api-Token": "{secret}", "Accept": "application/json"},
		st(200, `"users"`)).invalid(st(400), st(401), st(403)).hosts("sendbird.com")},
	"betterleaks.sidekiq-secret":        hc(rc, sidekiq()),
	"betterleaks.sidekiq-sensitive-url": hc(rc, sidekiq()),
	"betterleaks.twitter-bearer-token":  hc(rc, bearer("https://api.twitter.com/2/tweets?ids=20", st(200, `"data"`))),
	"betterleaks.typeform-api-token":    hc(pc, bearer("https://api.typeform.com/me", st(200, `"alias"`))),
	"betterleaks.yandex-api-key": {assurance: pc, prefix: "AQVN", http: get("https://resource-manager.api.cloud.yandex.net/resource-manager/v1/clouds",
		map[string]string{"Authorization": "Api-Key {secret}"}, st(200))},
	"betterleaks.yandex-access-token": {assurance: pc, prefix: "t1.", http: bearer("https://resource-manager.api.cloud.yandex.net/resource-manager/v1/clouds")},

	// Signed requests and multi-step schemes (signed.go).
	"betterleaks.alibaba-secret-key":                        {partners: p("id", pAlibabaID), assurance: pc, fn: alibaba},
	"betterleaks.alibaba-sts-access-key-secret":             {partners: p("id", pAlibabaSTSID, "token", pAlibabaSTSTok), assurance: pc, fn: alibaba},
	"betterleaks.azure-app-configuration-connection-string": {partners: p("endpoint", pAppConfigEndpoint, "id", pAppConfigID), assurance: pc, fn: azureAppConfig},
	"betterleaks.azure-servicebus-connection-string":        {assurance: pc, fn: azureServiceBus},
	"betterleaks.cloudflare-api-key.2":                      {partners: p("?account", pCFAccountID), assurance: pc, fn: cloudflareToken},
	"betterleaks.exoscale-api-key":                          {partners: p("secretkey", pExoscaleSecret), assurance: pc, fn: exoscale},
	"betterleaks.jwt":                                       {assurance: rc, fn: jwtIssuer},
	"betterleaks.polymarket-api-key":                        {partners: p("apisecret", pPolySecret, "passphrase", pPolyPassphrase), assurance: pc, prefix: "", fn: polymarket},
	"betterleaks.polymarket-private-key":                    {assurance: hx, prefix: "0x", fn: secp256k1Scalar},
	"betterleaks.gcp-application-default-credentials":       {assurance: pc, fn: gcpADC},
	"betterleaks.ovh-application-secret":                    {partners: p("appkey", pOVHAppKey, "consumer", pOVHConsumerKey), assurance: pc, fn: ovh},
	"veles.secrets/packagistsecret":                         {partners: p("key", pPackagistKey), assurance: pc, prefix: "packagist_acs_", fn: packagistHMAC},
}

func devcycle() *httpCheck {
	return post("https://bucketing-api.devcycle.com/v1/variables", "application/json",
		`{"user_id":"pleno-dlp-validation-user"}`, map[string]string{"Authorization": "Bearer {secret}"}, st(200)).invalid(st(401))
}

// sidekiq probes the licensed gem server; the secret is "user:pass".
func sidekiq() *httpCheck {
	return get("https://gems.contribsys.com/", map[string]string{"Authorization": "Basic {secret|b64}"}, st(200)).invalid(st(401), st(403))
}

func onfido(region string) *httpCheck {
	return get("https://api."+region+".onfido.com/v3.6/webhooks/",
		map[string]string{"Authorization": "Token token={secret}", "Accept": "application/json"}, st(200))
}
