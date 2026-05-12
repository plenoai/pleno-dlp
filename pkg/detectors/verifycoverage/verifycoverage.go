// Package verifycoverage exposes the docs/verify-coverage.md classification
// table to the rest of the binary. The doc is the human-facing source of
// truth; this package mirrors its `coverage-machine` block as a Go map so
// the CLI can answer "what is the verify status of detector X" without
// shipping the markdown alongside the binary.
//
// Drift between this map and the doc is rejected by the doc-sync test in
// verifycoverage_sync_test.go (sibling package). Adding a new
// non-Verifier detector therefore requires three coordinated edits:
//
//  1. register the detector under pkg/detectors/<provider>/,
//  2. add the row to docs/verify-coverage.md (machine block + prose table),
//  3. add the entry to Classes below.
//
// The coverage doc test (pkg/detectors/verifycoverage_test.go) catches
// (1) ↔ (2) drift; the sibling sync test catches (2) ↔ (3) drift. Any
// missing edit fails CI.
package verifycoverage

// Class is the verification-coverage class from the doc. Values are
// stable strings, not enums, because they ship to JSON output and to
// machine-readable doc rows; downstream tools pin to them.
type Class string

const (
	// ClassVerified — detector satisfies detectors.Verifier. The
	// classification is implicit (open-set complement); the doc lists
	// only b and c. The CLI synthesizes "a" by checking the type
	// assertion at lookup time.
	ClassVerified Class = "a"

	// ClassUnverifiedByDesign — detector deliberately ships without
	// Verify. Rationale lives in the doc (connection-string, HMAC
	// signing required, paired credential, generic shape, PII…).
	ClassUnverifiedByDesign Class = "b"

	// ClassVerifyGap — detector regex-matches but no Verify wired yet.
	// A follow-up PR is invited; the doc enumerates the upstream
	// verification path per row.
	ClassVerifyGap Class = "c"
)

// Label renders a class as a human-readable JSON-stable string. The
// values are wire-stable for `detectors list --verify-status`
// consumers; new entries go at the end.
func (c Class) Label() string {
	switch c {
	case ClassVerified:
		return "verified"
	case ClassUnverifiedByDesign:
		return "unverified-by-design"
	case ClassVerifyGap:
		return "verify-gap"
	default:
		return "unknown"
	}
}

// Lookup returns the doc-recorded class for a DetectorType name. It
// returns (ClassVerified, true) for any name not listed — class (a) is
// the open-set complement, and the caller is expected to have already
// confirmed the detector implements detectors.Verifier. For non-Verifier
// detectors not in Classes, this returns ("", false), which the caller
// should treat as a doc bug (the verify-coverage test would fail
// in CI before such a binary ships, but defense in depth).
func Lookup(detectorType string) (Class, bool) {
	if c, ok := Classes[detectorType]; ok {
		return c, true
	}
	return "", false
}

// Classes mirrors the `coverage-machine` block of docs/verify-coverage.md.
// Keys are DetectorType.String() values. Values are b or c only — class
// (a) is the open-set complement (every registered detector not listed
// here, that satisfies detectors.Verifier).
//
// Keep this table sorted alphabetically by key so diffs are stable.
var Classes = map[string]Class{
	// (b) Unverified-by-design — 44 detectors
	"APNs":               ClassUnverifiedByDesign,
	"AWSS3PresignedURL":  ClassUnverifiedByDesign,
	"AWX":                ClassUnverifiedByDesign,
	"ActiveCampaign":     ClassUnverifiedByDesign,
	"Adyen":              ClassUnverifiedByDesign,
	"AgoraIO":            ClassUnverifiedByDesign,
	"Akamai":             ClassUnverifiedByDesign,
	"AppStoreConnect":    ClassUnverifiedByDesign,
	"AzureSQLConnString": ClassUnverifiedByDesign,
	"BackblazeB2":        ClassUnverifiedByDesign,
	"Bamboo":             ClassUnverifiedByDesign,
	"BasicAuth":          ClassUnverifiedByDesign,
	"ConcourseCI":        ClassUnverifiedByDesign,
	"CrispChat":          ClassUnverifiedByDesign,
	"ElasticCloud":       ClassUnverifiedByDesign,
	"Exoscale":           ClassUnverifiedByDesign,
	"GCSSignedURL":       ClassUnverifiedByDesign,
	"GenericHighEntropy": ClassUnverifiedByDesign,
	"GoCD":               ClassUnverifiedByDesign,
	"JWT":                ClassUnverifiedByDesign,
	"Jenkins":            ClassUnverifiedByDesign,
	"Kafka":              ClassUnverifiedByDesign,
	"Kubeconfig":         ClassUnverifiedByDesign,
	"MongoDB":            ClassUnverifiedByDesign,
	"MySQL":              ClassUnverifiedByDesign,
	"OVHCloud":           ClassUnverifiedByDesign,
	"PIIAnonymize":       ClassUnverifiedByDesign,
	"PIIOpenAIPF":        ClassUnverifiedByDesign,
	// PIICreditCard / PIIEmail / PIIIBAN / PIIUSSSN entries removed —
	// the detectors were retired in favour of PIIAnonymize. The
	// DetectorType constants stay pinned at their ordinals (76..79)
	// per ADR-0002 but no live registration exists, so the doc /
	// Classes drift tests no longer require entries here.
	"PingIdentity": ClassUnverifiedByDesign,
	"Postgres":     ClassUnverifiedByDesign,
	// PrivateKeyPEM intentionally absent — the detector now satisfies
	// detectors.Verifier via blast-radius lookup against Certificate
	// Transparency (crt.sh `?spkisha256=`). It falls into the open-set
	// complement (class a). See docs/verify-coverage.md and the
	// pkg/detectors/privatekey/blastradius package.
	"RabbitMQ": ClassUnverifiedByDesign,
	"Redis":              ClassUnverifiedByDesign,
	"RequestBin":         ClassUnverifiedByDesign,
	"SMTP":               ClassUnverifiedByDesign,
	"Sinch":              ClassUnverifiedByDesign,
	"Smee":               ClassUnverifiedByDesign,
	"SonatypeNexus":      ClassUnverifiedByDesign,
	"SplunkHEC":          ClassUnverifiedByDesign,
	"Stytch":             ClassUnverifiedByDesign,
	"TeamCity":           ClassUnverifiedByDesign,
	"UpstashRedis":       ClassUnverifiedByDesign,
	"Wasabi":             ClassUnverifiedByDesign,
	"Wiz":                ClassUnverifiedByDesign,
	"Zoho":               ClassUnverifiedByDesign,

	// (c) Verifiable but not implemented — 42 detectors
	"AWSSession":             ClassVerifyGap,
	"AlibabaCloud":           ClassVerifyGap,
	"ArgoCD":                 ClassVerifyGap,
	"Atlassian":              ClassVerifyGap,
	"Auth0":                  ClassVerifyGap,
	"AzureAD":                ClassVerifyGap,
	"AzureApp":               ClassVerifyGap,
	"AzureContainerRegistry": ClassVerifyGap,
	"BitbucketServer":        ClassVerifyGap,
	"Bitwarden":              ClassVerifyGap,
	"Bugsnag":                ClassVerifyGap,
	"ClickHouseCloud":        ClassVerifyGap,
	"CloudflareR2":           ClassVerifyGap,
	"Confluence":             ClassVerifyGap,
	"Databricks":             ClassVerifyGap,
	"DatadogAppKey":          ClassVerifyGap,
	"DockerHub":              ClassVerifyGap,
	"DroneCI":                ClassVerifyGap,
	"Freshdesk":              ClassVerifyGap,
	"GCPIDToken":             ClassVerifyGap,
	"GetStream":              ClassVerifyGap,
	"GitLabPipeline":         ClassVerifyGap,
	"Grafana":                ClassVerifyGap,
	"Jira":                   ClassVerifyGap,
	"LaunchNotes":            ClassVerifyGap,
	"Looker":                 ClassVerifyGap,
	"Magento":                ClassVerifyGap,
	"Modal":                  ClassVerifyGap,
	"Okta":                   ClassVerifyGap,
	"PusherBeams":            ClassVerifyGap,
	"SalesforceRefresh":      ClassVerifyGap,
	"Segment":                ClassVerifyGap,
	"Sentry":                 ClassVerifyGap,
	"Snowflake":              ClassVerifyGap,
	"Spinnaker":              ClassVerifyGap,
	"Supabase":               ClassVerifyGap,
	"Tailscale":              ClassVerifyGap,
	"TektonHub":              ClassVerifyGap,
	"TencentCloud":           ClassVerifyGap,
	"Vault":                  ClassVerifyGap,
	"Vonage":                 ClassVerifyGap,
	"Zendesk":                ClassVerifyGap,
}
