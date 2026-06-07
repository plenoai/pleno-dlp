// Package verifycoverage mirrors docs/verify-coverage.md as Go data.
package verifycoverage

type Class string

const (
	ClassVerified           Class = "a"
	ClassUnverifiedByDesign Class = "b"
	ClassVerifyGap          Class = "c"
)

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

func Lookup(detectorType string) (Class, bool) {
	if c, ok := Classes[detectorType]; ok {
		return c, true
	}
	return "", false
}

var Classes = map[string]Class{
	// (b) Unverified-by-design — 50 detectors
	"APNs":              ClassUnverifiedByDesign,
	"AWSS3PresignedURL": ClassUnverifiedByDesign,
	"AgoraIO":           ClassUnverifiedByDesign,
	"Akamai":            ClassUnverifiedByDesign,
	"AppStoreConnect":   ClassUnverifiedByDesign,
	"Atlassian":         ClassUnverifiedByDesign,
	"Auth0":             ClassUnverifiedByDesign,
	// AzureAD, AzureApp, and AzureContainerRegistry intentionally absent —
	// AzureAD/AzureApp satisfy detectors.Verifier via context-extraction-based
	// OAuth2 client_credentials grant; AzureContainerRegistry satisfies it via
	// GET /v2/ (access tokens) and POST /oauth2/token (refresh tokens),
	// with the registry host extracted from the JWT payload. All three fall
	// into the open-set complement (class a).
	// AzureSQLConnString intentionally absent — the detector now satisfies
	// detectors.Verifier via TDS LOGIN7 wire-protocol handshake over TLS
	// against the *.database.windows.net host extracted from the connection
	// string. It falls into the open-set complement (class a).
	"BasicAuth":          ClassUnverifiedByDesign,
	"Bugsnag":            ClassUnverifiedByDesign,
	"CloudflareR2":       ClassUnverifiedByDesign,
	"ConcourseCI":        ClassUnverifiedByDesign,
	"Confluence":         ClassUnverifiedByDesign,
	"CrispChat":          ClassUnverifiedByDesign,
	"DatadogAppKey":      ClassUnverifiedByDesign,
	"DroneCI":            ClassUnverifiedByDesign,
	"Exoscale":           ClassUnverifiedByDesign,
	"GCSSignedURL":       ClassUnverifiedByDesign,
	"GenericHighEntropy": ClassUnverifiedByDesign,
	"GetStream":          ClassUnverifiedByDesign,
	"GitLabPipeline":     ClassUnverifiedByDesign,
	"GoCD":               ClassUnverifiedByDesign,
	"JWT":                ClassUnverifiedByDesign,
	"Jenkins":            ClassUnverifiedByDesign,
	"Jira":               ClassUnverifiedByDesign,
	"Kafka":              ClassUnverifiedByDesign,
	// Kubeconfig intentionally absent — the detector now satisfies
	// detectors.Verifier by probing GET <server>/version with the bearer
	// token or mTLS client cert extracted from the same kubeconfig YAML.
	// It falls into the open-set complement (class a).
	"LaunchNotes": ClassUnverifiedByDesign,
	"Looker":      ClassUnverifiedByDesign,
	"Magento":     ClassUnverifiedByDesign,
	"Modal":       ClassUnverifiedByDesign,
	// MongoDB intentionally absent — the detector now satisfies
	// detectors.Verifier via OP_MSG isMaster connectivity probe. It falls
	// into the open-set complement (class a).
	// MySQL intentionally absent — the detector now satisfies
	// detectors.Verifier via mysql_native_password wire-protocol handshake.
	// It falls into the open-set complement (class a).
	"OVHCloud":     ClassUnverifiedByDesign,
	"PIIAnonymize": ClassUnverifiedByDesign,
	"PIIOpenAIPF":  ClassUnverifiedByDesign,
	// PIICreditCard / PIIEmail / PIIIBAN / PIIUSSSN entries removed —
	// the detectors were retired in favour of PIIAnonymize. The
	// DetectorType constants stay pinned at their ordinals (76..79)
	// per ADR-0002 but no live registration exists, so the doc /
	// Classes drift tests no longer require entries here.
	"PingIdentity": ClassUnverifiedByDesign,
	// Postgres intentionally absent — the detector now satisfies
	// detectors.Verifier via PostgreSQL wire-protocol StartupMessage +
	// cleartext / MD5 password authentication. It falls into the open-set
	// complement (class a).
	// PrivateKeyPEM intentionally absent — the detector now satisfies
	// detectors.Verifier via blast-radius lookup against Certificate
	// Transparency (crt.sh `?spkisha256=`). It falls into the open-set
	// complement (class a). See docs/verify-coverage.md and the
	// pkg/detectors/privatekey/blastradius package.
	"PusherBeams": ClassUnverifiedByDesign,
	"RabbitMQ":    ClassUnverifiedByDesign,
	// Redis intentionally absent — the detector now satisfies
	// detectors.Verifier via RESP-protocol AUTH probe. It falls into the
	// open-set complement (class a).
	"RequestBin":    ClassUnverifiedByDesign,
	"SMTP":          ClassUnverifiedByDesign,
	"Segment":       ClassUnverifiedByDesign,
	"Sinch":         ClassUnverifiedByDesign,
	"Smee":          ClassUnverifiedByDesign,
	"SonatypeNexus": ClassUnverifiedByDesign,
	"Spinnaker":     ClassUnverifiedByDesign,
	"Stytch":        ClassUnverifiedByDesign,
	"TektonHub":     ClassUnverifiedByDesign,
	"UpstashRedis":  ClassUnverifiedByDesign,
	"Wiz":           ClassUnverifiedByDesign,
	"Zoho":          ClassUnverifiedByDesign,

	// (b) reclassified from (c): fundamentally unverifiable from the
	// matched secret, not merely not-yet-wired —
	//   SalesforceRefresh: refresh-token exchange requires instance URL +
	//     client_id + client_secret, none co-located in the matched chunk.
	//   Sentry: the matched value is a DSN ingest *write* key; the only
	//     "verify" is submitting an event (destructive / billed).
	//   Snowflake: keypair JWT auth needs the *private key* to sign the
	//     assertion, which is never present in the matched chunk.
	"SalesforceRefresh": ClassUnverifiedByDesign,
	"Sentry":            ClassUnverifiedByDesign,
	"Snowflake":         ClassUnverifiedByDesign,
}
