// Package aws detects AWS access key id / secret access key pairs and
// optionally verifies them via sts:GetCallerIdentity.
//
// Verify also enriches the finding with blast-radius metadata when the
// upstream call succeeds (driftwood-style "what does this credential
// actually unlock"):
//
//   - aws_account_id   12-digit AWS account number from sts:GetCallerIdentity
//   - aws_arn          full caller ARN, e.g. arn:aws:iam::123456789012:user/Alice
//   - aws_user_id      AWS-internal principal id (AIDA…/AROA…)
//   - aws_principal_kind  user | root | assumed-role | federated-user | other
//   - aws_partition    aws | aws-cn | aws-us-gov, parsed from the ARN
//   - aws_privileged   "true" when the caller is the account root, or
//     when the assumed-role / user name suggests an
//     admin path (`Admin`, `Administrator`,
//     `OrganizationAccountAccessRole`,
//     `AWSReservedSSO_Admin*`). Same Critical bucket
//     but triage-sortable by impact.
package aws

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// AKIA[0-9A-Z]{16} is the canonical access-key-id shape. ASIA covers temporary
// credentials but is intentionally out of scope for the MVP.
var (
	idRe = regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`)
	// Secret access key: 40 chars from the base64-ish set. The boundary `\b`
	// would treat `+` and `/` as boundaries, so we anchor with a negative
	// lookbehind-equivalent via byte class on the surrounding chars manually.
	secretRe = regexp.MustCompile(`[^A-Za-z0-9+/]([A-Za-z0-9+/]{40})[^A-Za-z0-9+/]`)
)

// arnRe parses a caller ARN into partition/service/account/resource so we
// can derive the principal kind without string-splitting in five places.
// Pattern: arn:<partition>:<service>::<account>:<resource>
//
// AWS reserves enough special-cases (root, federated-user/, assumed-role/<role>/<session>)
// that we extract the resource segment and let principalKind switch over it.
var arnRe = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov):([^:]+)::?(\d+)?:(.+)$`)

// stsRegion is the region used for the verification call. us-east-1 is a safe
// default — sts:GetCallerIdentity is a global API and accepts any region.
const stsRegion = "us-east-1"

// stsClientFactory builds an STS client. Tests override this to inject a
// mock that exposes the *sts.GetCallerIdentityOutput we want to assert
// against. Using a factory rather than passing a client into Scanner keeps
// the Scanner zero-value usable from `detectors.Register(Scanner{})`.
var stsClientFactory = newSTSClient

// stsCaller is the narrow interface verifyPair needs. The real *sts.Client
// satisfies it; tests substitute an httptest.Server-backed fake.
type stsCaller interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func newSTSClient(id, secret string) stsCaller {
	cfg := awssdk.Config{
		Region:      stsRegion,
		Credentials: credentials.NewStaticCredentialsProvider(id, secret, ""),
	}
	return sts.NewFromConfig(cfg)
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AWS }

func (Scanner) Keywords() []string { return []string{"AKIA"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	idMatches := idRe.FindAllSubmatchIndex(data, -1)
	if len(idMatches) == 0 {
		return nil, nil
	}

	// Pre-compute secret candidates. Use a wider sweep so we can pick the
	// nearest match to each access-key id.
	secretMatches := secretRe.FindAllSubmatchIndex(data, -1)

	results := make([]detectors.Result, 0, len(idMatches))
	for _, m := range idMatches {
		id := string(data[m[2]:m[3]])
		secret, ok := nearestSecret(m[2], data, secretMatches)
		extra := map[string]string{"access_key_id": id}
		res := detectors.Result{
			DetectorType: detectors.AWS,
			Raw:          []byte(id),
			Redacted:     redact(id),
			ExtraData:    extra,
		}
		if ok {
			res.RawV2 = []byte(secret)
			if verify {
				verified, meta, err := verifyWithMetadata(ctx, id, secret)
				res.Verified = verified
				res.VerificationErr = err
				for k, v := range meta {
					extra[k] = v
				}
			}
		}
		results = append(results, res)
	}
	return results, nil
}

// nearestSecret picks the closest 40-char base64-ish run within 256 bytes of
// the access-key id position. Returns the secret string and ok=true when one
// is found.
func nearestSecret(idStart int, data []byte, secrets [][]int) (string, bool) {
	const maxDistance = 256
	bestDist := maxDistance + 1
	best := ""
	for _, sm := range secrets {
		// sm[2]..sm[3] is the captured group (the 40-char run).
		start, end := sm[2], sm[3]
		dist := absDist(start, idStart)
		if dist < bestDist {
			bestDist = dist
			best = string(data[start:end])
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

func absDist(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}

func redact(id string) string {
	if len(id) <= 4 {
		return id
	}
	return id[:4] + "..."
}

// Verify expects "<access_key_id>:<secret_access_key>" because the
// detectors.Verifier interface only takes a single string. The engine
// never calls Verify directly with a packed string today; FromData
// performs the call inline. This method is provided to satisfy the
// Verifier contract and to stay forward-compatible.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	id, sk, ok := splitPair(secret)
	if !ok {
		return false, fmt.Errorf("aws: expected id:secret pair")
	}
	v, _, err := verifyWithMetadata(ctx, id, sk)
	return v, err
}

func splitPair(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// verifyWithMetadata performs the sts:GetCallerIdentity call and returns
// the verification outcome plus the parsed identity metadata. A
// successful call yields the account/arn/user-id triplet and the
// derived principal-kind / partition / privileged flags.
//
// On any error (rate limit, signature mismatch, expired key, transport
// failure) the call returns verified=false with err=nil — matching the
// existing Verifier contract that "could not confirm" is not a scan
// error.
func verifyWithMetadata(ctx context.Context, id, secret string) (bool, map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	client := stsClientFactory(id, secret)
	out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return false, nil, nil //nolint:nilerr // 401/403 etc. = unverified, not a scan error
	}
	meta := buildIdentityMetadata(out)
	return true, meta, nil
}

// buildIdentityMetadata extracts the blast-radius surface from a
// successful GetCallerIdentity response.
func buildIdentityMetadata(out *sts.GetCallerIdentityOutput) map[string]string {
	meta := map[string]string{}
	if out == nil {
		return meta
	}
	if out.Account != nil && *out.Account != "" {
		meta["aws_account_id"] = *out.Account
	}
	if out.Arn != nil && *out.Arn != "" {
		arn := *out.Arn
		meta["aws_arn"] = arn
		if partition, kind, resource, ok := parseARN(arn); ok {
			meta["aws_partition"] = partition
			meta["aws_principal_kind"] = kind
			if isPrivilegedResource(kind, resource) {
				meta["aws_privileged"] = "true"
			}
		}
	}
	if out.UserId != nil && *out.UserId != "" {
		meta["aws_user_id"] = *out.UserId
	}
	return meta
}

// parseARN extracts (partition, principal-kind, resource-tail). Returns
// ok=false when the ARN does not match the canonical
// `arn:<partition>:iam::<account>:<resource>` shape; STS occasionally
// returns federated identities with an empty account so the regex
// allows it.
func parseARN(arn string) (partition, kind, resource string, ok bool) {
	m := arnRe.FindStringSubmatch(arn)
	if m == nil {
		return "", "", "", false
	}
	partition = m[1]
	resource = m[4]
	kind = principalKind(resource)
	return partition, kind, resource, true
}

// principalKind maps the ARN resource segment to a coarse class. The
// surface is small enough that an explicit prefix table beats a regex.
func principalKind(resource string) string {
	switch {
	case resource == "root":
		return "root"
	case strings.HasPrefix(resource, "user/"):
		return "user"
	case strings.HasPrefix(resource, "assumed-role/"):
		return "assumed-role"
	case strings.HasPrefix(resource, "federated-user/"):
		return "federated-user"
	case strings.HasPrefix(resource, "role/"):
		return "role"
	default:
		return "other"
	}
}

// privilegedNameTokens is the set of substrings whose presence in a role
// or user name strongly suggests admin / break-glass privilege. Curated
// to favour false positives over false negatives — better to mark a
// "TestAdmin" key as privileged and let triage downgrade it than to
// silently miss a real admin key.
var privilegedNameTokens = []string{
	"admin",
	"administrator",
	"poweruser",
	"breakglass",
	"break-glass",
	"organizationaccountaccessrole",
	"awsreservedsso_admin",
	"superuser",
	"root",
}

// isPrivilegedResource flags root + admin-named principals. The
// resource-tail is the part after `arn:aws:iam::<account>:` so user
// names appear as `user/Alice` and assumed-role sessions as
// `assumed-role/<RoleName>/<SessionName>`. We lower-case once and run
// substring checks because we cannot enumerate the full naming
// conventions across orgs.
func isPrivilegedResource(kind, resource string) bool {
	if kind == "root" {
		return true
	}
	low := strings.ToLower(resource)
	for _, t := range privilegedNameTokens {
		if strings.Contains(low, t) {
			return true
		}
	}
	return false
}

func init() {
	detectors.Register(Scanner{})
}
