// Package awssession detects AWS temporary session credential triples
// (ASIA<16>) — access-key-id with paired secret access key and session token —
// and verifies them via sts:GetCallerIdentity.
//
// The matched secret is a complete temporary-credential triple: the ASIA
// access-key-id, the 40-char secret access key, and the session token. That
// triple is itself the credential STS accepts. GetCallerIdentity is a global
// API — us-east-1 accepts any token — so no per-tenant host or region context
// is needed: temporary creds verify by passing all three components through
// credentials.NewStaticCredentialsProvider(id, secret, sessionToken), which
// makes aws-sdk-go-v2 add the X-Amz-Security-Token header to the SigV4-signed
// request. This mirrors the sibling pkg/detectors/aws STS path exactly; ASIA
// only differs by supplying the captured session token as the third arg.
//
// Region/time-scoping is not an obstacle: GetCallerIdentity is global, and an
// expired token simply yields a correct Verified=false (ExpiredToken /
// InvalidClientTokenId / SignatureDoesNotMatch -> HTTP 403), not an error. We
// only probe when verify==true, identical to how the class-a aws detector
// gates its STS call.
//
// The token shape is the canonical signal: ASIA[0-9A-Z]{16} for the id, the
// 40-char secret-access-key shape from the existing AWS detector, plus a
// session token (FwoG…/IQoJb3JpZ2luX2VjE…) that is base64-ish and ~200 chars
// long. The session-token shape is what disambiguates this detector from the
// long-lived AKIA path owned by `pkg/detectors/aws`.
package awssession

import (
	"context"
	"regexp"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// stsRegion is the region used for the verification call. us-east-1 is a safe
// default — sts:GetCallerIdentity is a global API and accepts any region.
const stsRegion = "us-east-1"

// stsCaller is the narrow interface the verify path needs. The real
// *sts.Client satisfies it; tests substitute a deterministic fake.
type stsCaller interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// stsClientFactory builds an STS client from the full temporary-credential
// triple. Passing the sessionToken as the third arg makes aws-sdk-go-v2 sign
// with SigV4 and attach the X-Amz-Security-Token header. Tests override this
// to inject a mock. Using a factory keeps the zero-value Scanner usable from
// detectors.Register(Scanner{}).
var stsClientFactory = newSTSClient

func newSTSClient(id, secret, sessionToken string) stsCaller {
	cfg := awssdk.Config{
		Region:      stsRegion,
		Credentials: credentials.NewStaticCredentialsProvider(id, secret, sessionToken),
	}
	return sts.NewFromConfig(cfg)
}

var (
	// ASIA<16> is the temporary credential prefix. AKIA is owned by the
	// long-lived AWS detector and is intentionally excluded here so the two
	// don't double-fire on the same id.
	idRe = regexp.MustCompile(`\b(ASIA[0-9A-Z]{16})\b`)
	// 40-char base64-ish run, same shape as the long-lived secret access
	// key. We anchor with non-base64 surrounding bytes so adjacent tokens
	// don't merge into a single capture.
	secretRe = regexp.MustCompile(`[^A-Za-z0-9+/]([A-Za-z0-9+/]{40})[^A-Za-z0-9+/]`)
	// Session tokens are base64 with `+/=` and run 100..1024 chars. Go's
	// regexp engine caps the upper repetition bound at 1000, so we use
	// 100..1000 — that still covers every Amazon-issued session token
	// today.
	sessionRe = regexp.MustCompile(`[^A-Za-z0-9+/=]([A-Za-z0-9+/=]{100,1000})[^A-Za-z0-9+/=]`)
)

var contextKeywords = []string{"aws_session_token", "session_token", "sessiontoken", "x-amz-security-token"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AWSSession }

// ASIA prefilters cheaply; session_token catches cases where the id is on a
// separate line far from the prefix.
func (Scanner) Keywords() []string { return []string{"ASIA", "session_token"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	idMatches := idRe.FindAllSubmatchIndex(data, -1)
	if len(idMatches) == 0 {
		return nil, nil
	}
	secrets := secretRe.FindAllSubmatchIndex(data, -1)
	sessions := sessionRe.FindAllSubmatchIndex(data, -1)
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(idMatches))
	seen := map[string]struct{}{}
	for _, m := range idMatches {
		id := string(data[m[2]:m[3]])
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		// The session-token co-occurrence keyword is mandatory: ASIA can
		// otherwise show up in benign IAM policy fixtures. Without it we
		// emit nothing.
		if !nearKeyword(lower, m[2], m[3]) && !haveNearbySession(m[2], data, sessions) {
			continue
		}
		secret, _ := nearestRun(m[2], data, secrets, 512)
		session, _ := nearestRun(m[2], data, sessions, 1024)

		res := detectors.Result{
			DetectorType: detectors.AWSSession,
			Raw:          []byte(id),
			Redacted:     redact(id),
			ExtraData:    map[string]string{"access_key_id": id},
		}
		if secret != "" {
			res.RawV2 = []byte(secret)
		}
		if session != "" {
			res.ExtraData["session_token_prefix"] = redact(session)
		}
		// Verification needs the full triple: ASIA id, 40-char secret, and
		// the complete session token (not the redacted prefix). STS only
		// confirms a credential when all three sign the request.
		if verify && secret != "" && session != "" {
			verified, meta, err := verifyWithMetadata(ctx, id, secret, session)
			res.Verified = verified
			res.VerificationErr = err
			for k, v := range meta {
				res.ExtraData[k] = v
			}
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func haveNearbySession(idStart int, data []byte, sessions [][]int) bool {
	for _, sm := range sessions {
		if abs(sm[2]-idStart) <= 1024 {
			return true
		}
	}
	_ = data
	return false
}

func nearestRun(idStart int, data []byte, runs [][]int, maxDistance int) (string, bool) {
	bestDist := maxDistance + 1
	best := ""
	for _, sm := range runs {
		start, end := sm[2], sm[3]
		dist := abs(start - idStart)
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

func nearKeyword(lower string, start, end int) bool {
	const radius = 256
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, kw := range contextKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

// Verify expects the packed triple "<access_key_id>:<secret_access_key>:<session_token>"
// because detectors.Verifier takes a single string. FromData performs the
// call inline today; this method satisfies the Verifier contract and stays
// forward-compatible.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	id, sk, session, ok := splitTriple(secret)
	if !ok {
		return false, nil
	}
	v, _, err := verifyWithMetadata(ctx, id, sk, session)
	return v, err
}

// splitTriple parses "id:secret:session". The session token itself contains
// no ':' for Amazon-issued tokens (base64 with +/= only), so two splits from
// the left is unambiguous.
func splitTriple(s string) (id, secret, session string, ok bool) {
	first := strings.IndexByte(s, ':')
	if first < 0 {
		return "", "", "", false
	}
	rest := s[first+1:]
	second := strings.IndexByte(rest, ':')
	if second < 0 {
		return "", "", "", false
	}
	return s[:first], rest[:second], rest[second+1:], true
}

// verifyWithMetadata performs the sts:GetCallerIdentity call using the full
// temporary-credential triple and returns the verification outcome plus the
// parsed identity metadata.
//
// STS rejects invalid/mismatched/expired creds (InvalidClientTokenId /
// SignatureDoesNotMatch / ExpiredToken -> HTTP 403), and there is no wrong
// endpoint that could return a spurious 200. On any error (rate limit 429,
// signature mismatch, expired token, transport failure) the call returns
// verified=false. Rate-limit / transport errors surface as a
// VerificationErr; credential-rejection 403s are a clean Verified=false with
// err=nil — matching the existing Verifier contract that "could not confirm"
// is not a scan error.
func verifyWithMetadata(ctx context.Context, id, secret, session string) (bool, map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	client := stsClientFactory(id, secret, session)
	out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		if isCredentialRejection(err) {
			// Explicit rejection by STS: not valid, not an error.
			return false, nil, nil
		}
		// Rate limit (429) / transport: could-not-confirm. Surface the
		// error so the engine can show VerificationErr; no retry on 429.
		return false, nil, err
	}
	return true, buildIdentityMetadata(out), nil
}

// credentialRejectionCodes are the STS API error codes that mean the
// credential is definitively invalid (HTTP 403). These are a clean
// Verified=false, distinct from rate-limit / transport failures.
var credentialRejectionCodes = []string{
	"InvalidClientTokenId",
	"SignatureDoesNotMatch",
	"ExpiredToken",
	"TokenRefreshRequired",
	"AccessDenied",
	"UnrecognizedClientException",
}

// isCredentialRejection reports whether the SDK error carries one of the STS
// codes that mean "these creds are not valid" (vs. a transient failure). The
// SDK wraps API errors so we match on the rendered message, which always
// contains the error code.
func isCredentialRejection(err error) bool {
	msg := err.Error()
	for _, code := range credentialRejectionCodes {
		if strings.Contains(msg, code) {
			return true
		}
	}
	return false
}

// buildIdentityMetadata extracts the blast-radius surface from a successful
// GetCallerIdentity response. Temporary credentials always resolve to an
// assumed-role / federated principal.
func buildIdentityMetadata(out *sts.GetCallerIdentityOutput) map[string]string {
	meta := map[string]string{}
	if out == nil {
		return meta
	}
	if out.Account != nil && *out.Account != "" {
		meta["aws_account_id"] = *out.Account
	}
	if out.Arn != nil && *out.Arn != "" {
		meta["aws_arn"] = *out.Arn
	}
	if out.UserId != nil && *out.UserId != "" {
		meta["aws_user_id"] = *out.UserId
	}
	return meta
}

func init() {
	detectors.Register(Scanner{})
}
