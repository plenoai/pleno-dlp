// Package aws — Revoke implementation (issue #73).
//
// AWS revocation is structurally different from the other Revokers in
// this tree. GitHub / GitLab / Slack let the *holder of the secret*
// revoke the secret itself; the only credential needed is the secret
// (or the OAuth-app pair that minted it). AWS does not work that way:
// `iam:DeleteAccessKey` is a *principal-context* operation —
// revoking access key `AKIA...` requires (1) admin IAM credentials
// authorised to call iam:DeleteAccessKey, and (2) the IAM user the key
// belongs to (`UserName`). Neither piece is recoverable from the leaked
// access-key id alone.
//
// We therefore require the operator to supply both the admin
// credentials and the target user name out-of-band, via
// SetRevokeCredentials (CLI plumbing) or via the
// PLENO_DLP_REVOKE_AWS_* env vars. Without them Revoke returns a hard
// error so a misconfigured CI does not silently no-op.
//
// Implementation note: the SigV4 signer is implemented inline rather
// than via aws-sdk-go-v2's signer/v4 package. The detector dispatch
// path is hot and the SDK signer pulls in middleware/retry machinery
// we do not need for a single fire-and-forget POST. Inline keeps the
// dependency surface honest (already importing aws-sdk-go-v2 for
// sts:GetCallerIdentity in Verify) and keeps the revoke path
// independent of SDK retry timing — Revoke's policy is "one attempt,
// surface the result", not "retry on transient signing errors".
package aws

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is overridable from tests so revoke can hit an httptest server.
// The real IAM endpoint is global (region in the SigV4 signature is
// always "us-east-1" — IAM is a global service).
var apiBase = "https://iam.amazonaws.com"

// httpClient is shared across Revoke calls. 10s timeout matches Verify.
var revokeHTTPClient = &http.Client{Timeout: 10 * time.Second}

// Env variable names for the admin IAM credentials Revoke needs.
// Documented here so cmd/pleno-dlp/cmd/revoke.go and
// docs/revoke-support.md stay in sync with the canonical source.
const (
	EnvAdminAccessKeyID     = "PLENO_DLP_REVOKE_AWS_ADMIN_ACCESS_KEY_ID"
	EnvAdminSecretAccessKey = "PLENO_DLP_REVOKE_AWS_ADMIN_SECRET_ACCESS_KEY"
	EnvAdminSessionToken    = "PLENO_DLP_REVOKE_AWS_ADMIN_SESSION_TOKEN"
	EnvRegion               = "PLENO_DLP_REVOKE_AWS_REGION"
	EnvUserName             = "PLENO_DLP_REVOKE_AWS_USER_NAME"
)

// defaultRevokeRegion is used when the operator does not explicitly set
// a region. IAM is global; us-east-1 is the canonical signing region.
const defaultRevokeRegion = "us-east-1"

// revokeCreds holds the admin IAM credentials Revoke uses. Same
// rationale as the GitHub detector: Scanner is a value type registered
// through detectors.Register and shared across detector dispatch, so a
// package-level mutex-guarded struct is simpler than threading state
// through Scanner.
var (
	revokeCredsMu sync.RWMutex
	revokeCreds   struct {
		accessKeyID     string
		secretAccessKey string
		sessionToken    string
		region          string
		userName        string
	}
)

// SetRevokeCredentials wires the admin IAM credentials and target
// user name Revoke uses. Calling with all-empty args clears prior
// state (useful in tests). Region falls back to us-east-1 when
// unset.
func SetRevokeCredentials(adminAccessKeyID, adminSecretAccessKey, sessionToken, region, userName string) {
	revokeCredsMu.Lock()
	revokeCreds.accessKeyID = adminAccessKeyID
	revokeCreds.secretAccessKey = adminSecretAccessKey
	revokeCreds.sessionToken = sessionToken
	revokeCreds.region = region
	revokeCreds.userName = userName
	revokeCredsMu.Unlock()
}

func loadRevokeCreds() (accessKeyID, secretAccessKey, sessionToken, region, userName string) {
	revokeCredsMu.RLock()
	accessKeyID = revokeCreds.accessKeyID
	secretAccessKey = revokeCreds.secretAccessKey
	sessionToken = revokeCreds.sessionToken
	region = revokeCreds.region
	userName = revokeCreds.userName
	revokeCredsMu.RUnlock()
	if accessKeyID == "" {
		accessKeyID = os.Getenv(EnvAdminAccessKeyID)
	}
	if secretAccessKey == "" {
		secretAccessKey = os.Getenv(EnvAdminSecretAccessKey)
	}
	if sessionToken == "" {
		sessionToken = os.Getenv(EnvAdminSessionToken)
	}
	if region == "" {
		region = os.Getenv(EnvRegion)
	}
	if region == "" {
		region = defaultRevokeRegion
	}
	if userName == "" {
		userName = os.Getenv(EnvUserName)
	}
	return
}

// Revoke implements detectors.Revoker for AWS access-key id secrets.
//
// The endpoint is `POST https://iam.amazonaws.com/` with a
// form-encoded body invoking the DeleteAccessKey action. AWS's
// documented response codes (after SigV4 auth):
//
//   - 200 OK                                        -> revoked. Revoked = true.
//   - 404 / Error code "NoSuchEntity"               -> already revoked or
//     never existed. Revoked = true (idempotency contract — second-call
//     against an already-revoked secret MUST NOT hard-fail). Diagnostic
//     in RevokeResult.Err so the caller can distinguish "we revoked
//     just now" from "it was already gone".
//   - 403 / "AccessDenied" / "InvalidClientTokenId" /
//     "SignatureDoesNotMatch"                       -> hard error via the
//     second return value (admin creds don't have iam:DeleteAccessKey,
//     or the creds are wrong / expired).
//   - 429 ThrottlingException / Throttling          -> hard error, no retry.
//   - other                                         -> hard error with status + body snippet.
//
// Revoke is irreversible. Per ADR-0001 D6 the CLI gates this behind
// `--confirm` / `--dry-run` and the env var PLENO_DLP_ALLOW_REVOKE=1;
// the detector itself does NOT enforce any local gate so dry-run /
// confirmation policy lives uniformly at the CLI boundary.
//
// ProviderID is set to the revoked AccessKeyId so audit logs can
// cross-reference the provider's own records.
func (Scanner) Revoke(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	if secret == "" {
		return detectors.RevokeResult{}, errors.New("aws: revoke: empty secret")
	}
	// Validate input shape: only AKIA-prefixed access-key ids are
	// revocable via iam:DeleteAccessKey. Secret access keys, session
	// tokens (ASIA), and other AWS credential classes are out of scope.
	if !isAccessKeyID(secret) {
		return detectors.RevokeResult{}, errors.New("aws: revoke: secret must be an Access Key ID (AKIA...)")
	}
	adminID, adminSecret, sessionToken, region, userName := loadRevokeCreds()
	if adminID == "" || adminSecret == "" || userName == "" {
		return detectors.RevokeResult{}, fmt.Errorf(
			"aws revoke requires %s + %s + %s (env or --admin-access-key-id / --admin-secret-access-key / --user-name)",
			EnvAdminAccessKeyID, EnvAdminSecretAccessKey, EnvUserName,
		)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	form := url.Values{}
	form.Set("Action", "DeleteAccessKey")
	form.Set("UserName", userName)
	form.Set("AccessKeyId", secret)
	form.Set("Version", "2010-05-08")
	body := form.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/", strings.NewReader(body))
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	now := time.Now().UTC()
	if err := signV4(req, []byte(body), adminID, adminSecret, sessionToken, region, "iam", now); err != nil {
		return detectors.RevokeResult{}, fmt.Errorf("aws: revoke: sigv4 sign: %w", err)
	}

	resp, err := revokeHTTPClient.Do(req)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	revokedAt := time.Now().UTC()

	// AWS query API conventionally returns 4xx on errors and 200 on
	// success, with an XML <Error><Code>...</Code></Error> envelope
	// under the failure cases. Inspect the body for the error code so
	// we route NoSuchEntity to idempotency rather than to a hard fail.
	if resp.StatusCode == http.StatusOK {
		return detectors.RevokeResult{Revoked: true, RevokedAt: revokedAt, ProviderID: secret}, nil
	}

	code := extractErrorCode(respBody)
	switch code {
	case "NoSuchEntity":
		// Idempotent: key already gone (or the user has no such key).
		return detectors.RevokeResult{
			Revoked:    true,
			RevokedAt:  revokedAt,
			ProviderID: secret,
			Err:        errors.New("aws: access key already deleted or never existed (NoSuchEntity)"),
		}, nil
	case "AccessDenied":
		return detectors.RevokeResult{}, fmt.Errorf("aws: revoke: admin credentials lack iam:DeleteAccessKey (HTTP %d, AccessDenied)", resp.StatusCode)
	case "InvalidClientTokenId":
		return detectors.RevokeResult{}, fmt.Errorf("aws: revoke: admin credentials rejected (HTTP %d, InvalidClientTokenId) — check %s / %s", resp.StatusCode, EnvAdminAccessKeyID, EnvAdminSecretAccessKey)
	case "SignatureDoesNotMatch":
		return detectors.RevokeResult{}, fmt.Errorf("aws: revoke: SigV4 signature rejected (HTTP %d) — check %s", resp.StatusCode, EnvAdminSecretAccessKey)
	case "Throttling", "ThrottlingException", "TooManyRequestsException":
		return detectors.RevokeResult{}, fmt.Errorf("aws: revoke: rate-limited (HTTP %d, %s)", resp.StatusCode, code)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return detectors.RevokeResult{}, fmt.Errorf("aws: revoke: rate-limited (HTTP 429)")
	}

	snippet := respBody
	if len(snippet) > 256 {
		snippet = snippet[:256]
	}
	return detectors.RevokeResult{}, fmt.Errorf("aws: revoke: unexpected status %s: %s", resp.Status, string(snippet))
}

// isAccessKeyID accepts the AKIA* shape iam:DeleteAccessKey expects.
// AWS access key ids are exactly 20 chars: 4-char prefix (AKIA / AGPA /
// AROA / etc) plus 16 uppercase alphanumerics. Revoke supports the AKIA
// long-term user-key shape only.
func isAccessKeyID(s string) bool {
	if len(s) != 20 {
		return false
	}
	if !strings.HasPrefix(s, "AKIA") {
		return false
	}
	for i := 4; i < 20; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return true
}

// extractErrorCode pulls the first <Code>...</Code> value out of an AWS
// query-API XML error envelope. We avoid a full XML parse — the body is
// small, the Code element is at a fixed depth, and a substring lookup
// keeps the dependency surface small. Returns "" when no Code element
// is present (including non-XML bodies).
func extractErrorCode(body []byte) string {
	const open = "<Code>"
	const closeTag = "</Code>"
	i := bytes.Index(body, []byte(open))
	if i < 0 {
		return ""
	}
	rest := body[i+len(open):]
	j := bytes.Index(rest, []byte(closeTag))
	if j < 0 {
		return ""
	}
	return string(rest[:j])
}

// signV4 attaches an AWS Signature Version 4 Authorization header to
// req for service in region using the supplied static credentials.
// payload is the exact body the server will see (post-encoding). now is
// the signing instant — passed in so tests can pin a clock.
//
// Reference: docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
//
// Why not aws-sdk-go-v2/aws/signer/v4: we only need a one-shot
// synchronous signer for a single POST to iam.amazonaws.com. The
// SDK signer carries middleware coupling we do not benefit from
// here, and an inline signer keeps the revoke path independent of
// SDK retry timing.
func signV4(req *http.Request, payload []byte, accessKeyID, secretAccessKey, sessionToken, region, service string, now time.Time) error {
	const algorithm = "AWS4-HMAC-SHA256"

	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	// Required headers: host + x-amz-date (+ optional x-amz-security-token).
	// We sign exactly the headers we send; downstream proxies adding
	// headers is fine because they aren't in SignedHeaders.
	req.Header.Set("X-Amz-Date", amzDate)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}

	// Host header: net/http elides Host from req.Header.Set; the canonical
	// request uses req.Host (or req.URL.Host if Host is unset).
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	// Canonical headers — lowercase name, trimmed value, sorted by name.
	type kv struct{ k, v string }
	headers := []kv{
		{"host", host},
		{"x-amz-date", amzDate},
	}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		headers = append(headers, kv{"content-type", ct})
	}
	if sessionToken != "" {
		headers = append(headers, kv{"x-amz-security-token", sessionToken})
	}
	sort.Slice(headers, func(i, j int) bool { return headers[i].k < headers[j].k })

	var canonicalHeaders strings.Builder
	signedNames := make([]string, 0, len(headers))
	for _, h := range headers {
		canonicalHeaders.WriteString(h.k)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(h.v))
		canonicalHeaders.WriteByte('\n')
		signedNames = append(signedNames, h.k)
	}
	signedHeaders := strings.Join(signedNames, ";")

	// Canonical query string. We send the action in the body, so this is
	// always the empty string for IAM. We still encode rawquery for
	// safety in case a future caller appends one.
	canonicalQuery := canonicalQueryString(req.URL.RawQuery)

	// Canonical URI: empty path → "/". IAM uses "/" exclusively.
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	payloadHash := hex.EncodeToString(sha256sum(payload))
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		algorithm,
		amzDate,
		credentialScope,
		hex.EncodeToString(sha256sum([]byte(canonicalRequest))),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secretAccessKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	auth := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm, accessKeyID, credentialScope, signedHeaders, signature)
	req.Header.Set("Authorization", auth)
	return nil
}

func sha256sum(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// canonicalQueryString sorts query parameters by name (then by value)
// and encodes them per RFC 3986. AWS SigV4 requires this exact form.
func canonicalQueryString(raw string) string {
	if raw == "" {
		return ""
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return raw
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		vs := values[k]
		sort.Strings(vs)
		for j, v := range vs {
			if i > 0 || j > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(v))
		}
	}
	return b.String()
}

// Compile-time interface check. Scanner already satisfies Detector +
// Verifier from aws.go; this confirms Revoker too.
var _ detectors.Revoker = Scanner{}
