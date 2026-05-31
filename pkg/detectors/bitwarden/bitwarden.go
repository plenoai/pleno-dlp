// Package bitwarden detects Bitwarden Secrets Manager (BWS) machine-
// account access tokens (`0.<uuid>.<base64>:<base64>` shape near
// `bitwarden` keyword) and verifies them against the Bitwarden identity
// service.
//
// Verify replays the exact OAuth2 client_credentials flow the Bitwarden
// SDK performs (sdk-internal crates/bitwarden-core/src/auth):
// AccessToken::from_str splits the token into access_token_id (the uuid),
// client_secret (base64 before the colon) and encryption_key (base64 after
// the colon). The encryption_key is derived locally and NEVER sent — it is
// only needed to decrypt fetched secrets. AccessTokenRequest::new posts
// scope=api.secrets, client_id=<uuid> (bare, no `user.` prefix — that prefix
// is for personal API keys only), client_secret=<segment>,
// grant_type=client_credentials to {base}/connect/token as
// application/x-www-form-urlencoded. HTTP 200 with an access_token body means
// the credential is valid; HTTP 400/401 (invalid_client/invalid_grant) means
// rejected. This probe only mints a bearer token; it does not read or decrypt
// any secret, so verification is non-destructive.
package bitwarden

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is the Bitwarden cloud identity host. Verify appends
// /connect/token. EU / self-hosted deployments use a different identity host
// (e.g. https://identity.bitwarden.eu); tests override this var.
var apiBase = "https://identity.bitwarden.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// `0.` version + UUID + `.` + base64 access-key id + `:` + base64
// access-key secret. The version `0.` plus the colon separator is the
// distinctive shape; UUID + base64 segments confirm.
var tokenRe = regexp.MustCompile(`\b(0\.[a-f0-9-]{36}\.[A-Za-z0-9+/=_-]{20,}:[A-Za-z0-9+/=_-]{20,})\b`)

var contextKeywords = []string{"bitwarden", "bws", "bws_access", "secretsmanager"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Bitwarden }

func (Scanner) Keywords() []string { return []string{"0."} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(data[m[2]:m[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// `0.<uuid>.<base64>:<base64>` collides with arbitrary versioned
		// tokens; we require `bitwarden` co-occurrence to disambiguate.
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Bitwarden,
			Raw:          []byte(token),
			Redacted:     redact(token),
			// Bitwarden machine-account tokens grant cross-org secrets
			// access; we surface SeverityCritical because rotation is the
			// only safe remediation.
			Severity: detectors.SeverityCritical,
		}
		if verify {
			v, err := verifyToken(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
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

// Verify replays the Bitwarden SDK's OAuth2 client_credentials flow for a
// Secrets Manager machine-account access token.
func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	return verifyToken(ctx, secret)
}

// parseToken splits `0.<uuid>.<client_secret>:<encryption_key>` into the
// client_id (uuid) and client_secret. The encryption_key segment after the
// final colon is derived/used locally by the SDK and is NOT part of the
// credential the identity endpoint accepts, so it is discarded here.
func parseToken(token string) (clientID, clientSecret string, ok bool) {
	// Split on the last colon: the trailing segment is the encryption_key.
	colon := strings.LastIndex(token, ":")
	if colon < 0 {
		return "", "", false
	}
	head := token[:colon] // 0.<uuid>.<client_secret>
	// head is `0.<uuid>.<client_secret>` — split into 3 dot-separated parts.
	parts := strings.SplitN(head, ".", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	if parts[0] != "0" {
		return "", "", false
	}
	clientID = parts[1]
	clientSecret = parts[2]
	if clientID == "" || clientSecret == "" {
		return "", "", false
	}
	return clientID, clientSecret, true
}

func verifyToken(ctx context.Context, token string) (bool, error) {
	clientID, clientSecret, ok := parseToken(token)
	if !ok {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "api.secrets")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, doErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	// 200 -> valid; 400/401 -> invalid (invalid_client/invalid_grant);
	// 429 / 5xx -> transient (surfaced as VerificationErr, never Verified).
	return detectors.ClassifyVerifyHTTP(resp, doErr, []int{http.StatusOK}, []int{http.StatusBadRequest, http.StatusUnauthorized})
}

func redact(t string) string {
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
