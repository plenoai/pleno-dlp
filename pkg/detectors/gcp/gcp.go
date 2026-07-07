// Package gcp detects Google Cloud service-account JSON credentials and
// verifies them by exchanging a self-signed RS256 JWT for an OAuth2 access
// token at https://oauth2.googleapis.com/token.
package gcp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenURL = "https://oauth2.googleapis.com/token"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// gcp service-account JSON keys are multiline. Anchor on the unique pair:
// "type": "service_account" + a private_key block. We expand from there to the
// enclosing JSON object via brace counting.
var typeRe = regexp.MustCompile(`"type"\s*:\s*"service_account"`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GCPServiceAccount }

func (Scanner) Keywords() []string { return []string{"service_account"} }

type serviceAccount struct {
	Type        string `json:"type"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
	ProjectID   string `json:"project_id"`
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := typeRe.FindAllIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := []detectors.Result{}
	seen := map[string]struct{}{}
	for _, h := range hits {
		obj, ok := extractObject(data, h[0])
		if !ok {
			continue
		}
		var sa serviceAccount
		if err := json.Unmarshal(obj, &sa); err != nil {
			continue
		}
		if sa.Type != "service_account" || sa.ClientEmail == "" || !strings.Contains(sa.PrivateKey, "PRIVATE KEY") {
			continue
		}
		if _, dup := seen[sa.ClientEmail]; dup {
			continue
		}
		seen[sa.ClientEmail] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.GCPServiceAccount,
			Raw:          []byte(sa.ClientEmail),
			RawV2:        obj,
			Redacted:     redact(sa.ClientEmail),
			ExtraData: map[string]string{
				"client_email": sa.ClientEmail,
				"project_id":   sa.ProjectID,
			},
		}
		if verify {
			v, err := verifyServiceAccount(ctx, &sa)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

// extractObject walks left from the "type" hit until it finds the opening
// '{' of the enclosing JSON object, then walks right tracking brace depth and
// string state to find the matching '}'. Returns the slice [start..end+1].
func extractObject(data []byte, hit int) ([]byte, bool) {
	// Walk left for opening brace. Coarse string tracking — a stray '{' inside
	// a string would mis-anchor us, but the candidate is then rejected at the
	// JSON unmarshal step so the cost is just a wasted try.
	start := -1
	depth := 0
	inString := false
	for i := hit - 1; i >= 0; i-- {
		c := data[i]
		if c == '"' && (i == 0 || data[i-1] != '\\') {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		if c == '}' {
			depth++
			continue
		}
		if c == '{' {
			if depth == 0 {
				start = i
				break
			}
			depth--
		}
	}
	if start < 0 {
		return nil, false
	}
	// Walk right for matching closing brace, with proper escape handling.
	depth = 0
	inString = false
	escape := false
	for i := start; i < len(data); i++ {
		c := data[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' && inString {
			escape = true
			continue
		}
		if c == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return data[start : i+1], true
			}
		}
	}
	return nil, false
}

// Verify accepts the raw JSON blob (so the Verifier interface still holds)
// and exchanges a signed JWT for an access token.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	var sa serviceAccount
	if err := json.Unmarshal([]byte(secret), &sa); err != nil {
		return false, err
	}
	return verifyServiceAccount(ctx, &sa)
}

func verifyServiceAccount(ctx context.Context, sa *serviceAccount) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	jwt, err := signJWT(sa)
	if err != nil {
		return false, err
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", jwt)

	// We always exchange at the package-level tokenURL so tests can override.
	// Production GCP service accounts route to oauth2.googleapis.com here,
	// regardless of any token_uri inside the JSON.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest, http.StatusTooManyRequests:
		// 400 covers "invalid_grant" — wrong signature on a parseable but
		// otherwise revoked / mismatched key. Treat as unverified, not error.
		return false, nil
	default:
		return false, nil
	}
}

func signJWT(sa *serviceAccount) (string, error) {
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("gcp: invalid PEM in private_key")
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		key, ok = k.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("gcp: PKCS8 key is not RSA")
		}
	} else if k2, err2 := x509.ParsePKCS1PrivateKey(block.Bytes); err2 == nil {
		key = k2
	} else {
		return "", fmt.Errorf("gcp: cannot parse private key")
	}

	now := time.Now().Unix()
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	claims := map[string]interface{}{
		"iss":   sa.ClientEmail,
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud":   firstNonEmpty(sa.TokenURI, "https://oauth2.googleapis.com/token"),
		"iat":   now,
		"exp":   now + 600,
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := base64URL(hb) + "." + base64URL(cb)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64URL(sig), nil
}

func base64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func redact(email string) string {
	at := bytes.IndexByte([]byte(email), '@')
	if at < 0 {
		return "..."
	}
	if at <= 4 {
		return email[:at] + "@..."
	}
	return email[:4] + "...@" + email[at+1:]
}

func init() {
	detectors.Register(Scanner{})
}
