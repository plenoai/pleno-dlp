// Package azurestoragekey detects Azure Storage account keys embedded in
// AccountKey= connection strings (DefaultEndpointsProtocol=...;AccountName=...;AccountKey=...).
//
// Azure Storage account keys are 88-character base64 strings that decode to
// 64 bytes. They appear in connection strings alongside AccountName= so we
// anchor the detection to both fields, which makes false-positive rates very
// low without requiring a live-verify round-trip.
//
// # Verify
//
// Verify sends a signed List Containers REST request to
// https://<account>.blob.core.windows.net/?comp=list using HMAC-SHA256 with
// the decoded key (Shared Key Lite authorization). A 200 OK means the
// credential is live; 403/401 means wrong or revoked key.
package azurestoragekey

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dialTimeout = 8 * time.Second

// connRe matches the AccountName and AccountKey fields in an Azure Storage
// connection string in either order. The AccountKey value is an 88-character
// base64 string (64 decoded bytes, always ending with ==).
var connRe = regexp.MustCompile(
	`(?i)AccountName\s*=\s*([a-z0-9]{3,24})[^;]{0,200}AccountKey\s*=\s*([A-Za-z0-9+/]{86}==)` +
		`|` +
		`(?i)AccountKey\s*=\s*([A-Za-z0-9+/]{86}==)[^;]{0,200}AccountName\s*=\s*([a-z0-9]{3,24})`,
)

var httpClient = &http.Client{Timeout: dialTimeout}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AzureStorageKey }

func (Scanner) Keywords() []string { return []string{"AccountKey="} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := connRe.FindAllSubmatch(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}

	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}

	for _, m := range hits {
		var account, key string
		if string(m[1]) != "" {
			account = string(m[1])
			key = string(m[2])
		} else {
			key = string(m[3])
			account = string(m[4])
		}
		if account == "" || key == "" {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		res := detectors.Result{
			DetectorType: detectors.AzureStorageKey,
			Raw:          []byte(key),
			Redacted:     redact(key),
			ExtraData:    map[string]string{"account": account},
			Severity:     detectors.SeverityCritical,
		}
		if verify {
			// Encode account+key as "<account>\n<key>" — AccountKey is
			// base64 and never contains newlines, so this is unambiguous.
			v, err := s.Verify(ctx, account+"\n"+key)
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

// Verify sends a signed List Containers request using the Shared Key Lite
// authorization scheme. A 200 OK response confirms the key is valid.
//
// secret encodes "<account>\n<key>" — both fields are emitted by FromData.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, "\n", 2)
	if len(parts) != 2 {
		return false, fmt.Errorf("azurestoragekey: malformed secret (missing account\\nkey)")
	}
	account, key := parts[0], parts[1]
	return verifyStorageKey(ctx, account, key)
}

func verifyStorageKey(ctx context.Context, account, key string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return false, fmt.Errorf("azurestoragekey: base64 decode: %w", err)
	}

	now := time.Now().UTC().Format(http.TimeFormat)
	url := fmt.Sprintf("https://%s.blob.core.windows.net/?comp=list", account)

	// Shared Key Lite string-to-sign: Date\n + CanonicalizedResource
	canonicalized := fmt.Sprintf("/%s/\ncomp:list", account)
	stringToSign := now + "\n" + canonicalized

	mac := hmac.New(sha256.New, keyBytes)
	mac.Write([]byte(stringToSign))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	authHeader := fmt.Sprintf("SharedKeyLite %s:%s", account, sig)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("azurestoragekey: build request: %w", err)
	}
	req.Header.Set("Date", now)
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("x-ms-version", "2020-10-02")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("azurestoragekey: request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("azurestoragekey: unexpected status %d", resp.StatusCode)
	}
}

func redact(key string) string {
	if len(key) <= 8 {
		return "..."
	}
	return key[:4] + "..." + key[len(key)-4:]
}

// Compile-time interface checks.
var (
	_ detectors.Detector = Scanner{}
	_ detectors.Verifier = Scanner{}
)

func init() {
	detectors.Register(Scanner{})
}

// canonicalizedStringToSign returns the Shared Key Lite string-to-sign
// for a List Containers request (exported for testing).
func canonicalizedStringToSign(account, date string) string {
	return date + "\n" + fmt.Sprintf("/%s/\ncomp:list", strings.ToLower(account))
}
