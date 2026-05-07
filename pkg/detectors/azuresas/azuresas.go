// Package azuresas detects Azure Storage SAS (Shared Access Signature) URLs
// embedding the `sig=` query parameter.
//
// Verify performs an unauthenticated HEAD against the URL — SAS URLs carry
// their own credential in the query string, so a 200/206 from the storage
// endpoint confirms the signature is currently valid against that resource.
// 403 (signature does not match), 404 (resource gone), or 401 are all
// "unverified, not a scan error". The HEAD is read-only so it does not mutate
// the target.
package azuresas

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

// SAS URL: scheme + storage account + service domain + path + ?sv=...&sig=...
// We anchor on a `sig=` query because that's the cryptographic parameter; sv
// (service version) and other params are present too but sig is mandatory.
// The capture is the full URL up to whitespace / quote.
var sasURLRe = regexp.MustCompile(`https://[a-z0-9]{3,24}\.(?:blob|file|queue|table|dfs)\.core\.windows\.net/[^\s"'<>]*[?&]sig=[^\s"'<>&]+[^\s"'<>]*`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AzureSAS }

// `core.windows.net` is the unmistakable signal; `sig=` alone would over-fire
// on JWT signature query params on unrelated endpoints.
func (Scanner) Keywords() []string { return []string{"core.windows.net"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := sasURLRe.FindAll(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, m := range hits {
		url := string(m)
		if _, dup := seen[url]; dup {
			continue
		}
		seen[url] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.AzureSAS,
			Raw:          []byte(url),
			Redacted:     redact(url),
		}
		if verify {
			v, err := verifyURL(ctx, url)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	return verifyURL(ctx, secret)
}

func verifyURL(ctx context.Context, url string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusPartialContent:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusTooManyRequests:
		// 403 = AuthenticationFailed (signature mismatch) or expired.
		// 404 = container/blob gone but maybe the SAS itself is valid for
		// a different path; we conservatively call it unverified.
		return false, nil
	default:
		return false, nil
	}
}

func redact(url string) string {
	// Strip everything from `sig=` onwards so the SAS signature isn't
	// echoed back in logs / sarif.
	for i := 0; i+4 < len(url); i++ {
		if url[i] == 's' && url[i+1] == 'i' && url[i+2] == 'g' && url[i+3] == '=' {
			return url[:i+4] + "..."
		}
	}
	if len(url) <= 32 {
		return url
	}
	return url[:32] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
