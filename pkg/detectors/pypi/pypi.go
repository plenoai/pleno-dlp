// Package pypi detects PyPI upload tokens (pypi-AgEIc…) and verifies them
// against the upload endpoint. PyPI's legacy upload endpoint replies 200/403
// even for GET when the credentials are well-formed and authentic; we treat
// 200 / 405 (method-not-allowed) as verified.
package pypi

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://upload.pypi.org"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// PyPI tokens always start "pypi-AgEIc" followed by macaroon body.
var tokenRe = regexp.MustCompile(`\b(pypi-AgEIc[A-Za-z0-9_-]{50,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PyPI }

func (Scanner) Keywords() []string { return []string{"pypi-AgEIc"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		token := string(m)
		res := detectors.Result{
			DetectorType: detectors.PyPI,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/legacy/", nil)
	if err != nil {
		return false, err
	}
	creds := "__token__:" + secret
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusMethodNotAllowed:
		// 405 = endpoint exists & creds parsed; canonical for PyPI legacy GET.
		return true, nil
	case http.StatusForbidden, http.StatusUnauthorized, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
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
