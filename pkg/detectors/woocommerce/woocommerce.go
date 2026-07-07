// Package woocommerce detects WooCommerce REST API consumer key + secret
// pairs (`ck_<40hex>` + `cs_<40hex>`). Unverified-by-design — every
// WooCommerce install runs on a per-store host (`<store>.com/wp-json/wc/v3`),
// so verify only fires when apiBase is overridden. Raw=ck,
// RawV2=ck:cs per the trufflehog convention.
package woocommerce

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is empty by default — verify is skipped unless overridden.
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var ckRe = regexp.MustCompile(`\b(ck_[a-f0-9]{40})\b`)
var csRe = regexp.MustCompile(`\b(cs_[a-f0-9]{40})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.WooCommerce }

func (Scanner) Keywords() []string { return []string{"ck_", "cs_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	ckMatches := ckRe.FindAllSubmatch(data, -1)
	csMatches := csRe.FindAllSubmatch(data, -1)
	if len(ckMatches) == 0 || len(csMatches) == 0 {
		return nil, nil
	}
	ck := string(ckMatches[0][1])
	cs := string(csMatches[0][1])
	res := detectors.Result{
		DetectorType: detectors.WooCommerce,
		Raw:          []byte(ck),
		RawV2:        []byte(ck + ":" + cs),
		Redacted:     redact(ck),
	}
	if verify && apiBase != "" {
		v, err := s.Verify(ctx, ck+":"+cs)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	ck, cs := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/wp-json/wc/v3/system_status", nil)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(ck + ":" + cs))
	req.Header.Set("Authorization", "Basic "+auth)
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, nil
}

func redact(t string) string {
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
