// Package gcssignedurl detects Google Cloud Storage signed URLs (V4).
// A V4 signed URL embeds GOOG4-RSA-SHA256 in X-Goog-Algorithm, the
// service-account email in X-Goog-Credential, and an expiry. Anyone
// holding the URL can perform the underlying GCS operation until expiry.
//
// Verify is intentionally not performed — issuing the URL would fetch
// the underlying object and either leak it to the scanner's egress IP or
// trigger billable transfer. So gcssignedurl surfaces unverified-by-
// design at SeverityCritical when not yet expired (per X-Goog-Date +
// X-Goog-Expires) and SeverityHigh when expired.
package gcssignedurl

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var urlRe = regexp.MustCompile(`https?://storage\.googleapis\.com/[^\s"'<>]*?X-Goog-Algorithm=GOOG4-RSA-SHA256[^\s"'<>]*`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GCSSignedURL }

func (Scanner) Keywords() []string { return []string{"X-Goog-Algorithm=GOOG4-RSA-SHA256"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := urlRe.FindAll(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, m := range hits {
		full := string(m)
		if _, dup := seen[full]; dup {
			continue
		}
		seen[full] = struct{}{}
		extra := map[string]string{}
		expired := false
		if u, err := url.Parse(full); err == nil {
			q := u.Query()
			if cred := q.Get("X-Goog-Credential"); cred != "" {
				if email, _ := splitEmail(cred); email != "" {
					extra["service_account"] = email
				}
			}
			if signed := q.Get("X-Goog-SignedHeaders"); signed != "" {
				extra["signed_headers"] = signed
			}
			if date := q.Get("X-Goog-Date"); date != "" {
				extra["date"] = date
				if exp := q.Get("X-Goog-Expires"); exp != "" {
					extra["expires_seconds"] = exp
					if t, err := time.Parse("20060102T150405Z", date); err == nil {
						if secs, err := strconv.Atoi(exp); err == nil {
							if t.Add(time.Duration(secs) * time.Second).Before(time.Now()) {
								expired = true
							}
						}
					}
				}
			}
		}
		sev := detectors.SeverityCritical
		if expired {
			sev = detectors.SeverityHigh
			extra["expired"] = "true"
		}
		out = append(out, detectors.Result{
			DetectorType: detectors.GCSSignedURL,
			Raw:          []byte(full),
			Redacted:     redact(full),
			ExtraData:    extra,
			Severity:     sev,
		})
	}
	return out, nil
}

// splitEmail returns the service-account email portion of an
// X-Goog-Credential value:
//
//	<sa-email>/<date>/<region>/<service>/goog4_request
func splitEmail(cred string) (string, string) {
	parts := strings.Split(cred, "/")
	if len(parts) >= 4 {
		return parts[0], parts[1]
	}
	return "", ""
}

func redact(u string) string {
	if i := strings.Index(u, "?"); i > 0 && len(u) > i+24 {
		return u[:i+24] + "..."
	}
	if len(u) <= 32 {
		return u
	}
	return u[:32] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
