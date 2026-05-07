// Package awss3presigned detects AWS S3 presigned URLs. A presigned URL
// embeds an AWS4-HMAC-SHA256 signature, the access-key id (via
// X-Amz-Credential), the signed-headers list, and an expiration. Anyone
// holding the URL can perform the underlying S3 operation until expiry.
//
// Verify is intentionally not performed. Issuing the URL would actually
// fetch the underlying object and either leak it to a third party (the
// scanner's egress IP) or trigger billable transfer. So
// awss3presigned surfaces unverified-by-design at SeverityCritical when
// the URL has not yet expired (per X-Amz-Date + X-Amz-Expires) and
// SeverityHigh when expired. The full URL is the Raw secret because
// trimming it would lose the signature and therefore the rotation
// surface; the access-key id is captured into ExtraData.
package awss3presigned

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// S3 presigned URLs end with the X-Amz-Signature query parameter — the
// full URL must include host, the AWS4-HMAC-SHA256 algorithm marker, and
// the credential / signature pair.
var urlRe = regexp.MustCompile(`https?://[^\s"'<>]+\.(?:s3|s3-[a-z0-9-]+|s3\.[a-z0-9-]+)\.amazonaws\.com/[^\s"'<>]*?X-Amz-Algorithm=AWS4-HMAC-SHA256[^\s"'<>]*`)

// Path-style host (s3.amazonaws.com/bucket/key?…) — same algo marker.
var pathStyleRe = regexp.MustCompile(`https?://s3(?:\.[a-z0-9-]+)?\.amazonaws\.com/[^\s"'<>]*?X-Amz-Algorithm=AWS4-HMAC-SHA256[^\s"'<>]*`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AWSS3PresignedURL }

func (Scanner) Keywords() []string { return []string{"X-Amz-Algorithm=AWS4-HMAC-SHA256"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := append(urlRe.FindAll(data, -1), pathStyleRe.FindAll(data, -1)...)
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
			if cred := q.Get("X-Amz-Credential"); cred != "" {
				if akid, region, _ := parseCredential(cred); akid != "" {
					extra["access_key_id"] = akid
					if region != "" {
						extra["region"] = region
					}
				}
			}
			if signed := q.Get("X-Amz-SignedHeaders"); signed != "" {
				extra["signed_headers"] = signed
			}
			if date := q.Get("X-Amz-Date"); date != "" {
				extra["date"] = date
				if exp := q.Get("X-Amz-Expires"); exp != "" {
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
			DetectorType: detectors.AWSS3PresignedURL,
			Raw:          []byte(full),
			Redacted:     redact(full),
			ExtraData:    extra,
			Severity:     sev,
		})
	}
	return out, nil
}

// parseCredential splits the X-Amz-Credential value
// "<AKID>/<DATE>/<REGION>/s3/aws4_request" into (akid, region, date).
func parseCredential(c string) (akid, region, date string) {
	parts := strings.Split(c, "/")
	if len(parts) >= 4 {
		akid = parts[0]
		date = parts[1]
		region = parts[2]
	}
	return
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
