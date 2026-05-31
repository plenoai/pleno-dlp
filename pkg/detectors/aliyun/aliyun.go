// Package aliyun detects Alibaba Cloud (Aliyun) AccessKey id + secret pairs.
//
// AccessKey ids start with `LTAI` and run 16..24 alphanumerics; the paired
// AccessKey secret is a 30-char base62 token. Together they grant the
// owning RAM user's full configured policy — root accounts especially are
// SeverityCritical when paired.
//
// Verify performs a live, read-only probe against the global, region-agnostic
// ECS endpoint https://ecs.aliyuncs.com using Action=DescribeRegions. That
// endpoint needs no region selection, so the earlier "no reliable region"
// concern does not apply, and DescribeRegions returns the public region list —
// it leaks no tenant-specific data. The probe signs the request with the
// classic Aliyun RPC v1.0 HMAC-SHA1 query-signing scheme: the AccessKey id is
// the AccessKeyId param and the AccessKey secret is the HMAC key (secret+"&").
// A wrong signature yields SignatureDoesNotMatch (HTTP 400), so a false
// Verified=true is unreachable.
package aliyun

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is the global, region-agnostic ECS endpoint. Tests override it to
// point at an httptest.Server.
var apiBase = "https://ecs.aliyuncs.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// LTAI is the canonical AccessKey id prefix. Aliyun has issued shorter (16
// alnum) and longer (24 alnum) variants depending on issuance year; the
// 16..24 range covers both.
var idRe = regexp.MustCompile(`\b(LTAI[A-Za-z0-9]{12,20})\b`)

// AccessKey secrets are 30 base62 chars. We anchor with non-base62 surround
// so adjacent tokens don't merge into a single capture.
var secretRe = regexp.MustCompile(`[^A-Za-z0-9]([A-Za-z0-9]{30})[^A-Za-z0-9]`)

var contextKeywords = []string{"aliyun", "alibaba", "accesskey", "access_key", "alibabacloud"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AlibabaCloud }

// LTAI is distinctive enough on its own. We also prefilter on `aliyun` so
// secret-only chunks (when only the SecretKey leaks but not the id) don't
// reach FromData — pairing requires both.
func (Scanner) Keywords() []string { return []string{"LTAI", "aliyun", "alibaba"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	idMatches := idRe.FindAllSubmatchIndex(data, -1)
	if len(idMatches) == 0 {
		return nil, nil
	}
	secrets := secretRe.FindAllSubmatchIndex(data, -1)
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(idMatches))
	seen := map[string]struct{}{}
	for _, m := range idMatches {
		id := string(data[m[2]:m[3]])
		if _, dup := seen[id]; dup {
			continue
		}
		// Co-occurrence is mandatory because LTAI prefixed strings appear in
		// internal docs unrelated to live credentials.
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[id] = struct{}{}
		secret, hasSecret := nearestRun(m[2], data, secrets, 256)
		res := detectors.Result{
			DetectorType: detectors.AlibabaCloud,
			Raw:          []byte(id),
			Redacted:     redact(id),
			ExtraData:    map[string]string{"access_key_id": id},
		}
		if hasSecret {
			res.RawV2 = []byte(secret)
			// Paired credentials grant full account-scope access — Critical.
			res.Severity = detectors.SeverityCritical
			if verify {
				v, err := verifyPair(ctx, id, secret)
				res.Verified = v
				res.VerificationErr = err
			}
		}
		// Id-only findings cannot be signed (no HMAC key), so they stay
		// unverified regardless of the verify flag.
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
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

// Verify accepts the paired credential packed as "<accessKeyId>:<secret>"
// (engine convention, mirrors datadog). An id-only finding cannot be signed,
// so verify no-ops to (false, nil) when the secret half is absent.
func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	id, sec, ok := splitPair(secret)
	if !ok || id == "" || sec == "" {
		return false, nil
	}
	return verifyPair(ctx, id, sec)
}

func splitPair(s string) (string, string, bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// verifyPair signs an ECS DescribeRegions request with the leaked credential
// and classifies the response: 200 => valid, 400/404 (SignatureDoesNotMatch,
// InvalidAccessKeyId, etc.) => invalid, 429/5xx => transient (error).
func verifyPair(ctx context.Context, accessKeyID, accessKeySecret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	endpoint, err := signedURL(accessKeyID, accessKeySecret, time.Now().UTC())
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	resp, doErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, doErr, []int{http.StatusOK}, []int{http.StatusBadRequest, http.StatusNotFound})
}

// signedURL builds the fully-signed Aliyun RPC v1.0 (HMAC-SHA1) request URL for
// ECS DescribeRegions against apiBase.
func signedURL(accessKeyID, accessKeySecret string, now time.Time) (string, error) {
	params := map[string]string{
		"Action":           "DescribeRegions",
		"Version":          "2014-05-26",
		"Format":           "JSON",
		"AccessKeyId":      accessKeyID,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureVersion": "1.0",
		"SignatureNonce":   strconv.FormatInt(now.UnixNano(), 10),
		"Timestamp":        now.Format("2006-01-02T15:04:05Z"),
	}

	// Build the sorted canonical query exactly as Aliyun expects it.
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonical.WriteByte('&')
		}
		canonical.WriteString(percentEncode(k))
		canonical.WriteByte('=')
		canonical.WriteString(percentEncode(params[k]))
	}

	stringToSign := "GET&" + percentEncode("/") + "&" + percentEncode(canonical.String())

	mac := hmac.New(sha1.New, []byte(accessKeySecret+"&"))
	if _, err := mac.Write([]byte(stringToSign)); err != nil {
		return "", err
	}
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	final := canonical.String() + "&Signature=" + percentEncode(signature)
	return apiBase + "/?" + final, nil
}

// percentEncode implements Aliyun's RFC 3986 variant: url.QueryEscape then
// + -> %20, * -> %2A, %7E -> ~.
func percentEncode(s string) string {
	e := url.QueryEscape(s)
	e = strings.ReplaceAll(e, "+", "%20")
	e = strings.ReplaceAll(e, "*", "%2A")
	e = strings.ReplaceAll(e, "%7E", "~")
	return e
}

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
