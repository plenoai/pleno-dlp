// Package tencentcloud detects Tencent Cloud SecretId + SecretKey pairs and
// verifies them live against the STS OpenAPI.
//
// SecretIds start with `AKID` and are 32 alphanumerics; SecretKeys are 32
// base62 chars. Together they grant the owning CAM principal's full
// configured policy — root keys especially are SeverityCritical when paired.
//
// Verification calls STS GetCallerIdentity (sts.tencentcloudapi.com) signed
// with TC3-HMAC-SHA256, a deterministic AWS-SigV4-style scheme that needs no
// SDK. The host is fixed: region is an X-TC-Region header, not part of the
// canonical request, and GetCallerIdentity requires no region at all.
//
// Correctness trap: TencentCloud returns HTTP 200 even for auth failures and
// encodes the error in the JSON body (Response.Error.Code, e.g.
// AuthFailure.SignatureFailure / AuthFailure.SecretIdNotFound). A status-only
// classifier with acceptCodes:[200] would mark revoked keys verified, so we
// parse the body. ClassifyVerifyHTTP is used only to separate transport
// failures and transient 429/5xx from authoritative responses.
//
// Verify is a no-op when RawV2 (SecretKey) is absent: a lone SecretId is not a
// credential, so single-id matches surface unverified.
package tencentcloud

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is the STS OpenAPI host; tests override it. The signing service name
// stays "sts" regardless so the canonical request the server validates is
// stable even when the URL points at httptest.
var apiBase = "https://sts.tencentcloudapi.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

const (
	stsService = "sts"
	stsAction  = "GetCallerIdentity"
	stsVersion = "2018-08-13"
)

// SecretId: `AKID` + 28..36 alphanumerics. Tencent issues both 32 and 36-char
// variants depending on issuance year; we accept 32..40 total.
var idRe = regexp.MustCompile(`\b(AKID[A-Za-z0-9]{28,36})\b`)

// SecretKey: 32 base62 chars.
var secretRe = regexp.MustCompile(`[^A-Za-z0-9]([A-Za-z0-9]{32})[^A-Za-z0-9]`)

var contextKeywords = []string{"tencent", "tencentcloud", "secret_id", "secret_key", "tencent_cloud"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.TencentCloud }

func (Scanner) Keywords() []string { return []string{"AKID", "tencent"} }

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
		// Co-occurrence is mandatory: AKID-prefixed strings appear in unrelated
		// internal tooling.
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[id] = struct{}{}
		secret, hasSecret := nearestRun(m[2], data, secrets, 256)
		res := detectors.Result{
			DetectorType: detectors.TencentCloud,
			Raw:          []byte(id),
			Redacted:     redact(id),
			ExtraData:    map[string]string{"secret_id": id},
		}
		if hasSecret {
			res.RawV2 = []byte(secret)
			res.Severity = detectors.SeverityCritical
			if verify {
				v, account, err := verifyPair(ctx, id, secret)
				res.Verified = v
				res.VerificationErr = err
				if account != "" {
					res.ExtraData["tencent_account_id"] = account
				}
			}
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	// secret is packed as "<SecretId>:<SecretKey>"; a lone SecretId is not a
	// credential, so an unpaired value is a no-op (not an error).
	id, key, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	v, _, err := verifyPair(ctx, id, key)
	return v, err
}

func splitPair(s string) (string, string, bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// stsResponse models the GetCallerIdentity envelope. On success Error is nil
// and AccountId/Arn are populated; on auth failure (still HTTP 200) Error.Code
// is set, e.g. "AuthFailure.SignatureFailure".
type stsResponse struct {
	Response struct {
		AccountId string `json:"AccountId"`
		Arn       string `json:"Arn"`
		Error     *struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"Error"`
	} `json:"Response"`
}

// verifyPair calls STS GetCallerIdentity. Returns (verified, accountId, err).
// err is non-nil only for transient/transport conditions (429, 5xx, network,
// malformed body) so the engine records VerificationErr rather than a false
// "verified-not-valid" verdict.
func verifyPair(ctx context.Context, id, key string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	host := hostFromBase(apiBase)
	payload := []byte("{}")
	now := time.Now().UTC()
	timestamp := strconv.FormatInt(now.Unix(), 10)
	date := now.Format("2006-01-02")

	authorization := tc3Authorization(id, key, host, payload, timestamp, date)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase, bytes.NewReader(payload))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", host)
	req.Header.Set("X-TC-Action", stsAction)
	req.Header.Set("X-TC-Version", stsVersion)
	req.Header.Set("X-TC-Timestamp", timestamp)

	resp, err := httpClient.Do(req)
	// ClassifyVerifyHTTP separates transport failures and transient 429/5xx
	// from authoritative responses. We pass an empty acceptCodes set because a
	// 200 here does NOT mean "valid" — the body decides. We only consume the
	// error half (transient/transport) and ignore the bool.
	if _, classErr := detectors.ClassifyVerifyHTTP(resp, err, nil, nil); classErr != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return false, "", classErr
	}
	defer resp.Body.Close()

	var parsed stsResponse
	if decErr := json.NewDecoder(resp.Body).Decode(&parsed); decErr != nil {
		return false, "", fmt.Errorf("verify: decode response: %w", decErr)
	}

	if parsed.Response.Error != nil && parsed.Response.Error.Code != "" {
		// AuthFailure.* (SignatureFailure, SecretIdNotFound, TokenFailure) are
		// authoritative invalid verdicts. Other error codes (e.g. throttling)
		// are surfaced as VerificationErr so we never claim a key is dead on a
		// non-auth error.
		code := parsed.Response.Error.Code
		if strings.HasPrefix(code, "AuthFailure") {
			return false, "", nil
		}
		return false, "", fmt.Errorf("verify: unexpected error code %q", code)
	}
	if parsed.Response.AccountId != "" || parsed.Response.Arn != "" {
		return true, parsed.Response.AccountId, nil
	}
	// No error and no identity is ambiguous: never claim verified=true.
	return false, "", fmt.Errorf("verify: ambiguous response (no error, no identity)")
}

// hostFromBase extracts the host[:port] from apiBase for the Host header and
// canonical request. Falls back to the production host so a malformed override
// can't silently sign against the wrong service.
func hostFromBase(base string) string {
	h := base
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if h == "" {
		return "sts.tencentcloudapi.com"
	}
	return h
}

// tc3Authorization builds the TC3-HMAC-SHA256 Authorization header.
//
// Canonical request:
//
//	POST\n / \n \n content-type:...\nhost:...\nx-tc-action:...\n \n
//	content-type;host;x-tc-action \n HexSHA256(payload)
//
// String to sign:
//
//	TC3-HMAC-SHA256\n <timestamp> \n <date>/<service>/tc3_request \n
//	HexSHA256(canonicalRequest)
//
// Signing key chain seeded by "TC3"+SecretKey:
//
//	HMAC(("TC3"+key), date) -> HMAC(_, service) -> HMAC(_, "tc3_request")
func tc3Authorization(id, key, host string, payload []byte, timestamp, date string) string {
	const algorithm = "TC3-HMAC-SHA256"
	signedHeaders := "content-type;host;x-tc-action"
	lowerAction := strings.ToLower(stsAction)

	canonicalHeaders := "content-type:application/json; charset=utf-8\n" +
		"host:" + host + "\n" +
		"x-tc-action:" + lowerAction + "\n"
	hashedPayload := hexSHA256(payload)
	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		"/",
		"",
		canonicalHeaders,
		signedHeaders,
		hashedPayload,
	}, "\n")

	credentialScope := date + "/" + stsService + "/tc3_request"
	stringToSign := strings.Join([]string{
		algorithm,
		timestamp,
		credentialScope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	secretDate := hmacSHA256([]byte("TC3"+key), date)
	secretService := hmacSHA256(secretDate, stsService)
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))

	return fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm, id, credentialScope, signedHeaders, signature)
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
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

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
