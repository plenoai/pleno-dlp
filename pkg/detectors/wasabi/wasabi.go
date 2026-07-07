// Package wasabi detects Wasabi access key + secret pairs (S3-compatible
// shape: 20-char access key, 40-char secret) gated on the `wasabi`
// keyword window, and verifies them via the S3 GET Service (ListBuckets)
// operation.
//
// Wasabi buckets are regional, but GET Service is account-global: it
// enumerates every bucket the credential can see regardless of which
// region they live in, so the call does not need region-correct routing
// the way object GET/PUT does. We therefore sign SigV4 (service=s3,
// region=us-east-1) against the FIXED default endpoint
// https://s3.wasabisys.com — the same precedent the AWS detector relies
// on, where the region-agnostic sts:GetCallerIdentity is verified against
// a hardcoded us-east-1 endpoint.
//
// Because the host is fixed there is no path to a false Verified=true
// from a wrong endpoint: an invalid signature
// yields 403 SignatureDoesNotMatch and an unknown key yields 403
// InvalidAccessKeyId, neither of which is the 200 we accept.
package wasabi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://s3.wasabisys.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// us-east-1 is the canonical default for the account-global GET Service
// call; Wasabi accepts it regardless of where the buckets actually live.
const signRegion = "us-east-1"

var emptyPayloadHash = func() string {
	sum := sha256.Sum256(nil)
	return hex.EncodeToString(sum[:])
}()

var (
	accessKeyRe = regexp.MustCompile(`\b([A-Z0-9]{20})\b`)
	secretRe    = regexp.MustCompile(`\b([A-Za-z0-9+/]{40})\b`)
)

var contextKeywords = []string{"wasabi", "wasabi_access_key", "wasabi_secret", "wasabisys"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Wasabi }

func (Scanner) Keywords() []string { return []string{"wasabi"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	keys := accessKeyRe.FindAllSubmatchIndex(data, -1)
	if len(keys) == 0 {
		return nil, nil
	}
	secrets := secretRe.FindAllSubmatchIndex(data, -1)
	if len(secrets) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(keys))
	seen := map[string]struct{}{}
	for _, k := range keys {
		key := string(data[k[2]:k[3]])
		// Skip AKIA/ASIA prefixes — those are real AWS, not Wasabi.
		if strings.HasPrefix(key, "AKIA") || strings.HasPrefix(key, "ASIA") {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		if !nearKeyword(lower, k[2], k[3]) {
			continue
		}
		secret, ok := nearestSecret(k[2], data, secrets, key)
		if !ok {
			continue
		}
		seen[key] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Wasabi,
			Raw:          []byte(key),
			RawV2:        []byte(secret),
			Redacted:     redact(key),
			ExtraData:    map[string]string{"access_key_id": key},
		}
		if verify {
			v, err := verifyPair(ctx, key, secret)
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

func nearestSecret(keyStart int, data []byte, hits [][]int, key string) (string, bool) {
	const maxDistance = 2048
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		s := string(data[h[2]:h[3]])
		if s == key {
			continue
		}
		dist := h[2] - keyStart
		if dist < 0 {
			dist = -dist
		}
		if dist < bestDist {
			bestDist = dist
			best = s
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

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

// Verify expects "<access_key_id>:<secret_access_key>" because the
// detectors.Verifier interface only takes a single string. FromData
// performs the call inline; this method satisfies the Verifier contract
// and stays forward-compatible, mirroring the AWS detector.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	id, sk, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	return verifyPair(ctx, id, sk)
}

func splitPair(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// verifyPair signs a SigV4 GET Service (ListBuckets) request against the
// fixed Wasabi endpoint and classifies the response. A 200 means the
// credential pair is valid and account-scoped; a 403 (SignatureDoesNotMatch
// / InvalidAccessKeyId) is an authoritative rejection; 429 and 5xx are
// transient and surfaced as VerificationErr, never as Verified=true.
func verifyPair(ctx context.Context, id, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/", nil)
	if err != nil {
		return false, err
	}

	creds := awssdk.Credentials{AccessKeyID: id, SecretAccessKey: secret}
	signer := v4.NewSigner()
	if err := signer.SignHTTP(ctx, creds, req, emptyPayloadHash, "s3", signRegion, time.Now().UTC()); err != nil {
		return false, err
	}

	resp, err := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, err, []int{http.StatusOK}, []int{http.StatusForbidden})
}

func init() {
	detectors.Register(Scanner{})
}
