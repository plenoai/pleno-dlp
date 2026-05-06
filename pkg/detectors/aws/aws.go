// Package aws detects AWS access key id / secret access key pairs and
// optionally verifies them via sts:GetCallerIdentity.
package aws

import (
	"context"
	"fmt"
	"regexp"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// AKIA[0-9A-Z]{16} is the canonical access-key-id shape. ASIA covers temporary
// credentials but is intentionally out of scope for the MVP.
var (
	idRe = regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`)
	// Secret access key: 40 chars from the base64-ish set. The boundary `\b`
	// would treat `+` and `/` as boundaries, so we anchor with a negative
	// lookbehind-equivalent via byte class on the surrounding chars manually.
	secretRe = regexp.MustCompile(`[^A-Za-z0-9+/]([A-Za-z0-9+/]{40})[^A-Za-z0-9+/]`)
)

// stsRegion is the region used for the verification call. us-east-1 is a safe
// default — sts:GetCallerIdentity is a global API and accepts any region.
const stsRegion = "us-east-1"

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AWS }

func (Scanner) Keywords() []string { return []string{"AKIA"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	idMatches := idRe.FindAllSubmatchIndex(data, -1)
	if len(idMatches) == 0 {
		return nil, nil
	}

	// Pre-compute secret candidates. Use a wider sweep so we can pick the
	// nearest match to each access-key id.
	secretMatches := secretRe.FindAllSubmatchIndex(data, -1)

	results := make([]detectors.Result, 0, len(idMatches))
	for _, m := range idMatches {
		id := string(data[m[2]:m[3]])
		secret, ok := nearestSecret(m[2], data, secretMatches)
		res := detectors.Result{
			DetectorType: detectors.AWS,
			Raw:          []byte(id),
			Redacted:     redact(id),
			ExtraData:    map[string]string{"access_key_id": id},
		}
		if ok {
			res.RawV2 = []byte(secret)
			if verify {
				v, err := s.Verify(ctx, id+":"+secret)
				res.Verified = v
				res.VerificationErr = err
			}
		}
		results = append(results, res)
	}
	return results, nil
}

// nearestSecret picks the closest 40-char base64-ish run within 256 bytes of
// the access-key id position. Returns the secret string and ok=true when one
// is found.
func nearestSecret(idStart int, data []byte, secrets [][]int) (string, bool) {
	const maxDistance = 256
	bestDist := maxDistance + 1
	best := ""
	for _, sm := range secrets {
		// sm[2]..sm[3] is the captured group (the 40-char run).
		start, end := sm[2], sm[3]
		dist := absDist(start, idStart)
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

func absDist(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}

func redact(id string) string {
	if len(id) <= 4 {
		return id
	}
	return id[:4] + "..."
}

// Verify expects "<access_key_id>:<secret_access_key>" because the
// detectors.Verifier interface only takes a single string. The engine never
// calls Verify directly with a packed string today; FromData performs the
// call inline. This method is provided to satisfy the Verifier contract and
// to stay forward-compatible.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	id, sk, ok := splitPair(secret)
	if !ok {
		return false, fmt.Errorf("aws: expected id:secret pair")
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

func verifyPair(ctx context.Context, id, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cfg := awssdk.Config{
		Region:      stsRegion,
		Credentials: credentials.NewStaticCredentialsProvider(id, secret, ""),
	}
	client := sts.NewFromConfig(cfg)
	_, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return false, nil //nolint:nilerr // 401/403 etc. = unverified, not a scan error
	}
	return true, nil
}

func init() {
	detectors.Register(Scanner{})
}
